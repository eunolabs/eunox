/**
 * CLI ↔ Issuer integration tests — CR-3
 * ==========================================
 * Exercises the full PKCE browser-redirect → loopback → code-exchange →
 * issuer-POST → token-write path against in-process HTTP servers.
 *
 * Exit criterion E3: happy-path + error-path integration tests in
 * euno-platform/packages/integration-tests/.
 *
 * Architecture review finding: CR-3 (architecture-review-2026-05-stage4.md)
 *
 * ## Test structure
 *
 * Three in-process HTTP servers are wired together:
 *
 *   1. **Mock IdP server** — signs ES256 JWTs on demand via POST /token.
 *      Mirrors `infra/mock-oidc/server.mjs` but runs inline with the Jest
 *      process so no Docker is required.
 *
 *   2. **Issuer server** — wraps `CapabilityIssuerService` + `OidcStateStore`
 *      behind a minimal HTTP handler, identical in surface area to the two
 *      OIDC routes in `capability-issuer/src/index.ts`:
 *        GET  /api/v1/oidc/authorize
 *        POST /api/v1/oidc/token
 *        GET  /.well-known/jwks.json
 *
 *   3. *(Implicit)* The test itself acts as the CLI: it calls GET /authorize,
 *      then POST mock-IdP/token (simulating the loopback exchange), and
 *      finally POST issuer/oidc/token to obtain a capability token.
 *
 * ## Loopback exchange simulation
 *
 * The real CLI flow is:
 *   browser → IdP → loopback server (receives code) → CLI exchanges code for
 *   id_token → CLI posts id_token to issuer.
 *
 * Here we skip the browser and post the nonce directly to the mock IdP's
 * /token endpoint, which returns a signed id_token immediately. This
 * exercises every security check on the issuer side (replay prevention,
 * nonce binding, state binding) without requiring a real browser.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { AddressInfo } from 'net';
import * as jose from 'jose';

import {
  CapabilityTokenPayload,
  IdentityAdapter,
  IdentityAdapterConfig,
  IssuanceContext,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import { OidcStateStore } from '../../capability-issuer/src/oidc-state-store';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import { saveCapabilityToken } from '../../../../public/packages/cli/src/token-utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface RunningServer {
  server: http.Server;
  baseUrl: string;
  close: () => Promise<void>;
}

/** Context shared across tests for one mock-IdP instance. */
interface MockIdpContext {
  privateKey: jose.KeyLike;
  publicKey: jose.KeyLike;
  jwk: jose.JWK;
  /** Populated after `startMockIdpServer` is called. */
  issuer: string;
  clientId: string;
  kid: string;
}

// ── Low-level HTTP helpers ────────────────────────────────────────────────────

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

function listen(handler: http.RequestListener): Promise<RunningServer> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve({
        server,
        baseUrl,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

// ── Mock IdP ──────────────────────────────────────────────────────────────────

async function createMockIdpContext(): Promise<MockIdpContext> {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(publicKey);
  const kid = 'mock-idp-test-key-1';
  jwk.use = 'sig';
  jwk.alg = 'ES256';
  jwk.kid = kid;
  return {
    privateKey,
    publicKey,
    jwk,
    issuer: '', // filled after the server starts
    clientId: 'cli-it-client',
    kid,
  };
}

/**
 * Start a minimal OIDC-compatible mock IdP HTTP server.
 * The context's `issuer` field is populated once the server is listening.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json        — returns the mock public key
 *   GET  /.well-known/openid-configuration — discovery doc
 *   POST /token                        — mints a signed ES256 id_token
 *     Body: { nonce, sub?, groups? }
 *     Response: { id_token, token_type }
 */
async function startMockIdpServer(ctx: MockIdpContext): Promise<RunningServer> {
  const running = await listen(async (req, res) => {
    const url = req.url?.split('?')[0] ?? '';

    if (req.method === 'GET' && url === '/.well-known/jwks.json') {
      send(res, 200, { keys: [ctx.jwk] });
      return;
    }

    if (req.method === 'GET' && url === '/.well-known/openid-configuration') {
      send(res, 200, {
        issuer: ctx.issuer,
        jwks_uri: `${ctx.issuer}/.well-known/jwks.json`,
        token_endpoint: `${ctx.issuer}/token`,
        authorization_endpoint: `${ctx.issuer}/authorize`,
        id_token_signing_alg_values_supported: ['ES256'],
        scopes_supported: ['openid', 'profile', 'email'],
      });
      return;
    }

    if (req.method === 'POST' && url === '/token') {
      const raw = (await readJsonBody(req)) as {
        nonce?: string;
        sub?: string;
        groups?: string[];
      };
      const nonce = typeof raw.nonce === 'string' ? raw.nonce : '';
      const sub = typeof raw.sub === 'string' ? raw.sub : 'test-user@example.com';
      const groups = Array.isArray(raw.groups) ? raw.groups : ['Administrator'];
      const now = Math.floor(Date.now() / 1000);

      const idToken = await new jose.SignJWT({
        iss: ctx.issuer,
        aud: ctx.clientId,
        sub,
        iat: now,
        exp: now + 3600,
        nonce,
        email: sub.includes('@') ? sub : `${sub}@test.example`,
        groups,
      })
        .setProtectedHeader({ alg: 'ES256', kid: ctx.kid })
        .sign(ctx.privateKey);

      send(res, 200, { id_token: idToken, token_type: 'Bearer', expires_in: 3600 });
      return;
    }

    send(res, 404, { error: 'not found' });
  });

  // Back-fill the issuer URL so the signed tokens and discovery doc reference it.
  ctx.issuer = running.baseUrl;
  return running;
}

// ── Mock identity provider ────────────────────────────────────────────────────

/**
 * Identity provider that validates ES256 id_tokens signed by the mock IdP.
 * Mirrors the role the AWSCognitoIdentityProvider / AzureADIdentityProvider
 * play in production: validates the JWT then maps claims to a UserContext.
 */
class MockOidcIdentityProvider extends IdentityAdapter {
  public readonly name = 'mock-oidc';

  constructor(
    private readonly idpPublicKey: jose.KeyLike,
    private readonly expectedIssuer: string,
    private readonly expectedClientId: string,
  ) {
    super({ type: 'mock-oidc', name: 'mock-oidc' } as IdentityAdapterConfig);
  }

  async validateToken(idToken: string): Promise<UserContext> {
    const { payload } = await jose.jwtVerify(idToken, this.idpPublicKey, {
      issuer: this.expectedIssuer,
      audience: this.expectedClientId,
      algorithms: ['ES256'],
    });

    const sub = payload.sub ?? 'unknown';
    const email =
      typeof payload['email'] === 'string' ? payload['email'] : undefined;
    const groups = Array.isArray(payload['groups'])
      ? (payload['groups'] as unknown[]).filter(
          (g): g is string => typeof g === 'string',
        )
      : [];
    const nonce =
      typeof payload['nonce'] === 'string' ? payload['nonce'] : undefined;

    return {
      userId: sub,
      email,
      roles: groups,
      tenantId: 'cli-it-tenant',
      // Preserve all claims so the nonce can be checked by the issuer server.
      claims: { nonce, ...(payload as Record<string, unknown>) },
    };
  }

  async getUserRoles(_userId: string): Promise<string[]> {
    return [];
  }
}

// ── Test RS256 signer ─────────────────────────────────────────────────────────

const SIGNING_ALG = 'RS256';

/**
 * In-process RS256 signer — matches the pattern in `e2e.test.ts`.
 */
class JoseRsaSigner extends SigningAdapter {
  constructor(
    private readonly _privateKey: jose.KeyLike,
    private readonly _publicKeyPem: string,
    private readonly _keyId: string,
  ) {
    super({
      type: 'jose-rsa',
      name: 'jose-rsa',
      algorithm: SIGNING_ALG,
    } as SigningAdapterConfig);
  }

  async sign(
    payload: CapabilityTokenPayload,
    _context?: IssuanceContext,
  ): Promise<string> {
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: SIGNING_ALG, kid: this._keyId })
      .sign(this._privateKey);
  }

  async getPublicKey(): Promise<string> {
    return this._publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return this._keyId;
  }
}

async function createSigner(): Promise<JoseRsaSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, {
    extractable: true,
  });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  return new JoseRsaSigner(privateKey, publicKeyPem, 'cli-it-issuer-key');
}

// ── Issuer server ─────────────────────────────────────────────────────────────

/**
 * Minimal in-process HTTP wrapper around `CapabilityIssuerService` that
 * exposes the two OIDC endpoints from `capability-issuer/src/index.ts`.
 *
 * The handler replicates the production endpoint logic (replay prevention,
 * state binding, nonce check) so the integration test exercises the same
 * security invariants as the real server.
 */
async function startIssuerServer(opts: {
  service: CapabilityIssuerService;
  stateStore: OidcStateStore;
  idp: MockOidcIdentityProvider;
}): Promise<RunningServer> {
  const { service, stateStore, idp } = opts;

  return listen(async (req, res) => {
    const u = new URL(req.url ?? '/', 'http://localhost');
    const pathname = u.pathname;

    try {
      // ── GET /.well-known/jwks.json ─────────────────────────────────────
      if (req.method === 'GET' && pathname === '/.well-known/jwks.json') {
        const jwks = await service.getJwks();
        send(res, 200, jwks);
        return;
      }

      // ── GET /api/v1/oidc/authorize ─────────────────────────────────────
      if (req.method === 'GET' && pathname === '/api/v1/oidc/authorize') {
        const agentId = u.searchParams.get('agentId') ?? undefined;
        if (!agentId) {
          send(res, 400, {
            error: { code: 'INVALID_REQUEST', message: 'agentId is required' },
          });
          return;
        }
        const tenantId = u.searchParams.get('tenantId') ?? undefined;
        const { state, nonce } = await stateStore.createState({
          agentId,
          tenantId,
        });
        send(res, 200, { state, nonce });
        return;
      }

      // ── POST /api/v1/oidc/token ────────────────────────────────────────
      if (req.method === 'POST' && pathname === '/api/v1/oidc/token') {
        const body = (await readJsonBody(req)) as Record<string, unknown>;
        const { idToken, nonce, state, agentId, requestedCapabilities } = body;

        if (typeof idToken !== 'string' || !idToken) {
          send(res, 400, {
            error: { code: 'INVALID_REQUEST', message: 'idToken is required' },
          });
          return;
        }
        if (typeof agentId !== 'string' || !agentId) {
          send(res, 400, {
            error: { code: 'INVALID_REQUEST', message: 'agentId is required' },
          });
          return;
        }
        if (typeof nonce !== 'string' || !nonce) {
          send(res, 400, {
            error: { code: 'INVALID_REQUEST', message: 'nonce is required' },
          });
          return;
        }

        // --- Replay prevention (fail-closed) --------------------------------
        const tokenHash = crypto
          .createHash('sha256')
          .update(idToken)
          .digest('hex');
        const isNewToken = await stateStore.markIdTokenHashUsed(tokenHash);
        if (!isNewToken) {
          send(res, 401, {
            error: {
              code: 'AUTHENTICATION_FAILED',
              message: 'ID token has already been used — obtain a fresh token',
            },
          });
          return;
        }

        // --- Optional state binding -----------------------------------------
        if (typeof state === 'string' && state) {
          const pending = await stateStore.consumeState(state);
          if (!pending) {
            send(res, 401, {
              error: {
                code: 'AUTHENTICATION_FAILED',
                message:
                  'Unknown or expired state parameter — restart the authorization flow',
              },
            });
            return;
          }
          if (pending.nonce !== nonce) {
            send(res, 401, {
              error: {
                code: 'AUTHENTICATION_FAILED',
                message: 'Nonce mismatch — stored state nonce does not match',
              },
            });
            return;
          }
          if (pending.agentId && pending.agentId !== agentId) {
            send(res, 401, {
              error: {
                code: 'AUTHENTICATION_FAILED',
                message:
                  'agentId mismatch — request agentId does not match the stored state',
              },
            });
            return;
          }
        }

        // --- Validate id_token via IdP --------------------------------------
        let userContext: UserContext;
        try {
          userContext = await idp.validateToken(idToken);
        } catch (e) {
          send(res, 401, {
            error: {
              code: 'AUTHENTICATION_FAILED',
              message: e instanceof Error ? e.message : 'Token validation failed',
            },
          });
          return;
        }

        // --- Nonce claim binding (invariant 2) --------------------------------
        const tokenNonce = userContext.claims?.['nonce'] as string | undefined;
        if (!tokenNonce || tokenNonce !== nonce) {
          send(res, 401, {
            error: {
              code: 'AUTHENTICATION_FAILED',
              message:
                'Nonce claim in the ID token does not match the expected nonce',
            },
          });
          return;
        }

        // --- Issue capability token ------------------------------------------
        const response = await service.issueCapabilityFromUserContext({
          agentId,
          userContext,
          requestedCapabilities: Array.isArray(requestedCapabilities)
            ? (requestedCapabilities as import('@euno/common').CapabilityConstraint[])
            : undefined,
        });
        send(res, 200, response);
        return;
      }

      send(res, 404, { error: { code: 'NOT_FOUND', message: pathname } });
    } catch (e) {
      const err = e as { code?: string; message?: string; statusCode?: number };
      send(res, err.statusCode ?? 500, {
        error: {
          code: err.code ?? 'INTERNAL_ERROR',
          message: err.message ?? 'unknown error',
        },
      });
    }
  });
}

// ── Test harness ──────────────────────────────────────────────────────────────

interface CliIssuerHarness {
  mockIdpCtx: MockIdpContext;
  mockIdpServer: RunningServer;
  /** Issuer RS256 signer — exposed so tests can build a `JWTTokenVerifier`. */
  signer: JoseRsaSigner;
  stateStore: OidcStateStore;
  service: CapabilityIssuerService;
  issuerServer: RunningServer;
}

async function buildHarness(): Promise<CliIssuerHarness> {
  // 1. Mock IdP
  const mockIdpCtx = await createMockIdpContext();
  const mockIdpServer = await startMockIdpServer(mockIdpCtx);

  // 2. Signer + identity provider
  const signer = await createSigner();
  const idp = new MockOidcIdentityProvider(
    mockIdpCtx.publicKey,
    mockIdpCtx.issuer,
    mockIdpCtx.clientId,
  );

  // 3. State store + service
  const stateStore = new OidcStateStore();
  const service = new CapabilityIssuerService(
    signer,
    idp,
    'did:web:cli-it.issuer',
    900,
    createLogger('issuer-cli-it', 'test'),
  );

  // 4. Issuer HTTP server
  const issuerServer = await startIssuerServer({ service, stateStore, idp });

  return { mockIdpCtx, mockIdpServer, signer, stateStore, service, issuerServer };
}

async function teardownHarness(h: CliIssuerHarness): Promise<void> {
  await h.mockIdpServer.close();
  await h.issuerServer.close();
}

// ── PKCE flow helper ──────────────────────────────────────────────────────────

/**
 * Simulate the CLI's PKCE loopback exchange programmatically:
 *   1. GET issuer /api/v1/oidc/authorize?agentId=X  → { state, nonce }
 *   2. POST mock-IdP /token { nonce, sub, groups }   → { id_token }
 *   3. POST issuer /api/v1/oidc/token { ... }        → { token, expiresAt }
 */
async function runPkceFlow(
  h: CliIssuerHarness,
  agentId: string,
  opts?: { sub?: string; groups?: string[] },
): Promise<{
  state: string;
  nonce: string;
  idToken: string;
  capabilityToken: string;
  expiresAt: number;
}> {
  // Step 1: obtain state + nonce from issuer
  const authorizeResp = await fetch(
    `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=${encodeURIComponent(agentId)}`,
  );
  expect(authorizeResp.status).toBe(200);
  const { state, nonce } = (await authorizeResp.json()) as {
    state: string;
    nonce: string;
  };

  // Step 2: exchange with mock IdP (simulates the PKCE code exchange)
  const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      nonce,
      sub: opts?.sub ?? 'alice@corp.example',
      groups: opts?.groups ?? ['Administrator'],
    }),
  });
  expect(idpResp.status).toBe(200);
  const { id_token: idToken } = (await idpResp.json()) as {
    id_token: string;
  };

  // Step 3: submit id_token to issuer
  const issueResp = await fetch(
    `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ idToken, nonce, state, agentId }),
    },
  );
  expect(issueResp.status).toBe(200);
  const issueBody = (await issueResp.json()) as {
    token: string;
    expiresAt: number;
  };

  return {
    state,
    nonce,
    idToken,
    capabilityToken: issueBody.token,
    expiresAt: issueBody.expiresAt,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('CLI ↔ Issuer integration — PKCE loopback exchange (CR-3)', () => {
  let h: CliIssuerHarness;

  beforeEach(async () => {
    h = await buildHarness();
  });

  afterEach(async () => {
    await teardownHarness(h);
  });

  // ── Happy-path scenarios ─────────────────────────────────────────────────

  describe('happy path', () => {
    it('full PKCE flow produces a cryptographically valid RS256-signed JWT', async () => {
      const { capabilityToken, expiresAt } = await runPkceFlow(
        h,
        'cli-agent-1',
      );

      expect(capabilityToken).toBeDefined();
      expect(expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));

      // Verify the token signature with the issuer's real public key so the
      // test catches signing/algorithm/header regressions, not just token shape.
      // requireKid: true is safe because JoseRsaSigner.sign() includes `kid`
      // in the protected header, matching the production code path.
      const publicKeyPem = await h.signer.getPublicKey();
      const verifier = new JWTTokenVerifier(publicKeyPem, {
        requireKid: true,
        algorithms: ['RS256'],
      });
      const payload = await verifier.verify(capabilityToken);
      expect(payload.sub).toBe('cli-agent-1');
    });

    it('token payload has correct sub (agentId), iss, aud, and authorizedBy.userId', async () => {
      const { capabilityToken } = await runPkceFlow(h, 'cli-agent-2');

      const [, payloadB64] = capabilityToken.split('.');
      const payload = JSON.parse(
        Buffer.from(payloadB64!, 'base64url').toString('utf8'),
      ) as {
        sub: string;
        iss: string;
        aud: string;
        capabilities: unknown[];
        authorizedBy: { userId: string };
      };

      expect(payload.sub).toBe('cli-agent-2');
      expect(payload.iss).toBe('did:web:cli-it.issuer');
      expect(payload.aud).toBe('tool-gateway');
      expect(Array.isArray(payload.capabilities)).toBe(true);
      // The IdP resolved the user from the mock's `sub` claim.
      expect(payload.authorizedBy.userId).toBe('alice@corp.example');
    });

    it('token file written via saveCapabilityToken helper has 0600 Unix permissions', async () => {
      const { capabilityToken } = await runPkceFlow(h, 'cli-perms-test');

      // Use the actual CLI token-persistence helper (saveCapabilityToken from
      // public/packages/cli/src/token-utils.ts) — the same function the `euno
      // request` command calls after receiving the capability token — and assert
      // the resulting file mode without applying chmod inside the test.
      const tmpBase = path.join(
        os.tmpdir(),
        `euno-cli-it-${process.pid}-${Date.now()}`,
      );
      const tokenDir = path.join(tmpBase, 'tokens');

      const tokenPath = saveCapabilityToken(tokenDir, 'cli-perms-test', capabilityToken);

      const stat = fs.statSync(tokenPath);
      // Mask to the lower 9 permission bits (rwxrwxrwx).
      expect(stat.mode & 0o777).toBe(0o600);
      // Confirm the content written by the helper matches the original token.
      expect(fs.readFileSync(tokenPath, 'utf8')).toBe(capabilityToken);

      // Cleanup
      fs.rmSync(tmpBase, { recursive: true, force: true });
    });

    it('state binding: agentId bound to state is enforced — matching agentId succeeds', async () => {
      // GET authorize binds agentId to the state.
      const authResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=bound-agent`,
      );
      const { state, nonce } = (await authResp.json()) as {
        state: string;
        nonce: string;
      };

      const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          nonce,
          sub: 'alice@corp.example',
          groups: ['Administrator'],
        }),
      });
      const { id_token: idToken } = (await idpResp.json()) as {
        id_token: string;
      };

      const issueResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            idToken,
            nonce,
            state,
            agentId: 'bound-agent',
          }),
        },
      );
      expect(issueResp.status).toBe(200);
      const body = (await issueResp.json()) as { token: string };
      expect(body.token.split('.').length).toBe(3);
    });

    it('capabilities in the issued token come from the IdP-resolved role', async () => {
      const { capabilityToken } = await runPkceFlow(h, 'cli-agent-caps', {
        groups: ['Administrator'],
      });

      const [, payloadB64] = capabilityToken.split('.');
      const payload = JSON.parse(
        Buffer.from(payloadB64!, 'base64url').toString('utf8'),
      ) as { capabilities: Array<{ resource: string; actions: string[] }> };

      // Administrator role has api://** and storage://** capabilities.
      expect(payload.capabilities.length).toBeGreaterThan(0);
      const hasApiWild = payload.capabilities.some((c) =>
        c.resource.startsWith('api://'),
      );
      expect(hasApiWild).toBe(true);
    });
  });

  // ── Error-path scenarios ─────────────────────────────────────────────────

  describe('error paths', () => {
    it('nonce mismatch: id_token nonce ≠ request nonce → 401', async () => {
      const authResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=nonce-test-agent`,
      );
      const { state, nonce } = (await authResp.json()) as {
        state: string;
        nonce: string;
      };

      // Ask the IdP to sign a token with a *different* nonce.
      const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          nonce: 'wrong-nonce-value',
          sub: 'alice@corp.example',
          groups: ['Administrator'],
        }),
      });
      const { id_token: idToken } = (await idpResp.json()) as {
        id_token: string;
      };

      // Submit the mismatched id_token with the original nonce.
      const issueResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ idToken, nonce, state, agentId: 'nonce-test-agent' }),
        },
      );
      expect(issueResp.status).toBe(401);
      const body = (await issueResp.json()) as { error: { message: string } };
      expect(body.error.message.toLowerCase()).toMatch(/nonce/);
    });

    it('unknown state: invalid state parameter → 401', async () => {
      const authResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=state-test-agent`,
      );
      const { nonce } = (await authResp.json()) as { nonce: string };

      const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          nonce,
          sub: 'alice@corp.example',
          groups: ['Administrator'],
        }),
      });
      const { id_token: idToken } = (await idpResp.json()) as {
        id_token: string;
      };

      // Use a completely unknown state string.
      const issueResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            idToken,
            nonce,
            state: 'unknown-state-xyz-abcdef',
            agentId: 'state-test-agent',
          }),
        },
      );
      expect(issueResp.status).toBe(401);
      const body = (await issueResp.json()) as { error: { message: string } };
      expect(body.error.message.toLowerCase()).toMatch(/unknown|expired|state/);
    });

    it('id_token replay: second submission of the same token → 401', async () => {
      // First flow: succeeds.
      const authResp1 = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=replay-agent`,
      );
      const { state: state1, nonce: nonce1 } = (await authResp1.json()) as {
        state: string;
        nonce: string;
      };
      const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          nonce: nonce1,
          sub: 'alice@corp.example',
          groups: ['Administrator'],
        }),
      });
      const { id_token: idToken } = (await idpResp.json()) as {
        id_token: string;
      };

      const first = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            idToken,
            nonce: nonce1,
            state: state1,
            agentId: 'replay-agent',
          }),
        },
      );
      expect(first.status).toBe(200);

      // Second submission with the *same* id_token — replay must be blocked.
      // Obtain a fresh state so the test isn't blocked by "state already consumed".
      const authResp2 = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=replay-agent`,
      );
      const { state: state2, nonce: nonce2 } = (await authResp2.json()) as {
        state: string;
        nonce: string;
      };
      // Re-submit the SAME idToken (its hash is already marked used).
      const second = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            idToken,
            nonce: nonce2,
            state: state2,
            agentId: 'replay-agent',
          }),
        },
      );
      expect(second.status).toBe(401);
      const body = (await second.json()) as { error: { message: string } };
      expect(body.error.message.toLowerCase()).toContain('already been used');
    });

    it('invalid id_token (wrong signing key) → 401', async () => {
      const authResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=bad-sig-agent`,
      );
      const { state, nonce } = (await authResp.json()) as {
        state: string;
        nonce: string;
      };

      // Sign a token with a *different* key — signature verification must fail.
      const { privateKey: wrongKey } = await jose.generateKeyPair('ES256', {
        extractable: true,
      });
      const now = Math.floor(Date.now() / 1000);
      const badIdToken = await new jose.SignJWT({
        iss: h.mockIdpCtx.issuer,
        aud: h.mockIdpCtx.clientId,
        sub: 'alice@corp.example',
        nonce,
        iat: now,
        exp: now + 3600,
        groups: ['Administrator'],
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'wrong-key-id' })
        .sign(wrongKey);

      const issueResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            idToken: badIdToken,
            nonce,
            state,
            agentId: 'bad-sig-agent',
          }),
        },
      );
      expect(issueResp.status).toBe(401);
    });

    it('agentId mismatch with stored state → 401', async () => {
      // State is bound to 'agent-A'.
      const authResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize?agentId=agent-A`,
      );
      const { state, nonce } = (await authResp.json()) as {
        state: string;
        nonce: string;
      };

      const idpResp = await fetch(`${h.mockIdpServer.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          nonce,
          sub: 'alice@corp.example',
          groups: ['Administrator'],
        }),
      });
      const { id_token: idToken } = (await idpResp.json()) as {
        id_token: string;
      };

      // Submit with 'agent-B' — the stored state binds to 'agent-A'.
      const issueResp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ idToken, nonce, state, agentId: 'agent-B' }),
        },
      );
      expect(issueResp.status).toBe(401);
      const body = (await issueResp.json()) as { error: { message: string } };
      expect(body.error.message.toLowerCase()).toMatch(/agentid/);
    });

    it('missing agentId in POST /oidc/token → 400', async () => {
      const resp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ idToken: 'some.fake.token', nonce: 'n' }),
        },
      );
      expect(resp.status).toBe(400);
    });

    it('missing idToken in POST /oidc/token → 400', async () => {
      const resp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agentId: 'test-agent', nonce: 'n' }),
        },
      );
      expect(resp.status).toBe(400);
    });

    it('missing nonce in POST /oidc/token → 400', async () => {
      const resp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ idToken: 'some.fake.token', agentId: 'a' }),
        },
      );
      expect(resp.status).toBe(400);
    });

    it('missing agentId in GET /oidc/authorize → 400', async () => {
      const resp = await fetch(
        `${h.issuerServer.baseUrl}/api/v1/oidc/authorize`,
      );
      expect(resp.status).toBe(400);
    });
  });

  // ── JWKS endpoint ────────────────────────────────────────────────────────

  describe('JWKS endpoint', () => {
    it('GET /.well-known/jwks.json returns a JWKS with at least one key', async () => {
      const resp = await fetch(
        `${h.issuerServer.baseUrl}/.well-known/jwks.json`,
      );
      expect(resp.status).toBe(200);
      const body = (await resp.json()) as { keys: unknown[] };
      expect(Array.isArray(body.keys)).toBe(true);
      expect(body.keys.length).toBeGreaterThanOrEqual(1);
    });

    it('mock-IdP JWKS matches the key the mock-IdP signs with', async () => {
      const resp = await fetch(
        `${h.mockIdpServer.baseUrl}/.well-known/jwks.json`,
      );
      expect(resp.status).toBe(200);
      const body = (await resp.json()) as {
        keys: Array<{ kid: string; alg: string; use: string }>;
      };
      expect(body.keys.length).toBeGreaterThanOrEqual(1);
      const key = body.keys[0]!;
      expect(key.kid).toBe(h.mockIdpCtx.kid);
      expect(key.alg).toBe('ES256');
      expect(key.use).toBe('sig');
    });
  });

  // ── Discovery endpoint ───────────────────────────────────────────────────

  describe('mock-IdP discovery endpoint', () => {
    it('GET /.well-known/openid-configuration has expected fields', async () => {
      const resp = await fetch(
        `${h.mockIdpServer.baseUrl}/.well-known/openid-configuration`,
      );
      expect(resp.status).toBe(200);
      const body = (await resp.json()) as Record<string, unknown>;
      expect(body.issuer).toBe(h.mockIdpCtx.issuer);
      expect(body.token_endpoint).toBeDefined();
      expect(body.jwks_uri).toBeDefined();
      expect((body.id_token_signing_alg_values_supported as string[]).includes('ES256')).toBe(true);
    });
  });
});

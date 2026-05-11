/**
 * Task 3 — JWTTokenVerifier wiring integration tests.
 *
 * Verifies three contracts:
 *
 *   1. **TokenVerifier seam conformance** — `JwksTokenVerifier` structurally
 *      satisfies the `TokenVerifier` interface from
 *      `public/packages/common/src/runtime.ts:423`. TypeScript enforces this
 *      at compile time via the typed assignment; the runtime assertions make
 *      the guarantee explicit in the test output.
 *
 *   2. **Round-trip** — a JWT issued by `CapabilityIssuerService` (with a
 *      JWKS-discoverable `kid` in its protected header) is successfully
 *      verified by `JwksTokenVerifier` backed by `JwksClient`. This proves
 *      that the "single config change" wiring path (issuer → JWKS endpoint →
 *      gateway verifier) works end-to-end without a restart.
 *
 *   3. **Capability-model §6 invariant** — an unknown condition type embedded
 *      in a cryptographically-valid token is denied by the `EnforcementEngine`
 *      when the production `JwksTokenVerifier` is in use. Unknown types must
 *      never silently allow; this is the fail-closed forward-compatibility
 *      guarantee required by Stage 3 (see `docs/capability-model.md §6`).
 *
 * HTTP is fully mocked — no live servers required.
 */

import axios from 'axios';
import * as jose from 'jose';

import {
  CapabilityTokenPayload,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  IdentityAdapter,
  IdentityAdapterConfig,
  JwkSet,
  SigningAdapter,
  SigningAdapterConfig,
  SigningAlgorithm,
  TokenVerifier,
  UserContext,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import { JwksClient } from '../../tool-gateway/src/jwks-client';
import { JWTTokenVerifier, JwksTokenVerifier } from '../../tool-gateway/src/verifier';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// ── Constants ─────────────────────────────────────────────────────────────────

const SIGNING_ALG = 'RS256' as const;
const ISSUER_DID = 'did:web:task3-issuer.test';
const JWKS_URL = 'http://task3-issuer.test/.well-known/jwks.json';
const KEY_ID = 'task3-key-1';

// ── Stubs ─────────────────────────────────────────────────────────────────────

/**
 * Minimal identity adapter that accepts any non-empty auth token and returns
 * a fixed user context with the Administrator role.
 */
class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  private readonly context: UserContext;

  constructor(roles: string[] = ['Administrator']) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
    this.context = {
      userId: 'user-task3',
      email: 'user@task3.test',
      roles,
      tenantId: 'tenant-task3',
      claims: {},
    };
  }

  async validateToken(token: string): Promise<UserContext> {
    if (!token) throw new Error('missing auth token');
    return this.context;
  }

  async getUserRoles(): Promise<string[]> {
    return this.context.roles;
  }
}

/**
 * RS256 signing adapter backed by an in-memory key pair. Stamps every JWT
 * protected header with both `alg` and `kid` so the JWKS cache can resolve
 * the key by ID — exactly the production configuration.
 *
 * Also exposes `privateKey` and `jwk` for use by the test helpers that mint
 * tokens directly (bypassing the issuer's condition validation).
 */
class JoseRsaSignerWithKid extends SigningAdapter {
  readonly privateKey: jose.KeyLike;
  readonly publicKeyPem: string;
  readonly kid: string;
  /** Exported JWK of the public key (used to populate the mock JWKS endpoint). */
  readonly jwk: Record<string, unknown>;

  constructor(
    privateKey: jose.KeyLike,
    publicKeyPem: string,
    kid: string,
    jwk: Record<string, unknown>,
  ) {
    super({ type: 'jose-rsa', name: 'jose-rsa', algorithm: SIGNING_ALG } as SigningAdapterConfig);
    this.privateKey = privateKey;
    this.publicKeyPem = publicKeyPem;
    this.kid = kid;
    this.jwk = jwk;
  }

  override getAlgorithm(): SigningAlgorithm {
    // The base class `SigningAdapter.getAlgorithm()` already returns
    // `this.algorithm`, which is initialized from `config.algorithm = SIGNING_ALG`
    // in the constructor. This override is explicit for clarity so the test
    // fixture documents that the published JWK will include `alg: 'RS256'`
    // (the base-class method satisfies the `getAlgorithm?()` on `TokenSigner`
    // that `CapabilityIssuerService.getJwks()` calls to stamp `alg` in the JWKS).
    return SIGNING_ALG;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: SIGNING_ALG, kid: this.kid })
      .sign(this.privateKey);
  }

  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return this.kid;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Generate a fresh RSA key pair and return a ready-to-use signer. */
async function createSigner(): Promise<JoseRsaSignerWithKid> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  const exported = await jose.exportJWK(publicKey);
  const jwk: Record<string, unknown> = {
    ...exported,
    kid: KEY_ID,
    use: 'sig',
    alg: SIGNING_ALG,
    kty: exported.kty,
  };
  return new JoseRsaSignerWithKid(privateKey, publicKeyPem, KEY_ID, jwk);
}

/**
 * Build a `JwksClient` pointing at {@link JWKS_URL} and set up the axios mock
 * to return `jwks` for every GET to that URL.
 */
function makeJwksClient(jwks: JwkSet): JwksClient {
  mockedAxios.get.mockResolvedValue({ data: jwks });
  return new JwksClient({ jwksUrl: JWKS_URL, cacheTtlMs: 60_000 });
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe('Task 3 — JWTTokenVerifier wiring', () => {
  let signer: JoseRsaSignerWithKid;
  let issuerService: CapabilityIssuerService;

  beforeAll(async () => {
    signer = await createSigner();
    issuerService = new CapabilityIssuerService(
      signer,
      new StubIdentityProvider(['Administrator']),
      ISSUER_DID,
      900,
      createLogger('task3-issuer', 'test'),
    );
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ── 1. TokenVerifier seam conformance ──────────────────────────────────────

  describe('TokenVerifier seam conformance (runtime.ts:423)', () => {
    it('JwksTokenVerifier is assignable to TokenVerifier from @euno/common-core', () => {
      // The typed assignment is the primary compile-time assertion.
      // If JwksTokenVerifier diverges from the TokenVerifier interface
      // (e.g. an added required parameter or a return-type mismatch),
      // tsc rejects this file before Jest even runs.
      const client = new JwksClient({ jwksUrl: JWKS_URL });
      const verifier: TokenVerifier = new JwksTokenVerifier(client, { requireKid: false });

      expect(typeof verifier.verify).toBe('function');
      expect(typeof verifier.isRevoked).toBe('function');
    });

    it('JWTTokenVerifier is assignable to TokenVerifier from @euno/common-core', () => {
      const { publicKeyPem } = signer;
      const verifier: TokenVerifier = new JWTTokenVerifier(publicKeyPem, { requireKid: false });

      expect(typeof verifier.verify).toBe('function');
      expect(typeof verifier.isRevoked).toBe('function');
    });
  });

  // ── 2. Round-trip: issuer → JwksTokenVerifier ─────────────────────────────

  describe('Round-trip: CapabilityIssuerService → JwksTokenVerifier', () => {
    it('verifies a token issued by CapabilityIssuerService using JwksTokenVerifier backed by JwksClient', async () => {
      // Step 1: Issue a real capability token via CapabilityIssuerService.
      const issued = await issuerService.issueCapability({
        authToken: 'user-bearer-token',
        agentId: 'agent-task3',
      });
      expect(issued.token).toBeTruthy();

      // Step 2: Derive the JWKS that the issuer would publish at its
      //         /.well-known/jwks.json endpoint.
      const jwks = await issuerService.getJwks();
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0]!.kid).toBe(KEY_ID);
      expect(jwks.keys[0]!.alg).toBe(SIGNING_ALG);

      // Step 3: Wire the JwksClient and JwksTokenVerifier just as the gateway
      //         bootstrap does (bootstrap.ts Step 9, Step 7).
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, {
        algorithms: [SIGNING_ALG],
        requireKid: true,
      });

      // Step 4: Verify the issued token — this is the round-trip assertion.
      const payload = await verifier.verify(issued.token);

      expect(payload.iss).toBe(ISSUER_DID);
      expect(payload.sub).toBe('agent-task3');
      expect(payload.aud).toBe('tool-gateway');
      expect(payload.schemaVersion).toBe(CAPABILITY_TOKEN_SCHEMA_VERSION);
      expect(payload.capabilities.length).toBeGreaterThan(0);

      // Exactly one JWKS fetch: the initial cache population triggered by
      // verifying the token (kid present → no forced refresh needed).
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
      expect(mockedAxios.get).toHaveBeenCalledWith(JWKS_URL, expect.any(Object));
    });

    it('isRevoked returns false for a freshly-issued token (not yet revoked)', async () => {
      const issued = await issuerService.issueCapability({
        authToken: 'user-bearer-token',
        agentId: 'agent-task3-revoke',
      });

      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });

      // Verify so the payload is decoded.
      const payload = await verifier.verify(issued.token);
      expect(payload.jti).toBeTruthy();

      // The token has not been revoked.
      const revoked = await verifier.isRevoked(payload.jti as string);
      expect(revoked).toBe(false);
    });

    it('rejects a token whose kid is not present in the issuer JWKS', async () => {
      // Mint a token with a phantom kid that the JWKS never contains.
      const phantomToken = await new jose.SignJWT({
        iss: ISSUER_DID,
        sub: 'agent-phantom',
        aud: 'tool-gateway',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: 'phantom-jti',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [{ resource: 'api://svc', actions: ['read'] }],
      })
        .setProtectedHeader({ alg: SIGNING_ALG, kid: 'phantom-key' })
        .sign(signer.privateKey);

      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      // Both initial fetch and forced-refresh return the same JWKS (no phantom-key).
      mockedAxios.get.mockResolvedValue({ data: jwks });
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });

      await expect(verifier.verify(phantomToken)).rejects.toMatchObject({
        code: 'INVALID_TOKEN',
      });
    });

    it('rejects a token without a kid when requireKid=true', async () => {
      // Mint a token with no kid header.
      const noKidToken = await new jose.SignJWT({
        iss: ISSUER_DID,
        sub: 'agent-nokid',
        aud: 'tool-gateway',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: 'nokid-jti',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [{ resource: 'api://svc', actions: ['read'] }],
      })
        .setProtectedHeader({ alg: SIGNING_ALG }) // no kid
        .sign(signer.privateKey);

      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });

      await expect(verifier.verify(noKidToken)).rejects.toMatchObject({
        code: 'INVALID_TOKEN',
      });
    });
  });

  // ── 3. Capability-model §6 invariant ──────────────────────────────────────

  describe('§6 invariant: unknown condition types are denied (capability-model §6)', () => {
    /**
     * Mint a token directly with jose.SignJWT using the issuer's live key pair.
     * This bypasses the issuer's issuance-time condition validation so we can
     * embed an unknown condition type that a real issuer would reject.
     *
     * The token still carries a valid signature from a key in the JWKS, so the
     * `JwksTokenVerifier` will accept it — the invariant we are testing is that
     * the `EnforcementEngine` (enforceConditions) denies unknown types even
     * when the token's cryptography is sound.
     */
    async function mintTokenWithUnknownCondition(signer: JoseRsaSignerWithKid): Promise<string> {
      return new jose.SignJWT({
        iss: ISSUER_DID,
        sub: 'agent-task3-section6',
        aud: 'tool-gateway',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: `section6-${Math.random()}`,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [
          {
            resource: 'api://service/protected',
            actions: ['read'],
            // Embed an unknown condition type — a future issuer might mint
            // this; the gateway must deny rather than silently allow.
            conditions: [
              { type: 'futureConditionType', someParam: 'value' },
            ],
          },
        ],
      } as jose.JWTPayload)
        .setProtectedHeader({ alg: SIGNING_ALG, kid: signer.kid })
        .sign(signer.privateKey);
    }

    it('EnforcementEngine denies an unknown condition type when using JwksTokenVerifier', async () => {
      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });
      const engine = new EnforcementEngine({
        verifier,
        logger: createLogger('task3-engine', 'test'),
        dpop: { required: false },
      });

      const token = await mintTokenWithUnknownCondition(signer);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/protected',
      });

      expect(result.allowed).toBe(false);
      // The denial reason must name the unknown condition type so operators
      // can identify what needs to be added to their gateway deployment.
      expect(result.reason).toMatch(/futureConditionType/);
    });

    it('JwksTokenVerifier.verify() succeeds for the same token (signature is valid; §6 is an enforcement-layer invariant)', async () => {
      // This test is the complementary assertion: the verifier itself does not
      // reject the unknown condition — that responsibility belongs to the
      // enforcement layer (enforceConditions in EnforcementEngine.validateAction).
      // Both assertions together prove the full §6 invariant: the token passes
      // cryptographic verification but is denied at enforcement time.
      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });

      const token = await mintTokenWithUnknownCondition(signer);

      // Signature verification passes — the token is cryptographically sound.
      const payload = await verifier.verify(token);
      expect(payload.iss).toBe(ISSUER_DID);
      const cap = payload.capabilities[0];
      expect(cap).toBeDefined();
      // The unknown condition round-tripped intact through the signed JWT.
      const conditions = cap!.conditions;
      expect(Array.isArray(conditions)).toBe(true);
      const firstCondition = (conditions as Array<{ type: string }>)[0];
      expect(firstCondition).toBeDefined();
      expect(firstCondition!.type).toBe('futureConditionType');
    });

    it('tokens with only known condition types are allowed by the EnforcementEngine', async () => {
      // Control case: a token with a known condition type (timeWindow) is allowed
      // by the engine. This confirms the deny is condition-type-specific, not a
      // blanket denial of all conditioned tokens.
      const now = Math.floor(Date.now() / 1000);
      const token = await new jose.SignJWT({
        iss: ISSUER_DID,
        sub: 'agent-task3-control',
        aud: 'tool-gateway',
        iat: now,
        exp: now + 300,
        jti: `control-${Math.random()}`,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [
          {
            resource: 'api://service/control',
            actions: ['read'],
            conditions: [
              {
                type: 'timeWindow',
                notBefore: new Date(Date.now() - 60_000).toISOString(),
                notAfter: new Date(Date.now() + 60_000).toISOString(),
              },
            ],
          },
        ],
      } as jose.JWTPayload)
        .setProtectedHeader({ alg: SIGNING_ALG, kid: signer.kid })
        .sign(signer.privateKey);

      const jwks = await issuerService.getJwks();
      const client = makeJwksClient(jwks);
      const verifier = new JwksTokenVerifier(client, { algorithms: [SIGNING_ALG], requireKid: true });
      const engine = new EnforcementEngine({
        verifier,
        logger: createLogger('task3-engine-control', 'test'),
        dpop: { required: false },
      });

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/control',
      });

      expect(result.allowed).toBe(true);
    });
  });
});

/**
 * Shared in-process fixtures for the perf scenarios.
 *
 * Implements the load-test-artefacts deliverable from I-22
 * (`docs/IMPROVEMENTS_AND_REFACTORING.md`). Stands up:
 *
 *   - A real Tool Gateway via `createApp(deps)` — full middleware stack
 *     (helmet, tracing, prometheus, JSON parser, CORS, rate-limit) so
 *     the latency the load generator measures is what production agents
 *     would actually see.
 *   - A thin HTTP wrapper around `CapabilityIssuerService` mirroring the
 *     pattern used by `tests/e2e.test.ts` (the issuer has no app-factory
 *     yet — when R-1 lands here, swap the wrapper for `createApp(deps)`).
 *   - A stub HTTP backend the gateway's `/proxy/*` route forwards to,
 *     so proxy throughput is dominated by enforcement + the proxy hop
 *     and not by an unrelated upstream.
 *
 * Everything binds to `127.0.0.1` on an ephemeral port so multiple
 * scenarios can run sequentially without colliding.
 */

import * as http from 'http';
import { AddressInfo } from 'net';
import * as jose from 'jose';
import express from 'express';

import {
  BUILTIN_ACTION_RESOLVER,
  CapabilityTokenPayload,
  Counter,
  IdentityAdapter,
  IdentityAdapterConfig,
  ServiceConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  createKillSwitchManagerFromEnv,
  createLogger,
  createMetricsRegistry,
} from '@euno/common';
import { CapabilityIssuerService } from '../../../capability-issuer/src/issuer-service';
import { createApp as createGatewayApp } from '../../../tool-gateway/src/app-factory';
import type { GatewayDependencies } from '../../../tool-gateway/src/bootstrap';
import { EnforcementEngine } from '../../../tool-gateway/src/enforcement';
import { JWTTokenVerifier } from '../../../tool-gateway/src/verifier';

// ── Constants ────────────────────────────────────────────────────────────────

export const ISSUER_DID = 'did:web:perf.issuer.test';
export const SIGNING_ALG = 'RS256';
export const AUDIENCE = 'tool-gateway';
const ISSUANCE_USER_TOKEN = 'perf-user-token';

// ── Identity / signer ────────────────────────────────────────────────────────

class StaticIdentityProvider extends IdentityAdapter {
  public readonly name = 'perf-stub';
  constructor(private context: UserContext) {
    super({ type: 'perf-stub', name: 'perf-stub' } as unknown as IdentityAdapterConfig);
  }
  async validateToken(_token: string): Promise<UserContext> {
    return this.context;
  }
  async getUserRoles(): Promise<string[]> {
    return this.context.roles;
  }
}

class JoseRsaSigner extends SigningAdapter {
  constructor(
    private privateKey: jose.KeyLike,
    private publicKeyPem: string,
    private kid: string,
  ) {
    super({ type: 'jose-rsa', name: 'jose-rsa', algorithm: SIGNING_ALG } as unknown as SigningAdapterConfig);
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

async function createSigner(): Promise<JoseRsaSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, {
    extractable: true,
  });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  return new JoseRsaSigner(privateKey, publicKeyPem, 'perf-key-1');
}

/**
 * Silence the `auditLogger` private field on a service instance.
 * `winston` loggers honour a `silent: true` switch on each transport
 * (and a `level: 'silent'` on the logger itself), so we set both — the
 * cheapest way to drop every record on the floor without rewiring the
 * service. Used only by the perf harness; production code paths are
 * untouched.
 */
function silenceAuditLogger(svc: Record<string, unknown>): void {
  const logger = svc['auditLogger'] as
    | { level: string; transports: { silent: boolean }[] }
    | undefined;
  if (!logger) return;
  logger.level = 'silent';
  for (const t of logger.transports) {
    t.silent = true;
  }
}

// ── HTTP servers ─────────────────────────────────────────────────────────────

export interface RunningServer {
  baseUrl: string;
  close: () => Promise<void>;
}

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) return resolve({});
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
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise<void>((r) => {
            // `close()` waits for in-flight requests to complete, but the
            // upstream connections held open by http-proxy-middleware
            // never finish on their own when autocannon abruptly closes
            // its own keep-alive sockets. Force-close everything so the
            // perf runner can move on to the next scenario without
            // wedging the event loop.
            server.closeAllConnections?.();
            server.closeIdleConnections?.();
            server.close(() => r());
          }),
      });
    });
  });
}

function listenExpress(app: express.Express): Promise<RunningServer> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise<void>((r) => {
            server.closeAllConnections?.();
            server.closeIdleConnections?.();
            server.close(() => r());
          }),
      });
    });
  });
}

/**
 * Spin up a minimal Issuer HTTP front mirroring the production
 * routes. We mirror **every externally observable route** the
 * production `capability-issuer/src/index.ts` Express app exposes so
 * the perf scenarios can defend their SLOs:
 *
 *   GET  /health                             — liveness probe
 *   GET  /metrics                            — Prometheus scrape
 *   GET  /.well-known/jwks.json              — JWKS (live key-distribution path)
 *   GET  /.well-known/did.json               — DID document
 *   GET  /.well-known/capability-issuer      — issuer metadata
 *   GET  /api/v1/public-key                  — DEPRECATED legacy fetch
 *   POST /api/v1/issue                       — issue a fresh capability
 *   POST /api/v1/attenuate                   — attenuate parent → child
 *   POST /api/v1/renew                       — renew an existing capability
 *
 * The wrapper intentionally re-implements only the request/response
 * envelope; every code path delegates to the real
 * `CapabilityIssuerService`, so the latency the load generator
 * measures is the same hot path production runs.
 */
async function startIssuerServer(
  service: CapabilityIssuerService,
  signer: JoseRsaSigner,
  metricsRegistry: ReturnType<typeof createMetricsRegistry>,
): Promise<RunningServer> {
  // R-3 attribute: production stamps `issuer` and `service` labels via
  // `createMetricsRegistry`, and the prom-client `register.metrics()`
  // call handles serialisation. We keep that exact behaviour.
  const issuerDid = ISSUER_DID;
  return listen(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        return send(res, 200, { status: 'healthy', service: 'capability-issuer' });
      }
      if (req.method === 'GET' && req.url === '/metrics') {
        const body = await metricsRegistry.metrics();
        res.statusCode = 200;
        res.setHeader('content-type', metricsRegistry.contentType);
        return res.end(body);
      }
      if (req.method === 'GET' && req.url === '/.well-known/jwks.json') {
        return send(res, 200, await service.getJwks());
      }
      if (req.method === 'GET' && req.url === '/.well-known/did.json') {
        const publicKey = await signer.getPublicKey();
        return send(res, 200, {
          '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/jws-2020/v1',
          ],
          id: issuerDid,
          verificationMethod: [
            {
              id: `${issuerDid}#key-1`,
              type: 'JsonWebKey2020',
              controller: issuerDid,
              publicKeyPem: publicKey,
            },
          ],
          authentication: [`${issuerDid}#key-1`],
          assertionMethod: [`${issuerDid}#key-1`],
        });
      }
      if (req.method === 'GET' && req.url === '/.well-known/capability-issuer') {
        return send(res, 200, {
          issuer: issuerDid,
          schemaVersions: { current: 1, supported: [1] },
          signingAlgorithms: [SIGNING_ALG],
          endpoints: {
            jwks: '/.well-known/jwks.json',
            publicKey: '/api/v1/public-key (deprecated — use jwks)',
            didDocument: '/.well-known/did.json',
          },
        });
      }
      if (req.method === 'GET' && req.url === '/api/v1/public-key') {
        return send(res, 200, {
          publicKey: await signer.getPublicKey(),
          keyId: await signer.getKeyId(),
        });
      }
      if (req.method === 'POST' && req.url === '/api/v1/issue') {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
        if (!token) return send(res, 401, { error: { code: 'AUTHENTICATION_FAILED' } });
        const body = (await readJsonBody(req)) as { agentId?: string };
        if (!body?.agentId) return send(res, 400, { error: { code: 'INVALID_REQUEST' } });
        const result = await service.issueCapability({ authToken: token, agentId: body.agentId });
        return send(res, 200, result);
      }
      if (req.method === 'POST' && req.url === '/api/v1/attenuate') {
        const auth = req.headers.authorization || '';
        const parent = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
        if (!parent) return send(res, 401, { error: { code: 'AUTHENTICATION_FAILED' } });
        const body = (await readJsonBody(req)) as {
          requestedCapabilities?: unknown;
          ttl?: number;
        };
        if (!Array.isArray(body?.requestedCapabilities)) {
          return send(res, 400, { error: { code: 'INVALID_REQUEST' } });
        }
        const result = await service.attenuateCapability(
          parent,
          body.requestedCapabilities as never,
          body.ttl,
        );
        return send(res, 200, result);
      }
      if (req.method === 'POST' && req.url === '/api/v1/renew') {
        const auth = req.headers.authorization || '';
        const current = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
        if (!current) return send(res, 401, { error: { code: 'AUTHENTICATION_FAILED' } });
        const body = (await readJsonBody(req)) as { ttl?: number };
        const result = await service.renewCapability(current, body?.ttl);
        return send(res, 200, result);
      }
      send(res, 404, { error: { code: 'NOT_FOUND' } });
    } catch (e) {
      const err = e as { statusCode?: number; code?: string; message?: string };
      send(res, err.statusCode || 500, {
        error: { code: err.code || 'INTERNAL_ERROR', message: err.message || 'unknown' },
      });
    }
  });
}

/** Stub backend used by the gateway's `/proxy/*` route. */
async function startStubBackend(): Promise<RunningServer> {
  return listen((req, res) => {
    // Drain request body so keep-alive works for POST scenarios, but
    // keep handling cheap so the perf cost is dominated by the gateway.
    req.on('data', () => undefined);
    req.on('end', () => {
      send(res, 200, { ok: true, method: req.method, path: req.url ?? '' });
    });
  });
}

// ── Top-level harness ────────────────────────────────────────────────────────

export interface PerfHarness {
  /** Real Tool Gateway HTTP base URL (e.g. http://127.0.0.1:1234). */
  gatewayUrl: string;
  /** Issuer HTTP base URL. */
  issuerUrl: string;
  /** Backend echo HTTP base URL. */
  backendUrl: string;
  /** A capability token bound to AUDIENCE that grants every action on `**`. */
  capabilityTokenAdmin: string;
  /** A capability token whose role is `Viewer` — every write attempt 403s. */
  capabilityTokenViewer: string;
  /** Spare admin token used as the parent for `issuer-renew`. */
  capabilityTokenRenewable: string;
  /** Plain-text bearer token accepted by the stub identity provider. */
  userAuthToken: string;
  /** API key the gateway's `/admin/*` routes require. */
  adminApiKey: string;
  /** Tear down all in-process servers. */
  shutdown: () => Promise<void>;
}

/**
 * Build the full harness once per scenario run.
 *
 * Note we intentionally use a fresh-per-run `MetricsRegistry` and
 * `KillSwitchManager` so scenarios cannot leak state into each other
 * — each `runScenario` call starts from a known clean slate.
 */
export async function buildHarness(): Promise<PerfHarness> {
  const signer = await createSigner();
  const adminIdentity = new StaticIdentityProvider({
    userId: 'perf-admin',
    email: 'admin@perf.test',
    roles: ['Administrator'],
    tenantId: 'perf-tenant',
    claims: {},
  });
  const viewerIdentity = new StaticIdentityProvider({
    userId: 'perf-viewer',
    email: 'viewer@perf.test',
    roles: ['Viewer'],
    tenantId: 'perf-tenant',
    claims: {},
  });

  // Logger noise would dominate the perf hot path; pin to `error` so
  // the runner reports steady-state cost, not console formatting cost.
  const issuerLogger = createLogger('perf-issuer', 'production');
  issuerLogger.level = 'error';

  // Default role-policy map (`DEFAULT_ROLE_CAPABILITY_MAP`) only
  // grants `api://**` and `storage://**` to Administrator; the
  // gateway's tools route canonicalises every invocation to
  // `tool://<name>` so the default policy cannot authorise any tool
  // call. For perf we add a permissive `tool://**` grant so the
  // *allow* tools/invoke scenario actually exercises the success
  // path; the *deny* scenario uses the Viewer role which still has
  // no `tool://` grant and so still 403s as expected.
  const perfPolicy = {
    default: {
      Administrator: [
        { resource: 'tool://**', actions: ['read', 'write', 'delete', 'admin'] },
        { resource: 'api://**', actions: ['read', 'write', 'admin'] },
      ],
      Viewer: [{ resource: 'api://**', actions: ['read'] }],
    },
  };
  const adminService = new CapabilityIssuerService(
    signer,
    adminIdentity,
    ISSUER_DID,
    900,
    issuerLogger,
    { policy: perfPolicy as never },
  );
  const viewerService = new CapabilityIssuerService(
    signer,
    viewerIdentity,
    ISSUER_DID,
    900,
    issuerLogger,
    { policy: perfPolicy as never },
  );
  // CapabilityIssuerService creates its own internal `audit` winston
  // logger that defaults to `info` and writes to stdout. For perf runs
  // we silence it: every issuance would otherwise emit a multi-KB JSON
  // line per request, swamping CI output and skewing the latency
  // histogram with format/serialise cost that doesn't reflect what
  // production sees (production ships these to Console+CloudWatch
  // asynchronously). Field is private but the cost of *not* doing this
  // here is large enough to justify the reflection.
  silenceAuditLogger(adminService as unknown as Record<string, unknown>);
  silenceAuditLogger(viewerService as unknown as Record<string, unknown>);

  // Issuer-side metrics registry. Production wires this in
  // `capability-issuer/src/index.ts`; we mirror it so the
  // `issuer-metrics` scenario exercises the same scrape surface
  // (Node default collectors + the issuance counter).
  const issuerMetricsRegistry = createMetricsRegistry({
    serviceName: 'capability-issuer',
  });
  const issuanceCounter = new Counter({
    name: 'euno_issuer_issuance_total',
    help: 'Capability-issuance operations, labelled by operation and outcome.',
    labelNames: ['operation', 'outcome'],
    registers: [issuerMetricsRegistry],
  });
  // Pre-initialise series so `rate()` queries succeed before traffic flows.
  issuanceCounter.inc({ operation: 'issue', outcome: 'success' }, 0);
  issuanceCounter.inc({ operation: 'attenuate', outcome: 'success' }, 0);
  issuanceCounter.inc({ operation: 'renew', outcome: 'success' }, 0);

  const issuerServer = await startIssuerServer(adminService, signer, issuerMetricsRegistry);
  const backendServer = await startStubBackend();

  // Mint two long-lived tokens for the gateway scenarios. We mint
  // these once and reuse them across requests — the issuance scenario
  // exercises the issuer hot path separately. We also mint a spare
  // admin token used by the `issuer-renew` scenario (renew rejects
  // tokens that are already in the revocation list, so re-using the
  // gateway's token would skew steady-state cost).
  const adminCap = await adminService.issueCapability({
    authToken: ISSUANCE_USER_TOKEN,
    agentId: 'perf-agent-admin',
  });
  const viewerCap = await viewerService.issueCapability({
    authToken: ISSUANCE_USER_TOKEN,
    agentId: 'perf-agent-viewer',
  });
  const renewableCap = await adminService.issueCapability({
    authToken: ISSUANCE_USER_TOKEN,
    agentId: 'perf-agent-renew',
  });

  // Build a fully-wired gateway, hand-rolling deps the same way
  // bootstrap.initializeServices() would but skipping every external
  // I/O dependency (Redis, KMS, OCSF transport).
  const gatewayLogger = createLogger('perf-gateway', 'production');
  gatewayLogger.level = 'error';
  const verifier = new JWTTokenVerifier(await signer.getPublicKey(), [SIGNING_ALG]);
  const enforcementEngine = new EnforcementEngine({
    verifier,
    logger: gatewayLogger,
  });
  silenceAuditLogger(enforcementEngine as unknown as Record<string, unknown>);
  const killSwitchManager = await createKillSwitchManagerFromEnv({}, gatewayLogger);
  // Match the production registry shape: production calls
  // `createMetricsRegistry({ serviceName: 'tool-gateway' })` which
  // enables `collectDefaults` (process_cpu_seconds_total,
  // nodejs_eventloop_lag_seconds, …). The /metrics scenario is a
  // proxy for the Prometheus scrape surface, so its payload size and
  // serialisation cost must match what an operator would see in
  // production — disabling defaults here would have made the
  // scenario meaningless.
  const metricsRegistry = createMetricsRegistry({
    serviceName: 'tool-gateway',
  });
  // Production uses `euno_gateway_decisions_total` (see
  // `bootstrap.ts` and `enforcement.ts`); use the same name +
  // bootstrap pattern so the scenario exercises (and defends) the
  // exact series operators scrape.
  const decisionsCounter = new Counter({
    name: 'euno_gateway_decisions_total',
    help: 'Authorization decisions made by the gateway, labelled allow|deny.',
    labelNames: ['decision'],
    registers: [metricsRegistry],
  });
  decisionsCounter.inc({ decision: 'allow' }, 0);
  decisionsCounter.inc({ decision: 'deny' }, 0);
  // Bootstrap wires the counter to the engine via setDecisionRecorder
  // (the engine doesn't write to the counter directly). Mirror that
  // wiring so the /metrics scenario observes the gateway-decisions
  // series getting populated, the same as production.
  enforcementEngine.setDecisionRecorder((decision) => {
    decisionsCounter.inc({ decision });
  });

  // Admin endpoints require an API key when one is configured. Set
  // one here so the perf scenario for `/admin/kill-switch/status`
  // can authenticate; leaving it unset would make the route
  // unauthenticated, which is *not* the production hot path.
  const adminApiKey = 'perf-admin-key';

  const serviceConfig: ServiceConfig = {
    name: 'tool-gateway-perf',
    port: 0,
    environment: 'production',
    enableCryptographicAudit: false,
    policyVersion: '1.0.0',
  };

  const gatewayDeps: GatewayDependencies = {
    config: serviceConfig,
    logger: gatewayLogger,
    verifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: backendServer.baseUrl,
    allowedOrigins: [],
    // Disable rate limiting for perf — the test driver and the SUT live
    // on the same loopback IP, so the per-IP limiter would otherwise
    // throttle long runs and make the scenario meaningless. The SLO
    // floor on throughput defends the unrate-limited critical path.
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000_000,
    metricsRegistry,
    decisionsCounter,
    auditPipelineDrainTimeoutMs: 0,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    isReady: () => true,
    adminApiKey,
  };

  const app = createGatewayApp(gatewayDeps);
  const gatewayServer = await listenExpress(app);

  return {
    gatewayUrl: gatewayServer.baseUrl,
    issuerUrl: issuerServer.baseUrl,
    backendUrl: backendServer.baseUrl,
    capabilityTokenAdmin: adminCap.token,
    capabilityTokenViewer: viewerCap.token,
    capabilityTokenRenewable: renewableCap.token,
    userAuthToken: ISSUANCE_USER_TOKEN,
    adminApiKey,
    shutdown: async () => {
      await Promise.all([
        gatewayServer.close(),
        issuerServer.close(),
        backendServer.close(),
      ]);
      await killSwitchManager.close?.();
    },
  };
}

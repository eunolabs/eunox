/**
 * Tool Gateway bootstrap
 * ---------------------------------------------------------------------------
 * Sequences the three concern modules (dpop-module, revocation-module,
 * audit-module) and performs final wiring: JWKS client, action resolver,
 * verifier, enforcement engine. Hands the completed dependency bag to
 * `createApp(deps)`.
 *
 * `app-factory.ts` remains a pure composition function with no env reads,
 * no I/O and no listening.
 *
 * See R-2, R-3 in `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  ActionResolver,
  AuditPipeline,
  BUILTIN_ACTION_RESOLVER,
  AzureConfidentialLedgerClient,
  CrossChainAnchor,
  createLogger,
  createOcsfTransportFromEnv,
  createOcsfWinstonTransport,
  createMetricsRegistry,
  Counter,
  DpopReplayStore,
  EvidenceSigner,
  Gauge,
  GatewayConfig,
  GatewayQuotaEngine,
  CallCounterBackedGatewayQuotaEngine,
  KillSwitchManager,
  loadActionResolverFromFileWithHash,
  computeActionResolverHash,
  loadConfigOrExit,
  loadConfig,
  OcsfAuditTransport,
  Registry,
  ServiceConfig,
  CallCounterStore,
  UsageMeter,
  createUsageMeterFromEnv,
} from '@euno/common';
import { JWTTokenVerifier, JwksTokenVerifier } from './verifier';
import { buildProofsVerifierFromEnv } from './proofs-verifier-bootstrap';
import { JwksClient } from './jwks-client';
import { EnforcementEngine } from './enforcement';
import { RevocationStore, RevocationEpochStore } from './revocation-store';
import {
  InMemoryPartnerDidRegistry,
  RedisPartnerDidRegistry,
} from './partner-did-registry';
import { buildDpopModule } from './dpop-module';
import { buildRevocationModule } from './revocation-module';
import { buildAuditModule } from './audit-module';
import {
  GatewayTelemetryCollector,
  createGatewayTelemetryFromEnv,
} from './gateway-telemetry';

type Logger = ReturnType<typeof createLogger>;

/**
 * Fully-wired runtime dependencies handed to `createApp(deps)`.
 *
 * The bag is intentionally explicit so the factory can be invoked from
 * tests with hand-rolled fakes (no env, no Redis, no HTTP).
 */
export interface GatewayDependencies {
  config: ServiceConfig;
  logger: Logger;
  verifier: JWTTokenVerifier;
  enforcementEngine: EnforcementEngine;
  killSwitchManager: KillSwitchManager;
  callCounterStore?: CallCounterStore;
  revocationStore?: RevocationStore;
  /**
   * Per-issuer epoch store.  When set, every token verification also checks
   * the issuer epoch: tokens with `iat` before the epoch are rejected.
   * Wired from `REDIS_URL` (Redis-backed) or falls back to in-memory.
   */
  epochStore?: RevocationEpochStore;
  evidenceSigner?: EvidenceSigner;
  /**
   * Async audit pipeline (R-9). Present when evidence signing is
   * enabled and `AUDIT_PIPELINE_ENABLED=true` (the default). The
   * gateway entrypoint is responsible for calling `drain()` on
   * shutdown so buffered evidence is flushed before exit. When set,
   * `auditPipelineDrainTimeoutMs` is always populated by
   * `initializeServices` from `AUDIT_PIPELINE_DRAIN_TIMEOUT_MS`.
   */
  auditPipeline?: AuditPipeline;
  /**
   * Drain timeout (ms) used by the entrypoint on SIGTERM/SIGINT.
   * Always populated alongside `auditPipeline` (the validated config
   * supplies a default), so the entrypoint never passes `undefined`
   * into `AuditPipeline.drain()`.
   */
  auditPipelineDrainTimeoutMs: number;
  /**
   * Optional OCSF (F-6) audit transport. When configured via
   * `OCSF_TRANSPORT`, every signed evidence record and every
   * `AuditLogEntry`-shaped winston log line is also delivered as an
   * OCSF v1.1 event to a SIEM-friendly sink. The gateway entrypoint
   * is responsible for calling `close()` during shutdown.
   */
  ocsfTransport?: OcsfAuditTransport;
  /**
   * Optional shared DPoP replay store (F-2). When `REDIS_URL` is set
   * a `RedisDpopReplayStore` is wired so a captured proof cannot be
   * replayed once per replica inside its acceptance window;
   * otherwise an `InMemoryDpopReplayStore` is used (single-replica
   * / dev). The entrypoint is responsible for calling `close()` on
   * shutdown when the implementation owns external resources.
   */
  dpopReplayStore?: DpopReplayStore;
  /**
   * PostgreSQL connection pool owned by the ledger backend.  Present when
   * `AUDIT_LEDGER_BACKEND=postgres` or `AUDIT_LEDGER_BACKEND=per-replica-postgres`.
   * The entrypoint is responsible for calling `ledgerPgPool.end()` on graceful
   * shutdown so connection sockets are released.
   */
  ledgerPgPool?: import('@euno/common').PgPool;
  /**
   * Cross-chain anchor for the per-replica ledger backend.  Present when
   * `AUDIT_LEDGER_BACKEND=per-replica-postgres` and
   * `AUDIT_LEDGER_S3_BUCKET` is configured.  The entrypoint is responsible
   * for calling `crossChainAnchor.stop()` during graceful shutdown.
   */
  crossChainAnchor?: CrossChainAnchor;
  /**
   * The ledger backend exposed by the audit module. Present when
   * `AUDIT_LEDGER_BACKEND` is set to a queryable backend (`postgres`,
   * `per-replica-postgres`, `in-memory`, or `acl`). Used by the audit
   * query route (`GET /api/v1/audit/records`) to serve paginated,
   * filterable evidence without a separate DB connection pool.
   */
  auditLedgerBackend?: import('@euno/common').LedgerBackend;
  /**
   * Azure Confidential Ledger client for the ACL ledger backend.
   *
   * When `AUDIT_LEDGER_BACKEND=acl` the bootstrap resolves the client using
   * the following precedence:
   *   1. **This field** — if set, used as-is. Preferred for custom credentials,
   *      per-collection configuration, or injecting a mock in tests.
   *   2. **`AUDIT_LEDGER_ACL_ENDPOINT`** env var — if set, the bootstrap
   *      constructs a client using `DefaultAzureCredential` from `@azure/identity`
   *      (workload identity, managed identity, or `AZURE_*` env vars).
   *
   * A startup error is thrown when neither option is provided.
   */
  ledgerAclClient?: AzureConfidentialLedgerClient;
  /** Optional admin API key; when set the admin router enforces it. */
  adminApiKey?: string;
  /**
   * Optional tenant identifier that scopes the admin API to a single tenant.
   * When set, all mutating admin operations require a matching `tenantId` in
   * the request body.  Plumbed from `ADMIN_TENANT_ID`.
   */
  adminTenantId?: string;
  /**
   * Whether the kill-switch manager was configured with `failOpenOnWrite=true`
   * (`KILL_SWITCH_FAIL_OPEN_ON_WRITE=true`).  When true, the admin router
   * returns `207 Multi-Status` for mutating kill-switch endpoints to signal
   * that the kill was applied locally but fleet-wide propagation is not
   * guaranteed (CI-3).  Plumbed from `KILL_SWITCH_FAIL_OPEN_ON_WRITE`.
   */
  killSwitchFailOpenOnWrite?: boolean;
  /** Backend service URL for the proxy route. */
  backendServiceUrl: string;
  /** Port the admin HTTP server listens on (separate from the public `config.port`). */
  adminPort: number;
  /**
   * Network interface the admin HTTP server binds to. When set, the
   * entrypoint passes this as the `host` argument to `adminApp.listen()`
   * so the admin surface is reachable only on the named interface
   * (e.g. `127.0.0.1` or the pod's internal cluster IP) — defence in
   * depth against an ingress / route misconfiguration that would
   * otherwise expose `/admin/*` on the public load-balancer. The
   * gateway schema requires this to be a non-wildcard value when
   * NODE_ENV=production. Undefined falls back to Express's default
   * (bind all interfaces) for non-production / dev convenience.
   */
  adminHost?: string;
  /** CORS origins; empty array disables CORS. */
  allowedOrigins: string[];
  /** Rate-limit window in ms (sliding). */
  rateLimitWindowMs: number;
  /** Rate-limit max requests per window. */
  rateLimitMax: number;
  /**
   * Prometheus registry exposed on `/metrics` (F-5, addresses I-16).
   * The factory installs an HTTP latency / count middleware that writes
   * to this registry, and bootstrap pre-registers gateway-specific
   * series (revocation-list size, decision counter).
   */
  metricsRegistry: Registry;
  /**
   * Counter incremented by the enforcement engine on every authorization
   * decision, labelled `decision="allow"|"deny"`. Surfaced by F-5 so
   * operators can chart a deny-rate without scraping logs.
   */
  decisionsCounter: Counter<string>;
  /**
   * Returns true once `initializeServices()` has completed successfully.
   * Drives `/health/ready`. Defaults to always-true when omitted.
   */
  isReady?: () => boolean;
  /**
   * Logical region tag for this gateway instance (F-7,
   * `docs/MULTI_REGION_ISSUER.md`). Plumbed from `GATEWAY_REGION`.
   * When set, every request span is stamped with `euno.region`.
   * Empty/undefined means "not configured" — back-compat with single
   * region deployments.
   */
  region?: string;
  /**
   * Express `trust proxy` setting (security-critical for F-2 DPoP
   * `htu` reconstruction). When the gateway is deployed behind a
   * TLS-terminating reverse proxy / load balancer, this MUST be
   * configured so `req.protocol` / `req.hostname` reflect the
   * client-facing scheme and host the agent actually dialled (the
   * one its DPoP proof was signed against). Plumbed from the
   * `TRUST_PROXY` env var. Unset means Express's default of `false`
   * — safe for direct deployments.
   *
   * Accepts the full Express vocabulary: a boolean, a hop count, a
   * comma-separated list of CIDRs / IPs, or "loopback" /
   * "linklocal" / "uniquelocal". See:
   * https://expressjs.com/en/guide/behind-proxies.html
   */
  trustProxy?: string | boolean | number;
  /**
   * Pluggable {@link ActionResolver} (R-7, addresses I-4 and I-5).
   * Used by the proxy route to derive a capability action from the
   * inbound HTTP request, and by the tools route to derive an action
   * from a tool invocation. Loaded from `ACTION_RESOLVER_FILE` when
   * set; defaults to {@link BUILTIN_ACTION_RESOLVER} otherwise so
   * existing deployments keep their pre-R-7 behaviour exactly.
   */
  actionResolver: ActionResolver;
  /**
   * Optional partner-issuer resolver (cross-org trust harness). When
   * `TRUSTED_PARTNER_DIDS` is set, this is a configured
   * {@link PartnerIssuerResolver}; otherwise `undefined`. Passed to
   * `createAdminApp` so the admin router can expose the per-DID
   * cache-refresh endpoint.
   */
  partnerResolver?: import('./partner-issuer-resolver').PartnerIssuerResolver;
  /**
   * Optional partner-DID registry (two-eyes lifecycle, pin enforcement).
   * When configured, the admin router exposes proposal / approval / revoke
   * / list / refresh endpoints under `/admin/partner-dids/*`.
   */
  partnerRegistry?: InMemoryPartnerDidRegistry | RedisPartnerDidRegistry;
  /**
   * When true, the admin router requires `pinnedDocSha256` on all proposals.
   * Plumbed from `PARTNER_DID_REQUIRE_PIN`.
   */
  requirePin?: boolean;
  /**
   * HMAC-SHA-256 secret for pin attestation signing / verification.
   * Plumbed from `PARTNER_DID_PIN_SECRET`.  Passed to both the admin router
   * (for signing at approval time) and the partner-issuer resolver (for
   * verifying before trusting a cached pin).
   */
  pinAttestationSecret?: string;
  /**
   * When true, the approval endpoint auto-fetches the DID document and
   * computes `pinnedDocSha256` when the proposal lacks a pin.
   * Plumbed from `PARTNER_DID_AUTO_FETCH_PIN`.
   */
  partnerDidAutoFetchPin?: boolean;
  /**
   * Maximum upstream response body size (bytes) to buffer for field-level
   * redaction. Responses larger than this limit AND carrying a redaction
   * obligation are refused with HTTP 502 (`redaction_oversize`). Defaults
   * to 1 MiB; plumbed from `RESPONSE_REDACTION_MAX_BYTES`.
   */
  responseRedactionMaxBytes: number;
  /**
   * Per-tenant billing usage meter (Task 17).
   *
   * Accumulates enforcement-event and kill-switch-invocation counts since
   * the last `resetPeriod()` call. Surfaced via `GET /admin/usage`.
   * Always present in production; may be omitted in minimally-wired tests.
   */
  usageMeter?: UsageMeter;
  /**
   * Configured audit-log retention in days (Task 17).
   *
   * Surfaced in `GET /admin/usage` alongside the live usage counters so
   * billing operators can verify the tenant's tier. Plumbed from
   * `AUDIT_LEDGER_RETENTION_DAYS` when set; otherwise `undefined`.
   */
  auditRetentionDays?: number;
  /**
   * Hosted-mode telemetry collector (Task 16 — Telemetry continuity).
   * Present when `EUNO_TELEMETRY=1` (explicit opt-in, DI-4).  The enforce
   * route passes enforcement decisions to this collector; `initializeServices`
   * starts its flush timer and the entrypoint calls `stop()` on graceful
   * shutdown so any pending tenant stats are flushed before exit.
   *
   * `null` means telemetry is disabled (the default).
   * Omitted (undefined) is equivalent to `null` — telemetry is not collected.
   */
  gatewayTelemetry?: GatewayTelemetryCollector | null;
  /**
   * Source-IP trust mode for `POST /api/v1/enforce` (CR-2 fix).
   *
   * - `'gateway'` (default): use `req.ip` (connection-derived, respects
   *   `TRUST_PROXY`) as the authoritative `sourceIp` for `ipRange` conditions.
   *   Emits a `warn` log when the client-supplied body value differs.
   * - `'client'`: legacy behaviour — use the value from the request body.
   *
   * Plumbed from `ENFORCE_SOURCE_IP_MODE` env var.
   */
  sourceIpMode?: 'gateway' | 'client';
}

/**
 * Map a validated `GatewayConfig` to the runtime `ServiceConfig` shape
 * consumed by the rest of the gateway.  Single source of truth so
 * `loadConfigFromEnv()` and `initializeServices()` cannot drift.
 */
function gatewayConfigToServiceConfig(cfg: GatewayConfig): ServiceConfig {
  return {
    name: 'tool-gateway',
    port: cfg.PORT,
    environment: cfg.NODE_ENV,
    enableCryptographicAudit: cfg.ENABLE_CRYPTOGRAPHIC_AUDIT,
    signedAuditDecisions: cfg.EVIDENCE_SIGNED_DECISIONS as
      | Array<'allow' | 'deny'>
      | undefined,
    policyVersion: cfg.POLICY_VERSION || '1.0.0',
  };
}

/** Build the `ServiceConfig` from a validated `GatewayConfig`. */
export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): ServiceConfig {
  // Use the non-exiting form here so callers (notably tests) never see
  // the loader call `process.exit`. `initializeServices()` runs the
  // exit-on-failure variant before reaching this code path.
  const result = loadConfig(env, 'gateway');
  if (!result.ok) {
    throw new Error(
      `Invalid gateway configuration: ${result.errors
        .map((e) => `${e.field}: ${e.message}`)
        .join('; ')}`,
    );
  }
  return gatewayConfigToServiceConfig(result.config);
}

/** Compute the CORS allow-list with the same semantics as the legacy server. */
export function resolveAllowedOrigins(
  env: NodeJS.ProcessEnv,
  environment: ServiceConfig['environment'],
): string[] {
  // Re-validate so callers can pass a raw env without first running the
  // loader. Falls back to the same defaults the loader applies.
  const result = loadConfig(env, 'gateway');
  const origins = result.ok ? result.config.ALLOWED_ORIGINS : undefined;
  if (origins && origins.length > 0) {
    return origins;
  }
  if (environment === 'production') {
    return []; // No CORS in production unless explicitly configured
  }
  return ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'];
}

/**
 * Derive the JWKS URL from a legacy ISSUER_PUBLIC_KEY_URL.
 *
 * The old endpoint is `<base>/api/v1/public-key`; the new one is
 * `<base>/.well-known/jwks.json`.  If the URL ends with the legacy
 * suffix, strip it and append the JWKS path.  Otherwise return null
 * (caller will fall back to the default JWKS URL).
 */
function deriveJwksUrl(publicKeyUrl: string | undefined): string | undefined {
  if (!publicKeyUrl) return undefined;
  const suffix = '/api/v1/public-key';
  if (publicKeyUrl.endsWith(suffix)) {
    return `${publicKeyUrl.slice(0, -suffix.length)}/.well-known/jwks.json`;
  }
  // URL doesn't match the expected pattern — can't derive safely.
  return undefined;
}

/**
 * Derive the issuer's `/.well-known/capability-issuer` metadata URL.
 *
 * Resolution order:
 *   1. `explicitMetadataUrl` — when the operator sets `ISSUER_METADATA_URL`.
 *   2. Derived from `jwksUrl` — when the JWKS URL ends with
 *      `/.well-known/jwks.json` the metadata URL is the same base with
 *      `/.well-known/capability-issuer` appended.
 *   3. `undefined` — when neither is available; the parity check is skipped.
 */
export function deriveIssuerMetadataUrl(
  explicitMetadataUrl: string | undefined,
  jwksUrl: string,
): string | undefined {
  if (explicitMetadataUrl && explicitMetadataUrl.trim().length > 0) {
    return explicitMetadataUrl.trim();
  }
  const jwksSuffix = '/.well-known/jwks.json';
  if (jwksUrl.endsWith(jwksSuffix)) {
    return `${jwksUrl.slice(0, -jwksSuffix.length)}/.well-known/capability-issuer`;
  }
  return undefined;
}

/**
 * Fetch the issuer's `/.well-known/capability-issuer` discovery document and
 * compare its `actionResolverHash` against the locally-computed hash.
 *
 * On mismatch the behaviour is controlled by `enforcement`:
 *   - `'warn'`  — log a structured warning and continue.
 *   - `'error'` — throw so the gateway aborts startup.
 *
 * Non-fatal fetch/parse errors are always logged as warnings: we do not want
 * a transient issuer outage to block gateway restarts (the check is best-effort
 * at startup; the issuer's tokens are still cryptographically verified on every
 * request).
 *
 * @internal Exported for unit testing only; not part of the public API.
 */
export async function checkActionResolverHashParity({
  issuerMetadataUrl,
  localHash,
  enforcement,
  logger,
}: {
  issuerMetadataUrl: string;
  localHash: string;
  enforcement: string;
  logger: Logger;
}): Promise<void> {
  logger.info('Fetching issuer metadata for action-resolver hash parity check', {
    issuerMetadataUrl,
  });

  let remoteHash: string | undefined;
  try {
    const resp = await fetch(issuerMetadataUrl, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!resp.ok) {
      logger.warn(
        'Issuer metadata fetch returned non-OK status; skipping action-resolver hash parity check',
        { issuerMetadataUrl, status: resp.status },
      );
      return;
    }
    const body = (await resp.json()) as Record<string, unknown>;
    if (typeof body.actionResolverHash === 'string') {
      remoteHash = body.actionResolverHash;
    } else {
      logger.warn(
        'Issuer metadata does not include actionResolverHash; skipping parity check. ' +
          'Ensure the issuer is running a version that populates this field.',
        { issuerMetadataUrl },
      );
      return;
    }
  } catch (err) {
    logger.warn(
      'Failed to fetch issuer metadata for action-resolver hash parity check; ' +
        'check will be skipped. This is non-fatal but may indicate an issuer connectivity issue.',
      {
        issuerMetadataUrl,
        error: err instanceof Error ? err.message : String(err),
      },
    );
    return;
  }

  if (remoteHash === localHash) {
    logger.info('Action-resolver hash parity check passed', {
      hash: localHash,
      issuerMetadataUrl,
    });
    return;
  }

  const message =
    'ACTION RESOLVER HASH MISMATCH: the gateway is enforcing a different action ' +
    'vocabulary than the issuer used to mint tokens. Tokens whose actions appear ' +
    'valid to the issuer may be rejected by the gateway (or silently permitted). ' +
    'Ensure ACTION_RESOLVER_FILE is the same on both services, then restart. ' +
    `issuerHash=${remoteHash} localHash=${localHash} issuerMetadataUrl=${issuerMetadataUrl}`;

  if (enforcement === 'error') {
    throw new Error(message);
  } else {
    logger.warn(message, {
      issuerHash: remoteHash,
      localHash,
      issuerMetadataUrl,
    });
  }
}

/**
 * Parse the `TRUST_PROXY` env var into the value Express's
 * `app.set('trust proxy', …)` accepts. Mirrors the Express docs:
 *
 *   - `undefined`  → `false` (Express's default, ignore X-Forwarded-*)
 *   - `"true"`     → `true`  (trust every hop — UNSAFE if the gateway
 *                              is also reachable directly by clients)
 *   - `"false"`    → `false`
 *   - a non-negative integer string → numeric hop count (e.g. `"1"`
 *                                     trusts only the immediate proxy)
 *   - anything else → returned as-is so Express can interpret CIDR /
 *                     keyword forms like `"loopback"` or
 *                     `"10.0.0.0/8,172.16.0.0/12"`.
 */
function parseTrustProxy(value: string | undefined): string | boolean | number {
  if (value === undefined || value === '') return false;
  const trimmed = value.trim();
  if (trimmed.toLowerCase() === 'true') return true;
  if (trimmed.toLowerCase() === 'false') return false;
  if (/^\d+$/.test(trimmed)) {
    const n = Number(trimmed);
    if (Number.isFinite(n)) return n;
  }
  return trimmed;
}

/**
 * Subset of {@link GatewayDependencies} that can be injected into
 * {@link initializeServices} to override or augment what the bootstrap builds
 * from environment variables.
 *
 * Use this when you need to supply a cloud-SDK client that the standard
 * bootstrap cannot construct automatically (e.g. a custom Azure credential).
 */
export interface InjectableBootstrapDeps {
  /**
   * Pre-built Azure Confidential Ledger client.
   * Required when `AUDIT_LEDGER_BACKEND=acl` and you want to supply a
   * non-default credential or a mock for testing.  When omitted the bootstrap
   * falls back to constructing a client from `AUDIT_LEDGER_ACL_ENDPOINT` using
   * `DefaultAzureCredential`.
   */
  ledgerAclClient?: AzureConfidentialLedgerClient;
  /**
   * Pre-built {@link CrossChainAnchor} for `AUDIT_LEDGER_BACKEND=per-replica-postgres`.
   *
   * The standard bootstrap does not wire an S3 client, so it never creates a
   * `CrossChainAnchor` internally.  Supply one here when you want periodic
   * cross-replica Merkle commitments — typically by constructing
   * `PerReplicaPostgresLedgerBackend` with an `S3AnchorClient` and passing a
   * `CrossChainAnchor` that wraps it.  The bootstrap will call `.stop()` on it
   * during graceful shutdown.
   */
  crossChainAnchor?: CrossChainAnchor;
}

/**
 * Fetch the issuer public key, build verifier + enforcement engine and all
 * supporting stores. Throws on misconfiguration so the gateway fails closed.
 *
 * Returns the dependency bag consumed by `createApp(deps)` plus the
 * `setReady` toggle the entrypoint flips once the server starts listening.
 */
export async function initializeServices(
  env: NodeJS.ProcessEnv = process.env,
  injectDeps: InjectableBootstrapDeps = {},
): Promise<{ deps: GatewayDependencies; setReady: (ready: boolean) => void }> {
  // ── Step 1: Validate config ───────────────────────────────────────────────
  const validated: GatewayConfig = loadConfigOrExit(env, 'gateway');
  const config: ServiceConfig = gatewayConfigToServiceConfig(validated);
  const logger = createLogger(config.name, config.environment);

  // ── Step 2: OCSF transport (F-6) — created early so it can be shared with
  //            both the enforcement-engine audit logger and the pipeline sink.
  const ocsfProduct = { name: 'euno-tool-gateway', vendor: 'Euno' };
  const ocsfTransport: OcsfAuditTransport | undefined = createOcsfTransportFromEnv(env, logger);
  if (ocsfTransport) {
    logger.info('OCSF audit transport enabled', { transport: ocsfTransport.name });
  }

  // ── Step 3: Prometheus registry + counters ────────────────────────────────
  // Created BEFORE the stores so all callbacks are fully bound when passed to
  // the module factories — the late-binding anti-pattern is eliminated.
  const metricsRegistry = createMetricsRegistry({ serviceName: 'tool-gateway' });

  const decisionsCounter = new Counter({
    name: 'euno_gateway_decisions_total',
    help: 'Authorization decisions made by the gateway, labelled allow|deny.',
    labelNames: ['decision'],
    registers: [metricsRegistry],
  });
  decisionsCounter.inc({ decision: 'allow' }, 0);
  decisionsCounter.inc({ decision: 'deny' }, 0);

  const redisErrorsCounter = new Counter({
    name: 'euno_gateway_redis_errors_total',
    help: 'Redis errors encountered by gateway stores (dpop_replay, revocation, revocation_epoch, call_counter). ' +
      'A non-zero rate indicates Redis instability; a sustained rate means the gateway is ' +
      'failing closed on affected checks — monitor alongside denial rates.',
    labelNames: ['store'],
    registers: [metricsRegistry],
  });
  redisErrorsCounter.inc({ store: 'dpop_replay' }, 0);
  redisErrorsCounter.inc({ store: 'revocation' }, 0);
  redisErrorsCounter.inc({ store: 'revocation_epoch' }, 0);
  redisErrorsCounter.inc({ store: 'call_counter' }, 0);

  const revocationUnavailableCounter = new Counter({
    name: 'euno_gateway_revocation_unavailable_total',
    help: 'Revocation checks that could not be completed because the backing store (Redis) was unreachable. ' +
      'Does not fire in stale-readable or fail-open mode. ' +
      'A non-zero rate means the gateway is either fail-closing (→ 401) or returning 503 on token checks.',
    registers: [metricsRegistry],
  });
  revocationUnavailableCounter.inc(0);

  const counterFallbackCounter = new Counter({
    name: 'euno_gateway_counter_fallback_total',
    help: 'Call-counter increments served from the local in-memory fallback because Redis was unavailable. ' +
      'A non-zero rate means maxCalls enforcement is per-replica (effective cap = maxCalls × replicaCount).',
    registers: [metricsRegistry],
  });
  counterFallbackCounter.inc(0);

  // CI-2: usage-meter error counter — incremented when `recordEnforcement`
  // throws inside validateAction's finally block. A non-zero rate means
  // billing events are being silently lost; alert and investigate.
  const usageMeterErrorsCounter = new Counter({
    name: 'euno_usage_meter_errors_total',
    help: 'Errors thrown by the usage meter inside validateAction. ' +
      'A non-zero rate means per-tenant billing counters may be under-counting. ' +
      'Investigate the usage meter backend (Redis connectivity, etc.).',
    registers: [metricsRegistry],
  });
  usageMeterErrorsCounter.inc(0);

  // H-1: shard mis-route counter — conditional on sharding being enabled.
  const shardCount = validated.GATEWAY_SHARD_COUNT ?? 1;
  const shardIndex = validated.GATEWAY_SHARD_INDEX ?? 0;
  let shardMisroutedCounter: Counter | undefined;
  if (shardCount > 1) {
    shardMisroutedCounter = new Counter({
      name: 'euno_gateway_shard_misrouted_total',
      help: 'Requests whose agent `sub` does not hash to this shard. ' +
        'A non-zero steady-state rate means the Envoy shard router is mis-configured or ' +
        'its shard count does not match GATEWAY_SHARD_COUNT.',
      registers: [metricsRegistry],
    });
    shardMisroutedCounter.inc(0);
  }

  // Partner-DID circuit transitions — registered after partnerResolver is known;
  // declared here so the closure captures the variable reference.
  let partnerDidCircuitTransitionsCounter: Counter<string> | undefined;

  // ── Step 4: DPoP replay store (F-2) ──────────────────────────────────────
  const { dpopReplayStore } = await buildDpopModule(
    env,
    logger,
    () => redisErrorsCounter.inc({ store: 'dpop_replay' }),
  );

  // ── Step 5: Redis-backed control-surface stores ───────────────────────────
  const {
    revocationStore,
    epochStore,
    killSwitchManager,
    callCounterStore,
    revocationCircuitBreaker,
    callCounterCircuitBreaker,
    partnerRegistry,
    partnerResolver,
  } = await buildRevocationModule(validated, env, logger, {
    onRedisError: (store: string) => redisErrorsCounter.inc({ store }),
    onRevocationUnavailable: () => revocationUnavailableCounter.inc(),
    onCounterFallback: () => counterFallbackCounter.inc(),
    onShardMisrouted: () => shardMisroutedCounter?.inc(),
    onPartnerCircuitStateChange: (did, from, to) => {
      partnerDidCircuitTransitionsCounter?.inc({ did, from, to });
    },
  });

  // Register partner-DID circuit counter now that we know whether a resolver
  // was wired (avoids registering a counter that can never be incremented).
  if (partnerResolver) {
    partnerDidCircuitTransitionsCounter = new Counter({
      name: 'euno_gateway_partner_did_circuit_transitions_total',
      help: 'Number of per-DID circuit breaker state transitions for partner DID document resolution. ' +
        'Labels: did (partner DID string), from (previous state), to (new state). ' +
        'Alert on to="open" to detect flapping partner endpoints.',
      labelNames: ['did', 'from', 'to'],
      registers: [metricsRegistry],
    });
  }

  // ── Step 6: Prometheus gauges (reference stores via closures) ─────────────
  new Gauge({
    name: 'euno_gateway_revocation_list_size',
    help: 'Number of revocation entries currently tracked by the in-process revocation store. ' +
      'May include expired entries not yet pruned. Always 0 when a non-introspectable backend ' +
      '(e.g. Redis) is in use.',
    registers: [metricsRegistry],
    collect() {
      const store = revocationStore as { size?: () => number } | undefined;
      this.set(typeof store?.size === 'function' ? store.size() : 0);
    },
  });

  new Gauge({
    name: 'euno_gateway_redis_circuit_state',
    help: 'State of the Redis circuit breaker for each control-surface store: 0=closed (healthy), 1=half-open (probing), 2=open (failing fast).',
    labelNames: ['store'],
    registers: [metricsRegistry],
    collect() {
      const toNumeric = (s: string): number => {
        switch (s) {
          case 'closed': return 0;
          case 'half-open': return 1;
          case 'open': return 2;
          default: return 0;
        }
      };
      this.set({ store: 'revocation' }, toNumeric(revocationCircuitBreaker.getState()));
      this.set({ store: 'call_counter' }, toNumeric(callCounterCircuitBreaker.getState()));
    },
  });

  new Gauge({
    name: 'euno_gateway_shard_info',
    help: 'Static labels describing the shard topology of this replica.',
    labelNames: ['shard_index', 'shard_count'],
    registers: [metricsRegistry],
    collect() {
      this.set({ shard_index: String(shardIndex), shard_count: String(shardCount) }, 1);
    },
  });

  new Gauge({
    name: 'euno_gateway_shard_local_counter_size',
    help: 'Number of in-memory call-counter entries held by the shard-local store on this replica. ' +
      'Non-zero only when GATEWAY_SHARD_COUNT > 1 and traffic is flowing to this shard.',
    registers: [metricsRegistry],
    collect() {
      const store = callCounterStore as { localSize?: () => number } | undefined;
      this.set(typeof store?.localSize === 'function' ? store.localSize() : 0);
    },
  });

  // Kill-switch observability — lets operators chart kill-switch state and
  // correlate spikes in denial rates with an active kill.
  new Gauge({
    name: 'euno_gateway_kill_switch_active',
    help: 'Whether any kill switch is currently active on this replica. ' +
      '1 = at least one kill switch (global, session, or agent) is engaged; ' +
      '0 = no kills are active. The global_kill label distinguishes the global ' +
      'kill (which blocks ALL traffic) from per-entity kills.',
    labelNames: ['global_kill'],
    registers: [metricsRegistry],
    collect() {
      const status = killSwitchManager.getStatus();
      this.set({ global_kill: '1' }, status.globalKill ? 1 : 0);
      const anyPerEntityKill =
        status.killedSessionCount > 0 || status.killedAgentCount > 0 ? 1 : 0;
      this.set({ global_kill: '0' }, anyPerEntityKill);
    },
  });

  new Gauge({
    name: 'euno_gateway_kill_switch_killed_sessions',
    help: 'Number of session IDs currently in the kill list. ' +
      'Non-zero means at least one session is being actively blocked by the kill switch.',
    registers: [metricsRegistry],
    collect() {
      this.set(killSwitchManager.getStatus().killedSessionCount);
    },
  });

  new Gauge({
    name: 'euno_gateway_kill_switch_killed_agents',
    help: 'Number of agent IDs currently in the kill list. ' +
      'Non-zero means at least one agent is being actively blocked by the kill switch.',
    registers: [metricsRegistry],
    collect() {
      this.set(killSwitchManager.getStatus().killedAgentCount);
    },
  });

  // ── Step 7: JWKS client + pre-warm ───────────────────────────────────────
  const jwksCacheTtlMs = (validated.EUNO_JWKS_CACHE_TTL_SECONDS ?? 300) * 1000;
  const issuerJwksUrl = validated.ISSUER_JWKS_URL
    ?? deriveJwksUrl(validated.ISSUER_PUBLIC_KEY_URL)
    ?? 'http://localhost:3001/.well-known/jwks.json';

  if (!validated.ISSUER_JWKS_URL && validated.ISSUER_PUBLIC_KEY_URL) {
    logger.warn(
      'ISSUER_PUBLIC_KEY_URL is deprecated for gateway key bootstrap. ' +
        'Set ISSUER_JWKS_URL to the issuer\'s JWKS endpoint instead.',
      { derivedJwksUrl: issuerJwksUrl },
    );
  }

  const jwksClient = new JwksClient({ jwksUrl: issuerJwksUrl, cacheTtlMs: jwksCacheTtlMs, logger });
  logger.info('Fetching initial JWKS from Capability Issuer', { url: issuerJwksUrl });
  await jwksClient.getJwks();
  logger.info('JWKS fetched and cached successfully');

  const adminApiKey = validated.ADMIN_API_KEY;
  const adminTenantId = validated.ADMIN_TENANT_ID;
  const requireKid = validated.EUNO_REQUIRE_KID !== undefined ? validated.EUNO_REQUIRE_KID : true;

  // ── Step 8: Action resolver + parity check ────────────────────────────────
  let actionResolver: ActionResolver = BUILTIN_ACTION_RESOLVER;
  let localActionResolverHash: string;
  if (validated.ACTION_RESOLVER_FILE && validated.ACTION_RESOLVER_FILE.trim().length > 0) {
    logger.info('Loading action resolver config from file', { path: validated.ACTION_RESOLVER_FILE });
    const { resolver, hash } = loadActionResolverFromFileWithHash(validated.ACTION_RESOLVER_FILE);
    actionResolver = resolver;
    localActionResolverHash = hash;
    logger.info('Action resolver config loaded', { actionResolverHash: hash });
  } else {
    localActionResolverHash = computeActionResolverHash(null);
  }

  const issuerMetadataUrl = deriveIssuerMetadataUrl(validated.ISSUER_METADATA_URL, issuerJwksUrl);
  if (issuerMetadataUrl) {
    await checkActionResolverHashParity({
      issuerMetadataUrl,
      localHash: localActionResolverHash,
      enforcement: validated.ACTION_RESOLVER_HASH_ENFORCEMENT ?? 'warn',
      logger,
    });
  } else {
    logger.warn(
      'Skipping issuer action-resolver hash parity check: cannot derive issuer metadata URL. ' +
      'Set ISSUER_METADATA_URL to enable the check.',
    );
  }

  // ── Step 9: Verifier ─────────────────────────────────────────────────────
  const localIssuers = validated.LOCAL_ISSUER_IDS ?? [];
  const verifier = new JwksTokenVerifier(jwksClient, {
    revocationStore,
    epochStore,
    partnerResolver: partnerResolver ?? undefined,
    localIssuers: localIssuers.length > 0 ? localIssuers : undefined,
    requireKid,
    proofsVerifier: buildProofsVerifierFromEnv(validated, logger),
  });

  // ── Step 10: Replica identity ─────────────────────────────────────────────
  const replicaIdFromEnv = (validated as { AUDIT_REPLICA_ID?: string }).AUDIT_REPLICA_ID;
  let replicaId = replicaIdFromEnv ?? 'unknown-replica';
  if (!replicaIdFromEnv) {
    try {
      replicaId = (require('os') as typeof import('os')).hostname();
    } catch {
      // hostname() failed — keep the default 'unknown-replica'
    }
  }

  // ── Step 11: Audit module (evidence signer + pipeline) ───────────────────
  const {
    evidenceSigner,
    auditPipeline,
    auditPipelineDrainTimeoutMs,
    ledgerPgPool,
    crossChainAnchor,
    auditLedgerBackend,
  } = await buildAuditModule({
    validated,
    env,
    logger,
    config,
    metricsRegistry,
    replicaId,
    ledgerAclClient: injectDeps.ledgerAclClient,
    crossChainAnchorOverride: injectDeps.crossChainAnchor,
    ocsfTransport,
  });

  // ── Step 12: Gateway quota engine (F-1b) ──────────────────────────────────
  let gatewayQuota: GatewayQuotaEngine | undefined;
  if (validated.GATEWAY_QUOTA_ENABLED) {
    gatewayQuota = new CallCounterBackedGatewayQuotaEngine(
      callCounterStore,
      {
        max: validated.GATEWAY_QUOTA_MAX,
        windowSeconds: validated.GATEWAY_QUOTA_WINDOW_SECONDS,
        failOpen: !validated.GATEWAY_QUOTA_FAIL_CLOSED,
      },
      logger,
    );
    logger.info('Gateway quota engine enabled (F-1b)', {
      max: validated.GATEWAY_QUOTA_MAX,
      windowSeconds: validated.GATEWAY_QUOTA_WINDOW_SECONDS,
      failClosed: validated.GATEWAY_QUOTA_FAIL_CLOSED,
    });
  }

  // ── Step 13: Enforcement engine ───────────────────────────────────────────
  const signedDecisions = validated.EVIDENCE_SIGNED_DECISIONS as
    | Array<'allow' | 'deny'>
    | undefined;

  // ── Step 13a: Usage meter (CR-1 / Task 17) ───────────────────────────────
  // Use a Redis-backed UsageMeter when REDIS_URL (or USAGE_METER_REDIS_URL) is
  // configured so billing counters survive pod restarts. Falls back to the
  // InMemoryUsageMeter when no Redis URL is available (emits a warn in prod).
  // The onError callback wires Redis write failures to euno_usage_meter_errors_total
  // (CI-2) so operators can observe silent billing losses in dashboards.
  const usageMeter: UsageMeter = await createUsageMeterFromEnv(
    env,
    logger,
    () => usageMeterErrorsCounter.inc(),
  );

  // Audit-retention days — surfaced in GET /admin/usage for billing tier
  // confirmation. Read directly from the validated config (the field is
  // declared in the GatewayConfig schema as AUDIT_LEDGER_RETENTION_DAYS).
  const auditRetentionDays: number | undefined = validated.AUDIT_LEDGER_RETENTION_DAYS;

  const enforcementEngine = new EnforcementEngine({
    verifier,
    logger,
    killSwitchManager,
    evidenceSigner,
    auditPipeline,
    enableCryptographicAudit: config.enableCryptographicAudit,
    signedDecisions,
    argumentSchemaRequired: validated.ARGUMENT_SCHEMA_REQUIRED,
    policyVersion: config.policyVersion,
    callCounterStore,
    ...(gatewayQuota ? { gatewayQuota } : {}),
    region: validated.GATEWAY_REGION,
    ...(ocsfTransport
      ? { auditTransports: [createOcsfWinstonTransport(ocsfTransport, ocsfProduct)] }
      : {}),
    dpop: {
      required: validated.DPOP_REQUIRED,
      clockSkewSeconds: validated.DPOP_CLOCK_SKEW_SECONDS,
      maxAgeSeconds: validated.DPOP_MAX_AGE_SECONDS,
      replayStore: dpopReplayStore,
    },
    ...(validated.GATEWAY_AUDIENCE ? { gatewayAudience: validated.GATEWAY_AUDIENCE } : {}),
    usageMeter,
    onMeterError: () => usageMeterErrorsCounter.inc(),
  });

  // ── Step 14: Assemble deps bag ────────────────────────────────────────────
  let ready = false;
  const setReady = (value: boolean) => { ready = value; };

  enforcementEngine.setDecisionRecorder((decision) => {
    decisionsCounter.inc({ decision });
  });

  // ── Step 15: Hosted-mode telemetry (Task 16 — Telemetry continuity) ───────
  // Disabled by default (DI-4): only enabled when EUNO_TELEMETRY=1.
  // When enabled, the collector is started here and its flush timer is
  // unref'd so it never prevents clean process exit.
  const gatewayTelemetry = createGatewayTelemetryFromEnv(env);
  if (gatewayTelemetry) {
    logger.info('Gateway telemetry collector started (EUNO_TELEMETRY=1)');
  }

  // ── DI-3: Admin idempotency store startup warning ─────────────────────────
  // The admin idempotency store is in-memory (per-process) by default.  In a
  // multi-replica deployment the same Idempotency-Key sent to two different
  // replicas will be processed twice — the in-memory store only prevents
  // retries to the *same* replica.  When REDIS_URL is configured we emit a
  // startup warn so operators know the gap exists and can wire a
  // RedisAdminIdempotencyStore (see src/admin-api.ts) for Stage 4 HA admin.
  if (env.ADMIN_IDEMPOTENCY_REDIS_URL || env.REDIS_URL) {
    logger.warn(
      'DI-3: REDIS_URL is configured but the admin idempotency store is in-memory. ' +
        'In a multi-replica deployment, duplicate admin operations (kill, revoke, etc.) ' +
        'can be processed once per replica. To prevent this, wire RedisAdminIdempotencyStore ' +
        'from @euno/tool-gateway into createAdminRouter({ idempotencyStore: ... }). ' +
        'See docs/architecture-review-2026-05.md § DI-3.',
    );
  }

  const deps: GatewayDependencies = {
    config,
    logger,
    verifier,
    enforcementEngine,
    killSwitchManager,
    callCounterStore,
    revocationStore,
    epochStore,
    evidenceSigner,
    auditPipeline,
    auditPipelineDrainTimeoutMs,
    ...(ocsfTransport ? { ocsfTransport } : {}),
    dpopReplayStore,
    ...(ledgerPgPool ? { ledgerPgPool } : {}),
    ...(crossChainAnchor ? { crossChainAnchor } : {}),
    ...(auditLedgerBackend ? { auditLedgerBackend } : {}),
    adminApiKey,
    adminTenantId,
    killSwitchFailOpenOnWrite: env.KILL_SWITCH_FAIL_OPEN_ON_WRITE === 'true',
    backendServiceUrl: validated.BACKEND_SERVICE_URL || 'http://localhost:4000',
    adminPort: validated.ADMIN_PORT,
    adminHost: validated.ADMIN_HOST?.trim() || undefined,
    allowedOrigins: resolveAllowedOrigins(env, config.environment),
    rateLimitWindowMs: validated.RATE_LIMIT_WINDOW_MS,
    rateLimitMax: validated.RATE_LIMIT_MAX_REQUESTS,
    metricsRegistry,
    decisionsCounter,
    isReady: () => ready,
    region: validated.GATEWAY_REGION,
    trustProxy: parseTrustProxy(validated.TRUST_PROXY),
    actionResolver,
    partnerResolver: partnerResolver ?? undefined,
    partnerRegistry,
    requirePin: validated.PARTNER_DID_REQUIRE_PIN === true,
    pinAttestationSecret: validated.PARTNER_DID_PIN_SECRET || undefined,
    partnerDidAutoFetchPin: validated.PARTNER_DID_AUTO_FETCH_PIN,
    responseRedactionMaxBytes: validated.RESPONSE_REDACTION_MAX_BYTES,
    usageMeter,
    ...(auditRetentionDays !== undefined ? { auditRetentionDays } : {}),
    gatewayTelemetry,
    sourceIpMode: validated.ENFORCE_SOURCE_IP_MODE,
  };

  logger.info('Tool Gateway services initialized successfully');
  return { deps, setReady };
}


/**
 * Tool Gateway bootstrap
 * ---------------------------------------------------------------------------
 * Owns environment loading and dependency wiring (verifier, enforcement
 * engine, kill-switch, evidence signer, stores, partner resolver) so that
 * `app-factory.ts` can stay a pure composition function with no env reads,
 * no I/O and no listening.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  ServiceConfig,
  EvidenceSigner,
  AuditBatchSigner,
  AuditAnchor,
  createSoftwareEvidenceSignerFromEnv,
  LedgerAuditEvidenceSigner,
  AzureConfidentialLedgerBackend,
  AzureConfidentialLedgerClient,
  PostgresLedgerBackend,
  InMemoryLedgerBackend,
  LedgerChainError,
  SignedAuditEvidence,
  SignedBatchCommitment,
  KillSwitchManager,
  createKillSwitchManagerFromEnv,
  CallCounterStore,
  createCallCounterStoreFromEnv,
  InMemoryCallCounterStore,
  ShardLocalCallCounterStore,
  createLogger,
  createAuditLogger,
  loadActionResolverFromFileWithHash,
  computeActionResolverHash,
  loadConfigOrExit,
  loadConfig,
  GatewayConfig,
  createMetricsRegistry,
  Counter,
  Gauge,
  Registry,
  AuditPipeline,
  BackpressurePolicy,
  createAuditPipeline,
  createDpopReplayStoreFromEnv,
  DpopReplayStore,
  createOcsfTransportFromEnv,
  createOcsfWinstonTransport,
  signedEvidenceToOcsf,
  OcsfAuditTransport,
  RedisCircuitBreaker,
  GatewayQuotaEngine,
  CallCounterBackedGatewayQuotaEngine,
} from '@euno/common';
import { JWTTokenVerifier, JwksTokenVerifier } from './verifier';
import { buildProofsVerifierFromEnv } from './proofs-verifier-bootstrap';
import { JwksClient } from './jwks-client';
import { EnforcementEngine } from './enforcement';
import { createRevocationStoreFromEnv, RevocationStore, createRevocationEpochStoreFromEnv, RevocationEpochStore } from './revocation-store';
import { createPartnerIssuerResolverFromEnv } from './partner-issuer-resolver';
import {
  createPartnerDidRegistryFromEnv,
  InMemoryPartnerDidRegistry,
  RedisPartnerDidRegistry,
} from './partner-did-registry';

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
   * `AUDIT_LEDGER_BACKEND=postgres`.  The entrypoint is responsible for calling
   * `ledgerPgPool.end()` on graceful shutdown so connection sockets are released.
   */
  ledgerPgPool?: import('@euno/common').PgPool;
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
 * Minimal type stub for the `@azure-rest/confidential-ledger` SDK client.
 * Used only by {@link buildAclClientFromEndpoint}; extracted here to avoid
 * an unreadable inline type at the call site.
 *
 * @internal
 */
type AclSdkPath = {
  post(opts: { body: { contents: string } }): Promise<{ status: string; body: { transactionId: string } }>;
  get(): Promise<{ status: string; body: { transactionId: string; contents: string } }>;
};
type AclSdkClient = { path(route: string, ...params: string[]): AclSdkPath };
type AclSdkFactory = (endpoint: string, credential: unknown) => AclSdkClient;

/**
 * Build an {@link AzureConfidentialLedgerClient} by dynamically requiring
 * `@azure-rest/confidential-ledger` and `@azure/identity`.
 *
 * Both packages must be available at runtime (add to the deployment image).
 * Authentication uses `DefaultAzureCredential` — workload identity, managed
 * identity, or `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`
 * environment variables are all supported automatically.
 */
function buildAclClientFromEndpoint(endpoint: string): AzureConfidentialLedgerClient {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const ConfidentialLedger = ((require('@azure-rest/confidential-ledger') as { default: unknown }).default as AclSdkFactory);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { DefaultAzureCredential } = require('@azure/identity') as { DefaultAzureCredential: new () => unknown };
  const sdk = ConfidentialLedger(endpoint, new DefaultAzureCredential());
  return {
    async appendTransaction(contents: string) {
      const res = await sdk.path('/app/transactions').post({ body: { contents } });
      if (res.status !== '201') {
        throw new Error(`Azure Confidential Ledger append failed (HTTP ${res.status})`);
      }
      return { transactionId: res.body.transactionId };
    },
    async getLatestCommittedTransaction() {
      const res = await sdk.path('/app/transactions').get();
      if (res.status === '204') return null;
      if (res.status !== '200') {
        throw new Error(`Azure Confidential Ledger get-latest failed (HTTP ${res.status})`);
      }
      return { transactionId: res.body.transactionId, contents: res.body.contents };
    },
    async getTransaction(transactionId: string) {
      const res = await sdk.path('/app/transactions/{transactionId}', transactionId).get();
      if (res.status === '404') return null;
      if (res.status !== '200') {
        throw new Error(`Azure Confidential Ledger get-transaction failed (HTTP ${res.status})`);
      }
      return { transactionId, contents: res.body.contents };
    },
  };
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
  // Validate the environment against the typed `EunoConfig` Zod schema
  // (R-5 in `docs/IMPROVEMENTS_AND_REFACTORING.md`). This produces a
  // single, structured "what's wrong" report on misconfig and exits
  // before any service is constructed.
  const validated: GatewayConfig = loadConfigOrExit(env, 'gateway');

  const config: ServiceConfig = gatewayConfigToServiceConfig(validated);
  const logger = createLogger(config.name, config.environment);

  // F-6: optional OCSF audit transport. Constructed early so it can
  // be attached to (a) the audit logger (used by the synchronous
  // enforcement path) and (b) the audit pipeline's `onSigned` sink
  // (used when R-9 async signing is enabled). When `OCSF_TRANSPORT`
  // is unset the factory returns `undefined` and OCSF stays off —
  // existing deployments get no behavioural change.
  const ocsfProduct = {
    name: 'euno-tool-gateway',
    vendor: 'Euno',
  };
  const ocsfTransport = createOcsfTransportFromEnv(env, logger);
  if (ocsfTransport) {
    logger.info('OCSF audit transport enabled', { transport: ocsfTransport.name });
  }

  // F-2: shared DPoP replay store. Wires Redis when `REDIS_URL` is
  // set so a captured proof can't be replayed once per replica
  // inside its acceptance window — the failure mode flagged by the
  // PR review of F-2. Falls back to per-process in-memory when no
  // Redis is configured (single-replica / dev). See
  // `RedisDpopReplayStore` for the SET NX semantics that make this
  // race-free.
  //
  // `onError` is late-bound via the closure below because the Prometheus
  // counter is registered after the stores are created (the registry
  // setup comes later). The callback is only invoked on live requests,
  // by which point the counter is guaranteed to be non-null.
  let redisErrorsCounter: Counter<string> | undefined;
  // H-1: shard mis-route counter; also late-bound for the same reason.
  let shardMisroutedCounter: Counter | undefined;
  // Late-bound counters for per-surface degradation signals.
  let revocationUnavailableCounter: Counter | undefined;
  let counterFallbackCounter: Counter | undefined;
  const dpopReplayStore: DpopReplayStore = await createDpopReplayStoreFromEnv(
    env,
    logger,
    () => redisErrorsCounter?.inc({ store: 'dpop_replay' }),
  );

  // Build the JWKS client (R-6).  Prefers ISSUER_JWKS_URL; falls back to
  // deriving the JWKS URL from the deprecated ISSUER_PUBLIC_KEY_URL base.
  const jwksCacheTtlMs = (validated.EUNO_JWKS_CACHE_TTL_SECONDS ?? 300) * 1000;
  const issuerJwksUrl = validated.ISSUER_JWKS_URL
    ?? deriveJwksUrl(validated.ISSUER_PUBLIC_KEY_URL)
    ?? 'http://localhost:3001/.well-known/jwks.json';

  if (!validated.ISSUER_JWKS_URL && validated.ISSUER_PUBLIC_KEY_URL) {
    logger.warn(
      'ISSUER_PUBLIC_KEY_URL is deprecated for gateway key bootstrap. ' +
        'Set ISSUER_JWKS_URL to the issuer\'s JWKS endpoint ' +
        '(e.g. https://issuer.example.com/.well-known/jwks.json) instead.',
      { derivedJwksUrl: issuerJwksUrl },
    );
  }

  const jwksClient = new JwksClient({
    jwksUrl: issuerJwksUrl,
    cacheTtlMs: jwksCacheTtlMs,
    logger,
  });

  logger.info('Fetching initial JWKS from Capability Issuer', { url: issuerJwksUrl });
  // Pre-warm the JWKS cache so the first token verification is synchronous.
  await jwksClient.getJwks();
  logger.info('JWKS fetched and cached successfully');

  const adminApiKey = validated.ADMIN_API_KEY;
  const requireKid = validated.EUNO_REQUIRE_KID !== undefined ? validated.EUNO_REQUIRE_KID : true;

  // R-7: load operator-supplied ActionResolver from disk if
  // ACTION_RESOLVER_FILE is set. The same file is consumed by the
  // capability-issuer so mint-time CA tiering and gateway action
  // derivation share a single vocabulary. Failure to load is a
  // startup error so misconfiguration cannot survive into a running
  // process. Falls back to the in-process BUILTIN_ACTION_RESOLVER
  // (legacy behaviour) when the env var is unset.
  let actionResolver: ActionResolver = BUILTIN_ACTION_RESOLVER;
  // Canonical SHA-256 of the operator-supplied ActionResolverConfig. When no
  // file is configured this equals computeActionResolverHash(null) — the same
  // sentinel the issuer publishes — so the hashes still agree when both sides
  // use the built-in defaults.
  let localActionResolverHash: string;
  if (validated.ACTION_RESOLVER_FILE && validated.ACTION_RESOLVER_FILE.trim().length > 0) {
    logger.info('Loading action resolver config from file', {
      path: validated.ACTION_RESOLVER_FILE,
    });
    const { resolver, hash } = loadActionResolverFromFileWithHash(validated.ACTION_RESOLVER_FILE);
    actionResolver = resolver;
    localActionResolverHash = hash;
    logger.info('Action resolver config loaded', { actionResolverHash: hash });
  } else {
    localActionResolverHash = computeActionResolverHash(null);
  }

  // Action resolver vocabulary parity check: fetch the issuer's discovery
  // document and compare its actionResolverHash with our locally-computed
  // hash. A mismatch means the issuer minted tokens with a different action
  // vocabulary than we will enforce — a silent privilege-drift vector.
  //
  // The metadata URL is taken from ISSUER_METADATA_URL if set; otherwise
  // derived from ISSUER_JWKS_URL by replacing the JWKS suffix with the
  // capability-issuer suffix.  When neither can be derived (unlikely in
  // practice: the gateway already requires ISSUER_JWKS_URL in production)
  // the check is skipped with a warning.
  const issuerMetadataUrl = deriveIssuerMetadataUrl(
    validated.ISSUER_METADATA_URL,
    issuerJwksUrl,
  );
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

  // Build the revocation store from environment.  Defaults to in-memory; if
  // REVOCATION_REDIS_URL or REDIS_URL is set we connect to Redis so revocations
  // are shared across gateway replicas.  See docs/DISTRIBUTED_REVOCATION.md.
  //
  // A dedicated circuit breaker is wired for the revocation stores so repeated
  // Redis failures trip the circuit to "open" and subsequent authorization
  // decisions fail immediately (no TCP timeout on every request).  The circuit
  // breaker is shared between the revocation and epoch stores because they use
  // the same Redis URL (REVOCATION_REDIS_URL / REDIS_URL).
  const cbConfig = {
    failureThreshold: (validated as { REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD?: number }).REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD ?? 5,
    windowMs: (validated as { REDIS_CIRCUIT_BREAKER_WINDOW_MS?: number }).REDIS_CIRCUIT_BREAKER_WINDOW_MS ?? 10_000,
    cooldownMs: (validated as { REDIS_CIRCUIT_BREAKER_COOLDOWN_MS?: number }).REDIS_CIRCUIT_BREAKER_COOLDOWN_MS ?? 30_000,
  };

  // Separate circuit breakers per control surface so a failure on the
  // revocation Redis does not trip the call-counter circuit (or vice versa).
  const revocationCircuitBreaker = new RedisCircuitBreaker({
    ...cbConfig,
    onStateChange: (from, to) => {
      logger.warn('Redis revocation circuit breaker state change', { from, to });
    },
  });
  const callCounterCircuitBreaker = new RedisCircuitBreaker({
    ...cbConfig,
    onStateChange: (from, to) => {
      logger.warn('Redis call-counter circuit breaker state change', { from, to });
    },
  });

  const revocationStore = await createRevocationStoreFromEnv(
    env,
    logger,
    () => redisErrorsCounter?.inc({ store: 'revocation' }),
    revocationCircuitBreaker,
    () => revocationUnavailableCounter?.inc(),
  );

  // Build the per-issuer epoch store from environment.  Defaults to in-memory;
  // if REVOCATION_REDIS_URL or REDIS_URL is set we use Redis so an epoch set
  // on one replica is immediately honoured by all others.  Epochs are a
  // "revoke-all-before-T" knob for incident response (key compromise).  Redis
  // errors fail-closed by default (REVOCATION_EPOCH_FAIL_OPEN=false).
  // The epoch store reuses the revocation circuit breaker because both stores
  // target the same Redis URL.
  const epochStore = await createRevocationEpochStoreFromEnv(
    env,
    logger,
    () => redisErrorsCounter?.inc({ store: 'revocation_epoch' }),
    revocationCircuitBreaker,
  );

  // Build the kill-switch manager from environment.  Defaults to the
  // in-process implementation; if KILL_SWITCH_REDIS_URL or REDIS_URL is set
  // we use the Redis-backed manager so kills (global / session / agent)
  // propagate across every gateway replica.  See docs/DISTRIBUTED_KILL_SWITCH.md.
  // `createKillSwitchManagerFromEnv` always returns a manager (in-process
  // when Redis is unset, Redis-backed otherwise).
  const killSwitchManager: KillSwitchManager = await createKillSwitchManagerFromEnv(env, logger);

  // Build the call-counter store used by `maxCalls` condition enforcement.
  // When sharding is enabled (GATEWAY_SHARD_COUNT > 1) we use a
  // ShardLocalCallCounterStore: the in-memory store handles owned agents
  // (zero Redis traffic on the hot path) while the Redis store covers
  // mis-routed traffic during topology changes. When sharding is disabled
  // (default), we fall back to the standard Redis / in-memory selection.
  let callCounterStore: CallCounterStore;
  {
    const shardCount = validated.GATEWAY_SHARD_COUNT ?? 1;
    const shardIndex = validated.GATEWAY_SHARD_INDEX ?? 0;

    if (shardCount > 1) {
      logger.info('Horizontal sharding enabled (H-1): using shard-local call-counter store', {
        shardCount,
        shardIndex,
      });
      // The base Redis store is still needed for mis-routed traffic.
      const remoteStore = await createCallCounterStoreFromEnv(
        env,
        logger,
        () => redisErrorsCounter?.inc({ store: 'call_counter' }),
        callCounterCircuitBreaker,
        () => counterFallbackCounter?.inc(),
      );
      callCounterStore = new ShardLocalCallCounterStore(
        new InMemoryCallCounterStore(),
        remoteStore,
        {
          shardIndex,
          shardCount,
          onMisrouted: () => shardMisroutedCounter?.inc(),
        },
        logger,
      );
    } else {
      callCounterStore = await createCallCounterStoreFromEnv(
        env,
        logger,
        () => redisErrorsCounter?.inc({ store: 'call_counter' }),
        callCounterCircuitBreaker,
        () => counterFallbackCounter?.inc(),
      );
    }
  }

  // Build the cross-org partner-issuer trust resolver.
  // The registry is constructed first so the resolver can consult it for trust
  // decisions and pin verification; the legacy TRUSTED_PARTNER_DIDS env-var path
  // is preserved as a seed-and-warn fallback (deprecated in non-production,
  // hard-error in production unless PARTNER_DID_REGISTRY_REQUIRED=false).
  //
  // When REDIS_URL is set the factory creates its own ioredis connection so
  // admin-API writes (propose/approve/revoke) propagate to all replicas.
  const partnerRegistry = await createPartnerDidRegistryFromEnv(
    env,
    logger,
    undefined, // let the factory auto-create from REDIS_URL when set
    {
      requirePin: validated.PARTNER_DID_REQUIRE_PIN,
      // registryRequired: intentionally omitted — factory derives from NODE_ENV
      // (production → default true unless PARTNER_DID_REGISTRY_REQUIRED=false;
      //  non-production → default false unless PARTNER_DID_REGISTRY_REQUIRED=true).
      keyPrefix: validated.PARTNER_DID_REGISTRY_KEY_PREFIX,
      deploymentTier: validated.EUNO_DEPLOYMENT_TIER,
      nodeEnv: validated.NODE_ENV,
    },
  );

  const pinAttestationSecret = validated.PARTNER_DID_PIN_SECRET || undefined;
  const partnerDidAutoFetchPin = validated.PARTNER_DID_AUTO_FETCH_PIN;

  const partnerResolver = createPartnerIssuerResolverFromEnv(env, logger, partnerRegistry);
  if (partnerResolver) {
    const partnerDidCount = (validated.TRUSTED_PARTNER_DIDS ?? []).length;
    logger.info('Cross-org partner-issuer trust resolver enabled', {
      partnerDidCount,
      pinAttestationEnabled: !!pinAttestationSecret,
      autoFetchPin: partnerDidAutoFetchPin,
    });
  }

  // Optional allow-list of issuers (DIDs or simple identifiers) that the
  // local SPKI key is authorised to sign for.
  const localIssuers = validated.LOCAL_ISSUER_IDS ?? [];

  const verifier = new JwksTokenVerifier(jwksClient, {
    revocationStore,
    epochStore,
    partnerResolver: partnerResolver ?? undefined,
    localIssuers: localIssuers.length > 0 ? localIssuers : undefined,
    requireKid,
    // Multi-issuer trust hardening: build the cosignature + transparency-log
    // verifier from env. Returns undefined when neither REQUIRE_COSIGNATURE_COUNT
    // nor REQUIRE_TRANSPARENCY_LOG_PROOF is set, in which case the verifier
    // chain runs as before (back-compat).
    proofsVerifier: buildProofsVerifierFromEnv(validated, logger),
  });

  // Replica identity — needed both for the ledger backend (stamped on each row)
  // and for Merkle batch commitments in the audit pipeline.  Compute once here
  // so both uses share the same value.
  const replicaIdFromEnv = (validated as { AUDIT_REPLICA_ID?: string }).AUDIT_REPLICA_ID;
  let replicaId = replicaIdFromEnv ?? 'unknown-replica';
  if (!replicaIdFromEnv) {
    try {
      replicaId = (require('os') as typeof import('os')).hostname();
    } catch {
      // hostname() failed — keep the default 'unknown-replica'
    }
  }

  // Missing-signer is treated as a startup error so misconfiguration cannot
  // survive into a running process.
  //
  // I-8: when EVIDENCE_SIGNED_DECISIONS is defined it is authoritative
  // (an explicitly-empty list disables signing even if the legacy
  // boolean is true); only fall back to ENABLE_CRYPTOGRAPHIC_AUDIT when
  // the env var is unset. This must match the schema-level rule and the
  // EnforcementEngine constructor so all three layers agree.
  const signedDecisions = validated.EVIDENCE_SIGNED_DECISIONS as
    | Array<'allow' | 'deny'>
    | undefined;
  const willSignSomething =
    signedDecisions !== undefined
      ? signedDecisions.length > 0
      : !!config.enableCryptographicAudit;

  let evidenceSigner: EvidenceSigner | undefined;
  // When a ledger backend is used the Postgres pool is created here; expose
  // it in GatewayDependencies so the entrypoint can call pool.end() on shutdown.
  let ledgerPgPool: import('@euno/common').PgPool | undefined;
  // When a ledger backend wraps the signing key, keep softwareSigner available
  // as a batchSigner (signBatch() does not use chain state, so the software
  // signer can still fulfil the AuditBatchSigner role even in ledger mode).
  let auditBatchSigner: AuditBatchSigner | undefined;
  if (willSignSomething) {
    try {
      // Build the base software signer first (key loading, algorithm validation).
      const softwareSigner = createSoftwareEvidenceSignerFromEnv(env);
      if (!softwareSigner) {
        throw new Error(
          'No evidence signer is configured. Provide ' +
            'EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded ' +
            'private key) and optionally EVIDENCE_SIGNING_ALGORITHM / ' +
            'EVIDENCE_SIGNING_KEY_ID, or wire a KMS-backed EvidenceSigner ' +
            'programmatically. Refusing to start with cryptographic audit ' +
            'enabled but no signer attached.',
        );
      }

      // Optionally wrap with a pluggable ledger backend to close the
      // "compromised replica rewrites local chain" gap.
      const ledgerBackendName = (validated as { AUDIT_LEDGER_BACKEND?: 'none' | 'postgres' | 'in-memory' | 'acl' }).AUDIT_LEDGER_BACKEND;
      if (ledgerBackendName && ledgerBackendName !== 'none') {
        const pgUrl = (validated as { AUDIT_LEDGER_PG_URL?: string }).AUDIT_LEDGER_PG_URL;
        const hmacSecret = (validated as { AUDIT_LEDGER_HMAC_SECRET?: string }).AUDIT_LEDGER_HMAC_SECRET;
        const table = (validated as { AUDIT_LEDGER_TABLE?: string }).AUDIT_LEDGER_TABLE;
        const runMigrations = (validated as { AUDIT_LEDGER_RUN_MIGRATIONS?: boolean }).AUDIT_LEDGER_RUN_MIGRATIONS ?? false;
        const s3Bucket = (validated as { AUDIT_LEDGER_S3_BUCKET?: string }).AUDIT_LEDGER_S3_BUCKET;
        const anchorInterval = (validated as { AUDIT_LEDGER_ANCHOR_INTERVAL?: number }).AUDIT_LEDGER_ANCHOR_INTERVAL ?? 1000;
        const aclEndpoint = (validated as { AUDIT_LEDGER_ACL_ENDPOINT?: string }).AUDIT_LEDGER_ACL_ENDPOINT;

        if (ledgerBackendName === 'postgres') {
          if (!pgUrl) {
            throw new Error(
              'AUDIT_LEDGER_BACKEND=postgres requires AUDIT_LEDGER_PG_URL to be set.',
            );
          }
          if (!hmacSecret) {
            throw new Error(
              'AUDIT_LEDGER_BACKEND=postgres requires AUDIT_LEDGER_HMAC_SECRET to be set.',
            );
          }
          if (s3Bucket) {
            // Fail fast: AUDIT_LEDGER_S3_BUCKET is set but the bootstrap does not
            // inject a real S3 client.  Operators must wire a client via
            // GatewayDependencies.ledgerPgPool or use a custom entrypoint that
            // constructs PostgresLedgerBackend directly with an S3AnchorClient.
            throw new Error(
              'AUDIT_LEDGER_S3_BUCKET is set but no S3 client is wired in the standard ' +
                'bootstrap. Provide an S3AnchorClient by constructing PostgresLedgerBackend ' +
                'directly (with the s3.client option) in a custom entrypoint, or unset ' +
                'AUDIT_LEDGER_S3_BUCKET to rely on HMAC + in-DB chain integrity only.',
            );
          }

          // Dynamically require pg to avoid a hard dependency in @euno/common.
          // The tool-gateway package.json must list 'pg' as a dependency when
          // AUDIT_LEDGER_BACKEND=postgres is used.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-var-requires
          const { Pool } = require('pg') as { Pool: new (cfg: { connectionString: string }) => import('@euno/common').PgPool };
          const pgPool = new Pool({ connectionString: pgUrl });
          // Expose the pool so the entrypoint can call pgPool.end() on graceful shutdown.
          ledgerPgPool = pgPool;

          const pgBackend = new PostgresLedgerBackend(pgPool, {
            table,
            hmacSecret,
            onAnchorError: (err: Error) => {
              logger.error('Ledger S3 anchor failed', { error: err.message });
            },
          });

          if (runMigrations) {
            // DDL at startup is appropriate for development / single-replica
            // deployments only. Production databases should grant DML-only
            // privileges to the gateway role and run schema migrations from
            // a dedicated identity (Helm pre-install hook, Flyway/Liquibase
            // job, etc.). Surface the relaxed posture in logs so it is
            // observable to anyone reviewing a running production cluster.
            if (validated.NODE_ENV === 'production') {
              logger.warn(
                'AUDIT_LEDGER_RUN_MIGRATIONS=true in production: the gateway service account ' +
                  'is performing DDL on the audit ledger table. Production deployments should ' +
                  'instead run migrations from a sidecar / Job under a separate database role ' +
                  'with DDL privileges and grant the gateway role only DML on the table. See ' +
                  'docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md §1.6.',
              );
            }
            await pgBackend.migrate();
            logger.info('Audit ledger migrations completed', { table: table ?? 'euno_audit_ledger' });
          }

          // Use getCryptoSigner() (the safe public accessor added to AuditEvidenceSigner)
          // instead of accessing the private field via a cast.
          const cryptoSigner = softwareSigner.getCryptoSigner();
          const ledgerSigner = new LedgerAuditEvidenceSigner(
            cryptoSigner,
            pgBackend,
            replicaId,
          );
          // initialize() delegates to pgBackend.initialize() which seeds
          // lastAnchoredSeq from the DB tip so a restart doesn't re-anchor
          // the entire existing history.
          await ledgerSigner.initialize();
          evidenceSigner = ledgerSigner;
          // Keep softwareSigner as batchSigner: signBatch() does not depend on
          // chain state, so it can remain the AuditBatchSigner even in ledger mode.
          auditBatchSigner = softwareSigner;

          logger.info('Audit ledger backend: postgres', {
            table: table ?? 'euno_audit_ledger',
            anchorInterval,
          });
        } else if (ledgerBackendName === 'acl') {
          // Prefer an explicitly injected client (custom entrypoint / testing).
          // Fall back to constructing one from AUDIT_LEDGER_ACL_ENDPOINT using
          // DefaultAzureCredential (requires @azure-rest/confidential-ledger and
          // @azure/identity in the deployment image).
          let aclClient: AzureConfidentialLedgerClient;
          if (injectDeps.ledgerAclClient) {
            aclClient = injectDeps.ledgerAclClient;
            logger.info('Audit ledger backend: acl (using injected client)');
          } else if (aclEndpoint) {
            aclClient = buildAclClientFromEndpoint(aclEndpoint);
            logger.info('Audit ledger backend: acl', { endpoint: aclEndpoint });
          } else {
            throw new Error(
              'AUDIT_LEDGER_BACKEND=acl requires either injectDeps.ledgerAclClient ' +
                '(injected AzureConfidentialLedgerClient) or AUDIT_LEDGER_ACL_ENDPOINT to be set. ' +
                'For managed identity / workload identity deployments set AUDIT_LEDGER_ACL_ENDPOINT; ' +
                'the bootstrap will use DefaultAzureCredential. For custom credential scenarios ' +
                'provide ledgerAclClient via the second argument to initializeServices().',
            );
          }

          const aclBackend = new AzureConfidentialLedgerBackend(aclClient, {
            onError: (err: Error) => {
              logger.error('Audit ledger ACL error', { error: err.message });
            },
          });
          const cryptoSigner = softwareSigner.getCryptoSigner();
          const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, aclBackend, replicaId);
          // initialize() delegates to aclBackend.initialize() which seeds
          // in-process chain state from the latest ACL transaction.
          await ledgerSigner.initialize();
          evidenceSigner = ledgerSigner;
          // Keep softwareSigner as batchSigner for the same reason as postgres mode.
          auditBatchSigner = softwareSigner;
        } else if (ledgerBackendName === 'in-memory') {
          const inMemBackend = new InMemoryLedgerBackend();
          const cryptoSigner = softwareSigner.getCryptoSigner();
          const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, inMemBackend, replicaId);
          await ledgerSigner.initialize();
          evidenceSigner = ledgerSigner;
          // Keep softwareSigner as batchSigner for the same reason as in postgres mode.
          auditBatchSigner = softwareSigner;
          logger.info('Audit ledger backend: in-memory (development only — not tamper-resistant)');
        } else {
          throw new Error(`Unknown AUDIT_LEDGER_BACKEND value: "${ledgerBackendName}"`);
        }
      } else {
        // No ledger backend — use the software signer with in-process chain state.
        evidenceSigner = softwareSigner;
        auditBatchSigner = softwareSigner;
        if (ledgerBackendName === 'none' || !ledgerBackendName) {
          logger.warn(
            'Cryptographic audit is enabled but AUDIT_LEDGER_BACKEND is not set. ' +
              'The hash chain lives only in process memory and a compromised replica ' +
              'can rewrite history. Set AUDIT_LEDGER_BACKEND=postgres for production.',
          );
        }
      }
    } catch (err) {
      // Re-throw LedgerChainError immediately — it indicates a serious integrity problem.
      if (err instanceof LedgerChainError) throw err;
      throw new Error(
        'Evidence signing is enabled (ENABLE_CRYPTOGRAPHIC_AUDIT=true with ' +
          'EVIDENCE_SIGNED_DECISIONS unset, or EVIDENCE_SIGNED_DECISIONS ' +
          'non-empty) but the configured evidence signer could not be ' +
          'initialised: ' +
          (err instanceof Error ? err.message : String(err)),
      );
    }
    if (!evidenceSigner) {
      throw new Error(
        'Evidence signing is enabled (ENABLE_CRYPTOGRAPHIC_AUDIT=true with ' +
          'EVIDENCE_SIGNED_DECISIONS unset, or EVIDENCE_SIGNED_DECISIONS ' +
          'non-empty) but no evidence signer is configured. Provide ' +
          'EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded ' +
          'private key) and optionally EVIDENCE_SIGNING_ALGORITHM / ' +
          'EVIDENCE_SIGNING_KEY_ID, or wire a KMS-backed EvidenceSigner ' +
          'programmatically. Refusing to start with cryptographic audit ' +
          'enabled but no signer attached.',
      );
    }
    if (signedDecisions !== undefined) {
      logger.info('Cryptographic audit enabled with per-decision signing', {
        signedDecisions,
      });
    } else {
      logger.info('Cryptographic audit enabled with software evidence signer');
    }
  }

  // F-5 (I-16): Prometheus surface. Build a per-process registry tagged with
  // the service name and pre-register gateway-specific series. We build this
  // before the audit pipeline so the pipeline's dropped/signed/error
  // counters (R-9) can be registered on the same registry.
  const metricsRegistry = createMetricsRegistry({ serviceName: 'tool-gateway' });
  new Gauge({
    name: 'euno_gateway_revocation_list_size',
    help: 'Number of revocation entries currently tracked by the in-process revocation store. ' +
      'May include expired entries that have not yet been pruned (the in-memory store ' +
      'prunes lazily on lookup/insert). Always 0 when a non-introspectable backend ' +
      '(e.g. Redis) is in use.',
    registers: [metricsRegistry],
    collect() {
      const store = revocationStore as { size?: () => number } | undefined;
      this.set(typeof store?.size === 'function' ? store.size() : 0);
    },
  });
  const decisionsCounter = new Counter({
    name: 'euno_gateway_decisions_total',
    help: 'Authorization decisions made by the gateway, labelled allow|deny.',
    labelNames: ['decision'],
    registers: [metricsRegistry],
  });
  // Pre-initialise the time-series so `rate()` queries succeed before the
  // first request flows through the gateway.
  decisionsCounter.inc({ decision: 'allow' }, 0);
  decisionsCounter.inc({ decision: 'deny' }, 0);

  // Redis store health counter. Incremented by any of the four
  // Redis-backed stores (DPoP replay, revocation, revocation_epoch, call-counter) on
  // every operational error. A non-zero rate indicates that Redis is
  // partially unavailable; a sustained high rate means the gateway is
  // running in fail-closed mode (DPoP replay / revocation / maxCalls)
  // and legitimate requests will be denied.
  redisErrorsCounter = new Counter({
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

  // Revocation-unavailability counter.  Incremented when the revocation store
  // cannot complete a check because Redis is unreachable AND the configured
  // unavailableMode is 'fail-closed' (→ 401) or '503' (→ 503 to caller).
  // Distinct from redisErrorsCounter in that it fires on EVERY degraded check,
  // not just on raw socket errors — once the circuit is open, errors stop but
  // degraded responses continue until Redis recovers.  A non-zero rate here
  // combined with zero redis_errors means the circuit is open.
  revocationUnavailableCounter = new Counter({
    name: 'euno_gateway_revocation_unavailable_total',
    help: 'Revocation checks that could not be completed because the backing store (Redis) was unreachable. ' +
      'Does not fire in stale-readable or fail-open mode (those serve from the local cache / allow through). ' +
      'A non-zero rate means the gateway is either fail-closing (→ 401) or returning 503 on token checks.',
    registers: [metricsRegistry],
  });
  revocationUnavailableCounter.inc(0);

  // Counter-fallback counter.  Incremented every time the call-counter store
  // falls back to the local in-memory counter (Redis error or circuit-open).
  // Unlike redisErrorsCounter, this fires on EVERY fallback, including when the
  // circuit is already open (no new errors, but counting locally).
  // Agents still get a 200 in this mode; the counter fires as a signal that
  // maxCalls enforcement has relaxed from fleet-wide to per-replica.
  counterFallbackCounter = new Counter({
    name: 'euno_gateway_counter_fallback_total',
    help: 'Call-counter increments served from the local in-memory fallback because Redis was unavailable. ' +
      'A non-zero rate means maxCalls enforcement is per-replica (effective cap = maxCalls × replicaCount). ' +
      'Requests are not denied (counter loss → 200 with metric); use alongside redis_errors for root-cause.',
    registers: [metricsRegistry],
  });
  counterFallbackCounter.inc(0);

  // Circuit-breaker state gauges.  0 = closed (healthy), 1 = half-open
  // (probing), 2 = open (failing fast — Redis unreachable).  A sustained
  // value of 2 means the gateway is serving from its local cache / fallback
  // for the corresponding control surface.
  new Gauge({
    name: 'euno_gateway_redis_circuit_state',
    help: 'State of the Redis circuit breaker for each control-surface store: 0=closed (healthy), 1=half-open (probing), 2=open (failing fast). ' +
      'A value of 2 means the store is serving from its local fallback (stale-readable / local-counter mode).',
    labelNames: ['store'],
    registers: [metricsRegistry],
    collect() {
      const toNumeric = (s: string): number => {
        switch (s) {
          case 'closed': return 0;
          case 'half-open': return 1;
          case 'open': return 2;
          // No default needed: CircuitState is a union of the three cases
          // above; the exhaustive switch is a compile-time guarantee.
          default: return 0;
        }
      };
      this.set({ store: 'revocation' }, toNumeric(revocationCircuitBreaker.getState()));
      this.set({ store: 'call_counter' }, toNumeric(callCounterCircuitBreaker.getState()));
    },
  });

  // H-1: Horizontal sharding metrics.
  // `euno_gateway_shard_info` — static labels with the shard topology so
  // dashboards can correlate per-shard metrics to replica identity.
  // `euno_gateway_shard_local_counter_size` — size of the in-memory call
  // counter cache on this shard; a rising value means agents are accumulating
  // history (normal); a value at zero in a sharded deployment means the shard
  // is not receiving traffic (abnormal — check the Envoy router).
  // `euno_gateway_shard_misrouted_total` — mis-routed requests (LB topology
  // change in progress or misconfigured router); a sustained non-zero rate
  // means the Envoy router's shard count does not match GATEWAY_SHARD_COUNT.
  {
    const shardCount = validated.GATEWAY_SHARD_COUNT ?? 1;
    const shardIndex = validated.GATEWAY_SHARD_INDEX ?? 0;

    new Gauge({
      name: 'euno_gateway_shard_info',
      help: 'Static labels describing the shard topology of this replica.',
      labelNames: ['shard_index', 'shard_count'],
      registers: [metricsRegistry],
      collect() {
        this.set({ shard_index: String(shardIndex), shard_count: String(shardCount) }, 1);
      },
    });

    // Register unconditionally so the series always exists in Prometheus.
    // Returns 0 when sharding is disabled (GATEWAY_SHARD_COUNT <= 1) because
    // the store is not a ShardLocalCallCounterStore in that case.
    new Gauge({
      name: 'euno_gateway_shard_local_counter_size',
      help:
        'Number of in-memory call-counter entries held by the shard-local store on this replica. ' +
        'Non-zero only when GATEWAY_SHARD_COUNT > 1 and traffic is flowing to this shard.',
      registers: [metricsRegistry],
      collect() {
        const store = callCounterStore as { localSize?: () => number } | undefined;
        this.set(typeof store?.localSize === 'function' ? store.localSize() : 0);
      },
    });

    if (shardCount > 1) {

      shardMisroutedCounter = new Counter({
        name: 'euno_gateway_shard_misrouted_total',
        help:
          'Requests whose agent `sub` does not hash to this shard. ' +
          'A non-zero steady-state rate means the Envoy shard router is mis-configured or ' +
          'its shard count does not match GATEWAY_SHARD_COUNT.',
        registers: [metricsRegistry],
      });
      shardMisroutedCounter.inc(0);
    }
  }

  // R-9: build the async audit pipeline when evidence signing is on AND
  // the operator hasn't opted out via AUDIT_PIPELINE_ENABLED=false. The
  // pipeline lifts signEvidence off the request critical path; the
  // legacy synchronous behaviour is reachable for A/B comparison by
  // setting AUDIT_PIPELINE_ENABLED=false.
  let auditPipeline: AuditPipeline | undefined;
  const auditPipelineDrainTimeoutMs = validated.AUDIT_PIPELINE_DRAIN_TIMEOUT_MS;
  if (evidenceSigner && validated.AUDIT_PIPELINE_ENABLED) {
    const droppedCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_dropped_total',
      help: 'Audit-evidence records dropped by the async pipeline before they could be signed. ' +
        'Labelled by reason: queue_full (buffer full, waiter cap reached, or pipeline stopped) ' +
        'or aged_out (record exceeded AUDIT_PIPELINE_MAX_AGE_MS while waiting). A non-zero rate ' +
        'is the operator\'s signal to raise AUDIT_PIPELINE_MAX_SIZE / AUDIT_PIPELINE_WORKERS or ' +
        'to investigate signer latency.',
      labelNames: ['reason'],
      registers: [metricsRegistry],
    });
    droppedCounter.inc({ reason: 'queue_full' }, 0);
    droppedCounter.inc({ reason: 'aged_out' }, 0);

    const signedCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_signed_total',
      help: 'Audit-evidence records successfully signed by the async pipeline.',
      registers: [metricsRegistry],
    });
    signedCounter.inc(0);

    const signErrorsCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_sign_errors_total',
      help: 'Audit-evidence records the async pipeline failed to sign (signer rejection). ' +
        'A persistent non-zero rate indicates a broken signer key or KMS outage.',
      registers: [metricsRegistry],
    });
    signErrorsCounter.inc(0);

    new Gauge({
      name: 'euno_gateway_audit_pipeline_queue_depth',
      help: 'Current number of unsigned audit-evidence records buffered in the async pipeline ring.',
      registers: [metricsRegistry],
      collect() {
        this.set(auditPipeline ? auditPipeline.queueDepth() : 0);
      },
    });

    // Build the audit-log sink once, reuse it across every signed
    // record. Matches the logger the synchronous path in
    // `EnforcementEngine.generateEvidence` uses, so log routing is
    // identical whether or not R-9 is enabled.
    // F-7: stamp `region` on every audit record so multi-region
    // deployments can attribute events to a region after a regional
    // failover. Omitted when GATEWAY_REGION is unset (back-compat).
    const pipelineAuditLogger = createAuditLogger('tool-gateway', {
      region: validated.GATEWAY_REGION,
    });
    // F-6: bridge AuditLogEntry-shaped log records into OCSF.
    if (ocsfTransport) {
      pipelineAuditLogger.add(createOcsfWinstonTransport(ocsfTransport, ocsfProduct));
    }

    const backpressure: BackpressurePolicy =
      (validated.AUDIT_PIPELINE_BACKPRESSURE as BackpressurePolicy | undefined) ??
      'drop_oldest_with_metric';

    // replicaId was computed above (before the evidence signer block)
    // so the ledger backend and batch commitments use the same value.

    // Build the batch emitted/error counters BEFORE the pipeline so they
    // exist even if no batches are processed during startup.
    const batchEmittedCounter = new Counter({
      name: 'euno_gateway_audit_batch_emitted_total',
      help: 'Merkle batch commitments emitted by the async pipeline (signed or unsigned). ' +
        'Each emission anchors a set of signed audit-evidence records in the per-replica batch chain. ' +
        'Unsigned emissions occur when EVIDENCE_SIGNING_KEY_PEM is not set (dev/staging only).',
      registers: [metricsRegistry],
    });
    batchEmittedCounter.inc(0);

    const batchErrorsCounter = new Counter({
      name: 'euno_gateway_audit_batch_errors_total',
      help: 'Errors producing or anchoring Merkle batch commitments (signing failures + per-anchor publish failures). ' +
        'A non-zero rate means the batch chain may have gaps; investigate the signer or anchor endpoint.',
      registers: [metricsRegistry],
    });
    batchErrorsCounter.inc(0);

    // Batch logger: a dedicated structured logger for batch commitments so
    // SIEM queries can filter on `message === "Audit batch commitment"`.
    const batchAuditLogger = createAuditLogger('tool-gateway', {
      region: validated.GATEWAY_REGION,
    });

    // Timeout for the HTTP anchor's fetch call (milliseconds).
    // Prevents a hung TCP connection or slow TLS handshake from stalling
    // the pipeline worker indefinitely.
    const AUDIT_ANCHOR_TIMEOUT_MS = 30_000;

    // HTTP anchor — optional external endpoint (WORM bucket, transparency log, etc.)
    const anchors: AuditAnchor[] = [];
    const anchorUrl = (validated as { AUDIT_ANCHOR_URL?: string }).AUDIT_ANCHOR_URL;
    if (anchorUrl) {
      anchors.push({
        name: 'http',
        async anchorBatch(commitment: SignedBatchCommitment): Promise<void> {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), AUDIT_ANCHOR_TIMEOUT_MS);
          let response: Response;
          try {
            response = await fetch(anchorUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(commitment),
              signal: controller.signal,
            });
          } catch (err) {
            logger.error('Audit batch HTTP anchor failed', {
              error: err instanceof Error ? err.message : String(err),
              anchorUrl,
              timedOut: controller.signal.aborted,
            });
            // Re-throw so the pipeline records this via onBatchError.
            throw err;
          } finally {
            clearTimeout(timer);
          }
          if (!response.ok) {
            const msg = `HTTP anchor returned ${response.status}`;
            logger.warn('Audit batch HTTP anchor returned non-OK status', {
              status: response.status,
              anchorUrl,
              batchId: commitment.batchId,
            });
            // Throw so the pipeline records this via onBatchError.
            throw new Error(msg);
          }
        },
      });
      logger.info('Audit batch HTTP anchor configured', { anchorUrl });
    }

    // Use the explicitly-tracked auditBatchSigner (set alongside evidenceSigner above)
    // so batch commitments remain signed when a ledger backend wraps the evidence signer.
    // (AuditEvidenceSigner.signBatch() does not rely on chain state and is safe to use
    // as a batchSigner even when LedgerAuditEvidenceSigner handles per-record signing.)
    const batchSigner = auditBatchSigner;

    auditPipeline = createAuditPipeline({
      signer: evidenceSigner,
      maxSize: validated.AUDIT_PIPELINE_MAX_SIZE,
      workers: validated.AUDIT_PIPELINE_WORKERS,
      maxBatchSize: validated.AUDIT_PIPELINE_MAX_BATCH,
      maxAgeMs: validated.AUDIT_PIPELINE_MAX_AGE_MS,
      backpressure,
      maxWaiters: validated.AUDIT_PIPELINE_MAX_WAITERS,
      replicaId,
      batchSigner,
      anchors,
      onDropped: (count: number, reason: string) => {
        droppedCounter.inc({ reason }, count);
      },
      onSigned: (signed: SignedAuditEvidence) => {
        signedCounter.inc();
        // Mirror the per-record audit log line the synchronous path
        // emits, so operators searching for a specific evidence id
        // still find it once R-9 is enabled.
        try {
          pipelineAuditLogger.info('Cryptographic evidence generated', {
            evidenceId: signed.id,
            sessionId: signed.sessionId,
            decision: signed.decision,
            signature: signed.signature.substring(0, 20) + '...',
            seq: signed.seq,
            previousHash: signed.previousHash.substring(0, 16) + '...',
          });
        } catch {
          // Audit-log emission is best-effort; never break signing on it.
        }
        // F-6: forward the signed evidence to the OCSF sink. Errors
        // from the transport are swallowed inside `send` itself, so
        // we never need to wrap this in a try/catch.
        if (ocsfTransport) {
          void ocsfTransport.send(signedEvidenceToOcsf(signed, ocsfProduct));
        }
      },
      onSignError: (err: unknown) => {
        signErrorsCounter.inc();
        logger.error('Audit pipeline failed to sign evidence', {
          error: err instanceof Error ? err.message : String(err),
        });
      },
      onBatch: (commitment: SignedBatchCommitment) => {
        batchEmittedCounter.inc();
        try {
          batchAuditLogger.info('Audit batch commitment', {
            batchId: commitment.batchId,
            replicaId: commitment.replicaId,
            batchSeq: commitment.batchSeq,
            merkleRoot: commitment.merkleRoot,
            recordCount: commitment.recordCount,
            firstSeq: commitment.firstSeq,
            lastSeq: commitment.lastSeq,
            previousBatchHash: commitment.previousBatchHash.substring(0, 16) + '...',
          });
        } catch {
          // Audit-log emission is best-effort.
        }
      },
      onBatchError: (err: unknown) => {
        batchErrorsCounter.inc();
        logger.error('Audit batch commitment failed', {
          error: err instanceof Error ? err.message : String(err),
        });
      },
    });

    logger.info('Async audit pipeline enabled (R-9)', {
      maxSize: validated.AUDIT_PIPELINE_MAX_SIZE,
      workers: validated.AUDIT_PIPELINE_WORKERS,
      maxBatchSize: validated.AUDIT_PIPELINE_MAX_BATCH,
      maxAgeMs: validated.AUDIT_PIPELINE_MAX_AGE_MS,
      backpressure,
      maxWaiters: validated.AUDIT_PIPELINE_MAX_WAITERS ?? validated.AUDIT_PIPELINE_MAX_SIZE,
      replicaId,
      batchSigningEnabled: !!batchSigner,
      httpAnchorEnabled: !!anchorUrl,
    });
  } else if (evidenceSigner && !validated.AUDIT_PIPELINE_ENABLED) {
    logger.warn(
      'Async audit pipeline disabled (AUDIT_PIPELINE_ENABLED=false); ' +
        'evidence signing runs on the request critical path.',
    );
  }

  // Gateway quota engine (F-1b). Re-uses the existing callCounterStore
  // so no additional Redis client is needed. Enabled only when
  // GATEWAY_QUOTA_ENABLED=true to preserve pre-F-1b behaviour.
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
    // F-7: stamp region on every enforcement audit record (deny logs,
    // signed evidence). Symmetrical to ISSUER_REGION.
    region: validated.GATEWAY_REGION,
    // F-6: bridge AuditLogEntry-shaped log records the enforcement
    // engine emits on the request hot path (`Action allowed` /
    // `Action denied`) into OCSF. Without this hook OCSF would only
    // see `pipelineAuditLogger`'s "Cryptographic evidence generated"
    // line and miss every synchronous deny.
    ...(ocsfTransport
      ? { auditTransports: [createOcsfWinstonTransport(ocsfTransport, ocsfProduct)] }
      : {}),
    // F-2: DPoP / RFC 9449 sender-constrained tokens. `required=true`
    // (the default) refuses any token without `cnf.jkt`; set
    // DPOP_REQUIRED=false only for back-compat deployments where
    // issuers haven't been rolled out with DPoP support yet. The
    // replay store is per-instance unless wired to a shared backend
    // — multi-replica deployments using `REDIS_URL` get a
    // Redis-backed store automatically.
    dpop: {
      required: validated.DPOP_REQUIRED,
      clockSkewSeconds: validated.DPOP_CLOCK_SKEW_SECONDS,
      maxAgeSeconds: validated.DPOP_MAX_AGE_SECONDS,
      replayStore: dpopReplayStore,
    },
    // Cross-tenant audience defence: tokens are only accepted when
    // their `aud` claim matches GATEWAY_AUDIENCE. Defaults to
    // "tool-gateway" when not configured (back-compat).
    ...(validated.GATEWAY_AUDIENCE ? { gatewayAudience: validated.GATEWAY_AUDIENCE } : {}),
  });

  let ready = false;
  const setReady = (value: boolean) => {
    ready = value;
  };

  const rateLimitWindowMs = validated.RATE_LIMIT_WINDOW_MS;
  const rateLimitMax = validated.RATE_LIMIT_MAX_REQUESTS;

  enforcementEngine.setDecisionRecorder((decision) => {
    decisionsCounter.inc({ decision });
  });

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
    adminApiKey,
    backendServiceUrl: validated.BACKEND_SERVICE_URL || 'http://localhost:4000',
    adminPort: validated.ADMIN_PORT,
    // Trim `ADMIN_HOST` so values like " 127.0.0.1 " (whitespace from
    // a templated env var or downward-API source) bind correctly. The
    // schema's production-tier check already trims before validating,
    // so storing the raw string here would let a config that passed
    // validation still fail at `listen()` time with EADDRNOTAVAIL.
    adminHost: validated.ADMIN_HOST?.trim() || undefined,
    allowedOrigins: resolveAllowedOrigins(env, config.environment),
    rateLimitWindowMs,
    rateLimitMax,
    metricsRegistry,
    decisionsCounter,
    isReady: () => ready,
    region: validated.GATEWAY_REGION,
    trustProxy: parseTrustProxy(validated.TRUST_PROXY),
    actionResolver,
    partnerResolver: partnerResolver ?? undefined,
    partnerRegistry,
    requirePin: validated.PARTNER_DID_REQUIRE_PIN === true,
    pinAttestationSecret,
    partnerDidAutoFetchPin,
    responseRedactionMaxBytes: validated.RESPONSE_REDACTION_MAX_BYTES,
  };

  logger.info('Tool Gateway services initialized successfully');
  return { deps, setReady };
}

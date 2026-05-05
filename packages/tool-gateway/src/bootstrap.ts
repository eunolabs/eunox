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
  createSoftwareEvidenceSignerFromEnv,
  KillSwitchManager,
  createKillSwitchManagerFromEnv,
  CallCounterStore,
  createCallCounterStoreFromEnv,
  InMemoryCallCounterStore,
  ShardLocalCallCounterStore,
  createLogger,
  createAuditLogger,
  loadActionResolverFromFile,
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
} from '@euno/common';
import { JWTTokenVerifier, JwksTokenVerifier } from './verifier';
import { buildProofsVerifierFromEnv } from './proofs-verifier-bootstrap';
import { JwksClient } from './jwks-client';
import { EnforcementEngine } from './enforcement';
import { createRevocationStoreFromEnv, RevocationStore, createRevocationEpochStoreFromEnv, RevocationEpochStore } from './revocation-store';
import { createPartnerIssuerResolverFromEnv } from './partner-issuer-resolver';

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
 * Fetch the issuer public key, build verifier + enforcement engine and all
 * supporting stores. Throws on misconfiguration so the gateway fails closed.
 *
 * Returns the dependency bag consumed by `createApp(deps)` plus the
 * `setReady` toggle the entrypoint flips once the server starts listening.
 */
export async function initializeServices(
  env: NodeJS.ProcessEnv = process.env,
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
  if (validated.ACTION_RESOLVER_FILE && validated.ACTION_RESOLVER_FILE.trim().length > 0) {
    logger.info('Loading action resolver config from file', {
      path: validated.ACTION_RESOLVER_FILE,
    });
    actionResolver = loadActionResolverFromFile(validated.ACTION_RESOLVER_FILE);
    logger.info('Action resolver config loaded');
  }

  // Build the revocation store from environment.  Defaults to in-memory; if
  // REDIS_URL is set we connect to Redis so revocations are shared across
  // gateway replicas.  See docs/DISTRIBUTED_REVOCATION.md.
  const revocationStore = await createRevocationStoreFromEnv(
    env,
    logger,
    () => redisErrorsCounter?.inc({ store: 'revocation' }),
  );

  // Build the per-issuer epoch store from environment.  Defaults to in-memory;
  // if REDIS_URL is set we use Redis so an epoch set on one replica is
  // immediately honoured by all others.  Epochs are a "revoke-all-before-T"
  // knob for incident response (key compromise).  Redis errors fail-closed by
  // default (REVOCATION_EPOCH_FAIL_OPEN=false): the store returns the current
  // time as the epoch, blocking all tokens until Redis recovers.
  const epochStore = await createRevocationEpochStoreFromEnv(
    env,
    logger,
    () => redisErrorsCounter?.inc({ store: 'revocation_epoch' }),
  );

  // Build the kill-switch manager from environment.  Defaults to the
  // in-process implementation; if REDIS_URL is set we use the Redis-backed
  // manager so kills (global / session / agent) propagate across every
  // gateway replica.  See docs/DISTRIBUTED_KILL_SWITCH.md.
  // `createKillSwitchManagerFromEnv` always returns a manager (in-process
  // when REDIS_URL is unset, Redis-backed otherwise).
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
      );
    }
  }

  // Build the cross-org partner-issuer trust resolver.
  const partnerResolver = createPartnerIssuerResolverFromEnv(env, logger);
  if (partnerResolver) {
    const partnerDidCount = (env.TRUSTED_PARTNER_DIDS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean).length;
    logger.info('Cross-org partner-issuer trust resolver enabled', { partnerDidCount });
  }

  // Optional allow-list of issuers (DIDs or simple identifiers) that the
  // local SPKI key is authorised to sign for.
  const localIssuers = (env.LOCAL_ISSUER_IDS || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

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

  // Build the cryptographic evidence signer when audit signing is enabled.
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
  if (willSignSomething) {
    try {
      evidenceSigner = createSoftwareEvidenceSignerFromEnv(env);
    } catch (err) {
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

    auditPipeline = createAuditPipeline({
      signer: evidenceSigner,
      maxSize: validated.AUDIT_PIPELINE_MAX_SIZE,
      workers: validated.AUDIT_PIPELINE_WORKERS,
      maxBatchSize: validated.AUDIT_PIPELINE_MAX_BATCH,
      maxAgeMs: validated.AUDIT_PIPELINE_MAX_AGE_MS,
      backpressure,
      maxWaiters: validated.AUDIT_PIPELINE_MAX_WAITERS,
      onDropped: (count, reason) => {
        droppedCounter.inc({ reason }, count);
      },
      onSigned: (signed) => {
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
      onSignError: (err) => {
        signErrorsCounter.inc();
        logger.error('Audit pipeline failed to sign evidence', {
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
    });
  } else if (evidenceSigner && !validated.AUDIT_PIPELINE_ENABLED) {
    logger.warn(
      'Async audit pipeline disabled (AUDIT_PIPELINE_ENABLED=false); ' +
        'evidence signing runs on the request critical path.',
    );
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
    responseRedactionMaxBytes: validated.RESPONSE_REDACTION_MAX_BYTES,
  };

  logger.info('Tool Gateway services initialized successfully');
  return { deps, setReady };
}

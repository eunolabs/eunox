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
  ServiceConfig,
  EvidenceSigner,
  createSoftwareEvidenceSignerFromEnv,
  KillSwitchManager,
  createKillSwitchManagerFromEnv,
  CallCounterStore,
  createCallCounterStoreFromEnv,
  createLogger,
  loadConfigOrExit,
  loadConfig,
  GatewayConfig,
  createMetricsRegistry,
  Counter,
  Gauge,
  Registry,
} from '@euno/common';
import { JWTTokenVerifier, JwksTokenVerifier } from './verifier';
import { JwksClient } from './jwks-client';
import { EnforcementEngine } from './enforcement';
import { createRevocationStoreFromEnv, RevocationStore } from './revocation-store';
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
  evidenceSigner?: EvidenceSigner;
  /** Optional admin API key; when set the admin router enforces it. */
  adminApiKey?: string;
  /** Backend service URL for the proxy route. */
  backendServiceUrl: string;
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

  // Build the revocation store from environment.  Defaults to in-memory; if
  // REDIS_URL is set we connect to Redis so revocations are shared across
  // gateway replicas.  See docs/DISTRIBUTED_REVOCATION.md.
  const revocationStore = await createRevocationStoreFromEnv(env, logger);

  // Build the kill-switch manager from environment.  Defaults to the
  // in-process implementation; if REDIS_URL is set we use the Redis-backed
  // manager so kills (global / session / agent) propagate across every
  // gateway replica.  See docs/DISTRIBUTED_KILL_SWITCH.md.
  // `createKillSwitchManagerFromEnv` always returns a manager (in-process
  // when REDIS_URL is unset, Redis-backed otherwise).
  const killSwitchManager: KillSwitchManager = await createKillSwitchManagerFromEnv(env, logger);

  // Build the call-counter store used by `maxCalls` condition enforcement.
  const callCounterStore = await createCallCounterStoreFromEnv(env, logger);

  // Build the cross-org partner-issuer trust resolver.
  const partnerResolver = createPartnerIssuerResolverFromEnv(env);
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
    partnerResolver: partnerResolver ?? undefined,
    localIssuers: localIssuers.length > 0 ? localIssuers : undefined,
    requireKid,
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

  const enforcementEngine = new EnforcementEngine({
    verifier,
    logger,
    killSwitchManager,
    evidenceSigner,
    enableCryptographicAudit: config.enableCryptographicAudit,
    signedDecisions,
    argumentSchemaRequired: validated.ARGUMENT_SCHEMA_REQUIRED,
    policyVersion: config.policyVersion,
    callCounterStore,
  });

  let ready = false;
  const setReady = (value: boolean) => {
    ready = value;
  };

  const rateLimitWindowMs = validated.RATE_LIMIT_WINDOW_MS;
  const rateLimitMax = validated.RATE_LIMIT_MAX_REQUESTS;

  // F-5 (I-16): Prometheus surface. Build a per-process registry tagged with
  // the service name and pre-register gateway-specific series:
  //   - `euno_gateway_revocation_list_size` is collected on each scrape from
  //     the active revocation store (when the implementation exposes a
  //     `size()` accessor — currently the in-memory store; Redis-backed
  //     deployments can add their own collector later without changing the
  //     metric name). Operators use this to detect runaway revocation-list
  //     growth that signals abuse or a stuck pruner.
  //   - `euno_gateway_decisions_total{decision}` is incremented by the
  //     EnforcementEngine on every allow / deny so a deny-rate panel does
  //     not have to parse logs.
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
    evidenceSigner,
    adminApiKey,
    backendServiceUrl: validated.BACKEND_SERVICE_URL || 'http://localhost:4000',
    allowedOrigins: resolveAllowedOrigins(env, config.environment),
    rateLimitWindowMs,
    rateLimitMax,
    metricsRegistry,
    decisionsCounter,
    isReady: () => ready,
  };

  logger.info('Tool Gateway services initialized successfully');
  return { deps, setReady };
}

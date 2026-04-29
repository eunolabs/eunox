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
} from '@euno/common';
import axios from 'axios';
import { JWTTokenVerifier } from './verifier';
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
  const issuerPublicKeyUrl =
    validated.ISSUER_PUBLIC_KEY_URL || 'http://localhost:3001/api/v1/public-key';
  const adminApiKey = validated.ADMIN_API_KEY;

  logger.info('Fetching public key from Capability Issuer', { url: issuerPublicKeyUrl });
  const response = await axios.get(issuerPublicKeyUrl);
  const publicKey = response?.data?.publicKey;
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    throw new Error(
      `Invalid public key response from Capability Issuer at ${issuerPublicKeyUrl}: ` +
        `expected non-empty string at \`publicKey\`, got ${typeof publicKey}`,
    );
  }

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

  const verifier = new JWTTokenVerifier(
    publicKey,
    undefined,
    revocationStore,
    partnerResolver,
    localIssuers.length > 0 ? localIssuers : undefined,
  );

  // Build the cryptographic evidence signer when audit signing is enabled.
  // Missing-signer is treated as a startup error so misconfiguration cannot
  // survive into a running process.
  let evidenceSigner: EvidenceSigner | undefined;
  if (config.enableCryptographicAudit) {
    try {
      evidenceSigner = createSoftwareEvidenceSignerFromEnv(env);
    } catch (err) {
      throw new Error(
        'ENABLE_CRYPTOGRAPHIC_AUDIT=true but the configured evidence signer ' +
          'could not be initialised: ' +
          (err instanceof Error ? err.message : String(err)),
      );
    }
    if (!evidenceSigner) {
      throw new Error(
        'ENABLE_CRYPTOGRAPHIC_AUDIT=true but no evidence signer is configured. ' +
          'Provide EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded ' +
          'private key) and optionally EVIDENCE_SIGNING_ALGORITHM / EVIDENCE_SIGNING_KEY_ID, ' +
          'or wire a KMS-backed EvidenceSigner programmatically. Refusing to start ' +
          'with cryptographic audit enabled but no signer attached.',
      );
    }
    logger.info('Cryptographic audit enabled with software evidence signer');
  }

  const enforcementEngine = new EnforcementEngine({
    verifier,
    logger,
    killSwitchManager,
    evidenceSigner,
    enableCryptographicAudit: config.enableCryptographicAudit,
    policyVersion: config.policyVersion,
    callCounterStore,
  });

  let ready = false;
  const setReady = (value: boolean) => {
    ready = value;
  };

  const rateLimitWindowMs = validated.RATE_LIMIT_WINDOW_MS;
  const rateLimitMax = validated.RATE_LIMIT_MAX_REQUESTS;

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
    isReady: () => ready,
  };

  logger.info('Tool Gateway services initialized successfully');
  return { deps, setReady };
}

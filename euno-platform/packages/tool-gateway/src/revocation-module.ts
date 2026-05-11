/**
 * Revocation module — Redis-backed control-surface stores.
 *
 * Encapsulates construction of:
 *   • Revocation store (token JTI block-list)
 *   • Revocation epoch store (revoke-all-before-T knob)
 *   • Kill-switch manager (global / session / agent kill)
 *   • Call-counter store (maxCalls enforcement, optionally shard-local)
 *   • Partner DID registry + resolver (cross-org trust harness)
 *
 * All metric callbacks MUST be fully bound when passed — the
 * late-binding pattern from the pre-R-3 bootstrap has been eliminated.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  CallCounterStore,
  createCallCounterStoreFromEnv,
  createKillSwitchManagerFromEnv,
  createLogger,
  GatewayConfig,
  InMemoryCallCounterStore,
  KillSwitchManager,
  RedisCircuitBreaker,
  ShardLocalCallCounterStore,
} from '@euno/common';
import {
  createRevocationEpochStoreFromEnv,
  createRevocationStoreFromEnv,
  RevocationEpochStore,
  RevocationStore,
} from './revocation-store';
import {
  createPartnerDidRegistryFromEnv,
  InMemoryPartnerDidRegistry,
  RedisPartnerDidRegistry,
} from './partner-did-registry';
import {
  createPartnerIssuerResolverFromEnv,
  PartnerIssuerResolver,
  type PartnerIssuerResolverFromEnvOptions,
} from './partner-issuer-resolver';

type Logger = ReturnType<typeof createLogger>;

export interface RevocationModuleCallbacks {
  /**
   * Called on every Redis error on the specified control-surface store.
   * `store` is one of: `'revocation'`, `'revocation_epoch'`, `'call_counter'`.
   */
  onRedisError: (store: string) => void;
  /**
   * Called when the revocation store cannot complete a check (circuit open
   * or Redis unreachable) and the configured unavailableMode returns 401 or 503.
   */
  onRevocationUnavailable: () => void;
  /**
   * Called every time a call-counter increment falls back to the local
   * in-memory store (Redis error or circuit-open).
   */
  onCounterFallback: () => void;
  /**
   * Called when a request is routed to the wrong shard (H-1).
   * Only invoked when `GATEWAY_SHARD_COUNT > 1`.
   */
  onShardMisrouted: () => void;
  /**
   * Called on every per-DID partner circuit-breaker state transition.
   */
  onPartnerCircuitStateChange: (did: string, from: string, to: string) => void;
}

export interface RevocationModuleResult {
  revocationStore: RevocationStore;
  epochStore: RevocationEpochStore;
  killSwitchManager: KillSwitchManager;
  callCounterStore: CallCounterStore;
  /** Shared circuit breaker for the revocation + epoch stores. */
  revocationCircuitBreaker: RedisCircuitBreaker;
  /** Shared circuit breaker for the call-counter store. */
  callCounterCircuitBreaker: RedisCircuitBreaker;
  /** Partner DID registry (two-eyes lifecycle management). */
  partnerRegistry: InMemoryPartnerDidRegistry | RedisPartnerDidRegistry;
  /** Partner issuer resolver (cross-org trust harness). Undefined when not configured. */
  partnerResolver: PartnerIssuerResolver | undefined;
}

/**
 * Build all Redis-backed control-surface stores.
 *
 * @param callbacks Fully-bound metric callbacks.
 *   The caller MUST pre-bind its Prometheus counters before calling this
 *   function — unlike the previous late-binding pattern in bootstrap.ts.
 */
export async function buildRevocationModule(
  validated: GatewayConfig,
  env: NodeJS.ProcessEnv,
  logger: Logger,
  callbacks: RevocationModuleCallbacks,
): Promise<RevocationModuleResult> {
  // Circuit breaker config — fields are declared in GatewayConfigSchema with
  // schema-level defaults (5 / 10 000 ms / 30 000 ms) so they are always present
  // after validation. No type-cast or nullish-coalescing needed here.
  const cbConfig = {
    failureThreshold: validated.REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    windowMs: validated.REDIS_CIRCUIT_BREAKER_WINDOW_MS,
    cooldownMs: validated.REDIS_CIRCUIT_BREAKER_COOLDOWN_MS,
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
    () => callbacks.onRedisError('revocation'),
    revocationCircuitBreaker,
    () => callbacks.onRevocationUnavailable(),
  );

  // Per-issuer epoch store. Reuses the revocation circuit breaker because
  // both stores target the same Redis URL.
  const epochStore = await createRevocationEpochStoreFromEnv(
    env,
    logger,
    () => callbacks.onRedisError('revocation_epoch'),
    revocationCircuitBreaker,
  );

  const killSwitchManager: KillSwitchManager = await createKillSwitchManagerFromEnv(env, logger);

  // Call-counter store — shard-local when GATEWAY_SHARD_COUNT > 1.
  const shardCount = validated.GATEWAY_SHARD_COUNT ?? 1;
  const shardIndex = validated.GATEWAY_SHARD_INDEX ?? 0;

  let callCounterStore: CallCounterStore;
  if (shardCount > 1) {
    logger.info('Horizontal sharding enabled (H-1): using shard-local call-counter store', {
      shardCount,
      shardIndex,
    });
    const remoteStore = await createCallCounterStoreFromEnv(
      env,
      logger,
      () => callbacks.onRedisError('call_counter'),
      callCounterCircuitBreaker,
      () => callbacks.onCounterFallback(),
    );
    callCounterStore = new ShardLocalCallCounterStore(
      new InMemoryCallCounterStore(),
      remoteStore,
      {
        shardIndex,
        shardCount,
        onMisrouted: () => callbacks.onShardMisrouted(),
      },
      logger,
    );
  } else {
    callCounterStore = await createCallCounterStoreFromEnv(
      env,
      logger,
      () => callbacks.onRedisError('call_counter'),
      callCounterCircuitBreaker,
      () => callbacks.onCounterFallback(),
    );
  }

  // Cross-org partner DID registry + resolver.
  const partnerRegistry = await createPartnerDidRegistryFromEnv(
    env,
    logger,
    undefined, // let the factory auto-create from REDIS_URL when set
    {
      requirePin: validated.PARTNER_DID_REQUIRE_PIN,
      keyPrefix: validated.PARTNER_DID_REGISTRY_KEY_PREFIX,
      deploymentTier: validated.EUNO_DEPLOYMENT_TIER,
      nodeEnv: validated.NODE_ENV,
    },
  );

  const partnerResolverOptions: PartnerIssuerResolverFromEnvOptions = {
    onCircuitStateChange: (did, from, to) => {
      callbacks.onPartnerCircuitStateChange(did, from, to);
      logger.warn('Partner DID circuit breaker state change', { did, from, to });
    },
  };

  const partnerResolver = createPartnerIssuerResolverFromEnv(env, logger, partnerRegistry, partnerResolverOptions);
  if (partnerResolver) {
    const partnerDidCount = (validated.TRUSTED_PARTNER_DIDS ?? []).length;
    logger.info('Cross-org partner-issuer trust resolver enabled', {
      partnerDidCount,
      pinAttestationEnabled: !!(validated.PARTNER_DID_PIN_SECRET),
      autoFetchPin: validated.PARTNER_DID_AUTO_FETCH_PIN,
      circuitBreakerFailureThreshold: validated.PARTNER_DID_CB_FAILURE_THRESHOLD,
      circuitBreakerWindowSeconds: validated.PARTNER_DID_CB_WINDOW_SECONDS,
      circuitBreakerCooldownSeconds: validated.PARTNER_DID_CB_COOLDOWN_SECONDS,
    });
  }

  return {
    revocationStore,
    epochStore,
    killSwitchManager,
    callCounterStore,
    revocationCircuitBreaker,
    callCounterCircuitBreaker,
    partnerRegistry,
    partnerResolver: partnerResolver ?? undefined,
  };
}

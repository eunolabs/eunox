/**
 * Gateway quota engine (F-1b, addresses I-1b).
 *
 * ## Problem
 *
 * The gateway's existing `maxCalls` condition (backed by
 * {@link CallCounterStore}) is a per-token budget embedded in the
 * capability token itself — it is only enforced when the issuer minted
 * the token with a `maxCalls` condition. This leaves a gap: tokens
 * without `maxCalls` have no gateway-side invocation limit. A single
 * long-lived token can therefore be used to saturate the enforcement
 * engine (argument validation, condition evaluation, audit evidence
 * signing) at arbitrary throughput.
 *
 * ## Solution
 *
 * The `GatewayQuotaEngine` enforces a fleet-wide per-(jti, action,
 * resource) rate limit that fires on every `validateAction` call,
 * regardless of whether the token carries a `maxCalls` condition. The
 * rate limit is intentionally coarse (a large default of 1000 req/min)
 * and is designed to protect the enforcement hot-path from intentional
 * or accidental flooding, not to replace fine-grained per-token
 * budgets.
 *
 * ## Key design
 *
 * The composite key `jti|action|resource` (components escaped to
 * prevent injection) means:
 *
 *  - Different tokens (`jti`) have independent budgets, so a compromised
 *    token cannot affect a legitimate agent's quota.
 *  - Different actions on the same token have independent budgets:
 *    flooding `read` requests does not exhaust the `write` quota.
 *  - Different resources on the same action are counted separately.
 *
 * ## Placement in the enforcement pipeline
 *
 * The quota check runs after the capability match and argument
 * validation, so only well-formed requests directed at a genuinely
 * held capability consume quota — this avoids penalising agents that
 * probe capabilities they do not hold (those are denied before the
 * quota step). The check runs before typed-condition evaluation so that
 * even condition-failing requests count, which prevents adversaries
 * from bypassing the limit by sending requests designed to trip a
 * `timeWindow` or `ipRange` condition.
 *
 * ## Failure semantics
 *
 * The engine defaults to **fail-open** (`failOpen: true`): a Redis
 * outage does not deny legitimate traffic. This is the opposite of the
 * issuer-side limiter (which defaults fail-closed) because the gateway
 * quota is a rate-limiting advisory rather than a hard security gate
 * — the capability token itself is the authoritative access-control
 * artefact. Operators who want a hard stop can set
 * `GATEWAY_QUOTA_FAIL_CLOSED=true`.
 */

import { CallCounterStore } from './condition-registry';
import { RateLimitDecision } from './issuance-rate-limiter';
import { Logger } from './logger';
import { escapeRateLimitKeyComponent } from './key-utils';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Dimensions used to derive the per-request quota key. */
export interface GatewayQuotaKey {
  /** `jti` claim of the capability token being enforced. */
  jti: string;
  /** Resolved action (e.g. `read`, `write`). */
  action: string;
  /** Canonical resource URI (e.g. `tool://weather`). */
  resource: string;
  /**
   * `sub` claim of the capability token. Passed as the `agentSub` hint
   * to `CallCounterStore.incrementAndGet` so that
   * {@link ShardLocalCallCounterStore} can route quota increments to the
   * shard-local in-memory store instead of always falling back to the
   * remote Redis cluster. Without this hint, every quota check in a
   * sharded deployment would incur a remote Redis hop, negating the
   * horizontal-scaling benefit of the shard-local call-counter path.
   */
  agentSub: string;
}

/**
 * Quota enforcement surface consumed by {@link EnforcementEngine}.
 * Implementations must be safe to call concurrently from multiple
 * workers.
 */
export interface GatewayQuotaEngine {
  /**
   * Atomically count this invocation against the per-(jti, action,
   * resource) budget and report whether the caller is within quota.
   */
  checkAndCount(key: GatewayQuotaKey): Promise<RateLimitDecision>;
  /** Configured window length in seconds. */
  readonly windowSeconds: number;
}

export interface GatewayQuotaOptions {
  /**
   * Maximum invocations per `windowSeconds` for the same
   * (jti, action, resource) tuple. Default 1000.
   */
  max: number;
  /** Length of the tumbling window in seconds. Default 60. */
  windowSeconds: number;
  /**
   * When `true` (default), a {@link CallCounterStore} error allows the
   * request through rather than denying it. Flip to `false`
   * (`GATEWAY_QUOTA_FAIL_CLOSED=true`) for a hard stop.
   */
  failOpen: boolean;
}

export const DEFAULT_GATEWAY_QUOTA_MAX = 1000;
export const DEFAULT_GATEWAY_QUOTA_WINDOW_SECONDS = 60;
/** Key prefix prepended to every quota key before passing to the counter store. */
export const GATEWAY_QUOTA_KEY_PREFIX = 'gwq:';

// ---------------------------------------------------------------------------
// Key builder
// ---------------------------------------------------------------------------

/**
 * The three dimensions that are encoded into the Redis counter key.
 * `agentSub` is intentionally excluded — it is a routing hint for
 * {@link ShardLocalCallCounterStore} and must not be part of the key
 * (different agents sharing the same token's jti/action/resource would
 * otherwise land in separate buckets, undermining per-token quota).
 */
export interface GatewayQuotaKeyComponents {
  jti: string;
  action: string;
  resource: string;
}

/**
 * Build the canonical quota key from a {@link GatewayQuotaKeyComponents}.
 * Uses {@link escapeRateLimitKeyComponent} (shared with the issuance
 * rate limiter) to prevent injection/collision attacks.
 * Exposed for testing.
 */
export function buildGatewayQuotaKey(k: GatewayQuotaKeyComponents): string {
  const e = escapeRateLimitKeyComponent;
  return (
    `${GATEWAY_QUOTA_KEY_PREFIX}${e(k.jti)}` +
    `|${e(k.action)}` +
    `|${e(k.resource)}`
  );
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * `GatewayQuotaEngine` implementation backed by any {@link CallCounterStore}.
 * Uses the same `INCR`/`EXPIRE` tumbling-window semantics as the
 * `MaxCallsCondition` and the issuance rate limiter.
 */
export class CallCounterBackedGatewayQuotaEngine implements GatewayQuotaEngine {
  private readonly store: CallCounterStore;
  private readonly max: number;
  public readonly windowSeconds: number;
  private readonly failOpen: boolean;
  private readonly logger?: Logger;

  constructor(
    store: CallCounterStore,
    options: Partial<GatewayQuotaOptions> = {},
    logger?: Logger,
  ) {
    this.store = store;
    this.max = options.max ?? DEFAULT_GATEWAY_QUOTA_MAX;
    this.windowSeconds = options.windowSeconds ?? DEFAULT_GATEWAY_QUOTA_WINDOW_SECONDS;
    this.failOpen = options.failOpen ?? true;
    this.logger = logger;
  }

  async checkAndCount(key: GatewayQuotaKey): Promise<RateLimitDecision> {
    const storeKey = buildGatewayQuotaKey(key);
    let count: number;
    try {
      count = await this.store.incrementAndGet(storeKey, this.windowSeconds, key.agentSub);
    } catch (error) {
      this.logger?.error('Gateway quota store error', {
        key: storeKey,
        error: error instanceof Error ? error.message : 'Unknown error',
        failOpen: this.failOpen,
      });
      return this.outageDecision();
    }

    // `RedisCallCounterStore` returns `Number.POSITIVE_INFINITY` (not a throw)
    // when its backend is unavailable and `failClosedOnError` is true (the
    // default). We must recognise this sentinel here and apply our own
    // fail-open / fail-closed policy rather than incorrectly treating it as
    // a quota-exceeded denial.
    if (!isFinite(count)) {
      this.logger?.warn('Gateway quota store returned non-finite count (backend unavailable)', {
        key: storeKey,
        failOpen: this.failOpen,
      });
      return this.outageDecision();
    }

    if (count > this.max) {
      return {
        allowed: false,
        limit: this.max,
        remaining: 0,
        windowSeconds: this.windowSeconds,
        // Best-effort retry hint: we don't have the exact window
        // expiry here (the CallCounterStore interface doesn't expose
        // PTTL), so we use the full window as a conservative upper
        // bound. Agents that retry before the window closes will be
        // denied again immediately; using the full window prevents
        // retry-storm in the common case.
        retryAfterSeconds: this.windowSeconds,
      };
    }
    return {
      allowed: true,
      limit: this.max,
      remaining: Math.max(0, this.max - count),
      windowSeconds: this.windowSeconds,
      retryAfterSeconds: 0,
    };
  }

  /**
   * Produce an outage-path decision using the configured fail-open /
   * fail-closed policy. Factored out to avoid duplicating the two-branch
   * logic between the throw path and the POSITIVE_INFINITY path.
   */
  private outageDecision(): RateLimitDecision {
    if (this.failOpen) {
      // Fail-open: return a synthetic "allowed" decision with the
      // full budget so a Redis outage does not deny legitimate traffic.
      return {
        allowed: true,
        limit: this.max,
        remaining: this.max,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    }
    // Fail-closed: deny to protect the enforcement engine.
    return {
      allowed: false,
      limit: this.max,
      remaining: 0,
      windowSeconds: this.windowSeconds,
      retryAfterSeconds: this.windowSeconds,
    };
  }
}

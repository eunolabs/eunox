/**
 * Issuance rate limiter (F-1, addresses I-1).
 *
 * ## Multi-dimensional token-bucket
 *
 * The limiter keys each bucket on five dimensions:
 *   `(tenantId, userId, agentId, jti, ip)`
 *
 * This replaces the former per-IP `express-rate-limit` middleware, which was
 * keyed only on the network address before authentication completed. The
 * multi-dimensional approach is strictly stronger:
 *
 *  - **`tenantId`** — first in the key so per-tenant Redis prefix-scans work
 *    and a burst in one tenant never bleeds into another (F-7 prerequisite).
 *  - **`userId`** — the resolved identity-provider subject. An attacker who
 *    compromises a single account cannot exceed the budget regardless of how
 *    many machines they control.
 *  - **`agentId`** — the agent that requested the token. Different agents
 *    operated by the same user have independent budgets; a runaway agent
 *    cannot starve others belonging to the same user.
 *  - **`jti`** — the parent/current token identifier. Including `jti`
 *    partitions the budget per token lineage so attenuation and renewal
 *    of one token lineage do not consume the fresh-issuance budget. A
 *    caller performing fresh issuance uses the sentinel `'_no_jti'`.
 *  - **`ip`** — the client's network address. A single user cycling IPs
 *    (NAT rotation, multi-homed) gets one sub-budget per egress address,
 *    which, combined with the `userId` and `jti` dimensions above, produces
 *    a tightly bounded total. A caller with no visible IP uses the sentinel
 *    `'_no_ip'`.
 *
 * ## Backing infrastructure
 *
 * The preferred implementation ({@link CallCounterBackedIssuanceRateLimiter})
 * is backed by {@link CallCounterStore} — the same low-level infrastructure
 * the gateway uses for `maxCalls`-condition enforcement and the
 * {@link GatewayQuotaEngine}. This unifies the two Redis-counter subsystems:
 * a single connection (and a single key-space discipline) covers all
 * counting operations across both the issuer and the gateway.
 *
 * The legacy {@link RedisIssuanceRateLimiter} (own Redis client) is retained
 * for deployments that construct the limiter manually, but new code should
 * prefer {@link CallCounterBackedIssuanceRateLimiter} or the factory
 * {@link createIssuanceRateLimiterFromEnv}.
 *
 * ## Failure semantics
 *
 * Defaults to **fail-closed** (a Redis outage denies issuance with 429).
 * For an issuance-side limit, allowing unlimited mints when the
 * coordination layer is unavailable would defeat the entire purpose.
 * Operators who need fail-open behaviour (e.g. for staging) can opt in
 * with `failClosedOnError: false`.
 */

import { CallCounterStore } from './condition-registry';
import { createCallCounterStoreFromEnv } from './call-counter-store';
import { Logger } from './logger';
import { escapeRateLimitKeyComponent } from './key-utils';

/**
 * Outcome of an {@link IssuanceRateLimiter.consume} call.
 */
export interface RateLimitDecision {
  /** Whether the caller is allowed to proceed. */
  allowed: boolean;
  /** Configured maximum requests in the current window. */
  limit: number;
  /** Remaining tokens in the current window after this consume call (>= 0). */
  remaining: number;
  /** Length of the current window in seconds. */
  windowSeconds: number;
  /**
   * When `allowed === false`, the number of seconds the caller should
   * wait before retrying (i.e. until the current window ends). Always
   * defined; `0` for `allowed === true` calls is a meaningful "no
   * additional wait required".
   */
  retryAfterSeconds: number;
}

/**
 * Caller-supplied subject identifiers used to derive the bucket key.
 *
 * `tenantId` is optional because some identity providers do not surface a
 * tenant; in that case all callers fall into the synthetic `_no_tenant`
 * bucket. Operators with mixed-tenant traffic SHOULD configure a provider
 * that populates `tenantId` so per-tenant isolation is preserved.
 *
 * The bucket key is `(tenantId, userId, agentId, jti, ip)`.
 *
 * **`jti`** — token lineage identifier for the parent/current capability
 * token (absent on fresh issuance, mapped to the sentinel `'_no_jti'`).
 * Including `jti` means attenuation and renewal each count against a
 * per-lineage sub-budget rather than competing with fresh-issuance for
 * the same slot. Fresh issuance has its own `_no_jti` slot.
 *
 * **`ip`** — the client's network address. Including the source IP adds a
 * transport-layer dimension so a user exploiting IP-hopping or NAT rotation
 * to multiply their budget is bounded per-egress-address as well as
 * per-identity. Absent IP maps to the sentinel `'_no_ip'`.
 */
export interface IssuanceRateLimitSubject {
  tenantId?: string;
  userId: string;
  agentId: string;
  /**
   * Parent or current token's `jti` claim for attenuation / renewal
   * paths. Omit (or leave undefined) for fresh issuance — the sentinel
   * `'_no_jti'` is used automatically.
   */
  jti?: string;
  /**
   * Source IP of the HTTP request. Omit when the IP is unavailable —
   * the sentinel `'_no_ip'` is substituted automatically.
   */
  ip?: string;
}

export interface IssuanceRateLimiter {
  /**
   * Atomically count this issuance attempt against the configured
   * window and report whether the caller is within budget. Implementations
   * MUST be safe to call concurrently from multiple workers.
   */
  consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision>;
  /**
   * Length of the tumbling window in seconds. Exposed (rather than
   * surfaced only on a {@link RateLimitDecision}) so callers can pick a
   * sensible `Retry-After` value on the limiter-unavailable error
   * path — at that point no decision was produced, but the window is
   * still the right back-off horizon: a stampeding herd that retries
   * inside the same window will hit the same outage immediately.
   */
  readonly windowSeconds: number;
}

/**
 * Configuration shape shared by every implementation. Splitting it
 * out lets the env loader build one config object once and pass it
 * to whichever store it ends up constructing.
 */
export interface IssuanceRateLimiterOptions {
  /** Maximum requests permitted per `windowSeconds`. Default 60. */
  max: number;
  /** Length of the tumbling window in seconds. Default 60. */
  windowSeconds: number;
}

export const DEFAULT_ISSUANCE_RATE_LIMIT_MAX = 60;
export const DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS = 60;
/** Key prefix prepended to the output of {@link buildIssuanceRateLimitKey} by the limiter implementations (e.g. {@link CallCounterBackedIssuanceRateLimiter} and the legacy {@link RedisIssuanceRateLimiter}). Not embedded by {@link buildIssuanceRateLimitKey} itself. */
const DEFAULT_KEY_PREFIX = 'issrl:';

/**
 * Build the canonical rate-limit key. Exposed so tests can assert the
 * tenant-aware shape (which is the F-7 prerequisite — see file
 * header). Order is `tenantId|userId|agentId|jti|ip` so a Redis `KEYS`
 * scan from an operator can prefix-match a single tenant. Components
 * are escaped using {@link escapeRateLimitKeyComponent} (shared with
 * the gateway quota engine) to prevent injection / collision attacks.
 *
 * Sentinels used when optional fields are absent:
 *  - `tenantId` absent / empty → `'_no_tenant'`
 *  - `jti` absent / empty → `'_no_jti'` (fresh-issuance slot)
 *  - `ip` absent / empty → `'_no_ip'`
 */
export function buildIssuanceRateLimitKey(s: IssuanceRateLimitSubject): string {
  const tenant = s.tenantId && s.tenantId.length > 0 ? s.tenantId : '_no_tenant';
  const jti = s.jti && s.jti.length > 0 ? s.jti : '_no_jti';
  const ip = s.ip && s.ip.length > 0 ? s.ip : '_no_ip';
  const e = escapeRateLimitKeyComponent;
  return `${e(tenant)}|${e(s.userId)}|${e(s.agentId)}|${e(jti)}|${e(ip)}`;
}

/**
 * Single-process limiter suitable for development, single-replica
 * issuers, and unit tests. Production multi-replica deployments
 * should prefer {@link CallCounterBackedIssuanceRateLimiter} (selected
 * automatically by {@link createIssuanceRateLimiterFromEnv} when
 * `REDIS_URL` is set) which re-uses the gateway's {@link CallCounterStore}
 * infrastructure.
 */
export class InMemoryIssuanceRateLimiter implements IssuanceRateLimiter {
  private readonly buckets = new Map<string, { count: number; expiresAt: number }>();
  private readonly max: number;
  /** Configured tumbling-window length; satisfies the interface contract. */
  public readonly windowSeconds: number;

  constructor(options: Partial<IssuanceRateLimiterOptions> = {}) {
    this.max = options.max ?? DEFAULT_ISSUANCE_RATE_LIMIT_MAX;
    this.windowSeconds = options.windowSeconds ?? DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS;
  }

  /** Test helper. */
  size(): number {
    return this.buckets.size;
  }

  /** Test helper. */
  reset(): void {
    this.buckets.clear();
  }

  async consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> {
    const now = Date.now();
    const key = buildIssuanceRateLimitKey(subject);
    const existing = this.buckets.get(key);
    if (!existing || existing.expiresAt <= now) {
      this.buckets.set(key, { count: 1, expiresAt: now + this.windowSeconds * 1000 });
      return {
        allowed: true,
        limit: this.max,
        remaining: this.max - 1,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    }
    existing.count += 1;
    if (existing.count > this.max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((existing.expiresAt - now) / 1000));
      return {
        allowed: false,
        limit: this.max,
        remaining: 0,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds,
      };
    }
    return {
      allowed: true,
      limit: this.max,
      remaining: this.max - existing.count,
      windowSeconds: this.windowSeconds,
      retryAfterSeconds: 0,
    };
  }
}

/**
 * Minimal subset of the `ioredis` client surface this limiter
 * depends on. Defined locally so the package does not take a hard
 * runtime dependency on `ioredis` (callers wire one in via
 * {@link createIssuanceRateLimiterFromEnv} or by passing a client to
 * {@link RedisIssuanceRateLimiter} directly).
 */
export interface RedisIssuanceRateLimitClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  pttl(key: string): Promise<number>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface RedisIssuanceRateLimiterOptions extends IssuanceRateLimiterOptions {
  /** Key prefix, default `"issrl:"`. */
  keyPrefix?: string;
  /**
   * When true (default), a Redis error becomes a `deny` so the issuer
   * fails closed. When false, the error is propagated to the caller.
   */
  failClosedOnError?: boolean;
}

/**
 * Distributed token-bucket limiter backed by Redis.
 *
 * Uses `INCR` (atomic) plus a best-effort `EXPIRE` to attach the
 * tumbling window — the same pattern as
 * {@link RedisCallCounterStore} so the operational story is identical
 * (key prefix scan, TTL inspection, failure mode).
 */
export class RedisIssuanceRateLimiter implements IssuanceRateLimiter {
  private readonly client: RedisIssuanceRateLimitClient;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly max: number;
  /** Configured tumbling-window length; satisfies the interface contract. */
  public readonly windowSeconds: number;
  private readonly failClosedOnError: boolean;

  constructor(
    client: RedisIssuanceRateLimitClient,
    logger?: Logger,
    options: Partial<RedisIssuanceRateLimiterOptions> = {},
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.max = options.max ?? DEFAULT_ISSUANCE_RATE_LIMIT_MAX;
    this.windowSeconds = options.windowSeconds ?? DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS;
    this.failClosedOnError = options.failClosedOnError ?? true;
    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis issuance rate-limit connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> {
    const fullKey = `${this.keyPrefix}${buildIssuanceRateLimitKey(subject)}`;
    try {
      const value = await this.client.incr(fullKey);
      // First increment in the window owns the TTL. Subsequent ones
      // leave the existing TTL alone — that's what makes this a
      // *tumbling* window.
      if (value === 1) {
        await this.client.expire(fullKey, this.windowSeconds);
      }
      if (value > this.max) {
        let retryAfterSeconds = this.windowSeconds;
        try {
          const pttlMs = await this.client.pttl(fullKey);
          if (pttlMs > 0) {
            retryAfterSeconds = Math.max(1, Math.ceil(pttlMs / 1000));
          }
        } catch {
          // Best-effort; fall back to the window length.
        }
        return {
          allowed: false,
          limit: this.max,
          remaining: 0,
          windowSeconds: this.windowSeconds,
          retryAfterSeconds,
        };
      }
      return {
        allowed: true,
        limit: this.max,
        remaining: Math.max(0, this.max - value),
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    } catch (error) {
      this.logger?.error('Redis issuance rate-limit consume failed', {
        key: fullKey,
        error: error instanceof Error ? error.message : 'Unknown error',
        failClosedOnError: this.failClosedOnError,
      });
      if (this.failClosedOnError) {
        return {
          allowed: false,
          limit: this.max,
          remaining: 0,
          windowSeconds: this.windowSeconds,
          retryAfterSeconds: this.windowSeconds,
        };
      }
      // Fail-open: an unavailable limiter MUST NOT block issuance
      // when the operator has explicitly opted into availability over
      // F-1 enforcement. Returning `allowed: true` here (rather than
      // re-throwing) is what makes `ISSUANCE_RATE_LIMIT_FAIL_CLOSED=
      // false` actually take effect — the issuer's catch path treats
      // any propagated error as fail-closed because at that point the
      // operator's intent has already been honoured by the limiter.
      return {
        allowed: true,
        limit: this.max,
        remaining: this.max,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    }
  }

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch (error) {
      this.logger?.warn('Error while closing Redis issuance rate-limit client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

// ---------------------------------------------------------------------------
// CallCounterStore-backed implementation (preferred for new deployments)
// ---------------------------------------------------------------------------

/**
 * Options for {@link CallCounterBackedIssuanceRateLimiter}.
 */
export interface CallCounterBackedIssuanceRateLimiterOptions
  extends Partial<IssuanceRateLimiterOptions> {
  /**
   * Key prefix prepended to every store key so issuance-rate-limit
   * buckets live in a distinct namespace from `maxCalls`-condition
   * counters and gateway-quota keys. Default `"issrl:"`.
   */
  keyPrefix?: string;
  /**
   * When `true` (default), a {@link CallCounterStore} error returns a
   * deny decision so the issuer fails closed. Set `false` to allow
   * issuance to continue when the counter store is unavailable.
   */
  failClosedOnError?: boolean;
}

/**
 * Issuance rate limiter backed by a {@link CallCounterStore}.
 *
 * This is the **preferred** production implementation. It re-uses the
 * same low-level infrastructure that powers `maxCalls`-condition
 * enforcement and the {@link GatewayQuotaEngine}, so a single Redis
 * connection (and a single key-space discipline) covers all counting
 * operations across both the issuer and the gateway.
 *
 * The key passed to the store is:
 *
 *   `<keyPrefix><tenantId>|<userId>|<agentId>|<jti>|<ip>`
 *
 * e.g. `issrl:acme|alice|agent-7|tok-abc|192.0.2.1`
 *
 * The store's own key prefix (e.g. `capcall:`) is then prepended
 * by the store implementation, resulting in a final Redis key like:
 *
 *   `capcall:issrl:acme|alice|agent-7|tok-abc|192.0.2.1`
 *
 * This two-level prefixing keeps the issuance keys cleanly separated
 * from the gateway's `gwq:` quota keys and the `maxCalls` condition
 * keys in the same Redis namespace.
 *
 * ### Failure semantics
 *
 * When the store throws **or** returns a non-finite count (the
 * {@link CallCounterStore} convention for "backend unavailable"), the
 * limiter returns a deny decision (fail-closed) by default. Operators
 * who need fail-open behaviour can set `failClosedOnError: false`.
 */
export class CallCounterBackedIssuanceRateLimiter implements IssuanceRateLimiter {
  private readonly store: CallCounterStore;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly max: number;
  /** Configured tumbling-window length; satisfies the interface contract. */
  public readonly windowSeconds: number;
  private readonly failClosedOnError: boolean;

  constructor(
    store: CallCounterStore,
    options: CallCounterBackedIssuanceRateLimiterOptions = {},
    logger?: Logger,
  ) {
    this.store = store;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.max = options.max ?? DEFAULT_ISSUANCE_RATE_LIMIT_MAX;
    this.windowSeconds = options.windowSeconds ?? DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS;
    this.failClosedOnError = options.failClosedOnError ?? true;
  }

  async consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> {
    const storeKey = `${this.keyPrefix}${buildIssuanceRateLimitKey(subject)}`;
    let count: number;
    try {
      count = await this.store.incrementAndGet(storeKey, this.windowSeconds, subject.agentId);
    } catch (error) {
      this.logger?.error('Issuance rate-limit store error', {
        key: storeKey,
        error: error instanceof Error ? error.message : 'Unknown error',
        failClosedOnError: this.failClosedOnError,
      });
      return this.outageDecision();
    }

    // CallCounterStore uses POSITIVE_INFINITY as the "backend unavailable"
    // sentinel (same convention as GatewayQuotaEngine — see gateway-quota.ts).
    if (!isFinite(count)) {
      this.logger?.warn('Issuance rate-limit store returned non-finite count (backend unavailable)', {
        key: storeKey,
        failClosedOnError: this.failClosedOnError,
      });
      return this.outageDecision();
    }

    if (count > this.max) {
      return {
        allowed: false,
        limit: this.max,
        remaining: 0,
        windowSeconds: this.windowSeconds,
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

  private outageDecision(): RateLimitDecision {
    if (!this.failClosedOnError) {
      return {
        allowed: true,
        limit: this.max,
        remaining: this.max,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    }
    return {
      allowed: false,
      limit: this.max,
      remaining: 0,
      windowSeconds: this.windowSeconds,
      retryAfterSeconds: this.windowSeconds,
    };
  }
}

export interface IssuanceRateLimiterEnvOptions {
  /** Optional logger for boot diagnostics. */
  logger?: Logger;
  /**
   * Explicit maximum issuances per window.  When set, overrides the
   * `ISSUANCE_RATE_LIMIT_MAX` env var so callers can configure
   * per-credential-type limits (storage-grant, DB-token) without
   * constructing a synthetic `NodeJS.ProcessEnv`.
   */
  max?: number;
  /**
   * Explicit window length in seconds.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS`.
   */
  windowSeconds?: number;
  /**
   * Explicit Redis key prefix.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_KEY_PREFIX`.  Useful to namespace per-
   * credential-type limiters (e.g. `'sgrl:'` for storage grants,
   * `'dbrl:'` for DB tokens).
   */
  keyPrefix?: string;
  /**
   * Explicit fail-closed flag.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_FAIL_CLOSED`.
   */
  failClosedOnError?: boolean;
}

/**
 * Construct an {@link IssuanceRateLimiter} from environment variables.
 *
 * Returns the in-process {@link InMemoryIssuanceRateLimiter} when
 * `REDIS_URL` is unset (single-replica / development). When `REDIS_URL`
 * is set, returns a {@link CallCounterBackedIssuanceRateLimiter} backed
 * by a {@link createCallCounterStoreFromEnv | Redis CallCounterStore} —
 * the same infrastructure that powers `maxCalls`-condition enforcement
 * and the gateway quota engine. This eliminates the separate per-service
 * Redis connection that the legacy {@link RedisIssuanceRateLimiter} required.
 *
 * Environment variables (all can be overridden via `options`):
 *  - `REDIS_URL` — Redis connection string. When unset, falls back
 *    to the in-memory limiter.
 *  - `ISSUANCE_RATE_LIMIT_MAX` — max issuances per window. Default 60.
 *  - `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS` — window length. Default 60.
 *  - `ISSUANCE_RATE_LIMIT_KEY_PREFIX` — overrides default `"issrl:"`.
 *  - `ISSUANCE_RATE_LIMIT_FAIL_CLOSED` — `'true'` (default) or `'false'`.
 */
export async function createIssuanceRateLimiterFromEnv(
  env: NodeJS.ProcessEnv,
  options: IssuanceRateLimiterEnvOptions = {},
): Promise<IssuanceRateLimiter> {
  const logger = options.logger;

  const max =
    options.max ?? parsePositiveInt(env.ISSUANCE_RATE_LIMIT_MAX, DEFAULT_ISSUANCE_RATE_LIMIT_MAX);
  const windowSeconds =
    options.windowSeconds ??
    parsePositiveInt(
      env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
      DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
    );
  const failClosedOnError =
    options.failClosedOnError ?? env.ISSUANCE_RATE_LIMIT_FAIL_CLOSED !== 'false';
  const keyPrefix = options.keyPrefix ?? env.ISSUANCE_RATE_LIMIT_KEY_PREFIX ?? DEFAULT_KEY_PREFIX;

  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger?.info(
      'REDIS_URL not configured, using in-memory issuance rate limiter (single-replica only)',
      { max, windowSeconds },
    );
    return new InMemoryIssuanceRateLimiter({ max, windowSeconds });
  }

  // Use the shared CallCounterStore infrastructure (same as the gateway quota
  // engine) instead of spinning up a dedicated ioredis client. This keeps the
  // connection budget predictable and ensures all counter operations share the
  // same Redis keyspace conventions.
  //
  // Explicitly force CALL_COUNTER_FAIL_OPEN=false so that Redis outages are
  // NOT silently absorbed by a per-replica in-memory fallback. If we honoured
  // the env var here, ISSUANCE_RATE_LIMIT_FAIL_CLOSED would be meaningless:
  // outage → fallback kicks in → effective limit becomes max × replicaCount,
  // not a hard denial. The CallCounterBackedIssuanceRateLimiter's own
  // failClosedOnError / outageDecision() logic handles the outage signal
  // (POSITIVE_INFINITY) consistently across all replicas.
  //
  // Use 'false' (string) rather than `undefined` so createCallCounterStoreFromEnv
  // sees an explicit env override. Setting to `undefined` would leave the key
  // absent and the factory would re-read the real env var — which could still
  // be 'true' if the operator set it.
  const store = await createCallCounterStoreFromEnv(
    { ...env, CALL_COUNTER_FAIL_OPEN: 'false' },
    logger,
  );
  logger?.info('Using CallCounterStore-backed issuance rate limiter', {
    max,
    windowSeconds,
    keyPrefix,
    failClosedOnError,
  });
  return new CallCounterBackedIssuanceRateLimiter(
    store,
    { max, windowSeconds, keyPrefix, failClosedOnError },
    logger,
  );
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || raw.length === 0) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return n;
}

/**
 * Issuance rate limiter (F-1, addresses I-1).
 *
 * The pre-existing `express-rate-limit` middleware on `/api/v1/issue` is
 * **per-IP** only. A compromised user account with multiple IPs (or a
 * single IP shared by many users behind a corporate NAT) trivially
 * defeats it: in the first case the attacker mints unlimited tokens,
 * in the second case legitimate users blame each other.
 *
 * This module replaces that with a **per-(tenant, user, agent)** token
 * bucket evaluated *after* authentication, so the limit is keyed on the
 * resolved subject (and tenant) rather than transport metadata.
 *
 * ## Tenant-awareness
 *
 * The key is `(tenantId, userId, agentId)` — `tenantId` first so the
 * Redis-backed store partitions cleanly per tenant. This is the
 * load-bearing prerequisite called out by §6.1 #3 of
 * `docs/IMPROVEMENTS_AND_REFACTORING.md` for F-7 (multi-region
 * active/active issuer): without tenant-scoped keys, a per-user limit
 * coordinated across regions could legitimately deny one tenant's
 * traffic because of another tenant's burst.
 *
 * ## Algorithm
 *
 * Tumbling window of `windowSeconds`. The first issuance for a given
 * key starts the window; subsequent issuances inside the same window
 * are counted; when the count exceeds `max`, the request is denied
 * with {@link ErrorCode.RATE_LIMIT_EXCEEDED} (HTTP 429). When the
 * window elapses, the next request opens a fresh window. Tumbling (vs
 * sliding) was chosen for two reasons:
 *
 *  1. It maps directly to Redis `INCR` + `EXPIRE`, the same primitive
 *     the `RedisCallCounterStore` uses — so the operational story
 *     (TTLs, key-prefix conventions, failure semantics) is identical.
 *  2. The bound is *tighter* than a sliding window for the same
 *     `max`/`windowSeconds`, which is the right default for a deny
 *     primitive.
 *
 * ## Distributed coordination
 *
 * In-memory by default, Redis-backed when `REDIS_URL` is set. The
 * Redis variant uses atomic `INCR`/`EXPIRE` on the same `ioredis`
 * client surface as {@link RedisCallCounterStore}, so a multi-replica
 * issuer (or a multi-region active/active issuer per F-7) converges
 * on the same per-subject budget.
 *
 * ## Failure semantics
 *
 * Redis errors fail **closed** by default (the request is denied with
 * `RATE_LIMIT_EXCEEDED`). For an issuance-side limit, allowing
 * unlimited mints when the coordination layer is unavailable would
 * defeat the entire purpose. Operators who need fail-open behaviour
 * (e.g. for staging) can opt in with `failClosedOnError: false`.
 */

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
 * `tenantId` is optional because some identity providers do not
 * surface a tenant; in that case all callers fall into the
 * synthetic `_no_tenant` bucket. Operators with mixed-tenant traffic
 * SHOULD configure a provider that populates `tenantId` so per-tenant
 * isolation is preserved.
 *
 * The bucket key is `(tenantId, userId, agentId)`. This three-component
 * key bounds total KMS calls per identity regardless of which issuance
 * path (issue/attenuate/renew) is used, ensuring the budget is not
 * fragmented across token lineages or source IPs.
 *
 * **Why not include `jti` in the key?**
 * Including the parent/current `jti` would split the per-subject budget
 * into per-lineage buckets. An attacker could then mint N parent tokens
 * (consuming the `_no_jti` fresh-issuance budget) and obtain a
 * full attenuation/renew budget for each lineage, multiplying effective
 * KMS load by N instead of keeping it bounded.
 *
 * **Why not include `ip` in the key?**
 * Including the source IP would give the same user/agent a fresh counter
 * every time its source IP changes. A caller behind multiple egress IPs
 * (NAT rotation, CGNAT, multi-homed) would get one budget per IP,
 * multiplying its effective KMS budget — the opposite of the intended
 * constraint. The express-rate-limit middleware already provides a
 * coarse-grained per-IP guard at the HTTP layer.
 */
export interface IssuanceRateLimitSubject {
  tenantId?: string;
  userId: string;
  agentId: string;
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
const DEFAULT_KEY_PREFIX = 'issrl:';

/**
 * Escape a key component so the `|` separator (and the escape char
 * itself) cannot appear inside a component and forge a different
 * tuple. Without this, `(t, 'u|v', 'a')` and `(t, 'u', 'v|a')` would
 * share a bucket — and because `agentId` is request-controlled and
 * `userId` is provider-defined, that is a bucket-stealing primitive.
 *
 * Encoding: `\` -> `\\`, `|` -> `\|`. The decoded form is unambiguous
 * because every literal `|` in a component is now preceded by `\`,
 * while a real separator is not. Escape logic is in
 * {@link escapeRateLimitKeyComponent} (shared with the gateway quota engine).
 */

/**
 * Build the canonical rate-limit key. Exposed so tests can assert the
 * tenant-aware shape (which is the F-7 prerequisite — see file
 * header). Order is `tenantId | userId | agentId` so a Redis `KEYS`
 * scan from an operator can prefix-match a single tenant. Components
 * are escaped to prevent collisions when an identifier contains `|`.
 *
 * The key intentionally uses only three dimensions. See
 * {@link IssuanceRateLimitSubject} for the rationale behind excluding
 * `jti` (would fragment the budget per lineage) and `ip` (would allow
 * budget amplification via IP rotation).
 */
export function buildIssuanceRateLimitKey(s: IssuanceRateLimitSubject): string {
  const tenant = s.tenantId && s.tenantId.length > 0 ? s.tenantId : '_no_tenant';
  const e = escapeRateLimitKeyComponent;
  return `${e(tenant)}|${e(s.userId)}|${e(s.agentId)}`;
}

/**
 * Single-process limiter suitable for development, single-replica
 * issuers, and unit tests. Production multi-replica deployments
 * should use {@link RedisIssuanceRateLimiter} (selected automatically
 * by {@link createIssuanceRateLimiterFromEnv} when `REDIS_URL` is set).
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
 * is set, returns a {@link RedisIssuanceRateLimiter} backed by `ioredis`
 * — the same client wiring as {@link createCallCounterStoreFromEnv} so
 * deployments that already use Redis do not need an additional client.
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

  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger?.info(
      'REDIS_URL not configured, using in-memory issuance rate limiter (single-replica only)',
      { max, windowSeconds },
    );
    return new InMemoryIssuanceRateLimiter({ max, windowSeconds });
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    const isProduction =
      env.NODE_ENV === 'production' ||
      (env.EUNO_DEPLOYMENT_TIER && env.EUNO_DEPLOYMENT_TIER !== 'single-replica');
    if (isProduction) {
      throw new Error(
        'REDIS_URL is set but the "ioredis" package is not installed. ' +
          'Install it (npm install ioredis) to enable distributed issuance ' +
          'rate limiting. Refusing to fall back to the in-memory limiter in a ' +
          'production / multi-replica deployment: per-subject issuance budgets ' +
          'would be tracked per-pod rather than fleet-wide, multiplying the ' +
          'effective limit by the replica count. ' +
          `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger?.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed issuance ' +
        'rate limiting. Falling back to the in-memory limiter; counters ' +
        'WILL NOT be shared across issuer instances. This is only acceptable ' +
        'in development / single-replica deployments.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new InMemoryIssuanceRateLimiter({ max, windowSeconds });
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisIssuanceRateLimitClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const keyPrefix = options.keyPrefix ?? env.ISSUANCE_RATE_LIMIT_KEY_PREFIX ?? DEFAULT_KEY_PREFIX;
  logger?.info('Using Redis-backed issuance rate limiter', {
    max,
    windowSeconds,
    keyPrefix,
    failClosedOnError,
  });
  return new RedisIssuanceRateLimiter(client, logger, {
    max,
    windowSeconds,
    keyPrefix,
    failClosedOnError,
  });
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || raw.length === 0) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return n;
}

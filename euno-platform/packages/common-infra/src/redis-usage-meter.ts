/**
 * Redis-backed UsageMeter implementation for billing durability (CR-1).
 * ---------------------------------------------------------------------------
 * Addresses the billing integrity risk identified in architecture-review-2026-05.md
 * §CR-1: InMemoryUsageMeter holds all per-tenant enforcement-event counters
 * in process memory with no durable backend. A pod restart silently zeroes
 * every tenant's counter.
 *
 * ## Design
 *
 * `RedisUsageMeter` maintains both a local in-memory mirror (for synchronous
 * `getUsage`/`getAllUsage` reads) and Redis-backed counters (for durability
 * across pod restarts and visibility across replicas).
 *
 * - **Writes**: `recordEnforcement` and `recordKillSwitchInvocation` update
 *   in-memory state synchronously, then fire-and-forget Redis `INCR` commands
 *   so billing data survives a crash. An `onError` callback is called on every
 *   Redis write failure so callers can increment a Prometheus counter
 *   (`euno_usage_meter_errors_total`).
 *
 * - **Reads**: Always served from the local in-memory mirror — O(1), no Redis
 *   RTT on the admin hot path.
 *
 * - **Recovery**: Call `await meter.loadFromRedis()` on startup to hydrate the
 *   in-memory mirror from the durable counters. The bootstrap wires this call
 *   automatically via `createUsageMeterFromEnv`.
 *
 * ## Redis key schema
 *
 * | Key pattern                          | Type   | Value                       |
 * |--------------------------------------|--------|-----------------------------|
 * | `{prefix}{tenantId}:enforcement`     | string | INCR counter                |
 * | `{prefix}{tenantId}:allow`           | string | INCR counter                |
 * | `{prefix}{tenantId}:deny`            | string | INCR counter                |
 * | `{prefix}{tenantId}:kill`            | string | INCR counter                |
 * | `{prefix}{tenantId}:ps`              | string | ISO-8601 period start       |
 * | `{prefix}tenants`                    | set    | SADD of all tenant IDs      |
 *
 * All per-tenant counter keys are assigned a TTL on first creation so stale
 * data from inactive tenants eventually expires from Redis. The TTL defaults
 * to 93 days (three monthly billing periods) and is configurable via
 * `USAGE_METER_TTL_SECONDS` / `counterTtlSeconds` option.
 */

import { UsageMeter, TenantUsageSnapshot, InMemoryUsageMeter } from '@euno/common-core';
import { Logger } from '@euno/common-core';

// ---------------------------------------------------------------------------
// Redis client interface
// ---------------------------------------------------------------------------

/**
 * Minimal subset of the `ioredis` client surface required by
 * {@link RedisUsageMeter}. Defined locally so the package does not take a
 * hard compile-time dependency on any specific Redis client package —
 * the actual client is wired by the caller (typically via
 * {@link createUsageMeterFromEnv}).
 */
export interface RedisUsageMeterClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  /** Returns `1` if the member was added, `0` if it already existed. */
  sadd(key: string, member: string): Promise<number>;
  smembers(key: string): Promise<string[]>;
  /** GET — returns null when the key does not exist. */
  get(key: string): Promise<string | null>;
  /** SET — unconditional write. */
  set(key: string, value: string): Promise<unknown>;
  /**
   * SETEX — atomic write with expiry (SET key value EX seconds).
   * Avoids the race condition of a separate SET + EXPIRE pair.
   */
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  /**
   * SET … EX seconds NX — atomic conditional write with expiry.
   * Only writes when the key does NOT already exist; returns 'OK' on
   * success or null when the key was already present.
   * Avoids the race condition of a separate SETNX + EXPIRE pair.
   */
  setnxex(key: string, seconds: number, value: string): Promise<'OK' | null>;
  /**
   * SETNX — conditional write without expiry.
   * Used when TTL is explicitly disabled (counterTtlSeconds === 0) to
   * preserve the original period-start without overwriting it.
   * Returns 1 if written, 0 if the key already existed.
   */
  setnx(key: string, value: string): Promise<number>;
  /** DEL — delete one or more keys (variadic, matching ioredis signature). */
  del(...keys: string[]): Promise<unknown>;
  /** MGET — returns null for missing keys, preserving input order (variadic, matching ioredis signature). */
  mget(...keys: string[]): Promise<(string | null)[]>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

// ---------------------------------------------------------------------------
// RedisUsageMeter options
// ---------------------------------------------------------------------------

export interface RedisUsageMeterOptions {
  /**
   * Key prefix applied to every Redis key this instance writes/reads.
   * Default: `"euno:usage:"`.
   *
   * In multi-tenant/multi-gateway deployments, differentiate instances by
   * using distinct prefixes (e.g. `"euno:usage:prod-gw-1:"`).
   */
  keyPrefix?: string;
  /**
   * TTL (seconds) applied to per-tenant counter keys on first creation.
   * Keys expire after this duration of inactivity, cleaning up Redis for
   * tenants that stop using the system. Default: 93 days (93 × 86 400 s).
   *
   * Set to `0` to disable TTL (not recommended in production — stale keys
   * accumulate indefinitely).
   */
  counterTtlSeconds?: number;
  /** Logger for Redis error visibility. */
  logger?: Logger;
  /**
   * Called once per Redis write failure so callers can increment a
   * Prometheus counter (e.g. `euno_usage_meter_errors_total`). The error
   * has already been logged; this callback is purely for metric emission.
   */
  onError?: () => void;
}

// Default TTL: 93 days — three monthly billing windows with a safety buffer.
const DEFAULT_TTL_SECONDS = 93 * 86_400;
const DEFAULT_KEY_PREFIX = 'euno:usage:';

// ---------------------------------------------------------------------------
// Mutable in-memory counters (internal)
// ---------------------------------------------------------------------------

interface MutableCounters {
  enforcementEvents: number;
  allowDecisions: number;
  denyDecisions: number;
  killSwitchInvocations: number;
  issuanceEvents: number;
  renewalEvents: number;
  /** Per-user issuance counts (forensics; in-memory only, not persisted to Redis). */
  issuancesByUser: Record<string, number>;
  /** Per-user renewal counts (forensics; in-memory only, not persisted to Redis). */
  renewalsByUser: Record<string, number>;
  periodStart: string;
}

// ---------------------------------------------------------------------------
// RedisUsageMeter
// ---------------------------------------------------------------------------

/**
 * Redis-backed {@link UsageMeter} implementation.
 *
 * Provides durable billing counters that survive pod restarts:
 * - **Writes** fire-and-forget Redis INCR commands for every enforcement event.
 * - **Reads** are served from a local in-memory mirror — no Redis RTT on admin paths.
 * - **Recovery** is handled by {@link loadFromRedis} which hydrates local state
 *   from Redis on startup.
 *
 * See the module-level JSDoc for the full key schema and design rationale.
 */
export class RedisUsageMeter implements UsageMeter {
  private readonly client: RedisUsageMeterClient;
  private readonly keyPrefix: string;
  private readonly counterTtlSeconds: number;
  private readonly logger?: Logger;
  private readonly onError?: () => void;

  /** Local in-memory counters — source of truth for synchronous reads. */
  private readonly counters = new Map<string, MutableCounters>();

  constructor(client: RedisUsageMeterClient, options: RedisUsageMeterOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.counterTtlSeconds = options.counterTtlSeconds ?? DEFAULT_TTL_SECONDS;
    this.logger = options.logger;
    this.onError = options.onError;

    // Surface Redis connection errors so the operator can see them in logs
    // and (if an onError callback is wired) in Prometheus.
    this.client.on('error', (err: unknown) => {
      this.logger?.error('RedisUsageMeter: Redis connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  /**
   * Compute the next billing-period start timestamp, ensuring it is strictly
   * newer than the previous timestamp for an existing tenant entry.
   */
  private nextPeriodStart(previous?: string): string {
    const nowMs = Date.now();
    const previousMs = previous ? Date.parse(previous) : Number.NaN;
    const nextMs =
      Number.isFinite(previousMs) && previousMs >= nowMs ? previousMs + 1 : nowMs;
    return new Date(nextMs).toISOString();
  }

  // ── UsageMeter interface ──────────────────────────────────────────────────

  /** @inheritdoc */
  recordEnforcement(tenantId: string, decision: 'allow' | 'deny'): void {
    // 1. Update local in-memory state synchronously (for fast reads).
    const entry = this.getOrCreate(tenantId);
    entry.enforcementEvents += 1;
    if (decision === 'allow') {
      entry.allowDecisions += 1;
    } else {
      entry.denyDecisions += 1;
    }

    // 2. Fire-and-forget Redis writes for durability.
    void this.persistIncr(tenantId, 'enforcement');
    void this.persistIncr(tenantId, decision === 'allow' ? 'allow' : 'deny');
    void this.ensureTenantRegistered(tenantId, entry.periodStart);
  }

  /** @inheritdoc */
  recordKillSwitchInvocation(tenantId: string): void {
    const entry = this.getOrCreate(tenantId);
    entry.killSwitchInvocations += 1;

    void this.persistIncr(tenantId, 'kill');
    void this.ensureTenantRegistered(tenantId, entry.periodStart);
  }

  /** @inheritdoc */
  recordIssuance(tenantId: string, userId: string): void {
    const entry = this.getOrCreate(tenantId);
    entry.issuanceEvents += 1;
    entry.issuancesByUser[userId] = (entry.issuancesByUser[userId] ?? 0) + 1;

    void this.persistIncr(tenantId, 'issuance');
    void this.ensureTenantRegistered(tenantId, entry.periodStart);
  }

  /** @inheritdoc */
  recordRenewal(tenantId: string, userId: string): void {
    const entry = this.getOrCreate(tenantId);
    entry.renewalEvents += 1;
    entry.renewalsByUser[userId] = (entry.renewalsByUser[userId] ?? 0) + 1;

    void this.persistIncr(tenantId, 'renewal');
    void this.ensureTenantRegistered(tenantId, entry.periodStart);
  }

  /** @inheritdoc */
  getUsage(tenantId: string): TenantUsageSnapshot {
    const entry = this.counters.get(tenantId);
    if (!entry) {
      return {
        tenantId,
        enforcementEvents: 0,
        allowDecisions: 0,
        denyDecisions: 0,
        killSwitchInvocations: 0,
        issuanceEvents: 0,
        renewalEvents: 0,
        periodStart: new Date().toISOString(),
      };
    }
    return {
      tenantId,
      enforcementEvents: entry.enforcementEvents,
      allowDecisions: entry.allowDecisions,
      denyDecisions: entry.denyDecisions,
      killSwitchInvocations: entry.killSwitchInvocations,
      issuanceEvents: entry.issuanceEvents,
      renewalEvents: entry.renewalEvents,
      issuancesByUser: { ...entry.issuancesByUser },
      renewalsByUser: { ...entry.renewalsByUser },
      periodStart: entry.periodStart,
    };
  }

  /** @inheritdoc */
  getAllUsage(): TenantUsageSnapshot[] {
    return Array.from(this.counters.entries()).map(([tenantId, entry]) => ({
      tenantId,
      enforcementEvents: entry.enforcementEvents,
      allowDecisions: entry.allowDecisions,
      denyDecisions: entry.denyDecisions,
      killSwitchInvocations: entry.killSwitchInvocations,
      issuanceEvents: entry.issuanceEvents,
      renewalEvents: entry.renewalEvents,
      issuancesByUser: { ...entry.issuancesByUser },
      renewalsByUser: { ...entry.renewalsByUser },
      periodStart: entry.periodStart,
    }));
  }

  /** @inheritdoc */
  resetPeriod(tenantId?: string): void {
    if (tenantId !== undefined) {
      const entry = this.counters.get(tenantId);
      if (entry) {
        const nextPeriodStart = this.nextPeriodStart(entry.periodStart);
        entry.enforcementEvents = 0;
        entry.allowDecisions = 0;
        entry.denyDecisions = 0;
        entry.killSwitchInvocations = 0;
        entry.issuanceEvents = 0;
        entry.renewalEvents = 0;
        entry.issuancesByUser = {};
        entry.renewalsByUser = {};
        entry.periodStart = nextPeriodStart;
        void this.persistReset([tenantId], nextPeriodStart);
        return;
      }
    } else {
      const nextPeriodStart = this.nextPeriodStart(
        Array.from(this.counters.values()).reduce<string | undefined>(
          (latest, entry) => {
            if (!latest) return entry.periodStart;
            return Date.parse(entry.periodStart) > Date.parse(latest)
              ? entry.periodStart
              : latest;
          },
          undefined,
        ),
      );
      const allTenantIds: string[] = [];
      for (const [tid, entry] of this.counters.entries()) {
        entry.enforcementEvents = 0;
        entry.allowDecisions = 0;
        entry.denyDecisions = 0;
        entry.killSwitchInvocations = 0;
        entry.issuanceEvents = 0;
        entry.renewalEvents = 0;
        entry.issuancesByUser = {};
        entry.renewalsByUser = {};
        entry.periodStart = nextPeriodStart;
        allTenantIds.push(tid);
      }
      if (allTenantIds.length > 0) {
        void this.persistReset(allTenantIds, nextPeriodStart);
      }
    }
  }

  // ── Startup recovery ──────────────────────────────────────────────────────

  /**
   * Hydrate the in-memory mirror from durable Redis state.
   *
   * Call this once during gateway startup (after constructing the meter but
   * before serving requests) so billing counters survive pod restarts.
   * Non-fatal: on error, logs a warning and leaves in-memory state unchanged.
   *
   * Typical bootstrap pattern:
   * ```ts
   * const meter = new RedisUsageMeter(client, opts);
   * await meter.loadFromRedis();
   * ```
   */
  async loadFromRedis(): Promise<void> {
    const tenantsKey = `${this.keyPrefix}tenants`;
    let tenantIds: string[];

    try {
      tenantIds = await this.client.smembers(tenantsKey);
    } catch (err) {
      this.logger?.warn('RedisUsageMeter: Failed to load tenant list from Redis; starting with empty local state', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      return;
    }

    if (tenantIds.length === 0) {
      this.logger?.info('RedisUsageMeter: No existing tenant usage data found in Redis (new installation or keys expired)');
      return;
    }

    // Build all keys for a single bulk MGET across all tenants.
    const METRICS = ['enforcement', 'allow', 'deny', 'kill', 'issuance', 'renewal', 'ps'] as const;
    const keys: string[] = [];
    for (const tid of tenantIds) {
      for (const m of METRICS) {
        keys.push(`${this.keyPrefix}${tid}:${m}`);
      }
    }

    // Issue one MGET for all tenant keys. ioredis expects variadic arguments,
    // so we spread the keys array at the call site.
    let values: (string | null)[];
    try {
      values = await this.client.mget(...keys);
    } catch (err) {
      this.logger?.warn('RedisUsageMeter: Failed to load usage counters from Redis; starting with empty local state', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      return;
    }

    const metricsPerTenant = METRICS.length; // 7
    for (let i = 0; i < tenantIds.length; i++) {
      const tid = tenantIds[i];
      if (!tid) continue;
      const base = i * metricsPerTenant;
      const enforcement = parseIntOrZero(values[base]);
      const allow = parseIntOrZero(values[base + 1]);
      const deny = parseIntOrZero(values[base + 2]);
      const kill = parseIntOrZero(values[base + 3]);
      const issuance = parseIntOrZero(values[base + 4]);
      const renewal = parseIntOrZero(values[base + 5]);
      // Check the raw Redis value before applying the fallback so that the
      // "only populate if there's any data" guard below can distinguish a
      // completely expired tenant (all Redis keys gone) from one that has
      // only a period-start record remaining.
      const rawPs = values[base + 6];
      const ps = rawPs ?? new Date().toISOString();

      // Only populate if there's any data — skip tenants whose keys have
      // all expired (rawPs would be null in that case along with zero counters).
      if (enforcement > 0 || allow > 0 || deny > 0 || kill > 0 || issuance > 0 || renewal > 0 || rawPs !== null) {
        this.counters.set(tid, {
          enforcementEvents: enforcement,
          allowDecisions: allow,
          denyDecisions: deny,
          killSwitchInvocations: kill,
          issuanceEvents: issuance,
          renewalEvents: renewal,
          // Per-user breakdowns are not persisted to Redis; they reset on startup.
          issuancesByUser: {},
          renewalsByUser: {},
          periodStart: ps,
        });
      }
    }

    this.logger?.info('RedisUsageMeter: Loaded usage data from Redis on startup', {
      tenantsLoaded: tenantIds.length,
    });
  }

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch (err) {
      this.logger?.warn('RedisUsageMeter: Error closing Redis client', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Obtain or create the counter entry for `tenantId`.
   * Initialising on first access is safe: `tenantId` values come from
   * verified JWT tokens and have already been authenticated.
   */
  private getOrCreate(tenantId: string): MutableCounters {
    let entry = this.counters.get(tenantId);
    if (!entry) {
      entry = {
        enforcementEvents: 0,
        allowDecisions: 0,
        denyDecisions: 0,
        killSwitchInvocations: 0,
        issuanceEvents: 0,
        renewalEvents: 0,
        issuancesByUser: {},
        renewalsByUser: {},
        periodStart: new Date().toISOString(),
      };
      this.counters.set(tenantId, entry);
    }
    return entry;
  }

  /**
   * Fire-and-forget Redis INCR for the given tenant/metric pair.
   * Sets a TTL on the key's first creation so unused keys expire automatically.
   */
  private async persistIncr(tenantId: string, metric: string): Promise<void> {
    const key = `${this.keyPrefix}${tenantId}:${metric}`;
    try {
      const count = await this.client.incr(key);
      if (count === 1 && this.counterTtlSeconds > 0) {
        // First increment — attach TTL so inactive-tenant keys expire.
        await this.client.expire(key, this.counterTtlSeconds);
      }
    } catch (err) {
      this.logger?.error('RedisUsageMeter: Redis INCR failed', {
        key,
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      this.onError?.();
    }
  }

  /**
   * Fire-and-forget: register the tenant in the tracking set and set the
   * period-start marker (NX — only writes when the key does not yet exist,
   * so we never overwrite a period-start written by an earlier record).
   */
  private async ensureTenantRegistered(tenantId: string, periodStart: string): Promise<void> {
    try {
      const tenantsKey = `${this.keyPrefix}tenants`;
      const psKey = `${this.keyPrefix}${tenantId}:ps`;

      await this.client.sadd(tenantsKey, tenantId);
      // Use an atomic SET … EX … NX to write the period-start key only when
      // it does not already exist and atomically attach the TTL in one command.
      // This avoids the SETNX → crash → missing TTL race condition.
      // When TTL is disabled (counterTtlSeconds === 0), fall back to a plain
      // SET … NX (emulated via setnxex with TTL 0 → set NX without expiry).
      if (this.counterTtlSeconds > 0) {
        await this.client.setnxex(psKey, this.counterTtlSeconds, periodStart);
      } else {
        // TTL explicitly disabled: use SETNX so we write only when the key
        // is absent — same NX contract as setnxex but without expiry.
        await this.client.setnx(psKey, periodStart);
      }
    } catch (err) {
      this.logger?.error('RedisUsageMeter: Redis tenant registration failed', {
        tenantId,
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      this.onError?.();
    }
  }

  /**
   * Fire-and-forget: delete counter keys and write new period-start for the
   * given tenants (called by `resetPeriod`).
   */
  private async persistReset(tenantIds: string[], newPeriodStart: string): Promise<void> {
    const COUNTER_METRICS = ['enforcement', 'allow', 'deny', 'kill', 'issuance', 'renewal'] as const;
    try {
      const keysToDelete: string[] = [];
      for (const tid of tenantIds) {
        for (const m of COUNTER_METRICS) {
          keysToDelete.push(`${this.keyPrefix}${tid}:${m}`);
        }
      }

      if (keysToDelete.length > 0) {
        await this.client.del(...keysToDelete);
      }

      // Write new period-start for every tenant using an atomic SETEX so the
      // TTL is attached in the same command and cannot be dropped by a crash.
      for (const tid of tenantIds) {
        const psKey = `${this.keyPrefix}${tid}:ps`;
        if (this.counterTtlSeconds > 0) {
          await this.client.setex(psKey, this.counterTtlSeconds, newPeriodStart);
        } else {
          await this.client.set(psKey, newPeriodStart);
        }
      }
    } catch (err) {
      this.logger?.error('RedisUsageMeter: Redis reset failed', {
        tenantIds,
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      this.onError?.();
    }
  }
}

// ---------------------------------------------------------------------------
// Environment-driven factory
// ---------------------------------------------------------------------------

/**
 * Build a {@link UsageMeter} from environment variables.
 *
 * Resolution order:
 *   1. `USAGE_METER_REDIS_URL` — dedicated Redis URL for usage metering.
 *   2. `REDIS_URL`             — shared Redis URL used by other stores.
 *   3. In-memory fallback      — when neither is set.
 *
 * Configuration environment variables:
 *   - `USAGE_METER_REDIS_URL`    — dedicated Redis URL for usage metering.
 *   - `REDIS_URL`                — shared Redis URL (fallback).
 *   - `USAGE_METER_KEY_PREFIX`   — overrides the default `"euno:usage:"`.
 *   - `USAGE_METER_TTL_SECONDS`  — counter TTL (default 93 days).
 *
 * When a Redis URL is found, this function:
 *   1. Constructs a `RedisUsageMeter` backed by an `ioredis` client.
 *   2. Calls `loadFromRedis()` to recover counts from a prior pod's run.
 *   3. Returns the hydrated meter.
 *
 * In production deployments, configure `REDIS_URL` (or
 * `USAGE_METER_REDIS_URL`) so billing data survives pod restarts and all
 * replicas share a coherent view of usage counters. Without Redis, billing
 * data is lost on every restart — a `warn` is emitted in production /
 * multi-replica environments to make the gap visible.
 *
 * `ioredis` is loaded with a runtime `require()` so operators that do not
 * use Redis are not forced to install it.
 */
export async function createUsageMeterFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
  /** Optional callback invoked on every Redis write failure. */
  onError?: () => void,
): Promise<UsageMeter> {
  const redisUrl = env['USAGE_METER_REDIS_URL'] || env['REDIS_URL'];

  if (!redisUrl) {
    const isProduction = env['NODE_ENV'] === 'production' ||
      (!!env['EUNO_DEPLOYMENT_TIER'] && env['EUNO_DEPLOYMENT_TIER'] !== 'single-replica');
    if (isProduction) {
      logger?.warn(
        '[gateway] createUsageMeterFromEnv: neither USAGE_METER_REDIS_URL nor REDIS_URL is set. ' +
          'Using per-process in-memory usage meter. Billing counters WILL be lost on pod restart. ' +
          'Configure REDIS_URL to enable durable billing data (CR-1).',
      );
    } else {
      logger?.info('[gateway] createUsageMeterFromEnv: no Redis URL configured; using in-memory usage meter');
    }
    return new InMemoryUsageMeter();
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (loadError) {
    const detectedVar = env['USAGE_METER_REDIS_URL'] ? 'USAGE_METER_REDIS_URL' : 'REDIS_URL';
    logger?.error(
      `[gateway] createUsageMeterFromEnv: ${detectedVar} is set but "ioredis" is not installed. ` +
        'Install it (npm install ioredis) to enable durable billing metering. ' +
        'Falling back to in-memory usage meter — billing data will be lost on pod restart.',
      { error: loadError instanceof Error ? loadError.message : 'Unknown error', detectedVar },
    );
    return new InMemoryUsageMeter();
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisUsageMeterClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const keyPrefix = env['USAGE_METER_KEY_PREFIX'] || DEFAULT_KEY_PREFIX;
  // Allow `USAGE_METER_TTL_SECONDS=0` to explicitly disable TTL (stale keys
  // never expire). Any non-finite parse result falls back to the default.
  const ttlRaw = parseInt(env['USAGE_METER_TTL_SECONDS'] ?? String(DEFAULT_TTL_SECONDS), 10);
  const counterTtlSeconds = Number.isFinite(ttlRaw) && ttlRaw >= 0 ? ttlRaw : DEFAULT_TTL_SECONDS;

  const meter = new RedisUsageMeter(client, {
    keyPrefix,
    counterTtlSeconds,
    logger,
    onError,
  });

  // Hydrate in-memory state from Redis to recover usage counts after a pod restart.
  await meter.loadFromRedis();

  logger?.info('[gateway] createUsageMeterFromEnv: using Redis-backed durable usage meter', {
    keyPrefix,
    counterTtlSeconds,
    dedicatedUrl: !!env['USAGE_METER_REDIS_URL'],
  });

  return meter;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function parseIntOrZero(value: string | null | undefined): number {
  if (value === null || value === undefined) return 0;
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : 0;
}

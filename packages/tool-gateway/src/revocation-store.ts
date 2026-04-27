/**
 * Revocation Store
 *
 * Pluggable backing store for the JWT revocation list used by
 * {@link JWTTokenVerifier}.  In single-instance deployments the in-memory
 * implementation is sufficient.  In multi-instance / production deployments
 * a shared store (such as Redis) MUST be used so a revocation issued on one
 * gateway instance is immediately visible to all other instances.
 *
 * The architecture and operational guidance for Redis deployments is
 * documented in `docs/DISTRIBUTED_REVOCATION.md`.
 */

import { Logger } from '@euno/common';

/**
 * Common interface implemented by all revocation backends.
 */
export interface RevocationStore {
  /**
   * Returns true if the supplied token id has been revoked AND the revocation
   * has not yet expired.  Implementations MUST return false for unknown ids
   * and MUST treat expired revocation entries as absent.
   */
  isRevoked(tokenId: string): Promise<boolean>;

  /**
   * Mark a token id as revoked.  `expiresAt` is the unix-seconds timestamp at
   * which the underlying token would naturally expire; the revocation entry
   * may be pruned once that time has passed.
   */
  revoke(tokenId: string, expiresAt: number): Promise<void>;

  /**
   * Release any resources held by the store (network connections, timers,
   * etc.).  Idempotent.
   */
  close(): Promise<void>;
}

/**
 * In-process revocation store.
 *
 * Uses a Map keyed by JTI with the token expiry (unix seconds) as the value.
 * Stale entries are pruned lazily on lookup and eagerly on insert so the map
 * remains bounded to the active-token window.
 *
 * NOTE: this store is NOT shared across processes.  Use it only for local
 * development, single-instance deployments, or as a fallback when Redis is
 * not configured.
 */
export class InMemoryRevocationStore implements RevocationStore {
  private revokedTokens: Map<string, number> = new Map();

  async isRevoked(tokenId: string): Promise<boolean> {
    const expiry = this.revokedTokens.get(tokenId);
    if (expiry === undefined) {
      return false;
    }
    if (expiry <= nowSeconds()) {
      this.revokedTokens.delete(tokenId);
      return false;
    }
    return true;
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    // Bulk-prune expired entries before inserting so the map cannot grow
    // unboundedly even under sustained revocation traffic.
    const now = nowSeconds();
    for (const [jti, expiry] of this.revokedTokens) {
      if (expiry <= now) {
        this.revokedTokens.delete(jti);
      }
    }
    this.revokedTokens.set(tokenId, expiresAt);
  }

  async close(): Promise<void> {
    this.revokedTokens.clear();
  }

  /** Test/debug helper: number of currently-tracked entries. */
  size(): number {
    return this.revokedTokens.size;
  }
}

/**
 * Minimal subset of the redis client surface we depend on.  Defined locally
 * so we do not take a hard runtime dependency on `ioredis` (or any specific
 * client) – callers wire one in via {@link createRedisRevocationStore}.
 */
export interface RedisLikeClient {
  exists(key: string): Promise<number>;
  set(key: string, value: string, mode: 'EX', ttlSeconds: number): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Distributed revocation store backed by Redis.
 *
 * Each revocation is stored as a key `revoked:<jti>` with a TTL equal to the
 * remaining lifetime of the underlying token, so Redis itself prunes expired
 * entries.  A revocation issued on one gateway instance is therefore visible
 * to all other instances on the next `isRevoked()` call.
 *
 * **Fail-closed semantics:** if Redis is unreachable the store treats lookups
 * as "revoked" by default so a partitioned gateway cannot accidentally accept
 * tokens that may have been revoked elsewhere.  Pass `failOpen: true` to opt
 * into the (less safe) opposite behaviour for environments where availability
 * matters more than revocation freshness.
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisLikeClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly failOpen: boolean;

  constructor(
    client: RedisLikeClient,
    logger: Logger,
    options: { keyPrefix?: string; failOpen?: boolean } = {}
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'revoked:';
    this.failOpen = options.failOpen ?? false;

    this.client.on('error', (err: unknown) => {
      this.logger.error('Redis revocation store connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    try {
      const exists = await this.client.exists(this.key(tokenId));
      return exists === 1;
    } catch (error) {
      this.logger.error('Failed to query revocation status from Redis', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
        failMode: this.failOpen ? 'open' : 'closed',
      });
      // Default: fail closed.  An attacker (or split-brain network) cannot
      // bypass revocation by knocking out Redis.
      return !this.failOpen;
    }
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    const now = nowSeconds();
    const ttl = Math.max(expiresAt - now, 0);
    if (ttl <= 0) {
      // Token is already past its natural expiry – nothing to revoke.
      this.logger.warn('Skipping Redis revocation for already-expired token', { tokenId });
      return;
    }
    try {
      await this.client.set(this.key(tokenId), '1', 'EX', ttl);
      this.logger.info('Token revoked in Redis', { tokenId, ttlSeconds: ttl });
    } catch (error) {
      this.logger.error('Failed to revoke token in Redis', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch (error) {
      this.logger.warn('Error while closing Redis revocation store client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private key(tokenId: string): string {
    return `${this.keyPrefix}${tokenId}`;
  }
}

/**
 * Lazily construct a {@link RedisRevocationStore} backed by `ioredis`.
 *
 * `ioredis` is loaded with a runtime `require()` so deployments that do not
 * use Redis are not forced to install it.  When the dependency is absent and
 * the operator has explicitly requested Redis (by setting `REDIS_URL`), this
 * function logs a clear error and falls back to {@link InMemoryRevocationStore}
 * so the gateway can still start.
 */
export async function createRevocationStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger
): Promise<RevocationStore> {
  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger.info('REDIS_URL not configured, using in-memory revocation store');
    return new InMemoryRevocationStore();
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    logger.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
      'Install it (npm install ioredis) to enable distributed revocation. ' +
      'Falling back to in-memory revocation store; revocations WILL NOT be ' +
      'shared across gateway instances.',
      { error: error instanceof Error ? error.message : 'Unknown error' }
    );
    return new InMemoryRevocationStore();
  }

  // ioredis exports the constructor as either the module itself (CJS default)
  // or as `default` when imported via interop.
  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisLikeClient)(redisUrl, {
    // Bounded exponential backoff so transient outages do not turn into
    // unbounded latency on the request path.
    retryStrategy: (times: number) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });

  const failOpen = env.REVOCATION_FAIL_OPEN === 'true';
  const keyPrefix = env.REVOCATION_KEY_PREFIX || 'revoked:';

  logger.info('Using Redis revocation store for distributed token revocation', {
    keyPrefix,
    failMode: failOpen ? 'open' : 'closed',
  });

  return new RedisRevocationStore(client, logger, { keyPrefix, failOpen });
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * OIDC State Store — nonce management and ID-token-hash replay prevention.
 *
 * Two independent responsibilities are handled here:
 *
 * 1. **Nonce tracking** (`pendingStates`): The issuer generates a `state` +
 *    `nonce` pair when it redirects a user to the upstream IdP
 *    (`GET /api/v1/oidc/authorize`). When the code exchange comes back via
 *    `POST /api/v1/oidc/token`, the nonce stored against the state is retrieved
 *    and compared to the `nonce` claim in the IdP's ID token. This confirms the
 *    ID token was issued in response to *this* authorization request and has
 *    not been recycled from a different session.
 *
 * 2. **ID-token-hash replay prevention** (`usedIdTokenHashes`): Before any
 *    remote IdP validation the issuer computes a SHA-256 hash of the submitted
 *    `idToken` string and marks it as used **eagerly** (fail-closed). Any
 *    subsequent attempt to submit the same token within the TTL window is
 *    rejected, even if the first attempt failed at the IdP or issuance stage.
 *    This is required by the Stage-4 threat model (§5, row "IdP-token replay
 *    against the issuer"). Using the token hash rather than a caller-supplied
 *    field prevents bypassing the check with a fresh, arbitrary value.
 *
 * ## Implementations
 *
 * - {@link OidcStateStore} — in-memory (single-replica / dev). Safe for
 *   `EUNO_DEPLOYMENT_TIER=single-replica` self-host deployments.
 * - {@link RedisOidcStateStore} — Redis-backed (multi-replica / production).
 *   State and hash entries are stored as Redis keys with native TTL so they
 *   survive pod restarts and are visible across every replica. Replay
 *   prevention is fleet-wide (CR-1 fix from architecture-review-2026-05-stage4).
 *
 * ## Factory
 *
 * Use {@link createOidcStateStoreFromEnv} to select the right implementation
 * based on environment variables. This mirrors the pattern used by
 * `createIssuanceRateLimiterFromEnv` and `createMintRateLimiterFromEnv`.
 *
 * Entries expire after `codeTtlSeconds` (default 600 s, matching the default
 * maximum authorization-code lifetime of most IdPs).
 */

import crypto from 'crypto';
import type { Logger } from '@euno/common';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PendingOidcState {
  /** Random PKCE state value sent to the IdP. */
  state: string;
  /** Random nonce bound into the IdP ID token. */
  nonce: string;
  /** Timestamp (ms since epoch) at which this entry expires. */
  expiresAtMs: number;
  /** Optional tenant this state was created for. */
  tenantId?: string;
  /** Optional agentId this state was created for. */
  agentId?: string;
  /** The `redirect_uri` used in the authorization request. */
  redirectUri?: string;
}

// ---------------------------------------------------------------------------
// IOidcStateStore interface
// ---------------------------------------------------------------------------

/**
 * Common interface for OIDC state/nonce and ID-token-hash replay prevention.
 * Implemented by both {@link OidcStateStore} (in-memory) and
 * {@link RedisOidcStateStore} (Redis-backed).
 */
export interface IOidcStateStore {
  /**
   * Create a new pending state. Returns the generated `state` and `nonce`
   * values that should be included in the upstream IdP authorization URL.
   */
  createState(opts?: {
    tenantId?: string;
    agentId?: string;
    redirectUri?: string;
  }): Promise<{ state: string; nonce: string }> | { state: string; nonce: string };

  /**
   * Consume and return the pending state entry for `state`, or `undefined` if
   * the state is unknown or has expired. Each state may only be consumed once.
   */
  consumeState(state: string): Promise<PendingOidcState | undefined> | PendingOidcState | undefined;

  /**
   * Returns `true` if the ID-token hash has already been used within the
   * current TTL window, `false` otherwise. Does **not** mark the hash as used.
   */
  isIdTokenHashUsed(hash: string): Promise<boolean> | boolean;

  /**
   * Mark the ID-token hash as used. Subsequent calls to
   * {@link isIdTokenHashUsed} with the same hash will return `true` until
   * the TTL expires.
   *
   * Call this **before** any remote IdP call (fail-closed semantics).
   */
  markIdTokenHashUsed(hash: string): Promise<void> | void;
}

// ---------------------------------------------------------------------------
// OidcStateStore — in-memory implementation
// ---------------------------------------------------------------------------

/**
 * In-memory store for OIDC state/nonce pairs and used ID-token hashes.
 *
 * Safe for single-replica deployments. For multi-replica or HA deployments
 * use {@link RedisOidcStateStore} or call {@link createOidcStateStoreFromEnv}.
 */
export class OidcStateStore implements IOidcStateStore {
  /**
   * Pending states, keyed by the opaque `state` string sent to the IdP.
   * Entries are removed on retrieval (single-use) or on expiry sweep.
   */
  private readonly pendingStates = new Map<string, PendingOidcState>();

  /**
   * Used ID-token hashes. The value is the expiry timestamp (ms).
   * Re-submission of a token whose hash is still present is rejected.
   */
  private readonly usedIdTokenHashes = new Map<string, number>();

  /**
   * @param codeTtlSeconds TTL (seconds) for both state/nonce pairs and
   *   the used-hash log. Defaults to 600 (10 minutes).
   */
  constructor(private readonly codeTtlSeconds: number = 600) {}

  // -------------------------------------------------------------------------
  // State / nonce management
  // -------------------------------------------------------------------------

  /**
   * Create a new pending state. Returns the generated `state` and `nonce`
   * values that should be included in the upstream IdP authorization URL.
   */
  createState(opts: {
    tenantId?: string;
    agentId?: string;
    redirectUri?: string;
  } = {}): { state: string; nonce: string } {
    this.sweep();
    const state = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const expiresAtMs = Date.now() + this.codeTtlSeconds * 1000;
    this.pendingStates.set(state, {
      state,
      nonce,
      expiresAtMs,
      tenantId: opts.tenantId,
      agentId: opts.agentId,
      redirectUri: opts.redirectUri,
    });
    return { state, nonce };
  }

  /**
   * Consume and return the pending state entry for `state`, or `undefined` if
   * the state is unknown or has expired. Each state may only be consumed once.
   */
  consumeState(state: string): PendingOidcState | undefined {
    const entry = this.pendingStates.get(state);
    if (!entry) return undefined;
    this.pendingStates.delete(state);
    if (entry.expiresAtMs <= Date.now()) return undefined;
    return entry;
  }

  // -------------------------------------------------------------------------
  // ID-token-hash replay prevention
  // -------------------------------------------------------------------------

  /**
   * Returns `true` if the ID-token hash has already been seen within the
   * current TTL window, `false` otherwise. **Does not** mark the hash as used.
   */
  isIdTokenHashUsed(hash: string): boolean {
    const expiry = this.usedIdTokenHashes.get(hash);
    if (expiry === undefined) return false;
    if (expiry <= Date.now()) {
      this.usedIdTokenHashes.delete(hash);
      return false;
    }
    return true;
  }

  /**
   * Mark the ID-token hash as used. Subsequent calls to
   * {@link isIdTokenHashUsed} with the same hash will return `true` until
   * the TTL expires.
   *
   * Call this **before** any remote IdP call — fail-closed semantics: even
   * if the IdP call or downstream issuance fails, the same token cannot be
   * resubmitted. The caller must obtain a fresh token to retry.
   */
  markIdTokenHashUsed(hash: string): void {
    this.sweep();
    this.usedIdTokenHashes.set(hash, Date.now() + this.codeTtlSeconds * 1000);
  }

  // -------------------------------------------------------------------------
  // Internal maintenance
  // -------------------------------------------------------------------------

  /** Remove expired entries from both maps. */
  private sweep(): void {
    const now = Date.now();
    for (const [k, entry] of this.pendingStates) {
      if (entry.expiresAtMs <= now) this.pendingStates.delete(k);
    }
    for (const [k, expiry] of this.usedIdTokenHashes) {
      if (expiry <= now) this.usedIdTokenHashes.delete(k);
    }
  }

  /** Current number of pending (unconsumed) state entries — useful in tests. */
  get pendingStateCount(): number {
    return this.pendingStates.size;
  }

  /** Current number of used ID-token hash entries — useful in tests. */
  get usedIdTokenHashCount(): number {
    return this.usedIdTokenHashes.size;
  }
}

// ---------------------------------------------------------------------------
// RedisOidcStateStore — Redis-backed implementation (CR-1)
// ---------------------------------------------------------------------------

/**
 * Minimal subset of the `ioredis` client surface required by
 * {@link RedisOidcStateStore}. Defined locally so the package does not take a
 * hard compile-time dependency on `ioredis` — the actual client is wired by
 * the caller (typically via {@link createOidcStateStoreFromEnv}).
 */
export interface RedisOidcStateStoreClient {
  /** SET key value EX ttlSeconds — atomic write with expiry. */
  set(
    key: string,
    value: string,
    expiryMode: 'EX',
    time: number,
  ): Promise<'OK' | null>;
  /**
   * SET key value EX ttlSeconds NX — only write when key does NOT exist.
   * Returns 'OK' on success, null when key already exists.
   */
  set(
    key: string,
    value: string,
    expiryMode: 'EX',
    time: number,
    setMode: 'NX',
  ): Promise<'OK' | null>;
  /** GET — returns null when the key does not exist. */
  get(key: string): Promise<string | null>;
  /** GETDEL — atomically GET and DELETE the key. Returns null when absent. */
  getdel(key: string): Promise<string | null>;
  /** EXISTS key — returns 1 when the key exists, 0 when absent. */
  exists(key: string): Promise<number>;
  /** QUIT — gracefully close the connection. */
  quit(): Promise<unknown>;
  /** Register an event listener (used for 'error' events). */
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Redis-backed OIDC state store (CR-1 fix).
 *
 * Replaces the in-memory implementation for multi-replica issuer deployments.
 * State/nonce pairs and used ID-token hashes are stored as Redis keys with
 * native TTL so:
 *
 * - Entries expire automatically without in-process sweep logic.
 * - Fleet-wide replay prevention: a token replayed against a *different* pod
 *   is correctly rejected because the hash key is visible to every replica.
 * - Pod restarts do not reset the replay-prevention window.
 *
 * ## Redis key schema
 *
 * | Key pattern                        | Value                  | TTL              |
 * |------------------------------------|------------------------|------------------|
 * | `{prefix}state:{state}`            | JSON PendingOidcState  | codeTtlSeconds   |
 * | `{prefix}hash:{sha256hex}`         | `"1"` sentinel         | codeTtlSeconds   |
 *
 * `GETDEL` is used for single-use state consumption to atomically retrieve and
 * delete in one round-trip (avoids TOCTOU race under concurrent pods).
 *
 * ID-token hash marking uses `SET NX EX` so concurrent issuance requests for
 * the same token are serialised: exactly one succeeds, the rest see `null` and
 * treat the token as already used.
 */
export class RedisOidcStateStore implements IOidcStateStore {
  private readonly keyPrefix: string;

  constructor(
    private readonly client: RedisOidcStateStoreClient,
    private readonly codeTtlSeconds: number = 600,
    options: { keyPrefix?: string } = {},
  ) {
    this.keyPrefix = options.keyPrefix ?? 'oidc:';
    this.client.on('error', (err: unknown) => {
      // Errors are logged by the bootstrap; no action needed here.
      void err;
    });
  }

  // -------------------------------------------------------------------------
  // State / nonce management
  // -------------------------------------------------------------------------

  async createState(opts: {
    tenantId?: string;
    agentId?: string;
    redirectUri?: string;
  } = {}): Promise<{ state: string; nonce: string }> {
    const state = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const expiresAtMs = Date.now() + this.codeTtlSeconds * 1000;
    const entry: PendingOidcState = {
      state,
      nonce,
      expiresAtMs,
      tenantId: opts.tenantId,
      agentId: opts.agentId,
      redirectUri: opts.redirectUri,
    };
    await this.client.set(
      `${this.keyPrefix}state:${state}`,
      JSON.stringify(entry),
      'EX',
      Math.ceil(this.codeTtlSeconds),
    );
    return { state, nonce };
  }

  async consumeState(state: string): Promise<PendingOidcState | undefined> {
    // GETDEL atomically retrieves and removes the key in a single round-trip,
    // eliminating the TOCTOU window that a separate GET + DEL would have under
    // concurrent replicas racing to consume the same state value.
    const raw = await this.client.getdel(`${this.keyPrefix}state:${state}`);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as PendingOidcState;
    } catch {
      return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // ID-token-hash replay prevention
  // -------------------------------------------------------------------------

  async isIdTokenHashUsed(hash: string): Promise<boolean> {
    const count = await this.client.exists(`${this.keyPrefix}hash:${hash}`);
    return count > 0;
  }

  async markIdTokenHashUsed(hash: string): Promise<void> {
    // SET NX EX: only set when the key does NOT already exist. This makes the
    // "mark + check" operation atomic under concurrency: if two requests for
    // the same token race, exactly one gets 'OK' and the other sees null,
    // correctly triggering the replay-prevention 401.
    await this.client.set(
      `${this.keyPrefix}hash:${hash}`,
      '1',
      'EX',
      Math.ceil(this.codeTtlSeconds),
      'NX',
    );
  }

  /** Gracefully close the Redis connection. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      // Best-effort; ignore errors on close.
    }
  }
}

// ---------------------------------------------------------------------------
// createOidcStateStoreFromEnv factory
// ---------------------------------------------------------------------------

/**
 * Construct an {@link IOidcStateStore} from environment variables.
 *
 * - When `OIDC_STATE_REDIS_URL` or `REDIS_URL` is set, returns a
 *   {@link RedisOidcStateStore} so replay-prevention state is shared across
 *   every issuer replica (fleet-wide).
 * - When neither URL is set, returns the in-memory {@link OidcStateStore}
 *   and emits a structured `warn`. This is safe only for single-replica
 *   (`EUNO_DEPLOYMENT_TIER=single-replica`) deployments; in a multi-replica
 *   setup the in-memory store silently voids cross-replica replay prevention.
 *
 * `ioredis` is loaded via a runtime `require()` so callers that do not use
 * Redis are not forced to install it. When the URL is set but `ioredis` is
 * missing, the factory throws in production and falls back to in-memory in
 * development (matching `createCallCounterStoreFromEnv`).
 *
 * Environment variables:
 *  - `OIDC_STATE_REDIS_URL` — dedicated Redis URL for the OIDC state store.
 *  - `REDIS_URL` — shared Redis URL (fallback when `OIDC_STATE_REDIS_URL` is unset).
 *  - `OIDC_CODE_TTL_SECONDS` — TTL in seconds (default 600).
 */
export async function createOidcStateStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
): Promise<IOidcStateStore> {
  const ttlSeconds = parsePositiveInt(env.OIDC_CODE_TTL_SECONDS, 600);
  const redisUrl = env.OIDC_STATE_REDIS_URL || env.REDIS_URL;

  if (!redisUrl) {
    logger?.warn(
      'No Redis URL configured for OIDC state store; using in-memory (per-replica only). ' +
        'Set OIDC_STATE_REDIS_URL or REDIS_URL for fleet-wide replay prevention in multi-replica deployments.',
    );
    return new OidcStateStore(ttlSeconds);
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    RedisCtor = require('ioredis');
  } catch (error) {
    const isProduction =
      env.NODE_ENV === 'production' ||
      (env.EUNO_DEPLOYMENT_TIER !== undefined && env.EUNO_DEPLOYMENT_TIER !== 'single-replica');
    if (isProduction) {
      throw new Error(
        'REDIS_URL is set but the "ioredis" package is not installed. ' +
          'Install it (npm install ioredis) to enable fleet-wide OIDC replay prevention. ' +
          'Refusing to fall back to the in-memory store in a production / multi-replica deployment: ' +
          'replay prevention would be per-pod rather than fleet-wide. ' +
          `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger?.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Falling back to in-memory OIDC state store; replay prevention WILL NOT be ' +
        'shared across issuer replicas. Install "ioredis" for production use.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new OidcStateStore(ttlSeconds);
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisOidcStateStoreClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  client.on('error', (err: unknown) => {
    logger?.error('Redis OIDC state store connection error', {
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  });

  logger?.info('Using Redis-backed OIDC state store (fleet-wide replay prevention)', {
    keyPrefix: 'oidc:',
    ttlSeconds,
  });

  return new RedisOidcStateStore(client, ttlSeconds);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || raw.length === 0) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return n;
}

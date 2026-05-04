/**
 * DPoP — Demonstrating Proof-of-Possession at the Application Layer
 * ---------------------------------------------------------------------------
 * Reference implementation of the subset of RFC 9449 (DPoP) needed to
 * make Euno capability tokens **sender-constrained** (F-2 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`, addresses I-2).
 *
 * Why
 * ---
 * A capability JWT is a bearer credential: any caller that obtains it
 * can use it until the token expires or is revoked. RFC 9449 fixes
 * this by binding a token to a keypair the holder generates locally
 * and asks the issuer to remember in a `cnf.jkt` claim. Each protected
 * request then carries a freshly-signed "DPoP proof" JWT with the
 * HTTP method and URL of the request and a signature over the
 * holder's private key. The resource server checks:
 *
 *   1. The proof's signature verifies under the public JWK in its
 *      protected header (`jwk`).
 *   2. The SHA-256 thumbprint of that JWK equals the token's
 *      `cnf.jkt` (so the proof and the token agree on the holder).
 *   3. The proof's `htm`, `htu`, `iat`, and `jti` all line up with
 *      this request and the proof has not been replayed within a
 *      bounded TTL.
 *
 * Together these mean a stolen capability token is useless without
 * the holder's private key.
 *
 * What lives here
 * ---------------
 *   * {@link computeJwkThumbprint}   — RFC 7638 SHA-256 thumbprint.
 *   * {@link createDpopProof}        — Sign a proof JWT with a private key.
 *   * {@link verifyDpopProof}        — Full RFC 9449 proof check.
 *   * {@link InMemoryDpopReplayStore}— Bounded TTL set used to refuse
 *     replays within the proof's validity window.
 *   * {@link extractHtu}             — Canonicalise a request URL into
 *     an `htu` value (drops query/fragment per RFC 9449 § 4.2).
 *
 * Implementations of {@link DpopReplayStore} can be swapped (e.g. a
 * Redis-backed store for multi-instance gateways) without changing
 * the verification entry point.
 */

import * as jose from 'jose';
import * as nodeCrypto from 'crypto';
import { CapabilityError, ErrorCode } from './utils';

/**
 * Hard floor and default for {@link InMemoryDpopReplayStore} capacity.
 * The floor (1 024) keeps the bound large enough for tests and
 * single-replica dev gateways; the default (50 000) covers ~10 minutes
 * of 80 req/s sustained traffic before eviction kicks in.
 */
const REPLAY_STORE_MIN_ENTRIES = 1024;
const REPLAY_STORE_DEFAULT_MAX_ENTRIES = 50_000;
/**
 * Fraction of {@link InMemoryDpopReplayStore.maxEntries} evicted in a
 * single pass when the cache hits its cap and no entries have aged
 * out. 10 % keeps the bound tight without thrashing the Map under
 * burst traffic.
 */
const REPLAY_STORE_EVICTION_FRACTION = 0.1;

/**
 * Decoded set of DPoP proof header fields the verifier inspects
 * (RFC 9449 § 4.2). The `alg`, `jwk`, and `typ` members live in the
 * JWS protected header; the rest are claims in the JWT body.
 */
export interface DpopProofHeader {
  /** Always `"dpop+jwt"`. */
  typ: string;
  /** Asymmetric JWS algorithm: ES256, EdDSA, PS256, RS256, etc. */
  alg: string;
  /** Public JWK whose private counterpart signed this proof. */
  jwk: jose.JWK;
}

/** Decoded DPoP proof claims (RFC 9449 § 4.2). */
export interface DpopProofClaims {
  /** Unique proof id; the replay store rejects duplicates. */
  jti: string;
  /** HTTP method, upper-case (`POST`, `GET`, ...). */
  htm: string;
  /** Target URL with no query/fragment (see {@link extractHtu}). */
  htu: string;
  /** Issued-at unix seconds. */
  iat: number;
  /** Optional access-token hash (RFC 9449 § 6 — not yet used by Euno). */
  ath?: string;
  /** Optional nonce (RFC 9449 § 8 — not yet used by Euno). */
  nonce?: string;
}

/**
 * Result of a successful {@link verifyDpopProof} call. Surfaces the
 * computed thumbprint so the caller can pin it to the access token's
 * `cnf.jkt`, plus the canonicalised header / claims for logging and
 * for downstream `ath` checks once we add them.
 */
export interface DpopVerifyResult {
  /** Base64url SHA-256 thumbprint of `header.jwk`. */
  jkt: string;
  header: DpopProofHeader;
  claims: DpopProofClaims;
}

/** JWS algorithms accepted by {@link verifyDpopProof}. */
export const DPOP_SUPPORTED_ALGORITHMS = [
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
  'PS256',
  'PS384',
  'PS512',
  'RS256',
  'RS384',
  'RS512',
] as const;
export type DpopSupportedAlgorithm = (typeof DPOP_SUPPORTED_ALGORITHMS)[number];

/**
 * Pluggable replay defence. Verifiers call {@link checkAndRemember}
 * with the proof's `jti` (and the timestamp at which it should
 * expire); a `false` return means the proof has been seen before and
 * MUST be rejected.
 */
export interface DpopReplayStore {
  /**
   * Atomically test whether `jti` was seen recently. Returns `true`
   * when the proof is novel and was inserted; `false` when the proof
   * has been seen within its TTL and must be refused as a replay.
   *
   * `expiresAtUnixSec` is the wall-clock time at which the entry may
   * be evicted. Implementations MUST honour it as an upper bound so
   * memory does not grow unboundedly.
   */
  checkAndRemember(jti: string, expiresAtUnixSec: number): Promise<boolean>;
}

/**
 * In-memory replay defence sized for a single gateway process. Uses
 * a `Map<jti, expiresAt>` and lazily evicts expired entries on every
 * insert (amortised O(1)). Multi-instance deployments should plug in
 * a Redis-backed store so a replay sent to a different gateway
 * replica is still detected.
 *
 * `maxEntries` is a hard cap defending against an attacker generating
 * an unbounded number of unique `jti`s — when reached, the store
 * evicts the oldest 10% of entries before accepting the new one. The
 * default (50 000) covers ~10 minutes of 80 req/s sustained traffic.
 */
export class InMemoryDpopReplayStore implements DpopReplayStore {
  private readonly entries = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(opts: { maxEntries?: number } = {}) {
    this.maxEntries = Math.max(
      REPLAY_STORE_MIN_ENTRIES,
      opts.maxEntries ?? REPLAY_STORE_DEFAULT_MAX_ENTRIES,
    );
  }

  async checkAndRemember(jti: string, expiresAtUnixSec: number): Promise<boolean> {
    const nowSec = Math.floor(Date.now() / 1000);

    const existing = this.entries.get(jti);
    if (existing !== undefined && existing > nowSec) {
      // Still inside its window — replay.
      return false;
    }
    if (existing !== undefined) {
      // Stale entry — drop and treat as novel.
      this.entries.delete(jti);
    }

    if (this.entries.size >= this.maxEntries) {
      this.evictExpired(nowSec);
      if (this.entries.size >= this.maxEntries) {
        // Still over — drop the oldest REPLAY_STORE_EVICTION_FRACTION
        // (Map preserves insertion order). This keeps the bound
        // tight even if every queued jti is still in-window.
        const toDrop = Math.ceil(this.maxEntries * REPLAY_STORE_EVICTION_FRACTION);
        let dropped = 0;
        for (const key of this.entries.keys()) {
          this.entries.delete(key);
          dropped += 1;
          if (dropped >= toDrop) break;
        }
      }
    }

    this.entries.set(jti, expiresAtUnixSec);
    return true;
  }

  /** Remove every entry whose TTL has passed. Called inline on insert. */
  private evictExpired(nowSec: number): void {
    for (const [k, exp] of this.entries) {
      if (exp <= nowSec) {
        this.entries.delete(k);
      }
    }
  }

  /** Test helper: number of currently-tracked proofs. */
  size(): number {
    return this.entries.size;
  }
}

/**
 * Subset of the `ioredis` client surface this store depends on. Defined
 * locally so this package does not take a hard runtime dependency on
 * `ioredis` (callers wire one in via {@link createDpopReplayStoreFromEnv}
 * or by passing a client to {@link RedisDpopReplayStore} directly).
 */
export interface RedisDpopReplayClient {
  set(
    key: string,
    value: string,
    ttlMode: 'EX',
    ttlSeconds: number,
    setMode: 'NX',
  ): Promise<'OK' | null>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Default Redis key prefix for DPoP replay entries. Kept short so the
 * combined key length (`prefix + jti`) stays well under the Redis
 * 512 MB key limit; the value is the `jti`'s expiry written as a
 * placeholder (`"1"`) — only key-presence matters.
 */
const DEFAULT_DPOP_REPLAY_KEY_PREFIX = 'dpopjti:';

/**
 * Redis-backed DPoP replay store for multi-replica gateways. Without
 * a shared backend each gateway pod keeps its own in-memory `jti`
 * cache, so a captured proof can be replayed once per replica inside
 * the acceptance window — exactly the failure mode F-2 was designed
 * to close. Uses Redis `SET key value EX ttl NX` which is atomic and
 * race-free across replicas: the first writer wins, every subsequent
 * `checkAndRemember` for the same `jti` returns `false` until the
 * TTL elapses.
 *
 * Mirrors the operational story of {@link RedisCallCounterStore} —
 * same `ioredis`-shaped client surface, same `failClosedOnError`
 * semantics. When Redis is unavailable, **fail closed** is the safe
 * default: a verifier that cannot prove novelty MUST refuse the
 * proof, otherwise replay protection is silently disabled exactly
 * when the operator most needs it.
 */
export class RedisDpopReplayStore implements DpopReplayStore {
  private readonly client: RedisDpopReplayClient;
  private readonly keyPrefix: string;
  private readonly failClosedOnError: boolean;
  private readonly logger?: { warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void };

  constructor(
    client: RedisDpopReplayClient,
    opts: {
      keyPrefix?: string;
      failClosedOnError?: boolean;
      logger?: { warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void };
    } = {},
  ) {
    this.client = client;
    this.keyPrefix = opts.keyPrefix ?? DEFAULT_DPOP_REPLAY_KEY_PREFIX;
    this.failClosedOnError = opts.failClosedOnError !== false;
    this.logger = opts.logger;
  }

  async checkAndRemember(jti: string, expiresAtUnixSec: number): Promise<boolean> {
    const nowSec = Math.floor(Date.now() / 1000);
    // Always honour at least 1s TTL so an already-expired `jti`
    // arriving at the verifier (clock-skew edge case) doesn't poison
    // the cache forever. The verifier already rejects expired proofs
    // upstream — this is belt and braces.
    const ttlSec = Math.max(1, expiresAtUnixSec - nowSec);
    try {
      // SET NX: returns 'OK' when the key did not exist (novel proof),
      // null when it did (replay).
      const result = await this.client.set(
        `${this.keyPrefix}${jti}`,
        '1',
        'EX',
        ttlSec,
        'NX',
      );
      return result === 'OK';
    } catch (err) {
      this.logger?.error('Redis DPoP replay store error', {
        error: err instanceof Error ? err.message : String(err),
      });
      // Fail closed: pretend the proof was a replay so the request
      // is denied. Operators who consciously prefer availability
      // over replay-protection freshness can pass
      // `failClosedOnError: false` to flip this.
      return !this.failClosedOnError;
    }
  }

  /** Release the underlying Redis connection. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      // Closing on shutdown is best-effort.
    }
  }
}

/**
 * Factory that picks a {@link DpopReplayStore} implementation based on
 * the environment: Redis when `REDIS_URL` is set (multi-replica
 * gateways) and {@link InMemoryDpopReplayStore} otherwise (single
 * replica or local dev). Mirrors {@link createCallCounterStoreFromEnv}.
 *
 * Environment variables:
 *   - `REDIS_URL` — Redis connection string. When unset, returns the
 *     in-memory store.
 *   - `DPOP_REPLAY_KEY_PREFIX` — overrides the default `dpopjti:`.
 *   - `DPOP_REPLAY_FAIL_CLOSED_ON_ERROR` — `"false"` to fall open on
 *     Redis errors (default: fail closed).
 */
export async function createDpopReplayStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: { info: (...args: unknown[]) => void; warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void },
): Promise<DpopReplayStore> {
  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger?.info(
      'REDIS_URL not configured, using in-memory DPoP replay store. ' +
        'A captured DPoP proof can be replayed once per gateway replica ' +
        'inside its acceptance window — wire REDIS_URL in any multi-replica deployment.',
    );
    return new InMemoryDpopReplayStore();
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    RedisCtor = require('ioredis');
  } catch (error) {
    logger?.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed DPoP replay defence. ' +
        'Falling back to in-memory store; replay protection WILL NOT be ' +
        'shared across gateway instances.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new InMemoryDpopReplayStore();
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisDpopReplayClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const keyPrefix = env.DPOP_REPLAY_KEY_PREFIX || DEFAULT_DPOP_REPLAY_KEY_PREFIX;
  const failClosedOnError = env.DPOP_REPLAY_FAIL_CLOSED_ON_ERROR !== 'false';
  return new RedisDpopReplayStore(client, { keyPrefix, failClosedOnError, logger });
}

/**
 * Compute the canonical SHA-256 JWK thumbprint defined by RFC 7638.
 * Returns the base64url-encoded digest, suitable for use as a `cnf.jkt`
 * value or for comparison against one.
 *
 * Delegates to `jose.calculateJwkThumbprint` which already implements
 * the RFC 7638 canonical-JSON ordering (kty + the curve / modulus /
 * exponent fields per key type, in the order the spec mandates).
 */
export async function computeJwkThumbprint(jwk: jose.JWK): Promise<string> {
  return jose.calculateJwkThumbprint(jwk, 'sha256');
}

/**
 * Synchronous variant for the issuer side, where we receive a JWK in
 * the {@link IssueCapabilityRequest} body and want to stamp `cnf.jkt`
 * on the resulting capability token without making the call site
 * async-fan-out aware. Implements the same RFC 7638 algorithm.
 */
export async function jwkToJkt(jwk: Record<string, unknown>): Promise<string> {
  return computeJwkThumbprint(jwk as unknown as jose.JWK);
}

/**
 * Strip query string and fragment from a URL per RFC 9449 § 4.2.
 * Lower-cases the scheme and host (case-insensitive parts of the URL
 * per RFC 3986) and preserves an explicit non-default port. Used by
 * both proof producers and verifiers so the comparison is symmetric.
 */
export function extractHtu(url: string): string {
  const u = new URL(url);
  // URL toString() of `https://Example.COM/path?x=1#frag` is
  // `https://example.com/path?x=1#frag` already (host is canonicalised
  // by the WHATWG URL parser). We just drop search + hash.
  u.search = '';
  u.hash = '';
  return u.toString();
}

/**
 * Options accepted by {@link verifyDpopProof}.
 */
export interface VerifyDpopProofOptions {
  /** Signed compact JWS the client sent in the `DPoP` header. */
  proof: string;
  /** HTTP method of the request the proof is supposed to bind to. */
  httpMethod: string;
  /**
   * Target URL of the request the proof is supposed to bind to. The
   * verifier strips query/fragment via {@link extractHtu} before
   * comparing with the proof's `htu` claim.
   */
  httpUrl: string;
  /**
   * Replay store used to reject duplicate proofs within the proof's
   * validity window. Use {@link InMemoryDpopReplayStore} for
   * single-instance deployments; supply a shared backend for
   * multi-instance gateways.
   */
  replayStore: DpopReplayStore;
  /**
   * Acceptable clock skew (in seconds) for the `iat` check. Default 60.
   */
  clockSkewSeconds?: number;
  /**
   * Maximum age (in seconds) of an accepted proof. Anything older is
   * refused as expired. Default 300 (5 min).
   */
  maxAgeSeconds?: number;
  /**
   * If supplied, the verifier additionally requires the proof's
   * embedded JWK thumbprint to equal `expectedJkt` (the access
   * token's `cnf.jkt`). Callers MUST set this whenever they have an
   * access token in hand — otherwise an attacker could present a
   * proof signed with an *unrelated* keypair and pass verification.
   */
  expectedJkt?: string;
  /**
   * Allow-list of JWS algorithms. Defaults to
   * {@link DPOP_SUPPORTED_ALGORITHMS}. Operators MAY narrow this for
   * compliance reasons (e.g. allow only `ES256`). The list MUST NOT
   * include any symmetric alg — `none` and `HS*` are rejected by the
   * verifier regardless of caller input.
   */
  allowedAlgorithms?: readonly string[];
}

/**
 * Verify a DPoP proof per RFC 9449 § 4.3:
 *
 *   1. Parse the protected header; require `typ === "dpop+jwt"`,
 *      `alg ∈ allowedAlgorithms`, and an embedded `jwk`.
 *   2. Verify the JWS signature against `header.jwk`.
 *   3. Check `htm` matches the request method (case-insensitive).
 *   4. Check `htu` matches the request URL (with query / fragment
 *      stripped by both sides, see {@link extractHtu}).
 *   5. Check `iat` is within `±clockSkewSeconds` of "now" and not
 *      older than `maxAgeSeconds`.
 *   6. Check `jti` has not been seen within its remaining validity
 *      window (replay defence).
 *   7. Compute the SHA-256 thumbprint of `header.jwk` and (when
 *      `expectedJkt` was supplied) require it to match.
 *
 * Throws {@link CapabilityError} with {@link ErrorCode.INVALID_TOKEN}
 * (HTTP 401) on any failure so the gateway error middleware emits
 * a uniform `{ error: { code, message } }` envelope.
 */
export async function verifyDpopProof(
  options: VerifyDpopProofOptions,
): Promise<DpopVerifyResult> {
  const {
    proof,
    httpMethod,
    httpUrl,
    replayStore,
    clockSkewSeconds = 60,
    maxAgeSeconds = 300,
    expectedJkt,
    allowedAlgorithms = DPOP_SUPPORTED_ALGORITHMS,
  } = options;

  if (!proof || typeof proof !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof is required',
      401,
    );
  }

  // Step 1: Parse + validate the protected header before doing any
  // crypto. This keeps cheap rejections cheap.
  let protectedHeader: jose.ProtectedHeaderParameters;
  try {
    protectedHeader = jose.decodeProtectedHeader(proof);
  } catch {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof is malformed (header)',
      401,
    );
  }

  if (protectedHeader.typ !== 'dpop+jwt') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof has wrong typ: expected "dpop+jwt", got "${String(protectedHeader.typ ?? '')}"`,
      401,
    );
  }

  const alg = protectedHeader.alg;
  if (!alg || typeof alg !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof header missing alg',
      401,
    );
  }
  // RFC 9449 § 4.2: MUST be an asymmetric algorithm. Defence-in-depth
  // against a caller-supplied allow-list that erroneously contains a
  // symmetric alg.
  const upperAlg = alg.toUpperCase();
  if (upperAlg === 'NONE' || upperAlg.startsWith('HS')) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof uses forbidden symmetric algorithm: ${alg}`,
      401,
    );
  }
  if (!allowedAlgorithms.includes(alg)) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof uses disallowed algorithm: ${alg}`,
      401,
    );
  }

  const jwk = protectedHeader.jwk;
  if (!jwk || typeof jwk !== 'object') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof header missing jwk',
      401,
    );
  }
  // Reject any private-key material in the proof header (would leak
  // the holder's secret to anyone observing the request).
  const rejectedPrivateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];
  for (const m of rejectedPrivateMembers) {
    if (m in jwk) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `DPoP proof header jwk contains private member "${m}"`,
        401,
      );
    }
  }

  // Step 2: signature.
  let key: jose.KeyLike | Uint8Array;
  try {
    key = await jose.importJWK(jwk as jose.JWK, alg);
  } catch (err) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof jwk is not importable: ${err instanceof Error ? err.message : 'unknown error'}`,
      401,
    );
  }

  let verified: jose.JWTVerifyResult;
  try {
    verified = await jose.jwtVerify(proof, key, {
      algorithms: [alg],
      // Don't use jose's clockTolerance / maxTokenAge here; we apply
      // our own checks below so the error messages stay specific
      // (and so we have full control over `nbf` semantics, which the
      // DPoP spec leaves alone).
    });
  } catch (err) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof signature verification failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      401,
    );
  }

  const claims = verified.payload as unknown as Partial<DpopProofClaims>;

  // Step 3: htm.
  if (typeof claims.htm !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof missing htm claim',
      401,
    );
  }
  if (claims.htm.toUpperCase() !== httpMethod.toUpperCase()) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof htm mismatch: proof says "${claims.htm}", request is "${httpMethod}"`,
      401,
    );
  }

  // Step 4: htu.
  if (typeof claims.htu !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof missing htu claim',
      401,
    );
  }
  let canonicalRequestHtu: string;
  let canonicalProofHtu: string;
  try {
    canonicalRequestHtu = extractHtu(httpUrl);
    canonicalProofHtu = extractHtu(claims.htu);
  } catch {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof htu is not a valid URL',
      401,
    );
  }
  if (canonicalProofHtu !== canonicalRequestHtu) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof htu mismatch: proof says "${canonicalProofHtu}", request is "${canonicalRequestHtu}"`,
      401,
    );
  }

  // Step 5: iat.
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof missing or invalid iat claim',
      401,
    );
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (claims.iat > nowSec + clockSkewSeconds) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof iat is in the future (beyond accepted clock skew)',
      401,
    );
  }
  if (nowSec - claims.iat > maxAgeSeconds) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `DPoP proof is too old (issued ${nowSec - claims.iat}s ago, max ${maxAgeSeconds}s)`,
      401,
    );
  }

  // Step 6: jti / replay.
  if (typeof claims.jti !== 'string' || claims.jti.length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof missing jti claim',
      401,
    );
  }
  // Remember the proof until the end of its acceptance window so a
  // replay within the window is rejected.
  const replayExpiresAt = claims.iat + maxAgeSeconds;
  const novel = await replayStore.checkAndRemember(claims.jti, replayExpiresAt);
  if (!novel) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof jti has already been used (replay)',
      401,
    );
  }

  // Step 7: thumbprint.
  const jkt = await computeJwkThumbprint(jwk as jose.JWK);
  if (expectedJkt !== undefined && jkt !== expectedJkt) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'DPoP proof JWK does not match the access token cnf.jkt',
      401,
    );
  }

  return {
    jkt,
    header: {
      typ: 'dpop+jwt',
      alg,
      jwk: jwk as jose.JWK,
    },
    claims: {
      jti: claims.jti,
      htm: claims.htm,
      htu: claims.htu,
      iat: claims.iat,
      ...(typeof claims.ath === 'string' ? { ath: claims.ath } : {}),
      ...(typeof claims.nonce === 'string' ? { nonce: claims.nonce } : {}),
    },
  };
}

/**
 * Inputs accepted by {@link createDpopProof}. The agent-runtime calls
 * this once per outbound request.
 */
export interface CreateDpopProofOptions {
  /**
   * Private key (already imported) used to sign the proof.  Created
   * once at runtime startup via `jose.generateKeyPair` or
   * `jose.importJWK`.
   */
  privateKey: jose.KeyLike | Uint8Array;
  /** Public JWK whose thumbprint matches the access token's `cnf.jkt`. */
  publicJwk: jose.JWK;
  /** JWS algorithm — must agree with `privateKey`'s capabilities. */
  algorithm: string;
  /** HTTP method, e.g. `'POST'`. */
  httpMethod: string;
  /** Target URL the proof binds to (query/fragment stripped by us). */
  httpUrl: string;
  /**
   * Optional issued-at override (unix seconds). Defaults to "now". Mostly
   * useful in tests.
   */
  iat?: number;
  /**
   * Optional pre-allocated jti. Defaults to a fresh random UUID. Tests
   * use this to assert replay rejection.
   */
  jti?: string;
}

/**
 * Sign a DPoP proof JWT bound to (`httpMethod`, `httpUrl`, `now`).
 * The agent-runtime calls this once per outbound request and sends
 * the result in a `DPoP` HTTP header.
 *
 * Note: the public JWK MUST be sanitised (no private members) by the
 * caller — `jose.exportJWK` of a public key handle already does so;
 * tests that hand-craft JWKs should use only the public-half members.
 */
export async function createDpopProof(
  options: CreateDpopProofOptions,
): Promise<string> {
  const iat = options.iat ?? Math.floor(Date.now() / 1000);
  const jti = options.jti ?? generateRandomJti();
  const htu = extractHtu(options.httpUrl);

  const protectedHeader: jose.JWTHeaderParameters = {
    alg: options.algorithm,
    typ: 'dpop+jwt',
    jwk: options.publicJwk,
  };

  return new jose.SignJWT({
    htm: options.httpMethod.toUpperCase(),
    htu,
    jti,
  })
    .setProtectedHeader(protectedHeader)
    .setIssuedAt(iat)
    .sign(options.privateKey);
}

/**
 * Generate a random JWT id suitable for DPoP `jti`. Uses the global
 * Web-Crypto-style `crypto.randomUUID` when available (Node ≥ 14.17,
 * all supported browsers); otherwise falls back to 16 base16 bytes
 * of `crypto.getRandomValues`.
 */
function generateRandomJti(): string {
  if (typeof nodeCrypto.randomUUID === 'function') {
    return nodeCrypto.randomUUID();
  }
  return nodeCrypto.randomBytes(16).toString('hex');
}

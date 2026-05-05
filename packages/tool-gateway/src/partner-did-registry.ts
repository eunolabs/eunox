/**
 * Partner-DID Registry
 * ---------------------------------------------------------------------------
 * A pluggable registry of partner-DID *trust entries* that underpins the
 * cross-org trust model.  The registry replaces the single `TRUSTED_PARTNER_DIDS`
 * env-var with a proper lifecycle:
 *
 *   proposed → active → revoked
 *
 * with a mandatory **two-eyes** (four-eyes) approval step before activation,
 * optional cryptographic pinning (JCS-SHA-256 over the DID document and/or
 * per-VM JWK thumbprints), and an extension point for secondary-resolver
 * cross-checks.
 *
 * Two implementations are shipped:
 *   - {@link InMemoryPartnerDidRegistry} — single-replica / dev; seeded at
 *     boot from `TRUSTED_PARTNER_DIDS` if set.
 *   - {@link RedisPartnerDidRegistry} — multi-replica / production; stores
 *     each entry as a JSON blob at `HSET euno:gateway:partner-did:<did>` and
 *     tracks the index in a Redis set.
 *
 * The factory {@link createPartnerDidRegistryFromEnv} mirrors the
 * established `…FromEnv` pattern used by all other gateway stores.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { Logger } from '@euno/common';

// ──────────────────────────────────────────────────────────────────────────────
// Pin attestation
// ──────────────────────────────────────────────────────────────────────────────

/**
 * A gateway-signed attestation that binds a DID-document hash to the operator
 * who approved the entry and the exact moment of activation.
 *
 * The HMAC-SHA-256 is computed over the canonical JSON serialisation of
 * `{ did, pinnedDocSha256, approver, activatedAt }` using a shared secret
 * stored in `PARTNER_DID_PIN_SECRET`.  This means:
 *
 *   - If the Redis store is tampered with (pin swapped), the HMAC breaks.
 *   - If the secret is rotated, existing attestations become invalid.
 *     The gateway **fails closed** when a present-but-invalid attestation is
 *     detected — the entry must be re-approved via the admin API to generate
 *     a fresh attestation under the new secret.
 *   - Env-var-seeded entries (from `TRUSTED_PARTNER_DIDS`) never have
 *     attestations; the resolver treats them as unpinned.
 */
export interface PinAttestation {
  /** The DID this attestation covers — prevents cross-DID substitution. */
  did: string;
  /** The JCS-SHA-256 fingerprint that was pinned at activation. */
  pinnedDocSha256: string;
  /** Operator identity who performed the approval (from X-Admin-Operator). */
  approver: string;
  /** Unix ms timestamp of activation — prevents replay across activations. */
  activatedAt: number;
  /** HMAC-SHA-256(secret, canonicalJson) — hex lower-case. */
  hmac: string;
}

/**
 * Produce a {@link PinAttestation} over the supplied fields.
 *
 * The canonical payload is `jcsSerialize({ did, pinnedDocSha256, approver,
 * activatedAt })`.  Callers MUST supply all four fields; the returned
 * attestation includes the HMAC over that payload.
 */
export function createPinAttestation(
  fields: Omit<PinAttestation, 'hmac'>,
  secret: string,
): PinAttestation {
  const payload = jcsSerialize({
    did: fields.did,
    pinnedDocSha256: fields.pinnedDocSha256,
    approver: fields.approver,
    activatedAt: fields.activatedAt,
  });
  const hmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return { ...fields, hmac };
}

/**
 * Verify a {@link PinAttestation} produced by {@link createPinAttestation}.
 *
 * Returns `true` when the HMAC matches, `false` otherwise.  Timing-safe
 * comparison prevents timing oracles.  Malformed `hmac` values (non-hex,
 * wrong length, non-string) are treated as invalid and return `false` rather
 * than throwing, so this function is always safe to call in boolean context.
 */
export function verifyPinAttestation(attestation: PinAttestation, secret: string): boolean {
  const payload = jcsSerialize({
    did: attestation.did,
    pinnedDocSha256: attestation.pinnedDocSha256,
    approver: attestation.approver,
    activatedAt: attestation.activatedAt,
  });
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  // Guard: attestation.hmac must be a 64-char lowercase hex string.
  // Buffer.from(..., 'hex') silently truncates non-hex characters, which would
  // cause timingSafeEqual to throw on a buffer-length mismatch.
  if (typeof attestation.hmac !== 'string' || !/^[0-9a-f]{64}$/i.test(attestation.hmac)) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(
      Buffer.from(attestation.hmac, 'hex'),
      Buffer.from(expected, 'hex'),
    );
  } catch {
    return false;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Schema types
// ──────────────────────────────────────────────────────────────────────────────

export type PartnerDidStatus = 'proposed' | 'active' | 'revoked';

/** Optional secondary-resolver spec for cross-check.  See 2C in the plan. */
export interface SecondaryResolverSpec {
  /** Resolver method tag (informational; only 'web' performs a real fetch today). */
  method: 'web' | 'ion-anchor' | 'ipfs';
  /** URL to fetch the canonicalized DID document from. */
  url: string;
  /**
   * When present the resolver fetches the URL, canonicalizes the JSON document,
   * and requires that its SHA-256 (hex) equals this value.
   * When absent the resolver performs byte-equality between the two canonicalized
   * documents (primary vs. secondary).
   */
  expectedSha256?: string;
}

/**
 * One entry in the trust registry — one partner DID.
 */
export interface PartnerDidEntry {
  /** The partner's DID (primary key). */
  did: string;
  status: PartnerDidStatus;
  /**
   * Operator identity string (from `X-Admin-Operator` header inside an
   * already-authenticated `X-Admin-Api-Key` channel) who submitted the
   * proposal.
   */
  proposer: string;
  /**
   * Operator identity who approved.  Must differ from `proposer`.
   * Undefined when still in `proposed` state.
   */
  approver?: string;
  proposedAt: number; // unix ms
  activatedAt?: number; // unix ms
  revokedAt?: number; // unix ms
  /**
   * SHA-256 (hex, lower-case) over the JCS-canonicalized DID document.
   * When present the resolver rejects any document whose hash differs —
   * prevents MITM of the DID-document endpoint.
   */
  pinnedDocSha256?: string;
  /**
   * Per-VM JWK thumbprint pins (RFC 7638 SHA-256, base64url).
   * Key: `kid` value from the verification method.
   * Value: expected thumbprint (from `jose.calculateJwkThumbprint`).
   */
  pinnedVerificationKeys?: Record<string, string>;
  /** Optional secondary-resolver cross-check specification. */
  secondaryResolver?: SecondaryResolverSpec;
  /** Optional validity window (unix ms). */
  notBefore?: number;
  notAfter?: number;
  /** Free-form operator note (incident-ticket reference, etc.). */
  notes?: string;
  /**
   * Gateway-signed attestation binding `pinnedDocSha256` to the approver and
   * activation timestamp (see {@link PinAttestation}).  Produced automatically
   * by the admin approval endpoint when `PARTNER_DID_PIN_SECRET` is configured.
   * Absent for env-var-seeded entries and for proposals approved before the
   * feature was enabled.
   */
  pinAttestation?: PinAttestation;
}

// ──────────────────────────────────────────────────────────────────────────────
// Interface
// ──────────────────────────────────────────────────────────────────────────────

export interface PartnerDidRegistry {
  /**
   * Return true when `did` is in `active` status (or present in the legacy
   * env-var set that was used to seed the registry).  Used by the resolver
   * before any network call.
   */
  trusts(did: string): Promise<boolean>;

  /** Return the full entry for `did`, or `undefined` when not found. */
  get(did: string): Promise<PartnerDidEntry | undefined>;

  /**
   * Create a new entry in `proposed` state.  Throws when `did` already has an
   * `active` or `proposed` entry.
   */
  propose(entry: Omit<PartnerDidEntry, 'status' | 'proposedAt'>): Promise<PartnerDidEntry>;

  /**
   * Transition a `proposed` entry to `active`.  Throws when:
   *  - entry does not exist
   *  - entry is not in `proposed` state
   *  - `approver === entry.proposer` (two-eyes violation)
   *
   * @param pinOverrides  Optional fields to merge into the entry at activation:
   *   `pinnedDocSha256`      — auto-computed hash (overwrites or supplies the pin).
   *   `pinnedVerificationKeys` — auto-computed per-VM thumbprints.
   *   `pinAttestation`       — gateway-signed attestation (see {@link PinAttestation}).
   *   Passing these here keeps the approval as an atomic state transition.
   */
  approve(
    did: string,
    approver: string,
    pinOverrides?: Partial<Pick<PartnerDidEntry, 'pinnedDocSha256' | 'pinnedVerificationKeys' | 'pinAttestation'>>,
  ): Promise<PartnerDidEntry>;

  /**
   * Mark an entry as `revoked`.  Single-operator (incident response is
   * intentionally fast).  Throws when the entry does not exist.
   */
  revoke(did: string, revokedBy: string): Promise<PartnerDidEntry>;

  /** List all entries, optionally filtered by status. */
  list(statusFilter?: PartnerDidStatus): Promise<PartnerDidEntry[]>;
}

// ──────────────────────────────────────────────────────────────────────────────
// JCS canonicalization (minimal, sufficient for DID docs)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Produce a deterministic JSON serialization of `value` by sorting all object
 * keys recursively (JCS / RFC 8785 §3.2.3).  Only handles plain JSON values
 * (objects, arrays, strings, numbers, booleans, null) — DID documents never
 * contain binary or special types that a full JCS implementation would need.
 */
export function jcsSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(jcsSerialize).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  return (
    '{' +
    sortedKeys
      .map((k) => JSON.stringify(k) + ':' + jcsSerialize(obj[k]))
      .join(',') +
    '}'
  );
}

/** Compute the JCS-SHA-256 fingerprint of an object (hex, lower-case). */
export function jcsSha256(value: unknown): string {
  return crypto.createHash('sha256').update(jcsSerialize(value)).digest('hex');
}

// ──────────────────────────────────────────────────────────────────────────────
// InMemory implementation
// ──────────────────────────────────────────────────────────────────────────────

export class InMemoryPartnerDidRegistry implements PartnerDidRegistry {
  private readonly entries = new Map<string, PartnerDidEntry>();

  /**
   * Seed with a set of already-trusted DIDs (from `TRUSTED_PARTNER_DIDS`).
   * Each seeded entry is `active` with operator identity
   * `"env:TRUSTED_PARTNER_DIDS"` and no pin material.
   */
  seed(dids: string[]): void {
    for (const did of dids) {
      if (!this.entries.has(did)) {
        this.entries.set(did, {
          did,
          status: 'active',
          proposer: 'env:TRUSTED_PARTNER_DIDS',
          approver: 'env:TRUSTED_PARTNER_DIDS',
          proposedAt: Date.now(),
          activatedAt: Date.now(),
        });
      }
    }
  }

  async trusts(did: string): Promise<boolean> {
    const entry = this.entries.get(did);
    if (!entry || entry.status !== 'active') return false;
    const now = Date.now();
    if (entry.notBefore !== undefined && now < entry.notBefore) return false;
    if (entry.notAfter !== undefined && now > entry.notAfter) return false;
    return true;
  }

  async get(did: string): Promise<PartnerDidEntry | undefined> {
    return this.entries.get(did);
  }

  async propose(
    entry: Omit<PartnerDidEntry, 'status' | 'proposedAt'>,
  ): Promise<PartnerDidEntry> {
    const existing = this.entries.get(entry.did);
    if (existing && (existing.status === 'active' || existing.status === 'proposed')) {
      throw new Error(
        `Partner DID ${entry.did} already exists with status '${existing.status}'`,
      );
    }
    const newEntry: PartnerDidEntry = {
      ...entry,
      // Always store pinnedDocSha256 in lowercase so hash comparisons are
      // unambiguous regardless of the case the proposer supplied.
      ...(entry.pinnedDocSha256 !== undefined
        ? { pinnedDocSha256: entry.pinnedDocSha256.toLowerCase() }
        : {}),
      status: 'proposed',
      proposedAt: Date.now(),
    };
    this.entries.set(entry.did, newEntry);
    return newEntry;
  }

  async approve(
    did: string,
    approver: string,
    pinOverrides?: Partial<Pick<PartnerDidEntry, 'pinnedDocSha256' | 'pinnedVerificationKeys' | 'pinAttestation'>>,
  ): Promise<PartnerDidEntry> {
    const entry = this.entries.get(did);
    if (!entry) {
      throw new Error(`Partner DID not found: ${did}`);
    }
    if (entry.status !== 'proposed') {
      throw new Error(
        `Partner DID ${did} cannot be approved: current status is '${entry.status}'`,
      );
    }
    if (approver === entry.proposer) {
      throw new TwoEyesViolationError(
        `Two-eyes violation: approver '${approver}' is the same as proposer`,
        did,
        approver,
      );
    }
    // Normalize pinnedDocSha256 to lowercase regardless of source (pinOverrides
    // or carried over from the proposal) so attestation field comparisons are
    // unambiguous.
    const effectivePin = pinOverrides?.pinnedDocSha256 ?? entry.pinnedDocSha256;
    const updated: PartnerDidEntry = {
      ...entry,
      ...(pinOverrides ?? {}),
      ...(effectivePin !== undefined ? { pinnedDocSha256: effectivePin.toLowerCase() } : {}),
      status: 'active',
      approver,
      activatedAt: Date.now(),
    };
    this.entries.set(did, updated);
    return updated;
  }

  async revoke(did: string, _revokedBy: string): Promise<PartnerDidEntry> {
    const entry = this.entries.get(did);
    if (!entry) {
      throw new Error(`Partner DID not found: ${did}`);
    }
    const updated: PartnerDidEntry = {
      ...entry,
      status: 'revoked',
      revokedAt: Date.now(),
    };
    this.entries.set(did, updated);
    return updated;
  }

  async list(statusFilter?: PartnerDidStatus): Promise<PartnerDidEntry[]> {
    const all = [...this.entries.values()];
    return statusFilter ? all.filter((e) => e.status === statusFilter) : all;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Two-eyes violation error (typed for admin-api to catch)
// ──────────────────────────────────────────────────────────────────────────────

export class TwoEyesViolationError extends Error {
  constructor(
    message: string,
    public readonly did: string,
    public readonly operator: string,
  ) {
    super(message);
    this.name = 'TwoEyesViolationError';
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal Redis interface (same pattern as revocation-store.ts)
// ──────────────────────────────────────────────────────────────────────────────

export interface RegistryRedisClient {
  hget(key: string, field: string): Promise<string | null>;
  hset(key: string, field: string, value: string): Promise<unknown>;
  smembers(key: string): Promise<string[]>;
  sadd(key: string, ...members: string[]): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

// ──────────────────────────────────────────────────────────────────────────────
// Redis implementation
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Redis-backed registry.  Each entry is stored as:
 *
 *   `HSET <keyPrefix>:<did>  data  <JSON blob>`
 *
 * and the DID is tracked in the index set:
 *
 *   `SADD <indexKey>  <did>`
 *
 * so `list()` can enumerate all DIDs with a single `SMEMBERS` call.
 */
export class RedisPartnerDidRegistry implements PartnerDidRegistry {
  private readonly client: RegistryRedisClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly indexKey: string;
  private readonly onError?: () => void;

  constructor(
    client: RegistryRedisClient,
    logger: Logger,
    options: {
      keyPrefix?: string;
      onError?: () => void;
    } = {},
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'euno:gateway:partner-did';
    this.indexKey = `${this.keyPrefix}:index`;
    this.onError = options.onError;

    this.client.on('error', (err: unknown) => {
      this.logger.error('RedisPartnerDidRegistry Redis error', {
        error: err instanceof Error ? err.message : String(err),
      });
      this.onError?.();
    });
  }

  private entryKey(did: string): string {
    return `${this.keyPrefix}:${did}`;
  }

  private async readEntry(did: string): Promise<PartnerDidEntry | undefined> {
    try {
      const raw = await this.client.hget(this.entryKey(did), 'data');
      if (!raw) return undefined;
      return JSON.parse(raw) as PartnerDidEntry;
    } catch (err) {
      this.logger.error('RedisPartnerDidRegistry: failed to read entry', {
        did,
        error: err instanceof Error ? err.message : 'unknown error',
      });
      this.onError?.();
      return undefined;
    }
  }

  private async writeEntry(entry: PartnerDidEntry): Promise<void> {
    try {
      await this.client.hset(this.entryKey(entry.did), 'data', JSON.stringify(entry));
      await this.client.sadd(this.indexKey, entry.did);
    } catch (err) {
      this.logger.error('RedisPartnerDidRegistry: failed to write entry', {
        did: entry.did,
        error: err instanceof Error ? err.message : 'unknown error',
      });
      this.onError?.();
      throw err;
    }
  }

  async trusts(did: string): Promise<boolean> {
    const entry = await this.readEntry(did);
    if (!entry || entry.status !== 'active') return false;
    const now = Date.now();
    if (entry.notBefore !== undefined && now < entry.notBefore) return false;
    if (entry.notAfter !== undefined && now > entry.notAfter) return false;
    return true;
  }

  async get(did: string): Promise<PartnerDidEntry | undefined> {
    return this.readEntry(did);
  }

  async propose(
    entry: Omit<PartnerDidEntry, 'status' | 'proposedAt'>,
  ): Promise<PartnerDidEntry> {
    const existing = await this.readEntry(entry.did);
    if (existing && (existing.status === 'active' || existing.status === 'proposed')) {
      throw new Error(
        `Partner DID ${entry.did} already exists with status '${existing.status}'`,
      );
    }
    const newEntry: PartnerDidEntry = {
      ...entry,
      // Always store pinnedDocSha256 in lowercase so hash comparisons are
      // unambiguous regardless of the case the proposer supplied.
      ...(entry.pinnedDocSha256 !== undefined
        ? { pinnedDocSha256: entry.pinnedDocSha256.toLowerCase() }
        : {}),
      status: 'proposed',
      proposedAt: Date.now(),
    };
    await this.writeEntry(newEntry);
    return newEntry;
  }

  async approve(
    did: string,
    approver: string,
    pinOverrides?: Partial<Pick<PartnerDidEntry, 'pinnedDocSha256' | 'pinnedVerificationKeys' | 'pinAttestation'>>,
  ): Promise<PartnerDidEntry> {
    const entry = await this.readEntry(did);
    if (!entry) throw new Error(`Partner DID not found: ${did}`);
    if (entry.status !== 'proposed') {
      throw new Error(
        `Partner DID ${did} cannot be approved: current status is '${entry.status}'`,
      );
    }
    if (approver === entry.proposer) {
      throw new TwoEyesViolationError(
        `Two-eyes violation: approver '${approver}' is the same as proposer`,
        did,
        approver,
      );
    }
    // Normalize pinnedDocSha256 to lowercase regardless of source.
    const effectivePin = pinOverrides?.pinnedDocSha256 ?? entry.pinnedDocSha256;
    const updated: PartnerDidEntry = {
      ...entry,
      ...(pinOverrides ?? {}),
      ...(effectivePin !== undefined ? { pinnedDocSha256: effectivePin.toLowerCase() } : {}),
      status: 'active',
      approver,
      activatedAt: Date.now(),
    };
    await this.writeEntry(updated);
    return updated;
  }

  async revoke(did: string, _revokedBy: string): Promise<PartnerDidEntry> {
    const entry = await this.readEntry(did);
    if (!entry) throw new Error(`Partner DID not found: ${did}`);
    const updated: PartnerDidEntry = {
      ...entry,
      status: 'revoked',
      revokedAt: Date.now(),
    };
    await this.writeEntry(updated);
    return updated;
  }

  async list(statusFilter?: PartnerDidStatus): Promise<PartnerDidEntry[]> {
    try {
      const dids = await this.client.smembers(this.indexKey);
      const entries = await Promise.all(dids.map((did) => this.readEntry(did)));
      const valid = entries.filter((e): e is PartnerDidEntry => e !== undefined);
      return statusFilter ? valid.filter((e) => e.status === statusFilter) : valid;
    } catch (err) {
      this.logger.error('RedisPartnerDidRegistry: failed to list entries', {
        error: err instanceof Error ? err.message : String(err),
      });
      this.onError?.();
      return [];
    }
  }

  async seed(dids: string[]): Promise<void> {
    for (const did of dids) {
      const existing = await this.readEntry(did);
      if (!existing) {
        await this.writeEntry({
          did,
          status: 'active',
          proposer: 'env:TRUSTED_PARTNER_DIDS',
          approver: 'env:TRUSTED_PARTNER_DIDS',
          proposedAt: Date.now(),
          activatedAt: Date.now(),
        });
      }
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Secondary-resolver fetch helper
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Fetch the body at `url` and return it as a parsed JSON value.
 * Uses the built-in `https`/`http` module to avoid pulling extra deps.
 * Throws on non-200 status, network error, JSON parse failure, timeout,
 * or body exceeding `maxBytes`.
 *
 * @param url - The URL to fetch.
 * @param options.timeoutMs - Request timeout in milliseconds (default 5 000 ms).
 * @param options.maxBytes - Maximum body size in bytes (default 1 MiB = 1 048 576 bytes).
 *
 * @internal Exported for unit tests.
 */
export function fetchJson(
  url: string,
  options: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<unknown> {
  const { timeoutMs = 5_000, maxBytes = 1_048_576 } = options;

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const mod = url.startsWith('https://') ? https : http;
    const req = mod.get(url, (res) => {
      if (res.statusCode !== 200) {
        done(() => reject(new Error(`Secondary resolver fetch returned HTTP ${res.statusCode} for ${url}`)));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      res.on('data', (c: Buffer) => {
        totalBytes += c.length;
        if (totalBytes > maxBytes) {
          done(() =>
            reject(
              new Error(
                `Secondary resolver response from ${url} exceeded size limit (${maxBytes} bytes)`,
              ),
            ),
          );
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        try {
          done(() => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
        } catch (e) {
          done(() => reject(new Error(`Secondary resolver response at ${url} is not valid JSON: ${String(e)}`)));
        }
      });
      res.on('error', (err) => done(() => reject(err)));
    });
    req.on('error', (err) => done(() => reject(err)));
    // Apply request timeout — destroy the socket so the request fails
    // immediately rather than hanging indefinitely.
    req.setTimeout(timeoutMs, () => {
      done(() =>
        reject(new Error(`Secondary resolver request to ${url} timed out after ${timeoutMs}ms`)),
      );
      req.destroy();
    });
    req.end();
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// Factory
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Options accepted by {@link createPartnerDidRegistryFromEnv}.
 */
export interface RegistryFromEnvOptions {
  /**
   * When true, a missing `pinnedDocSha256` on any entry is treated as a hard
   * error at seed / propose time (enforces pin discipline for new entries).
   * Plumbed from `PARTNER_DID_REQUIRE_PIN`.
   */
  requirePin?: boolean;
  /**
   * Override the "is TRUSTED_PARTNER_DIDS allowed?" decision.
   *
   *   - `true`  — hard startup error when `TRUSTED_PARTNER_DIDS` is set.
   *   - `false` — warn but continue (legacy / explicit opt-out in production).
   *   - `undefined` (default) — auto-determined: production defaults to `true`
   *     (read env `PARTNER_DID_REGISTRY_REQUIRED !== 'false'`); non-production
   *     defaults to `false` (read env `PARTNER_DID_REGISTRY_REQUIRED === 'true'`).
   *
   * Plumbed from `PARTNER_DID_REGISTRY_REQUIRED`.
   */
  registryRequired?: boolean;
  /**
   * Redis key prefix override.  Plumbed from `PARTNER_DID_REGISTRY_KEY_PREFIX`.
   */
  keyPrefix?: string;
  /** Deployment tier — used for Redis ioredis install error escalation. */
  deploymentTier?: string;
  /** Node environment — controls production default for `registryRequired`. */
  nodeEnv?: string;
}

/**
 * Build a {@link PartnerDidRegistry} from environment variables and an
 * optional Redis client.  Mirrors the other `…FromEnv` factory functions.
 *
 * When `TRUSTED_PARTNER_DIDS` is set the factory seeds the registry with
 * those DIDs as `active`+unpinned entries.
 *
 * **Production behaviour (NODE_ENV=production):**  Any use of
 * `TRUSTED_PARTNER_DIDS` is treated as a startup error _unless_
 * `PARTNER_DID_REGISTRY_REQUIRED=false` is explicitly set (conscious opt-out).
 * This prevents a config-map redeploy from silently bypassing the two-eyes
 * approval workflow in production.
 *
 * **Non-production behaviour:** `TRUSTED_PARTNER_DIDS` emits a deprecation
 * warning unless `PARTNER_DID_REGISTRY_REQUIRED=true` is set (hard error).
 *
 * The function is **async** so that Redis-backed seed entries can be
 * fully written before the gateway begins serving requests (avoiding the
 * startup race where requests arrive before seeded DIDs are persisted).
 *
 * When `redis` is `undefined` and `REDIS_URL` is set, the factory
 * creates its own ioredis connection for the registry, mirroring the
 * behaviour of `createRevocationStoreFromEnv`.
 */
export async function createPartnerDidRegistryFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  redis?: RegistryRedisClient,
  opts: RegistryFromEnvOptions = {},
): Promise<InMemoryPartnerDidRegistry | RedisPartnerDidRegistry> {
  const {
    requirePin = env.PARTNER_DID_REQUIRE_PIN === 'true',
    keyPrefix = env.PARTNER_DID_REGISTRY_KEY_PREFIX,
    deploymentTier = env.EUNO_DEPLOYMENT_TIER,
    nodeEnv = env.NODE_ENV,
  } = opts;

  // In production, default to requiring the registry (blocking TRUSTED_PARTNER_DIDS).
  // An operator who consciously wants the env-var bypass in production must set
  // PARTNER_DID_REGISTRY_REQUIRED=false explicitly.  Outside production the default
  // is the legacy warning-only behaviour; set PARTNER_DID_REGISTRY_REQUIRED=true
  // to turn it into an error.
  const isProduction = nodeEnv === 'production';
  const registryRequired = opts.registryRequired !== undefined
    ? opts.registryRequired
    : (isProduction
        ? env.PARTNER_DID_REGISTRY_REQUIRED !== 'false'   // production: default TRUE (opt-out)
        : env.PARTNER_DID_REGISTRY_REQUIRED === 'true');  // non-prod: default false (opt-in)

  // Build the backing store.
  // Prefer an explicitly-supplied client; otherwise auto-create from REDIS_URL
  // (same lazy-ioredis pattern as createRevocationStoreFromEnv).
  let redisClient: RegistryRedisClient | undefined = redis;
  if (!redisClient && env.REDIS_URL) {
    let RedisCtor: unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      RedisCtor = require('ioredis');
    } catch (err) {
      const isProductionOrMultiReplica =
        isProduction ||
        (deploymentTier && deploymentTier !== 'single-replica');
      const detail = err instanceof Error ? err.message : 'unknown error';
      if (isProductionOrMultiReplica) {
        throw new Error(
          'REDIS_URL is set but the "ioredis" package is not installed. ' +
          'Install it (npm install ioredis) to enable the distributed partner-DID registry. ' +
          `Original error: ${detail}`,
        );
      }
      logger.error(
        'REDIS_URL is set but ioredis is not installed; partner-DID registry will use in-memory store. ' +
        'Registry writes will not propagate across replicas.',
        { error: detail },
      );
    }
    if (RedisCtor) {
      const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
      redisClient = new (Ctor as new (url: string, opts?: unknown) => RegistryRedisClient)(
        env.REDIS_URL,
        {
          retryStrategy: (times: number) => Math.min(times * 50, 2000),
          maxRetriesPerRequest: 3,
          lazyConnect: false,
        },
      );
      logger.info('Partner-DID registry using Redis', { keyPrefix: keyPrefix ?? 'euno:gateway:partner-did' });
    }
  }

  const registry: InMemoryPartnerDidRegistry | RedisPartnerDidRegistry = redisClient
    ? new RedisPartnerDidRegistry(redisClient, logger, { keyPrefix, onError: undefined })
    : new InMemoryPartnerDidRegistry();

  // Seed from TRUSTED_PARTNER_DIDS if set.
  const rawDids = env.TRUSTED_PARTNER_DIDS;
  if (rawDids) {
    const dids = rawDids
      .split(',')
      .map((d) => d.trim())
      .filter((d) => d.length > 0);

    if (dids.length > 0) {
      if (registryRequired) {
        const optOutInstructions = isProduction
          ? 'Set PARTNER_DID_REGISTRY_REQUIRED=false to opt out (production only, not recommended).'
          : 'Remove TRUSTED_PARTNER_DIDS and use the partner-DID registry admin API instead.';
        throw new Error(
          'TRUSTED_PARTNER_DIDS is set but the partner-DID registry is required. ' +
          'This env-var bypass has no pin, no two-eyes approval, and no audit trail — ' +
          'a config-map change can silently add an untrusted issuer without operator review. ' +
          optOutInstructions,
        );
      }

      const msg =
        'TRUSTED_PARTNER_DIDS is set and seeded into the partner-DID registry as unpinned active ' +
        'entries. This env-var bypass has no pin, no two-eyes approval, and no audit trail. ' +
        'Migrate to the registry admin API (POST /admin/partner-dids/proposals) and remove ' +
        'TRUSTED_PARTNER_DIDS. In production, set PARTNER_DID_REGISTRY_REQUIRED=false ' +
        'only as a temporary transition measure.';

      logger.warn(msg);

      // Await the seed so all entries are persisted before the gateway
      // starts serving requests (prevents the startup race on the Redis path).
      await registry.seed(dids);
    }
  }

  void requirePin; // enforced at proposal time in admin-api, not the registry itself
  return registry;
}

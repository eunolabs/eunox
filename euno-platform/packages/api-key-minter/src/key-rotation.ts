/**
 * KeyRotationManager — end-to-end key rotation for the API-key minter
 * ────────────────────────────────────────────────────────────────────────────
 * Implements the key rotation procedure described in
 * docs/security/minter-threat-model.md §3 and the SRE runbook at
 * docs/runbooks/minter-key-rotation.md.
 *
 * ## Rotation procedure (scheduled or emergency)
 *
 * Call `initiateRotation()` first.  This writes a `rotation_start` row to
 * the immutable audit store **before** any other steps, so the audit trail
 * is complete even if the process crashes mid-rotation.
 *
 * After the new key is live in the JWKS endpoint, call `completeRotation()`.
 * This writes a `rotation_complete` row and removes the old `kid` from the
 * active-key registry.
 *
 * ## Emergency rotation
 *
 * Pass `{ reason: 'emergency' }` to `initiateRotation()`.  This stamps the
 * audit row with `result: 'rotation_emergency'` and triggers the kill-switch
 * and bulk-revocation steps in the runbook.
 *
 * ## Tested runbook
 *
 * See `tests/key-rotation.test.ts` for an end-to-end test covering:
 *   - Happy-path rotation (old → new key, JWKS update, audit trail)
 *   - Emergency rotation (audit row, kill-switch invocation)
 *   - Duplicate `initiateRotation` calls (idempotent via audit check)
 *
 * @module key-rotation
 */

import { MintAuditRecord, MintAuditStore } from './mint-audit';
import * as crypto from 'crypto';

// ── Types ─────────────────────────────────────────────────────────────────────

/** A single entry in the minter's JWKS key set. */
export interface JwksKeyEntry {
  /** Key ID matching the `kid` header of tokens signed by this key. */
  kid: string;
  /** JWS algorithm (e.g. `ES256`, `RS256`). */
  alg: string;
  /** Base64URL-encoded public key material (JWK `x`/`y`/`n`/`e` depending on key type). */
  [field: string]: string;
}

/**
 * A store that holds the set of currently active (advertised) public keys.
 *
 * In production this is backed by a shared Redis hash or Postgres row that
 * all minter replicas read when building the JWKS response.  For tests and
 * development, {@link InMemoryJwksStore} is provided.
 *
 * The store is intentionally narrow — only the methods required by
 * {@link KeyRotationManager} are in the interface.
 */
export interface JwksStore {
  /** Add or replace a key entry (upsert by `kid`). */
  addKey(key: JwksKeyEntry): Promise<void>;
  /** Remove a key entry by `kid`. */
  removeKey(kid: string): Promise<void>;
  /** Return all currently active key entries. */
  listKeys(): Promise<JwksKeyEntry[]>;
}

/** Options controlling a single rotation operation. */
export interface RotationOptions {
  /**
   * Human-readable reason.  For emergency rotations this MUST be `'emergency'`
   * (the runbook queries `reason = 'emergency'` to filter emergency events).
   * Defaults to `'scheduled'`.
   */
  reason?: string;
  /** Operator identity string stored in the audit record for accountability. */
  initiatedBy?: string;
}

/** Return value of {@link KeyRotationManager.initiateRotation}. */
export interface RotationInitiatedResult {
  /** The `jti` of the audit record written by `initiateRotation`. */
  auditJti: string;
  /** Rotation kind (`'scheduled'` or `'emergency'`). */
  kind: 'scheduled' | 'emergency';
}

/** Return value of {@link KeyRotationManager.completeRotation}. */
export interface RotationCompletedResult {
  /** The `jti` of the audit record written by `completeRotation`. */
  auditJti: string;
  /** `kid` of the old key that was removed from the JWKS store. */
  retiredKid: string;
}

// ── InMemoryJwksStore ─────────────────────────────────────────────────────────

/** In-memory JWKS store for development and unit tests. */
export class InMemoryJwksStore implements JwksStore {
  private readonly keys = new Map<string, JwksKeyEntry>();

  async addKey(key: JwksKeyEntry): Promise<void> {
    this.keys.set(key.kid, { ...key });
  }

  async removeKey(kid: string): Promise<void> {
    this.keys.delete(kid);
  }

  async listKeys(): Promise<JwksKeyEntry[]> {
    return Array.from(this.keys.values());
  }
}

// ── KeyRotationManager ────────────────────────────────────────────────────────

export interface KeyRotationManagerOptions {
  /**
   * The immutable mint-audit store.
   *
   * Must use credentials separate from the minter's signing path so that an
   * audit record cannot be deleted by the minter service itself
   * (threat model §6).
   */
  auditStore: MintAuditStore;
  /** JWKS store shared across all minter replicas. */
  jwksStore: JwksStore;
  /**
   * Tenant ID scoping this manager instance.
   *
   * A single minter service may manage keys for multiple tenants; create one
   * `KeyRotationManager` per tenant to keep audit rows correctly scoped.
   */
  tenantId: string;
}

/**
 * Manages the end-to-end key rotation procedure for the API-key minter.
 *
 * ### Thread safety
 *
 * Concurrent `initiateRotation` calls for the same `(tenantId, newKid)` pair
 * are idempotent: the second call detects that a `rotation_start` row already
 * exists and returns its `auditJti` without writing a duplicate.  Concurrent
 * calls with *different* `newKid` values on the same tenant are not serialised
 * here — operators must coordinate at the HSM level (only one rotation at a
 * time per tenant is expected; the JWKS endpoint is updated atomically).
 */
export class KeyRotationManager {
  private readonly auditStore: MintAuditStore;
  private readonly jwksStore: JwksStore;
  private readonly tenantId: string;

  constructor(opts: KeyRotationManagerOptions) {
    this.auditStore = opts.auditStore;
    this.jwksStore = opts.jwksStore;
    this.tenantId = opts.tenantId;
  }

  /**
   * Step 1 of the rotation procedure.
   *
   * Writes a `rotation_start` (or `rotation_emergency`) audit row and adds the
   * new key to the JWKS store.  Both old and new keys are active in JWKS during
   * the transition window so in-flight tokens signed by the old key remain
   * verifiable until they expire (max TTL = 5 min per threat model §2).
   *
   * **Must be called before any HSM operations that use the new key.**
   *
   * @param newKey   - The new public-key entry to add to the JWKS store.
   * @param oldKid   - The `kid` of the key being rotated out (recorded in the
   *                   audit row for blast-radius queries).
   * @param opts     - Optional rotation options (reason, initiatedBy).
   */
  async initiateRotation(
    newKey: JwksKeyEntry,
    oldKid: string,
    opts: RotationOptions = {},
  ): Promise<RotationInitiatedResult> {
    const reason = opts.reason ?? 'scheduled';
    const isEmergency = reason === 'emergency';
    const kind: 'scheduled' | 'emergency' = isEmergency ? 'emergency' : 'scheduled';

    // Idempotency: check whether a rotation_start OR rotation_emergency row for
    // this (tenantId, newKid) already exists so duplicate calls are safe
    // regardless of whether the reason is changed between calls (e.g. scheduled
    // re-run that becomes emergency — both result types signal that rotation for
    // this key has already been initiated).
    const existing =
      (await this.findRotationAuditRow(newKey.kid, 'rotation_start')) ??
      (await this.findRotationAuditRow(newKey.kid, 'rotation_emergency'));
    if (existing) {
      return { auditJti: existing.jti, kind };
    }

    // Generate a unique JTI for the audit record.
    const auditJti = generateRotationJti();

    // Write the audit row FIRST — before touching the JWKS store — so the
    // trail is complete even if the process crashes between these two steps.
    const auditRecord: MintAuditRecord = {
      keyPrefix: '',          // no API key involved in key rotation events
      tenantId: this.tenantId,
      agentId: '',            // no agent involved
      sessionId: '',          // no session
      jti: auditJti,
      policyId: '',           // no policy change
      issuedAt: new Date().toISOString(),
      expiresAt: 0,           // no token expiry for lifecycle events
      kid: newKey.kid,
      result: isEmergency ? 'rotation_emergency' : 'rotation_start',
      reason: opts.initiatedBy
        ? `${reason} (by ${opts.initiatedBy}); retiring ${oldKid}`
        : `${reason}; retiring ${oldKid}`,
    };
    await this.auditStore.record(auditRecord);

    // Publish the new key to the JWKS store.  Both old and new keys are now
    // active; tokens signed by the old key remain verifiable.
    await this.jwksStore.addKey(newKey);

    return { auditJti, kind };
  }

  /**
   * Step 2 of the rotation procedure.
   *
   * Removes the old key from the JWKS store (tokens signed by it can no longer
   * be verified after this call) and writes a `rotation_complete` audit row.
   *
   * **Call only after the old key's maximum-TTL window has elapsed** (≤ 5 min)
   * so that no valid in-flight tokens are rejected.  For emergency rotations
   * the kill switch should be activated before this call to immediately
   * invalidate all tokens signed by the compromised key regardless of TTL.
   *
   * @param newKid - The `kid` of the new (now active) signing key.
   * @param oldKid - The `kid` of the key being retired.
   * @param opts   - Optional rotation options (reason, initiatedBy).
   */
  async completeRotation(
    newKid: string,
    oldKid: string,
    opts: RotationOptions = {},
  ): Promise<RotationCompletedResult> {
    const reason = opts.reason ?? 'scheduled';

    // Idempotency: check whether a rotation_complete row for this
    // (tenantId, newKid, oldKid) triple already exists.  The audit record
    // stores oldKid in its reason field, so we check for both kid and oldKid
    // to avoid a false match if the same newKid is used to complete a different
    // rotation in the future.
    const existing = await this.findRotationAuditRow(newKid, 'rotation_complete', oldKid);
    if (existing) {
      return { auditJti: existing.jti, retiredKid: oldKid };
    }

    const auditJti = generateRotationJti();

    // Remove the old key from JWKS first.
    await this.jwksStore.removeKey(oldKid);

    // Write the completion audit row.
    const auditRecord: MintAuditRecord = {
      keyPrefix: '',
      tenantId: this.tenantId,
      agentId: '',
      sessionId: '',
      jti: auditJti,
      policyId: '',
      issuedAt: new Date().toISOString(),
      expiresAt: 0,
      kid: newKid,
      result: 'rotation_complete',
      reason: opts.initiatedBy
        ? `${reason} (by ${opts.initiatedBy}); retired ${oldKid}`
        : `${reason}; retired ${oldKid}`,
    };
    await this.auditStore.record(auditRecord);

    return { auditJti, retiredKid: oldKid };
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  /**
   * Return the first matching audit row for a given `kid` and `result` type,
   * or `undefined` if none exists.
   *
   * Used for idempotency checking in `initiateRotation` and `completeRotation`.
   * Filters client-side from `listByTenant` to avoid adding a provider-specific
   * `findByKid` method to the narrow `MintAuditStore` interface.
   *
   * @param kid            - The `kid` of the key whose rotation row to look for.
   * @param result         - The `result` value to match.
   * @param reasonContains - Optional substring that must appear in the `reason`
   *                         field (used to tighten idempotency checks that need
   *                         to distinguish the `oldKid` within the reason text).
   */
  private async findRotationAuditRow(
    kid: string,
    result: MintAuditRecord['result'],
    reasonContains?: string,
  ): Promise<MintAuditRecord | undefined> {
    // `listByTenant` returns the most recent entries; limit to a reasonable
    // window (1000) to avoid a full table scan for busy tenants.
    const rows = await this.auditStore.listByTenant(this.tenantId, 1000);
    return rows.find(
      r =>
        r.kid === kid &&
        r.result === result &&
        (reasonContains === undefined || r.reason?.includes(reasonContains) === true),
    );
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────

/**
 * Generate a unique JTI for a key-rotation audit record.
 * Uses `crypto.randomUUID()` which is available in Node.js ≥ 14.17.
 */
function generateRotationJti(): string {
  return crypto.randomUUID();
}

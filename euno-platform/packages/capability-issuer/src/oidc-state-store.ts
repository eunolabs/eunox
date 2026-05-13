/**
 * OIDC State Store — nonce management and authorization-code replay prevention.
 *
 * Two independent responsibilities are handled here:
 *
 * 1. **Nonce tracking** (`pendingStates`): The issuer generates a `state` +
 *    `nonce` pair when it redirects a user to the upstream IdP
 *    (`GET /api/v1/oidc/authorize`). When the authorization code comes back
 *    via `POST /api/v1/oidc/token`, the nonce stored against the state is
 *    retrieved and compared to the `nonce` claim in the IdP's ID token.
 *    This confirms the ID token was issued in response to *this* authorization
 *    request and has not been recycled from a different session.
 *
 * 2. **ID-token-hash replay prevention** (`usedIdTokenHashes`): Before any
 *    remote IdP validation the issuer computes a SHA-256 hash of the submitted
 *    `idToken` string and marks it as used **eagerly** (fail-closed). Any
 *    subsequent attempt to submit the same token within the TTL window is
 *    rejected, even if the first attempt failed at the IdP or issuance stage.
 *    This is required by the Stage-4 threat model (§5, row "IdP-token replay
 *    against the issuer"). Using the token hash rather than a caller-supplied
 *    `code` field prevents bypassing the check with a fresh, arbitrary code.
 *
 * Both stores are **in-memory**. For multi-replica deployments the stores
 * should be backed by a shared Redis instance (a future improvement); the
 * single-replica in-memory implementation is sufficient for Stage-4 and
 * production-safe for single-replica self-host deployments.
 *
 * Entries expire after `codeTtlSeconds` (default 600 s, matching the default
 * maximum authorization-code lifetime of most IdPs). A lightweight sweep is
 * triggered on every write to avoid unbounded memory growth.
 */

import crypto from 'crypto';

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
// OidcStateStore
// ---------------------------------------------------------------------------

/**
 * In-memory store for OIDC state/nonce pairs and used authorization codes.
 */
export class OidcStateStore {
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
   *   the used-code log. Defaults to 600 (10 minutes).
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
  // Authorization-code replay prevention
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

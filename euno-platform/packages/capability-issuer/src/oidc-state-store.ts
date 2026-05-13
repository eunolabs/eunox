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
 * 2. **Authorization-code replay prevention** (`usedCodes`): After the issuer
 *    exchanges an authorization code for tokens it marks that code as "used".
 *    Any subsequent attempt to exchange the same code within the TTL window is
 *    rejected. This is required by the Stage-4 threat model (§5, row
 *    "IdP-token replay against the issuer").
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
   * Used authorization codes. The value is the expiry timestamp (ms).
   * Re-submission of a code whose entry is still present is rejected.
   */
  private readonly usedCodes = new Map<string, number>();

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
   * Returns `true` if the code has already been used within the current TTL
   * window, `false` otherwise. **Does not** mark the code as used.
   */
  isCodeUsed(code: string): boolean {
    const expiry = this.usedCodes.get(code);
    if (expiry === undefined) return false;
    if (expiry <= Date.now()) {
      this.usedCodes.delete(code);
      return false;
    }
    return true;
  }

  /**
   * Mark `code` as used. Subsequent calls to {@link isCodeUsed} with the same
   * code will return `true` until the TTL expires.
   *
   * Call this **after** a successful code exchange with the IdP, not before —
   * if the exchange fails the code should remain available for a retry (IdP
   * network hiccup, etc.).
   */
  markCodeUsed(code: string): void {
    this.sweep();
    this.usedCodes.set(code, Date.now() + this.codeTtlSeconds * 1000);
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
    for (const [k, expiry] of this.usedCodes) {
      if (expiry <= now) this.usedCodes.delete(k);
    }
  }

  /** Current number of pending (unconsumed) state entries — useful in tests. */
  get pendingStateCount(): number {
    return this.pendingStates.size;
  }

  /** Current number of used-code entries — useful in tests. */
  get usedCodeCount(): number {
    return this.usedCodes.size;
  }
}

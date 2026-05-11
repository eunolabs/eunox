/**
 * Outcome written to `mint_audit.result` for each row.
 *
 * - `'minted'`             — normal capability token issuance.
 * - `'rotation_start'`     — a key rotation has been initiated; written before
 *                            any other rotation steps so the audit trail is
 *                            complete even on process crash.
 * - `'rotation_complete'`  — all rotation steps succeeded and the old key has
 *                            been removed from the JWKS endpoint.
 * - `'rotation_emergency'` — emergency key rotation (compromise response).
 *
 * Query hint: `WHERE result IN ('rotation_start','rotation_complete','rotation_emergency')`
 * returns all key-lifecycle events for offline auditing.
 */
export type MintAuditResult =
  | 'minted'
  | 'rotation_start'
  | 'rotation_complete'
  | 'rotation_emergency';

export interface MintAuditRecord {
  id?: number;
  keyPrefix: string;
  tenantId: string;
  agentId: string;
  sessionId: string;
  jti: string;
  policyId: string;
  issuedAt: string;    // ISO-8601
  expiresAt: number;   // unix seconds
  /**
   * Key ID (`kid`) of the signing key used for this mint.
   *
   * Required for blast-radius enumeration on key compromise
   * (see docs/security/minter-threat-model.md §2–3):
   * `SELECT * FROM mint_audit WHERE kid = $compromised_kid`.
   */
  kid: string;
  /**
   * Audit record type.  Defaults to `'minted'` for normal token issuances.
   * Key-rotation lifecycle events use `'rotation_start'` / `'rotation_complete'`
   * / `'rotation_emergency'`.
   */
  result?: MintAuditResult;
  /**
   * Free-text reason for the event.
   * For rotation events: `'scheduled'`, `'emergency'`, or a custom message.
   * For normal mints: omitted.
   */
  reason?: string;
}

export interface MintAuditStore {
  record(entry: MintAuditRecord): Promise<void>;
  listByTenant(tenantId: string, limit?: number): Promise<MintAuditRecord[]>;
}

export class InMemoryMintAuditStore implements MintAuditStore {
  private readonly entries: MintAuditRecord[] = [];

  async record(entry: MintAuditRecord): Promise<void> {
    this.entries.push({ ...entry, id: this.entries.length + 1 });
  }

  async listByTenant(tenantId: string, limit = 100): Promise<MintAuditRecord[]> {
    return this.entries
      .filter(e => e.tenantId === tenantId)
      .slice(-limit);
  }

  getAll(): MintAuditRecord[] {
    return [...this.entries];
  }
}

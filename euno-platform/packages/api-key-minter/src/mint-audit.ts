export interface MintAuditRecord {
  id?: number;
  keyPrefix: string;
  tenantId: string;
  agentId: string;
  sessionId: string;
  jti: string;
  policyId: string;
  issuedAt: string;   // ISO-8601
  expiresAt: number;  // unix seconds
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

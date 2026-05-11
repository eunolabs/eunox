import { CapabilityConstraint } from '@euno/common';
import { API_KEY_DUMMY_PREFIX } from './api-key';

export interface ApiKeyRecord {
  id?: number;
  prefix: string;
  keyDigest: string;       // base64url(HMAC-SHA256(pepper, secret))
  hmacKeyVersion: string;
  tenantId: string;
  policyId: string;
  capabilities: CapabilityConstraint[];
  scopes: string[];
  label?: string;
  createdAt: string;       // ISO-8601
  lastUsedAt?: string;
  expiresAt?: string;
  revokedAt?: string;
}

export interface CreateApiKeyInput {
  tenantId: string;
  policyId: string;
  capabilities: CapabilityConstraint[];
  scopes: string[];
  label?: string;
  expiresAt?: string;
}

export interface ApiKeyStore {
  createKey(record: ApiKeyRecord): Promise<void>;
  getByPrefix(prefix: string): Promise<ApiKeyRecord | undefined>;
  getDummyRecord(): Promise<ApiKeyRecord>;
  updateLastUsedAt(prefix: string, timestamp: string): Promise<void>;
  revokeKey(prefix: string): Promise<void>;
  listByTenant(tenantId: string): Promise<ApiKeyRecord[]>;
}

export class InMemoryApiKeyStore implements ApiKeyStore {
  private readonly records = new Map<string, ApiKeyRecord>();
  private readonly dummy: ApiKeyRecord;

  constructor() {
    this.dummy = {
      prefix: API_KEY_DUMMY_PREFIX,
      keyDigest: Buffer.alloc(32).toString('base64url'),
      hmacKeyVersion: 'dummy',
      tenantId: '',
      policyId: '',
      capabilities: [],
      scopes: [],
      createdAt: new Date().toISOString(),
    };
  }

  async createKey(record: ApiKeyRecord): Promise<void> {
    this.records.set(record.prefix, { ...record });
  }

  async getByPrefix(prefix: string): Promise<ApiKeyRecord | undefined> {
    return this.records.get(prefix);
  }

  async getDummyRecord(): Promise<ApiKeyRecord> {
    return this.dummy;
  }

  async updateLastUsedAt(prefix: string, timestamp: string): Promise<void> {
    const record = this.records.get(prefix);
    if (record) {
      record.lastUsedAt = timestamp;
    }
  }

  async revokeKey(prefix: string): Promise<void> {
    const record = this.records.get(prefix);
    if (record) {
      record.revokedAt = new Date().toISOString();
    }
  }

  async listByTenant(tenantId: string): Promise<ApiKeyRecord[]> {
    return Array.from(this.records.values()).filter(r => r.tenantId === tenantId);
  }
}

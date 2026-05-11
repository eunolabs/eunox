import * as crypto from 'crypto';
import { CapabilityError, ErrorCode, CapabilityConstraint, createLogger } from '@euno/common';
import { ApiKeyRecord, ApiKeyStore } from './api-key-store';
import { parseApiKey, API_KEY_DUMMY_PREFIX } from './api-key';

export interface PepperEntry {
  version: string;
  key: Buffer;
}

export interface ApiKeyVerifierOptions {
  store: ApiKeyStore;
  peppers: PepperEntry[];
  logger?: ReturnType<typeof createLogger>;
}

export interface VerifiedApiKey {
  tenantId: string;
  policyId: string;
  capabilities: CapabilityConstraint[];
  scopes: string[];
  prefix: string;
}

export class ApiKeyVerifier {
  private readonly dummyDigest: Buffer;

  constructor(private readonly opts: ApiKeyVerifierOptions) {
    this.dummyDigest = crypto.randomBytes(32);
  }

  async verify(raw: string): Promise<VerifiedApiKey> {
    // Step 1: parse format (throws 401 on invalid format)
    const parsed = parseApiKey(raw);

    // Step 2: fetch both the real row and the dummy row in parallel
    const [realRow, dummyRow] = await Promise.all([
      this.opts.store.getByPrefix(parsed.prefix),
      this.opts.store.getByPrefix(API_KEY_DUMMY_PREFIX),
    ]);

    // Step 3: pick the row to compare against (real or dummy)
    const row: ApiKeyRecord = realRow ?? (dummyRow ?? this.buildFallbackDummyRecord());
    const secretBuffer = Buffer.from(parsed.secret, 'utf8');

    // Step 4: compute HMAC for all active peppers (always iterate all to avoid timing leak)
    let matchFound = false;
    for (const pepper of this.opts.peppers) {
    // HMAC-SHA256 with a 256-bit pepper is intentional for API key storage.
    // API keys are high-entropy random values (≥285 bits), not user passwords;
    // PBKDF/bcrypt/scrypt are unnecessary and would add latency without benefit.
    const computed = this.hmac(pepper.key, secretBuffer);
      let stored: Buffer;
      try {
        stored = Buffer.from(row.keyDigest, 'base64url');
        if (stored.length !== 32) stored = this.dummyDigest;
      } catch {
        stored = this.dummyDigest;
      }
      // constant-time compare; matchFound only set when real row exists
      const match =
        stored.length === computed.length &&
        crypto.timingSafeEqual(computed, stored) &&
        row.hmacKeyVersion === pepper.version &&
        realRow !== undefined;
      if (match) matchFound = true;
    }

    // Step 5: reject invalid/revoked/expired
    if (!matchFound || !realRow) {
      throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Invalid API key', 401);
    }
    if (realRow.revokedAt !== undefined) {
      throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'API key has been revoked', 401);
    }
    if (realRow.expiresAt !== undefined && new Date(realRow.expiresAt) < new Date()) {
      throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'API key has expired', 401);
    }

    // Step 6: update last used (fire-and-forget)
    void this.opts.store.updateLastUsedAt(realRow.prefix, new Date().toISOString()).catch(() => { /* ignore */ });

    return {
      tenantId: realRow.tenantId,
      policyId: realRow.policyId,
      capabilities: realRow.capabilities,
      scopes: realRow.scopes,
      prefix: realRow.prefix,
    };
  }

  private hmac(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha256', key).update(data).digest();
  }

  private buildFallbackDummyRecord(): ApiKeyRecord {
    return {
      prefix: API_KEY_DUMMY_PREFIX,
      keyDigest: this.dummyDigest.toString('base64url'),
      hmacKeyVersion: 'dummy',
      tenantId: '',
      policyId: '',
      capabilities: [],
      scopes: [],
      createdAt: new Date().toISOString(),
    };
  }
}

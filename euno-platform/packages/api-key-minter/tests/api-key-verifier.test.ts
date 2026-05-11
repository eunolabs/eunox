import * as crypto from 'crypto';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { generateApiKey, API_KEY_DUMMY_PREFIX } from '../src/api-key';

function makePepper(version = 'v1'): { version: string; key: Buffer } {
  return { version, key: crypto.randomBytes(32) };
}

function computeDigest(pepperKey: Buffer, secret: string): string {
  return crypto.createHmac('sha256', pepperKey).update(secret, 'utf8').digest().toString('base64url');
}

async function setupStore(pepper: { version: string; key: Buffer }) {
  const store = new InMemoryApiKeyStore();
  const { prefix, secret, raw } = generateApiKey();
  const keyDigest = computeDigest(pepper.key, secret);
  await store.createKey({
    prefix,
    keyDigest,
    hmacKeyVersion: pepper.version,
    tenantId: 'tenant-1',
    policyId: 'policy-1',
    capabilities: [],
    scopes: ['enforce'],
    createdAt: new Date().toISOString(),
  });
  return { store, prefix, secret, raw };
}

describe('ApiKeyVerifier', () => {
  it('returns VerifiedApiKey for a valid key', async () => {
    const pepper = makePepper();
    const { store, raw } = await setupStore(pepper);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    const result = await verifier.verify(raw);
    expect(result.tenantId).toBe('tenant-1');
    expect(result.policyId).toBe('policy-1');
    expect(result.scopes).toEqual(['enforce']);
  });

  it('throws 401 for invalid key format', async () => {
    const pepper = makePepper();
    const { store } = await setupStore(pepper);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    await expect(verifier.verify('not-a-key')).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 401 when prefix not found', async () => {
    const pepper = makePepper();
    const { store } = await setupStore(pepper);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    // Generate a fresh key that was never stored
    const { raw } = generateApiKey();
    await expect(verifier.verify(raw)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 401 for wrong secret', async () => {
    const pepper = makePepper();
    const { store, prefix } = await setupStore(pepper);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    // Construct a raw key with the correct prefix but wrong (valid-format) secret
    const wrongSecret = 'A'.repeat(48);
    await expect(verifier.verify(`sk-${prefix}.${wrongSecret}`)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 401 for revoked key', async () => {
    const pepper = makePepper();
    const { store, raw, prefix } = await setupStore(pepper);
    await store.revokeKey(prefix);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    await expect(verifier.verify(raw)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws 401 for expired key', async () => {
    const expPepper = makePepper('v2');
    const expStore = new InMemoryApiKeyStore();
    const newKey = generateApiKey();
    const expDigest = computeDigest(expPepper.key, newKey.secret);
    await expStore.createKey({
      prefix: newKey.prefix,
      keyDigest: expDigest,
      hmacKeyVersion: expPepper.version,
      tenantId: 'tenant-1',
      policyId: 'policy-1',
      capabilities: [],
      scopes: ['enforce'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const expVerifier = new ApiKeyVerifier({ store: expStore, peppers: [expPepper] });
    await expect(expVerifier.verify(newKey.raw)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('correctly uses matching pepper version', async () => {
    const pepperV1 = makePepper('v1');
    const pepperV2 = makePepper('v2');
    const store = new InMemoryApiKeyStore();
    const key = generateApiKey();
    // Store with pepperV2 digest
    const digest = computeDigest(pepperV2.key, key.secret);
    await store.createKey({
      prefix: key.prefix,
      keyDigest: digest,
      hmacKeyVersion: 'v2',
      tenantId: 'tenant-2',
      policyId: 'policy-2',
      capabilities: [],
      scopes: ['read'],
      createdAt: new Date().toISOString(),
    });
    // Verifier with both peppers - v2 should match
    const verifier = new ApiKeyVerifier({ store, peppers: [pepperV1, pepperV2] });
    const result = await verifier.verify(key.raw);
    expect(result.tenantId).toBe('tenant-2');
  });

  it('updateLastUsedAt is called on successful verify', async () => {
    const pepper = makePepper();
    const { store, raw, prefix } = await setupStore(pepper);
    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    await verifier.verify(raw);
    // Give fire-and-forget time to settle
    await new Promise(r => setTimeout(r, 10));
    const record = await store.getByPrefix(prefix);
    expect(record?.lastUsedAt).toBeDefined();
  });

  it('dummy prefix constant is not valid Base58', () => {
    expect(API_KEY_DUMMY_PREFIX).toContain('_');
  });
});

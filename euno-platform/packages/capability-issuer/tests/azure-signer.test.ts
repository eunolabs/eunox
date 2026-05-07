/**
 * Unit tests for AzureKeyVaultSigner — exercises the IssuanceContext
 * integration: key lookup by policyHash, composite `${policyHash}:${audience}`
 * lookup, algorithm detection from the mapped key, and client caching.
 */

import * as jose from 'jose';
import { CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

// ---------------------------------------------------------------------------
// Mock Azure SDK at module level (before importing the signer)
// ---------------------------------------------------------------------------

const mockGetKey = jest.fn();
const mockSign = jest.fn();

jest.mock('@azure/keyvault-keys', () => ({
  KeyClient: jest.fn().mockImplementation(() => ({
    getKey: mockGetKey,
  })),
  CryptographyClient: jest.fn().mockImplementation(() => ({
    sign: mockSign,
  })),
}));

jest.mock('@azure/identity', () => ({
  DefaultAzureCredential: jest.fn().mockImplementation(() => ({})),
  ClientSecretCredential: jest.fn().mockImplementation(() => ({})),
}));

import { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from '../src/azure-signer';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Build a minimal KeyVaultKey-shaped object for a given algorithm. */
async function makeKeyVaultKey(
  opts: { keyName: string; alg: 'RS256' } | { keyName: string; alg: 'ES256' },
): Promise<Record<string, unknown>> {
  if (opts.alg === 'RS256') {
    const { publicKey } = await jose.generateKeyPair('RS256');
    const jwk = await jose.exportJWK(publicKey);
    if (!jwk.n || !jwk.e) throw new Error('RSA JWK must contain n and e components');
    return {
      id: `https://vault.azure.net/keys/${opts.keyName}/1`,
      name: opts.keyName,
      keyType: 'RSA',
      properties: {},
      key: {
        kty: 'RSA',
        n: Buffer.from(jwk.n, 'base64url'),
        e: Buffer.from(jwk.e, 'base64url'),
        crv: undefined,
        x: undefined,
        y: undefined,
      },
    };
  } else {
    const { publicKey } = await jose.generateKeyPair('ES256');
    const jwk = await jose.exportJWK(publicKey);
    if (!jwk.x || !jwk.y) throw new Error('EC JWK must contain x and y coordinates');
    return {
      id: `https://vault.azure.net/keys/${opts.keyName}/1`,
      name: opts.keyName,
      keyType: 'EC',
      properties: {},
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.from(jwk.x, 'base64url'),
        y: Buffer.from(jwk.y, 'base64url'),
        n: undefined,
        e: undefined,
      },
    };
  }
}

const MINIMAL_PAYLOAD = {
  iss: 'did:web:example.com',
  sub: 'agent-1',
  aud: 'tool-gateway',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: 'test-jti',
  schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
  capabilities: [],
};

const BASE_CONFIG: AzureKeyVaultAdapterConfig = {
  type: 'azure-keyvault',
  name: 'test',
  keyVault: {
    vaultUrl: 'https://test-vault.vault.azure.net/',
    keyName: 'default-key',
  },
};

// ---------------------------------------------------------------------------
// Helpers to capture CryptographyClient constructor calls
// ---------------------------------------------------------------------------

beforeEach(() => {
  jest.clearAllMocks();
  // Default sign response
  mockSign.mockResolvedValue({ result: Buffer.alloc(256, 0xab) });
});

// ---------------------------------------------------------------------------
// initialize() — default key
// ---------------------------------------------------------------------------

describe('initialize()', () => {
  it('fetches the default key on first call and skips subsequent calls', async () => {
    const defaultKey = await makeKeyVaultKey({ keyName: 'default-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(defaultKey);

    const signer = new AzureKeyVaultSigner(BASE_CONFIG);
    await signer.initialize();
    await signer.initialize(); // second call must be a no-op

    expect(mockGetKey).toHaveBeenCalledTimes(1);
    expect(mockGetKey).toHaveBeenCalledWith('default-key', undefined);
  });

  it('auto-detects RS256 for an RSA default key', async () => {
    const defaultKey = await makeKeyVaultKey({ keyName: 'default-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(defaultKey);

    const signer = new AzureKeyVaultSigner(BASE_CONFIG);
    await signer.initialize();
    expect(signer.getAlgorithm()).toBe('RS256');
  });
});

// ---------------------------------------------------------------------------
// sign() — fallback to default when no context / no mapping
// ---------------------------------------------------------------------------

describe('sign() — default key fallback', () => {
  async function makeSignerWithDefault() {
    const defaultKey = await makeKeyVaultKey({ keyName: 'default-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(defaultKey);
    const signer = new AzureKeyVaultSigner(BASE_CONFIG);
    await signer.initialize();
    return signer;
  }

  it('signs with the default client when no context is provided', async () => {
    const signer = await makeSignerWithDefault();
    const token = await signer.sign(MINIMAL_PAYLOAD);

    // Only one getKey call (the default key during initialize)
    expect(mockGetKey).toHaveBeenCalledTimes(1);
    // mockSign was called exactly once for the sign operation
    expect(mockSign).toHaveBeenCalledTimes(1);
    expect(token.split('.')).toHaveLength(3);
  });

  it('signs with the default client when context has no mapping in keysByPolicyHash', async () => {
    const signer = new AzureKeyVaultSigner({
      ...BASE_CONFIG,
      keyVault: {
        ...BASE_CONFIG.keyVault,
        keysByPolicyHash: { 'other-hash': 'other-key' },
      },
    });
    const defaultKey = await makeKeyVaultKey({ keyName: 'default-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(defaultKey);
    await signer.initialize();

    await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'unmapped-hash',
      subject: 'agent-1',
      audience: 'tool-gateway',
    });

    // Only default key fetched — no second getKey for the unmapped hash
    expect(mockGetKey).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// sign() — policy-specific key selection
// ---------------------------------------------------------------------------

describe('sign() — policy-specific key via keysByPolicyHash', () => {
  async function makeSignerWithPolicyMap(
    keyMap: Record<string, string>,
  ) {
    const defaultKey = await makeKeyVaultKey({ keyName: 'default-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(defaultKey); // for initialize()

    const signer = new AzureKeyVaultSigner({
      ...BASE_CONFIG,
      keyVault: {
        ...BASE_CONFIG.keyVault,
        keysByPolicyHash: keyMap,
      },
    });
    await signer.initialize();
    return signer;
  }

  it('fetches the mapped key and uses its algorithm (ES256) when policyHash matches', async () => {
    const signer = await makeSignerWithPolicyMap({ 'pol-hash-1': 'policy-key-ec' });

    const policyKey = await makeKeyVaultKey({ keyName: 'policy-key-ec', alg: 'ES256' });
    mockGetKey.mockResolvedValueOnce(policyKey);

    const token = await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'pol-hash-1',
      subject: 'agent-1',
      audience: 'tool-gateway',
    });

    // Two getKey calls: default during initialize + policy key during sign
    expect(mockGetKey).toHaveBeenCalledTimes(2);
    expect(mockGetKey).toHaveBeenLastCalledWith('policy-key-ec');

    // JWT header must advertise ES256 (the mapped key's algorithm)
    const headerJson = JSON.parse(
      Buffer.from(token.split('.')[0]!, 'base64url').toString('utf-8'),
    );
    expect(headerJson.alg).toBe('ES256');
  });

  it('caches the policy-specific client — only one getKey per distinct policyHash', async () => {
    const signer = await makeSignerWithPolicyMap({ 'pol-hash-2': 'cached-key' });

    const policyKey = await makeKeyVaultKey({ keyName: 'cached-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(policyKey);

    // First sign — fetches the policy key
    await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'pol-hash-2',
      subject: 'agent-1',
      audience: 'tool-gateway',
    });
    // Second sign — must use the cached client, no additional getKey call
    await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'pol-hash-2',
      subject: 'agent-1',
      audience: 'tool-gateway',
    });

    // Two calls total: default-key + policy-key-on-first-sign only
    expect(mockGetKey).toHaveBeenCalledTimes(2);
  });

  it('uses the composite "${policyHash}:${audience}" key when present', async () => {
    const signer = await makeSignerWithPolicyMap({
      'pol-hash-3': 'plain-key',
      'pol-hash-3:acme.tool-gateway': 'acme-specific-key',
    });

    const acmeKey = await makeKeyVaultKey({ keyName: 'acme-specific-key', alg: 'ES256' });
    mockGetKey.mockResolvedValueOnce(acmeKey);

    await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'pol-hash-3',
      subject: 'agent-1',
      audience: 'acme.tool-gateway',
    });

    // Should have fetched 'acme-specific-key', not 'plain-key'
    expect(mockGetKey).toHaveBeenLastCalledWith('acme-specific-key');
  });

  it('falls back to the plain policyHash entry when no composite key matches', async () => {
    const signer = await makeSignerWithPolicyMap({
      'pol-hash-4': 'plain-key',
    });

    const plainKey = await makeKeyVaultKey({ keyName: 'plain-key', alg: 'RS256' });
    mockGetKey.mockResolvedValueOnce(plainKey);

    await signer.sign(MINIMAL_PAYLOAD, {
      policyHash: 'pol-hash-4',
      subject: 'agent-1',
      audience: 'other.tool-gateway', // no composite entry for this audience
    });

    expect(mockGetKey).toHaveBeenLastCalledWith('plain-key');
  });
});

/**
 * Unit tests for GCPCloudKMSSigner
 * Mocks the @google-cloud/kms client to avoid real network calls
 */

import * as jose from 'jose';

// ---------------------------------------------------------------------------
// Mock @google-cloud/kms at module level
// ---------------------------------------------------------------------------

const mockGetCryptoKey = jest.fn();
const mockGetPublicKey = jest.fn();
const mockAsymmetricSign = jest.fn();
const mockClose = jest.fn();

jest.mock('@google-cloud/kms', () => ({
  KeyManagementServiceClient: jest.fn().mockImplementation(() => ({
    getCryptoKey: mockGetCryptoKey,
    getPublicKey: mockGetPublicKey,
    asymmetricSign: mockAsymmetricSign,
    close: mockClose,
  })),
}));

import { GCPCloudKMSSigner } from '../src/gcp-cloudkms-signer';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const GCP_CONFIG = {
  projectId: 'test-project',
  locationId: 'us-central1',
  keyRingId: 'test-ring',
  cryptoKeyId: 'test-key',
};

const EXPLICIT_VERSION_NAME = `projects/${GCP_CONFIG.projectId}/locations/${GCP_CONFIG.locationId}/keyRings/${GCP_CONFIG.keyRingId}/cryptoKeys/${GCP_CONFIG.cryptoKeyId}/cryptoKeyVersions/1`;

/** Extract PEM string from a generated public key */
async function exportPublicKeyPEM(alg: string): Promise<{ pem: string; publicKey: jose.KeyLike }> {
  const { publicKey } = await jose.generateKeyPair(alg as any);
  const pem = await jose.exportSPKI(publicKey);
  return { pem, publicKey };
}

// ---------------------------------------------------------------------------
// initialize() tests
// ---------------------------------------------------------------------------

describe('GCPCloudKMSSigner – initialize()', () => {
  beforeEach(() => {
    mockGetCryptoKey.mockReset();
    mockGetPublicKey.mockReset();
    mockAsymmetricSign.mockReset();
    mockClose.mockReset();
  });

  it('should resolve the primary version when cryptoKeyVersion is not set', async () => {
    const { pem } = await exportPublicKeyPEM('RS256');

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    await signer.initialize();

    expect(mockGetCryptoKey).toHaveBeenCalledTimes(1);
    expect(mockGetPublicKey).toHaveBeenCalledWith({ name: EXPLICIT_VERSION_NAME });
  });

  it('should use the explicit cryptoKeyVersion when set', async () => {
    const { pem } = await exportPublicKeyPEM('RS256');

    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: { ...GCP_CONFIG, cryptoKeyVersion: '3' },
    });

    await signer.initialize();

    // getCryptoKey should NOT have been called because the version is explicit
    expect(mockGetCryptoKey).not.toHaveBeenCalled();
    expect(mockGetPublicKey).toHaveBeenCalledWith({
      name: `${EXPLICIT_VERSION_NAME.replace('/cryptoKeyVersions/1', '/cryptoKeyVersions/3')}`,
    });
  });

  // -----------------------------------------------------------------------
  // Algorithm mapping
  // -----------------------------------------------------------------------

  const algCases: Array<{ gcpAlgo: string; expected: string }> = [
    { gcpAlgo: 'RSA_SIGN_PKCS1_2048_SHA256', expected: 'RS256' },
    { gcpAlgo: 'RSA_SIGN_PKCS1_3072_SHA256', expected: 'RS256' },
    { gcpAlgo: 'RSA_SIGN_PKCS1_4096_SHA256', expected: 'RS256' },
    { gcpAlgo: 'RSA_SIGN_PKCS1_4096_SHA512', expected: 'RS512' },
    { gcpAlgo: 'EC_SIGN_P256_SHA256',         expected: 'ES256' },
    { gcpAlgo: 'EC_SIGN_P384_SHA384',         expected: 'ES384' },
    { gcpAlgo: 'EC_SIGN_P521_SHA512',         expected: 'ES512' },
  ];

  test.each(algCases)('should detect $expected for GCP algorithm $gcpAlgo', async ({ gcpAlgo, expected }) => {
    const joseAlg = expected.startsWith('RS') ? expected : expected;
    const { pem } = await exportPublicKeyPEM(joseAlg);

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: gcpAlgo }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    await signer.initialize();
    expect(signer.getAlgorithm()).toBe(expected);
  });

  it('should throw for an unknown/unsupported GCP algorithm', async () => {
    const { pem } = await exportPublicKeyPEM('RS256');

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'SOME_FUTURE_ALGO' }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    await expect(signer.initialize()).rejects.toThrow('Unsupported GCP KMS signing algorithm: SOME_FUTURE_ALGO');
  });

  it('should throw when primary key version is not available', async () => {
    mockGetCryptoKey.mockResolvedValueOnce([{ primary: null }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    await expect(signer.initialize()).rejects.toThrow('Failed to get primary crypto key version from GCP Cloud KMS');
  });
});

// ---------------------------------------------------------------------------
// sign() – DER→JOSE conversion for ECDSA
// ---------------------------------------------------------------------------

describe('GCPCloudKMSSigner – sign() ECDSA DER-to-JOSE conversion', () => {
  beforeEach(() => {
    mockGetCryptoKey.mockReset();
    mockGetPublicKey.mockReset();
    mockAsymmetricSign.mockReset();
    mockClose.mockReset();
  });

  it('should produce a valid 3-part JWT with an ES256 JOSE-format signature', async () => {
    const { pem } = await exportPublicKeyPEM('ES256');

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'EC_SIGN_P256_SHA256' }]);

    // Return a well-formed DER ECDSA signature (32-byte r and s)
    const r = Buffer.alloc(32, 0x11);
    const s = Buffer.alloc(32, 0x22);
    const rDer = Buffer.concat([Buffer.from([0x02, r.length]), r]);
    const sDer = Buffer.concat([Buffer.from([0x02, s.length]), s]);
    const inner = Buffer.concat([rDer, sDer]);
    const fakeDerSig = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);

    mockAsymmetricSign.mockResolvedValueOnce([{ signature: fakeDerSig }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    const payload = {
      iss: 'did:web:example.com',
      sub: 'agent-1',
      aud: 'tool-gateway',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: 'test-jti',
      capabilities: [],
    };

    const token = await signer.sign(payload);

    // Verify JWT structure
    const parts = token.split('.');
    expect(parts).toHaveLength(3);

    // Decode and verify header
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf-8'));
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');

    // Decode and verify payload
    const decodedPayload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf-8'));
    expect(decodedPayload.sub).toBe('agent-1');

    // Verify the DER signature was converted to 64-byte JOSE (r||s) format
    const signatureBytes = Buffer.from(parts[2]!, 'base64url');
    expect(signatureBytes.length).toBe(64);
    expect(signatureBytes.slice(0, 32)).toEqual(r);
    expect(signatureBytes.slice(32)).toEqual(s);
  });

  it('should NOT convert RSA signatures (they must be used as-is)', async () => {
    const { pem } = await exportPublicKeyPEM('RS256');

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }]);

    // Return a 256-byte RSA signature (typical for RSA-2048)
    const fakeRsaSig = Buffer.alloc(256, 0xab);
    mockAsymmetricSign.mockResolvedValueOnce([{ signature: fakeRsaSig }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    const payload = {
      iss: 'did:web:example.com',
      sub: 'agent-2',
      aud: 'tool-gateway',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: 'test-jti-2',
      capabilities: [],
    };

    const token = await signer.sign(payload);

    // RSA signature should be base64url-encoded as-is (no DER-to-JOSE conversion)
    const parts = token.split('.');
    const signatureBytes = Buffer.from(parts[2]!, 'base64url');
    expect(signatureBytes.length).toBe(256);
    expect(signatureBytes).toEqual(fakeRsaSig);
  });
});

// ---------------------------------------------------------------------------
// dispose() tests
// ---------------------------------------------------------------------------

describe('GCPCloudKMSSigner – dispose()', () => {
  beforeEach(() => {
    mockGetCryptoKey.mockReset();
    mockGetPublicKey.mockReset();
    mockClose.mockReset();
  });

  it('should call kmsClient.close() and clear internal state', async () => {
    const { pem } = await exportPublicKeyPEM('RS256');

    mockGetCryptoKey.mockResolvedValueOnce([{ primary: { name: EXPLICIT_VERSION_NAME } }]);
    mockGetPublicKey.mockResolvedValueOnce([{ pem, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }]);

    const signer = new GCPCloudKMSSigner({
      type: 'gcp-cloudkms',
      name: 'test',
      gcpKMS: GCP_CONFIG,
    });

    await signer.initialize();
    await signer.dispose();

    expect(mockClose).toHaveBeenCalledTimes(1);
  });
});

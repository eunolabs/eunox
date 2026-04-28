/**
 * Unit tests for AWSKMSSigner
 * Mocks the AWS SDK to avoid real network calls
 */

import { AWSKMSSigner, derEcdsaToJose } from '../src/aws-kms-signer';
import * as jose from 'jose';
import { CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

// Mock @aws-sdk/client-kms at module level
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-kms', () => {
  const real = jest.requireActual('@aws-sdk/client-kms');
  return {
    ...real,
    KMSClient: jest.fn().mockImplementation(() => ({
      send: mockSend,
      destroy: jest.fn(),
    })),
  };
});

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Generate a real RSA-2048 key pair and produce a DER-encoded public key */
async function generateRSAKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
  // We need raw DER bytes, not PEM; decode the base64 portion
  const pemLines = (await jose.exportSPKI(publicKey)).split('\n').filter(l => !l.startsWith('---') && l.length > 0);
  const pubKeyDerBytes = Buffer.from(pemLines.join(''), 'base64');
  return { publicKey, privateKey, pubKeyDerBytes };
}

/** Generate a real P-256 key pair and produce a DER-encoded public key */
async function generateP256KeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const pemLines = (await jose.exportSPKI(publicKey)).split('\n').filter(l => !l.startsWith('---') && l.length > 0);
  const pubKeyDerBytes = Buffer.from(pemLines.join(''), 'base64');
  return { publicKey, privateKey, pubKeyDerBytes };
}

/**
 * Build a minimal DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }).
 * Handles both short-form and long-form DER length encoding correctly.
 */
function buildDerSignature(r: Buffer, s: Buffer): Buffer {
  const rDer = Buffer.concat([Buffer.from([0x02, r.length]), r]);
  const sDer = Buffer.concat([Buffer.from([0x02, s.length]), s]);
  const inner = Buffer.concat([rDer, sDer]);

  let seqLen: Buffer;
  if (inner.length < 128) {
    seqLen = Buffer.from([inner.length]);
  } else if (inner.length < 256) {
    seqLen = Buffer.from([0x81, inner.length]);
  } else {
    seqLen = Buffer.from([0x82, (inner.length >> 8) & 0xff, inner.length & 0xff]);
  }

  return Buffer.concat([Buffer.from([0x30]), seqLen, inner]);
}

// ---------------------------------------------------------------------------
// derEcdsaToJose helper tests
// ---------------------------------------------------------------------------

describe('derEcdsaToJose', () => {
  it('should convert a valid ES256 DER signature to 64-byte JOSE format', () => {
    // Minimal valid DER signature for a P-256 key (r and s each 32 bytes)
    const r = Buffer.alloc(32, 0xab);
    const s = Buffer.alloc(32, 0xcd);
    const der = buildDerSignature(r, s);

    const jose = derEcdsaToJose(der, 'ES256');
    expect(jose.length).toBe(64);
    expect(jose.slice(0, 32)).toEqual(r);
    expect(jose.slice(32)).toEqual(s);
  });

  it('should strip leading zero byte in r/s (DER positive-integer padding)', () => {
    // DER adds a 0x00 prefix when the MSB of r or s is set
    const rValue = Buffer.alloc(32, 0xff);
    const sValue = Buffer.alloc(32, 0xee);
    // Pad with 0x00 to indicate positive integers (as DER requires for bytes with MSB set)
    const r = Buffer.concat([Buffer.from([0x00]), rValue]);
    const s = Buffer.concat([Buffer.from([0x00]), sValue]);
    const der = buildDerSignature(r, s);

    const jose = derEcdsaToJose(der, 'ES256');
    expect(jose.length).toBe(64);
    // After stripping the leading 0x00, r is 32 bytes of 0xff
    expect(jose[0]).toBe(0xff);
    // Same for s
    expect(jose[32]).toBe(0xee);
  });

  it('should produce 96 bytes for ES384', () => {
    const r = Buffer.alloc(48, 0x01);
    const s = Buffer.alloc(48, 0x02);
    const der = buildDerSignature(r, s);

    const jose = derEcdsaToJose(der, 'ES384');
    expect(jose.length).toBe(96);
  });

  it('should produce 132 bytes for ES512', () => {
    // ES512 coordinates are 66 bytes, total inner content > 127 bytes → long-form DER length
    const r = Buffer.alloc(66, 0x01);
    const s = Buffer.alloc(66, 0x02);
    const der = buildDerSignature(r, s);

    const jose = derEcdsaToJose(der, 'ES512');
    expect(jose.length).toBe(132);
  });

  it('should throw for invalid DER (missing SEQUENCE tag)', () => {
    expect(() => derEcdsaToJose(Buffer.from([0x01, 0x00]), 'ES256')).toThrow('missing SEQUENCE tag');
  });
});

// ---------------------------------------------------------------------------
// AWSKMSSigner tests
// ---------------------------------------------------------------------------

describe('AWSKMSSigner', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  // -----------------------------------------------------------------------
  // initialize() – algorithm detection
  // -----------------------------------------------------------------------

  describe('initialize() algorithm detection', () => {
    it('should detect ES256 for ECC_NIST_P256 key spec', async () => {
      const { pubKeyDerBytes } = await generateP256KeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'ECC_NIST_P256',
        SigningAlgorithms: ['ECDSA_SHA_256'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      expect(signer.getAlgorithm()).toBe('ES256');
    });

    it('should detect ES384 for ECC_NIST_P384 key spec', async () => {
      const { publicKey } = await jose.generateKeyPair('ES384');
      const pemLines = (await jose.exportSPKI(publicKey)).split('\n').filter(l => !l.startsWith('---') && l.length > 0);
      const pubKeyDerBytes = Buffer.from(pemLines.join(''), 'base64');

      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'ECC_NIST_P384',
        SigningAlgorithms: ['ECDSA_SHA_384'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      expect(signer.getAlgorithm()).toBe('ES384');
    });

    it('should detect ES512 for ECC_NIST_P521 key spec', async () => {
      const { publicKey } = await jose.generateKeyPair('ES512');
      const pemLines = (await jose.exportSPKI(publicKey)).split('\n').filter(l => !l.startsWith('---') && l.length > 0);
      const pubKeyDerBytes = Buffer.from(pemLines.join(''), 'base64');

      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'ECC_NIST_P521',
        SigningAlgorithms: ['ECDSA_SHA_512'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      expect(signer.getAlgorithm()).toBe('ES512');
    });

    it('should detect RS256 for RSA_2048 key spec with SHA256 algorithm', async () => {
      const { pubKeyDerBytes } = await generateRSAKeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'RSA_2048',
        SigningAlgorithms: ['RSASSA_PKCS1_V1_5_SHA_256'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      expect(signer.getAlgorithm()).toBe('RS256');
    });

    it('should detect RS512 when RSASSA_PKCS1_V1_5_SHA_512 is available', async () => {
      const { pubKeyDerBytes } = await generateRSAKeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'RSA_4096',
        SigningAlgorithms: ['RSASSA_PKCS1_V1_5_SHA_256', 'RSASSA_PKCS1_V1_5_SHA_512'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      expect(signer.getAlgorithm()).toBe('RS512');
    });

    it('should throw for an unsupported key spec', async () => {
      const { pubKeyDerBytes } = await generateRSAKeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'HMAC_256',
        SigningAlgorithms: [],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await expect(signer.initialize()).rejects.toThrow('Unsupported AWS KMS key spec: HMAC_256');
    });

    it('should respect an explicitly configured algorithm and not override it', async () => {
      const { pubKeyDerBytes } = await generateP256KeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'ECC_NIST_P256',
        SigningAlgorithms: ['ECDSA_SHA_256'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        algorithm: 'ES256',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      // When explicitly configured, algorithm should not be changed
      expect(signer.getAlgorithm()).toBe('ES256');
    });
  });

  // -----------------------------------------------------------------------
  // sign() – ECDSA DER→JOSE conversion produces a jose-verifiable token
  // -----------------------------------------------------------------------

  describe('sign() ECDSA DER-to-JOSE conversion', () => {
    it('should produce a valid 3-part JWT with an ES256 JOSE-format signature', async () => {
      // Generate a real P-256 key pair
      const { pubKeyDerBytes } = await generateP256KeyPair();

      // Mock GetPublicKey (first call in initialize)
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'ECC_NIST_P256',
        SigningAlgorithms: ['ECDSA_SHA_256'],
      });

      const signerInstance = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signerInstance.initialize();

      // Return a well-formed DER ECDSA signature (32-byte r and s) from the Sign mock
      // The signature bytes are synthetic but structurally valid DER
      const r = Buffer.alloc(32, 0x11);
      const s = Buffer.alloc(32, 0x22);
      const rDer = Buffer.concat([Buffer.from([0x02, r.length]), r]);
      const sDer = Buffer.concat([Buffer.from([0x02, s.length]), s]);
      const inner = Buffer.concat([rDer, sDer]);
      const fakeDerSig = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);

      mockSend.mockResolvedValueOnce({ Signature: fakeDerSig });

      const payload = {
        iss: 'did:web:example.com',
        sub: 'agent-1',
        aud: 'tool-gateway',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: 'test-jti',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await signerInstance.sign(payload);

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

      // Verify signature was converted from DER (71 bytes) to JOSE format (exactly 64 bytes for ES256)
      const signatureBytes = Buffer.from(parts[2]!, 'base64url');
      expect(signatureBytes.length).toBe(64);

      // Verify the r and s values were correctly extracted from DER
      expect(signatureBytes.slice(0, 32)).toEqual(r);
      expect(signatureBytes.slice(32)).toEqual(s);
    });

    it('should NOT convert RSA signatures (they must be used as-is)', async () => {
      const { pubKeyDerBytes } = await generateRSAKeyPair();

      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'RSA_2048',
        SigningAlgorithms: ['RSASSA_PKCS1_V1_5_SHA_256'],
      });

      const signerInstance = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signerInstance.initialize();

      // Return a 256-byte RSA signature (typical for RSA-2048)
      const fakeRsaSig = Buffer.alloc(256, 0xab);
      mockSend.mockResolvedValueOnce({ Signature: fakeRsaSig });

      const payload = {
        iss: 'did:web:example.com',
        sub: 'agent-2',
        aud: 'tool-gateway',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: 'test-jti-2',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await signerInstance.sign(payload);

      // RSA signature should be base64url-encoded as-is (no DER-to-JOSE conversion)
      const parts = token.split('.');
      const signatureBytes = Buffer.from(parts[2]!, 'base64url');
      expect(signatureBytes.length).toBe(256);
      expect(signatureBytes).toEqual(fakeRsaSig);
    });
  });

  // -----------------------------------------------------------------------
  // dispose() – calls kmsClient.destroy()
  // -----------------------------------------------------------------------

  describe('dispose()', () => {
    it('should call kmsClient.destroy() and clear the public key cache', async () => {
      const { pubKeyDerBytes } = await generateRSAKeyPair();
      mockSend.mockResolvedValueOnce({
        PublicKey: pubKeyDerBytes,
        KeySpec: 'RSA_2048',
        SigningAlgorithms: ['RSASSA_PKCS1_V1_5_SHA_256'],
      });

      const signer = new AWSKMSSigner({
        type: 'aws-kms',
        name: 'test',
        awsKMS: { region: 'us-east-1', keyId: 'test-key-id' },
      });

      await signer.initialize();
      const { KMSClient } = await import('@aws-sdk/client-kms');
      const mockClientResults = (KMSClient as jest.Mock).mock.results;
      const mockClientInstance = mockClientResults[mockClientResults.length - 1]?.value;

      await signer.dispose();

      expect(mockClientInstance.destroy).toHaveBeenCalledTimes(1);
      // After dispose the cache is cleared; without a new mock the re-initialization
      // will fail, confirming the cache was cleared
      await expect(signer.getPublicKey()).rejects.toThrow();
    });
  });
});

/**
 * Tests for AuditEvidenceSigner – signing and cryptographic verification.
 */

import * as crypto from 'crypto';
import {
  AuditEvidenceSigner,
  CryptoSigner,
  createAuditEvidence,
  createSoftwareEvidenceSigner,
  createSoftwareEvidenceSignerFromEnv,
} from '../src/evidence';

/**
 * In-process CryptoSigner backed by a freshly generated RSA key pair.  Used
 * to exercise both the signing and verification code paths end-to-end.
 */
class TestRsaSigner implements CryptoSigner {
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKey: crypto.KeyObject;
  private readonly keyId = 'test-key-1';

  constructor() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    // Sign the SHA-256 digest with PKCS#1 v1.5 padding (RS256 semantics).
    return crypto.sign(null, digest, {
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }

  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    keyId: string,
    _algorithm: string
  ): Promise<boolean> {
    if (keyId !== this.keyId) {
      return false;
    }
    return crypto.verify(
      null,
      digest,
      { key: this.publicKey, dsaEncoding: 'ieee-p1363' },
      signature
    );
  }

  async getKeyId(): Promise<string> {
    return this.keyId;
  }

  getAlgorithm(): string {
    return 'RS256';
  }
}

class SignOnlySigner implements CryptoSigner {
  async signDigest(): Promise<Buffer> {
    return Buffer.from('not-a-real-signature');
  }
  async getKeyId(): Promise<string> {
    return 'sign-only';
  }
  getAlgorithm(): string {
    return 'RS256';
  }
}

function makeEvidence() {
  return createAuditEvidence({
    sessionId: 'sess-1',
    userId: 'user-1',
    prompt: 'hello',
    documents: { foo: 'bar' },
    tool: 'read_file',
    args: { path: '/etc/hosts' },
    agentId: 'agent-1',
    resource: 'tool://read_file',
    action: 'read',
    capabilityId: 'cap-1',
    decision: 'allow',
    policyVersion: '1.0.0',
  });
}

describe('AuditEvidenceSigner', () => {
  it('round-trips: signed evidence verifies successfully', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());

    expect(signed.signature).toBeTruthy();
    expect(signed.keyId).toBe('test-key-1');
    expect(signed.algorithm).toBe('RS256');

    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('rejects evidence with a tampered field', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());
    const tampered = { ...signed, action: 'write' };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('rejects evidence with a tampered signing-metadata field (keyId)', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());
    const tampered = { ...signed, keyId: 'attacker-key' };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('rejects evidence with a corrupted signature', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());
    const tampered = { ...signed, signature: Buffer.from('zzzzz').toString('base64') };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('fails closed (returns false) when the signer cannot verify', async () => {
    const signer = new AuditEvidenceSigner(new SignOnlySigner());
    const signed = await signer.signEvidence(makeEvidence());
    expect(signed.signature).toBeTruthy();
    // Sign-only signer has no verifyDigest – verification must fail closed,
    // never return true based on metadata presence alone.
    expect(await signer.verifyEvidence(signed)).toBe(false);
  });

  it('rejects records missing signature / keyId / algorithm', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());
    expect(await signer.verifyEvidence({ ...signed, signature: '' })).toBe(false);
    expect(await signer.verifyEvidence({ ...signed, keyId: '' })).toBe(false);
    expect(await signer.verifyEvidence({ ...signed, algorithm: '' })).toBe(false);
  });

  it('rejects empty / malformed base64 signatures', async () => {
    const signer = new AuditEvidenceSigner(new TestRsaSigner());
    const signed = await signer.signEvidence(makeEvidence());
    // Empty buffer after base64 decode → reject without invoking the signer
    expect(await signer.verifyEvidence({ ...signed, signature: '' })).toBe(false);
  });
});

describe('createSoftwareEvidenceSigner', () => {
  function generatePem(type: 'rsa' | 'ec' | 'ed25519'): string {
    if (type === 'rsa') {
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    }
    if (type === 'ec') {
      const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    }
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  }

  it('round-trips evidence using an RSA PEM key (RS256)', async () => {
    const pem = generatePem('rsa');
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: pem, keyId: 'sw-1' });
    const signed = await signer.signEvidence(makeEvidence());
    expect(signed.keyId).toBe('sw-1');
    expect(signed.algorithm).toBe('RS256');
    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('round-trips evidence using an EC PEM key (ES256)', async () => {
    const pem = generatePem('ec');
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: pem, algorithm: 'ES256' });
    const signed = await signer.signEvidence(makeEvidence());
    expect(signed.algorithm).toBe('ES256');
    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('round-trips evidence using an Ed25519 PEM key (EdDSA)', async () => {
    const pem = generatePem('ed25519');
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: pem, algorithm: 'EdDSA' });
    const signed = await signer.signEvidence(makeEvidence());
    expect(signed.algorithm).toBe('EdDSA');
    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('detects tampering with the signed payload', async () => {
    const pem = generatePem('rsa');
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: pem });
    const signed = await signer.signEvidence(makeEvidence());
    expect(await signer.verifyEvidence({ ...signed, action: 'write' })).toBe(false);
  });

  it('throws when the algorithm does not match the key type', () => {
    const rsaPem = generatePem('rsa');
    expect(() => createSoftwareEvidenceSigner({ privateKeyPem: rsaPem, algorithm: 'ES256' })).toThrow(
      /requires an EC key/,
    );
  });

  it('throws when no private key is supplied', () => {
    expect(() => createSoftwareEvidenceSigner({} as { privateKeyPem?: string })).toThrow(
      /privateKeyPem or privateKeyPath/,
    );
  });

  it('throws on an unsupported algorithm', () => {
    const pem = generatePem('rsa');
    expect(() => createSoftwareEvidenceSigner({ privateKeyPem: pem, algorithm: 'HS256' })).toThrow(
      /unsupported algorithm/,
    );
  });

  it('throws on RS384/RS512/PS512/ES384 (incompatible with SHA-256 digest)', () => {
    const rsaPem = generatePem('rsa');
    for (const alg of ['RS384', 'RS512', 'PS384', 'PS512']) {
      expect(() => createSoftwareEvidenceSigner({ privateKeyPem: rsaPem, algorithm: alg })).toThrow(
        /unsupported algorithm/,
      );
    }
  });

  it('throws when both privateKeyPem and privateKeyPath are supplied', () => {
    const pem = generatePem('rsa');
    expect(() =>
      createSoftwareEvidenceSigner({ privateKeyPem: pem, privateKeyPath: '/tmp/does-not-matter.pem' }),
    ).toThrow(/mutually exclusive/);
  });

  it('throws when both publicKeyPem and publicKeyPath are supplied', () => {
    const pem = generatePem('rsa');
    expect(() =>
      createSoftwareEvidenceSigner({
        privateKeyPem: pem,
        publicKeyPem: pem,
        publicKeyPath: '/tmp/does-not-matter.pem',
      }),
    ).toThrow(/mutually exclusive/);
  });

  it('throws when the PEM cannot be parsed', () => {
    expect(() => createSoftwareEvidenceSigner({ privateKeyPem: 'not-a-pem' })).toThrow(
      /failed to parse private key PEM/,
    );
  });
});

describe('createSoftwareEvidenceSignerFromEnv', () => {
  it('returns undefined when no key env vars are set', () => {
    expect(createSoftwareEvidenceSignerFromEnv({})).toBeUndefined();
  });

  it('builds a signer from EVIDENCE_SIGNING_KEY_PEM', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const signer = createSoftwareEvidenceSignerFromEnv({
      EVIDENCE_SIGNING_KEY_PEM: pem,
      EVIDENCE_SIGNING_KEY_ID: 'env-key',
    } as NodeJS.ProcessEnv);
    expect(signer).toBeDefined();
    const signed = await signer!.signEvidence(makeEvidence());
    expect(signed.keyId).toBe('env-key');
    expect(await signer!.verifyEvidence(signed)).toBe(true);
  });
});

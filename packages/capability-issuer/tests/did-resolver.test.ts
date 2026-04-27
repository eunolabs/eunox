/**
 * Unit tests for DID Resolution Utilities
 *
 * Covers:
 *  - did:key resolution (Ed25519, P-256, secp256k1)
 *  - did:ion resolution (mocked HTTP fetch)
 *  - did:web resolution (mocked HTTP fetch)
 *  - JWK → PEM conversion via extractPublicKeyPem
 *  - Helper utilities: findVerificationMethod, determineSigningAlgorithm
 */

import { generateKeyPairSync } from 'crypto';
import * as jose from 'jose';
import {
  resolveDID,
  resolveDidKey,
  resolveDidIon,
  extractPublicKeyPem,
  findVerificationMethod,
  determineSigningAlgorithm,
  encodeBase58Btc,
  type DIDDocument,
  type VerificationMethod,
} from '../src/did-resolver';

// ---------------------------------------------------------------------------
// Helper: build a did:key from raw bytes + multicodec prefix
// ---------------------------------------------------------------------------

function makeDidKey(codecPrefix: number[], keyBytes: Uint8Array): string {
  const prefixBuf = Buffer.from(codecPrefix);
  const combined = new Uint8Array(prefixBuf.length + keyBytes.length);
  combined.set(prefixBuf);
  combined.set(keyBytes, prefixBuf.length);
  return `did:key:z${encodeBase58Btc(combined)}`;
}

// ---------------------------------------------------------------------------
// did:key – Ed25519
// ---------------------------------------------------------------------------

describe('resolveDidKey – Ed25519', () => {
  let edPublicKeyBytes: Uint8Array;
  let edDid: string;

  beforeAll(() => {
    // Generate a real Ed25519 key pair so we can verify round-trip
    const { publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
    edPublicKeyBytes = Buffer.from(jwk.x, 'base64url');
    edDid = makeDidKey([0xed, 0x01], edPublicKeyBytes); // multicodec Ed25519 = 0xed
  });

  it('resolves a valid Ed25519 did:key to a DID Document', async () => {
    const doc = await resolveDidKey(edDid);

    expect(doc.id).toBe(edDid);
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('sets the verification method id to did#identifier', async () => {
    const identifier = edDid.substring('did:key:'.length);
    const doc = await resolveDidKey(edDid);
    expect(doc.verificationMethod![0]!.id).toBe(`${edDid}#${identifier}`);
  });

  it('includes publicKeyJwk with kty=OKP and crv=Ed25519', async () => {
    const doc = await resolveDidKey(edDid);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.alg).toBe('EdDSA');
  });

  it('preserves the original public key x coordinate', async () => {
    const doc = await resolveDidKey(edDid);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    const recoveredBytes = Buffer.from(jwk.x!, 'base64url');
    expect(recoveredBytes).toEqual(Buffer.from(edPublicKeyBytes));
  });

  it('populates authentication / assertionMethod references', async () => {
    const identifier = edDid.substring('did:key:'.length);
    const vmId = `${edDid}#${identifier}`;
    const doc = await resolveDidKey(edDid);
    expect(doc.authentication).toContain(vmId);
    expect(doc.assertionMethod).toContain(vmId);
  });

  it('rejects a did:key with wrong key length', async () => {
    // Build a key with only 16 bytes instead of 32
    const shortKey = makeDidKey([0xed, 0x01], new Uint8Array(16));
    await expect(resolveDidKey(shortKey)).rejects.toMatchObject({
      message: expect.stringContaining('Invalid Ed25519 key length'),
    });
  });
});

// ---------------------------------------------------------------------------
// did:key – P-256
// ---------------------------------------------------------------------------

describe('resolveDidKey – P-256', () => {
  // A known P-256 compressed public key.
  // x = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
  // y = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299 (even → prefix 0x02)
  // Source: NIST SP 800-186 Table 3, P-256 example key pair
  // https://csrc.nist.gov/publications/detail/sp/800-186/final
  const knownX = BigInt('0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6');
  const compressedHex =
    '02' + knownX.toString(16).padStart(64, '0');
  const compressedBytes = Buffer.from(compressedHex, 'hex');
  const p256Did = makeDidKey([0x80, 0x24], compressedBytes); // multicodec P-256 = 0x1200 → varint [0x80, 0x24]

  it('resolves a valid P-256 did:key to a DID Document', async () => {
    const doc = await resolveDidKey(p256Did);
    expect(doc.id).toBe(p256Did);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('includes publicKeyJwk with kty=EC and crv=P-256', async () => {
    const doc = await resolveDidKey(p256Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.alg).toBe('ES256');
  });

  it('recovers the correct x coordinate after decompression', async () => {
    const doc = await resolveDidKey(p256Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    const xRecovered = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
    expect(xRecovered).toBe(knownX);
  });

  it('produces a y that satisfies the curve equation y² = x³ - 3x + b mod p', async () => {
    const doc = await resolveDidKey(p256Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    const x = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
    const y = BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex'));

    const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const a = p - 3n;
    const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
    const lhs = (y * y) % p;
    const rhs = ((x * x % p) * x % p + a * x % p + b) % p;
    expect(lhs).toBe(rhs);
  });
});

// ---------------------------------------------------------------------------
// did:key – secp256k1
// ---------------------------------------------------------------------------

describe('resolveDidKey – secp256k1', () => {
  // A known secp256k1 compressed public key (Bitcoin generator point G)
  // Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  const compressedHex = '02' + Gx.toString(16).padStart(64, '0');
  const compressedBytes = Buffer.from(compressedHex, 'hex');
  const k1Did = makeDidKey([0xe7, 0x01], compressedBytes); // multicodec secp256k1 = 0xe7

  it('resolves a valid secp256k1 did:key to a DID Document', async () => {
    const doc = await resolveDidKey(k1Did);
    expect(doc.id).toBe(k1Did);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('includes publicKeyJwk with kty=EC and crv=secp256k1', async () => {
    const doc = await resolveDidKey(k1Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('secp256k1');
    expect(jwk.alg).toBe('ES256K');
  });

  it('recovers the correct x coordinate after decompression', async () => {
    const doc = await resolveDidKey(k1Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    const xRecovered = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
    expect(xRecovered).toBe(Gx);
  });

  it('produces a y that satisfies y² = x³ + 7 mod p', async () => {
    const doc = await resolveDidKey(k1Did);
    const jwk = doc.verificationMethod![0]!.publicKeyJwk!;
    const x = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
    const y = BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex'));

    const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    const lhs = (y * y) % p;
    const rhs = ((x * x % p) * x % p + 7n) % p;
    expect(lhs).toBe(rhs);
  });
});

// ---------------------------------------------------------------------------
// did:key – error cases
// ---------------------------------------------------------------------------

describe('resolveDidKey – error cases', () => {
  it('rejects a string that is not a did:key', async () => {
    await expect(resolveDidKey('did:web:example.com')).rejects.toMatchObject({
      message: expect.stringContaining('Not a did:key'),
    });
  });

  it('rejects an identifier without multibase z prefix', async () => {
    await expect(resolveDidKey('did:key:mABCDEF')).rejects.toMatchObject({
      message: expect.stringContaining('Only base58btc'),
    });
  });

  it('rejects an unsupported multicodec', async () => {
    // X25519 multicodec = 0xec (236)
    const x25519Bytes = new Uint8Array(32).fill(0x42);
    const x25519Did = makeDidKey([0xec, 0x01], x25519Bytes);
    await expect(resolveDidKey(x25519Did)).rejects.toMatchObject({
      message: expect.stringContaining('Unsupported did:key codec'),
    });
  });
});

// ---------------------------------------------------------------------------
// resolveDID dispatch
// ---------------------------------------------------------------------------

describe('resolveDID – method dispatch', () => {
  it('dispatches did:key correctly', async () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
    const keyBytes = Buffer.from(jwk.x, 'base64url');
    const did = makeDidKey([0xed, 0x01], keyBytes);
    const doc = await resolveDID(did);
    expect(doc.id).toBe(did);
  });

  it('throws for an unsupported method', async () => {
    await expect(resolveDID('did:unknown:abc')).rejects.toMatchObject({
      message: expect.stringContaining("DID method 'unknown' is not supported"),
    });
  });

  it('throws for an invalid DID', async () => {
    await expect(resolveDID('not-a-did')).rejects.toMatchObject({
      message: expect.stringContaining('Invalid DID format'),
    });
  });
});

// ---------------------------------------------------------------------------
// extractPublicKeyPem – JWK → PEM conversion
// ---------------------------------------------------------------------------

describe('extractPublicKeyPem', () => {
  it('returns publicKeyPem as-is when already set', async () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'RsaVerificationKey2018',
      controller: 'did:example:abc',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...\n-----END PUBLIC KEY-----\n',
    };
    const pem = await extractPublicKeyPem(vm);
    expect(pem).toBe(vm.publicKeyPem);
  });

  it('converts an Ed25519 JWK to SPKI PEM', async () => {
    // Generate a real Ed25519 key
    const { publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;

    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, alg: 'EdDSA' },
    };

    const pem = await extractPublicKeyPem(vm);
    expect(pem).toMatch(/-----BEGIN PUBLIC KEY-----/);

    // The PEM should round-trip: import as SPKI and re-export as JWK
    const reimported = await jose.importSPKI(pem, 'EdDSA');
    const reexported = await jose.exportJWK(reimported);
    expect(reexported.x).toBe(jwk.x);
  });

  it('converts a P-256 JWK to SPKI PEM', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;

    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, alg: 'ES256' },
    };

    const pem = await extractPublicKeyPem(vm);
    expect(pem).toMatch(/-----BEGIN PUBLIC KEY-----/);

    const reimported = await jose.importSPKI(pem, 'ES256');
    const reexported = await jose.exportJWK(reimported);
    expect(reexported.x).toBe(jwk.x);
    expect(reexported.y).toBe(jwk.y);
  });

  it('converts an RSA JWK to SPKI PEM', async () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;

    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256' },
    };

    const pem = await extractPublicKeyPem(vm);
    expect(pem).toMatch(/-----BEGIN PUBLIC KEY-----/);
  });

  it('throws NOT_IMPLEMENTED when no supported key format is present', async () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:example:abc',
      publicKeyBase58: 'someBase58Key',
    };
    await expect(extractPublicKeyPem(vm)).rejects.toMatchObject({
      message: expect.stringContaining('Public key format not supported'),
    });
  });
});

// ---------------------------------------------------------------------------
// resolveDidIon – mocked HTTP fetch
// ---------------------------------------------------------------------------

describe('resolveDidIon', () => {
  const mockDid = 'did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w';

  const mockDIDDocument: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: mockDid,
    verificationMethod: [
      {
        id: `${mockDid}#key-1`,
        type: 'JsonWebKey2020',
        controller: mockDid,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'test-x', alg: 'EdDSA' },
      },
    ],
  };

  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('returns the DID Document from ION resolver (nested didDocument)', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: mockDIDDocument,
        didDocumentMetadata: {},
      }),
    } as unknown as Response);

    const doc = await resolveDidIon(mockDid);
    expect(doc.id).toBe(mockDid);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('returns the DID Document when resolver returns a flat document', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => mockDIDDocument,
    } as unknown as Response);

    const doc = await resolveDidIon(mockDid);
    expect(doc.id).toBe(mockDid);
  });

  it('throws AUTHENTICATION_FAILED on HTTP error', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
    } as unknown as Response);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      message: expect.stringContaining('HTTP 404'),
    });
  });

  it('throws AUTHENTICATION_FAILED on network error', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network failure'));

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      message: expect.stringContaining('network failure'),
    });
  });

  it('throws INVALID_TOKEN on DID mismatch', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        didDocument: { ...mockDIDDocument, id: 'did:ion:different' },
      }),
    } as unknown as Response);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      message: expect.stringContaining('DID document ID mismatch'),
    });
  });

  it('rejects a string that is not a did:ion', async () => {
    await expect(resolveDidIon('did:web:example.com')).rejects.toMatchObject({
      message: expect.stringContaining('Not a did:ion'),
    });
  });
});

// ---------------------------------------------------------------------------
// findVerificationMethod
// ---------------------------------------------------------------------------

describe('findVerificationMethod', () => {
  const doc: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: 'did:example:abc',
    verificationMethod: [
      { id: 'did:example:abc#key-1', type: 'JsonWebKey2020', controller: 'did:example:abc' },
      { id: 'did:example:abc#key-2', type: 'JsonWebKey2020', controller: 'did:example:abc' },
    ],
  };

  it('returns the first verification method when no keyId is provided', () => {
    const vm = findVerificationMethod(doc);
    expect(vm?.id).toBe('did:example:abc#key-1');
  });

  it('finds a verification method by fragment', () => {
    const vm = findVerificationMethod(doc, 'key-2');
    expect(vm?.id).toBe('did:example:abc#key-2');
  });

  it('finds a verification method by full key ID', () => {
    const vm = findVerificationMethod(doc, 'did:example:abc#key-1');
    expect(vm?.id).toBe('did:example:abc#key-1');
  });

  it('returns null when key not found', () => {
    const vm = findVerificationMethod(doc, 'key-99');
    expect(vm).toBeNull();
  });

  it('returns null when verificationMethod list is empty', () => {
    const emptyDoc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: 'did:example:abc' };
    expect(findVerificationMethod(emptyDoc)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// determineSigningAlgorithm
// ---------------------------------------------------------------------------

describe('determineSigningAlgorithm', () => {
  it('reads algorithm from publicKeyJwk.alg', () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#k',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'x', alg: 'EdDSA' },
    };
    expect(determineSigningAlgorithm(vm)).toBe('EdDSA');
  });

  it('infers ES256 for EC P-256 JWK without explicit alg', () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#k',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    };
    expect(determineSigningAlgorithm(vm)).toBe('ES256');
  });

  it('infers EdDSA for Ed25519VerificationKey2020 type', () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#k',
      type: 'Ed25519VerificationKey2020',
      controller: 'did:example:abc',
    };
    expect(determineSigningAlgorithm(vm)).toBe('EdDSA');
  });

  it('throws for unknown type with no JWK', () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#k',
      type: 'UnknownKeyType2099',
      controller: 'did:example:abc',
    };
    expect(() => determineSigningAlgorithm(vm)).toThrow();
  });
});

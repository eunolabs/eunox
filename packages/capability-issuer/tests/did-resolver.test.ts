/**
 * Unit tests for DID Resolution Utilities
 *
 * Covers:
 *  - did:key resolution (Ed25519, P-256, secp256k1)
 *  - did:ion resolution (mocked HTTP fetch)
 *  - JWK → PEM conversion via extractPublicKeyPem
 *  - Helper utilities: findVerificationMethod, determineSigningAlgorithm
 */

import { generateKeyPairSync } from 'crypto';
import * as jose from 'jose';
import { ErrorCode } from '@euno/common';
import {
  resolveDID,
  resolveDidKey,
  resolveDidIon,
  resolveDidWeb,
  parseDidWebHttpAllowList,
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

  it('rejects an identifier that is too long (> 256 base58 chars)', async () => {
    // 257 '1' characters → all-zero bytes decoding, but too long
    const longDid = 'did:key:z' + '1'.repeat(257);
    await expect(resolveDidKey(longDid)).rejects.toMatchObject({
      message: expect.stringContaining('too long'),
    });
  });

  it('rejects did:key:z (empty key material after decode)', async () => {
    // 'z' alone = multibase prefix with empty base58 string → empty decoded bytes
    await expect(resolveDidKey('did:key:z')).rejects.toMatchObject({
      message: expect.stringContaining('missing multicodec prefix or key material'),
    });
  });

  it('rejects a P-256 key with an invalid prefix byte (0x04 = uncompressed)', async () => {
    // Build a 33-byte payload with invalid prefix 0x04
    const invalidKey = Buffer.alloc(33);
    invalidKey[0] = 0x04;
    invalidKey.fill(0x01, 1);
    const badDid = makeDidKey([0x80, 0x24], invalidKey); // P-256 codec 0x1200
    await expect(resolveDidKey(badDid)).rejects.toMatchObject({
      message: expect.stringContaining('Invalid compressed P-256 key prefix'),
    });
  });

  it('rejects a secp256k1 key with an invalid prefix byte', async () => {
    const invalidKey = Buffer.alloc(33);
    invalidKey[0] = 0x04;
    invalidKey.fill(0x01, 1);
    const badDid = makeDidKey([0xe7, 0x01], invalidKey); // secp256k1 codec 0xe7
    await expect(resolveDidKey(badDid)).rejects.toMatchObject({
      message: expect.stringContaining('Invalid compressed secp256k1 key prefix'),
    });
  });

  it('rejects a P-256 key with an x that is not on the curve', async () => {
    // x = 1 is not a valid x coordinate on P-256 (no corresponding y exists)
    const offCurveKey = Buffer.alloc(33, 0);
    offCurveKey[0] = 0x02;   // even-y prefix
    offCurveKey[32] = 0x01;  // x = 1 (little-endian last byte = 1)
    const badDid = makeDidKey([0x80, 0x24], offCurveKey);
    await expect(resolveDidKey(badDid)).rejects.toMatchObject({
      message: expect.stringContaining('does not correspond to a point on the curve'),
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

  it('converts a P-256 JWK that has no alg field by deriving algorithm from vm type', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;

    // Omit the alg field – extractPublicKeyPem should fall back to determineSigningAlgorithm
    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, // no alg
    };

    const pem = await extractPublicKeyPem(vm);
    expect(pem).toMatch(/-----BEGIN PUBLIC KEY-----/);
  });

  it('throws INVALID_REQUEST for a malformed JWK (missing required key material)', async () => {
    const vm: VerificationMethod = {
      id: 'did:example:abc#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:example:abc',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', alg: 'ES256' }, // missing x and y
    };
    await expect(extractPublicKeyPem(vm)).rejects.toMatchObject({
      message: expect.stringContaining('Invalid or unsupported publicKeyJwk'),
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

  it('throws INVALID_TOKEN with 404 status when the DID is not registered', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    } as unknown as Response);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
      statusCode: 404,
      message: expect.stringContaining('not found'),
    });
  });

  it('throws AUTHENTICATION_FAILED on resolver 5xx error', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
    } as unknown as Response);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      message: expect.stringContaining('HTTP 503'),
    });
  });

  it('throws 504 timeout error when fetch aborts', async () => {
    const timeoutError = new Error('The operation was aborted');
    timeoutError.name = 'TimeoutError';
    global.fetch = jest.fn().mockRejectedValue(timeoutError);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      statusCode: 504,
      message: expect.stringContaining('timed out'),
    });
  });

  it('produces a clear DNS error message when the resolver host is unknown', async () => {
    const dnsError = Object.assign(new Error('getaddrinfo ENOTFOUND ion.example'), {
      code: 'ENOTFOUND',
    });
    global.fetch = jest.fn().mockRejectedValue(dnsError);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      message: expect.stringContaining('DNS lookup failed'),
    });
  });

  it('produces a clear connection error message on ECONNREFUSED', async () => {
    const connError = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), {
      code: 'ECONNREFUSED',
    });
    global.fetch = jest.fn().mockRejectedValue(connError);

    await expect(resolveDidIon(mockDid)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      message: expect.stringContaining('connection failed'),
    });
  });

  it('throws AUTHENTICATION_FAILED on generic network error', async () => {
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

// ---------------------------------------------------------------------------
// did:web — URL construction, custom ports, and HTTP test-mode allow-list
// (Sprint 3-4 gap #5: cross-org trust harness)
// ---------------------------------------------------------------------------

describe('parseDidWebHttpAllowList', () => {
  it('returns an empty set when env var is unset', () => {
    expect(parseDidWebHttpAllowList(undefined).size).toBe(0);
  });

  it('returns an empty set when env var is empty', () => {
    expect(parseDidWebHttpAllowList('').size).toBe(0);
    expect(parseDidWebHttpAllowList('   ').size).toBe(0);
  });

  it('parses a comma-separated list, trims whitespace and lowercases entries', () => {
    const set = parseDidWebHttpAllowList('Partner-Sim.Local:4001, OTHER.example.com ,foo');
    expect(Array.from(set).sort()).toEqual(['foo', 'other.example.com', 'partner-sim.local:4001']);
  });
});

describe('resolveDidWeb', () => {
  let originalFetch: typeof global.fetch;
  let originalAllow: string | undefined;
  let lastUrl: string | undefined;

  const buildFetchMock = (didDoc: DIDDocument) =>
    jest.fn().mockImplementation(async (url: string) => {
      lastUrl = url;
      return {
        ok: true,
        json: async () => didDoc,
      } as unknown as Response;
    });

  beforeEach(() => {
    originalFetch = global.fetch;
    originalAllow = process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    lastUrl = undefined;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    if (originalAllow === undefined) {
      delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    } else {
      process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = originalAllow;
    }
  });

  it('rejects identifiers that are not did:web', async () => {
    await expect(resolveDidWeb('did:key:zfoo')).rejects.toMatchObject({
      code: ErrorCode.INVALID_REQUEST,
    });
  });

  it('fetches the .well-known/did.json over HTTPS by default', async () => {
    delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    const did = 'did:web:example.com';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    const result = await resolveDidWeb(did);
    expect(result.id).toBe(did);
    expect(lastUrl).toBe('https://example.com/.well-known/did.json');
  });

  it('appends path segments for nested did:web identifiers', async () => {
    delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    const did = 'did:web:example.com:user:alice';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    await resolveDidWeb(did);
    expect(lastUrl).toBe('https://example.com/user/alice/did.json');
  });

  it('supports custom ports encoded as %3A in the host label', async () => {
    delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    const did = 'did:web:partner-sim.local%3A4001';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    await resolveDidWeb(did);
    // The %3A must decode back to ':' so the port is preserved in the URL.
    expect(lastUrl).toBe('https://partner-sim.local:4001/.well-known/did.json');
  });

  it('switches to HTTP only for hosts in DID_WEB_ALLOW_HTTP_FOR_HOSTS', async () => {
    process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = 'partner-sim.local:4001';
    const did = 'did:web:partner-sim.local%3A4001';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    await resolveDidWeb(did);
    expect(lastUrl).toBe('http://partner-sim.local:4001/.well-known/did.json');
  });

  it('keeps using HTTPS for hosts NOT in the allow-list (fail-closed)', async () => {
    process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = 'partner-sim.local:4001';
    const did = 'did:web:example.com';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    await resolveDidWeb(did);
    expect(lastUrl?.startsWith('https://')).toBe(true);
  });

  it('matches the allow-list case-insensitively', async () => {
    process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = 'Partner-Sim.Local:4001';
    const did = 'did:web:partner-sim.local%3A4001';
    const doc: DIDDocument = { '@context': 'https://www.w3.org/ns/did/v1', id: did };
    global.fetch = buildFetchMock(doc);

    await resolveDidWeb(did);
    expect(lastUrl?.startsWith('http://')).toBe(true);
  });

  it('rejects the document when its id does not match the requested DID', async () => {
    delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    const did = 'did:web:example.com';
    global.fetch = buildFetchMock({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:other.com',
    });

    await expect(resolveDidWeb(did)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
      statusCode: 400,
    });
  });

  it('surfaces non-2xx responses as AUTHENTICATION_FAILED', async () => {
    delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
    } as unknown as Response);

    await expect(resolveDidWeb('did:web:example.com')).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      statusCode: 502,
    });
  });
});

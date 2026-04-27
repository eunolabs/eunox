/**
 * DID Resolution Utilities
 *
 * Implements W3C DID resolution for did:web, did:ion, and did:key methods
 * Reference: https://www.w3.org/TR/did-core/
 */

import { CapabilityError, ErrorCode } from '@euno/common';
import * as jose from 'jose';

/**
 * W3C DID Document structure
 * https://www.w3.org/TR/did-core/#did-documents
 */
export interface DIDDocument {
  '@context': string | string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
}

/**
 * Verification Method in DID Document
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: JsonWebKey2020;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  publicKeyPem?: string;
}

/**
 * JSON Web Key 2020 format
 */
export interface JsonWebKey2020 {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  use?: string;
  alg?: string;
}

/**
 * Service endpoint in DID Document
 */
export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | Record<string, unknown>;
}

/**
 * DID Resolution Result
 */
export interface DIDResolutionResult {
  didDocument: DIDDocument | null;
  didResolutionMetadata: {
    contentType?: string;
    error?: string;
  };
  didDocumentMetadata: Record<string, unknown>;
}

/**
 * Resolve a DID to its DID Document
 * Supports did:web and did:ion methods
 */
export async function resolveDID(did: string): Promise<DIDDocument> {
  if (!did || !did.startsWith('did:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Invalid DID format: ${did}`,
      400
    );
  }

  const [, method] = did.split(':');

  switch (method) {
    case 'web':
      return await resolveDidWeb(did);
    case 'ion':
      return await resolveDidIon(did);
    case 'key':
      return await resolveDidKey(did);
    default:
      throw new CapabilityError(
        ErrorCode.NOT_IMPLEMENTED,
        `DID method '${method}' is not supported. Supported methods: web, ion, key`,
        501
      );
  }
}

/**
 * Resolve did:web to DID Document
 *
 * did:web method specification:
 * - did:web:example.com -> https://example.com/.well-known/did.json
 * - did:web:example.com:user:alice -> https://example.com/user/alice/did.json
 *
 * Reference: https://w3c-ccg.github.io/did-method-web/
 */
export async function resolveDidWeb(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:web:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:web identifier: ${did}`,
      400
    );
  }

  // Extract domain and path from DID
  const didParts = did.substring('did:web:'.length).split(':');
  if (didParts.length === 0 || !didParts[0]) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Invalid did:web format: ${did}`,
      400
    );
  }

  const domain = decodeURIComponent(didParts[0]);
  const path = didParts.slice(1).map(decodeURIComponent).join('/');

  // Construct URL to DID Document
  let url: string;
  if (path) {
    // did:web:example.com:user:alice -> https://example.com/user/alice/did.json
    url = `https://${domain}/${path}/did.json`;
  } else {
    // did:web:example.com -> https://example.com/.well-known/did.json
    url = `https://${domain}/.well-known/did.json`;
  }

  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/did+json, application/json',
      },
      // Set reasonable timeout
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to resolve did:web: HTTP ${response.status} from ${url}`,
        502
      );
    }

    const didDocument = await response.json() as DIDDocument;

    // Validate that the DID in the document matches the requested DID
    if (didDocument.id !== did) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `DID document ID mismatch: expected ${did}, got ${didDocument.id}`,
        400
      );
    }

    return didDocument;
  } catch (error) {
    if (error instanceof CapabilityError) {
      throw error;
    }

    throw new CapabilityError(
      ErrorCode.AUTHENTICATION_FAILED,
      `Failed to resolve did:web ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      502
    );
  }
}

// ---------------------------------------------------------------------------
// Base58btc helpers (used by did:key resolution)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Decode a base58btc string (without multibase prefix) to a byte array.
 */
function decodeBase58Btc(encoded: string): Uint8Array {
  let value = 0n;
  for (const char of encoded) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx < 0) {
      throw new Error(`Invalid base58btc character: '${char}'`);
    }
    value = value * 58n + BigInt(idx);
  }

  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }

  // Leading '1' characters each represent a zero byte
  for (const char of encoded) {
    if (char === '1') {
      bytes.unshift(0);
    } else {
      break;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Encode a byte array to a base58btc string (without multibase prefix).
 */
function encodeBase58Btc(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }

  let encoded = '';
  while (value > 0n) {
    encoded = BASE58_ALPHABET[Number(value % 58n)] + encoded;
    value /= 58n;
  }

  // Prepend '1' for each leading zero byte
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = '1' + encoded;
    } else {
      break;
    }
  }

  return encoded;
}

/**
 * Read an unsigned varint from a byte array at the given offset.
 * Returns [value, bytesConsumed].
 */
function readVarint(bytes: Uint8Array, offset: number = 0): [number, number] {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;
  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    if (byte === undefined) {
      break;
    }
    bytesRead++;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if (!(byte & 0x80)) {
      break;
    }
  }
  return [value, bytesRead];
}

// ---------------------------------------------------------------------------
// Elliptic-curve helpers (used by did:key P-256 and secp256k1 resolution)
// ---------------------------------------------------------------------------

/**
 * Modular exponentiation using BigInt arithmetic.
 */
function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) {
      result = (result * b) % mod;
    }
    e /= 2n;
    b = (b * b) % mod;
  }
  return result;
}

/**
 * Decompress a P-256 (secp256r1) compressed public key to (x, y) BigInt coordinates.
 */
function decompressP256(compressed: Uint8Array): { x: bigint; y: bigint } {
  const prefix = compressed[0];
  const x = BigInt('0x' + Buffer.from(compressed.slice(1)).toString('hex'));

  // P-256 curve parameters (NIST P-256 / secp256r1)
  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const a = p - 3n; // -3 mod p
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

  // y² = x³ + ax + b mod p
  const x3 = (x * x % p) * x % p;
  const ax = (a * x) % p;
  const y2 = (x3 + ax + b) % p;

  // Square root via Tonelli–Shanks shortcut: p ≡ 3 (mod 4) → y = y²^((p+1)/4) mod p
  const y = modpow(y2, (p + 1n) / 4n, p);

  // Select the root with the correct parity (prefix 0x02 → even, 0x03 → odd)
  const yFinal = (prefix === 0x02)
    ? (y % 2n === 0n ? y : p - y)
    : (y % 2n === 1n ? y : p - y);

  return { x, y: yFinal };
}

/**
 * Decompress a secp256k1 compressed public key to (x, y) BigInt coordinates.
 */
function decompressSecp256k1(compressed: Uint8Array): { x: bigint; y: bigint } {
  const prefix = compressed[0];
  const x = BigInt('0x' + Buffer.from(compressed.slice(1)).toString('hex'));

  // secp256k1 curve parameters
  const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const b = 7n; // a = 0

  // y² = x³ + 7 mod p
  const x3 = (x * x % p) * x % p;
  const y2 = (x3 + b) % p;

  // p ≡ 3 (mod 4) → y = y²^((p+1)/4) mod p
  const y = modpow(y2, (p + 1n) / 4n, p);

  const yFinal = (prefix === 0x02)
    ? (y % 2n === 0n ? y : p - y)
    : (y % 2n === 1n ? y : p - y);

  return { x, y: yFinal };
}

/**
 * Encode a BigInt as a zero-padded, base64url-encoded byte string of `length` bytes.
 */
function bigintToBase64Url(n: bigint, length: number): string {
  const hex = n.toString(16).padStart(length * 2, '0');
  return Buffer.from(hex, 'hex').toString('base64url');
}

// ---------------------------------------------------------------------------
// did:ion resolver
// ---------------------------------------------------------------------------

/**
 * Resolve did:ion to DID Document via the public ION resolver.
 *
 * ION is a Sidetree-based DID network anchored on Bitcoin.
 * Reference: https://identity.foundation/ion/
 *
 * Uses the Microsoft ION resolver REST API:
 * https://ion.msidentity.com/api/v1.0/identifiers/{did}
 */
export async function resolveDidIon(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:ion:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:ion identifier: ${did}`,
      400
    );
  }

  const resolverUrl = `https://ion.msidentity.com/api/v1.0/identifiers/${encodeURIComponent(did)}`;

  try {
    const response = await fetch(resolverUrl, {
      headers: {
        'Accept': 'application/did+json, application/json',
      },
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to resolve did:ion: HTTP ${response.status} from ION resolver`,
        502
      );
    }

    // The ION resolver wraps the DID Document in a resolution result object:
    // { "@context": ..., "didDocument": { ... }, "didDocumentMetadata": { ... } }
    const result = await response.json() as { didDocument?: DIDDocument } & DIDDocument;
    const didDocument: DIDDocument = result.didDocument ?? result;

    if (!didDocument.id) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'ION resolver returned an invalid response: missing DID document id',
        502
      );
    }

    if (didDocument.id !== did) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `DID document ID mismatch: expected ${did}, got ${didDocument.id}`,
        400
      );
    }

    return didDocument;
  } catch (error) {
    if (error instanceof CapabilityError) {
      throw error;
    }

    throw new CapabilityError(
      ErrorCode.AUTHENTICATION_FAILED,
      `Failed to resolve did:ion ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      502
    );
  }
}

/**
 * Resolve did:key to DID Document
 *
 * did:key is a self-contained DID method that encodes the public key in the DID itself
 * using multibase (base58btc) and multicodec encoding.
 * Reference: https://w3c-ccg.github.io/did-method-key/
 *
 * Supported key types:
 * - Ed25519  (multicodec 0xed)
 * - P-256    (multicodec 0x1200)
 * - secp256k1 (multicodec 0xe7)
 */
export async function resolveDidKey(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:key:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:key identifier: ${did}`,
      400
    );
  }

  const identifier = did.substring('did:key:'.length);

  // The identifier is multibase-encoded; 'z' prefix = base58btc
  if (!identifier.startsWith('z')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Unsupported multibase encoding in did:key '${identifier}'. Only base58btc (prefix 'z') is supported.`,
      400
    );
  }

  // Decode the base58btc-encoded key material (strip the 'z' multibase prefix)
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58Btc(identifier.substring(1));
  } catch (e) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Failed to decode did:key identifier: ${e instanceof Error ? e.message : 'Unknown error'}`,
      400
    );
  }

  // Parse the multicodec varint prefix to determine the key type
  const [codec, headerLen] = readVarint(decoded, 0);
  const keyBytes = decoded.slice(headerLen);

  // Verification method ID follows the did:key spec: did#identifier
  const vmId = `${did}#${identifier}`;

  let verificationMethod: VerificationMethod;

  switch (codec) {
    case 0xed: {
      // Ed25519 public key (32 bytes)
      if (keyBytes.length !== 32) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Invalid Ed25519 key length in did:key: expected 32 bytes, got ${keyBytes.length}`,
          400
        );
      }
      verificationMethod = {
        id: vmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: Buffer.from(keyBytes).toString('base64url'),
          alg: 'EdDSA',
        },
      };
      break;
    }

    case 0x1200: {
      // P-256 / secp256r1 compressed public key (33 bytes: 0x02/0x03 prefix + 32-byte x)
      if (keyBytes.length !== 33) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Invalid P-256 compressed key length in did:key: expected 33 bytes, got ${keyBytes.length}`,
          400
        );
      }
      const { x, y } = decompressP256(keyBytes);
      verificationMethod = {
        id: vmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: bigintToBase64Url(x, 32),
          y: bigintToBase64Url(y, 32),
          alg: 'ES256',
        },
      };
      break;
    }

    case 0xe7: {
      // secp256k1 compressed public key (33 bytes)
      if (keyBytes.length !== 33) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Invalid secp256k1 compressed key length in did:key: expected 33 bytes, got ${keyBytes.length}`,
          400
        );
      }
      const { x, y } = decompressSecp256k1(keyBytes);
      verificationMethod = {
        id: vmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'EC',
          crv: 'secp256k1',
          x: bigintToBase64Url(x, 32),
          y: bigintToBase64Url(y, 32),
          alg: 'ES256K',
        },
      };
      break;
    }

    default:
      throw new CapabilityError(
        ErrorCode.NOT_IMPLEMENTED,
        `Unsupported did:key codec 0x${codec.toString(16)}. ` +
          'Supported key types: Ed25519 (0xed), P-256 (0x1200), secp256k1 (0xe7).',
        501
      );
  }

  const didDocument: DIDDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [vmId],
    assertionMethod: [vmId],
    capabilityInvocation: [vmId],
    capabilityDelegation: [vmId],
  };

  return didDocument;
}

// Export the base58btc encoder so callers can construct did:key DIDs from raw key bytes.
export { encodeBase58Btc };

/**
 * Find a verification method in a DID Document by key ID
 *
 * @param didDocument The DID Document to search
 * @param keyId Optional key ID fragment (e.g., "key-1"). If not provided, returns first verification method
 * @returns The verification method, or null if not found
 */
export function findVerificationMethod(
  didDocument: DIDDocument,
  keyId?: string
): VerificationMethod | null {
  if (!didDocument.verificationMethod || didDocument.verificationMethod.length === 0) {
    return null;
  }

  if (!keyId) {
    // Return the first verification method
    const first = didDocument.verificationMethod[0];
    return first || null;
  }

  // Construct full key ID if needed
  const fullKeyId = keyId.includes('#') ? keyId : `${didDocument.id}#${keyId}`;

  // Search for the verification method, normalizing fragment-only IDs
  const vm = didDocument.verificationMethod.find(vm => {
    const normalizedId = vm.id.startsWith('#')
      ? `${didDocument.id}${vm.id}`
      : vm.id;
    return normalizedId === fullKeyId;
  });
  if (!vm) {
    return null;
  }
  return vm;
}

/**
 * Extract public key from verification method in PEM format.
 *
 * Supports:
 * - `publicKeyPem`: returned as-is
 * - `publicKeyJwk`: converted to SubjectPublicKeyInfo PEM via `jose`
 *
 * @param verificationMethod The verification method containing the public key
 * @returns Public key in PEM (SubjectPublicKeyInfo) format
 */
export async function extractPublicKeyPem(verificationMethod: VerificationMethod): Promise<string> {
  // Already in PEM format – return directly
  if (verificationMethod.publicKeyPem) {
    return verificationMethod.publicKeyPem;
  }

  // Convert JWK to SPKI PEM using jose
  if (verificationMethod.publicKeyJwk) {
    // Use the alg field from the JWK when present; otherwise let jose infer it
    const alg = verificationMethod.publicKeyJwk.alg;
    const keyLike = await jose.importJWK(verificationMethod.publicKeyJwk as jose.JWK, alg);
    return await jose.exportSPKI(keyLike as jose.KeyLike);
  }

  // Unsupported key format
  throw new CapabilityError(
    ErrorCode.NOT_IMPLEMENTED,
    `Public key format not supported for verification method type: ${verificationMethod.type}`,
    501
  );
}

/**
 * Determine the JWT signing algorithm from a verification method
 *
 * @param verificationMethod The verification method
 * @returns The JWT algorithm (e.g., 'RS256', 'ES256')
 */
export function determineSigningAlgorithm(verificationMethod: VerificationMethod): string {
  // Check JWK first
  if (verificationMethod.publicKeyJwk?.alg) {
    return verificationMethod.publicKeyJwk.alg;
  }

  // Infer from verification method type
  const type = verificationMethod.type;

  if (type.includes('RsaVerificationKey') || type.includes('JsonWebKey2020')) {
    if (verificationMethod.publicKeyJwk?.kty === 'RSA') {
      return 'RS256'; // Default RSA algorithm
    }
    if (verificationMethod.publicKeyJwk?.kty === 'EC') {
      // Determine based on curve
      const crv = verificationMethod.publicKeyJwk.crv;
      if (crv === 'P-256') return 'ES256';
      if (crv === 'P-384') return 'ES384';
      if (crv === 'P-521') return 'ES512';
      if (crv === 'secp256k1') return 'ES256K';
    }
  }

  if (type.includes('Ed25519')) {
    return 'EdDSA';
  }

  if (type.includes('EcdsaSecp256k1')) {
    return 'ES256K';
  }

  // No algorithm could be inferred — fail closed to prevent misuse
  throw new CapabilityError(
    ErrorCode.INVALID_REQUEST,
    `Cannot determine signing algorithm for verification method type: ${type}. ` +
      'Ensure the DID Document provides explicit alg in publicKeyJwk or uses a recognised key type.',
    400
  );
}

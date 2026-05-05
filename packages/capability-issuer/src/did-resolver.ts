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
 * Runtime options that influence DID resolution behaviour.  Pass these
 * through from boot-time validated config so resolver functions do not
 * need to read `process.env` directly.
 */
export interface DidResolverOptions {
  /**
   * Pre-parsed HTTP allow-list for did:web.  When provided, any host[:port]
   * in the set is fetched over plain HTTP instead of HTTPS.
   * Construct via {@link parseDidWebHttpAllowList} at service boot and pass
   * through from the validated config — do not read `process.env` at call
   * time.
   */
  httpAllowList?: Set<string>;
  /**
   * Explicit did:ion resolver base URL.  When provided, overrides the
   * compiled-in default (`https://ion.msidentity.com/api/v1.0/identifiers`).
   * Pass from the validated config (`cfg.ION_RESOLVER_URL`) at boot.
   */
  ionResolverUrl?: string;
}

/**
 * Resolve a DID to its DID Document
 * Supports did:web and did:ion methods
 */
export async function resolveDID(did: string, opts?: DidResolverOptions): Promise<DIDDocument> {
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
      return await resolveDidWeb(did, opts?.httpAllowList);
    case 'ion':
      return await resolveDidIon(did, opts?.ionResolverUrl);
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
 * Parse the comma-separated `DID_WEB_ALLOW_HTTP_FOR_HOSTS` allow-list into
 * a Set of lower-cased host[:port] entries. Empty / unset values yield an
 * empty set (the default — fail closed).
 *
 * Exported only for unit tests.
 */
export function parseDidWebHttpAllowList(raw: string | undefined): Set<string> {
  if (!raw) {
    return new Set();
  }
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0)
  );
}

/**
 * Resolve did:web to DID Document
 *
 * did:web method specification:
 * - did:web:example.com -> https://example.com/.well-known/did.json
 * - did:web:example.com:user:alice -> https://example.com/user/alice/did.json
 * - Custom ports are encoded into the host label as %3A, for example
 *   did:web:partner-sim.local%3A4001 -> https://partner-sim.local:4001/.well-known/did.json
 *
 * Reference: https://w3c-ccg.github.io/did-method-web/
 *
 * **Test-mode HTTP exception (cross-org harness, gap #5):**
 * The default behaviour is HTTPS-only — production DID resolution MUST go
 * over TLS. For local docker-compose / CI harnesses that cannot terminate
 * TLS, pass an explicit `httpAllowList` (built via `parseDidWebHttpAllowList`
 * from the validated config): any host[:port] in the set will be fetched over
 * plain HTTP. Hosts NOT in the set still go over HTTPS. Omitting the argument
 * means "no exceptions" (fail-closed).
 */
export async function resolveDidWeb(did: string, httpAllowList?: Set<string>): Promise<DIDDocument> {
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

  // Decide HTTP vs HTTPS. Default is HTTPS — the allow-list is opt-in.
  // Production deployments that never supply an httpAllowList use HTTPS for
  // all did:web resolution (fail-closed). Callers should build the allow-list
  // from the validated config via parseDidWebHttpAllowList() at boot and pass
  // it through DidResolverOptions / PartnerIssuerResolverOptions.
  const resolvedAllowList = httpAllowList ?? new Set<string>();
  const scheme = resolvedAllowList.has(domain.toLowerCase()) ? 'http' : 'https';

  // Construct URL to DID Document
  let url: string;
  if (path) {
    // did:web:example.com:user:alice -> https://example.com/user/alice/did.json
    url = `${scheme}://${domain}/${path}/did.json`;
  } else {
    // did:web:example.com -> https://example.com/.well-known/did.json
    url = `${scheme}://${domain}/.well-known/did.json`;
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
 *
 * Uses BigInt arithmetic (no bitwise shifts) to avoid JS 32-bit wrap-around
 * on large values. Rejects inputs with more than 10 continuation bytes or
 * values that exceed Number.MAX_SAFE_INTEGER.
 */
function readVarint(bytes: Uint8Array, offset: number = 0): [number, number] {
  let value = 0n;
  let factor = 1n;
  let bytesRead = 0;
  const maxVarintBytes = 10;
  const maxSafeInteger = BigInt(Number.MAX_SAFE_INTEGER);

  while (offset + bytesRead < bytes.length) {
    if (bytesRead >= maxVarintBytes) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Invalid did:key: varint exceeds maximum length',
        400
      );
    }

    const byte = bytes[offset + bytesRead];
    if (byte === undefined) {
      break;
    }
    bytesRead++;
    value += BigInt(byte & 0x7f) * factor;

    if (value > maxSafeInteger) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Invalid did:key: varint value exceeds supported range',
        400
      );
    }

    if ((byte & 0x80) === 0) {
      return [Number(value), bytesRead];
    }

    factor *= 128n;
  }

  throw new CapabilityError(
    ErrorCode.INVALID_REQUEST,
    'Invalid did:key: unterminated varint sequence',
    400
  );
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
    if (e & 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/**
 * Decompress a P-256 (secp256r1) compressed public key to (x, y) BigInt coordinates.
 * Validates the prefix byte and verifies the recovered point lies on the curve.
 */
function decompressP256(compressed: Uint8Array): { x: bigint; y: bigint } {
  const prefix = compressed[0];

  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Invalid compressed P-256 key prefix 0x${prefix?.toString(16) ?? '??'}: expected 0x02 or 0x03`,
      400
    );
  }

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

  // Verify the point is on the curve (y² ≡ y2 mod p)
  if ((y * y) % p !== y2) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Invalid P-256 compressed key: x coordinate does not correspond to a point on the curve',
      400
    );
  }

  // Select the root with the correct parity (prefix 0x02 → even, 0x03 → odd)
  const yFinal = (prefix === 0x02)
    ? (y % 2n === 0n ? y : p - y)
    : (y % 2n === 1n ? y : p - y);

  return { x, y: yFinal };
}

/**
 * Decompress a secp256k1 compressed public key to (x, y) BigInt coordinates.
 * Validates the prefix byte and verifies the recovered point lies on the curve.
 */
function decompressSecp256k1(compressed: Uint8Array): { x: bigint; y: bigint } {
  const prefix = compressed[0];

  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Invalid compressed secp256k1 key prefix 0x${prefix?.toString(16) ?? '??'}: expected 0x02 or 0x03`,
      400
    );
  }

  const x = BigInt('0x' + Buffer.from(compressed.slice(1)).toString('hex'));

  // secp256k1 curve parameters
  const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const b = 7n; // a = 0

  // y² = x³ + 7 mod p
  const x3 = (x * x % p) * x % p;
  const y2 = (x3 + b) % p;

  // p ≡ 3 (mod 4) → y = y²^((p+1)/4) mod p
  const y = modpow(y2, (p + 1n) / 4n, p);

  // Verify the point is on the curve (y² ≡ y2 mod p)
  if ((y * y) % p !== y2) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Invalid secp256k1 compressed key: x coordinate does not correspond to a point on the curve',
      400
    );
  }

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

/** Timeout in milliseconds for the ION resolver HTTP request. */
const ION_RESOLVER_TIMEOUT_MS = 15000;

/**
 * Default ION resolver endpoint (Microsoft public resolver).
 * Override by passing `resolverBaseUrl` (sourced from `cfg.ION_RESOLVER_URL`)
 * to {@link resolveDidIon} so deployments running their own ION node can
 * point at it without reading process.env at call time.
 */
const DEFAULT_ION_RESOLVER_URL = 'https://ion.msidentity.com/api/v1.0/identifiers';

/**
 * Resolve did:ion to DID Document via an ION resolver REST API.
 *
 * ION is a Sidetree-based DID network anchored on Bitcoin.
 * Reference: https://identity.foundation/ion/
 *
 * Defaults to the public Microsoft resolver
 * (https://ion.msidentity.com/api/v1.0/identifiers/{did}); pass an explicit
 * `resolverBaseUrl` (from the validated config) to use a self-hosted node.
 *
 * Errors are categorised so callers (and operators reading the logs) can
 * distinguish:
 *   - validation failures (bad DID format)               → 400 INVALID_REQUEST
 *   - the DID does not exist                             → 404 INVALID_TOKEN
 *   - resolver timeout / DNS / connection refused / TLS  → 504 / 502 AUTHENTICATION_FAILED
 *   - resolver 5xx                                       → 502 AUTHENTICATION_FAILED
 *   - resolver 4xx (other than 404)                      → 502 AUTHENTICATION_FAILED
 *   - DID document content invalid                       → 502 / 400
 */
export async function resolveDidIon(did: string, resolverBaseUrl?: string): Promise<DIDDocument> {
  if (!did.startsWith('did:ion:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:ion identifier: ${did}`,
      400
    );
  }

  // Prefer the explicitly-supplied URL (from validated boot config) over the
  // compiled-in default so that library consumers and deployments with
  // self-hosted ION can override without touching process.env.
  const rawBase = resolverBaseUrl ?? DEFAULT_ION_RESOLVER_URL;
  // Trim trailing slashes without a backtracking regex (avoids ReDoS on
  // adversarial inputs derived from library consumers).
  let trimEnd = rawBase.length;
  while (trimEnd > 0 && rawBase[trimEnd - 1] === '/') trimEnd--;
  const resolverBase = rawBase.slice(0, trimEnd);
  const resolverUrl = `${resolverBase}/${encodeURIComponent(did)}`;

  let response: Response;
  try {
    response = await fetch(resolverUrl, {
      headers: {
        'Accept': 'application/did+json, application/json',
      },
      signal: AbortSignal.timeout(ION_RESOLVER_TIMEOUT_MS),
    });
  } catch (error) {
    // Network-layer failures: timeout, DNS, ECONNREFUSED, TLS, etc.
    // Distinguish them so operators can act on the right thing.
    const message = error instanceof Error ? error.message : 'Unknown network error';
    const name = error instanceof Error ? error.name : '';
    const code = (error as { code?: string } | undefined)?.code;

    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `ION resolver request timed out after ${ION_RESOLVER_TIMEOUT_MS}ms (resolver=${resolverBase}): ${message}`,
        504
      );
    }

    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `ION resolver DNS lookup failed (resolver=${resolverBase}): ${message}. ` +
        'Check the ION_RESOLVER_URL config value and network egress configuration.',
        502
      );
    }

    if (code === 'ECONNREFUSED' || code === 'ECONNRESET') {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `ION resolver connection failed (resolver=${resolverBase}): ${message}. ` +
        'The resolver may be down or unreachable from this environment.',
        502
      );
    }

    throw new CapabilityError(
      ErrorCode.AUTHENTICATION_FAILED,
      `Failed to contact ION resolver (resolver=${resolverBase}): ${message}`,
      502
    );
  }

  if (response.status === 404) {
    // Per the DID resolution spec, 404 means the DID is not registered.
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `did:ion identifier not found: ${did}`,
      404
    );
  }

  if (!response.ok) {
    // Differentiate between caller-side problems (4xx, e.g. 400/410) and
    // resolver-side problems (5xx) for clearer operational signal.
    const category = response.status >= 500 ? 'resolver error' : 'request rejected by resolver';
    throw new CapabilityError(
      ErrorCode.AUTHENTICATION_FAILED,
      `Failed to resolve did:ion (${category}): HTTP ${response.status} ${response.statusText} from ${resolverBase}`,
      502
    );
  }

  let result: { didDocument?: DIDDocument } & DIDDocument;
  try {
    // The ION resolver wraps the DID Document in a resolution result object:
    // { "@context": ..., "didDocument": { ... }, "didDocumentMetadata": { ... } }
    result = await response.json() as { didDocument?: DIDDocument } & DIDDocument;
  } catch (error) {
    throw new CapabilityError(
      ErrorCode.AUTHENTICATION_FAILED,
      `ION resolver returned a malformed JSON response: ${error instanceof Error ? error.message : 'Unknown error'}`,
      502
    );
  }

  const didDocument: DIDDocument = result.didDocument ?? result;

  if (!didDocument || !didDocument.id) {
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

  // Guard against excessively long identifiers to prevent CPU DoS in decodeBase58Btc()
  // Longest valid key (P-256/secp256k1, 33 bytes) encodes to ~50 base58 chars; 256 is generous
  const base58Str = identifier.substring(1);
  if (base58Str.length > 256) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `did:key identifier is too long (${base58Str.length} chars; max 256)`,
      400
    );
  }

  // Decode the base58btc-encoded key material (strip the 'z' multibase prefix)
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58Btc(base58Str);
  } catch (e) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Failed to decode did:key identifier: ${e instanceof Error ? e.message : 'Unknown error'}`,
      400
    );
  }

  // Require at least 2 bytes (1+ byte varint + 1 byte key material)
  if (decoded.length < 2) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Invalid did:key: missing multicodec prefix or key material',
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
    try {
      // Use the alg field from the JWK when present; otherwise derive from the verification method
      const alg = verificationMethod.publicKeyJwk.alg || determineSigningAlgorithm(verificationMethod);
      const keyLike = await jose.importJWK(verificationMethod.publicKeyJwk as jose.JWK, alg);
      return await jose.exportSPKI(keyLike as jose.KeyLike);
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Invalid or unsupported publicKeyJwk in verification method',
        400
      );
    }
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

/**
 * DID Resolution Utilities
 *
 * Implements W3C DID resolution for did:web and did:ion methods
 * Reference: https://www.w3.org/TR/did-core/
 */

import { CapabilityError, ErrorCode } from '@euno/common';

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

/**
 * Resolve did:ion to DID Document
 *
 * ION is a Layer 2 DID network built on Bitcoin
 * Reference: https://identity.foundation/ion/
 *
 * TODO: This is a placeholder. Full implementation requires:
 * - ION node endpoint or REST API access
 * - Sidetree resolution protocol
 */
export async function resolveDidIon(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:ion:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:ion identifier: ${did}`,
      400
    );
  }

  // For now, throw not implemented
  // Future implementation would query ION resolver:
  // - https://ion.msidentity.com/api/v1.0/identifiers/{did}
  // - Or local ION node
  throw new CapabilityError(
    ErrorCode.NOT_IMPLEMENTED,
    'did:ion resolution not yet implemented. Please use did:web for now.',
    501
  );
}

/**
 * Resolve did:key to DID Document
 *
 * did:key is a self-contained DID method that encodes the public key in the DID itself
 * Reference: https://w3c-ccg.github.io/did-method-key/
 *
 * TODO: This is a placeholder. Full implementation requires:
 * - Multibase/Multicodec decoding
 * - Key type detection and JWK conversion
 */
export async function resolveDidKey(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:key:')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Not a did:key identifier: ${did}`,
      400
    );
  }

  // For now, throw not implemented
  // Future implementation would:
  // 1. Decode the multibase-encoded public key from DID
  // 2. Construct a minimal DID Document with the key
  throw new CapabilityError(
    ErrorCode.NOT_IMPLEMENTED,
    'did:key resolution not yet implemented. Please use did:web for now.',
    501
  );
}

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
 * Extract public key from verification method in PEM format
 *
 * @param verificationMethod The verification method containing the public key
 * @returns Public key in PEM format
 */
export function extractPublicKeyPem(verificationMethod: VerificationMethod): string {
  // If already in PEM format, return it
  if (verificationMethod.publicKeyPem) {
    return verificationMethod.publicKeyPem;
  }

  // If in JWK format, we need to convert to PEM
  if (verificationMethod.publicKeyJwk) {
    // For now, throw an error. Full implementation would convert JWK to PEM
    // This would require crypto libraries to perform the conversion
    throw new CapabilityError(
      ErrorCode.NOT_IMPLEMENTED,
      'JWK to PEM conversion not yet implemented. Please use publicKeyPem in DID Document.',
      501
    );
  }

  // If in other formats, not supported yet
  throw new CapabilityError(
    ErrorCode.NOT_IMPLEMENTED,
    `Public key format not supported: ${verificationMethod.type}`,
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

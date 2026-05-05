/**
 * Issuance — signer pipeline.
 *
 * Drives the {@link TokenSigner} adapter for both fresh issuance and
 * the verify-then-resign flows used by attenuation and renewal. Owns:
 *
 *  - the algorithm allow-list ({@link ALLOWED_SIGNING_ALGORITHMS}),
 *  - parent-token decode + signature verification with mapped errors,
 *  - delegation to the configured signer for the JWS.
 *
 * Extracted from `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  CapabilityError,
  CapabilityTokenPayload,
  ErrorCode,
  IssuanceContext,
  SIGNING_ALGORITHMS,
  TokenSigner,
} from '@euno/common';
import * as jose from 'jose';

/** Algorithms permitted for capability token signatures. Sourced from
 *  the shared {@link SIGNING_ALGORITHMS} tuple so this allow-list cannot
 *  drift from the {@link SigningAlgorithm} type. */
export const ALLOWED_SIGNING_ALGORITHMS = SIGNING_ALGORITHMS;

/**
 * Sign a capability-token payload with the configured signer.
 *
 * Threads the optional {@link IssuanceContext} through to the signer so
 * KMS back-ends (AWS, Azure Key Vault, GCP Cloud KMS) can scope the signing
 * operation to a pre-authorised grant or key version for the current policy
 * boundary.  Callers that do not (yet) construct an {@link IssuanceContext}
 * may omit it — signers treat `undefined` as an unconstrained sign, which
 * preserves full backward compatibility.
 *
 * Thin wrapper kept for symmetry with {@link verifyParentToken} so
 * the orchestrator never imports the raw signer directly.
 */
export async function signPayload(
  signer: TokenSigner,
  payload: CapabilityTokenPayload,
  context?: IssuanceContext,
): Promise<string> {
  return signer.sign(payload, context);
}

/**
 * Verify a parent capability token (used by attenuation and renewal)
 * and return its decoded payload.
 *
 * - Decodes the JWS header first so malformed tokens fail fast with
 *   `INVALID_TOKEN`.
 * - Rejects algorithms not in {@link ALLOWED_SIGNING_ALGORITHMS} to
 *   prevent algorithm-confusion attacks.
 * - Imports the issuer's public key with the asserted algorithm.
 * - Verifies signature, issuer, and audience via `jose.jwtVerify`.
 * - Maps `jose` error codes to {@link CapabilityError} so callers can
 *   surface 401/403/expired errors consistently.
 */
export async function verifyParentToken(
  signer: TokenSigner,
  parentToken: string,
  expected: { issuer: string; audience: string },
  malformedTokenMessage: string,
): Promise<CapabilityTokenPayload> {
  let algorithm: string;
  try {
    const header = jose.decodeProtectedHeader(parentToken);
    algorithm = header.alg ?? 'RS256';
  } catch {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      malformedTokenMessage,
      401,
    );
  }

  if (!ALLOWED_SIGNING_ALGORITHMS.includes(algorithm as (typeof ALLOWED_SIGNING_ALGORITHMS)[number])) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `Token uses disallowed algorithm: ${algorithm}`,
      401,
    );
  }

  const publicKey = await signer.getPublicKey();
  const publicKeyObj = await jose.importSPKI(publicKey, algorithm);

  const { payload } = await jose.jwtVerify(parentToken, publicKeyObj, {
    issuer: expected.issuer,
    audience: expected.audience,
    algorithms: [algorithm],
  });

  return payload as unknown as CapabilityTokenPayload;
}

/**
 * Map a low-level error caught while verifying a parent token to the
 * appropriate {@link CapabilityError}. Re-throws {@link CapabilityError}
 * unchanged. Used by attenuation and renewal so the same `jose` error
 * codes are translated identically in both places.
 *
 * `expiredMessage` and `invalidMessagePrefix` let each call site keep
 * its current user-facing wording (e.g. "Parent capability token has
 * expired" vs "Capability token has expired; re-authentication is
 * required").
 */
export function mapVerifyError(
  error: unknown,
  expiredMessage: string,
  invalidMessagePrefix: string,
): never {
  if (error instanceof CapabilityError) throw error;

  if (error instanceof Error && (error as { code?: string }).code === 'ERR_JWT_EXPIRED') {
    throw new CapabilityError(ErrorCode.EXPIRED_TOKEN, expiredMessage, 401);
  }

  if (
    error instanceof Error &&
    ((error as { code?: string }).code === 'ERR_JWS_INVALID' ||
      (error as { code?: string }).code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' ||
      (error as { code?: string }).code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED')
  ) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `${invalidMessagePrefix}: ${error.message}`,
      401,
    );
  }

  throw error;
}

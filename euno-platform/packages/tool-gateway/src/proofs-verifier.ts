/**
 * ProofsVerifier — gateway-side verification of multi-issuer trust proofs.
 * ---------------------------------------------------------------------------
 * Hooks into the {@link JWTTokenVerifier.performPostVerificationChecks}
 * pipeline. After a token's primary signature has been verified, this
 * module checks the optional `proofs` claim:
 *
 *   - cosignatures (`proofs.cosig[]`) — counter-signatures from independent
 *     authorities. The gateway requires at least
 *     `REQUIRE_COSIGNATURE_COUNT` valid cosignatures (default 0 → off);
 *   - SCTs (`proofs.sct[]`) — Signed Certificate Timestamps from
 *     transparency logs. When `REQUIRE_TRANSPARENCY_LOG_PROOF=true`, at
 *     least one SCT MUST verify against a trusted log key.
 *
 * Defaults are off (`REQUIRE_COSIGNATURE_COUNT=0`,
 * `REQUIRE_TRANSPARENCY_LOG_PROOF=false`) so this is a strict opt-in
 * defence; deployments that have not yet rolled out the cosigner or
 * transparency-log infrastructure continue to work unchanged.
 *
 * Strict-mode rejections raise {@link CapabilityError} with
 * {@link ErrorCode.INVALID_TOKEN} (HTTP 401) so the failure surfaces the
 * same way as any other signature failure.
 */

import {
  buildIssuanceReceipt,
  CapabilityError,
  CapabilityTokenPayload,
  ErrorCode,
  JwkSet,
  Logger,
  ProofsVerificationResult,
  verifyIssuanceProofs,
} from '@euno/common';

/**
 * Configuration for {@link ProofsVerifier}. All fields are optional so the
 * verifier degrades to a no-op when neither cosignatures nor SCTs are
 * required (default deployment).
 */
export interface ProofsVerifierConfig {
  /**
   * Minimum number of valid cosignatures the gateway requires on every
   * token. `0` (default) disables cosignature enforcement. When `> 0`,
   * tokens whose `proofs.cosig[]` does not yield at least this many valid
   * signatures (against {@link cosignerJwks}) are rejected with
   * {@link ErrorCode.INVALID_TOKEN}.
   */
  requireCosignatureCount: number;
  /**
   * Trusted cosigner public keys, indexed by `kid`. Required when
   * {@link requireCosignatureCount} is `> 0`. Loaded from a JWKS file or
   * URL on the gateway side — see `COSIGNER_JWKS_FILE` /
   * `COSIGNER_JWKS_URL` in the gateway env-config schema.
   */
  cosignerJwks?: JwkSet;
  /**
   * When `true`, every token MUST carry at least one SCT that verifies
   * against a trusted transparency-log key. Default `false`.
   */
  requireTransparencyLogProof: boolean;
  /**
   * Trusted transparency-log JWKS, keyed by `logId`. Required when
   * {@link requireTransparencyLogProof} is `true`. The verifier rejects
   * SCTs whose `logId` is not present in this map (a token bearing an
   * SCT from an unknown log is treated as no SCT at all).
   */
  logJwksByLogId?: Map<string, JwkSet>;
  /**
   * Optional logger for structured audit messages emitted on every
   * proof-verification failure. Falls back to silent on `undefined`.
   */
  logger?: Logger;
}

/**
 * Stateless verifier — holds only the trust configuration. Safe to share
 * across requests.
 */
export class ProofsVerifier {
  private readonly cfg: ProofsVerifierConfig;

  constructor(cfg: ProofsVerifierConfig) {
    if (cfg.requireCosignatureCount < 0 || !Number.isInteger(cfg.requireCosignatureCount)) {
      throw new Error(
        `ProofsVerifier: requireCosignatureCount must be a non-negative integer, got ${cfg.requireCosignatureCount}`,
      );
    }
    if (cfg.requireCosignatureCount > 0 && !cfg.cosignerJwks) {
      throw new Error(
        'ProofsVerifier: cosignerJwks is required when requireCosignatureCount > 0',
      );
    }
    if (cfg.requireTransparencyLogProof && (!cfg.logJwksByLogId || cfg.logJwksByLogId.size === 0)) {
      throw new Error(
        'ProofsVerifier: logJwksByLogId is required (non-empty) when requireTransparencyLogProof=true',
      );
    }
    this.cfg = cfg;
  }

  /**
   * Returns true when no proof-side enforcement is configured. Hot-path
   * helper so the verifier can short-circuit without recomputing the
   * receipt for the common "no proofs required" case.
   */
  isNoOp(): boolean {
    return this.cfg.requireCosignatureCount === 0 && !this.cfg.requireTransparencyLogProof;
  }

  /**
   * Verify the proofs (if any) carried by a token payload. Throws
   * {@link CapabilityError} when a required proof is missing or invalid.
   * No-op when {@link isNoOp} returns `true`.
   *
   * Even in no-op mode, a token that DOES carry proofs is still verified
   * opportunistically: this means an attacker cannot present a token with
   * a forged `proofs` claim and rely on the gateway to ignore it. Failures
   * on opportunistic verification are logged but not rejected, preserving
   * back-compat for partial rollouts where some tokens have proofs and
   * some do not.
   */
  async verify(payload: CapabilityTokenPayload): Promise<void> {
    const proofs = payload.proofs;

    // Hot-path short-circuit: no proofs configured AND token has no proofs
    // → nothing to do. Cheapest path.
    if (this.isNoOp() && !proofs) return;

    // Build the canonical receipt from the token's load-bearing claims.
    // Note: capabilities are required for the receipt; an attenuated /
    // renewed token still carries them. If `capabilities` is missing the
    // schema-version check has already caught it upstream.
    const receipt = buildIssuanceReceipt({
      iss: payload.iss,
      sub: payload.sub,
      aud: payload.aud,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
      capabilities: payload.capabilities,
    });

    let result: ProofsVerificationResult;
    try {
      result = await verifyIssuanceProofs(proofs, receipt, {
        ...(this.cfg.cosignerJwks ? { cosignerJwks: this.cfg.cosignerJwks } : {}),
        ...(this.cfg.logJwksByLogId ? { logJwksByLogId: this.cfg.logJwksByLogId } : {}),
      });
    } catch (err) {
      // verifyIssuanceProofs throws CapabilityError only for verifier-
      // misconfig (malformed JWK in the trust set). Surface that as a
      // 500-equivalent — the operator's gateway is misconfigured, not the
      // caller's fault.
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Issuance proofs verification failed due to gateway misconfiguration: ${err instanceof Error ? err.message : 'unknown'}`,
        500,
      );
    }

    // Strict-mode enforcement.
    if (this.cfg.requireCosignatureCount > 0 && result.validCosignatures < this.cfg.requireCosignatureCount) {
      this.cfg.logger?.warn('Token rejected: insufficient cosignatures', {
        jti: payload.jti,
        sub: payload.sub,
        iss: payload.iss,
        required: this.cfg.requireCosignatureCount,
        valid: result.validCosignatures,
        failures: result.failures,
      });
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Token requires at least ${this.cfg.requireCosignatureCount} valid cosignature(s); ${result.validCosignatures} verified`,
        401,
      );
    }
    if (this.cfg.requireTransparencyLogProof && result.validScts < 1) {
      this.cfg.logger?.warn('Token rejected: missing/invalid transparency-log proof', {
        jti: payload.jti,
        sub: payload.sub,
        iss: payload.iss,
        validScts: result.validScts,
        failures: result.failures,
      });
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Token does not carry a valid transparency-log inclusion proof (SCT)',
        401,
      );
    }

    // Opportunistic verification (no strict enforcement requested but the
    // token carries proofs that did not verify): log and continue. This
    // matters during partial rollouts so audit trails capture failed
    // proofs even before the gateway flips to strict mode.
    if (result.failures.length > 0 && this.cfg.logger) {
      this.cfg.logger.info('Token carries unverified issuance proofs (advisory)', {
        jti: payload.jti,
        sub: payload.sub,
        iss: payload.iss,
        failures: result.failures,
        validCosignatures: result.validCosignatures,
        validScts: result.validScts,
      });
    }
  }
}

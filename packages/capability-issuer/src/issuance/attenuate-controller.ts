/**
 * AttenuateController — thin handler for capability attenuation.
 *
 * Owns the endpoint-specific logic for the POST /api/v1/attenuate flow:
 *
 *   verify parent → rate limit → validate capability subset → validate
 *   conditions → compute expiry → build child payload → sign → audit
 *
 * All shared machinery (signing, rate limiting, proofs) is delegated to
 * the injected {@link MintingPipeline}.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  AuditLogEntry,
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  IssueCapabilityResponse,
  generateId,
  getCurrentTimestamp,
} from '@euno/common';
import { MintingPipeline } from './minting-pipeline';
import {
  buildAttenuatedPayload,
  buildIssuanceContext,
  mapVerifyError,
  validateCapabilitySubset,
  validateConditionsForCapabilities,
  verifyParentToken,
} from './index';

export interface AttenuateControllerOptions {
  /** Default TTL in seconds. Defaults to 900. */
  defaultTtl?: number;
}

/**
 * AttenuateController — handler for the attenuation endpoint.
 *
 * Accepts a valid, unexpired capability JWT and produces a child token
 * whose capabilities are a subset of the parent's. The child cannot
 * exceed the parent's expiry.
 */
export class AttenuateController {
  private readonly defaultTtl: number;

  constructor(
    private readonly pipeline: MintingPipeline,
    opts: AttenuateControllerOptions = {},
  ) {
    this.defaultTtl = opts.defaultTtl ?? 900;
  }

  /**
   * Attenuate an existing capability token. The child token will have
   * equal or fewer privileges than the parent.
   */
  async handle(
    parentToken: string,
    requestedCapabilities: CapabilityConstraint[],
    ttl?: number,
    enforcement?: { clientIp?: string },
  ): Promise<IssueCapabilityResponse> {
    try {
      this.pipeline.logger.info('Attenuating capability token');

      const parentPayload = await verifyParentToken(
        this.pipeline.signer,
        parentToken,
        { issuer: this.pipeline.issuerDid, audience: this.pipeline.gatewayAudience },
        'Invalid parent capability token format',
      );

      // Step 2: Validate parent token is not expired.
      const now = getCurrentTimestamp();
      if (parentPayload.exp < now) {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Parent capability token has expired',
          401,
        );
      }

      // Step 2a: Per-(tenantId, userId, agentId, jti, ip) rate limit for attenuation
      // (F-1). Shares the same bucket as fresh issuance and renewal so the
      // per-identity KMS budget covers all mint paths. Uses the parent token's
      // jti to scope the budget to this capability lineage.
      await this.pipeline.enforceRateLimit({
        tenantId: parentPayload.authorizedBy?.tenantId,
        userId: parentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: parentPayload.sub,
        jti: parentPayload.jti,
        ip: enforcement?.clientIp,
      });

      // Step 3: Validate requested capabilities are a subset of parent's.
      validateCapabilitySubset(parentPayload.capabilities, requestedCapabilities);

      // Step 3b: Validate the typed conditions on the attenuated set.
      validateConditionsForCapabilities(requestedCapabilities);

      // Step 4: Calculate expiration (cannot exceed parent's expiration).
      const requestedTTL = ttl ?? this.defaultTtl;
      const expiresAt = Math.min(now + requestedTTL, parentPayload.exp);

      // Step 5: Build and sign the child token.
      const tokenId = generateId();
      const childPayload = buildAttenuatedPayload({
        issuerDid: this.pipeline.issuerDid,
        parent: parentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities: requestedCapabilities,
      });

      this.pipeline.logger.info('Signing attenuated capability token', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });
      await this.pipeline.attachProofs(childPayload);
      // Restore the policy hash from the parent token so the attenuated child
      // is signed under the same policy boundary as the original issuance.
      const attenuationPolicyHash = parentPayload.policyHash ?? this.pipeline.cachedPolicyHash;
      const attenuationContext = buildIssuanceContext({
        policyHash: attenuationPolicyHash,
        subject: parentPayload.sub,
        audience: this.pipeline.gatewayAudience,
      });
      const token = await this.pipeline.signToken(childPayload, attenuationContext);

      // Step 6: Audit log the attenuation.
      await this.logAttenuation(
        parentPayload.sub,
        tokenId,
        parentPayload.jti,
        requestedCapabilities,
      );

      this.pipeline.logger.info('Capability token attenuated successfully', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: requestedCapabilities,
      };
    } catch (error) {
      this.pipeline.logger.error('Failed to attenuate capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Parent capability token has expired',
          'Invalid parent capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to attenuate capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability attenuation for audit trail.
   */
  private async logAttenuation(
    agentId: string,
    tokenId: string,
    parentTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        parentCapabilityId: parentTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.pipeline.auditLogger.info('Capability token attenuated', auditEntry);
  }
}

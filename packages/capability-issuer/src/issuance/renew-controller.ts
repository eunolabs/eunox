/**
 * RenewalController — thin handler for capability renewal.
 *
 * Owns the endpoint-specific logic for the POST /api/v1/renew flow:
 *
 *   verify token → rate limit → build renewed payload → sign → audit
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
  CapabilityTokenPayload,
  ErrorCode,
  IssueCapabilityResponse,
  generateId,
  getCurrentTimestamp,
  getExpirationTimestamp,
} from '@euno/common';
import { MintingPipeline } from './minting-pipeline';
import {
  buildIssuanceContext,
  buildRenewedPayload,
  mapVerifyError,
  verifyParentToken,
} from './index';

export interface RenewalControllerOptions {
  /** Default TTL in seconds. Defaults to 900. */
  defaultTtl?: number;
}

/**
 * RenewalController — handler for the renewal endpoint.
 *
 * Accepts a valid, unexpired capability JWT and produces a new token
 * with the same capabilities but a fresh expiry.
 */
export class RenewalController {
  private readonly defaultTtl: number;

  constructor(
    private readonly pipeline: MintingPipeline,
    opts: RenewalControllerOptions = {},
  ) {
    this.defaultTtl = opts.defaultTtl ?? 900;
  }

  /**
   * Renew an existing capability token with a fresh expiration. Token
   * keeps the same capabilities but gets a new TTL.
   */
  async handle(
    currentToken: string,
    ttl?: number,
    enforcement?: { clientIp?: string },
  ): Promise<IssueCapabilityResponse> {
    try {
      this.pipeline.logger.info('Renewing capability token');

      const currentPayload = await verifyParentToken(
        this.pipeline.signer,
        currentToken,
        { issuer: this.pipeline.issuerDid, audience: this.pipeline.gatewayAudience },
        'Invalid capability token format',
      );

      // Step 1a: Per-(tenantId, userId, agentId, jti, ip) rate limit for renewal (F-1).
      // An attacker holding a non-expired token can otherwise extend its
      // lineage forever in a tight renew loop, defeating short TTLs.
      // Shares the same bucket as fresh issuance and attenuation. Uses the
      // current token's jti to scope the budget to this capability lineage.
      await this.pipeline.enforceRateLimit({
        tenantId: currentPayload.authorizedBy?.tenantId,
        userId: currentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: currentPayload.sub,
        jti: currentPayload.jti,
        ip: enforcement?.clientIp,
      });

      // Step 2: Build the renewed token.
      const now = getCurrentTimestamp();
      const expiresAt = getExpirationTimestamp(ttl ?? this.defaultTtl);
      const tokenId = generateId();
      const renewedPayload: CapabilityTokenPayload = buildRenewedPayload({
        issuerDid: this.pipeline.issuerDid,
        current: currentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
      });

      // Step 3: Sign the renewed token.
      this.pipeline.logger.info('Signing renewed capability token', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });
      await this.pipeline.attachProofs(renewedPayload);
      // Restore the policy hash from the token being renewed so the new token
      // is signed under the same policy boundary as the original issuance.
      const renewalPolicyHash = currentPayload.policyHash ?? this.pipeline.cachedPolicyHash;
      const renewalContext = buildIssuanceContext({
        policyHash: renewalPolicyHash,
        subject: currentPayload.sub,
        audience: this.pipeline.gatewayAudience,
      });
      const token = await this.pipeline.signToken(renewedPayload, renewalContext);

      // Step 4: Audit log the renewal.
      await this.logRenewal(
        currentPayload.sub,
        tokenId,
        currentPayload.jti,
        currentPayload.capabilities,
      );

      this.pipeline.logger.info('Capability token renewed successfully', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: currentPayload.capabilities,
      };
    } catch (error) {
      this.pipeline.logger.error('Failed to renew capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Capability token has expired; re-authentication is required',
          'Invalid capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to renew capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability renewal for audit trail.
   */
  private async logRenewal(
    agentId: string,
    tokenId: string,
    previousTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'renewal',
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        previousCapabilityId: previousTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.pipeline.auditLogger.info('Capability token renewed', auditEntry);
  }
}

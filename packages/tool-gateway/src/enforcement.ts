/**
 * Enforcement Engine for Tool Gateway
 * Validates capability tokens and enforces action permissions
 */

import {
  TokenVerifier,
  ValidateActionRequest,
  ValidateActionResponse,
  CapabilityError,
  ErrorCode,
  isActionAllowed,
  Logger,
  createAuditLogger,
  AuditLogEntry,
  generateId,
  KillSwitchManager,
  EvidenceSigner,
  SignedAuditEvidence,
  createAuditEvidence,
} from '@euno/common';

export interface EnforcementEngineOptions {
  verifier: TokenVerifier;
  logger: Logger;
  killSwitchManager?: KillSwitchManager;
  evidenceSigner?: EvidenceSigner;
  policyVersion?: string;
  enableCryptographicAudit?: boolean;
}

export class EnforcementEngine {
  private verifier: TokenVerifier;
  private logger: Logger;
  private auditLogger: Logger;
  private killSwitchManager?: KillSwitchManager;
  private evidenceSigner?: EvidenceSigner;
  private policyVersion: string;
  private enableCryptographicAudit: boolean;

  constructor(options: EnforcementEngineOptions) {
    this.verifier = options.verifier;
    this.logger = options.logger;
    this.auditLogger = createAuditLogger('tool-gateway');
    this.killSwitchManager = options.killSwitchManager;
    this.evidenceSigner = options.evidenceSigner;
    this.policyVersion = options.policyVersion || '1.0.0';
    this.enableCryptographicAudit = options.enableCryptographicAudit || false;
  }

  /**
   * Validate an action request
   */
  async validateAction(request: ValidateActionRequest): Promise<ValidateActionResponse> {
    try {
      // Step 1: Verify the token signature and decode
      this.logger.debug('Verifying capability token');
      const payload = await this.verifier.verify(request.token);

      // Step 2: Check kill switch
      const rawSessionId = request.context?.sessionId;
      const sessionId = typeof rawSessionId === 'string' ? rawSessionId : undefined;
      if (this.killSwitchManager && this.killSwitchManager.shouldBlock(sessionId, payload.sub)) {
        await this.logDenial(payload.sub, request.action, request.resource, 'Kill switch activated', sessionId);
        throw new CapabilityError(
          ErrorCode.AUTHORIZATION_FAILED,
          'Agent or session has been terminated',
          403
        );
      }

      // Step 3: Check if the token is intended for this gateway
      if (payload.aud !== 'tool-gateway') {
        await this.logDenial(payload.sub, request.action, request.resource, 'Invalid audience', sessionId);
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token audience does not match this gateway',
          403
        );
      }

      // Step 4: Check if the action is allowed for the resource
      const allowed = isActionAllowed(
        request.action,
        request.resource,
        payload.capabilities
      );

      if (!allowed) {
        await this.logDenial(
          payload.sub,
          request.action,
          request.resource,
          'Insufficient permissions',
          sessionId
        );

        // Generate cryptographic evidence for denied action if enabled
        if (this.enableCryptographicAudit && this.evidenceSigner && payload.authorizedBy) {
          await this.generateEvidence({
            sessionId: sessionId || 'unknown',
            userId: payload.authorizedBy.userId,
            tool: request.resource,
            args: request.context || {},
            agentId: payload.sub,
            resource: request.resource,
            action: request.action,
            capabilityId: payload.jti,
            decision: 'deny',
          });
        }

        return {
          allowed: false,
          reason: 'Insufficient permissions for the requested action and resource',
        };
      }

      // Step 5: Find the matched capability
      const matchedCapability = payload.capabilities.find(cap => {
        return isActionAllowed(request.action, request.resource, [cap]);
      });

      // Step 6: Log the successful validation
      await this.logValidation(
        payload.sub,
        request.action,
        request.resource,
        payload.jti,
        sessionId
      );

      // Step 7: Generate cryptographic evidence for allowed action if enabled
      if (this.enableCryptographicAudit && this.evidenceSigner && payload.authorizedBy) {
        await this.generateEvidence({
          sessionId: sessionId || 'unknown',
          userId: payload.authorizedBy.userId,
          tool: request.resource,
          args: request.context || {},
          agentId: payload.sub,
          resource: request.resource,
          action: request.action,
          capabilityId: payload.jti,
          decision: 'allow',
        });
      }

      this.logger.info('Action validated successfully', {
        agentId: payload.sub,
        action: request.action,
        resource: request.resource,
      });

      return {
        allowed: true,
        matchedCapability,
      };
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      this.logger.error('Action validation failed', {
        action: request.action,
        resource: request.resource,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      throw new CapabilityError(
        ErrorCode.AUTHORIZATION_FAILED,
        `Action validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500
      );
    }
  }

  /**
   * Generate cryptographic audit evidence
   */
  private async generateEvidence(params: {
    sessionId: string;
    userId: string;
    tool: string;
    args: unknown;
    agentId: string;
    resource: string;
    action: string;
    capabilityId: string;
    decision: 'allow' | 'deny';
  }): Promise<SignedAuditEvidence | null> {
    if (!this.evidenceSigner) {
      return null;
    }

    try {
      const evidence = createAuditEvidence({
        ...params,
        policyVersion: this.policyVersion,
      });

      const signedEvidence = await this.evidenceSigner.signEvidence(evidence);

      // Log the signed evidence
      this.auditLogger.info('Cryptographic evidence generated', {
        evidenceId: signedEvidence.id,
        sessionId: signedEvidence.sessionId,
        decision: signedEvidence.decision,
        signature: signedEvidence.signature.substring(0, 20) + '...',
      });

      return signedEvidence;
    } catch (error) {
      this.logger.error('Failed to generate cryptographic evidence', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }
  }

  /**
   * Log successful validation for audit trail
   */
  private async logValidation(
    agentId: string,
    action: string,
    resource: string,
    capabilityId: string,
    sessionId?: string
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date(),
      eventType: 'validation',
      agentId,
      action,
      resource,
      capabilityId,
      decision: 'allow',
      metadata: sessionId ? { sessionId } : undefined,
    };

    this.auditLogger.info('Action allowed', auditEntry);
  }

  /**
   * Log denied action for audit trail
   */
  private async logDenial(
    agentId: string,
    action: string,
    resource: string,
    reason: string,
    sessionId?: string
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date(),
      eventType: 'denial',
      agentId,
      action,
      resource,
      decision: 'deny',
      reason,
      metadata: sessionId ? { sessionId } : undefined,
    };

    this.auditLogger.info('Action denied', auditEntry);
  }
}

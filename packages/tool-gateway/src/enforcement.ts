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
} from '@euno/common';

export class EnforcementEngine {
  private verifier: TokenVerifier;
  private logger: Logger;
  private auditLogger: Logger;

  constructor(verifier: TokenVerifier, logger: Logger) {
    this.verifier = verifier;
    this.logger = logger;
    this.auditLogger = createAuditLogger('tool-gateway');
  }

  /**
   * Validate an action request
   */
  async validateAction(request: ValidateActionRequest): Promise<ValidateActionResponse> {
    try {
      // Step 1: Verify the token signature and decode
      this.logger.debug('Verifying capability token');
      const payload = await this.verifier.verify(request.token);

      // Step 2: Check if the token is intended for this gateway
      if (payload.aud !== 'tool-gateway') {
        await this.logDenial(payload.sub, request.action, request.resource, 'Invalid audience');
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token audience does not match this gateway',
          403
        );
      }

      // Step 3: Check if the action is allowed for the resource
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
          'Insufficient permissions'
        );

        return {
          allowed: false,
          reason: 'Insufficient permissions for the requested action and resource',
        };
      }

      // Step 4: Find the matched capability
      const matchedCapability = payload.capabilities.find(cap => {
        return isActionAllowed(request.action, request.resource, [cap]);
      });

      // Step 5: Log the successful validation
      await this.logValidation(
        payload.sub,
        request.action,
        request.resource,
        payload.jti
      );

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
   * Log successful validation for audit trail
   */
  private async logValidation(
    agentId: string,
    action: string,
    resource: string,
    capabilityId: string
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
    reason: string
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
    };

    this.auditLogger.info('Action denied', auditEntry);
  }
}

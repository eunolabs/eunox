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
  validateArguments,
  CallCounterStore,
  ConditionContext,
  enforceConditions,
  CapabilityTokenPayload,
} from '@euno/common';

export interface EnforcementEngineOptions {
  verifier: TokenVerifier;
  logger: Logger;
  killSwitchManager?: KillSwitchManager;
  evidenceSigner?: EvidenceSigner;
  policyVersion?: string;
  enableCryptographicAudit?: boolean;
  /**
   * Counter store used for {@link MaxCallsCondition} enforcement. When
   * omitted, capabilities that carry a `maxCalls` condition are denied
   * (deny-by-default on missing infrastructure) — wire in
   * {@link createCallCounterStoreFromEnv} at startup to enable it.
   */
  callCounterStore?: CallCounterStore;
}

export class EnforcementEngine {
  private verifier: TokenVerifier;
  private logger: Logger;
  private auditLogger: Logger;
  private killSwitchManager?: KillSwitchManager;
  private evidenceSigner?: EvidenceSigner;
  private policyVersion: string;
  private enableCryptographicAudit: boolean;
  private callCounterStore?: CallCounterStore;

  constructor(options: EnforcementEngineOptions) {
    this.verifier = options.verifier;
    this.logger = options.logger;
    this.auditLogger = createAuditLogger('tool-gateway');
    this.killSwitchManager = options.killSwitchManager;
    this.evidenceSigner = options.evidenceSigner;
    this.policyVersion = options.policyVersion || '1.0.0';
    this.enableCryptographicAudit = options.enableCryptographicAudit || false;
    this.callCounterStore = options.callCounterStore;
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
        // Use a distinct error code so callers (e.g. agent-runtime) can tell a
        // kill-switch denial apart from an ordinary authorization failure and
        // refuse to refresh-and-retry — refreshing after a kill-switch event
        // would just produce another doomed token.
        throw new CapabilityError(
          ErrorCode.AGENT_TERMINATED,
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

      // Step 5b: Argument-level enforcement.
      // After the (action, resource) check passes, validate the actual
      // arguments / request body against the matched capability's
      // declared `argumentSchema`. This is the first-class enforcement
      // point that prevents an agent with `read on api://crm/customers`
      // from passing an arbitrary body to that endpoint.
      //
      // Capabilities without an `argumentSchema` impose no argument
      // constraints (preserving existing behaviour for callers that have
      // not yet adopted argument schemas).
      if (matchedCapability?.argumentSchema) {
        const argsToValidate = extractArgsForValidation(request.context);

        try {
          validateArguments(argsToValidate, matchedCapability.argumentSchema);
        } catch (err) {
          const reason =
            err instanceof CapabilityError
              ? err.message
              : 'Argument validation failed';

          await this.logDenial(
            payload.sub,
            request.action,
            request.resource,
            reason,
            sessionId
          );

          if (this.enableCryptographicAudit && this.evidenceSigner && payload.authorizedBy) {
            // Hash the *exact* value that was validated, not the
            // surrounding context metadata. This keeps the evidence
            // hash tightly coupled to the input that caused the denial
            // and avoids drift from method/path/session noise.
            await this.emitDenialEvidence(payload, request, sessionId, argsToValidate);
          }

          return {
            allowed: false,
            reason,
          };
        }
      }

      // Step 5c: Condition enforcement. After the (action, resource)
      // match and any argument-schema check pass, every typed
      // condition on the matched capability must also evaluate to
      // "allow" (typed-condition contract from
      // docs/capability-model.md). Conditions are validated at mint
      // time, so any condition that reaches enforcement is structurally
      // sound — we still defend against unknown types here by treating
      // them as denials, in case a token from a future issuer carries
      // a condition this gateway does not yet implement.
      if (matchedCapability?.conditions && matchedCapability.conditions.length > 0) {
        const conditionCtx = this.buildConditionContext(request, payload.jti);
        const result = await enforceConditions(matchedCapability.conditions, conditionCtx);
        if (!result.allow) {
          const reason = `Condition not satisfied: ${result.reason}`;
          await this.logDenial(
            payload.sub,
            request.action,
            request.resource,
            reason,
            sessionId
          );

          if (this.enableCryptographicAudit && this.evidenceSigner && payload.authorizedBy) {
            await this.emitDenialEvidence(payload, request, sessionId, request.context || {});
          }

          return {
            allowed: false,
            reason,
          };
        }
      }

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
  /**
   * Convenience wrapper around {@link generateEvidence} for the
   * gateway's three denial paths (argument-schema validation, condition
   * enforcement, and any future deny site). Centralizes the field
   * mapping from `payload + request → AuditEvidence` so each call site
   * stays a single line and the evidence shape cannot drift across
   * paths.
   *
   * Caller is responsible for the `enableCryptographicAudit` /
   * `evidenceSigner` / `payload.authorizedBy` guard so the cost of
   * building this object isn't paid when audit signing is disabled.
   */
  private async emitDenialEvidence(
    payload: CapabilityTokenPayload,
    request: ValidateActionRequest,
    sessionId: string | undefined,
    args: unknown,
  ): Promise<void> {
    if (!payload.authorizedBy) return;
    await this.generateEvidence({
      sessionId: sessionId || 'unknown',
      userId: payload.authorizedBy.userId,
      tool: request.resource,
      args,
      agentId: payload.sub,
      resource: request.resource,
      action: request.action,
      capabilityId: payload.jti,
      decision: 'deny',
    });
  }

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

  /**
   * Build a {@link ConditionContext} from the validation request.
   *
   * The gateway's `ValidateActionRequest.context` is an open
   * `Record<string, unknown>` populated by the upstream tool / proxy
   * adapter. Each typed condition handler reads exactly the fields it
   * needs from this record; missing fields cause that handler to deny
   * (deny-by-default on missing context).
   *
   * Conventions consumed here (all optional):
   *   - `sourceIp: string`               — for `ipRange`
   *   - `operation: string`              — for `allowedOperations`
   *   - `filePath: string`               — for `allowedExtensions`
   *   - `tables: Array<{table, columns?}>` — for `allowedTables`
   *   - `recipients: string[]`           — for `recipientDomain`
   *
   * The counter store and a per-capability `counterKey` are wired in
   * directly so the handler does not depend on the request shape.
   */
  private buildConditionContext(
    request: ValidateActionRequest,
    capabilityId: string,
  ): ConditionContext {
    const ctx = (request.context ?? {}) as Record<string, unknown>;
    const ctxOut: ConditionContext = {
      now: new Date(),
      counterStore: this.callCounterStore,
      counterKey: capabilityId,
    };
    if (typeof ctx.sourceIp === 'string') ctxOut.sourceIp = ctx.sourceIp;
    if (typeof ctx.operation === 'string') ctxOut.operation = ctx.operation;
    if (typeof ctx.filePath === 'string') ctxOut.filePath = ctx.filePath;
    if (Array.isArray(ctx.tables)) {
      const tables: Array<{ table: string; columns?: string[] }> = [];
      for (const entry of ctx.tables) {
        if (
          entry &&
          typeof entry === 'object' &&
          typeof (entry as { table?: unknown }).table === 'string'
        ) {
          const e = entry as { table: string; columns?: unknown };
          const cleaned: { table: string; columns?: string[] } = { table: e.table };
          if (Array.isArray(e.columns) && e.columns.every((c) => typeof c === 'string')) {
            cleaned.columns = e.columns as string[];
          }
          tables.push(cleaned);
        }
      }
      if (tables.length > 0) ctxOut.tables = tables;
    }
    if (Array.isArray(ctx.recipients) && ctx.recipients.every((r) => typeof r === 'string')) {
      ctxOut.recipients = ctx.recipients as string[];
    }
    return ctxOut;
  }
}

/**
 * Pick the value to feed into argument-schema validation from a
 * validation-request context. The tool-gateway sets `args` on the
 * tool-invoke path and `body` on the proxy path; we honour either,
 * preferring `args` when both are present. If neither key is set we
 * return `undefined` so the schema is evaluated against an empty value
 * (and any `required` constraint correctly rejects the call).
 */
function extractArgsForValidation(
  context: Record<string, unknown> | undefined
): unknown {
  if (!context) {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(context, 'args')) {
    return context.args;
  }
  if (Object.prototype.hasOwnProperty.call(context, 'body')) {
    return context.body;
  }
  return undefined;
}

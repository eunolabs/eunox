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
  setActiveSpanEunoAttributes,
  EUNO_ATTR,
} from '@euno/common';

export interface EnforcementEngineOptions {
  verifier: TokenVerifier;
  logger: Logger;
  killSwitchManager?: KillSwitchManager;
  evidenceSigner?: EvidenceSigner;
  policyVersion?: string;
  /**
   * Legacy single-toggle for evidence signing. When `true`, both `allow`
   * and `deny` decisions are signed; when `false`, neither is. Kept for
   * backward compatibility — for finer-grained control prefer
   * {@link signedDecisions} (I-8).
   */
  enableCryptographicAudit?: boolean;
  /**
   * Per-decision evidence-signing selection (I-8). When provided, this
   * is authoritative and {@link enableCryptographicAudit} is ignored.
   * Lets operators express asymmetric policies such as "sign every
   * `deny` but skip `allow`" — impossible to express with a single
   * boolean. An empty array disables signing entirely.
   */
  signedDecisions?: Array<'allow' | 'deny'>;
  /**
   * Strict argument-schema mode (I-7). When `true`, any matched
   * capability that does not declare an `argumentSchema` is denied
   * outright. Default `false` preserves existing behaviour: capabilities
   * without a schema impose no argument-level constraint. Enable once
   * every capability accepted by this gateway has been migrated to
   * declare an explicit argument schema.
   */
  argumentSchemaRequired?: boolean;
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
  /**
   * Resolved per-decision signing set (I-8). Built once in the
   * constructor from `signedDecisions` (when provided) or from the
   * legacy `enableCryptographicAudit` boolean. All hot-path checks read
   * from this set so the per-call cost is a single Set.has lookup.
   */
  private signedDecisions: Set<'allow' | 'deny'>;
  private argumentSchemaRequired: boolean;
  private callCounterStore?: CallCounterStore;

  constructor(options: EnforcementEngineOptions) {
    this.verifier = options.verifier;
    this.logger = options.logger;
    this.auditLogger = createAuditLogger('tool-gateway');
    this.killSwitchManager = options.killSwitchManager;
    this.evidenceSigner = options.evidenceSigner;
    this.policyVersion = options.policyVersion || '1.0.0';
    if (options.signedDecisions !== undefined) {
      this.signedDecisions = new Set(options.signedDecisions);
    } else if (options.enableCryptographicAudit) {
      this.signedDecisions = new Set<'allow' | 'deny'>(['allow', 'deny']);
    } else {
      this.signedDecisions = new Set();
    }
    this.argumentSchemaRequired = options.argumentSchemaRequired || false;
    this.callCounterStore = options.callCounterStore;
  }

  /**
   * Returns true when audit evidence for the given decision should be
   * cryptographically signed under the current configuration. Used at
   * every signing site so the policy lives in one place.
   */
  private shouldSignDecision(decision: 'allow' | 'deny'): boolean {
    return (
      this.signedDecisions.has(decision) &&
      this.evidenceSigner !== undefined
    );
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
        if (this.shouldSignDecision('deny') && payload.authorizedBy) {
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
      // constraints by default (preserving existing behaviour for
      // callers that have not yet adopted argument schemas).
      //
      // I-7 strict mode: when `argumentSchemaRequired` is true the
      // gateway instead denies any matched capability that does not
      // declare an argument schema. This lets operators fail-closed on
      // schema-less tokens once every capability accepted by this
      // gateway has been migrated.
      if (this.argumentSchemaRequired && matchedCapability && !matchedCapability.argumentSchema) {
        const reason =
          'Argument schema required: matched capability has no argumentSchema and the gateway is in strict argument-schema mode';
        await this.logDenial(
          payload.sub,
          request.action,
          request.resource,
          reason,
          sessionId,
        );

        if (this.shouldSignDecision('deny') && payload.authorizedBy) {
          await this.emitDenialEvidence(payload, request, sessionId, request.context || {});
        }

        return {
          allowed: false,
          reason,
        };
      }

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

          if (this.shouldSignDecision('deny') && payload.authorizedBy) {
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

          if (this.shouldSignDecision('deny') && payload.authorizedBy) {
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
      if (this.shouldSignDecision('allow') && payload.authorizedBy) {
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
      timestamp: new Date().toISOString(),
      eventType: 'validation',
      agentId,
      action,
      resource,
      capabilityId,
      decision: 'allow',
      metadata: sessionId ? { sessionId } : undefined,
    };

    // R-3: stamp the documented `euno.*` attributes onto the active
    // request span so traces carry the same identifiers as the audit
    // log. No-op when no SDK is wired in.
    setActiveSpanEunoAttributes({
      [EUNO_ATTR.AGENT_ID]: agentId,
      [EUNO_ATTR.ACTION]: action,
      [EUNO_ATTR.RESOURCE]: resource,
      [EUNO_ATTR.JTI]: capabilityId,
      [EUNO_ATTR.OUTCOME]: 'allow',
    });

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
      timestamp: new Date().toISOString(),
      eventType: 'denial',
      agentId,
      action,
      resource,
      decision: 'deny',
      reason,
      metadata: sessionId ? { sessionId } : undefined,
    };

    // R-3: mirror the audit decision onto the active span.
    setActiveSpanEunoAttributes({
      [EUNO_ATTR.AGENT_ID]: agentId,
      [EUNO_ATTR.ACTION]: action,
      [EUNO_ATTR.RESOURCE]: resource,
      [EUNO_ATTR.OUTCOME]: 'deny',
      [EUNO_ATTR.REASON]: reason,
    });

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

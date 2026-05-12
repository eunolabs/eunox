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
  findMatchingCapability,
  Logger,
  createAuditLogger,
  AuditLogEntry,
  generateId,
  KillSwitchManager,
  EvidenceSigner,
  AuditEvidence,
  SignedAuditEvidence,
  createAuditEvidence,
  validateArguments,
  CallCounterStore,
  ConditionContext,
  enforceConditions,
  redactConditions,
  hasRedactObligation,
  CapabilityTokenPayload,
  setActiveSpanEunoAttributes,
  EUNO_ATTR,
  AuditPipeline,
  DpopReplayStore,
  InMemoryDpopReplayStore,
  verifyDpopProof,
  GatewayQuotaEngine,
  UsageMeter,
} from '@euno/common';
import type TransportStream from 'winston-transport';

export interface EnforcementEngineOptions {
  verifier: TokenVerifier;
  logger: Logger;
  killSwitchManager?: KillSwitchManager;
  evidenceSigner?: EvidenceSigner;
  /**
   * Optional async audit pipeline (R-9, addresses I-21). When supplied,
   * the engine enqueues unsigned `AuditEvidence` onto the pipeline
   * instead of awaiting `EvidenceSigner.signEvidence` on the request
   * critical path — signing latency no longer adds to the agent's p99.
   * The pipeline owns the call to the signer; `evidenceSigner` need
   * not be set on the engine when a pipeline is wired in. When BOTH
   * are supplied the pipeline wins (it already wraps a signer).
   */
  auditPipeline?: AuditPipeline;
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
  /**
   * Logical region tag for this gateway instance (F-7,
   * `docs/MULTI_REGION_ISSUER.md`). When supplied, every audit record
   * the engine emits is stamped with `region`. Plumbed by
   * `bootstrap.ts` from the `GATEWAY_REGION` env var. Empty/undefined
   * means "not configured" and the field is omitted (back-compat).
   */
  region?: string;
  /**
   * Optional list of additional winston transports to attach to this
   * engine's audit logger. Used by `bootstrap.ts` to wire the F-6
   * OCSF bridge so every `AuditLogEntry` the engine emits on the
   * request hot path (`Action allowed` / `Action denied`) is also
   * mirrored to the configured SIEM. Without this hook OCSF would
   * only see the signed-evidence sink, missing every synchronous
   * deny on the validation path.
   *
   * Failures attaching a transport are not the engine's concern —
   * the caller chose to add it, the caller owns its health.
   */
  auditTransports?: TransportStream[];
  /**
   * DPoP (RFC 9449 / F-2) configuration.
   *
   * - `required` defaults to `true` and matches the `DPOP_REQUIRED`
   *   env-var default, so embedders that omit `dpop` get the same
   *   sender-constrained-token enforcement as the production gateway.
   *   When `true`, any token without a `cnf.jkt` claim is rejected.
   *   Set to `false` only for backward-compatible deployments that
   *   have not yet rolled DPoP issuance out to all callers.
   * - `replayStore` is the per-instance (or shared) store used to
   *   reject replays of a previously-seen proof. **When `required`
   *   is `true`, a `replayStore` MUST be supplied** — otherwise the
   *   constructor throws. This closes the seam where embedders or
   *   tests could silently fall back to an in-process store, which
   *   downgrades sender-constrained tokens to ordinary bearer tokens
   *   across the fleet (a captured proof remains accepted at any
   *   replica that has not yet seen its `jti`). To intentionally
   *   keep the in-process store in single-replica or development
   *   deployments, pass `allowInProcessReplayStore: true`; the engine
   *   logs a loud warning so the relaxed posture is observable.
   *   When `required` is `false`, an omitted `replayStore` is treated
   *   as an in-process store with no warning (DPoP is opt-in there).
   * - `clockSkewSeconds` and `maxAgeSeconds` are forwarded to
   *   {@link verifyDpopProof}.
   */
  dpop?: {
    replayStore?: DpopReplayStore;
    required?: boolean;
    /**
     * Explicit opt-in for the {@link InMemoryDpopReplayStore} fallback
     * when {@link required} is `true`. Set this only for single-replica
     * deployments, embedded callers that do not span replicas, or
     * tests. The engine logs a warning at construction time when this
     * is set so the relaxed replay-defence posture is observable.
     */
    allowInProcessReplayStore?: boolean;
    clockSkewSeconds?: number;
    maxAgeSeconds?: number;
  };
  /**
   * Expected `aud` claim for capability tokens this gateway accepts.
   * Defaults to `"tool-gateway"`. Configure a unique value per tenant
   * (e.g. `"tool-gateway:acme-corp-prod"`) so tokens minted by one
   * tenant's issuer cannot be replayed at another tenant's gateway.
   * MUST match the GATEWAY_AUDIENCE configured on the issuer.
   */
  gatewayAudience?: string;
  /**
   * Optional per-(jti, action, resource) gateway quota engine (F-1b).
   * When supplied, every `validateAction` call that matches a
   * capability is counted against the per-token/action/resource budget
   * **before** typed-condition evaluation. This protects the enforcement
   * hot-path from token-flooding even when the token carries no
   * `maxCalls` condition. The engine defaults to fail-open (errors
   * allow the request) — flip `GATEWAY_QUOTA_FAIL_CLOSED=true` for a
   * hard stop. Omitting this option preserves pre-F-1b behaviour
   * (no gateway-side invocation quota beyond per-token `maxCalls`
   * conditions).
   */
  gatewayQuota?: GatewayQuotaEngine;
  /**
   * Optional billing meter (Task 17). When supplied, every enforcement
   * decision that can be attributed to a verified token with a
   * `tenantId` claim increments the per-tenant counter.
   *
   * Failures in the meter MUST NOT affect the enforcement outcome —
   * the engine swallows meter errors in the same finally-block that
   * guards the Prometheus decision recorder.
   */
  usageMeter?: UsageMeter;
}

/**
 * Result of {@link EnforcementEngine.validateAction}. Extends
 * {@link ValidateActionResponse} with an in-process redaction lobe
 * built from the matched capability's response-time obligations
 * (R-4 step 1, supports F-3). Callers on the response path (the
 * `/proxy` and `/api/v1/tools/invoke` routes) MUST pipe their JSON
 * response body through `applyResponseRedactions` when present so
 * `redactFields` and any policy-backend-supplied redaction actually
 * strip fields before the body leaves the gateway.
 */
export interface EnforcementResult extends ValidateActionResponse {
  applyResponseRedactions?: (body: unknown) => unknown;
  /**
   * Machine-readable denial code when `allowed` is `false`. Drawn from
   * `ErrorCode`. When absent the caller should default to
   * `AUTHORIZATION_FAILED`. Only meaningful when `allowed === false`.
   */
  denialCode?: string;
  /**
   * Condition type string for DenialInfo serialisation when `allowed` is
   * `false`. When absent the caller defaults to `'policy'`. Only meaningful
   * when `allowed === false`.
   */
  denialConditionType?: string;
}

export class EnforcementEngine {
  private verifier: TokenVerifier;
  private logger: Logger;
  private auditLogger: Logger;
  private killSwitchManager?: KillSwitchManager;
  private evidenceSigner?: EvidenceSigner;
  /**
   * Async audit pipeline (R-9). When set, evidence is enqueued
   * fire-and-forget so signing latency stays off the request path.
   */
  private auditPipeline?: AuditPipeline;
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
  /**
   * Per-(jti, action, resource) gateway quota engine (F-1b). When set,
   * each `validateAction` call that successfully matches a capability
   * is counted before typed-condition evaluation.
   */
  private gatewayQuota?: GatewayQuotaEngine;
  /**
   * Optional sink invoked once per `validateAction` call with the final
   * decision (`allow` | `deny`). Wired by `bootstrap.ts` to a Prometheus
   * counter so operators can chart deny-rate without scraping logs
   * (F-5, addresses I-16). Failures throwing out of validateAction —
   * e.g. token-format errors that map to 401 — count as `deny` because
   * from the caller's perspective the action did not go through.
   */
  private decisionRecorder?: (decision: 'allow' | 'deny') => void;
  /**
   * Optional billing usage meter (Task 17). When set, every enforcement
   * decision attributed to a verified token with a `tenantId` claim is
   * recorded against that tenant's counter.
   */
  private usageMeter?: UsageMeter;

  /**
   * DPoP (RFC 9449 / F-2) verification surface. `required=true`
   * rejects any token lacking `cnf.jkt`. The replay store is shared
   * across `validateAction` calls so duplicate proofs are detected
   * within their TTL.
   */
  private dpopRequired: boolean;
  private dpopReplayStore: DpopReplayStore;
  private dpopClockSkewSeconds: number;
  private dpopMaxAgeSeconds: number;

  /** Expected audience string for capability tokens. */
  private gatewayAudience: string;

  constructor(options: EnforcementEngineOptions) {
    this.verifier = options.verifier;
    this.logger = options.logger;
    this.auditLogger = createAuditLogger('tool-gateway', { region: options.region });
    if (options.auditTransports) {
      for (const t of options.auditTransports) {
        this.auditLogger.add(t);
      }
    }
    this.killSwitchManager = options.killSwitchManager;
    this.evidenceSigner = options.evidenceSigner;
    this.auditPipeline = options.auditPipeline;
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
    this.gatewayQuota = options.gatewayQuota;
    this.usageMeter = options.usageMeter;
    this.gatewayAudience = options.gatewayAudience ?? 'tool-gateway';
    // Defaults are aligned with the `DPOP_REQUIRED` env var (which
    // defaults to `true`) so embedders that omit `dpop` get the same
    // sender-constrained-token enforcement as the production gateway.
    // The historical "default false in code, default true in env"
    // asymmetry leaked into production via embedded callers.
    this.dpopRequired = options.dpop?.required ?? true;
    const suppliedReplayStore = options.dpop?.replayStore;
    const allowInProcess = options.dpop?.allowInProcessReplayStore === true;
    if (this.dpopRequired && !suppliedReplayStore && !allowInProcess) {
      // Fail closed: refuse to construct the engine when DPoP is
      // required but no shared replay store has been wired. Without
      // this guard the engine would silently install an
      // {@link InMemoryDpopReplayStore}, which only catches replays
      // on the originating replica — a captured proof replayed at
      // a sibling pod would be accepted, downgrading sender-
      // constrained tokens to ordinary bearer tokens across the
      // fleet with no startup signal.
      throw new Error(
        'EnforcementEngine: dpop.required=true but no dpop.replayStore was supplied. ' +
          'A captured DPoP proof would be replayable across replicas because the in-process ' +
          'fallback only tracks jtis on the originating instance. Wire a shared store ' +
          '(e.g. RedisDpopReplayStore via createDpopReplayStoreFromEnv) — or, for explicitly ' +
          'single-replica or development deployments, pass dpop.allowInProcessReplayStore=true ' +
          'to acknowledge that replay defence is per-process only.',
      );
    }
    if (this.dpopRequired && !suppliedReplayStore && allowInProcess) {
      // Loud warning: the operator opted in to the in-process
      // fallback. Make the relaxed posture observable in logs so an
      // accidental promotion from dev to prod surfaces immediately.
      this.logger.warn(
        'EnforcementEngine: dpop.required=true with the in-process replay store. ' +
          'DPoP replay defence is scoped to this process only; a captured proof can ' +
          'be replayed once per replica inside its acceptance window. Acceptable for ' +
          'single-replica or development deployments only.',
      );
    }
    this.dpopReplayStore = suppliedReplayStore ?? new InMemoryDpopReplayStore();
    this.dpopClockSkewSeconds = options.dpop?.clockSkewSeconds ?? 60;
    this.dpopMaxAgeSeconds = options.dpop?.maxAgeSeconds ?? 300;
  }

  /**
   * Returns true when audit evidence for the given decision should be
   * cryptographically signed under the current configuration. Used at
   * every signing site so the policy lives in one place.
   *
   * Either a direct `evidenceSigner` or an async `auditPipeline` (R-9)
   * satisfies the "signer attached" half of this check — the engine
   * does not care which mechanism actually signs.
   */
  private shouldSignDecision(decision: 'allow' | 'deny'): boolean {
    return (
      this.signedDecisions.has(decision) &&
      (this.evidenceSigner !== undefined || this.auditPipeline !== undefined)
    );
  }

  /**
   * Register a sink that observes every `allow` / `deny` decision made
   * by this engine. Used by `bootstrap.ts` to feed the Prometheus
   * `euno_gateway_decisions_total` counter (F-5, addresses I-16).
   * Replaces any previously-registered recorder; pass `undefined` to
   * detach.
   */
  setDecisionRecorder(recorder: ((decision: 'allow' | 'deny') => void) | undefined): void {
    this.decisionRecorder = recorder;
  }

  /**
   * Validate an action request
   */
  async validateAction(request: ValidateActionRequest): Promise<EnforcementResult> {
    // Default to `deny` so any control path that fails to assign — including
    // a future edit that adds a new branch — records as a denial. From the
    // operator's perspective, anything that isn't an explicit allow is a
    // denied action, so this is also the correct fail-safe value.
    let outcome: 'allow' | 'deny' = 'deny';
    // tenantId is captured from the verified token payload inside
    // validateActionInner so we can report it to the usage meter without
    // threading it all the way up through the return type.
    let capturedTenantId: string | undefined;
    try {
      const result = await this.validateActionInner(request, (tid) => { capturedTenantId = tid; });
      outcome = result.allowed ? 'allow' : 'deny';
      return result;
    } finally {
      try {
        this.decisionRecorder?.(outcome);
        if (capturedTenantId !== undefined) {
          this.usageMeter?.recordEnforcement(capturedTenantId, outcome);
        }
      } catch {
        // Metric sinks must never destabilise the request path.
      }
    }
  }

  private async validateActionInner(
    request: ValidateActionRequest,
    onTenantId?: (tenantId: string) => void,
  ): Promise<EnforcementResult> {
    try {
      // Step 1: Verify the token signature and decode
      this.logger.debug('Verifying capability token');
      const payload = await this.verifier.verify(request.token);

      // Report tenantId to the outer validateAction so it can be passed to
      // the usage meter. Done immediately after verification so even requests
      // that are subsequently denied (wrong audience, kill-switch, conditions)
      // are still attributed to the correct tenant.
      const tenantId = payload.authorizedBy?.tenantId;
      if (tenantId) onTenantId?.(tenantId);

      // Step 1b (F-2): If the token is sender-constrained (carries
      // `cnf.jkt`) we MUST verify the request also carries a valid
      // DPoP proof signed by the matching key. When the operator has
      // enabled `dpop.required`, we additionally reject any token
      // *without* `cnf.jkt` so a downgrade attack — strip the
      // confirmation claim, present a plain bearer token — cannot
      // bypass the proof-of-possession check.
      const tokenJkt = payload.cnf?.jkt;
      if (tokenJkt) {
        if (!request.dpop) {
          await this.logDenial(
            payload.sub,
            request.action,
            request.resource,
            'DPoP proof required but missing',
            typeof request.context?.sessionId === 'string' ? request.context.sessionId : undefined,
          );
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            'DPoP proof required (token is sender-constrained) but request did not carry a DPoP header',
            401,
          );
        }
        try {
          await verifyDpopProof({
            proof: request.dpop.proof,
            httpMethod: request.dpop.httpMethod,
            httpUrl: request.dpop.httpUrl,
            replayStore: this.dpopReplayStore,
            clockSkewSeconds: this.dpopClockSkewSeconds,
            maxAgeSeconds: this.dpopMaxAgeSeconds,
            expectedJkt: tokenJkt,
          });
        } catch (err) {
          await this.logDenial(
            payload.sub,
            request.action,
            request.resource,
            err instanceof Error ? `DPoP verification failed: ${err.message}` : 'DPoP verification failed',
            typeof request.context?.sessionId === 'string' ? request.context.sessionId : undefined,
          );
          throw err;
        }
      } else if (this.dpopRequired) {
        await this.logDenial(
          payload.sub,
          request.action,
          request.resource,
          'Token is not sender-constrained (cnf.jkt missing) but gateway requires DPoP',
          typeof request.context?.sessionId === 'string' ? request.context.sessionId : undefined,
        );
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token is not sender-constrained (cnf.jkt missing) but this gateway requires DPoP',
          401,
        );
      }

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
      if (payload.aud !== this.gatewayAudience) {
        await this.logDenial(payload.sub, request.action, request.resource, 'Invalid audience', sessionId);
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token audience does not match this gateway',
          403
        );
      }

      // Step 4: Find the capability that permits this (action, resource) pair.
      // A single pass returns the matched cap directly — no second scan is
      // needed to recover it after the allow/deny decision is made.
      const matchedCapability = findMatchingCapability(
        request.action,
        request.resource,
        payload.capabilities
      );

      if (!matchedCapability) {
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
            tenantId: payload.authorizedBy.tenantId,
            denialCode: 'NO_MATCHING_CAPABILITY',
          });
        }

        return {
          allowed: false,
          reason: 'Insufficient permissions for the requested action and resource',
        };
      }

      // Step 5: Argument-level enforcement.
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
      if (this.argumentSchemaRequired && !matchedCapability.argumentSchema) {
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
          await this.emitDenialEvidence(payload, request, sessionId, request.context || {}, 'ARGUMENT_SCHEMA_REQUIRED');
        }

        return {
          allowed: false,
          reason,
          denialCode: ErrorCode.ARGUMENT_SCHEMA_VIOLATION,
          denialConditionType: 'argumentSchema',
        };
      }

      if (matchedCapability.argumentSchema) {
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
            await this.emitDenialEvidence(payload, request, sessionId, argsToValidate, 'ARGUMENT_VALIDATION');
          }

          return {
            allowed: false,
            reason,
            denialCode: ErrorCode.ARGUMENT_SCHEMA_VIOLATION,
            denialConditionType: 'argumentSchema',
          };
        }
      }

      // Step 5.5: Gateway quota enforcement (F-1b). Fires after the
      // capability match and argument validation so only requests that
      // actually hold the matching capability consume quota — this
      // avoids penalising agents for probing capabilities they don't
      // have. Fires *before* typed-condition evaluation so that
      // condition-failing requests (e.g. wrong time-window, wrong IP)
      // still count, preventing adversaries from bypassing the quota
      // by crafting requests guaranteed to trip a benign condition.
      if (this.gatewayQuota) {
        const quotaDecision = await this.gatewayQuota.checkAndCount({
          jti: payload.jti,
          action: request.action,
          resource: request.resource,
          agentSub: payload.sub,
        });
        if (!quotaDecision.allowed) {
          const reason = 'Gateway invocation quota exceeded for this token/action/resource';
          await this.logDenial(payload.sub, request.action, request.resource, reason, sessionId);
          if (this.shouldSignDecision('deny') && payload.authorizedBy) {
            await this.emitDenialEvidence(payload, request, sessionId, request.context || {}, 'QUOTA_EXCEEDED');
          }
          throw new CapabilityError(
            ErrorCode.RATE_LIMIT_EXCEEDED,
            `${reason}. Retry after ${quotaDecision.retryAfterSeconds}s.`,
            429,
            { 'Retry-After': String(quotaDecision.retryAfterSeconds) },
          );
        }
      }

      // Step 6: Condition enforcement. After the (action, resource)
      // match and any argument-schema check pass, every typed
      // condition on the matched capability must also evaluate to
      // "allow" (typed-condition contract from
      // docs/capability-model.md). Conditions are validated at mint
      // time, so any condition that reaches enforcement is structurally
      // sound — we still defend against unknown types here by treating
      // them as denials, in case a token from a future issuer carries
      // a condition this gateway does not yet implement.
      if (matchedCapability.conditions && matchedCapability.conditions.length > 0) {
        const conditionCtx = this.buildConditionContext(request, payload.jti, payload.sub);
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
            await this.emitDenialEvidence(
              payload,
              request,
              sessionId,
              request.context || {},
              'CONDITION_FAILED',
              result.conditionType,
            );
          }

          return {
            allowed: false,
            reason,
            denialConditionType: result.conditionType,
          };
        }
      }

      // Step 7: Log the successful validation
      await this.logValidation(
        payload.sub,
        request.action,
        request.resource,
        payload.jti,
        sessionId
      );

      // Step 8: Generate cryptographic evidence for allowed action if enabled
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
          tenantId: payload.authorizedBy.tenantId,
        });
      }

      this.logger.info('Action validated successfully', {
        agentId: payload.sub,
        action: request.action,
        resource: request.resource,
      });

      // R-4 step 1: build the response-time redaction lobe from the
      // matched capability's conditions, but only when at least one
      // condition actually declares a `redact` lobe under the current
      // registry. This keeps the per-call cost zero for capabilities
      // whose only conditions are pure authorization checks (e.g.
      // `timeWindow`, `ipRange`, `maxCalls`).
      const conditions = matchedCapability.conditions;
      const applyResponseRedactions: ((body: unknown) => unknown) | undefined =
        conditions && hasRedactObligation(conditions)
          ? (body) => redactConditions(conditions, body)
          : undefined;

      return {
        allowed: true,
        matchedCapability,
        ...(applyResponseRedactions ? { applyResponseRedactions } : {}),
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
    denialCode?: string,
    conditionType?: string,
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
      tenantId: payload.authorizedBy.tenantId,
      denialCode,
      conditionType,
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
    tenantId?: string;
    denialCode?: string;
    conditionType?: string;
  }): Promise<SignedAuditEvidence | null> {
    if (!this.evidenceSigner && !this.auditPipeline) {
      return null;
    }

    let evidence: AuditEvidence;
    try {
      evidence = createAuditEvidence({
        ...params,
        policyVersion: this.policyVersion,
      });
    } catch (error) {
      this.logger.error('Failed to build audit evidence', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }

    // R-9: prefer the async pipeline. Enqueue is fire-and-forget under
    // the default backpressure policy, so the request critical path
    // does not pay signing latency. The pipeline owns the call to
    // `signEvidence` and the "evidence generated" log line (wired in
    // bootstrap via `onSigned`); we therefore return `null` here so
    // callers don't depend on a synchronously-signed value that no
    // longer exists on the hot path.
    //
    // Under the `block` backpressure policy we MUST await the enqueue:
    // the caller chose `block` precisely so the producer pays
    // backpressure when the buffer is full. Fire-and-forget there
    // would let promise-resolver objects pile up unboundedly while
    // the buffer stayed pinned. The pipeline still caps parked
    // waiters at `maxWaiters` (and drops with a metric beyond that)
    // as a defence-in-depth bound, but the await is what actually
    // delivers the documented backpressure semantics.
    if (this.auditPipeline) {
      const enqueued = this.auditPipeline.enqueue(evidence);
      if (this.auditPipeline.backpressurePolicy === 'block') {
        await enqueued;
      } else {
        // `void` is intentional: under the drop policy `enqueue` is
        // microtask-resolved and awaiting would re-add the latency
        // R-9 just removed. Errors thrown synchronously (none under
        // the current implementation) are swallowed by the
        // surrounding try/catch in `validateAction`'s callers.
        void enqueued;
      }
      return null;
    }

    try {
      const signedEvidence = await this.evidenceSigner!.signEvidence(evidence);

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
    agentSub?: string,
  ): ConditionContext {
    const ctx = (request.context ?? {}) as Record<string, unknown>;
    const ctxOut: ConditionContext = {
      now: new Date(),
      counterStore: this.callCounterStore,
      counterKey: capabilityId,
      agentSub,
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

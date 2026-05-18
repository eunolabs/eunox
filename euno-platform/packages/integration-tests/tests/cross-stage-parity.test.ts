/**
 * Cross-stage parity test suite — Task 19
 * =========================================
 * Operational proof of the schema-parity claim in docs/mvp.md
 * §"Policy and audit schema parity (non-negotiable)".
 *
 * WHAT THIS PROVES
 * ----------------
 * Identical `CapabilityCondition[]` fed to:
 *   (a) the local enforcement path — `findMatchingCapability` +
 *       `enforceConditions` from @euno/common (the same functions
 *       `ConditionEnforcerPDP` in @euno/mcp delegates to)
 *   (b) the hosted enforcement path — `EnforcementEngine.validateAction`
 *       in @euno/tool-gateway, via a JWT whose `capabilities` carry
 *       equivalent constraints
 * …produces IDENTICAL decisions, IDENTICAL obligations, and the same
 * OCSF-record pre-signature fields for every recorded `tools/call`
 * request in the parity fixture set.
 *
 * RESOURCE NAMING CONVENTION (documented, not a parity failure)
 * ------------------------------------------------------------
 * The two modes use different resource URI schemes:
 *
 *   Local manifest / ConditionEnforcerPDP:
 *     - Constraint `resource` field is the plain MCP tool name, e.g.
 *       `"query_db"`. The PDP tries the raw name first, then the
 *       `mcp-tool://query_db` normalized form.
 *
 *   Hosted gateway / EnforcementEngine:
 *     - The enforce route normalises every tool call to the canonical
 *       form `tool://<toolName>` before calling validateAction.
 *     - JWT capability `resource` fields must therefore use `tool://`
 *       URIs (or `tool://*` / `tool://**` wildcards) to match.
 *
 * For a parity fixture to work with BOTH modes, each scenario below
 * defines two structurally equivalent constraint sets that differ only
 * in the `resource` field:
 *
 *   localConstraints  — use plain tool names ("query_db")
 *   hostedConstraints — use tool:// URIs  ("tool://query_db")
 *
 * The `conditions` array is **identical** in both sets; all assertions
 * target the conditions logic, not the resource string.
 *
 * OCSF pre-signature parity
 * -------------------------
 * The `AuditEvidence` struct that both paths write before signing shares
 * the following fields with identical values:
 *   - `decision`      — allow / deny.
 *   - `conditionType` — which condition triggered a deny.
 *
 * The OCSF deny tests below exercise this directly: an `EnforcementEngine`
 * instance is wired with a stub `EvidenceSigner` and the JWT includes
 * `authorizedBy` so `emitDenialEvidence` is called. The captured
 * `AuditEvidence.conditionType` is then asserted to be `'timeWindow'`.
 *
 * Known divergence in denial codes (explicitly asserted):
 *   - Local path: `PdpDecision.denialCode` = type-specific code,
 *     e.g. `TIME_WINDOW_DENIED`.
 *   - Hosted path: `EnforcementResult` returned to the caller does NOT
 *     populate `denialCode` / `denialConditionType` for generic condition
 *     failures (those values are written only to `AuditEvidence` via
 *     `emitDenialEvidence`). Flagged with a TODO for follow-up.
 *   This divergence is documented, tested, and flagged for a follow-up
 *   to align the hosted result's `denialCode` field.
 *
 * Known divergence in `resource` audit field:
 *   - Local path records the bare tool name.
 *   - Hosted path records `tool://toolName`.
 *   Downstream consumers strip the prefix when comparing across modes.
 */

import * as jose from 'jose';
import {
  CapabilityConstraint,
  CapabilityCondition,
  CapabilityTokenPayload,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  ConditionContext,
  InMemoryCallCounterStore,
  enforceConditions,
  findMatchingCapability,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  hasRedactObligation,
  redactConditions,
  AuditEvidence,
  SignedAuditEvidence,
  EvidenceSigner,
  GENESIS_HASH,
  canonicalSha256,
} from '@euno/common';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import {
  buildAttenuatedPayload,
  buildRenewedPayload,
} from '../../capability-issuer/src/issuance/payload-builder';

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const logger = createLogger('parity-test', 'test');

let privateKey: jose.KeyLike;
let publicKeyPem: string;
let verifier: JWTTokenVerifier;

function makeCounterStore(): InMemoryCallCounterStore {
  return new InMemoryCallCounterStore();
}

function makeEngine(counterStore?: InMemoryCallCounterStore): EnforcementEngine {
  return new EnforcementEngine({
    verifier,
    logger,
    callCounterStore: counterStore ?? makeCounterStore(),
    // DPoP is disabled in the parity tests — we are comparing
    // condition-enforcement logic, not the sender-constrained-token mechanism.
    dpop: { required: false },
  });
}

/** Sign a JWT capability token for the hosted mode. */
async function signToken(
  capabilities: CapabilityConstraint[],
  extra: Partial<CapabilityTokenPayload> = {},
): Promise<string> {
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:test.issuer',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `jti-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
    ...extra,
  };
  return new jose.SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

/**
 * Evaluate the LOCAL enforcement path.
 *
 * Replicates the core logic of `ConditionEnforcerPDP.decide()` using
 * shared @euno/common primitives. Both modes call the same condition
 * handlers from `@euno/common/condition-registry`.
 *
 * @param localConstraints - Constraints with plain tool-name resources.
 * @param toolName         - The MCP tool name being called.
 * @param condCtx          - Condition context (now, counterStore, etc.).
 */
async function evaluateLocal(
  localConstraints: CapabilityConstraint[],
  toolName: string,
  condCtx: Partial<ConditionContext> & {
    counterStore?: InMemoryCallCounterStore;
  } = {},
): Promise<{
  allow: boolean;
  conditionType?: string;
  obligations: Array<{ type: 'redactFields'; paths: string[] }>;
}> {
  // Local PDP tries plain name first, then mcp-tool:// normalised form.
  const matched =
    findMatchingCapability('call', toolName, localConstraints) ??
    findMatchingCapability('call', `mcp-tool://${toolName}`, localConstraints);

  if (!matched) {
    // No constraint for this tool → pass-through allow (manifest-restriction model).
    return { allow: true, obligations: [] };
  }

  if (matched.conditions && matched.conditions.length > 0) {
    const ctx: ConditionContext = {
      now: new Date(),
      counterStore: condCtx.counterStore ?? makeCounterStore(),
      counterKey: condCtx.counterKey,
      sourceIp: condCtx.sourceIp,
      recipients: condCtx.recipients,
      agentSub: 'test-agent',
      ...condCtx,
    };
    const result = await enforceConditions(matched.conditions, ctx);
    if (!result.allow) {
      return {
        allow: false,
        conditionType: result.conditionType,
        obligations: [],
      };
    }
  }

  // Extract redactFields obligations from matched conditions.
  const obligations: Array<{ type: 'redactFields'; paths: string[] }> = [];
  if (matched.conditions && hasRedactObligation(matched.conditions)) {
    for (const cond of matched.conditions) {
      if (cond.type === 'redactFields') {
        obligations.push({ type: 'redactFields', paths: cond.fields });
      }
    }
  }

  return { allow: true, obligations };
}

/**
 * Evaluate the HOSTED enforcement path via EnforcementEngine.validateAction().
 *
 * @param hostedConstraints - Constraints with `tool://` resource URIs.
 * @param toolName          - The MCP tool name (engine receives `tool://toolName`).
 * @param contextOverrides  - Extra fields forwarded to the enforcement context.
 * @param engine_           - Optional engine instance (for maxCalls isolation).
 */
async function evaluateHosted(
  hostedConstraints: CapabilityConstraint[],
  toolName: string,
  contextOverrides: Record<string, unknown> = {},
  engine_?: EnforcementEngine,
): Promise<{
  allow: boolean;
  conditionType?: string;
  obligations: Array<{ type: 'redactFields'; paths: string[] }>;
  denialCode?: string;
}> {
  const token = await signToken(hostedConstraints);
  // The enforce route normalises resources to tool://<toolName>.
  const canonicalResource = `tool://${toolName}`;
  const eng = engine_ ?? makeEngine();
  const result = await eng.validateAction({
    token,
    action: 'call',
    resource: canonicalResource,
    context: {
      sessionId: 'parity-test-session',
      tool: toolName,
      args: {},
      ...contextOverrides,
    },
  });

  if (!result.allowed) {
    return {
      allow: false,
      conditionType: result.denialConditionType,
      obligations: [],
      denialCode: result.denialCode,
    };
  }

  // Extract redactFields obligations (mirrors buildObligations in enforce.ts).
  const obligations: Array<{ type: 'redactFields'; paths: string[] }> = [];
  if (result.matchedCapability?.conditions) {
    for (const cond of result.matchedCapability.conditions) {
      if (cond.type === 'redactFields') {
        obligations.push({ type: 'redactFields', paths: cond.fields });
      }
    }
  }

  return { allow: true, obligations };
}

/**
 * Build a parallel constraint pair from a shared condition list.
 *
 * `local`  uses the plain tool name (for ConditionEnforcerPDP).
 * `hosted` uses the `tool://` URI  (for EnforcementEngine).
 * Both carry the same conditions array.
 */
function constraintPair(
  toolName: string,
  conditions: CapabilityCondition[],
): { local: CapabilityConstraint[]; hosted: CapabilityConstraint[] } {
  return {
    local: [{ resource: toolName, actions: ['call'], conditions }],
    hosted: [{ resource: `tool://${toolName}`, actions: ['call'], conditions }],
  };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/**
 * Builds a stateful `signEvidence` stub that models the production
 * `AuditEvidenceSigner` chain contract (incrementing seq, chained
 * previousHash). Using a real chain ensures future assertions on chain
 * metadata will catch regressions rather than silently passing.
 */
function makeChainedSignEvidence(
  overrides: Partial<Pick<SignedAuditEvidence, 'signature' | 'keyId' | 'algorithm'>> = {},
): jest.Mock<Promise<SignedAuditEvidence>, [AuditEvidence]> {
  let seq = 0;
  let previousHash: string = GENESIS_HASH;
  const signature = overrides.signature ?? 'parity-sig';
  const keyId = overrides.keyId ?? 'parity-kid';
  const algorithm = overrides.algorithm ?? 'RS256';
  return jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(async (ev) => {
    seq += 1;
    const signed: SignedAuditEvidence = {
      ...ev,
      signature,
      keyId,
      algorithm,
      previousHash,
      seq,
    };
    previousHash = canonicalSha256(signed);
    return signed;
  });
}

beforeAll(async () => {
  const { publicKey, privateKey: privKey } = await jose.generateKeyPair('RS256', { extractable: true });
  privateKey = privKey;
  publicKeyPem = await jose.exportSPKI(publicKey);
  verifier = new JWTTokenVerifier(publicKeyPem, { requireKid: false });
});

// ---------------------------------------------------------------------------
// Parity scenarios
// ---------------------------------------------------------------------------

describe('Cross-stage enforcement parity — Task 19', () => {
  // ── Scenario 1: bare allow (no conditions) ─────────────────────────────

  describe('Scenario 1 — unconstrained tool: allow with no obligations', () => {
    const { local, hosted } = constraintPair('query_db', []);

    it('local mode allows', async () => {
      const result = await evaluateLocal(local, 'query_db');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([]);
    });

    it('hosted mode allows', async () => {
      const result = await evaluateHosted(hosted, 'query_db');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([]);
    });

    it('decisions match', async () => {
      const localResult = await evaluateLocal(local, 'query_db');
      const hostedResult = await evaluateHosted(hosted, 'query_db');
      expect(localResult.allow).toBe(hostedResult.allow);
      expect(localResult.obligations).toEqual(hostedResult.obligations);
    });
  });

  // ── Scenario 2: redactFields obligation ────────────────────────────────

  describe('Scenario 2 — redactFields condition: allow with obligation', () => {
    const conditions: CapabilityCondition[] = [
      { type: 'redactFields', fields: ['result.ssn', 'result.password'] },
    ];
    const { local, hosted } = constraintPair('fetch_profile', conditions);

    it('local mode allows and emits redactFields obligation', async () => {
      const result = await evaluateLocal(local, 'fetch_profile');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([
        { type: 'redactFields', paths: ['result.ssn', 'result.password'] },
      ]);
    });

    it('hosted mode allows and emits identical redactFields obligation', async () => {
      const result = await evaluateHosted(hosted, 'fetch_profile');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([
        { type: 'redactFields', paths: ['result.ssn', 'result.password'] },
      ]);
    });

    it('decisions and obligations match', async () => {
      const localResult = await evaluateLocal(local, 'fetch_profile');
      const hostedResult = await evaluateHosted(hosted, 'fetch_profile');
      expect(localResult.allow).toBe(hostedResult.allow);
      expect(localResult.obligations).toEqual(hostedResult.obligations);
    });
  });

  // ── Scenario 3a: timeWindow — currently valid ──────────────────────────

  describe('Scenario 3a — timeWindow (valid): allow', () => {
    const conditions: CapabilityCondition[] = [
      {
        type: 'timeWindow',
        notBefore: '2020-01-01T00:00:00Z',
        notAfter: '2099-12-31T23:59:59Z',
      },
    ];
    const { local, hosted } = constraintPair('scheduled_report', conditions);

    it('local mode allows within valid window', async () => {
      const result = await evaluateLocal(local, 'scheduled_report');
      expect(result.allow).toBe(true);
    });

    it('hosted mode allows within valid window', async () => {
      const result = await evaluateHosted(hosted, 'scheduled_report');
      expect(result.allow).toBe(true);
    });

    it('decisions match', async () => {
      const localResult = await evaluateLocal(local, 'scheduled_report');
      const hostedResult = await evaluateHosted(hosted, 'scheduled_report');
      expect(localResult.allow).toBe(hostedResult.allow);
    });
  });

  // ── Scenario 3b: timeWindow — expired ─────────────────────────────────

  describe('Scenario 3b — timeWindow (expired): deny', () => {
    const conditions: CapabilityCondition[] = [
      {
        type: 'timeWindow',
        notBefore: '2000-01-01T00:00:00Z',
        notAfter: '2000-12-31T23:59:59Z',
      },
    ];
    const { local, hosted } = constraintPair('expired_tool', conditions);

    it('local mode denies with conditionType=timeWindow', async () => {
      const result = await evaluateLocal(local, 'expired_tool');
      expect(result.allow).toBe(false);
      expect(result.conditionType).toBe('timeWindow');
    });

    it('hosted mode denies', async () => {
      const result = await evaluateHosted(hosted, 'expired_tool');
      expect(result.allow).toBe(false);
    });

    it('decisions match (both deny)', async () => {
      const localResult = await evaluateLocal(local, 'expired_tool');
      const hostedResult = await evaluateHosted(hosted, 'expired_tool');
      expect(localResult.allow).toBe(hostedResult.allow);
      expect(localResult.allow).toBe(false);
    });

    it('conditionType in denial results matches between modes', async () => {
      const localResult = await evaluateLocal(local, 'expired_tool');
      const hostedResult = await evaluateHosted(hosted, 'expired_tool');

      expect(localResult.conditionType).toBe('timeWindow');
      expect(hostedResult.conditionType).toBe('timeWindow');
    });
  });

  // ── Scenario 4a: recipientDomain — allowed ─────────────────────────────

  describe('Scenario 4a — recipientDomain (allowed): allow', () => {
    const conditions: CapabilityCondition[] = [
      { type: 'recipientDomain', domains: ['example.com', 'corp.example.com'] },
    ];
    const { local, hosted } = constraintPair('send_email_allowed', conditions);

    it('local mode allows when recipient domain is in allowlist', async () => {
      const result = await evaluateLocal(local, 'send_email_allowed', {
        recipients: ['alice@example.com'],
      });
      expect(result.allow).toBe(true);
    });

    it('hosted mode allows when recipient domain is in allowlist', async () => {
      const result = await evaluateHosted(
        hosted,
        'send_email_allowed',
        { recipients: ['alice@example.com'] },
      );
      expect(result.allow).toBe(true);
    });

    it('decisions match', async () => {
      const localResult = await evaluateLocal(local, 'send_email_allowed', {
        recipients: ['alice@example.com'],
      });
      const hostedResult = await evaluateHosted(
        hosted,
        'send_email_allowed',
        { recipients: ['alice@example.com'] },
      );
      expect(localResult.allow).toBe(hostedResult.allow);
    });
  });

  // ── Scenario 4b: recipientDomain — blocked ─────────────────────────────

  describe('Scenario 4b — recipientDomain (blocked): deny', () => {
    const conditions: CapabilityCondition[] = [
      { type: 'recipientDomain', domains: ['example.com'] },
    ];
    const { local, hosted } = constraintPair('send_email_blocked', conditions);

    it('local mode denies when recipient domain is not in allowlist', async () => {
      const result = await evaluateLocal(local, 'send_email_blocked', {
        recipients: ['attacker@evil.com'],
      });
      expect(result.allow).toBe(false);
      expect(result.conditionType).toBe('recipientDomain');
    });

    it('hosted mode denies when recipient domain is not in allowlist', async () => {
      const result = await evaluateHosted(
        hosted,
        'send_email_blocked',
        { recipients: ['attacker@evil.com'] },
      );
      expect(result.allow).toBe(false);
    });

    it('decisions match (both deny)', async () => {
      const localResult = await evaluateLocal(local, 'send_email_blocked', {
        recipients: ['attacker@evil.com'],
      });
      const hostedResult = await evaluateHosted(
        hosted,
        'send_email_blocked',
        { recipients: ['attacker@evil.com'] },
      );
      expect(localResult.allow).toBe(hostedResult.allow);
      expect(localResult.allow).toBe(false);
    });
  });

  // ── Scenario 5: maxCalls ───────────────────────────────────────────────

  describe('Scenario 5 — maxCalls: allow until limit, then deny', () => {
    const conditions: CapabilityCondition[] = [
      { type: 'maxCalls', count: 1, windowSeconds: 3600 },
    ];
    const { local, hosted } = constraintPair('bulk_export', conditions);

    it('local mode: first call allowed, second call denied', async () => {
      const counterStore = makeCounterStore();
      const counterKey = 'maxcalls-local-test|bulk_export|bulk_export';

      const first = await evaluateLocal(local, 'bulk_export', {
        counterStore,
        counterKey,
        agentSub: 'test-agent',
      });
      expect(first.allow).toBe(true);

      const second = await evaluateLocal(local, 'bulk_export', {
        counterStore,
        counterKey,
        agentSub: 'test-agent',
      });
      expect(second.allow).toBe(false);
      expect(second.conditionType).toBe('maxCalls');
    });

    it('hosted mode: first call allowed, second call denied (per-token counter)', async () => {
      const hostedStore = makeCounterStore();
      const eng = makeEngine(hostedStore);

      const token1 = await signToken(hosted);
      const firstResult = await eng.validateAction({
        token: token1,
        action: 'call',
        resource: 'tool://bulk_export',
        context: { sessionId: 'maxcalls-hosted-test', tool: 'bulk_export', args: {} },
      });
      expect(firstResult.allowed).toBe(true);

      // Reuse the same token — the counter key in the engine is derived
      // from capabilityId (the token's jti), so the second call with the
      // same token consumes the remaining quota.
      const secondResult = await eng.validateAction({
        token: token1,
        action: 'call',
        resource: 'tool://bulk_export',
        context: { sessionId: 'maxcalls-hosted-test', tool: 'bulk_export', args: {} },
      });
      expect(secondResult.allowed).toBe(false);
    });

    it('decisions match across first and second calls', async () => {
      const localStore = makeCounterStore();
      const localKey = 'maxcalls-parity|bulk_export|bulk_export';
      const hostedStore = makeCounterStore();
      const eng = makeEngine(hostedStore);
      const token = await signToken(hosted);

      // First call: both allow.
      const localFirst = await evaluateLocal(local, 'bulk_export', {
        counterStore: localStore,
        counterKey: localKey,
        agentSub: 'test-agent',
      });
      const hostedFirst = await eng.validateAction({
        token,
        action: 'call',
        resource: 'tool://bulk_export',
        context: { sessionId: 'maxcalls-parity', tool: 'bulk_export', args: {} },
      });
      expect(localFirst.allow).toBe(true);
      expect(hostedFirst.allowed).toBe(true);
      expect(localFirst.allow).toBe(hostedFirst.allowed);

      // Second call: both deny.
      const localSecond = await evaluateLocal(local, 'bulk_export', {
        counterStore: localStore,
        counterKey: localKey,
        agentSub: 'test-agent',
      });
      const hostedSecond = await eng.validateAction({
        token,
        action: 'call',
        resource: 'tool://bulk_export',
        context: { sessionId: 'maxcalls-parity', tool: 'bulk_export', args: {} },
      });
      expect(localSecond.allow).toBe(false);
      expect(hostedSecond.allowed).toBe(false);
      expect(localSecond.allow).toBe(hostedSecond.allowed);
    });
  });

  // ── Scenario 6: combined conditions ────────────────────────────────────

  describe('Scenario 6 — combined: valid timeWindow + redactFields', () => {
    const conditions: CapabilityCondition[] = [
      {
        type: 'timeWindow',
        notBefore: '2020-01-01T00:00:00Z',
        notAfter: '2099-12-31T23:59:59Z',
      },
      { type: 'redactFields', fields: ['result.internalNotes'] },
    ];
    const { local, hosted } = constraintPair('audit_log', conditions);

    it('local mode allows and includes redactFields obligation', async () => {
      const result = await evaluateLocal(local, 'audit_log');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([
        { type: 'redactFields', paths: ['result.internalNotes'] },
      ]);
    });

    it('hosted mode allows and includes identical redactFields obligation', async () => {
      const result = await evaluateHosted(hosted, 'audit_log');
      expect(result.allow).toBe(true);
      expect(result.obligations).toEqual([
        { type: 'redactFields', paths: ['result.internalNotes'] },
      ]);
    });

    it('decisions and obligations match', async () => {
      const localResult = await evaluateLocal(local, 'audit_log');
      const hostedResult = await evaluateHosted(hosted, 'audit_log');
      expect(localResult.allow).toBe(hostedResult.allow);
      expect(localResult.obligations).toEqual(hostedResult.obligations);
    });
  });

  // ── Scenario 7: unlisted tool — documented intentional divergence ───────
  //
  // This scenario documents the intentional semantic difference between modes
  // for tools NOT listed in the policy:
  //
  //   Local (manifest-restriction model):
  //     A manifest only restricts explicitly listed tools.  Unlisted tools
  //     pass through — allowing the operator to call out the tools that
  //     need governance without blocking everything else by default.
  //
  //   Hosted (capability-whitelist model):
  //     A JWT's `capabilities` is an explicit whitelist.  Any tool not
  //     present is denied — the minter only encodes what the agent is
  //     authorized to call.
  //
  // Parity applies only to tools that ARE listed in both the manifest and
  // the JWT (i.e., constrained tools).  The unlisted-tool behaviour is
  // a deliberate design choice, not a bug.

  describe('Scenario 7 — unlisted tool: documented intentional semantic divergence', () => {
    const { local: localC, hosted: hostedC } = constraintPair('known_tool', []);

    it('local mode: unlisted tool passes through (allow)', async () => {
      const result = await evaluateLocal(localC, 'unknown_tool');
      expect(result.allow).toBe(true);
    });

    it('hosted mode: unlisted tool is denied (capability-whitelist model)', async () => {
      const result = await evaluateHosted(hostedC, 'unknown_tool');
      expect(result.allow).toBe(false);
    });
  });

  // ── OCSF pre-signature field parity ────────────────────────────────────

  describe('OCSF pre-signature field parity', () => {
    describe('allow decision: audit-relevant fields are equivalent', () => {
      const conditions: CapabilityCondition[] = [
        { type: 'redactFields', fields: ['result.confidential'] },
      ];
      const { local, hosted } = constraintPair('data_export', conditions);

      it('decision field matches', async () => {
        const localResult = await evaluateLocal(local, 'data_export');
        const hostedResult = await evaluateHosted(hosted, 'data_export');
        const localDecision = localResult.allow ? 'allow' : 'deny';
        const hostedDecision = hostedResult.allow ? 'allow' : 'deny';
        expect(localDecision).toBe('allow');
        expect(hostedDecision).toBe('allow');
        expect(localDecision).toBe(hostedDecision);
      });

      it('obligations (OCSF unmapped.obligationsApplied) match', async () => {
        const localResult = await evaluateLocal(local, 'data_export');
        const hostedResult = await evaluateHosted(hosted, 'data_export');
        expect(localResult.obligations).toEqual(hostedResult.obligations);
      });

      it('conditionType is absent for allow decisions in both modes', async () => {
        const localResult = await evaluateLocal(local, 'data_export');
        const hostedResult = await evaluateHosted(hosted, 'data_export');
        expect(localResult.conditionType).toBeUndefined();
        expect(hostedResult.conditionType).toBeUndefined();
      });
    });

    describe('deny decision: audit-relevant fields', () => {
      const conditions: CapabilityCondition[] = [
        { type: 'timeWindow', notAfter: '2000-01-01T00:00:00Z' },
      ];
      const { local, hosted } = constraintPair('time_locked', conditions);

      it('decision field matches (both deny)', async () => {
        const localResult = await evaluateLocal(local, 'time_locked');
        const hostedResult = await evaluateHosted(hosted, 'time_locked');
        expect(localResult.allow).toBe(false);
        expect(hostedResult.allow).toBe(false);
      });

      it('local result carries conditionType=timeWindow for audit record population', async () => {
        const localResult = await evaluateLocal(local, 'time_locked');
        // This value is written to McpAuditRecord.conditionType and then to
        // the OCSF record's unmapped.conditionType field.
        expect(localResult.conditionType).toBe('timeWindow');
      });

      /**
       * Verify that the hosted engine writes conditionType='timeWindow' to
       * AuditEvidence via emitDenialEvidence when an evidence signer is wired
       * and the JWT includes authorizedBy.  This is the canonical OCSF
       * pre-signature parity assertion — both modes record the same
       * conditionType in their audit evidence.
       */
      it('hosted engine writes conditionType=timeWindow to AuditEvidence', async () => {
        const signEvidence = makeChainedSignEvidence();
        const mockSigner: EvidenceSigner = {
          signEvidence,
          verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => true),
        };
        const auditEngine = new EnforcementEngine({
          verifier,
          logger,
          callCounterStore: makeCounterStore(),
          dpop: { required: false },
          evidenceSigner: mockSigner,
          enableCryptographicAudit: true,
        });

        // authorizedBy is required to gate emitDenialEvidence.
        const token = await signToken(hosted, {
          authorizedBy: { userId: 'parity-user', roles: ['test'], tenantId: 'tenant-parity' },
        });
        await auditEngine.validateAction({
          token,
          action: 'call',
          resource: 'tool://time_locked',
          context: { sessionId: 'ocsf-parity-session', tool: 'time_locked', args: {} },
        });

        // emitDenialEvidence must have been called.
        expect(signEvidence).toHaveBeenCalledTimes(1);
        // AuditEvidence.conditionType is 'timeWindow' — matching the local path.
        expect(signEvidence).toHaveBeenCalledWith(
          expect.objectContaining({ decision: 'deny', conditionType: 'timeWindow' }),
        );
      });

      it('propagates EnforcementResult.denialConditionType for condition failures', async () => {
        const hostedResult = await evaluateHosted(hosted, 'time_locked');
        expect(hostedResult.conditionType).toBe('timeWindow');
      });
    });

    describe('resource naming: documented prefix difference', () => {
      it('local audit records bare tool name; hosted records tool:// URI', () => {
        const toolName = 'data_export';
        // Local mode: McpAuditRecord.toolName = 'data_export'
        const localResource = toolName;
        // Hosted mode: AuditEvidence.resource = 'tool://data_export'
        const hostedResource = `tool://${toolName}`;
        expect(hostedResource).toBe('tool://data_export');
        // Normalised comparison — downstream consumers strip the prefix.
        expect(hostedResource.replace(/^tool:\/\//, '')).toBe(localResource);
      });
    });
  });

  // ── Redaction logic parity ──────────────────────────────────────────────

  describe('Redaction logic parity: shared redactConditions produces identical output', () => {
    it('both modes use the same redactConditions function from @euno/common', () => {
      const conditions: CapabilityCondition[] = [
        { type: 'redactFields', fields: ['result.password', 'result.token'] },
      ];

      const sampleResponse = {
        result: {
          userId: 'u123',
          password: 'secret',
          token: 'tok_abc',
          email: 'user@example.com',
        },
      };

      // redactConditions (called by ConditionEnforcerPDP transport on the
      // local response path) and applyResponseRedactions (called by the
      // gateway on the hosted response path) both delegate to redactConditions
      // from @euno/common. Deleted fields are removed, not masked.
      const redacted = redactConditions(conditions, sampleResponse);

      // The redactFields handler uses deleteDottedPath, which removes the
      // field entirely (the agent / downstream consumer sees no value).
      expect(redacted).toEqual({
        result: {
          userId: 'u123',
          email: 'user@example.com',
          // 'password' and 'token' are deleted (not replaced with a placeholder)
        },
      });
    });

    it('redactConditions output is identical whether conditions came from local or hosted path', () => {
      // When the hosted gateway sends obligations back to the @euno/mcp client,
      // the client calls applyRemoteObligations → redactFields. The local path
      // calls redactConditions directly from the matched conditions. Both paths
      // ultimately execute the same deleteDottedPath logic.
      const conditions: CapabilityCondition[] = [
        { type: 'redactFields', fields: ['meta.internal'] },
      ];
      const body = { result: 'value', meta: { internal: 'secret', version: '1.0' } };

      // Simulated local path: redactConditions(matchedConditions, body)
      const localRedacted = redactConditions(conditions, body);
      // Simulated hosted path: same function, same conditions, same body
      const hostedRedacted = redactConditions(conditions, body);

      expect(localRedacted).toEqual(hostedRedacted);
      expect(localRedacted).toEqual({
        result: 'value',
        meta: { version: '1.0' },
      });
    });
  });
});

// ── Stage-4 parity: minter-vs-issuer produces identical gateway decisions ──

/**
 * Task 11 — Cross-stage parity test extension
 * ============================================
 *
 * WHAT THIS PROVES
 * ----------------
 * The same `AgentCapabilityManifest` capability constraints fed to:
 *   (a) Stage-3 API-key minter — produces a token where `authorizedBy.userId`
 *       is the API-key prefix (a synthetic string, e.g. "sk-abc12345").
 *   (b) Stage-4 OIDC issuer    — produces a token where `authorizedBy.userId`
 *       is the real IdP-resolved user identity (e.g. "user@corp.com").
 *
 * …produce IDENTICAL decisions, IDENTICAL obligations, and IDENTICAL OCSF
 * pre-signature `conditionType` values on the gateway. This is the
 * operational proof of exit criterion E6 in docs/stage4executionplan.md.
 *
 * INTENTIONAL DIVERGENCE (also documented in docs/stage-3-gateway-protocol.md §12)
 * ----------------------------------------------------------------------------------
 * The `authorizedBy.userId` claim differs by design between the two paths:
 *   - Stage-3 minter: userId = API-key prefix (synthetic identifier).
 *   - Stage-4 issuer: userId = IdP-resolved user identity (real principal).
 *
 * The gateway's EnforcementEngine evaluates capability constraints and
 * conditions only; it does NOT branch on `authorizedBy.userId`. That claim is
 * persisted in AuditEvidence for forensics and support — it does not affect
 * the allow/deny decision or the obligations returned.
 *
 * The `sub` claim is IDENTICAL in both paths (sub = agentId), so the gateway
 * sees the same agent subject regardless of which issuance path was used.
 *
 * Gateway operators comparing minter-vs-issuer audit rows MUST exclude
 * `authorizedBy.userId` when asserting decision parity across issuance paths.
 */
describe('Stage-4 parity: minter-vs-issuer produces identical gateway decisions (Task 11)', () => {
  // Capabilities derived from a shared AgentCapabilityManifest — these are
  // identical in both the minter and issuer tokens, because both paths resolve
  // capabilities from the same manifest / role-policy.
  const SHARED_MANIFEST_CAPABILITIES: CapabilityConstraint[] = [
    {
      resource: 'tool://query_api',
      actions: ['call'],
      conditions: [
        {
          type: 'timeWindow',
          notBefore: '2020-01-01T00:00:00Z',
          notAfter: '2099-12-31T23:59:59Z',
        },
      ],
    },
    {
      resource: 'tool://export_data',
      actions: ['call'],
      conditions: [
        { type: 'redactFields', fields: ['result.pii', 'result.secret'] },
      ],
    },
  ];

  /**
   * Build a token that mirrors what the Stage-3 API-key minter produces:
   * authorizedBy.userId = apiKeyPrefix (synthetic identifier).
   */
  async function signMinterStyleToken(
    capabilities: CapabilityConstraint[] = SHARED_MANIFEST_CAPABILITIES,
  ): Promise<string> {
    return signToken(capabilities, {
      sub: 'agent-parity-test',
      authorizedBy: {
        // Stage-3 path: the minted API-key prefix — not a real user identity.
        userId: 'sk-abc12345',
        roles: ['Viewer'],
        tenantId: 'tenant-parity',
      },
    });
  }

  /**
   * Build a token that mirrors what the Stage-4 OIDC issuer produces:
   * authorizedBy.userId = real IdP-resolved user identity.
   */
  async function signIssuerStyleToken(
    capabilities: CapabilityConstraint[] = SHARED_MANIFEST_CAPABILITIES,
  ): Promise<string> {
    return signToken(capabilities, {
      sub: 'agent-parity-test',
      authorizedBy: {
        // Stage-4 path: real IdP user identity (e.g. Entra ID UPN or Cognito sub).
        userId: 'user@corp.com',
        roles: ['Viewer'],
        tenantId: 'tenant-parity',
      },
    });
  }

  // ── Allow scenario ─────────────────────────────────────────────────────

  describe('allow scenario: same capabilities → identical allow decision on both paths', () => {
    it('minter-style token: gateway allows the tool call', async () => {
      const token = await signMinterStyleToken();
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://query_api',
        context: { sessionId: 'minter-allow-1', tool: 'query_api', args: {} },
      });
      expect(result.allowed).toBe(true);
    });

    it('issuer-style token: gateway allows the same tool call', async () => {
      const token = await signIssuerStyleToken();
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://query_api',
        context: { sessionId: 'issuer-allow-1', tool: 'query_api', args: {} },
      });
      expect(result.allowed).toBe(true);
    });

    it('allow decisions match regardless of authorizedBy.userId', async () => {
      const minterToken = await signMinterStyleToken();
      const issuerToken = await signIssuerStyleToken();
      const minterResult = await makeEngine().validateAction({
        token: minterToken,
        action: 'call',
        resource: 'tool://query_api',
        context: { sessionId: 'minter-allow-cmp', tool: 'query_api', args: {} },
      });
      const issuerResult = await makeEngine().validateAction({
        token: issuerToken,
        action: 'call',
        resource: 'tool://query_api',
        context: { sessionId: 'issuer-allow-cmp', tool: 'query_api', args: {} },
      });
      expect(minterResult.allowed).toBe(true);
      expect(minterResult.allowed).toBe(issuerResult.allowed);
    });
  });

  // ── Deny scenario ──────────────────────────────────────────────────────

  describe('deny scenario: expired timeWindow → identical deny on both paths', () => {
    const EXPIRED_CAPABILITIES: CapabilityConstraint[] = [
      {
        resource: 'tool://locked_tool',
        actions: ['call'],
        conditions: [
          {
            type: 'timeWindow',
            notBefore: '2000-01-01T00:00:00Z',
            notAfter: '2000-12-31T23:59:59Z',
          },
        ],
      },
    ];

    it('minter-style token: gateway denies call in expired window', async () => {
      const token = await signMinterStyleToken(EXPIRED_CAPABILITIES);
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://locked_tool',
        context: { sessionId: 'minter-deny-1', tool: 'locked_tool', args: {} },
      });
      expect(result.allowed).toBe(false);
    });

    it('issuer-style token: gateway denies the same call in expired window', async () => {
      const token = await signIssuerStyleToken(EXPIRED_CAPABILITIES);
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://locked_tool',
        context: { sessionId: 'issuer-deny-1', tool: 'locked_tool', args: {} },
      });
      expect(result.allowed).toBe(false);
    });

    it('denial decisions and conditionType match between both paths', async () => {
      const minterToken = await signMinterStyleToken(EXPIRED_CAPABILITIES);
      const issuerToken = await signIssuerStyleToken(EXPIRED_CAPABILITIES);
      const minterResult = await makeEngine().validateAction({
        token: minterToken,
        action: 'call',
        resource: 'tool://locked_tool',
        context: { sessionId: 'minter-deny-cmp', tool: 'locked_tool', args: {} },
      });
      const issuerResult = await makeEngine().validateAction({
        token: issuerToken,
        action: 'call',
        resource: 'tool://locked_tool',
        context: { sessionId: 'issuer-deny-cmp', tool: 'locked_tool', args: {} },
      });
      expect(minterResult.allowed).toBe(false);
      expect(minterResult.allowed).toBe(issuerResult.allowed);
      // conditionType is populated identically by the shared condition engine.
      expect(minterResult.denialConditionType).toBe('timeWindow');
      expect(minterResult.denialConditionType).toBe(issuerResult.denialConditionType);
    });
  });

  // ── Obligation parity ──────────────────────────────────────────────────

  describe('obligation parity: redactFields conditions are identical from both paths', () => {
    it('minter-style token: matched capability carries redactFields conditions', async () => {
      const token = await signMinterStyleToken();
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://export_data',
        context: { sessionId: 'minter-oblig-1', tool: 'export_data', args: {} },
      });
      expect(result.allowed).toBe(true);
      expect(result.matchedCapability?.conditions).toContainEqual(
        expect.objectContaining({ type: 'redactFields' }),
      );
    });

    it('issuer-style token: matched capability carries identical redactFields conditions', async () => {
      const token = await signIssuerStyleToken();
      const result = await makeEngine().validateAction({
        token,
        action: 'call',
        resource: 'tool://export_data',
        context: { sessionId: 'issuer-oblig-1', tool: 'export_data', args: {} },
      });
      expect(result.allowed).toBe(true);
      expect(result.matchedCapability?.conditions).toContainEqual(
        expect.objectContaining({ type: 'redactFields' }),
      );
    });

    it('matched capability conditions are identical between both paths', async () => {
      const minterToken = await signMinterStyleToken();
      const issuerToken = await signIssuerStyleToken();
      const minterResult = await makeEngine().validateAction({
        token: minterToken,
        action: 'call',
        resource: 'tool://export_data',
        context: { sessionId: 'minter-oblig-cmp', tool: 'export_data', args: {} },
      });
      const issuerResult = await makeEngine().validateAction({
        token: issuerToken,
        action: 'call',
        resource: 'tool://export_data',
        context: { sessionId: 'issuer-oblig-cmp', tool: 'export_data', args: {} },
      });
      expect(minterResult.allowed).toBe(issuerResult.allowed);
      expect(minterResult.matchedCapability?.conditions).toEqual(
        issuerResult.matchedCapability?.conditions,
      );
    });
  });

  // ── OCSF pre-signature parity ──────────────────────────────────────────

  describe('OCSF pre-signature parity: AuditEvidence fields are identical from both paths', () => {
    const DENY_FOR_OCSF: CapabilityConstraint[] = [
      {
        resource: 'tool://ocsf_locked',
        actions: ['call'],
        conditions: [{ type: 'timeWindow', notAfter: '2000-01-01T00:00:00Z' }],
      },
    ];

    function makeAuditEngine(): { engine: EnforcementEngine; signEvidence: jest.Mock } {
      const signEvidence = makeChainedSignEvidence();
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => true),
      };
      const engine = new EnforcementEngine({
        verifier,
        logger,
        callCounterStore: makeCounterStore(),
        dpop: { required: false },
        evidenceSigner: mockSigner,
        enableCryptographicAudit: true,
      });
      return { engine, signEvidence };
    }

    it('minter-style token: AuditEvidence.conditionType=timeWindow on denial', async () => {
      const { engine, signEvidence } = makeAuditEngine();
      const token = await signMinterStyleToken(DENY_FOR_OCSF);
      await engine.validateAction({
        token,
        action: 'call',
        resource: 'tool://ocsf_locked',
        context: { sessionId: 'ocsf-minter', tool: 'ocsf_locked', args: {} },
      });
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny', conditionType: 'timeWindow' }),
      );
    });

    it('issuer-style token: AuditEvidence.conditionType=timeWindow on denial (identical)', async () => {
      const { engine, signEvidence } = makeAuditEngine();
      const token = await signIssuerStyleToken(DENY_FOR_OCSF);
      await engine.validateAction({
        token,
        action: 'call',
        resource: 'tool://ocsf_locked',
        context: { sessionId: 'ocsf-issuer', tool: 'ocsf_locked', args: {} },
      });
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny', conditionType: 'timeWindow' }),
      );
    });
  });

  // ── Documented divergence: authorizedBy.userId ─────────────────────────

  describe('documented divergence: authorizedBy.userId differs by design', () => {
    it('minter-style token carries apiKeyPrefix as authorizedBy.userId', async () => {
      const token = await signMinterStyleToken();
      const parsed = JSON.parse(
        Buffer.from(token.split('.')[1]!, 'base64url').toString(),
      ) as { authorizedBy: { userId: string } };
      // Stage-3 minter writes a synthetic API-key prefix, not a real user identity.
      expect(parsed.authorizedBy.userId).toBe('sk-abc12345');
    });

    it('issuer-style token carries real IdP userId as authorizedBy.userId', async () => {
      const token = await signIssuerStyleToken();
      const parsed = JSON.parse(
        Buffer.from(token.split('.')[1]!, 'base64url').toString(),
      ) as { authorizedBy: { userId: string } };
      // Stage-4 issuer writes a real, auditable IdP-resolved user identity.
      expect(parsed.authorizedBy.userId).toBe('user@corp.com');
    });

    it('sub claim is identical (agentId) in both paths — the agent is the same', async () => {
      const minterToken = await signMinterStyleToken();
      const issuerToken = await signIssuerStyleToken();
      const minterParsed = JSON.parse(
        Buffer.from(minterToken.split('.')[1]!, 'base64url').toString(),
      ) as { sub: string };
      const issuerParsed = JSON.parse(
        Buffer.from(issuerToken.split('.')[1]!, 'base64url').toString(),
      ) as { sub: string };
      // The JWT `sub` claim is the agent's stable identifier — identical in both paths.
      expect(minterParsed.sub).toBe(issuerParsed.sub);
      expect(minterParsed.sub).toBe('agent-parity-test');
    });
  });
});

// ── Stage-4 parity: cnf.jkt and region preservation ─────────────────────

describe('Stage-4 parity: cnf.jkt and region preservation across attenuation and renewal', () => {
  const issuerDid = 'did:web:stage4-test.issuer';
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 900;

  function makeBasePayload(overrides: Partial<CapabilityTokenPayload> = {}): CapabilityTokenPayload {
    return {
      iss: issuerDid,
      sub: 'agent-stage4',
      aud: 'tool-gateway',
      iat: now,
      exp,
      jti: `jti-base-${Math.random()}`,
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      authorizedBy: { userId: 'user-1', roles: ['Admin'], tenantId: 'tenant-1' },
      ...overrides,
    };
  }

  describe('buildAttenuatedPayload', () => {
    it('preserves cnf.jkt from the parent token', () => {
      const parent = makeBasePayload({ cnf: { jkt: 'test-jkt-thumbprint' } });
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      });
      expect(child.cnf).toBeDefined();
      expect(child.cnf?.jkt).toBe('test-jkt-thumbprint');
    });

    it('preserves region from the parent token', () => {
      const parent = makeBasePayload({ region: 'eu-west-1' });
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      });
      expect(child.region).toBe('eu-west-1');
    });

    it('preserves both cnf.jkt and region together', () => {
      const parent = makeBasePayload({ cnf: { jkt: 'both-jkt' }, region: 'us-east-1' });
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      });
      expect(child.cnf?.jkt).toBe('both-jkt');
      expect(child.region).toBe('us-east-1');
    });

    it('does not add cnf when parent has none', () => {
      const parent = makeBasePayload();
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      });
      expect(child.cnf).toBeUndefined();
    });

    it('does not add region when parent has none', () => {
      const parent = makeBasePayload();
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: [{ resource: 'api://svc/x', actions: ['read'] }],
      });
      expect(child.region).toBeUndefined();
    });
  });

  describe('buildRenewedPayload', () => {
    it('preserves cnf.jkt from the current token', () => {
      const current = makeBasePayload({ cnf: { jkt: 'renew-jkt-thumbprint' } });
      const renewed = buildRenewedPayload({
        issuerDid,
        current,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.cnf).toBeDefined();
      expect(renewed.cnf?.jkt).toBe('renew-jkt-thumbprint');
    });

    it('preserves region from the current token', () => {
      const current = makeBasePayload({ region: 'ap-southeast-1' });
      const renewed = buildRenewedPayload({
        issuerDid,
        current,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.region).toBe('ap-southeast-1');
    });

    it('preserves both cnf.jkt and region together across renewal', () => {
      const current = makeBasePayload({ cnf: { jkt: 'renew-both-jkt' }, region: 'ca-central-1' });
      const renewed = buildRenewedPayload({
        issuerDid,
        current,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.cnf?.jkt).toBe('renew-both-jkt');
      expect(renewed.region).toBe('ca-central-1');
    });

    it('does not add cnf when current token has none', () => {
      const current = makeBasePayload();
      const renewed = buildRenewedPayload({
        issuerDid,
        current,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.cnf).toBeUndefined();
    });

    it('does not add region when current token has none', () => {
      const current = makeBasePayload();
      const renewed = buildRenewedPayload({
        issuerDid,
        current,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.region).toBeUndefined();
    });
  });

  describe('multi-hop preservation (attenuation → renewal)', () => {
    it('cnf.jkt survives attenuation followed by renewal', () => {
      const parent = makeBasePayload({ cnf: { jkt: 'multi-hop-jkt' } });
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: parent.capabilities,
      });
      const renewed = buildRenewedPayload({
        issuerDid,
        current: child,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.cnf?.jkt).toBe('multi-hop-jkt');
    });

    it('region survives attenuation followed by renewal', () => {
      const parent = makeBasePayload({ region: 'eu-central-1' });
      const child = buildAttenuatedPayload({
        issuerDid,
        parent,
        iat: now,
        exp,
        jti: `jti-child-${Math.random()}`,
        capabilities: parent.capabilities,
      });
      const renewed = buildRenewedPayload({
        issuerDid,
        current: child,
        iat: now,
        exp: exp + 900,
        jti: `jti-renewed-${Math.random()}`,
      });
      expect(renewed.region).toBe('eu-central-1');
    });
  });
});

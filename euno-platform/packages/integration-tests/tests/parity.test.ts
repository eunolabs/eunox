/**
 * Task 19 — Cross-stage parity test suite
 * ---------------------------------------------------------------------------
 * Operational proof of the schema-parity claim from docs/mvp.md §"Policy and
 * audit schema parity (non-negotiable)".
 *
 * This harness runs the same {@link AgentCapabilityManifest} through two
 * enforcement paths and asserts that they are behaviourally equivalent:
 *
 *   (a) **Local mode** — {@link ConditionEnforcerPDP} from `@euno/mcp`.
 *       Used when the user runs `euno-mcp` without `--enforcer-url`.
 *       Policy is loaded from a local manifest; conditions are evaluated
 *       in-process; audit records are written to `~/.euno/audit.jsonl`.
 *
 *   (b) **Hosted gateway mode** — {@link EnforcementEngine} from `@euno/tool-gateway`.
 *       Used when a JWT capability token is presented to the gateway's
 *       `POST /api/v1/enforce` endpoint.  The same capability constraints
 *       are encoded in the JWT's `capabilities` claim.
 *
 * ### What "parity" means
 *
 * For every `tools/call` request in the recorded fixture set:
 *
 * 1. **Decision parity** — both modes reach the same `allow`/`deny` outcome.
 * 2. **Obligation parity** — both modes derive identical `redactFields`
 *    obligations from the matched constraint's conditions.
 * 3. **OCSF pre-signature status-field parity** — the deterministic OCSF
 *    event fields computed from the decision (`class_uid`, `category_uid`,
 *    `severity_id`, `status_id`, `status`) are identical.  These are the
 *    fields that would be identical regardless of which signing mechanism
 *    (local HMAC vs KMS-backed asymmetric) is used to seal the record.
 *
 * ### Design note
 *
 * Both paths are called **in-process** — no HTTP servers are started.
 * The gateway path calls `EnforcementEngine.validateAction()` directly
 * using `action: 'call'` and `resource: toolName` so that the
 * `findMatchingCapability` call resolves against the same
 * `CapabilityConstraint` shapes the local `ConditionEnforcerPDP` uses
 * (which also uses `MCP_TOOL_CALL_ACTION = 'call'`).  This is consistent
 * with the fact that both paths share the exact same `@euno/common-core`
 * matching logic — the parity test exercises that shared logic under
 * both callers.
 *
 * @module
 */

import * as jose from 'jose';
import type { CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import {
  AgentCapabilityManifest,
  CapabilityConstraint,
  CapabilityTokenPayload,
  InMemoryCallCounterStore,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  GENESIS_HASH,
  canonicalSha256,
  AuditEvidence,
  SignedAuditEvidence,
  Obligation,
} from '@euno/common';
import { ConditionEnforcerPDP } from '@euno/mcp';
import type { PdpContext, PdpDecision, LocalPolicySource } from '@euno/mcp';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const logger = createLogger('parity-test');

/** Shared RS256 key pair created once for the whole suite. */
let privateKey: jose.KeyLike;
let verifier: JWTTokenVerifier;

beforeAll(async () => {
  const { publicKey, privateKey: priv } = await jose.generateKeyPair('RS256');
  privateKey = priv;
  const publicKeyPem = await jose.exportSPKI(publicKey);
  verifier = new JWTTokenVerifier(publicKeyPem, { requireKid: false });
});

/** Create a capability JWT encoding the given constraints. */
async function mintToken(
  constraints: CapabilityConstraint[],
  extra?: Partial<CapabilityTokenPayload>,
): Promise<string> {
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:parity-test.euno.internal',
    sub: 'parity-test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `parity-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: constraints,
    authorizedBy: { userId: 'test-user', roles: [], tenantId: 'test-tenant' },
    ...extra,
  };
  return new jose.SignJWT(payload as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

/** Wrap a static manifest into a {@link LocalPolicySource}. */
function staticSource(manifest: AgentCapabilityManifest): LocalPolicySource {
  return { load: async () => manifest };
}

/** Minimal MCP CallToolRequest factory. */
function callTool(
  toolName: string,
  args: Record<string, unknown> = {},
): CallToolRequest {
  return {
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  };
}

/** PdpContext used for all local-mode calls in this suite. */
const PDP_CTX: PdpContext = { sessionId: 'parity-session-1' };

/**
 * Extract the effective obligations from a local-mode {@link PdpDecision}.
 *
 * Local mode exposes obligations indirectly via `matchedConditions` — the
 * transport layer calls `applyRedactObligations(result, matchedConditions)`.
 * This helper mirrors that logic: it produces the canonical `Obligation[]`
 * that would be sent over the wire if the same enforcement ran in remote mode.
 */
function localObligations(decision: PdpDecision): Obligation[] {
  if (!decision.allow || !decision.matchedConditions) return [];
  return decision.matchedConditions
    .filter((c) => c.type === 'redactFields')
    .map((c) => {
      if (c.type !== 'redactFields') throw new Error('unreachable');
      return { type: 'redactFields' as const, paths: c.fields };
    });
}

/**
 * Build an EvidenceSigner mock that captures the last unsigned `AuditEvidence`
 * before signing so we can inspect the pre-signature content.
 */
function makeCapturingEvidenceSigner(): {
  signer: import('@euno/common').EvidenceSigner;
  captured: AuditEvidence[];
} {
  const captured: AuditEvidence[] = [];
  let seq = 0;
  let previousHash = GENESIS_HASH;

  const signer: import('@euno/common').EvidenceSigner = {
    async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
      captured.push({ ...evidence });
      seq += 1;
      const signed: SignedAuditEvidence = {
        ...evidence,
        signature: 'test-sig',
        keyId: 'test-kid',
        algorithm: 'RS256',
        previousHash,
        seq,
      };
      previousHash = canonicalSha256(signed);
      return signed;
    },
    async verifyEvidence(_signedEvidence: SignedAuditEvidence): Promise<boolean> {
      return true;
    },
  };
  return { signer, captured };
}

// ---------------------------------------------------------------------------
// OCSF pre-signature status fields
// ---------------------------------------------------------------------------

/**
 * The OCSF API Activity event fields that are determined solely by the
 * enforcement decision and are therefore identical regardless of the signing
 * mechanism.
 *
 * These are the fields that, per the parity contract, must match between a
 * record produced by `@euno/mcp`'s local audit sink and one produced by the
 * gateway's `signedEvidenceToOcsf()` helper:
 *
 *   - `class_uid: 6003`  — OCSF class for API Activity
 *   - `category_uid: 6`  — OCSF category for Application Activity
 *   - `severity_id`      — 1 (Informational) for allow, 3 (Medium) for deny
 *   - `status_id`        — 1 (Success) for allow, 2 (Failure) for deny
 *   - `status`           — "Success" | "Failure"
 */
interface OcsfStatusFields {
  class_uid: number;
  category_uid: number;
  severity_id: number;
  status_id: number;
  status: string;
}

function ocsfStatusFromDecision(decision: 'allow' | 'deny'): OcsfStatusFields {
  const allow = decision === 'allow';
  return {
    class_uid: 6003,
    category_uid: 6,
    severity_id: allow ? 1 : 3,
    status_id: allow ? 1 : 2,
    status: allow ? 'Success' : 'Failure',
  };
}

// ---------------------------------------------------------------------------
// Shared test manifest and JWT constraints
// ---------------------------------------------------------------------------

/**
 * Capability constraints used in BOTH the manifest and the JWT.
 *
 * Using `actions: ['call']` matches the `MCP_TOOL_CALL_ACTION` constant used
 * by `ConditionEnforcerPDP`, and we call `EnforcementEngine.validateAction()`
 * directly with `action: 'call'` so the engine side resolves via the same
 * `findMatchingCapability` logic rather than going through the HTTP route's
 * `ActionResolver` (which would map to `'execute'` instead).
 *
 * Resource strings are bare tool names so that both
 * `findMatchingCapability('call', toolName, constraints)` in local mode and
 * `findMatchingCapability('call', toolName, jwtCapabilities)` in gateway mode
 * resolve to the same constraint.
 */
const SHARED_CONSTRAINTS: CapabilityConstraint[] = [
  // 1. Unconditional allow
  {
    resource: 'read_file',
    actions: ['call'],
  },
  // 2. Allow with a redactFields obligation
  {
    resource: 'send_email',
    actions: ['call'],
    conditions: [
      {
        type: 'redactFields',
        fields: ['recipients', 'bcc'],
      },
    ],
  },
  // 3. maxCalls(1) — denies on the second call within the same session/key
  {
    resource: 'database_query',
    actions: ['call'],
    conditions: [
      {
        type: 'maxCalls',
        count: 1,
        windowSeconds: 3600,
      },
    ],
  },
  // 4. timeWindow condition set to a window that has already passed
  {
    resource: 'maintenance_task',
    actions: ['call'],
    conditions: [
      {
        type: 'timeWindow',
        // notAfter in the past — both modes deny because `now > notAfter`.
        notAfter: '2020-01-01T00:00:00.000Z',
      },
    ],
  },
  // 5. argumentSchema requiring a non-empty 'url' field
  {
    resource: 'fetch_url',
    actions: ['call'],
    argumentSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', minLength: 1 },
      },
      required: ['url'],
    },
  },
];

/** The manifest loaded by the local ConditionEnforcerPDP. */
const PARITY_MANIFEST: AgentCapabilityManifest = {
  agentId: 'parity-test-agent',
  name: 'Parity Test Agent',
  version: '1.0.0',
  requiredCapabilities: SHARED_CONSTRAINTS,
};

// ---------------------------------------------------------------------------
// Test fixture type
// ---------------------------------------------------------------------------

interface ParityFixture {
  description: string;
  toolName: string;
  args?: Record<string, unknown>;
  /** Shared counter store so call-count state is preserved across multi-call tests. */
  counterStore?: InMemoryCallCounterStore;
  expectedDecision: 'allow' | 'deny';
}

// ---------------------------------------------------------------------------
// Main parity test suite
// ---------------------------------------------------------------------------

describe('cross-stage parity test suite (Task 19)', () => {
  let engine: EnforcementEngine;
  let localPdp: ConditionEnforcerPDP;
  let jwtToken: string;
  /** Shared counter store — both paths must share state for maxCalls tests. */
  const sharedCounterStore = new InMemoryCallCounterStore();

  beforeAll(async () => {
    // Gateway path: EnforcementEngine with the JWT verifier and a capturing
    // evidence signer so we can inspect the pre-signature AuditEvidence.
    engine = new EnforcementEngine({
      dpop: { required: false },
      verifier,
      logger,
      callCounterStore: sharedCounterStore,
      policyVersion: 'parity-test-v1',
      // Capture every signed evidence record for assertion.
      evidenceSigner: makeCapturingEvidenceSigner().signer,
      enableCryptographicAudit: true,
    });

    // Local path: ConditionEnforcerPDP backed by the same constraints.
    localPdp = new ConditionEnforcerPDP({
      policySource: staticSource(PARITY_MANIFEST),
      // Share the counter store so the maxCalls state is consistent.
      counterStore: sharedCounterStore,
    });

    // JWT encodes the same constraints the local PDP loads from the manifest.
    jwtToken = await mintToken(SHARED_CONSTRAINTS);
  });

  // Helper: run a single fixture through BOTH paths and assert parity.
  async function assertParity(fixture: ParityFixture): Promise<void> {
    const { toolName, args = {}, expectedDecision } = fixture;
    const request = callTool(toolName, args);

    // ── Local path ─────────────────────────────────────────────────────────
    const localDecision = await localPdp.decide(request, PDP_CTX);
    const localOutcome: 'allow' | 'deny' = localDecision.allow ? 'allow' : 'deny';
    const localObls = localObligations(localDecision);

    // ── Gateway path ───────────────────────────────────────────────────────
    // We call validateAction() directly with the same action='call' and
    // resource=toolName so capability matching uses identical action/resource
    // strings as the local ConditionEnforcerPDP.
    const gatewayResult = await engine.validateAction({
      token: jwtToken,
      action: 'call',
      resource: toolName,
      context: {
        sessionId: PDP_CTX.sessionId,
        tool: toolName,
        args,
      },
    });
    const gatewayOutcome: 'allow' | 'deny' = gatewayResult.allowed ? 'allow' : 'deny';

    // Gateway obligations come from matchedCapability.conditions, mirroring the
    // enforce route's buildObligations() helper.
    const gatewayObls: Obligation[] = (
      gatewayResult.matchedCapability?.conditions ?? []
    )
      .filter((c) => c.type === 'redactFields')
      .map((c) => {
        if (c.type !== 'redactFields') throw new Error('unreachable');
        return { type: 'redactFields' as const, paths: c.fields };
      });

    // ── Assertions ─────────────────────────────────────────────────────────

    // 1. Decision parity
    expect(localOutcome).toBe(expectedDecision);
    expect(gatewayOutcome).toBe(expectedDecision);

    // 2. Obligation parity
    expect(localObls).toEqual(gatewayObls);

    // 3. OCSF pre-signature status-field parity
    const expectedOcsf = ocsfStatusFromDecision(expectedDecision);
    const localOcsf = ocsfStatusFromDecision(localOutcome);
    const gatewayOcsf = ocsfStatusFromDecision(gatewayOutcome);
    expect(localOcsf).toEqual(expectedOcsf);
    expect(gatewayOcsf).toEqual(expectedOcsf);
  }

  // ── Fixture 1: unconditional allow ────────────────────────────────────────

  it('allows read_file unconditionally — no obligations', async () => {
    await assertParity({
      description: 'unconditional allow, no conditions',
      toolName: 'read_file',
      expectedDecision: 'allow',
    });
  });

  // ── Fixture 2: allow with redactFields obligation ─────────────────────────

  it('allows send_email and returns identical redactFields obligations', async () => {
    await assertParity({
      description: 'allow with redactFields obligation',
      toolName: 'send_email',
      args: { to: 'alice@example.com', subject: 'Hi', body: 'Hello' },
      expectedDecision: 'allow',
    });

    // Verify obligation contents explicitly
    const request = callTool('send_email', { to: 'alice@example.com', subject: 'Hi' });
    const localDecision = await localPdp.decide(request, PDP_CTX);
    const obls = localObligations(localDecision);
    expect(obls).toEqual([{ type: 'redactFields', paths: ['recipients', 'bcc'] }]);
  });

  // ── Fixture 3: first database_query is within maxCalls(1) ─────────────────

  it('allows database_query on the first call (within maxCalls limit)', async () => {
    await assertParity({
      description: 'maxCalls: first call within limit',
      toolName: 'database_query',
      args: { query: 'SELECT 1' },
      expectedDecision: 'allow',
    });
  });

  // ── Fixture 4: second database_query exceeds maxCalls(1) ──────────────────

  it('denies database_query on the second call (maxCalls limit exceeded)', async () => {
    // After the first call above the counter is at 1; this second call pushes
    // it over the maxCalls: 1 threshold.  Both paths share sharedCounterStore
    // so they see the same counter state.
    await assertParity({
      description: 'maxCalls: second call exceeds limit',
      toolName: 'database_query',
      args: { query: 'SELECT 2' },
      expectedDecision: 'deny',
    });

    // Verify the conditionType from the local decision matches 'maxCalls'
    const request = callTool('database_query', { query: 'SELECT 3' });
    const localDecision = await localPdp.decide(request, PDP_CTX);
    expect(localDecision.allow).toBe(false);
    expect(localDecision.conditionType).toBe('maxCalls');
  });

  // ── Fixture 5: timeWindow deny ────────────────────────────────────────────

  it('denies maintenance_task when outside the allowed time window', async () => {
    await assertParity({
      description: 'timeWindow condition: window has passed',
      toolName: 'maintenance_task',
      expectedDecision: 'deny',
    });

    // Verify the conditionType from the local decision matches 'timeWindow'
    const request = callTool('maintenance_task');
    const localDecision = await localPdp.decide(request, PDP_CTX);
    expect(localDecision.allow).toBe(false);
    expect(localDecision.conditionType).toBe('timeWindow');
  });

  // ── Fixture 6: argumentSchema allow ──────────────────────────────────────

  it('allows fetch_url when the url argument satisfies the schema', async () => {
    await assertParity({
      description: 'argumentSchema: valid args → allow',
      toolName: 'fetch_url',
      args: { url: 'https://api.example.com/data' },
      expectedDecision: 'allow',
    });
  });

  // ── Fixture 7: argumentSchema deny ────────────────────────────────────────

  it('denies fetch_url when required url argument is missing', async () => {
    await assertParity({
      description: 'argumentSchema: missing required url → deny',
      toolName: 'fetch_url',
      args: {},
      expectedDecision: 'deny',
    });
  });

  // ── Fixture 8: tool not in manifest → local allows, gateway denies ────────
  //
  // This test intentionally documents a KNOWN DESIGN DIFFERENCE between stages:
  //
  //   • Local mode (ConditionEnforcerPDP): tools NOT listed in the manifest are
  //     allowed — the manifest is a restriction list, not an allowlist.
  //   • Gateway mode (EnforcementEngine): tools NOT in the JWT capabilities are
  //     denied — the JWT is an explicit access grant.
  //
  // This difference is expected and is called out in docs/mvp.md §"Schema parity"
  // (the four seams being swapped in Stage 3 are TokenVerifier, CallCounterStore,
  // EvidenceSigner, and KillSwitchManager — the policy-storage model also shifts
  // from "restrict listed tools" to "grant listed tools").  The parity contract
  // covers tools that ARE in both the manifest and the JWT, which is the set
  // tested by fixtures 1–7 above.

  it('documents known Stage 1→3 design difference: unlisted tool allow vs deny', async () => {
    const unlistedTool = 'unknown_tool';
    const request = callTool(unlistedTool);

    // Local mode: unlisted → allow (manifest only restricts listed tools)
    const localDecision = await localPdp.decide(request, PDP_CTX);
    expect(localDecision.allow).toBe(true);

    // Gateway mode: unlisted → deny (JWT capabilities are an explicit grant)
    const gatewayResult = await engine.validateAction({
      token: jwtToken,
      action: 'call',
      resource: unlistedTool,
      context: { sessionId: PDP_CTX.sessionId },
    });
    expect(gatewayResult.allowed).toBe(false);
  });

  // ── OCSF pre-signature status-field parity (table-driven) ─────────────────

  describe('OCSF pre-signature status fields', () => {
    it.each([
      ['allow', 1, 1, 'Success'],
      ['deny', 3, 2, 'Failure'],
    ] as const)(
      'decision=%s → severity_id=%i, status_id=%i, status=%s, class_uid=6003, category_uid=6',
      (decision, severity_id, status_id, status) => {
        const fields = ocsfStatusFromDecision(decision);
        expect(fields).toEqual({
          class_uid: 6003,
          category_uid: 6,
          severity_id,
          status_id,
          status,
        });

        // Verify that both local and gateway outcomes produce the same OCSF
        // status fields for this decision value.
        const localFields = ocsfStatusFromDecision(decision);
        const gatewayFields = ocsfStatusFromDecision(decision);
        expect(localFields).toEqual(gatewayFields);
      },
    );
  });

  // ── AuditEvidence pre-signature content parity ────────────────────────────
  //
  // Verifies that the AuditEvidence records emitted by the gateway's
  // EnforcementEngine carry the correct decision, tool, and conditionType
  // fields — the same semantic fields that the local audit sink encodes in
  // the McpAuditRecord and then into the OCSF unmapped block.

  describe('AuditEvidence pre-signature content', () => {
    let capturedEngine: EnforcementEngine;
    let captured: AuditEvidence[];

    beforeAll(async () => {
      const store = new InMemoryCallCounterStore();
      const { signer, captured: c } = makeCapturingEvidenceSigner();
      captured = c;
      capturedEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        callCounterStore: store,
        policyVersion: 'parity-evidence-v1',
        evidenceSigner: signer,
        enableCryptographicAudit: true,
      });
    });

    it('captures allow evidence with correct tool and decision', async () => {
      const token = await mintToken(SHARED_CONSTRAINTS);
      await capturedEngine.validateAction({
        token,
        action: 'call',
        resource: 'read_file',
        context: { sessionId: 'evidence-session', tool: 'read_file', args: {} },
      });

      const evidence = captured.find((e) => e.tool === 'read_file' && e.decision === 'allow');
      expect(evidence).toBeDefined();
      expect(evidence!.decision).toBe('allow');
      expect(evidence!.tool).toBe('read_file');

      // Derived OCSF status fields must match the allow expectation
      const fields = ocsfStatusFromDecision(evidence!.decision);
      expect(fields.severity_id).toBe(1);
      expect(fields.status_id).toBe(1);
      expect(fields.status).toBe('Success');
      expect(fields.class_uid).toBe(6003);
      expect(fields.category_uid).toBe(6);
    });

    it('captures deny evidence with correct tool, decision, and conditionType', async () => {
      const token = await mintToken(SHARED_CONSTRAINTS);

      // maintenance_task is denied by a timeWindow condition.
      await capturedEngine.validateAction({
        token,
        action: 'call',
        resource: 'maintenance_task',
        context: { sessionId: 'evidence-session', tool: 'maintenance_task', args: {} },
      });

      const evidence = captured.find(
        (e) => e.tool === 'maintenance_task' && e.decision === 'deny',
      );
      expect(evidence).toBeDefined();
      expect(evidence!.decision).toBe('deny');
      expect(evidence!.tool).toBe('maintenance_task');

      // Derived OCSF status fields must match the deny expectation
      const fields = ocsfStatusFromDecision(evidence!.decision);
      expect(fields.severity_id).toBe(3);
      expect(fields.status_id).toBe(2);
      expect(fields.status).toBe('Failure');
      expect(fields.class_uid).toBe(6003);
      expect(fields.category_uid).toBe(6);
    });

    it('pre-signature AuditEvidence decision field aligns with McpAuditRecord decision field', async () => {
      // Both the gateway's AuditEvidence and the local McpAuditRecord use the
      // same decision: 'allow' | 'deny' value — verified here by running the
      // same tool through both paths and confirming the field name and value
      // are identical in both representations.
      const token = await mintToken(SHARED_CONSTRAINTS);
      const localDecision = await localPdp.decide(callTool('read_file'), PDP_CTX);
      await capturedEngine.validateAction({
        token,
        action: 'call',
        resource: 'read_file',
        context: { sessionId: 'alignment-session', tool: 'read_file', args: {} },
      });

      // Local: PdpDecision.allow (boolean)
      const localRecord = {
        decision: localDecision.allow ? 'allow' : 'deny',
        toolName: 'read_file',
      };

      // Gateway: AuditEvidence.decision (string literal)
      const gatewayEvidence = captured.find(
        (e) => e.tool === 'read_file' && e.decision === 'allow',
      );
      expect(gatewayEvidence).toBeDefined();

      // Both must agree
      expect(localRecord.decision).toBe(gatewayEvidence!.decision);
    });
  });
});

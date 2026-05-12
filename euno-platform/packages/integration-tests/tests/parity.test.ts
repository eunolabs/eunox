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
 * 3. **OCSF status-field parity** — the status fields produced by the real
 *    `signedEvidenceToOcsf()` function on captured gateway evidence
 *    (`class_uid`, `category_uid`, `severity_id`, `status_id`, `status`)
 *    match the expected values for the decision.
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
  signedEvidenceToOcsf,
  OcsfProductInfo,
  EvidenceSigner,
} from '@euno/common';
import { ConditionEnforcerPDP } from '@euno/mcp';
import type { PdpContext, PdpDecision, LocalPolicySource } from '@euno/mcp';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const logger = createLogger('parity-test');

/** Product metadata used when calling signedEvidenceToOcsf() in tests. */
const OCSF_PRODUCT: OcsfProductInfo = { name: 'parity-test', version: '0.0.0' };

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
) {
  return {
    method: 'tools/call' as const,
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
 * Build an {@link EvidenceSigner} mock that captures every
 * {@link SignedAuditEvidence} produced by the engine so tests can inspect
 * the real pre-signature content and call {@link signedEvidenceToOcsf} on it.
 *
 * The signer mock constant values ('test-sig', 'test-kid') are used only
 * inside this helper and make the mock nature explicit.
 */
const TEST_SIG = 'test-sig';
const TEST_KID = 'test-kid';

function makeCapturingEvidenceSigner(): {
  signer: EvidenceSigner;
  captured: SignedAuditEvidence[];
} {
  const captured: SignedAuditEvidence[] = [];
  let seq = 0;
  let previousHash = GENESIS_HASH;

  const signer: EvidenceSigner = {
    async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
      seq += 1;
      const signed: SignedAuditEvidence = {
        ...evidence,
        signature: TEST_SIG,
        keyId: TEST_KID,
        algorithm: 'RS256',
        previousHash,
        seq,
      };
      previousHash = canonicalSha256(signed);
      captured.push(signed);
      return signed;
    },
    async verifyEvidence(_signedEvidence: SignedAuditEvidence): Promise<boolean> {
      return true;
    },
  };
  return { signer, captured };
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
  // 3. maxCalls(1) — tested in the self-contained maxCalls test below
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
  toolName: string;
  args?: Record<string, unknown>;
  expectedDecision: 'allow' | 'deny';
}

// ---------------------------------------------------------------------------
// Main parity test suite
// ---------------------------------------------------------------------------

describe('cross-stage parity test suite (Task 19)', () => {
  let engine: EnforcementEngine;
  let localPdp: ConditionEnforcerPDP;
  let jwtToken: string;
  /**
   * Signed evidence captured from the main `engine`'s signer.
   * Exposed at describe scope so `assertParity` can inspect newly added
   * entries and call `signedEvidenceToOcsf()` on them.
   */
  let capturedSigned: SignedAuditEvidence[];

  beforeAll(async () => {
    const { signer, captured } = makeCapturingEvidenceSigner();
    capturedSigned = captured;

    // Gateway path: EnforcementEngine with the JWT verifier and a capturing
    // evidence signer so assertParity can validate real OCSF status fields.
    engine = new EnforcementEngine({
      dpop: { required: false },
      verifier,
      logger,
      policyVersion: 'parity-test-v1',
      evidenceSigner: signer,
      enableCryptographicAudit: true,
    });

    // Local path: ConditionEnforcerPDP backed by the same constraints.
    localPdp = new ConditionEnforcerPDP({
      policySource: staticSource(PARITY_MANIFEST),
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
    const beforeLen = capturedSigned.length;
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

    // 3. OCSF status-field parity — use the real signedEvidenceToOcsf()
    //    function on captured gateway evidence to validate the status fields
    //    rather than a local helper recomputing them from the decision string.
    const newlySigned = capturedSigned.slice(beforeLen);
    const signed = newlySigned.find((e) => e.tool === toolName);
    expect(signed).toBeDefined();
    if (signed) {
      const ocsfEvent = signedEvidenceToOcsf(signed, OCSF_PRODUCT);
      expect(ocsfEvent.class_uid).toBe(6003);
      expect(ocsfEvent.category_uid).toBe(6);
      expect(ocsfEvent.severity_id).toBe(expectedDecision === 'deny' ? 3 : 1);
      expect(ocsfEvent.status_id).toBe(expectedDecision === 'allow' ? 1 : 2);
      expect(ocsfEvent.status).toBe(expectedDecision === 'allow' ? 'Success' : 'Failure');
    }
  }

  // ── Fixture 1: unconditional allow ────────────────────────────────────────

  it('allows read_file unconditionally — no obligations', async () => {
    await assertParity({
      toolName: 'read_file',
      expectedDecision: 'allow',
    });
  });

  // ── Fixture 2: allow with redactFields obligation ─────────────────────────

  it('allows send_email and returns identical redactFields obligations', async () => {
    await assertParity({
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

  // ── Fixture 3: maxCalls allow→deny transition ──────────────────────────────
  //
  // Uses dedicated counter store, PDP, and engine so the allow→deny transition
  // is driven entirely within this single test and does not depend on
  // execution order relative to other test cases.

  it('enforces maxCalls(1): allows on first call, denies on second call', async () => {
    const maxStore = new InMemoryCallCounterStore();
    const maxLocalPdp = new ConditionEnforcerPDP({
      policySource: staticSource(PARITY_MANIFEST),
      counterStore: maxStore,
    });
    const maxToken = await mintToken(SHARED_CONSTRAINTS);
    const maxEngine = new EnforcementEngine({
      dpop: { required: false },
      verifier,
      logger,
      callCounterStore: maxStore,
      policyVersion: 'parity-maxcalls',
    });

    const resource = 'database_query';
    const ctx = { sessionId: PDP_CTX.sessionId, tool: resource, args: {} };

    // ── First call: both paths allow ──────────────────────────────────────
    const localAllow = await maxLocalPdp.decide(callTool(resource, { query: 'SELECT 1' }), PDP_CTX);
    const gwAllow = await maxEngine.validateAction({
      token: maxToken,
      action: 'call',
      resource,
      context: { ...ctx, args: { query: 'SELECT 1' } },
    });
    expect(localAllow.allow).toBe(true);
    expect(gwAllow.allowed).toBe(true);

    // ── Second call: both paths deny ──────────────────────────────────────
    const localDeny = await maxLocalPdp.decide(callTool(resource, { query: 'SELECT 2' }), PDP_CTX);
    const gwDeny = await maxEngine.validateAction({
      token: maxToken,
      action: 'call',
      resource,
      context: { ...ctx, args: { query: 'SELECT 2' } },
    });
    expect(localDeny.allow).toBe(false);
    expect(localDeny.conditionType).toBe('maxCalls');
    expect(gwDeny.allowed).toBe(false);
  });

  // ── Fixture 4: timeWindow deny ────────────────────────────────────────────

  it('denies maintenance_task when outside the allowed time window', async () => {
    await assertParity({
      toolName: 'maintenance_task',
      expectedDecision: 'deny',
    });

    // Verify the conditionType from the local decision matches 'timeWindow'
    const request = callTool('maintenance_task');
    const localDecision = await localPdp.decide(request, PDP_CTX);
    expect(localDecision.allow).toBe(false);
    expect(localDecision.conditionType).toBe('timeWindow');
  });

  // ── Fixture 5: argumentSchema allow ──────────────────────────────────────

  it('allows fetch_url when the url argument satisfies the schema', async () => {
    await assertParity({
      toolName: 'fetch_url',
      args: { url: 'https://api.example.com/data' },
      expectedDecision: 'allow',
    });
  });

  // ── Fixture 6: argumentSchema deny ────────────────────────────────────────

  it('denies fetch_url when required url argument is missing', async () => {
    await assertParity({
      toolName: 'fetch_url',
      args: {},
      expectedDecision: 'deny',
    });
  });

  // ── Fixture 7: tool not in manifest → local allows, gateway denies ────────
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
  // tested by fixtures 1–6 above.

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

  // ── OCSF pre-signature status fields (table-driven via real mapping) ────────
  //
  // Calls `signedEvidenceToOcsf()` on actual captured gateway evidence for an
  // allow and a deny, then checks the exact field values.  This validates the
  // real OCSF mapping function, not a local test-only helper.

  describe('OCSF pre-signature status fields', () => {
    it('allow decision → class_uid=6003, category_uid=6, severity_id=1, status_id=1, status=Success', async () => {
      const token = await mintToken(SHARED_CONSTRAINTS);
      const beforeLen = capturedSigned.length;
      await engine.validateAction({
        token,
        action: 'call',
        resource: 'read_file',
        context: { sessionId: 'ocsf-allow-test' },
      });
      const signed = capturedSigned.slice(beforeLen).find((e) => e.tool === 'read_file');
      expect(signed).toBeDefined();
      const ev = signedEvidenceToOcsf(signed!, OCSF_PRODUCT);
      expect(ev.class_uid).toBe(6003);
      expect(ev.category_uid).toBe(6);
      expect(ev.severity_id).toBe(1);
      expect(ev.status_id).toBe(1);
      expect(ev.status).toBe('Success');
    });

    it('deny decision → class_uid=6003, category_uid=6, severity_id=3, status_id=2, status=Failure', async () => {
      const token = await mintToken(SHARED_CONSTRAINTS);
      const beforeLen = capturedSigned.length;
      await engine.validateAction({
        token,
        action: 'call',
        resource: 'maintenance_task',
        context: { sessionId: 'ocsf-deny-test' },
      });
      const signed = capturedSigned.slice(beforeLen).find((e) => e.tool === 'maintenance_task');
      expect(signed).toBeDefined();
      const ev = signedEvidenceToOcsf(signed!, OCSF_PRODUCT);
      expect(ev.class_uid).toBe(6003);
      expect(ev.category_uid).toBe(6);
      expect(ev.severity_id).toBe(3);
      expect(ev.status_id).toBe(2);
      expect(ev.status).toBe('Failure');
    });
  });

  // ── AuditEvidence pre-signature content parity ────────────────────────────
  //
  // Verifies that the AuditEvidence records emitted by the gateway's
  // EnforcementEngine carry the correct decision, tool, and conditionType
  // fields — the same semantic fields that the local audit sink encodes in
  // the McpAuditRecord and then into the OCSF unmapped block.

  describe('AuditEvidence pre-signature content', () => {
    let capturedEngine: EnforcementEngine;
    let captured: SignedAuditEvidence[];

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

    // Clear captured evidence before each test so assertions target only the
    // evidence produced by the current test's validateAction() call.
    beforeEach(() => {
      captured.length = 0;
    });

    it('captures allow evidence with correct tool and decision', async () => {
      const token = await mintToken(SHARED_CONSTRAINTS);
      await capturedEngine.validateAction({
        token,
        action: 'call',
        resource: 'read_file',
        context: { sessionId: 'evidence-session', tool: 'read_file', args: {} },
      });

      expect(captured).toHaveLength(1);
      const signed = captured[0]!;
      expect(signed.decision).toBe('allow');
      expect(signed.tool).toBe('read_file');

      // Real OCSF mapping must produce the expected allow status fields.
      const ev = signedEvidenceToOcsf(signed, OCSF_PRODUCT);
      expect(ev.class_uid).toBe(6003);
      expect(ev.category_uid).toBe(6);
      expect(ev.severity_id).toBe(1);
      expect(ev.status_id).toBe(1);
      expect(ev.status).toBe('Success');
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

      expect(captured).toHaveLength(1);
      const signed = captured[0]!;
      expect(signed.decision).toBe('deny');
      expect(signed.tool).toBe('maintenance_task');
      // Gateway sets conditionType on evidence so downstream SIEM queries can
      // distinguish which type of condition caused the denial.
      expect(signed.conditionType).toBe('timeWindow');

      // Real OCSF mapping must produce the expected deny status fields.
      const ev = signedEvidenceToOcsf(signed, OCSF_PRODUCT);
      expect(ev.class_uid).toBe(6003);
      expect(ev.category_uid).toBe(6);
      expect(ev.severity_id).toBe(3);
      expect(ev.status_id).toBe(2);
      expect(ev.status).toBe('Failure');
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

      expect(captured).toHaveLength(1);
      const gatewayEvidence = captured[0]!;
      expect(localRecord.decision).toBe(gatewayEvidence.decision);
    });
  });
});

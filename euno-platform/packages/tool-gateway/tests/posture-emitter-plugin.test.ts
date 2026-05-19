/**
 * Tests for PostureEmitterPlugin and evidenceToInventoryRecord.
 *
 * Unit tests (8):
 *   1. onSigned is a no-op when the emitter reports isEnabled()=false
 *   2. onSigned with an allow decision enqueues a record in the emitter
 *   3. onSigned with a deny decision also enqueues (posture tracks all signed events)
 *   4. emitObserved rejection is caught and logged at warn level, not propagated
 *   5. evidenceToInventoryRecord maps agentId directly
 *   6. evidenceToInventoryRecord maps tenantId to owningTeam
 *   7. evidenceToInventoryRecord falls back to 'unknown' for owningTeam when tenantId absent
 *   8. evidenceToInventoryRecord sets both firstSeen and lastSeen to the evidence timestamp
 *
 * Integration test (1):
 *   9. A signed enforcement event fed via onSigned is delivered end-to-end through
 *      a real DurablePostureEmitter (:memory:) with a recording plugin.
 */

import { SignedAuditEvidence, AgentInventoryRecord, GENESIS_HASH } from '@euno/common';
import { DurablePostureEmitter, PostureEmitterPlugin as DurableEmitterPlugin } from '@euno/posture-emitter';
import { PostureEmitterPlugin, evidenceToInventoryRecord } from '../src/posture-emitter-plugin';

// ---------------------------------------------------------------------------
// Helpers

/** Build a minimal-but-valid SignedAuditEvidence for testing. */
function makeEvidence(
  overrides: Partial<SignedAuditEvidence> = {},
): SignedAuditEvidence {
  const ts = new Date('2025-06-01T12:00:00.000Z').toISOString();
  return {
    id: 'ev-001',
    sessionId: 'sess-001',
    userId: 'user-001',
    promptHash: 'phash',
    tool: 'my-tool',
    argsHash: 'ahash',
    nonce: 'nonce',
    ts,
    policyVersion: '0.1.0',
    agentId: 'agent-abc',
    resource: 'api://service/tool',
    action: 'invoke',
    capabilityId: 'jti-00000000-0000-0000-0000-000000000001',
    decision: 'allow',
    signature: 'sig',
    keyId: 'kid-1',
    algorithm: 'RS256',
    previousHash: GENESIS_HASH,
    seq: 1,
    ...overrides,
  };
}

/**
 * Wait up to `timeoutMs` for a predicate to become true, polling every 10 ms.
 * Throws when the deadline is exceeded.
 */
async function waitFor(pred: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('waitFor timed out');
    await new Promise((res) => setTimeout(res, 10));
  }
}

/**
 * Recording plugin that collects delivered records for assertion.
 * Implements the posture-emitter PostureEmitterPlugin interface.
 */
class RecordingPlugin implements DurableEmitterPlugin {
  readonly name = 'recording';
  readonly observed: AgentInventoryRecord[] = [];

  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    this.observed.push(record);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async emitRevoked(_agentId: string, _revokedAt: string): Promise<void> {
    // not needed in these tests
  }
}

/** Build a fast DurablePostureEmitter with a :memory: queue for tests. */
function makeEmitter(plugin: RecordingPlugin): DurablePostureEmitter {
  return new DurablePostureEmitter({
    plugins: [plugin],
    queuePath: ':memory:',
    deliveryPollIntervalMs: 10,
    pluginTimeoutMs: 500,
    backoffBaseMs: 10,
    backoffMaxMs: 50,
  });
}

// ---------------------------------------------------------------------------
// Unit tests

describe('PostureEmitterPlugin', () => {
  // ── Test 1: disabled emitter is a no-op ──────────────────────────────────
  it('1. onSigned is a no-op when the emitter is disabled', () => {
    const disabledEmitter = new DurablePostureEmitter({
      enabled: false,
      plugins: [],
    });
    const plugin = new PostureEmitterPlugin({ emitter: disabledEmitter });
    const spy = jest.spyOn(disabledEmitter, 'emitObserved');

    plugin.onSigned(makeEvidence());

    expect(spy).not.toHaveBeenCalled();
    disabledEmitter.stop().catch(() => undefined);
  });

  // ── Test 2: allow decision is enqueued ───────────────────────────────────
  it('2. onSigned with an allow decision enqueues a record', async () => {
    const recording = new RecordingPlugin();
    const emitter = makeEmitter(recording);
    emitter.start();
    const plugin = new PostureEmitterPlugin({ emitter });

    plugin.onSigned(makeEvidence({ decision: 'allow' }));

    // Allow the fire-and-forget emitObserved promise to resolve.
    await new Promise((res) => setImmediate(res));
    // The queue depth should be 1 (event pending delivery).
    expect(emitter.queueDepth()).toBe(1);

    await emitter.stop();
  });

  // ── Test 3: deny decision is also enqueued ───────────────────────────────
  it('3. onSigned with a deny decision also enqueues a record', async () => {
    const recording = new RecordingPlugin();
    const emitter = makeEmitter(recording);
    emitter.start();
    const plugin = new PostureEmitterPlugin({ emitter });

    plugin.onSigned(makeEvidence({ decision: 'deny' }));

    await new Promise((res) => setImmediate(res));
    expect(emitter.queueDepth()).toBe(1);

    await emitter.stop();
  });

  // ── Test 4: emitObserved rejection is caught and logged ──────────────────
  it('4. emitObserved rejection is caught and logged as warn, not propagated', async () => {
    const recording = new RecordingPlugin();
    const emitter = makeEmitter(recording);
    emitter.start();

    // Stub emitObserved to reject so we can verify error handling.
    jest
      .spyOn(emitter, 'emitObserved')
      .mockRejectedValueOnce(new Error('SQLite write failed'));

    const warnSpy = jest.fn();
    const fakeLogger = { warn: warnSpy } as never;
    const plugin = new PostureEmitterPlugin({ emitter, logger: fakeLogger });

    // Must not throw even though emitObserved rejects.
    expect(() => plugin.onSigned(makeEvidence())).not.toThrow();

    // Give the rejected promise's catch handler time to fire.
    await new Promise((res) => setTimeout(res, 20));
    expect(warnSpy).toHaveBeenCalledWith(
      'posture-emitter: failed to enqueue enforcement event',
      expect.objectContaining({ agentId: 'agent-abc', error: 'SQLite write failed' }),
    );

    await emitter.stop();
  });
});

describe('evidenceToInventoryRecord', () => {
  // ── Test 5: agentId mapping ───────────────────────────────────────────────
  it('5. maps agentId directly from the evidence record', () => {
    const record = evidenceToInventoryRecord(makeEvidence({ agentId: 'agent-xyz' }));
    expect(record.agentId).toBe('agent-xyz');
  });

  // ── Test 6: tenantId → owningTeam ────────────────────────────────────────
  it('6. maps tenantId to owningTeam when tenantId is present', () => {
    const record = evidenceToInventoryRecord(
      makeEvidence({ tenantId: 'acme-corp' }),
    );
    expect(record.owningTeam).toBe('acme-corp');
  });

  // ── Test 7: missing tenantId falls back to 'unknown' ─────────────────────
  it("7. owningTeam falls back to 'unknown' when tenantId is absent", () => {
    // Create evidence without tenantId
    const ev = makeEvidence();
    delete (ev as Partial<SignedAuditEvidence>).tenantId;
    const record = evidenceToInventoryRecord(ev);
    expect(record.owningTeam).toBe('unknown');
  });

  // ── Test 8: ts → firstSeen and lastSeen ──────────────────────────────────
  it('8. sets both firstSeen and lastSeen to the evidence ts field', () => {
    const ts = '2025-06-15T09:30:00.000Z';
    const record = evidenceToInventoryRecord(makeEvidence({ ts }));
    expect(record.firstSeen).toBe(ts);
    expect(record.lastSeen).toBe(ts);
  });

  it('uses capabilityId as capabilityManifestHash', () => {
    const capabilityId = 'jti-deadbeef';
    const record = evidenceToInventoryRecord(makeEvidence({ capabilityId }));
    expect(record.capabilityManifestHash).toBe(capabilityId);
  });

  it("sets runtime and region to 'unknown' (not available in enforcement evidence)", () => {
    const record = evidenceToInventoryRecord(makeEvidence());
    expect(record.runtime).toBe('unknown');
    expect(record.region).toBe('unknown');
  });

  it("sets schemaVersion to '1.0'", () => {
    const record = evidenceToInventoryRecord(makeEvidence());
    expect(record.schemaVersion).toBe('1.0');
  });
});

// ---------------------------------------------------------------------------
// Integration test

describe('PostureEmitterPlugin — end-to-end integration', () => {
  /**
   * Test 9: A signed enforcement event fed via `onSigned` travels through
   * `PostureEmitterPlugin` → `DurablePostureEmitter` (SQLite :memory:) →
   * `RecordingPlugin` and arrives with the correct agentId and timestamps.
   */
  it('9. enforcement event is delivered end-to-end to the recording plugin', async () => {
    const recording = new RecordingPlugin();
    const emitter = new DurablePostureEmitter({
      plugins: [recording],
      queuePath: ':memory:',
      deliveryPollIntervalMs: 10,
      pluginTimeoutMs: 500,
      backoffBaseMs: 10,
      backoffMaxMs: 50,
      // Disable dedupe window so the first event always emits.
      dedupeWindowMs: 0,
    });
    emitter.start();
    const plugin = new PostureEmitterPlugin({ emitter });

    const ts = '2025-07-01T08:00:00.000Z';
    const evidence = makeEvidence({
      agentId: 'agent-integration',
      tenantId: 'integration-team',
      capabilityId: 'jti-integration-001',
      ts,
    });

    // Feed the signed evidence through the shim.
    plugin.onSigned(evidence);

    // Wait for the delivery worker to pick up and deliver the event.
    await waitFor(() => recording.observed.length >= 1, 2_000);

    // Assert the delivered record has the correct fields.
    const delivered = recording.observed[0]!;
    expect(delivered.agentId).toBe('agent-integration');
    expect(delivered.owningTeam).toBe('integration-team');
    expect(delivered.capabilityManifestHash).toBe('jti-integration-001');
    expect(delivered.firstSeen).toBe(ts);
    expect(delivered.lastSeen).toBe(ts);
    expect(delivered.schemaVersion).toBe('1.0');
    expect(delivered.runtime).toBe('unknown');
    expect(delivered.region).toBe('unknown');

    await emitter.stop();
  });
});

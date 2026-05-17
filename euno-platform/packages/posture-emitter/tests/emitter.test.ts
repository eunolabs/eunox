/**
 * Unit tests for the PostureEmitter facade.
 *
 * Covers:
 *   - one failing plugin does not block other plugins,
 *   - 5-minute dedupe window suppresses duplicate emits,
 *   - revocation fans out to every plugin,
 *   - per-plugin timeout fires and does not propagate,
 *   - disabled emitter is a no-op,
 *   - buildRecord populates the parity-set fields and reuses the
 *     shared canonical hash for `capabilityManifestHash`.
 */
import { AgentCapabilityManifest, AgentInventoryRecord, canonicalSha256 } from '@euno/common';
import { PostureEmitter, PostureEmitterPlugin } from '../src';

class RecordingPlugin implements PostureEmitterPlugin {
  readonly name: string;
  observed: AgentInventoryRecord[] = [];
  revoked: { agentId: string; revokedAt: string }[] = [];
  shouldFail = false;
  delayMs = 0;
  constructor(name: string) {
    this.name = name;
  }
  async emitObserved(r: AgentInventoryRecord): Promise<void> {
    if (this.delayMs) await new Promise((res) => setTimeout(res, this.delayMs));
    if (this.shouldFail) throw new Error(`${this.name} boom`);
    this.observed.push(r);
  }
  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    if (this.shouldFail) throw new Error(`${this.name} boom`);
    this.revoked.push({ agentId, revokedAt });
  }
}

function makeRecord(overrides: Partial<AgentInventoryRecord> = {}): AgentInventoryRecord {
  const now = new Date().toISOString();
  return {
    schemaVersion: '1.0',
    agentId: 'agent-1',
    owningTeam: 'team-a',
    capabilityManifestHash: 'abc',
    runtime: 'node:20',
    region: 'eastus2',
    firstSeen: now,
    lastSeen: now,
    ...overrides,
  };
}

describe('PostureEmitter', () => {
  it('is a no-op when no plugins are configured', async () => {
    const emitter = new PostureEmitter({ plugins: [] });
    expect(emitter.isEnabled()).toBe(false);
    // Should not throw, should not record.
    await emitter.emitObserved(makeRecord());
    expect(emitter.snapshot()).toHaveLength(0);
  });

  it('is a no-op when explicitly disabled', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new PostureEmitter({ enabled: false, plugins: [p] });
    expect(emitter.isEnabled()).toBe(false);
    await emitter.emitObserved(makeRecord());
    expect(p.observed).toHaveLength(0);
  });

  it('fans out emitObserved to all plugins in parallel', async () => {
    const a = new RecordingPlugin('a');
    const b = new RecordingPlugin('b');
    const emitter = new PostureEmitter({ plugins: [a, b] });
    await emitter.emitObserved(makeRecord());
    expect(a.observed).toHaveLength(1);
    expect(b.observed).toHaveLength(1);
  });

  it('isolates per-plugin failures', async () => {
    const ok = new RecordingPlugin('ok');
    const bad = new RecordingPlugin('bad');
    bad.shouldFail = true;
    const warn = jest.fn();
    const emitter = new PostureEmitter({
      plugins: [bad, ok],
      logger: { warn } as unknown as import('@euno/common').Logger,
    });
    // Should not throw despite `bad` rejecting.
    await expect(emitter.emitObserved(makeRecord())).resolves.toBeUndefined();
    expect(ok.observed).toHaveLength(1);
    expect(warn).toHaveBeenCalled();
  });

  it('suppresses duplicate emitObserved inside the dedupe window', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new PostureEmitter({ plugins: [p], dedupeWindowMs: 60_000 });
    await emitter.emitObserved(makeRecord());
    await emitter.emitObserved(makeRecord());
    expect(p.observed).toHaveLength(1);
  });

  it('records revocation locally and fans out to plugins', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new PostureEmitter({ plugins: [p] });
    await emitter.emitObserved(makeRecord());
    await emitter.emitRevoked('agent-1', '2026-04-29T01:00:00Z');
    expect(p.revoked).toEqual([
      { agentId: 'agent-1', revokedAt: '2026-04-29T01:00:00Z' },
    ]);
    // Local store has the revoked record.
    expect(emitter.snapshot()[0]?.revokedAt).toBe('2026-04-29T01:00:00Z');
  });

  it('refreshOnce re-emits all active records', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new PostureEmitter({ plugins: [p], dedupeWindowMs: 0 });
    await emitter.emitObserved(makeRecord({ agentId: 'a' }));
    await emitter.emitObserved(makeRecord({ agentId: 'b' }));
    p.observed = [];
    await emitter.refreshOnce();
    expect(p.observed.map((r) => r.agentId).sort()).toEqual(['a', 'b']);
  });

  it('refreshOnce skips revoked records', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new PostureEmitter({ plugins: [p], dedupeWindowMs: 0 });
    await emitter.emitObserved(makeRecord({ agentId: 'a' }));
    await emitter.emitRevoked('a', new Date().toISOString());
    p.observed = [];
    p.revoked = [];
    await emitter.refreshOnce();
    expect(p.observed).toHaveLength(0);
  });

  it('per-plugin timeout fires without propagating', async () => {
    const slow = new RecordingPlugin('slow');
    slow.delayMs = 200;
    const fast = new RecordingPlugin('fast');
    const warn = jest.fn();
    const emitter = new PostureEmitter({
      plugins: [slow, fast],
      pluginTimeoutMs: 20,
      logger: { warn } as unknown as import('@euno/common').Logger,
    });
    await emitter.emitObserved(makeRecord());
    // Fast plugin still recorded; slow plugin timed out.
    expect(fast.observed).toHaveLength(1);
    expect(warn).toHaveBeenCalledWith(
      'posture emit failed',
      expect.objectContaining({ plugin: 'slow' }),
    );
  });

  it('startPeriodicRefresh returns a stop function and is no-op when disabled', () => {
    const emitter = new PostureEmitter({ enabled: false, plugins: [] });
    const stop = emitter.startPeriodicRefresh(1);
    expect(typeof stop).toBe('function');
    stop();
  });
});

describe('PostureEmitter.buildRecord', () => {
  it('falls back to "unknown" for missing manifest fields', () => {
    const r = PostureEmitter.buildRecord({ agentId: 'a' });
    expect(r.agentId).toBe('a');
    expect(r.owningTeam).toBe('unknown');
    expect(r.runtime).toBe('unknown');
    expect(r.region).toBe('unknown');
    expect(r.schemaVersion).toBe('1.0');
  });

  it('reuses canonicalSha256 for the manifest hash', () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'a',
      name: 'A',
      version: '0.1.0',
      requiredCapabilities: [],
      metadata: { owner: 'team-a', runtime: 'python:3.12' },
    };
    const r = PostureEmitter.buildRecord({ agentId: 'a', manifest, region: 'eu-west-1' });
    expect(r.owningTeam).toBe('team-a');
    expect(r.runtime).toBe('python:3.12');
    expect(r.region).toBe('eu-west-1');
    expect(r.capabilityManifestHash).toBe(canonicalSha256(manifest));
  });
});

describe('PostureEmitter.fromEnv', () => {
  it('returns a disabled emitter when POSTURE_EMITTER_ENABLED is unset', () => {
    const emitter = PostureEmitter.fromEnv({});
    expect(emitter.isEnabled()).toBe(false);
  });

  it('defaults to the stdout plugin when enabled with no plugin list', () => {
    const emitter = PostureEmitter.fromEnv({ POSTURE_EMITTER_ENABLED: 'true' });
    expect(emitter.isEnabled()).toBe(true);
  });

  it('falls back to stdout when all configured plugins are misconfigured', () => {
    const warn = jest.fn();
    const emitter = PostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_EMITTER_PLUGINS: 'security-hub',
        // intentionally missing AWS_ACCOUNT_ID etc.
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(emitter.isEnabled()).toBe(true);
    expect(warn).toHaveBeenCalled();
  });
});

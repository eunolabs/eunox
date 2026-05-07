/**
 * Unit tests for the redactForPosture helper. Default policy is
 * minimum-five-fields-only; optional fields require an explicit opt-in.
 */
import { AgentInventoryRecord } from '@euno/common';
import { redactForPosture } from '../src/redact';

const FULL: AgentInventoryRecord = {
  schemaVersion: '1.0',
  agentId: 'agent-1',
  owningTeam: 'team-a',
  capabilityManifestHash: 'abc',
  runtime: 'node:20',
  region: 'eastus2',
  cloudAccount: 'sub-123',
  manifestUri: 'https://example.com/m.json',
  capabilities: [{ resource: 'r', actions: ['read'] }],
  firstSeen: 't0',
  lastSeen: 't1',
};

describe('redactForPosture', () => {
  it('strips optional fields by default', () => {
    const out = redactForPosture(FULL);
    expect(out.cloudAccount).toBeUndefined();
    expect(out.manifestUri).toBeUndefined();
    expect(out.capabilities).toBeUndefined();
    // Required parity fields preserved
    expect(out.agentId).toBe('agent-1');
    expect(out.owningTeam).toBe('team-a');
    expect(out.capabilityManifestHash).toBe('abc');
    expect(out.runtime).toBe('node:20');
    expect(out.region).toBe('eastus2');
  });

  it('includes opted-in optional fields', () => {
    const out = redactForPosture(FULL, {
      includeCloudAccount: true,
      includeManifestUri: true,
      includeCapabilities: true,
    });
    expect(out.cloudAccount).toBe('sub-123');
    expect(out.manifestUri).toBe('https://example.com/m.json');
    expect(out.capabilities).toEqual([{ resource: 'r', actions: ['read'] }]);
  });

  it('preserves revokedAt when set', () => {
    const out = redactForPosture({ ...FULL, revokedAt: 'tx' });
    expect(out.revokedAt).toBe('tx');
  });

  it('does not mutate input', () => {
    const copy = JSON.parse(JSON.stringify(FULL));
    redactForPosture(FULL, { includeCapabilities: true });
    expect(FULL).toEqual(copy);
  });
});

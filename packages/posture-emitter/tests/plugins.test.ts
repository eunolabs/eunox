/**
 * Unit tests for the per-cloud posture-emitter plugins. The cloud
 * SDKs are NOT installed in CI; tests inject a mocked client via
 * the `clientFactory` test seam so the SDK's `require()` paths are
 * never reached.
 *
 * Asserts the parity-set field-name contract: the five required
 * fields (agentId / owningTeam / capabilityManifestHash / runtime /
 * region) appear in every per-surface payload under their canonical
 * names — see `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 1.
 */
import { AgentInventoryRecord } from '@euno/common';
import { DefenderCspmPlugin } from '../src/plugins/defender-cspm';
import { SccPlugin } from '../src/plugins/scc';
import { SecurityHubPlugin } from '../src/plugins/security-hub';
import { StdoutPosturePlugin } from '../src/plugins/stdout';

const RECORD: AgentInventoryRecord = {
  schemaVersion: '1.0',
  agentId: 'agent-xyz',
  owningTeam: 'team-a',
  capabilityManifestHash: 'deadbeef',
  runtime: 'node:20',
  region: 'eastus2',
  cloudAccount: 'sub-1',
  capabilities: [{ resource: 'r', actions: ['read'] }],
  firstSeen: '2026-04-29T00:00:00.000Z',
  lastSeen: '2026-04-29T00:00:00.000Z',
};

describe('StdoutPosturePlugin', () => {
  it('emits a JSON line for observed records', async () => {
    const lines: string[] = [];
    const plugin = new StdoutPosturePlugin({ sink: (l) => lines.push(l) });
    await plugin.emitObserved(RECORD);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('"event":"observed"');
    // Default redaction strips capabilities + cloudAccount.
    expect(lines[0]).not.toContain('cloudAccount');
    expect(lines[0]).not.toContain('"capabilities"');
    // Parity fields preserved.
    expect(lines[0]).toContain('"agentId":"agent-xyz"');
    expect(lines[0]).toContain('"owningTeam":"team-a"');
    expect(lines[0]).toContain('"capabilityManifestHash":"deadbeef"');
    expect(lines[0]).toContain('"runtime":"node:20"');
    expect(lines[0]).toContain('"region":"eastus2"');
  });

  it('emits revoked events', async () => {
    const lines: string[] = [];
    const plugin = new StdoutPosturePlugin({ sink: (l) => lines.push(l) });
    await plugin.emitRevoked('agent-xyz', '2026-04-29T01:00:00Z');
    expect(lines[0]).toContain('"event":"revoked"');
    expect(lines[0]).toContain('"agentId":"agent-xyz"');
  });
});

describe('DefenderCspmPlugin', () => {
  function makeClient() {
    return {
      assessments: {
        createOrUpdate: jest.fn().mockResolvedValue(undefined),
        delete: jest.fn().mockResolvedValue(undefined),
      },
    };
  }

  it('emits a custom assessment with parity fields in additionalData', async () => {
    const client = makeClient();
    const plugin = new DefenderCspmPlugin({
      subscriptionId: 'sub-1',
      clientFactory: () => client,
    });
    await plugin.emitObserved(RECORD);
    expect(client.assessments.createOrUpdate).toHaveBeenCalledTimes(1);
    const [resourceId, name, body] = client.assessments.createOrUpdate.mock.calls[0]!;
    expect(resourceId).toBe('/subscriptions/sub-1');
    expect(name).toBe('euno-agent-agent-xyz');
    const additionalData = (body as {
      properties: { additionalData: Record<string, unknown> };
    }).properties.additionalData;
    expect(additionalData['agentId']).toBe('agent-xyz');
    expect(additionalData['owningTeam']).toBe('team-a');
    expect(additionalData['capabilityManifestHash']).toBe('deadbeef');
    expect(additionalData['runtime']).toBe('node:20');
    expect(additionalData['region']).toBe('eastus2');
  });

  it('soft-deletes on revoke (NotApplicable) instead of hard delete', async () => {
    const client = makeClient();
    const plugin = new DefenderCspmPlugin({
      subscriptionId: 'sub-1',
      clientFactory: () => client,
    });
    await plugin.emitRevoked('agent-xyz', '2026-04-29T01:00:00Z');
    expect(client.assessments.delete).not.toHaveBeenCalled();
    expect(client.assessments.createOrUpdate).toHaveBeenCalledTimes(1);
    const body = client.assessments.createOrUpdate.mock.calls[0]![2] as {
      properties: { status: { code: string }; additionalData: { revokedAt: string } };
    };
    expect(body.properties.status.code).toBe('NotApplicable');
    expect(body.properties.additionalData.revokedAt).toBe('2026-04-29T01:00:00Z');
  });

  it('rejects construction without subscriptionId', () => {
    expect(() => new DefenderCspmPlugin({ subscriptionId: '' })).toThrow();
  });
});

describe('SecurityHubPlugin', () => {
  function makeClient() {
    return { send: jest.fn().mockResolvedValue(undefined) };
  }

  it('emits a finding with parity fields in ProductFields and Tags', async () => {
    const client = makeClient();
    const plugin = new SecurityHubPlugin({
      awsAccountId: '111111111111',
      region: 'us-east-1',
      productArn: 'arn:aws:securityhub:us-east-1:111111111111:product/euno',
      clientFactory: () => client,
      commandFactory: (input) => ({ input }),
    });
    await plugin.emitObserved(RECORD);
    expect(client.send).toHaveBeenCalledTimes(1);
    const cmd = client.send.mock.calls[0]![0] as { input: { Findings: any[] } };
    const f = cmd.input.Findings[0]!;
    expect(f.AwsAccountId).toBe('111111111111');
    expect(f.GeneratorId).toBe('euno/posture-emitter/v1');
    expect(f.ProductFields.agentId).toBe('agent-xyz');
    expect(f.ProductFields.owningTeam).toBe('team-a');
    expect(f.ProductFields.capabilityManifestHash).toBe('deadbeef');
    expect(f.ProductFields.runtime).toBe('node:20');
    expect(f.ProductFields.region).toBe('eastus2');
    // Tags carry the same parity set on Resources[].
    expect(f.Resources[0].Tags).toEqual({
      agentId: 'agent-xyz',
      owningTeam: 'team-a',
      capabilityManifestHash: 'deadbeef',
      runtime: 'node:20',
      region: 'eastus2',
    });
  });

  it('marks finding RESOLVED on revoke', async () => {
    const client = makeClient();
    const plugin = new SecurityHubPlugin({
      awsAccountId: '111111111111',
      region: 'us-east-1',
      productArn: 'arn:aws:securityhub:us-east-1:111111111111:product/euno',
      clientFactory: () => client,
      commandFactory: (input) => ({ input }),
    });
    await plugin.emitRevoked('agent-xyz', '2026-04-29T01:00:00Z');
    const cmd = client.send.mock.calls[0]![0] as { input: { Findings: any[] } };
    const f = cmd.input.Findings[0]!;
    expect(f.Workflow.Status).toBe('RESOLVED');
    expect(f.ProductFields.revokedAt).toBe('2026-04-29T01:00:00Z');
  });

  it('rejects construction with missing required config', () => {
    expect(
      () =>
        new SecurityHubPlugin({
          awsAccountId: '',
          region: 'us-east-1',
          productArn: 'arn',
        }),
    ).toThrow();
  });
});

describe('SccPlugin', () => {
  function makeClient() {
    return {
      createFinding: jest.fn().mockResolvedValue(undefined),
      updateFinding: jest.fn().mockResolvedValue(undefined),
    };
  }

  it('creates a finding with parity fields in sourceProperties', async () => {
    const client = makeClient();
    const plugin = new SccPlugin({
      sourceName: 'organizations/123/sources/456',
      projectId: 'proj-1',
      clientFactory: () => client,
    });
    await plugin.emitObserved(RECORD);
    expect(client.createFinding).toHaveBeenCalledTimes(1);
    const req = client.createFinding.mock.calls[0]![0] as {
      parent: string;
      findingId: string;
      finding: { category: string; sourceProperties: Record<string, unknown> };
    };
    expect(req.parent).toBe('organizations/123/sources/456');
    expect(req.findingId).toBe('agent-xyz');
    expect(req.finding.category).toBe('EUNO_AGENT_INVENTORY');
    expect(req.finding.sourceProperties['agentId']).toBe('agent-xyz');
    expect(req.finding.sourceProperties['owningTeam']).toBe('team-a');
    expect(req.finding.sourceProperties['capabilityManifestHash']).toBe('deadbeef');
    expect(req.finding.sourceProperties['runtime']).toBe('node:20');
    expect(req.finding.sourceProperties['region']).toBe('eastus2');
  });

  it('falls back to updateFinding on ALREADY_EXISTS', async () => {
    const client = makeClient();
    client.createFinding.mockRejectedValueOnce(Object.assign(new Error('exists'), { code: 6 }));
    const plugin = new SccPlugin({
      sourceName: 'organizations/123/sources/456',
      projectId: 'proj-1',
      clientFactory: () => client,
    });
    await plugin.emitObserved(RECORD);
    expect(client.updateFinding).toHaveBeenCalledTimes(1);
  });

  it('marks finding INACTIVE on revoke', async () => {
    const client = makeClient();
    const plugin = new SccPlugin({
      sourceName: 'organizations/123/sources/456',
      projectId: 'proj-1',
      clientFactory: () => client,
    });
    await plugin.emitRevoked('agent-xyz', '2026-04-29T01:00:00Z');
    const req = client.updateFinding.mock.calls[0]![0] as {
      finding: { state: string; sourceProperties: { revokedAt: string } };
    };
    expect(req.finding.state).toBe('INACTIVE');
    expect(req.finding.sourceProperties.revokedAt).toBe('2026-04-29T01:00:00Z');
  });

  it('sanitizes findingIds with non-allowed characters', async () => {
    const client = makeClient();
    const plugin = new SccPlugin({
      sourceName: 'organizations/123/sources/456',
      projectId: 'proj-1',
      clientFactory: () => client,
    });
    const r: AgentInventoryRecord = { ...RECORD, agentId: 'did:web:example.com#agent-1' };
    await plugin.emitObserved(r);
    const req = client.createFinding.mock.calls[0]![0] as { findingId: string };
    expect(req.findingId).toMatch(/^[A-Za-z0-9_-]{1,32}$/);
  });
});

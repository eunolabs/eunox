/**
 * Tests for the issuance-context builder and policy hash helper.
 */

import { buildIssuanceContext, computeCapabilityPolicyHash } from '../src/issuance/issuance-context';
import { canonicalSha256 } from '@euno/common';

const DEFAULT_POLICY = {
  default: {
    'data-analyst': [{ resource: 'db://prod/reports', actions: ['read'] }],
  },
};

const DEFAULT_MANIFEST = {
  agentId: 'agent-001',
  name: 'Test Agent',
  version: '1.0.0',
  requiredCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
  optionalCapabilities: [],
};

// Precompute as the service would do it at startup
const DEFAULT_POLICY_HASH = computeCapabilityPolicyHash(DEFAULT_POLICY);

describe('computeCapabilityPolicyHash', () => {
  it('excludes dbUsernamesByRole from the digest', () => {
    const policyWithDb = {
      ...DEFAULT_POLICY,
      dbUsernamesByRole: { 'data-analyst': 'analyst_user' },
    };
    const withoutDb = computeCapabilityPolicyHash(DEFAULT_POLICY);
    const withDb = computeCapabilityPolicyHash(policyWithDb);
    // Adding dbUsernamesByRole must NOT change the policy hash
    expect(withDb).toBe(withoutDb);
  });

  it('changes the digest when capability grants change', () => {
    const modified = {
      default: {
        'data-analyst': [{ resource: 'db://prod/reports', actions: ['read', 'write'] }],
      },
    };
    expect(computeCapabilityPolicyHash(modified)).not.toBe(DEFAULT_POLICY_HASH);
  });

  it('includes tenant overrides in the digest', () => {
    const withTenant = {
      ...DEFAULT_POLICY,
      tenants: { 'acme': { 'data-analyst': [{ resource: 'db://acme/reports', actions: ['read'] }] } },
    };
    expect(computeCapabilityPolicyHash(withTenant)).not.toBe(DEFAULT_POLICY_HASH);
  });

  it('is deterministic: same policy always yields the same hash', () => {
    expect(computeCapabilityPolicyHash(DEFAULT_POLICY)).toBe(DEFAULT_POLICY_HASH);
  });
});

describe('buildIssuanceContext', () => {
  it('uses the supplied policyHash verbatim', () => {
    const ctx = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      subject: 'agent-001',
      audience: 'tool-gateway',
    });
    expect(ctx.policyHash).toBe(DEFAULT_POLICY_HASH);
  });

  it('includes manifestHash when a manifest is supplied', () => {
    const ctx = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      manifest: DEFAULT_MANIFEST,
      subject: 'agent-001',
      audience: 'tool-gateway',
    });
    expect(ctx.manifestHash).toBe(canonicalSha256(DEFAULT_MANIFEST));
  });

  it('omits manifestHash when no manifest is supplied', () => {
    const ctx = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      subject: 'agent-001',
      audience: 'tool-gateway',
    });
    expect(ctx.manifestHash).toBeUndefined();
  });

  it('stamps subject and audience verbatim', () => {
    const ctx = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      subject: 'my-agent',
      audience: 'tool-gateway:acme-prod',
    });
    expect(ctx.subject).toBe('my-agent');
    expect(ctx.audience).toBe('tool-gateway:acme-prod');
  });

  it('is deterministic: identical inputs yield identical outputs', () => {
    const a = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      manifest: DEFAULT_MANIFEST,
      subject: 's',
      audience: 'a',
    });
    const b = buildIssuanceContext({
      policyHash: DEFAULT_POLICY_HASH,
      manifest: DEFAULT_MANIFEST,
      subject: 's',
      audience: 'a',
    });
    expect(a).toEqual(b);
  });

  it('different manifests produce different manifestHashes', () => {
    const mA = { agentId: 'agent-A', name: 'A', version: '1.0.0', requiredCapabilities: [{ resource: 'api://svc', actions: ['read'] }], optionalCapabilities: [] };
    const mB = { agentId: 'agent-B', name: 'B', version: '1.0.0', requiredCapabilities: [{ resource: 'api://svc', actions: ['write'] }], optionalCapabilities: [] };

    const ctxA = buildIssuanceContext({ policyHash: DEFAULT_POLICY_HASH, manifest: mA, subject: 's', audience: 'a' });
    const ctxB = buildIssuanceContext({ policyHash: DEFAULT_POLICY_HASH, manifest: mB, subject: 's', audience: 'a' });

    expect(ctxA.manifestHash).not.toBe(ctxB.manifestHash);
  });
});

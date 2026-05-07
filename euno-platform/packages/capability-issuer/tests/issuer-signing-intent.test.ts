/**
 * Service-level tests: verify that CapabilityIssuerService forwards
 * IssuanceContext through all three signing paths (issue, attenuate, renew)
 * and that the context carries the expected policyHash and audience.
 *
 * A spy on the signer's sign() method captures the IssuanceContext passed at
 * signing time so we can assert the wiring without inspecting KMS behaviour.
 */

import * as jose from 'jose';
import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  IssuanceContext,
  RoleCapabilityPolicy,
  createLogger,
} from '@euno/common';
import { computeCapabilityPolicyHash } from '../src/issuance/issuance-context';

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private context: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(): Promise<UserContext> {
    return this.context;
  }
  async getUserRoles(): Promise<string[]> {
    return this.context.roles;
  }
}

class SpySigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  private publicKeyPem!: string;
  /** All (payload, context) tuples recorded by sign() calls. */
  public readonly signCalls: Array<{ payload: CapabilityTokenPayload; context: IssuanceContext | undefined }> = [];

  constructor() {
    super({ type: 'spy', name: 'spy', algorithm: 'RS256' } as SigningAdapterConfig);
  }

  async init(): Promise<void> {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.publicKeyPem = await jose.exportSPKI(publicKey);
  }

  async sign(payload: CapabilityTokenPayload, context?: IssuanceContext): Promise<string> {
    this.signCalls.push({ payload, context });
    return new jose.SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(this.privateKey);
  }

  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return 'spy-key';
  }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const POLICY: RoleCapabilityPolicy = {
  default: {
    analyst: [{ resource: 'db://prod/reports', actions: ['read'] }],
  },
};

const logger = createLogger('issuer-signing-intent-test', 'test');

async function makeService(opts?: { policy?: RoleCapabilityPolicy; audience?: string }) {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['analyst'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new SpySigner();
  await signer.init();
  const policy = opts?.policy ?? POLICY;
  const service = new CapabilityIssuerService(signer, identity, 'did:web:example.com', 900, logger, {
    policy,
    gatewayAudience: opts?.audience ?? 'tool-gateway',
    requireConsent: false,
  });
  return { service, signer };
}

// ---------------------------------------------------------------------------
// issueCapability — context forwarding
// ---------------------------------------------------------------------------

describe('issueCapability — IssuanceContext forwarding', () => {
  it('passes an IssuanceContext with the correct policyHash to the signer', async () => {
    const { service, signer } = await makeService();
    const expectedHash = computeCapabilityPolicyHash(POLICY);

    await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });

    expect(signer.signCalls).toHaveLength(1);
    const ctx = signer.signCalls[0]!.context;
    expect(ctx).toBeDefined();
    expect(ctx!.policyHash).toBe(expectedHash);
  });

  it('stamps the policyHash into the minted token payload', async () => {
    const { service, signer } = await makeService();
    const expectedHash = computeCapabilityPolicyHash(POLICY);

    await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-2',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });

    const payload = signer.signCalls[0]!.payload;
    expect(payload.policyHash).toBe(expectedHash);
  });

  it('sets context.audience to the configured gatewayAudience', async () => {
    const { service, signer } = await makeService({ audience: 'my-gateway' });

    await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-3',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });

    const ctx = signer.signCalls[0]!.context;
    expect(ctx!.audience).toBe('my-gateway');
  });

  it('excludes dbUsernamesByRole from the policyHash', async () => {
    const policyWithDb: RoleCapabilityPolicy = {
      ...POLICY,
      dbUsernamesByRole: { analyst: 'analyst_user' },
    };
    const { service, signer } = await makeService({ policy: policyWithDb });
    const hashWithoutDb = computeCapabilityPolicyHash(POLICY);

    await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-4',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });

    const ctx = signer.signCalls[0]!.context;
    // Hash must be identical to the one computed without dbUsernamesByRole
    expect(ctx!.policyHash).toBe(hashWithoutDb);
  });
});

// ---------------------------------------------------------------------------
// attenuateCapability — context forwarding and policy-hash restoration
// ---------------------------------------------------------------------------

describe('attenuateCapability — IssuanceContext forwarding', () => {
  async function issueToken(service: CapabilityIssuerService) {
    const resp = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });
    return resp.token;
  }

  it('passes an IssuanceContext to the signer for the attenuated child', async () => {
    const { service, signer } = await makeService();
    const parentToken = await issueToken(service);
    const sigCallsBeforeAttenuation = signer.signCalls.length;

    await service.attenuateCapability(
      parentToken,
      [{ resource: 'db://prod/reports', actions: ['read'] }],
    );

    expect(signer.signCalls.length).toBeGreaterThan(sigCallsBeforeAttenuation);
    const ctx = signer.signCalls[signer.signCalls.length - 1]!.context;
    expect(ctx).toBeDefined();
    expect(ctx!.policyHash).toBeDefined();
  });

  it('restores policyHash from the parent token (not the current loaded policy)', async () => {
    const { service, signer } = await makeService();
    const expectedHash = computeCapabilityPolicyHash(POLICY);
    const parentToken = await issueToken(service);

    await service.attenuateCapability(
      parentToken,
      [{ resource: 'db://prod/reports', actions: ['read'] }],
    );

    // The policyHash in the attenuation context must equal the hash stamped in
    // the parent, which itself equals the hash of the service's loaded policy.
    const attenuationCtx = signer.signCalls[signer.signCalls.length - 1]!.context;
    expect(attenuationCtx!.policyHash).toBe(expectedHash);
  });

  it('stamps the policyHash into the attenuated child payload', async () => {
    const { service, signer } = await makeService();
    const parentToken = await issueToken(service);

    await service.attenuateCapability(
      parentToken,
      [{ resource: 'db://prod/reports', actions: ['read'] }],
    );

    const childPayload = signer.signCalls[signer.signCalls.length - 1]!.payload;
    expect(childPayload.policyHash).toBeDefined();
    expect(childPayload.policyHash).toBe(computeCapabilityPolicyHash(POLICY));
  });
});

// ---------------------------------------------------------------------------
// renewCapability — context forwarding and policy-hash restoration
// ---------------------------------------------------------------------------

describe('renewCapability — IssuanceContext forwarding', () => {
  async function issueToken(service: CapabilityIssuerService) {
    const resp = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'db://prod/reports', actions: ['read'] }],
    });
    return resp.token;
  }

  it('passes an IssuanceContext to the signer for the renewed token', async () => {
    const { service, signer } = await makeService();
    const originalToken = await issueToken(service);
    const sigCallsBefore = signer.signCalls.length;

    await service.renewCapability(originalToken);

    expect(signer.signCalls.length).toBeGreaterThan(sigCallsBefore);
    const ctx = signer.signCalls[signer.signCalls.length - 1]!.context;
    expect(ctx).toBeDefined();
    expect(ctx!.policyHash).toBeDefined();
  });

  it('restores policyHash from the current token for renewCapability', async () => {
    const { service, signer } = await makeService();
    const expectedHash = computeCapabilityPolicyHash(POLICY);
    const originalToken = await issueToken(service);

    await service.renewCapability(originalToken);

    const renewalCtx = signer.signCalls[signer.signCalls.length - 1]!.context;
    expect(renewalCtx!.policyHash).toBe(expectedHash);
  });

  it('stamps the policyHash into the renewed token payload', async () => {
    const { service, signer } = await makeService();
    const originalToken = await issueToken(service);

    await service.renewCapability(originalToken);

    const renewedPayload = signer.signCalls[signer.signCalls.length - 1]!.payload;
    expect(renewedPayload.policyHash).toBeDefined();
    expect(renewedPayload.policyHash).toBe(computeCapabilityPolicyHash(POLICY));
  });
});

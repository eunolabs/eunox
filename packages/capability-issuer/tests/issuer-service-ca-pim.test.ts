/**
 * Tests for CapabilityIssuerService Conditional Access (#3) and PIM
 * activation (#4) enforcement, added by the Sprint 3-4 gap closure.
 *
 * These tests use a stubbed identity provider (no Azure AD / Graph
 * dependency) and exercise the issuer's branching on
 * `userContext.caEvaluation` and `userContext.roleSources`.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  CaEvaluation,
  ResolvedRole,
  createLogger,
} from '@euno/common';

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private context: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(_token: string): Promise<UserContext> {
    return this.context;
  }
  async getUserRoles(_userId: string): Promise<string[]> {
    return this.context.roles;
  }
}

class StubSigner extends SigningAdapter {
  constructor() {
    super({ type: 'stub', name: 'stub', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    // Encode `exp` into the fake signature so tests can verify TTL capping.
    return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
  }
  async getPublicKey(): Promise<string> {
    return '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----';
  }
  async getKeyId(): Promise<string> {
    return 'stub-key-id';
  }
}

const logger = createLogger('issuer-service-ca-pim-test', 'test');

function makeContext(overrides: Partial<UserContext> = {}): UserContext {
  return {
    userId: 'user-1',
    email: 'user-1@example.com',
    roles: ['Reader'],
    tenantId: 'tenant-1',
    claims: {},
    ...overrides,
  };
}

function makeService(
  ctx: UserContext,
  options: ConstructorParameters<typeof CapabilityIssuerService>[5] = {},
) {
  const identity = new StubIdentityProvider(ctx);
  const signer = new StubSigner();
  return new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
    options,
  );
}

const ALL_TIERS_SATISFIED: CaEvaluation = {
  satisfiedTiers: ['read', 'write', 'delete', 'admin'],
  presentedAcrs: [],
};

describe('CapabilityIssuerService — Conditional Access enforcement', () => {
  it('issues a token when caEvaluation is undefined (back-compat)', async () => {
    const ctx = makeContext({ roles: ['SalesManager'] });
    const service = makeService(ctx);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
    });
    expect(result.token).toBeTruthy();
  });

  it('issues a token when every requested action tier is satisfied', async () => {
    const ctx = makeContext({
      roles: ['SalesManager'],
      caEvaluation: { ...ALL_TIERS_SATISFIED },
    });
    const service = makeService(ctx);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('denies issuance with CONDITIONAL_ACCESS_REQUIRED when a requested tier is not satisfied', async () => {
    const ctx = makeContext({
      roles: ['Administrator'],
      caEvaluation: {
        satisfiedTiers: ['read'],
        requiredAcrsByTier: {
          write: ['urn:euno:mfa'],
          admin: ['urn:euno:mfa'],
        },
        presentedAcrs: [],
      },
    });
    const service = makeService(ctx);
    // Role-derived (no requestedCapabilities): Administrator's default
    // mapping includes write/admin actions, which the read-only CA
    // evaluation does not satisfy → deny.
    await expect(
      service.issueCapability({ authToken: 'tok', agentId: 'agent-1' }),
    ).rejects.toMatchObject({
      code: 'CONDITIONAL_ACCESS_REQUIRED',
      statusCode: 403,
    });
  });

  it('denies role-derived issuance when default role grants admin but only read is satisfied', async () => {
    // Administrator role's default mapping includes admin/write actions.
    const ctx = makeContext({
      roles: ['Administrator'],
      caEvaluation: {
        satisfiedTiers: ['read'],
        presentedAcrs: [],
      },
    });
    const service = makeService(ctx);
    await expect(
      service.issueCapability({ authToken: 'tok', agentId: 'agent-1' }),
    ).rejects.toMatchObject({
      code: 'CONDITIONAL_ACCESS_REQUIRED',
      statusCode: 403,
    });
  });

  it('classifies resource-specific verbs into legacy CA tiers', async () => {
    // `read` actions map to the read tier; satisfiedTiers includes read.
    const ctx = makeContext({
      roles: ['Viewer'],
      caEvaluation: {
        satisfiedTiers: ['read'], // delete not satisfied
        presentedAcrs: [],
      },
    });
    const service = makeService(ctx);

    // A read-only request succeeds.
    await expect(
      service.issueCapability({
        authToken: 'tok',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read'] },
        ],
      }),
    ).resolves.toBeTruthy();
  });
});

describe('CapabilityIssuerService — PIM enforcement', () => {
  const ACTIVE_END = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  it('issues a token when roleSources is undefined (back-compat)', async () => {
    const ctx = makeContext({ roles: ['Administrator'] });
    const service = makeService(ctx, {
      pimRequiredRoles: ['Global Administrator'],
    });
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('denies with AUTHORIZATION_FAILED when a pimRequiredRole is held but not pim-active', async () => {
    const sources: ResolvedRole[] = [
      { name: 'Reader', source: { kind: 'permanent' } },
      { name: 'Global Administrator', source: { kind: 'permanent' } },
    ];
    const ctx = makeContext({
      roles: ['Reader', 'Global Administrator'],
      roleSources: sources,
    });
    const service = makeService(ctx, {
      pimRequiredRoles: ['Global Administrator'],
    });
    await expect(
      service.issueCapability({ authToken: 'tok', agentId: 'agent-1' }),
    ).rejects.toMatchObject({
      code: 'AUTHORIZATION_FAILED',
      statusCode: 403,
    });
  });

  it('allows issuance when the pimRequiredRole is pim-active', async () => {
    const sources: ResolvedRole[] = [
      {
        name: 'Global Administrator',
        source: { kind: 'pim-active', assignmentId: 'a1', endDateTime: ACTIVE_END },
      },
    ];
    const ctx = makeContext({
      roles: ['Global Administrator'],
      roleSources: sources,
    });
    const service = makeService(ctx, {
      pimRequiredRoles: ['Global Administrator'],
    });
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('does not block when the user does not hold the pimRequiredRole at all', async () => {
    const sources: ResolvedRole[] = [
      { name: 'Reader', source: { kind: 'permanent' } },
    ];
    const ctx = makeContext({
      roles: ['Reader'],
      roleSources: sources,
    });
    const service = makeService(ctx, {
      pimRequiredRoles: ['Global Administrator'],
    });
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('caps capability TTL at the smallest remaining pim-active window', async () => {
    const tenMinutesEnd = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const sources: ResolvedRole[] = [
      {
        name: 'Reader',
        source: { kind: 'pim-active', assignmentId: 'a1', endDateTime: tenMinutesEnd },
      },
    ];
    const ctx = makeContext({ roles: ['Reader'], roleSources: sources });
    // defaultTTL is 900s (15 min) — should be capped to ~570s (10min - 30s margin).
    const service = makeService(ctx);
    const before = Math.floor(Date.now() / 1000);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    const elapsedTtl = result.expiresAt - before;
    // Capped at 10 minutes - 30s safety margin = 570s, with a few seconds of slack.
    expect(elapsedTtl).toBeLessThanOrEqual(600);
    expect(elapsedTtl).toBeGreaterThan(500);
  });

  it('does not cap TTL when capTtlToPimActivation is disabled', async () => {
    const tenMinutesEnd = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const sources: ResolvedRole[] = [
      {
        name: 'Reader',
        source: { kind: 'pim-active', assignmentId: 'a1', endDateTime: tenMinutesEnd },
      },
    ];
    const ctx = makeContext({ roles: ['Reader'], roleSources: sources });
    const service = makeService(ctx, { capTtlToPimActivation: false });
    const before = Math.floor(Date.now() / 1000);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    const elapsedTtl = result.expiresAt - before;
    // Default TTL of 900s should be applied, not capped.
    expect(elapsedTtl).toBeGreaterThan(800);
    expect(elapsedTtl).toBeLessThanOrEqual(900);
  });

  it('does not cap TTL when there are no pim-active roles (only permanent)', async () => {
    const sources: ResolvedRole[] = [
      { name: 'Reader', source: { kind: 'permanent' } },
    ];
    const ctx = makeContext({ roles: ['Reader'], roleSources: sources });
    const service = makeService(ctx);
    const before = Math.floor(Date.now() / 1000);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    const elapsedTtl = result.expiresAt - before;
    expect(elapsedTtl).toBeGreaterThan(800);
    expect(elapsedTtl).toBeLessThanOrEqual(900);
  });

  it('uses the smallest endDateTime when multiple pim-active roles are present', async () => {
    const fiveMinutesEnd = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const thirtyMinutesEnd = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const sources: ResolvedRole[] = [
      {
        name: 'Reader',
        source: { kind: 'pim-active', assignmentId: 'a1', endDateTime: thirtyMinutesEnd },
      },
      {
        name: 'Editor',
        source: { kind: 'pim-active', assignmentId: 'a2', endDateTime: fiveMinutesEnd },
      },
    ];
    const ctx = makeContext({ roles: ['Reader', 'Editor'], roleSources: sources });
    const service = makeService(ctx);
    const before = Math.floor(Date.now() / 1000);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
    });
    const elapsedTtl = result.expiresAt - before;
    // Capped at 5 minutes - 30s safety margin = 270s, with slack.
    expect(elapsedTtl).toBeLessThanOrEqual(300);
    expect(elapsedTtl).toBeGreaterThan(200);
  });
});

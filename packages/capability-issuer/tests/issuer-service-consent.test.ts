/**
 * Tests for the new issuance-time controls added to harden the
 * token-acquisition flow:
 *
 *   1. Per-agent manifest constraint at issuance time — even if the user's
 *      roles allow more, the issuer must refuse to mint a token outside the
 *      agent's declared `requiredCapabilities ∪ optionalCapabilities`.
 *
 *   2. Explicit user consent — sensitive actions (write/delete/admin) and
 *      the optional `requireConsent` strict mode require a validated
 *      consent record bound to the same user and agent.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  AgentCapabilityManifest,
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  UserConsent,
  CapabilityTokenPayload,
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
  async sign(_payload: CapabilityTokenPayload): Promise<string> {
    return 'header.payload.signature';
  }
  async getPublicKey(): Promise<string> {
    return '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----';
  }
  async getKeyId(): Promise<string> {
    return 'stub-key-id';
  }
}

const logger = createLogger('issuer-service-consent-test', 'test');

function makeService(roles: string[], requireConsent = false) {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles,
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new StubSigner();
  return new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
    { requireConsent },
  );
}

const validConsent = (overrides: Partial<UserConsent> = {}): UserConsent => ({
  userId: 'user-1',
  agentId: 'agent-1',
  grantedCapabilities: [{ resource: 'api://crm/**', actions: ['read', 'write'] }],
  grantedAt: Math.floor(Date.now() / 1000),
  ...overrides,
});

describe('CapabilityIssuerService — manifest enforcement at issuance time', () => {
  const baseManifest: AgentCapabilityManifest = {
    agentId: 'agent-1',
    name: 'CRM Bot',
    version: '1.0.0',
    requiredCapabilities: [
      { resource: 'api://crm/customers', actions: ['read'] },
    ],
    optionalCapabilities: [
      { resource: 'api://crm/orders', actions: ['read'] },
    ],
  };

  it('allows a request that falls within the manifest', async () => {
    const service = makeService(['Administrator']);
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: baseManifest,
    });
    expect(response.capabilities).toEqual([
      { resource: 'api://crm/customers', actions: ['read'] },
    ]);
  });

  it('rejects a resource outside the manifest, even when roles permit it', async () => {
    const service = makeService(['Administrator']);
    // Administrator role grants api://** but the manifest does not declare
    // api://billing/invoices, so issuance must be denied.
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://billing/invoices', actions: ['read'] }],
        manifest: baseManifest,
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects an action outside the manifest, even when roles permit it', async () => {
    const service = makeService(['Administrator']);
    // Administrator can write api://**, but the manifest only declares read on
    // api://crm/customers, so write must be refused.
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
        manifest: baseManifest,
        consent: validConsent(),
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects when the manifest agentId does not match the request agentId', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
        manifest: { ...baseManifest, agentId: 'different-agent' },
      }),
    ).rejects.toMatchObject({ statusCode: 400 });
  });
});

describe('CapabilityIssuerService — explicit user consent', () => {
  it('requires consent when a sensitive action is requested', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('does not require consent for read-only requests', async () => {
    const service = makeService(['Administrator']);
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
    });
    expect(response.capabilities).toHaveLength(1);
  });

  it('grants when valid consent covers all requested capabilities', async () => {
    const service = makeService(['Administrator']);
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
      consent: validConsent(),
    });
    expect(response.capabilities).toEqual([
      { resource: 'api://crm/customers', actions: ['write'] },
    ]);
  });

  it('rejects consent bound to a different user', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
        consent: validConsent({ userId: 'someone-else' }),
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects consent bound to a different agent', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
        consent: validConsent({ agentId: 'other-agent' }),
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects expired consent', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['write'] }],
        consent: validConsent({ expiresAt: Math.floor(Date.now() / 1000) - 60 }),
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects consent that does not cover the requested action', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['delete'] }],
        consent: validConsent(), // grants read+write only
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects consent that does not cover the requested resource', async () => {
    const service = makeService(['Administrator']);
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://billing/invoices', actions: ['write'] }],
        consent: validConsent(), // grants api://crm/** only
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('strict mode (requireConsent=true) demands consent even for read-only requests', async () => {
    const strict = makeService(['Administrator'], true);
    await expect(
      strict.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });

    // And succeeds once a covering consent record is supplied.
    const response = await strict.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      consent: validConsent({
        grantedCapabilities: [{ resource: 'api://crm/**', actions: ['read'] }],
      }),
    });
    expect(response.capabilities).toHaveLength(1);
  });

  it('strict mode rejects when the request has no requestedCapabilities at all', async () => {
    const strict = makeService(['Administrator'], true);
    await expect(
      strict.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
      }),
    ).rejects.toMatchObject({ statusCode: 400 });
  });
});

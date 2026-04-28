/**
 * Direct unit tests for CapabilityIssuerService — focused on the
 * wildcard-aware subset validation introduced when extracting the
 * Sprint-1 role mapper out of the Azure-only path.
 *
 * Earlier the subset check used exact resource-string equality, which
 * meant role mappings with wildcard resources (e.g. `api://**`,
 * `storage://sales-data/**` from the Administrator / SalesManager roles)
 * never authorized concrete resources beneath them. The fix uses
 * `matchesResource` so the subset semantics align with the gateway's
 * enforcement engine.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
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

const logger = createLogger('issuer-service-test', 'test');

function makeService(roles: string[]) {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles,
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new StubSigner();
  return new CapabilityIssuerService(signer, identity, 'did:web:example.com', 900, logger);
}

describe('CapabilityIssuerService subset validation', () => {
  it('grants a concrete resource when the role mapping covers it via /** wildcard (Administrator)', async () => {
    const service = makeService(['Administrator']);
    // Administrator role includes `api://**` (read/write/admin)
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'api://crm/customers', actions: ['read', 'write'] },
      ],
    });

    expect(response.capabilities).toEqual([
      { resource: 'api://crm/customers', actions: ['read', 'write'] },
    ]);
  });

  it('grants a concrete storage resource when the role mapping covers it via prefix wildcard (SalesManager)', async () => {
    const service = makeService(['SalesManager']);
    // SalesManager role includes `storage://sales-data/**` (read/write)
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'storage://sales-data/2026-q1/forecast.csv', actions: ['read'] },
      ],
    });

    expect(response.capabilities).toEqual([
      { resource: 'storage://sales-data/2026-q1/forecast.csv', actions: ['read'] },
    ]);
  });

  it('still rejects requested resources not covered by any role mapping', async () => {
    const service = makeService(['Viewer']);
    // Viewer does NOT grant write on api://crm/customers
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['write'] },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('rejects requested resources outside any wildcard scope', async () => {
    const service = makeService(['Viewer']);
    // Viewer's mappings cover api://crm/* and storage://sales-data/**, but
    // not storage://datasets/**.
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'storage://datasets/foo', actions: ['read'] },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });
});

describe('CapabilityIssuerService externalised role policy', () => {
  function makeServiceWithPolicy(
    roles: string[],
    tenantId: string | undefined,
    policy: ConstructorParameters<typeof CapabilityIssuerService>[5],
  ) {
    const identity = new StubIdentityProvider({
      userId: 'user-1',
      email: 'user@example.com',
      roles,
      tenantId,
      claims: {},
    });
    const signer = new StubSigner();
    return new CapabilityIssuerService(signer, identity, 'did:web:example.com', 900, logger, policy);
  }

  it('uses the supplied policy instead of the in-code default', async () => {
    const policy = {
      default: {
        AppRole: [{ resource: 'api://app/widgets', actions: ['read' as const] }],
      },
    };
    const service = makeServiceWithPolicy(['AppRole'], 'tenant-1', policy);
    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
    });
    expect(response.capabilities).toEqual([
      { resource: 'api://app/widgets', actions: ['read'] },
    ]);
    // The Sprint-1 default Administrator role must NOT leak when a custom
    // policy is supplied.
    expect(response.capabilities).not.toContainEqual(
      expect.objectContaining({ resource: 'api://**' }),
    );
  });

  it('honours per-tenant overrides when the user belongs to that tenant', async () => {
    const policy = {
      default: {
        Viewer: [{ resource: 'api://crm/customers', actions: ['read' as const] }],
      },
      tenants: {
        'tenant-vip': {
          Viewer: [
            { resource: 'api://crm/customers', actions: ['read' as const] },
            { resource: 'api://crm/reports', actions: ['read' as const] },
          ],
        },
      },
    };
    const standard = makeServiceWithPolicy(['Viewer'], 'tenant-standard', policy);
    const vip = makeServiceWithPolicy(['Viewer'], 'tenant-vip', policy);

    const standardResp = await standard.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
    });
    const vipResp = await vip.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
    });

    expect(standardResp.capabilities).toHaveLength(1);
    expect(vipResp.capabilities).toHaveLength(2);
    expect(vipResp.capabilities).toContainEqual({
      resource: 'api://crm/reports',
      actions: ['read'],
    });
  });

  it('removes a default role for a tenant when the override is empty', async () => {
    const policy = {
      default: {
        Viewer: [{ resource: 'api://crm/customers', actions: ['read' as const] }],
      },
      tenants: {
        'tenant-suspended': { Viewer: [] },
      },
    };
    const service = makeServiceWithPolicy(['Viewer'], 'tenant-suspended', policy);
    // No capabilities → requesting any resource must be denied.
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read'] },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
  });
});

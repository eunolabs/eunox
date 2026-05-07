/**
 * Tests for the issuance-time validation of typed
 * {@link CapabilityCondition} payloads. Pre-fix the issuer accepted
 * any `conditions` shape and silently signed it into the token; the
 * gateway then ignored the field entirely, producing a fail-open
 * authorization path. The contract under test:
 *
 *   1. Malformed conditions (typos, wrong value types, missing
 *      required fields) are rejected at mint time with INVALID_REQUEST.
 *   2. Unknown discriminators are likewise rejected — there is no
 *      "unrecognized = pass through" path.
 *   3. Well-formed conditions (every built-in type) round-trip into
 *      the issued token unchanged.
 *   4. The same validation runs on `attenuateCapability` so a child
 *      token cannot smuggle in a malformed condition.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  CapabilityConstraint,
  createLogger,
} from '@euno/common';
import * as jose from 'jose';

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

/**
 * Real RS256 signer so attenuated tests can verify the parent token.
 * Re-using a single key pair across tests is fine — none of these
 * assertions inspect signatures.
 */
class JoseSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  private publicKeyPem!: string;
  constructor() {
    super({ type: 'jose', name: 'jose', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async init(): Promise<void> {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.publicKeyPem = await jose.exportSPKI(publicKey);
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(this.privateKey);
  }
  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }
  async getKeyId(): Promise<string> {
    return 'kid-1';
  }
}

const logger = createLogger('issuer-conditions-test', 'test');

async function makeService(): Promise<{
  service: CapabilityIssuerService;
  signer: JoseSigner;
}> {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'], // grants api://** so resource matches are not the bottleneck
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new JoseSigner();
  await signer.init();
  const service = new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
  );
  return { service, signer };
}

async function decode(token: string): Promise<CapabilityTokenPayload> {
  // Tests deliberately decode without verification — we are inspecting
  // the structural shape of conditions the issuer signed.
  const decoded = jose.decodeJwt(token);
  return decoded as unknown as CapabilityTokenPayload;
}

describe('CapabilityIssuerService — condition validation at issuance', () => {
  it('rejects an unknown condition discriminator with INVALID_REQUEST', async () => {
    const { service } = await makeService();
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          {
            resource: 'api://crm/customers',
            actions: ['read'],
            conditions: [{ type: 'rateLimit' as 'timeWindow' } as any],
          },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
  });

  it('rejects a malformed timeWindow (no boundaries)', async () => {
    const { service } = await makeService();
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          {
            resource: 'api://crm/customers',
            actions: ['read'],
            conditions: [{ type: 'timeWindow' }],
          },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
  });

  it('rejects a malformed ipRange (bad CIDR)', async () => {
    const { service } = await makeService();
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          {
            resource: 'api://crm/customers',
            actions: ['read'],
            conditions: [{ type: 'ipRange', cidrs: ['10.0.0.0/33'] }],
          },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 400 });
  });

  it('rejects a malformed maxCalls (zero count)', async () => {
    const { service } = await makeService();
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          {
            resource: 'api://crm/customers',
            actions: ['read'],
            conditions: [{ type: 'maxCalls', count: 0, windowSeconds: 60 }],
          },
        ],
      }),
    ).rejects.toMatchObject({ statusCode: 400 });
  });

  it('annotates the index of the offending capability in the error message', async () => {
    const { service } = await makeService();
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read'] },
          {
            resource: 'api://crm/reports',
            actions: ['read'],
            conditions: [{ type: 'unknown' as 'timeWindow' } as any],
          },
        ],
      }),
    ).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringMatching(/capability\[1\]/),
    });
  });

  it('round-trips well-formed conditions for every built-in type', async () => {
    const { service } = await makeService();
    const conditions = [
      { type: 'timeWindow', notAfter: '2099-01-01T00:00:00Z' },
      { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      { type: 'allowedOperations', operations: ['SELECT'] },
      { type: 'allowedExtensions', extensions: ['.pdf'] },
      { type: 'allowedTables', tables: ['customers'], columns: { customers: ['id'] } },
      { type: 'maxCalls', count: 100, windowSeconds: 60 },
      { type: 'recipientDomain', domains: ['example.com'] },
      { type: 'redactFields', fields: ['ssn'] },
    ] as const;

    const response = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        {
          resource: 'api://crm/customers',
          actions: ['read'],
          conditions: [...conditions] as unknown as CapabilityConstraint['conditions'],
        },
      ],
    });
    const payload = await decode(response.token);
    expect(payload.capabilities[0]?.conditions).toEqual(conditions);
  });

  it('also validates conditions in attenuateCapability', async () => {
    const { service } = await makeService();

    // First mint a parent token with no conditions.
    const parent = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'api://crm/customers', actions: ['read'] },
      ],
    });

    // Now try to attenuate it with a malformed condition — must fail
    // before the child token is signed.
    await expect(
      service.attenuateCapability(parent.token, [
        {
          resource: 'api://crm/customers',
          actions: ['read'],
          conditions: [{ type: 'maxCalls', count: -1, windowSeconds: 60 }],
        },
      ]),
    ).rejects.toMatchObject({ statusCode: 400 });
  });
});

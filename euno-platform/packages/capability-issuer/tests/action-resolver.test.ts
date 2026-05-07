/**
 * Tests for R-7: ActionResolver plumbing through CapabilityIssuerService.
 *
 * The issuer must use the injected {@link ActionResolver} when computing
 * the Conditional-Access tier of a granted action. Previously the
 * substring-matching `actionToCaTier` heuristic was inlined into
 * `enforceConditionalAccess`, so an operator could not tier a custom
 * verb without renaming the verb to contain the right substring.
 *
 * These tests verify that:
 *  1. supplying a resolver that pins `app:custom-read` to `read`
 *     successfully issues against a `read`-only CA evaluation (the
 *     legacy heuristic would have fallen back to `read` here too —
 *     pinned to verify the resolver is consulted), and
 *  2. supplying a resolver that pins `app:custom-read` to `admin`
 *     denies issuance against the same CA evaluation, proving that
 *     the issuer is reading tiers from the resolver, not from the
 *     legacy substring heuristic.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  DefaultActionResolver,
  IdentityAdapter,
  IdentityAdapterConfig,
  RoleCapabilityPolicy,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  CaEvaluation,
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
    return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
  }
  async getPublicKey(): Promise<string> {
    return '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----';
  }
  async getKeyId(): Promise<string> {
    return 'stub-key-id';
  }
}

const logger = createLogger('issuer-action-resolver-test', 'test');

function makeContext(overrides: Partial<UserContext> = {}): UserContext {
  return {
    userId: 'user-1',
    email: 'user-1@example.com',
    roles: ['CustomRole'],
    tenantId: 'tenant-1',
    claims: {},
    ...overrides,
  };
}

// A policy that grants the custom verbs used by these tests so the
// requested-within-role-scope check succeeds and the CA enforcement
// branch becomes the only thing under test.
const POLICY: RoleCapabilityPolicy = {
  default: {
    CustomRole: [
      {
        resource: 'api://things',
        actions: ['app:custom-read', 'forward_delete_request', 'read'],
      },
    ],
  },
};

function makeService(
  ctx: UserContext,
  options: ConstructorParameters<typeof CapabilityIssuerService>[5] = {},
) {
  return new CapabilityIssuerService(
    new StubSigner(),
    new StubIdentityProvider(ctx),
    'did:web:example.com',
    900,
    logger,
    { policy: POLICY, ...options },
  );
}

const READ_ONLY_CA: CaEvaluation = {
  satisfiedTiers: ['read'],
  presentedAcrs: [],
};

describe('CapabilityIssuerService — ActionResolver plumbing (R-7)', () => {
  it('uses the injected ActionResolver to tier a custom verb to read (issuance succeeds)', async () => {
    const resolver = new DefaultActionResolver({
      actionTiers: { 'app:custom-read': 'read' },
    });
    const ctx = makeContext({ caEvaluation: { ...READ_ONLY_CA } });
    const service = makeService(ctx, { actionResolver: resolver });

    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'api://things', actions: ['app:custom-read'] },
      ],
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('uses the injected ActionResolver to tier a custom verb to admin (issuance denied)', async () => {
    // Same verb, same CA evaluation, different resolver — proves the
    // resolver is the source of truth for CA tiering.
    const resolver = new DefaultActionResolver({
      actionTiers: { 'app:custom-read': 'admin' },
    });
    const ctx = makeContext({ caEvaluation: { ...READ_ONLY_CA } });
    const service = makeService(ctx, { actionResolver: resolver });

    await expect(
      service.issueCapability({
        authToken: 'tok',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'api://things', actions: ['app:custom-read'] },
        ],
      }),
    ).rejects.toMatchObject({
      code: 'CONDITIONAL_ACCESS_REQUIRED',
      statusCode: 403,
    });
  });

  it("does not mis-tier custom verbs containing 'delete' as a substring (I-5 regression)", async () => {
    // Legacy substring heuristic would have tiered this as `delete`,
    // denying against a read-only CA evaluation. The new resolver
    // tiers it as `read` (the configured defaultTier) so the request
    // succeeds — this is the user-observable I-5 fix.
    const ctx = makeContext({ caEvaluation: { ...READ_ONLY_CA } });
    const service = makeService(ctx);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'api://things', actions: ['forward_delete_request'] },
      ],
    });
    expect(result.tokenId).toBeTruthy();
  });

  it('still defaults to BUILTIN_ACTION_RESOLVER when no resolver is supplied (back-compat)', async () => {
    const ctx = makeContext({
      caEvaluation: { satisfiedTiers: ['read'], presentedAcrs: [] },
    });
    const service = makeService(ctx);
    const result = await service.issueCapability({
      authToken: 'tok',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'api://things', actions: ['read'] },
      ],
    });
    expect(result.tokenId).toBeTruthy();
  });
});

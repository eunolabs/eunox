/**
 * Integration tests for the issuer-service ↔ posture-emitter
 * pipeline introduced by sprint-3-4-gap item #9.
 *
 * Asserts:
 *  - When no emitter is configured (default), issuance proceeds
 *    unchanged and no record is observed anywhere.
 *  - When an emitter is configured, a single observation is enqueued
 *    synchronously (within issueCapability) containing the five
 *    required parity fields (agentId, owningTeam,
 *    capabilityManifestHash, runtime, region).
 *  - An emitter that rejects does NOT fail the issuance (posture
 *    observability is never a control-plane gate).
 *  - The capabilityManifestHash matches the canonical-hash of the
 *    manifest, so the posture record correlates with audit evidence.
 */
import { CapabilityIssuerService, PostureEmitterLike } from '../src/issuer-service';
import {
  AgentCapabilityManifest,
  AgentInventoryRecord,
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  canonicalSha256,
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

class JoseSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  constructor() {
    super({ type: 'jose', name: 'jose', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async init(): Promise<void> {
    const { privateKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(this.privateKey);
  }
  async getPublicKey(): Promise<string> {
    return '';
  }
  async getKeyId(): Promise<string> {
    return 'kid-1';
  }
}

const logger = createLogger('issuer-posture-test', 'test');

async function makeService(
  postureEmitter?: PostureEmitterLike,
  postureRegion?: string,
): Promise<CapabilityIssuerService> {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new JoseSigner();
  await signer.init();
  const ctorOpts: ConstructorParameters<typeof CapabilityIssuerService>[5] = {};
  if (postureEmitter) ctorOpts.postureEmitter = postureEmitter;
  if (postureRegion) ctorOpts.postureRegion = postureRegion;
  return new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
    ctorOpts,
  );
}

class CollectingEmitter implements PostureEmitterLike {
  observed: AgentInventoryRecord[] = [];
  enabled = true;
  isEnabled(): boolean {
    return this.enabled;
  }
  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    this.observed.push(record);
  }
}

const MANIFEST: AgentCapabilityManifest = {
  agentId: 'agent-1',
  name: 'Sales agent',
  version: '1.2.3',
  requiredCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
  metadata: { owner: 'team-sales', runtime: 'python:3.12' },
};

// ---------------------------------------------------------------------------

describe('Issuer-service ↔ posture-emitter pipeline', () => {
  it('issues without invoking any emitter when none is configured (back-compat)', async () => {
    const service = await makeService();
    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: MANIFEST,
    });
    expect(resp.token).toBeTruthy();
  });

  it('emits an observation containing the parity-set fields after issuance', async () => {
    const emitter = new CollectingEmitter();
    const service = await makeService(emitter, 'eastus2');
    await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: MANIFEST,
    });
    // The enqueue is awaited inside issueCapability — no flush needed.
    expect(emitter.observed).toHaveLength(1);
    const r = emitter.observed[0]!;
    expect(r.schemaVersion).toBe('1.0');
    expect(r.agentId).toBe('agent-1');
    expect(r.owningTeam).toBe('team-sales');
    expect(r.runtime).toBe('python:3.12');
    expect(r.region).toBe('eastus2');
    expect(r.capabilityManifestHash).toBe(canonicalSha256(MANIFEST));
  });

  it('falls back to "unknown" when the manifest is absent', async () => {
    const emitter = new CollectingEmitter();
    const service = await makeService(emitter);
    await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-2',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
    });
    expect(emitter.observed).toHaveLength(1);
    expect(emitter.observed[0]!.owningTeam).toBe('unknown');
    expect(emitter.observed[0]!.runtime).toBe('unknown');
  });

  it('does not invoke the emitter when isEnabled() returns false', async () => {
    const emitter = new CollectingEmitter();
    emitter.enabled = false;
    const service = await makeService(emitter);
    await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: MANIFEST,
    });
    expect(emitter.observed).toHaveLength(0);
  });

  it('treats emitter failure as best-effort: issuance still succeeds', async () => {
    const failing: PostureEmitterLike = {
      isEnabled: () => true,
      emitObserved: () => Promise.reject(new Error('boom')),
    };
    const service = await makeService(failing);
    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: MANIFEST,
    });
    expect(resp.token).toBeTruthy();
    expect(resp.tokenId).toBeTruthy();
  });

  it('enqueue is synchronous with issueCapability — no tick needed before asserting', async () => {
    // Verify that the observation is present immediately when issueCapability
    // resolves, without any setImmediate/setTimeout/microtask flush.
    // This is the core guarantee of the transactional posture design: the
    // record is durable before the HTTP response leaves the process.
    let observedDuringIssue: AgentInventoryRecord[] = [];
    const capturingEmitter: PostureEmitterLike = {
      isEnabled: () => true,
      async emitObserved(record) {
        observedDuringIssue = [...observedDuringIssue, record];
      },
    };
    const service = await makeService(capturingEmitter);
    await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      manifest: MANIFEST,
    });
    // No await, no flush — the record must already be present.
    expect(observedDuringIssue).toHaveLength(1);
    expect(observedDuringIssue[0]!.agentId).toBe('agent-1');
  });
});

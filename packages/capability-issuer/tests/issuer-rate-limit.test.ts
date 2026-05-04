/**
 * Tests for the per-(tenant, user, agent) issuance rate limit
 * integration in {@link CapabilityIssuerService} (F-1, addresses I-1
 * in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 *
 * Verifies that:
 *   1. Issuance proceeds normally when no limiter is configured
 *      (back-compat with deployments that have not opted in yet).
 *   2. Once the limiter denies, `issueCapability` throws a
 *      `CapabilityError` with `RATE_LIMIT_EXCEEDED` (HTTP 429) AND
 *      the error is raised *before* any signing happens (a
 *      compromised account cannot exhaust the KMS budget).
 *   3. The deny-callback fires so the HTTP entrypoint can increment
 *      the Prometheus counter.
 *   4. Buckets are isolated per tenant (the F-7 prerequisite).
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  IssuanceRateLimitSubject,
  IssuanceRateLimiter,
  RateLimitDecision,
  SigningAdapter,
  SigningAdapterConfig,
  CapabilityTokenPayload,
  UserContext,
  ErrorCode,
  CapabilityError,
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
 * Counts every `sign()` call so the test can assert the rate-limit
 * deny path skips the signer entirely (no wasted KMS budget).
 */
class CountingSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  private publicKeyPem!: string;
  signCalls = 0;
  constructor() {
    super({ type: 'jose', name: 'jose', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async init(): Promise<void> {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.publicKeyPem = await jose.exportSPKI(publicKey);
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    this.signCalls += 1;
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

class RecordingLimiter implements IssuanceRateLimiter {
  calls: IssuanceRateLimitSubject[] = [];
  /** Programmable per-key allow-count; defaults to a single allow then deny. */
  allowCounts = new Map<string, number>();
  defaultAllowCount = 1;
  /** Satisfies the interface contract; tests do not exercise this. */
  readonly windowSeconds = 60;
  async consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> {
    this.calls.push(subject);
    const key = `${subject.tenantId ?? '_'}|${subject.userId}|${subject.agentId}`;
    const remaining = this.allowCounts.get(key) ?? this.defaultAllowCount;
    if (remaining <= 0) {
      return {
        allowed: false,
        limit: this.defaultAllowCount,
        remaining: 0,
        windowSeconds: 60,
        retryAfterSeconds: 7,
      };
    }
    this.allowCounts.set(key, remaining - 1);
    return {
      allowed: true,
      limit: this.defaultAllowCount,
      remaining: remaining - 1,
      windowSeconds: 60,
      retryAfterSeconds: 0,
    };
  }
}

const logger = createLogger('issuer-rate-limit-test', 'test');

async function makeService(opts: {
  limiter?: IssuanceRateLimiter;
  onDenied?: (s: IssuanceRateLimitSubject) => void;
  tenantId?: string;
  userId?: string;
}): Promise<{ service: CapabilityIssuerService; signer: CountingSigner }> {
  const identity = new StubIdentityProvider({
    userId: opts.userId ?? 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'],
    tenantId: opts.tenantId ?? 'tenant-1',
    claims: {},
  });
  const signer = new CountingSigner();
  await signer.init();
  const service = new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
    {
      issuanceRateLimiter: opts.limiter,
      onIssuanceRateLimited: opts.onDenied,
    },
  );
  return { service, signer };
}

const issueRequest = (agentId = 'agent-1') => ({
  authToken: 'stub-token',
  agentId,
  requestedCapabilities: [{ resource: 'api://example.com/x', actions: ['read'] }],
});

describe('CapabilityIssuerService — F-1 issuance rate limit', () => {
  it('issues normally when no limiter is configured (back-compat)', async () => {
    const { service, signer } = await makeService({});
    const r = await service.issueCapability(issueRequest());
    expect(r.token).toBeDefined();
    expect(signer.signCalls).toBe(1);
  });

  it('denies with RATE_LIMIT_EXCEEDED once the limiter says so, BEFORE signing', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 1; // one allow, then deny
    const denied: IssuanceRateLimitSubject[] = [];
    const { service, signer } = await makeService({
      limiter,
      onDenied: (s) => denied.push(s),
    });

    const first = await service.issueCapability(issueRequest());
    expect(first.token).toBeDefined();
    expect(signer.signCalls).toBe(1);

    await expect(service.issueCapability(issueRequest())).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      statusCode: 429,
    });
    // The signer MUST NOT have been invoked again — F-1 fires before
    // the signing step so a compromised account cannot exhaust KMS.
    expect(signer.signCalls).toBe(1);
    // The deny-callback fired exactly once with the resolved subject
    expect(denied).toHaveLength(1);
    expect(denied[0]).toEqual({
      tenantId: 'tenant-1',
      userId: 'user-1',
      agentId: 'agent-1',
    });
  });

  it('keys the bucket on (tenantId, userId, agentId) — the F-7 prerequisite', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 1;
    const t1 = await makeService({ limiter, tenantId: 'tenant-A', userId: 'u' });
    const t2 = await makeService({ limiter, tenantId: 'tenant-B', userId: 'u' });

    // tenant-A allowed once, then denied
    await t1.service.issueCapability(issueRequest());
    await expect(t1.service.issueCapability(issueRequest())).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
    });
    // tenant-B's bucket is independent — still one allow available
    const ok = await t2.service.issueCapability(issueRequest());
    expect(ok.token).toBeDefined();

    // The limiter saw both tenants distinctly
    const seenTenants = new Set(limiter.calls.map((c) => c.tenantId));
    expect(seenTenants).toEqual(new Set(['tenant-A', 'tenant-B']));
  });

  it('fails closed (deny with 429) when the limiter throws', async () => {
    const throwingLimiter: IssuanceRateLimiter = {
      windowSeconds: 60,
      consume: async () => {
        throw new Error('redis-down');
      },
    };
    const { service, signer } = await makeService({ limiter: throwingLimiter });
    await expect(service.issueCapability(issueRequest())).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      statusCode: 429,
    });
    expect(signer.signCalls).toBe(0);
  });

  it('fails-closed 429 carries Retry-After mirroring the limiter window', async () => {
    const throwingLimiter: IssuanceRateLimiter = {
      windowSeconds: 42,
      consume: async () => {
        throw new Error('redis-down');
      },
    };
    const { service } = await makeService({ limiter: throwingLimiter });
    try {
      await service.issueCapability(issueRequest());
      throw new Error('expected throw');
    } catch (err) {
      // Confirms the comment-vs-code drift fix: the Retry-After header
      // really does mirror the configured window length, not a hard-
      // coded constant.
      expect((err as CapabilityError).responseHeaders?.['Retry-After']).toBe('42');
    }
  });

  it('surfaces the limiter denial as a CapabilityError (not a generic Error)', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 0;
    const { service } = await makeService({ limiter });
    try {
      await service.issueCapability(issueRequest());
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CapabilityError);
      expect((err as CapabilityError).statusCode).toBe(429);
    }
  });

  it('attaches a Retry-After header so clients can back off correctly', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 0;
    const { service } = await makeService({ limiter });
    try {
      await service.issueCapability(issueRequest());
      throw new Error('expected throw');
    } catch (err) {
      const headers = (err as CapabilityError).responseHeaders;
      expect(headers).toBeDefined();
      // The recording limiter always reports retryAfterSeconds=7
      expect(headers?.['Retry-After']).toBe('7');
    }
  });

  it('also rate-limits attenuate — an attacker with one parent token can otherwise mint unlimited children', async () => {
    const limiter = new RecordingLimiter();
    // Allow exactly one mint; the issuance below burns it, so the
    // first attenuation must be denied.
    limiter.defaultAllowCount = 1;
    const { service, signer } = await makeService({ limiter });
    const issued = await service.issueCapability(issueRequest());
    expect(signer.signCalls).toBe(1);
    await expect(
      service.attenuateCapability(issued.token, [
        { resource: 'api://example.com/x', actions: ['read'] },
      ]),
    ).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      statusCode: 429,
    });
    // Signer was NOT called for the denied attenuation — F-1 fires
    // before the signing pipeline.
    expect(signer.signCalls).toBe(1);
  });

  it('also rate-limits renew — an attacker can otherwise extend a token lineage indefinitely', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 1; // one allow, used by the initial issuance
    const { service, signer } = await makeService({ limiter });
    const issued = await service.issueCapability(issueRequest());
    expect(signer.signCalls).toBe(1);
    await expect(service.renewCapability(issued.token)).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      statusCode: 429,
    });
    expect(signer.signCalls).toBe(1);
  });

  it('shares the bucket across issue / attenuate / renew (same subject)', async () => {
    const limiter = new RecordingLimiter();
    limiter.defaultAllowCount = 2; // two mints total across all paths
    const { service } = await makeService({ limiter });
    const issued = await service.issueCapability(issueRequest()); // burns 1
    const attenuated = await service.attenuateCapability(issued.token, [
      { resource: 'api://example.com/x', actions: ['read'] },
    ]); // burns the 2nd
    await expect(service.renewCapability(attenuated.token)).rejects.toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
    });
    // The limiter saw three consume() calls — one per mint method —
    // all keyed on the same (tenantId, userId, agentId).
    expect(limiter.calls).toHaveLength(3);
    const subjects = new Set(
      limiter.calls.map((c) => `${c.tenantId}|${c.userId}|${c.agentId}`),
    );
    expect(subjects.size).toBe(1);
  });
});

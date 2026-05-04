/**
 * F-2 (DPoP / sender-constrained capability tokens) — issuer-side
 * integration tests.
 *
 * Verifies the full path through the orchestrator:
 *   1. Tokens issued without a DPoP hint are plain bearer tokens
 *      (no `cnf` claim — back-compat).
 *   2. Tokens issued with `dpopJkt` carry `cnf.jkt` matching exactly.
 *   3. Tokens issued with `dpopJwk` (raw public key) get the same
 *      thumbprint stamped, computed by the issuer.
 *   4. A malformed `dpopJwk` produces a clean INVALID_REQUEST 400, not
 *      a silently-bound-as-bearer success.
 *   5. Attenuation and renewal preserve `cnf.jkt` so the binding
 *      cannot be dropped by a subsequent issuance step.
 */

import { CapabilityIssuerService } from '../src/issuer-service';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  CapabilityTokenPayload,
  CapabilityError,
  ErrorCode,
  UserContext,
  computeJwkThumbprint,
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

const logger = createLogger('issuer-dpop-test', 'test');

async function makeService(): Promise<{ service: CapabilityIssuerService; signer: JoseSigner }> {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'],
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
  return jose.decodeJwt(token) as unknown as CapabilityTokenPayload;
}

async function generateDpopFixture(): Promise<{ jwk: jose.JWK; jkt: string }> {
  const { publicKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(publicKey);
  const jkt = await computeJwkThumbprint(jwk);
  return { jwk, jkt };
}

const baseRequest = () => ({
  authToken: 'stub-token',
  agentId: 'agent-1',
  requestedCapabilities: [{ resource: 'api://example.com/x', actions: ['read'] }],
});

describe('CapabilityIssuerService — F-2 DPoP binding', () => {
  it('does NOT add a cnf claim for plain (non-DPoP) issuance (back-compat)', async () => {
    const { service } = await makeService();
    const r = await service.issueCapability(baseRequest());
    const payload = await decode(r.token);
    expect(payload.cnf).toBeUndefined();
  });

  it('stamps cnf.jkt from an explicit dpopJkt thumbprint', async () => {
    const { service } = await makeService();
    const fixture = await generateDpopFixture();
    const r = await service.issueCapability({ ...baseRequest(), dpopJkt: fixture.jkt });
    const payload = await decode(r.token);
    expect(payload.cnf?.jkt).toBe(fixture.jkt);
  });

  it('computes the thumbprint when only dpopJwk is supplied', async () => {
    const { service } = await makeService();
    const fixture = await generateDpopFixture();
    const r = await service.issueCapability({
      ...baseRequest(),
      dpopJwk: fixture.jwk as unknown as Record<string, unknown>,
    });
    const payload = await decode(r.token);
    expect(payload.cnf?.jkt).toBe(fixture.jkt);
  });

  it('prefers dpopJkt over dpopJwk when both are supplied', async () => {
    const { service } = await makeService();
    const a = await generateDpopFixture();
    const b = await generateDpopFixture();
    const r = await service.issueCapability({
      ...baseRequest(),
      dpopJkt: a.jkt,
      dpopJwk: b.jwk as unknown as Record<string, unknown>,
    });
    const payload = await decode(r.token);
    expect(payload.cnf?.jkt).toBe(a.jkt);
  });

  it('rejects a malformed dpopJwk with INVALID_REQUEST (not silently bearer)', async () => {
    const { service } = await makeService();
    let err: unknown;
    try {
      await service.issueCapability({
        ...baseRequest(),
        dpopJwk: { not: 'a valid jwk' },
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(CapabilityError);
    expect((err as CapabilityError).code).toBe(ErrorCode.INVALID_REQUEST);
  });

  it('rejects a non-thumbprint-shaped dpopJkt with INVALID_REQUEST (PR review #5)', async () => {
    // RFC 7638 SHA-256 thumbprints are exactly 43 unpadded base64url
    // characters. A wrong-length / wrong-alphabet value can never match
    // a verifier's recomputed thumbprint, so the issuer must refuse it
    // up front rather than mint a token the gateway is guaranteed to
    // reject on first use.
    const { service } = await makeService();
    const bad = ['', 'too-short', 'X'.repeat(42), 'X'.repeat(44), 'has spaces in it not allowed!!!!!!!!!!!!!!!'];
    for (const dpopJkt of bad) {
      let err: unknown;
      try {
        await service.issueCapability({ ...baseRequest(), dpopJkt });
      } catch (e) {
        err = e;
      }
      // Empty string falls through to the "no DPoP" branch (back-compat:
      // a plain bearer is fine when no binding was requested at all),
      // so we only assert a CapabilityError for non-empty bogus values.
      if (dpopJkt === '') continue;
      expect(err).toBeInstanceOf(CapabilityError);
      expect((err as CapabilityError).code).toBe(ErrorCode.INVALID_REQUEST);
    }
  });

  it('accepts a well-formed RFC 7638 thumbprint (43 base64url chars)', async () => {
    const { service } = await makeService();
    const fixture = await generateDpopFixture();
    expect(fixture.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const issued = await service.issueCapability({
      ...baseRequest(),
      dpopJkt: fixture.jkt,
    });
    const payload = await decode(issued.token);
    expect(payload.cnf?.jkt).toBe(fixture.jkt);
  });

  it('preserves cnf across attenuation', async () => {
    const { service } = await makeService();
    const fixture = await generateDpopFixture();
    const issued = await service.issueCapability({
      ...baseRequest(),
      dpopJkt: fixture.jkt,
    });
    const child = await service.attenuateCapability(issued.token, [
      { resource: 'api://example.com/x', actions: ['read'] },
    ]);
    const payload = await decode(child.token);
    expect(payload.cnf?.jkt).toBe(fixture.jkt);
  });

  it('preserves cnf across renewal', async () => {
    const { service } = await makeService();
    const fixture = await generateDpopFixture();
    const issued = await service.issueCapability({
      ...baseRequest(),
      dpopJkt: fixture.jkt,
    });
    const renewed = await service.renewCapability(issued.token);
    const payload = await decode(renewed.token);
    expect(payload.cnf?.jkt).toBe(fixture.jkt);
  });
});

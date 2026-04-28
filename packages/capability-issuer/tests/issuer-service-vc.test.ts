/**
 * Tests for the W3C Verifiable Credential envelope embedded in
 * capability tokens.
 *
 * `docs/execution-plan.md` Sprint 4 (Team CP, "Verifiable Credential
 * Issuance") requires capability tokens to carry a W3C VC envelope so
 * verifiers built on standard VC libraries can consume them without
 * proprietary code.  The envelope MUST mirror the JWT claim set
 * exactly — any drift between the JWT view and the VC view of the
 * same token would let the two views authorize different things.
 *
 * These tests assert:
 *   1. Newly issued tokens carry a well-formed `vc` object with the
 *      W3C base context, a `CapabilityCredential` type, and a
 *      `credentialSubject` whose `id` matches the JWT `sub`.
 *   2. Attenuated tokens carry the *narrowed* capability set in the
 *      VC view, plus a `parentCapabilityId` so the delegation chain is
 *      visible to a VC-only verifier.
 *   3. Renewed tokens carry a fresh `id` (urn:uuid:<jti>) and link to
 *      the previous token via `parentCapabilityId`.
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
import * as jose from 'jose';
import * as crypto from 'crypto';

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

/**
 * Real RSA-backed signer that captures the *last payload it was asked
 * to sign* so the test can inspect the VC envelope that was attached
 * to the payload before signing.  We use a real key pair (rather than
 * a no-op stub) because the attenuate/renew code paths verify the
 * input token cryptographically — a no-op signer would fail jwtVerify
 * before our VC-population code even runs.
 */
class CapturingRSASigner extends SigningAdapter {
  public lastPayload: CapabilityTokenPayload | undefined;
  private readonly privateKeyPem: string;
  private readonly publicKeyPem: string;
  private privateKeyObj: jose.KeyLike | undefined;

  constructor() {
    super({ type: 'stub-rsa', name: 'stub-rsa', algorithm: 'RS256' } as SigningAdapterConfig);
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    this.privateKeyPem = privateKey;
    this.publicKeyPem = publicKey;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    this.lastPayload = payload;
    if (!this.privateKeyObj) {
      this.privateKeyObj = await jose.importPKCS8(this.privateKeyPem, 'RS256');
    }
    // Pass the full payload object as additional claims; we deliberately
    // do NOT call `.setIssuer()` / `.setAudience()` / `.setIssuedAt()`
    // / `.setExpirationTime()` because the issuer service has already
    // populated `iss` / `aud` / `iat` / `exp` on the payload itself.
    // Letting jose.SignJWT also set them would either overwrite our
    // values with `now` or duplicate them.
    const jwt = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: 'RS256', kid: 'stub-key-id' })
      .sign(this.privateKeyObj);
    return jwt;
  }

  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return 'stub-key-id';
  }
}

const logger = createLogger('issuer-vc-test', 'test');

function makeService(): { service: CapabilityIssuerService; signer: CapturingRSASigner } {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new CapturingRSASigner();
  const service = new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
  );
  return { service, signer };
}

describe('CapabilityIssuerService W3C Verifiable Credential envelope', () => {
  describe('on issueCapability', () => {
    it('attaches a well-formed VC envelope to the issued token payload', async () => {
      const { service, signer } = makeService();

      await service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-vc-1',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read'] },
        ],
      });

      const payload = signer.lastPayload!;
      expect(payload.vc).toBeDefined();

      const vc = payload.vc!;

      // W3C VC Data Model § 5.2: the `@context` array MUST include the
      // base credentials context as its first element.
      expect(Array.isArray(vc['@context'])).toBe(true);
      expect(vc['@context'][0]).toBe('https://www.w3.org/2018/credentials/v1');

      // W3C VC Data Model § 5.3: every VC MUST have type
      // `VerifiableCredential`, plus our app-specific subtype so
      // verifiers can route on it.
      expect(vc.type).toContain('VerifiableCredential');
      expect(vc.type).toContain('CapabilityCredential');

      // The VC view of the credential subject MUST mirror the JWT
      // `sub` so the two views authorize the same subject.  Drift here
      // would let a VC-only verifier accept a token meant for a
      // different agent.
      expect(vc.credentialSubject.id).toBe('agent-vc-1');
      expect(vc.credentialSubject.id).toBe(payload.sub);

      // The capabilities claim MUST appear in `credentialSubject` so a
      // VC-only verifier sees the same authorization scope as a
      // JWT-only verifier.
      expect(vc.credentialSubject.capabilities).toEqual(payload.capabilities);

      // `authorizedBy` (user identity that authorized issuance) MUST
      // round-trip into the VC view for audit reasons.
      expect(vc.credentialSubject.authorizedBy).toEqual(payload.authorizedBy);

      // W3C VC Data Model § 4.2: a VC's `id` MUST be a single URI.  We
      // mint it as `urn:uuid:<jti>` so a VC-only verifier sees the
      // same authoritative credential id as a JWT-only verifier
      // reading `jti`.  Pinning this here means accidentally dropping
      // the prefix or the field in `buildVerifiableCredential` fails
      // CI rather than silently breaking interop with VC libraries.
      expect(vc.id).toBe(`urn:uuid:${payload.jti}`);

      // A freshly *issued* token has no parent, so the VC view MUST
      // NOT carry a `parentCapabilityId` (otherwise a verifier might
      // misinterpret the token as an attenuation).
      expect(vc.credentialSubject.parentCapabilityId).toBeUndefined();
    });
  });

  describe('on attenuateCapability', () => {
    it('the VC envelope on the child token carries the narrowed capabilities and links to the parent', async () => {
      const { service, signer } = makeService();

      // First, issue a parent token with multiple actions on the
      // resource so we have something to narrow.
      const parent = await service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-vc-2',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read', 'write'] },
        ],
        consent: {
          userId: 'user-1',
          agentId: 'agent-vc-2',
          grantedCapabilities: [
            { resource: 'api://**', actions: ['read', 'write'] },
          ],
          grantedAt: Math.floor(Date.now() / 1000),
        },
      });

      // Now attenuate to read-only.
      const child = await service.attenuateCapability(parent.token, [
        { resource: 'api://crm/customers', actions: ['read'] },
      ]);

      const childPayload = signer.lastPayload!;
      expect(childPayload.jti).toBe(child.tokenId);

      const vc = childPayload.vc!;
      expect(vc).toBeDefined();

      // Critical invariant: the VC view MUST reflect the *narrowed*
      // capability set, not the parent's broader set.  A VC-only
      // verifier checking only the credentialSubject must see the
      // attenuated scope.
      expect(vc.credentialSubject.capabilities).toEqual([
        { resource: 'api://crm/customers', actions: ['read'] },
      ]);

      // The delegation chain must be visible in the VC view as well
      // as the JWT view, so cross-org verifiers can audit it.
      expect(vc.credentialSubject.parentCapabilityId).toBe(parent.tokenId);
      expect(vc.credentialSubject.id).toBe('agent-vc-2');

      // The child VC's own `id` must reference the *child* jti, not
      // the parent's, so revocation / referencing of the child
      // credential is unambiguous.
      expect(vc.id).toBe(`urn:uuid:${childPayload.jti}`);
    });
  });

  describe('on renewCapability', () => {
    it('the VC envelope on the renewed token references the new jti and links to the previous token', async () => {
      const { service, signer } = makeService();

      const original = await service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-vc-3',
        requestedCapabilities: [
          { resource: 'api://crm/customers', actions: ['read'] },
        ],
      });

      const renewed = await service.renewCapability(original.token);

      const renewedPayload = signer.lastPayload!;
      const vc = renewedPayload.vc!;
      expect(vc).toBeDefined();

      // Renewed-token invariant: the VC's parentCapabilityId points at
      // the *previous* token's jti so the audit chain is preserved
      // across renewals.
      expect(vc.credentialSubject.parentCapabilityId).toBe(original.tokenId);

      // And the credentialSubject must reflect the renewed token's
      // own claims, not the original's.
      expect(renewedPayload.jti).toBe(renewed.tokenId);
      expect(vc.credentialSubject.id).toBe('agent-vc-3');
      expect(vc.credentialSubject.capabilities).toEqual(original.capabilities);

      // The renewed VC carries a *fresh* identifier — `urn:uuid:<new
      // jti>` — distinct from the previous token's id.  This is the
      // invariant called out in the test-file header comment; pinning
      // it here means a regression that reuses the previous jti or
      // drops the urn prefix fails CI.
      expect(vc.id).toBe(`urn:uuid:${renewedPayload.jti}`);
      expect(vc.id).not.toBe(`urn:uuid:${original.tokenId}`);
    });
  });
});

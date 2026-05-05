/**
 * Integration test — issuance proofs (cosignature + transparency log).
 *
 * Verifies the full end-to-end loop for the multi-issuer trust hardening:
 *
 *   1. Capability-issuer is configured with two cosigners and a
 *      transparency log; minted tokens carry `proofs.cosig[]` and
 *      `proofs.sct[]`.
 *
 *   2. Gateway is configured with the matching cosigner JWKS + log JWKS
 *      and `REQUIRE_COSIGNATURE_COUNT=2` + `REQUIRE_TRANSPARENCY_LOG_PROOF=true`.
 *      The gateway verifier accepts the token.
 *
 *   3. Strict-mode rejection: a plain (no-proofs) token from the same
 *      issuer is rejected by the strict gateway.
 *
 *   4. Forged-cosignature rejection: a token with `proofs.cosig[].sig`
 *      tampered is rejected.
 *
 *   5. Back-compat: with both REQUIRE_* set to off (default), the same
 *      strict-issued token is accepted, and a plain unsigned-proofs
 *      token is also accepted.
 *
 *   6. Forge defence: an attacker who controls *only* the primary signer
 *      (the residual blast radius after compromise of the issuer pod's
 *      KMS permission) cannot mint a token the strict gateway accepts —
 *      they have no way to produce valid cosignatures or SCTs.
 */

import * as jose from 'jose';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import {
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  CapabilityTokenPayload,
  IdentityAdapter,
  IdentityAdapterConfig,
  InMemoryTransparencyLog,
  JwkSet,
  SigningAdapter,
  SigningAdapterConfig,
  SoftwareCosigner,
  UserContext,
  buildIssuanceReceipt,
  capabilitiesHash,
  createAuditLogger,
  generateId,
} from '@euno/common';
import {
  JWTTokenVerifier,
} from '../../tool-gateway/src/verifier';
import { ProofsVerifier } from '../../tool-gateway/src/proofs-verifier';

const ISSUER_DID = 'did:web:euno.test';
const AUDIENCE = 'tool-gateway';
const SIGNING_ALG = 'EdDSA';

// ── Helpers ────────────────────────────────────────────────────────────────

class StaticIdentityProvider extends IdentityAdapter {
  public readonly name = 'static';
  constructor() {
    super({ type: 'static', name: 'static' } as IdentityAdapterConfig);
  }
  async validateToken(_authToken: string): Promise<UserContext> {
    return {
      userId: 'user-1',
      tenantId: 't-1',
      roles: ['Administrator'],
      email: 'u@example.com',
      claims: {},
    };
  }
  async getUserRoles(): Promise<string[]> {
    return ['Administrator'];
  }
}

class JoseSigner extends SigningAdapter {
  private readonly kid = 'issuer-primary-1';
  constructor(
    private readonly privateKey: jose.KeyLike,
    private readonly publicSpki: string,
  ) {
    super({ type: 'jose-eddsa', name: 'jose-eddsa', algorithm: SIGNING_ALG } as SigningAdapterConfig);
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: SIGNING_ALG, kid: this.kid })
      .sign(this.privateKey);
  }
  async getPublicKey(): Promise<string> {
    return this.publicSpki;
  }
  async getKeyId(): Promise<string> {
    return this.kid;
  }
}

async function makePrimarySigner(): Promise<JoseSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const publicSpki = await jose.exportSPKI(publicKey);
  return new JoseSigner(privateKey, publicSpki);
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe('Issuance proofs — cosignature + transparency log (multi-issuer trust)', () => {
  let issuerService: CapabilityIssuerService;
  let signer: JoseSigner;
  let cosignerA: SoftwareCosigner;
  let cosignerB: SoftwareCosigner;
  let transparencyLog: InMemoryTransparencyLog;
  let cosignerJwks: JwkSet;
  let logJwksByLogId: Map<string, JwkSet>;

  beforeEach(async () => {
    signer = await makePrimarySigner();
    cosignerA = await SoftwareCosigner.generateEd25519('cosig-A');
    cosignerB = await SoftwareCosigner.generateEd25519('cosig-B');
    transparencyLog = await InMemoryTransparencyLog.generateEd25519({
      logId: 'tlog-prod-1',
      kid: 'tlog-key-1',
    });

    cosignerJwks = {
      keys: [await cosignerA.getPublicJwk(), await cosignerB.getPublicJwk()],
    };
    logJwksByLogId = new Map([['tlog-prod-1', await transparencyLog.getPublicJwks()]]);

    issuerService = new CapabilityIssuerService(
      signer,
      new StaticIdentityProvider(),
      ISSUER_DID,
      900,
      createAuditLogger('test-issuer'),
      {
        cosigners: [cosignerA, cosignerB],
        transparencyLogs: [transparencyLog],
        gatewayAudience: AUDIENCE,
      },
    );
  });

  it('issued token carries cosig[2] + sct[1] and is accepted by the strict gateway verifier', async () => {
    const response = await issuerService.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });

    // ── Inspect the proofs carried by the minted token ───────────────
    const decoded = jose.decodeJwt(response.token) as unknown as CapabilityTokenPayload;
    expect(decoded.proofs).toBeDefined();
    expect(decoded.proofs?.cosig).toHaveLength(2);
    expect(decoded.proofs?.cosig?.map((c) => c.kid).sort()).toEqual(['cosig-A', 'cosig-B']);
    expect(decoded.proofs?.sct).toHaveLength(1);
    expect(decoded.proofs?.sct?.[0]?.logId).toBe('tlog-prod-1');

    // ── Verify under a strict gateway ────────────────────────────────
    const proofsVerifier = new ProofsVerifier({
      requireCosignatureCount: 2,
      requireTransparencyLogProof: true,
      cosignerJwks,
      logJwksByLogId,
    });
    const verifier = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      proofsVerifier,
    );
    const verified = await verifier.verify(response.token);
    expect(verified.sub).toBe('agent-1');
    expect(verified.proofs?.cosig).toHaveLength(2);

    // The transparency log recorded exactly one entry for this issuance.
    const entries = transparencyLog.getEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.receipt.jti).toBe(decoded.jti);
    // And the receipt the log signed matches the canonical receipt
    // derived from the public token claims — auditors can recompute it.
    expect(entries[0]?.receipt.capabilitiesHash).toBe(
      capabilitiesHash(decoded.capabilities),
    );
  });

  it('strict gateway REJECTS a token from the same issuer that lacks proofs', async () => {
    // Build an "issuer without proofs" by re-using the same signer but
    // no cosigners / no log.
    const proofless = new CapabilityIssuerService(
      signer,
      new StaticIdentityProvider(),
      ISSUER_DID,
      900,
      createAuditLogger('test-issuer-proofless'),
      { gatewayAudience: AUDIENCE },
    );
    const response = await proofless.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-2',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });
    const decoded = jose.decodeJwt(response.token) as unknown as CapabilityTokenPayload;
    expect(decoded.proofs).toBeUndefined();

    const strict = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      new ProofsVerifier({
        requireCosignatureCount: 2,
        requireTransparencyLogProof: true,
        cosignerJwks,
        logJwksByLogId,
      }),
    );
    await expect(strict.verify(response.token)).rejects.toThrow(
      /at least 2 valid cosignature/,
    );
  });

  it('strict gateway REJECTS a token whose cosignature has been tampered with', async () => {
    const response = await issuerService.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-3',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });
    const decoded = jose.decodeJwt(response.token) as unknown as CapabilityTokenPayload;

    // Tamper: flip a bit in the first cosignature, then re-mint the
    // token (same primary signer key) so the JWS signature stays valid
    // but the cosignature inside the payload no longer verifies. This
    // simulates the residual attacker — they own the primary KMS key
    // but not the cosigner key.
    const tampered: CapabilityTokenPayload = JSON.parse(JSON.stringify(decoded));
    const sig = tampered.proofs!.cosig![0]!.sig;
    // Swap the first character to something else in the base64url alphabet
    tampered.proofs!.cosig![0]!.sig = (sig.startsWith('A') ? 'B' : 'A') + sig.slice(1);
    const reForged = await signer.sign(tampered);

    const strict = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      new ProofsVerifier({
        requireCosignatureCount: 2,
        requireTransparencyLogProof: true,
        cosignerJwks,
        logJwksByLogId,
      }),
    );
    await expect(strict.verify(reForged)).rejects.toThrow(
      /at least 2 valid cosignature/,
    );
  });

  it('FORGE DEFENCE: attacker who owns only the primary signer cannot mint a strict-acceptable token', async () => {
    // Simulate the post-compromise scenario described in the problem
    // statement: attacker has full KMS signDigest access but zero
    // visibility into either cosigner key or the transparency log.
    const forgedPayload: CapabilityTokenPayload = {
      iss: ISSUER_DID,
      sub: 'attacker-controlled-agent',
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: generateId(),
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'api://crown-jewels', actions: ['*'] }],
    };

    // Even if the attacker fabricates `proofs` claims with random
    // signatures, none of them verify against the trusted JWKS.
    forgedPayload.proofs = {
      cosig: [
        { kid: 'cosig-A', alg: 'EdDSA', sig: 'A'.repeat(86) },
        { kid: 'cosig-B', alg: 'EdDSA', sig: 'A'.repeat(86) },
      ],
      sct: [
        {
          logId: 'tlog-prod-1',
          kid: 'tlog-key-1',
          alg: 'EdDSA',
          timestamp: Date.now(),
          sig: 'A'.repeat(86),
        },
      ],
    };
    const forged = await signer.sign(forgedPayload);

    const strict = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      new ProofsVerifier({
        requireCosignatureCount: 2,
        requireTransparencyLogProof: true,
        cosignerJwks,
        logJwksByLogId,
      }),
    );
    await expect(strict.verify(forged)).rejects.toThrow(
      /at least 2 valid cosignature|transparency-log inclusion proof/,
    );

    // Belt and braces: the transparency log has no record of this jti —
    // an auditor reconciling the log would also flag the absence.
    expect(transparencyLog.getEntries().some((e) => e.receipt.jti === forgedPayload.jti)).toBe(false);
  });

  it('back-compat: gateway with no proofs requirement accepts both proofed and non-proofed tokens', async () => {
    const verifier = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      // No proofs verifier configured → behaves exactly as before this feature.
    );

    const proofed = await issuerService.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-4',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });
    await expect(verifier.verify(proofed.token)).resolves.toBeDefined();

    const proofless = new CapabilityIssuerService(
      signer,
      new StaticIdentityProvider(),
      ISSUER_DID,
      900,
      createAuditLogger('test-issuer-bcompat'),
      { gatewayAudience: AUDIENCE },
    );
    const plain = await proofless.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-5',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });
    await expect(verifier.verify(plain.token)).resolves.toBeDefined();
  });

  it('attenuation + renewal also attach proofs', async () => {
    // Need to verify the parent token using the same audience.
    const parent = await issuerService.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-6',
    });

    const attenuated = await issuerService.attenuateCapability(parent.token, [
      { resource: 'api://svc', actions: ['read'] },
    ]);
    const decodedAtt = jose.decodeJwt(attenuated.token) as unknown as CapabilityTokenPayload;
    expect(decodedAtt.proofs?.cosig).toHaveLength(2);
    expect(decodedAtt.proofs?.sct).toHaveLength(1);

    const renewed = await issuerService.renewCapability(parent.token);
    const decodedRen = jose.decodeJwt(renewed.token) as unknown as CapabilityTokenPayload;
    expect(decodedRen.proofs?.cosig).toHaveLength(2);
    expect(decodedRen.proofs?.sct).toHaveLength(1);

    // Verify the attenuated token under strict gateway
    const strict = new JWTTokenVerifier(
      await signer.getPublicKey(),
      ['EdDSA'],
      undefined,
      undefined,
      undefined,
      undefined,
      false,
      new ProofsVerifier({
        requireCosignatureCount: 2,
        requireTransparencyLogProof: true,
        cosignerJwks,
        logJwksByLogId,
      }),
    );
    await expect(strict.verify(attenuated.token)).resolves.toBeDefined();
    await expect(strict.verify(renewed.token)).resolves.toBeDefined();

    // The transparency log now has 3 entries: parent + attenuated + renewed.
    expect(transparencyLog.getEntries()).toHaveLength(3);
  });

  it('canonical receipt derivation matches between issuer and gateway', async () => {
    // Belt-and-braces: the gateway re-derives the receipt from the
    // public claims; the issuer derives it from the same claims before
    // signing. They MUST agree byte-for-byte, otherwise neither
    // cosignatures nor SCTs would ever verify.
    const response = await issuerService.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-7',
      requestedCapabilities: [{ resource: 'api://svc', actions: ['read'] }],
    });
    const decoded = jose.decodeJwt(response.token) as unknown as CapabilityTokenPayload;
    const gatewayReceipt = buildIssuanceReceipt({
      iss: decoded.iss,
      sub: decoded.sub,
      aud: decoded.aud,
      iat: decoded.iat,
      exp: decoded.exp,
      jti: decoded.jti,
      capabilities: decoded.capabilities,
    });
    const logEntry = transparencyLog.getEntries().find((e) => e.receipt.jti === decoded.jti);
    expect(logEntry?.receipt).toEqual(gatewayReceipt);
  });
});

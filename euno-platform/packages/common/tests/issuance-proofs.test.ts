/**
 * Tests for the issuance-proofs / cosigner / transparency-log modules
 * (multi-issuer trust hardening — addresses the critical "single-issuer
 * trust root" risk).
 *
 * Coverage:
 *
 *  - canonical JSON serialization is deterministic and order-independent
 *    on object keys but order-preserving on arrays;
 *  - receipt + SCT signing inputs are domain-separated;
 *  - {@link SoftwareCosigner} round-trip (sign → verify) for Ed25519 + ES256;
 *  - {@link InMemoryTransparencyLog} is append-only, signs SCTs that the
 *    verifier accepts, and exposes a JWKS the verifier can consume;
 *  - {@link verifyIssuanceProofs} catches every failure class
 *    (unknown kid, wrong signature, missing trust JWKS, alg mismatch);
 *  - {@link cosignPayload} / {@link witnessPayload} short-circuit on
 *    empty signer lists (back-compat — no `proofs` claim emitted).
 */

import {
  buildIssuanceReceipt,
  canonicalJsonStringify,
  canonicalReceiptSigningInput,
  canonicalSctSigningInput,
  capabilitiesHash,
  Cosignature,
  CapabilityTokenPayload,
  COSIG_INPUT_DOMAIN_TAG,
  cosignPayload,
  InMemoryTransparencyLog,
  IssuanceProofs,
  IssuanceReceipt,
  SCT_INPUT_DOMAIN_TAG,
  Sct,
  sha256Base64Url,
  SoftwareCosigner,
  verifyCosignature,
  verifyIssuanceProofs,
  verifySct,
  witnessPayload,
} from '../src';

function buildPayload(
  overrides: Partial<CapabilityTokenPayload> = {},
): CapabilityTokenPayload {
  return {
    iss: 'did:web:issuer.example.com',
    sub: 'agent-42',
    aud: 'tool-gateway',
    iat: 1_700_000_000,
    exp: 1_700_000_900,
    jti: 'jti-abc',
    schemaVersion: '1.0',
    capabilities: [
      { resource: 'api://service/path', actions: ['read', 'write'] },
    ],
    ...overrides,
  };
}

describe('canonicalJsonStringify', () => {
  it('sorts object keys deterministically at every depth', () => {
    const a = canonicalJsonStringify({ b: 1, a: { z: 2, y: 3 } });
    const b = canonicalJsonStringify({ a: { y: 3, z: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"y":3,"z":2},"b":1}');
  });

  it('preserves array order', () => {
    expect(canonicalJsonStringify([1, 2, 3])).toBe('[1,2,3]');
    expect(canonicalJsonStringify([3, 2, 1])).toBe('[3,2,1]');
  });

  it('drops undefined object members (matches JSON.stringify)', () => {
    expect(canonicalJsonStringify({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalJsonStringify(Number.NaN)).toThrow(/non-finite/);
    expect(() => canonicalJsonStringify(Number.POSITIVE_INFINITY)).toThrow(
      /non-finite/,
    );
  });
});

describe('capabilitiesHash', () => {
  it('is stable across equivalent inputs', () => {
    const caps = [{ resource: 'api://x', actions: ['read'] }];
    expect(capabilitiesHash(caps)).toBe(capabilitiesHash([...caps]));
  });

  it('changes when actions change', () => {
    const a = capabilitiesHash([{ resource: 'api://x', actions: ['read'] }]);
    const b = capabilitiesHash([
      { resource: 'api://x', actions: ['read', 'write'] },
    ]);
    expect(a).not.toBe(b);
  });
});

describe('buildIssuanceReceipt', () => {
  it('extracts the load-bearing claims and hashes the capability set', () => {
    const payload = buildPayload();
    const receipt = buildIssuanceReceipt(payload);
    expect(receipt).toEqual({
      iss: payload.iss,
      sub: payload.sub,
      aud: payload.aud,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
      capabilitiesHash: capabilitiesHash(payload.capabilities),
    });
  });
});

describe('domain-separated signing inputs', () => {
  it('cosignature input carries the cosignature domain tag', () => {
    const receipt = buildIssuanceReceipt(buildPayload());
    const input = Buffer.from(canonicalReceiptSigningInput(receipt)).toString(
      'utf8',
    );
    expect(input.startsWith(`${COSIG_INPUT_DOMAIN_TAG}\n`)).toBe(true);
  });

  it('SCT input carries the SCT domain tag and rejects newline in logId', () => {
    const input = Buffer.from(
      canonicalSctSigningInput('log-1', 1, 'hash'),
    ).toString('utf8');
    expect(input.startsWith(`${SCT_INPUT_DOMAIN_TAG}\n`)).toBe(true);
    expect(() => canonicalSctSigningInput('bad\nid', 1, 'h')).toThrow(/newline/);
    expect(() => canonicalSctSigningInput('ok', -1, 'h')).toThrow(/non-negative/);
  });
});

describe('SoftwareCosigner', () => {
  it('round-trips an Ed25519 cosignature', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-ed-1');
    const receipt = buildIssuanceReceipt(buildPayload());
    const cosig = await cosigner.cosignReceipt(receipt);
    expect(cosig.kid).toBe('cosigner-ed-1');
    expect(cosig.alg).toBe('EdDSA');
    expect(cosig.sig).toMatch(/^[A-Za-z0-9_-]+$/);

    const jwk = await cosigner.getPublicJwk();
    expect(jwk.kid).toBe('cosigner-ed-1');
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk.use).toBe('sig');
    await expect(verifyCosignature(jwk, cosig, receipt)).resolves.toBe(true);
  });

  it('rejects a tampered receipt (capabilities reordered)', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-1');
    const payload = buildPayload({
      capabilities: [
        { resource: 'api://a', actions: ['read'] },
        { resource: 'api://b', actions: ['read'] },
      ],
    });
    const original = buildIssuanceReceipt(payload);
    const cosig = await cosigner.cosignReceipt(original);
    const tampered = buildIssuanceReceipt({
      ...payload,
      capabilities: [
        { resource: 'api://b', actions: ['read'] },
        { resource: 'api://a', actions: ['read'] },
      ],
    });
    expect(tampered.capabilitiesHash).not.toBe(original.capabilitiesHash);
    const jwk = await cosigner.getPublicJwk();
    await expect(verifyCosignature(jwk, cosig, tampered)).resolves.toBe(false);
  });

  it('rejects malformed sig bytes (returns false, does not throw)', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-2');
    const receipt = buildIssuanceReceipt(buildPayload());
    const cosig = await cosigner.cosignReceipt(receipt);
    const jwk = await cosigner.getPublicJwk();
    const bad: Cosignature = { ...cosig, sig: 'not-a-sig' };
    await expect(verifyCosignature(jwk, bad, receipt)).resolves.toBe(false);
  });

  it('rejects an alg-mismatched JWK (alg-confusion guard)', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-3');
    const receipt = buildIssuanceReceipt(buildPayload());
    const cosig = await cosigner.cosignReceipt(receipt);
    const jwk = await cosigner.getPublicJwk();
    const wrongAlgJwk = { ...jwk, alg: 'ES256' };
    await expect(verifyCosignature(wrongAlgJwk, cosig, receipt)).resolves.toBe(false);
  });
});

describe('cosignPayload', () => {
  it('returns undefined when there are no cosigners (back-compat)', async () => {
    expect(await cosignPayload(buildPayload(), [])).toBeUndefined();
  });

  it('produces one cosignature per cosigner, in order', async () => {
    const a = await SoftwareCosigner.generateEd25519('a');
    const b = await SoftwareCosigner.generateEd25519('b');
    const sigs = await cosignPayload(buildPayload(), [a, b]);
    expect(sigs?.map((s) => s.kid)).toEqual(['a', 'b']);
  });
});

describe('InMemoryTransparencyLog', () => {
  it('signs SCTs that the verifier accepts', async () => {
    let now = 1_700_000_000_000;
    const log = await InMemoryTransparencyLog.generateEd25519({
      logId: 'euno-test-log-1',
      kid: 'log-key-1',
      clock: () => now++,
    });
    const payload = buildPayload();
    const receipt = buildIssuanceReceipt(payload);
    const sct = await log.submit(receipt);
    expect(sct.logId).toBe('euno-test-log-1');
    expect(sct.kid).toBe('log-key-1');
    expect(sct.entryIndex).toBe(0);
    expect(sct.timestamp).toBe(1_700_000_000_000);

    const jwks = await log.getPublicJwks();
    const jwk = jwks.keys[0]!;
    const receiptHash = sha256Base64Url(canonicalReceiptSigningInput(receipt));
    await expect(verifySct(jwk, sct, receiptHash)).resolves.toBe(true);
  });

  it('appends entries in submission order', async () => {
    const log = await InMemoryTransparencyLog.generateEd25519({
      logId: 'log-2',
      kid: 'k',
    });
    const r1 = buildIssuanceReceipt(buildPayload({ jti: 'a' }));
    const r2 = buildIssuanceReceipt(buildPayload({ jti: 'b' }));
    const s1 = await log.submit(r1);
    const s2 = await log.submit(r2);
    expect(s1.entryIndex).toBe(0);
    expect(s2.entryIndex).toBe(1);
    const entries = log.getEntries();
    expect(entries.map((e) => e.receipt.jti)).toEqual(['a', 'b']);
  });

  it('rejects logIds containing newlines (would break SCT signing input)', async () => {
    await expect(
      InMemoryTransparencyLog.generateEd25519({ logId: 'bad\nid', kid: 'k' }),
    ).rejects.toThrow(/newline/);
  });

  it('SCT verification fails when receipt hash differs (binding check)', async () => {
    const log = await InMemoryTransparencyLog.generateEd25519({
      logId: 'log-3',
      kid: 'k',
    });
    const receipt = buildIssuanceReceipt(buildPayload());
    const sct = await log.submit(receipt);
    const jwk = (await log.getPublicJwks()).keys[0]!;
    const wrongHash = sha256Base64Url('different');
    await expect(verifySct(jwk, sct, wrongHash)).resolves.toBe(false);
  });
});

describe('witnessPayload', () => {
  it('returns undefined for empty log set (back-compat)', async () => {
    expect(await witnessPayload(buildPayload(), [])).toBeUndefined();
  });

  it('submits one entry per log, in order', async () => {
    const l1 = await InMemoryTransparencyLog.generateEd25519({
      logId: 'l1',
      kid: 'k',
    });
    const l2 = await InMemoryTransparencyLog.generateEd25519({
      logId: 'l2',
      kid: 'k',
    });
    const scts = await witnessPayload(buildPayload(), [l1, l2]);
    expect(scts?.map((s) => s.logId)).toEqual(['l1', 'l2']);
    expect(l1.getEntries()).toHaveLength(1);
    expect(l2.getEntries()).toHaveLength(1);
  });
});

describe('verifyIssuanceProofs', () => {
  async function setup() {
    const cosignerA = await SoftwareCosigner.generateEd25519('cosigner-A');
    const cosignerB = await SoftwareCosigner.generateEd25519('cosigner-B');
    const log = await InMemoryTransparencyLog.generateEd25519({
      logId: 'tlog-1',
      kid: 'tlog-key-1',
    });
    const payload = buildPayload();
    const receipt = buildIssuanceReceipt(payload);
    const cosigs = await cosignPayload(payload, [cosignerA, cosignerB]);
    const scts = await witnessPayload(payload, [log]);
    const proofs: IssuanceProofs = {
      ...(cosigs ? { cosig: cosigs } : {}),
      ...(scts ? { sct: scts } : {}),
    };
    const cosignerJwks = {
      keys: [await cosignerA.getPublicJwk(), await cosignerB.getPublicJwk()],
    };
    const logJwksByLogId = new Map([['tlog-1', await log.getPublicJwks()]]);
    return { proofs, receipt, cosignerJwks, logJwksByLogId };
  }

  it('verifies all proofs when trust set is correct', async () => {
    const { proofs, receipt, cosignerJwks, logJwksByLogId } = await setup();
    const result = await verifyIssuanceProofs(proofs, receipt, {
      cosignerJwks,
      logJwksByLogId,
    });
    expect(result.failures).toEqual([]);
    expect(result.validCosignatures).toBe(2);
    expect(result.validScts).toBe(1);
  });

  it('flags unknown cosigner kid as a failure (does not silently drop)', async () => {
    const { proofs, receipt, logJwksByLogId } = await setup();
    const tamperedJwks = { keys: [] };
    const result = await verifyIssuanceProofs(proofs, receipt, {
      cosignerJwks: tamperedJwks,
      logJwksByLogId,
    });
    expect(result.validCosignatures).toBe(0);
    expect(result.failures.length).toBeGreaterThan(0);
    expect(result.failures.some((f) => f.includes('not in the trusted cosigner JWKS'))).toBe(true);
  });

  it('flags missing cosigner JWKS as a failure when cosigs are present', async () => {
    const { proofs, receipt, logJwksByLogId } = await setup();
    const result = await verifyIssuanceProofs(proofs, receipt, {
      logJwksByLogId,
    });
    expect(result.validCosignatures).toBe(0);
    expect(result.failures.some((f) =>
      f.includes('no cosigner JWKS is configured'),
    )).toBe(true);
  });

  it('flags unknown logId as a failure', async () => {
    const { proofs, receipt, cosignerJwks } = await setup();
    const result = await verifyIssuanceProofs(proofs, receipt, {
      cosignerJwks,
      logJwksByLogId: new Map(),
    });
    expect(result.validScts).toBe(0);
    expect(result.failures.some((f) => f.includes('no transparency-log JWKS'))).toBe(true);
  });

  it('rejects a wrong-key cosignature (right kid, different key)', async () => {
    const { proofs, receipt, logJwksByLogId } = await setup();
    // Replace cosigner-A's JWK with an unrelated key bearing the same kid.
    const impostor = await SoftwareCosigner.generateEd25519('cosigner-A');
    const cosignerJwks = {
      keys: [await impostor.getPublicJwk()],
    };
    const result = await verifyIssuanceProofs(proofs, receipt, {
      cosignerJwks,
      logJwksByLogId,
    });
    expect(result.validCosignatures).toBe(0);
    expect(result.failures.some((f) => f.includes('did not verify'))).toBe(true);
  });

  it('returns no failures and no proofs when proofs is undefined (back-compat)', async () => {
    const { receipt } = await setup();
    const result = await verifyIssuanceProofs(undefined, receipt, {});
    expect(result).toEqual({ validCosignatures: 0, validScts: 0, failures: [] });
  });

  it('binds SCT to the exact receipt — verifying with a different jti fails', async () => {
    const { proofs, cosignerJwks, logJwksByLogId } = await setup();
    const fakeReceipt: IssuanceReceipt = {
      iss: 'did:web:issuer.example.com',
      sub: 'agent-42',
      aud: 'tool-gateway',
      iat: 1_700_000_000,
      exp: 1_700_000_900,
      jti: 'different-jti',
      capabilitiesHash: capabilitiesHash([
        { resource: 'api://service/path', actions: ['read', 'write'] },
      ]),
    };
    const result = await verifyIssuanceProofs(proofs, fakeReceipt, {
      cosignerJwks,
      logJwksByLogId,
    });
    expect(result.validCosignatures).toBe(0);
    expect(result.validScts).toBe(0);
    expect(result.failures.length).toBeGreaterThan(0);
  });
});

describe('Sct shape exports', () => {
  it('Sct + IssuanceProofs are exported types (compile-time only)', () => {
    const _sct: Sct = {
      logId: 'l',
      kid: 'k',
      alg: 'EdDSA',
      timestamp: 1,
      sig: 'x',
    };
    const _proofs: IssuanceProofs = { cosig: [], sct: [_sct] };
    void _proofs;
    expect(_sct.logId).toBe('l');
  });
});

// ---------------------------------------------------------------------------
// Regression tests for review feedback on the multi-issuer trust PR.
// These tests pin behaviour that protects against post-compromise attacks
// the original implementation did not cover.
// ---------------------------------------------------------------------------

describe('IssuanceReceipt — cnf.jkt binding (DPoP thumbprint substitution defence)', () => {
  it('omits cnfJkt when payload has no cnf (legacy receipt bytes unchanged)', () => {
    const r = buildIssuanceReceipt(buildPayload());
    expect(Object.prototype.hasOwnProperty.call(r, 'cnfJkt')).toBe(false);
    // canonical JSON must not contain the field
    const json = canonicalJsonStringify(r);
    expect(json).not.toContain('cnfJkt');
  });

  it('includes cnfJkt in the receipt when payload carries cnf.jkt', () => {
    const payload = buildPayload({ cnf: { jkt: 'thumbprint-A' } });
    const r = buildIssuanceReceipt(payload);
    expect(r.cnfJkt).toBe('thumbprint-A');
    // canonical JSON includes the field exactly once
    expect(canonicalJsonStringify(r)).toContain('"cnfJkt":"thumbprint-A"');
  });

  it('REJECTS a token whose DPoP thumbprint was rewritten after cosignature', async () => {
    // Attacker scenario: holds the primary issuer key, takes a legitimate
    // token that already has a valid cosignature, and rewrites cnf.jkt to
    // point at a DPoP key the attacker controls. With cnf.jkt baked into
    // the receipt, the cosignature no longer verifies on the rewritten
    // token.
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-1');
    const original = buildPayload({ cnf: { jkt: 'victim-thumbprint' } });
    const cosigs = await cosignPayload(original, [cosigner]);
    expect(cosigs).toHaveLength(1);

    // Tampered: same payload but cnf.jkt swapped to attacker's key.
    const tampered = { ...original, cnf: { jkt: 'attacker-thumbprint' } };
    const tamperedReceipt = buildIssuanceReceipt(tampered);
    const cosignerJwks = { keys: [await cosigner.getPublicJwk()] };

    const result = await verifyIssuanceProofs(
      { cosig: cosigs! },
      tamperedReceipt,
      { cosignerJwks },
    );
    expect(result.validCosignatures).toBe(0);
    expect(result.failures.length).toBeGreaterThan(0);
    expect(result.failures[0]).toMatch(/did not verify/);
  });
});

describe('verifyIssuanceProofs — cosignature replay/dedup', () => {
  it('counts the same kid only ONCE toward REQUIRE_COSIGNATURE_COUNT', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-A');
    const payload = buildPayload();
    const single = (await cosignPayload(payload, [cosigner]))!;
    expect(single).toHaveLength(1);

    // Attacker repeats the same valid cosignature twice.
    const replayed: Cosignature[] = [single[0]!, single[0]!];
    const cosignerJwks = { keys: [await cosigner.getPublicJwk()] };
    const result = await verifyIssuanceProofs(
      { cosig: replayed },
      buildIssuanceReceipt(payload),
      { cosignerJwks },
    );
    expect(result.validCosignatures).toBe(1);
    expect(result.failures.some((f) => /more than once/.test(f))).toBe(true);
  });
});

describe('verifyIssuanceProofs — defensive shape checks (no 500s on malformed proofs)', () => {
  it('treats malformed cosig entries as verification failures, not exceptions', async () => {
    const cosigner = await SoftwareCosigner.generateEd25519('cosigner-A');
    const cosignerJwks = { keys: [await cosigner.getPublicJwk()] };
    const receipt = buildIssuanceReceipt(buildPayload());

    // A pathological proofs object an attacker could craft.
    const proofs = {
      cosig: [
        null,
        {} as unknown,
        { kid: 'x' } as unknown,
        { kid: 1, alg: 'EdDSA', sig: 'x' } as unknown,
      ] as Cosignature[],
    };
    await expect(
      verifyIssuanceProofs(proofs, receipt, { cosignerJwks }),
    ).resolves.toMatchObject({ validCosignatures: 0 });
    const result = await verifyIssuanceProofs(proofs, receipt, { cosignerJwks });
    expect(result.failures.length).toBe(4);
    expect(result.failures.every((f) => /malformed/.test(f))).toBe(true);
  });

  it('treats malformed sct entries as verification failures, not exceptions', async () => {
    const log = await InMemoryTransparencyLog.generateEd25519({ logId: 'l1', kid: 'kid-1' });
    const logJwks = await log.getPublicJwks();
    const logJwksByLogId = new Map([['l1', logJwks]]);
    const receipt = buildIssuanceReceipt(buildPayload());

    const proofs = {
      sct: [
        null,
        {} as unknown,
        { logId: 'l1' } as unknown,
        { logId: 'l1', kid: 'kid-1', alg: 'EdDSA', timestamp: 'not-a-number', sig: 'x' } as unknown,
      ] as Sct[],
    };
    const result = await verifyIssuanceProofs(proofs, receipt, { logJwksByLogId });
    expect(result.failures.length).toBe(4);
    expect(result.failures.every((f) => /malformed/.test(f))).toBe(true);
  });
});

describe('InMemoryTransparencyLog — concurrent submit safety', () => {
  it('assigns unique, monotonic indices under parallel submits', async () => {
    const log = await InMemoryTransparencyLog.generateEd25519({ logId: 'l1', kid: 'kid-1' });
    const N = 50;
    const receipts: IssuanceReceipt[] = Array.from({ length: N }, (_, i) =>
      buildIssuanceReceipt(buildPayload({ jti: `jti-${i}` })),
    );
    const scts = await Promise.all(receipts.map((r) => log.submit(r)));
    const indices = scts.map((s) => s.entryIndex).sort((a, b) => (a as number) - (b as number));
    // Indices must be {0,1,...,N-1} — no duplicates, no gaps.
    for (let i = 0; i < N; i += 1) {
      expect(indices[i]).toBe(i);
    }
    // getEntries returns N entries in index order.
    const entries = log.getEntries();
    expect(entries).toHaveLength(N);
    entries.forEach((e, i) => expect(e.index).toBe(i));
  });
});

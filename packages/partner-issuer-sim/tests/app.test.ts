/**
 * Unit tests for the partner-issuer-sim Express app.
 *
 * Covers:
 * - Health check
 * - DID document is served and references the configured DID + JWK.
 * - `/issue` mints a verifiable JWT whose signature checks against the
 *   key advertised in the DID document.
 * - `/issue` rejects malformed bodies.
 * - `/validate` enforces trusted issuer + capability matching.
 * - Deterministic key derivation: the same `PARTNER_SEED` produces the
 *   same DID document on every run (CI stability).
 */

import request from 'supertest';
import * as jose from 'jose';
import { CapabilityTokenPayload, CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';
import { createPartnerApp } from '../src/app';
import { loadOrCreateKey } from '../src/keys';

const PARTNER_DID = 'did:web:partner-sim.local%3A4001';
const SEED_HEX = 'a'.repeat(64);

function buildApp(opts: { trustedIssuerDids?: string[] } = {}) {
  const key = loadOrCreateKey({ seed: SEED_HEX });
  return {
    key,
    app: createPartnerApp({
      issuerDid: PARTNER_DID,
      audience: 'tool-gateway',
      defaultTtlSeconds: 600,
      key,
      trustedIssuerDids: opts.trustedIssuerDids,
    }),
  };
}

describe('partner-issuer-sim — key derivation', () => {
  it('produces the same key material for the same seed (CI determinism)', () => {
    const a = loadOrCreateKey({ seed: SEED_HEX });
    const b = loadOrCreateKey({ seed: SEED_HEX });
    expect(a.publicKeyPem).toBe(b.publicKeyPem);
    expect(a.privateKeyPem).toBe(b.privateKeyPem);
    expect(a.publicKeyJwk.x).toBe(b.publicKeyJwk.x);
  });

  it('rejects a malformed seed', () => {
    expect(() => loadOrCreateKey({ seed: 'not-a-real-seed' })).toThrow(/PARTNER_SEED/);
  });

  it('produces a different key when no seed is given (random)', () => {
    const a = loadOrCreateKey({});
    const b = loadOrCreateKey({});
    expect(a.publicKeyPem).not.toBe(b.publicKeyPem);
  });
});

describe('partner-issuer-sim — endpoints', () => {
  it('GET /healthz returns ok', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', issuer: PARTNER_DID });
  });

  it('GET /.well-known/did.json serves the partner DID document', async () => {
    const { app, key } = buildApp();
    const res = await request(app).get('/.well-known/did.json');
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(PARTNER_DID);
    expect(res.body.verificationMethod).toHaveLength(1);
    const vm = res.body.verificationMethod[0];
    expect(vm.id).toBe(`${PARTNER_DID}#key-1`);
    expect(vm.type).toBe('JsonWebKey2020');
    expect(vm.publicKeyJwk).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      x: key.publicKeyJwk.x,
      alg: 'EdDSA',
    });
  });

  it('POST /issue mints a JWT verifiable with the published key', async () => {
    const { app, key } = buildApp();
    const res = await request(app)
      .post('/issue')
      .send({
        partnerAgentId: 'partner-agent-1',
        capabilities: [
          { resource: 'storage://shared-data/**', actions: ['read'] },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.token).toEqual(expect.any(String));
    expect(res.body.tokenId).toEqual(expect.any(String));

    const publicKey = await jose.importSPKI(key.publicKeyPem, 'EdDSA');
    const { payload } = await jose.jwtVerify(res.body.token, publicKey, {
      algorithms: ['EdDSA'],
    });
    const cap = payload as unknown as CapabilityTokenPayload;
    expect(cap.iss).toBe(PARTNER_DID);
    expect(cap.sub).toBe('partner-agent-1');
    expect(cap.aud).toBe('tool-gateway');
    expect(cap.schemaVersion).toBe(CAPABILITY_TOKEN_SCHEMA_VERSION);
    expect(cap.capabilities).toEqual([
      { resource: 'storage://shared-data/**', actions: ['read'] },
    ]);
    expect(cap.exp).toBeGreaterThan(cap.iat);
  });

  it('POST /issue rejects a missing partnerAgentId', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/issue')
      .send({ capabilities: [{ resource: 'x', actions: ['read'] }] });
    expect(res.status).toBe(400);
  });

  it('POST /issue rejects an empty capability list', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/issue')
      .send({ partnerAgentId: 'a', capabilities: [] });
    expect(res.status).toBe(400);
  });

  it('POST /validate rejects tokens from an untrusted issuer', async () => {
    // Partner is configured to trust no one.
    const { app, key } = buildApp({ trustedIssuerDids: [] });
    const privateKey = await jose.importPKCS8(key.privateKeyPem, 'EdDSA');
    const token = await new jose.SignJWT({
      iss: PARTNER_DID,
      sub: 'self',
      aud: 'tool-gateway',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: 'jti-1',
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'x', actions: ['read'] }],
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${PARTNER_DID}#key-1` })
      .sign(privateKey);

    const res = await request(app)
      .post('/validate')
      .send({ token, action: 'read', resource: 'x' });
    expect(res.status).toBe(403);
    expect(res.body.allowed).toBe(false);
    expect(res.body.reason).toMatch(/not trusted/);
  });
});

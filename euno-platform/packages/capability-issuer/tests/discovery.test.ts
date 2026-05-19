/**
 * Task 9 — `/.well-known/capability-issuer` discovery v1.0.0
 *
 * Route tests for the versioned discovery endpoint.
 * Covers:
 *   1. schemaVersion field is "1.0.0"
 *   2. All Stage-5 fields are present (partnerFederation, scim, auditExport, capabilities)
 *   3. Cache-Control: public, max-age=300 is set
 *   4. ETag header is present and in the expected quoted-SHA-256 format
 *   5. ETag is stable across repeated requests (deterministic)
 *   6. ETag derives from the response body
 *   7. If-None-Match matching ETag → 304 Not Modified (no body)
 *   8. If-None-Match mismatch → 200 with full body
 */

import crypto from 'crypto';
import request from 'supertest';
import { app } from '../src/index';

// Mock Azure services to keep the test environment self-contained.
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

describe('GET /.well-known/capability-issuer — discovery v1.0.0 (Task 9)', () => {
  let body: Record<string, unknown>;
  let headers: Record<string, string>;
  let currentEtag: string;

  beforeAll(async () => {
    const response = await request(app).get('/.well-known/capability-issuer');
    expect(response.status).toBe(200);
    body = response.body as Record<string, unknown>;
    headers = response.headers as Record<string, string>;
    currentEtag = headers['etag'] as string;
  });

  // ── Test 1: schemaVersion field ────────────────────────────────────────────
  it('returns schemaVersion "1.0.0"', () => {
    expect(body).toHaveProperty('schemaVersion', '1.0.0');
  });

  // ── Test 2: Stage-5 fields ─────────────────────────────────────────────────
  it('includes partnerFederation with registrationEndpoint pointing to the gateway admin path', () => {
    expect(body).toHaveProperty('partnerFederation');
    const pf = body.partnerFederation as Record<string, unknown>;
    expect(typeof pf.registrationEndpoint).toBe('string');
    expect(pf.registrationEndpoint).toBe('/admin/partner-dids/proposals');
    // discoveryParam was removed — it pointed to a non-existent endpoint.
    expect(pf).not.toHaveProperty('discoveryParam');
  });

  it('includes scim.baseUri', () => {
    expect(body).toHaveProperty('scim');
    const scim = body.scim as Record<string, unknown>;
    expect(typeof scim.baseUri).toBe('string');
    expect((scim.baseUri as string).length).toBeGreaterThan(0);
  });

  it('includes auditExport with endpoint and chainProof', () => {
    expect(body).toHaveProperty('auditExport');
    const ae = body.auditExport as Record<string, unknown>;
    expect(typeof ae.endpoint).toBe('string');
    expect(typeof ae.chainProof).toBe('string');
    expect((ae.endpoint as string).length).toBeGreaterThan(0);
    expect((ae.chainProof as string).length).toBeGreaterThan(0);
  });

  it('includes capabilities array with required Stage-5 entries', () => {
    expect(body).toHaveProperty('capabilities');
    expect(Array.isArray(body.capabilities)).toBe(true);
    const caps = body.capabilities as string[];
    expect(caps).toContain('partner-federation');
    expect(caps).toContain('scim-provisioning');
    expect(caps).toContain('cross-chain-anchor');
    expect(caps).toContain('db-token-service');
    expect(caps).toContain('storage-grant-service');
  });

  // ── Test 3: Cache-Control header ───────────────────────────────────────────
  it('sets Cache-Control: public, max-age=300', () => {
    expect(headers['cache-control']).toMatch(/public/);
    expect(headers['cache-control']).toMatch(/max-age=300/);
  });

  // ── Test 4: ETag header present and well-formed ────────────────────────────
  it('sets an ETag header in quoted SHA-256 hex format', () => {
    const etag = headers['etag'];
    expect(etag).toBeDefined();
    // Quoted SHA-256 hex: 64 hex chars surrounded by double-quotes
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
  });

  // ── Test 5: ETag is stable (deterministic) ─────────────────────────────────
  it('returns the same ETag on repeated requests (stable body)', async () => {
    const first = await request(app).get('/.well-known/capability-issuer');
    const second = await request(app).get('/.well-known/capability-issuer');
    expect(first.headers['etag']).toBe(second.headers['etag']);
  });

  // ── Test 6: ETag derives from response body ────────────────────────────────
  it('ETag is the SHA-256 of the serialised response body', async () => {
    const response = await request(app).get('/.well-known/capability-issuer');
    const bodyText = JSON.stringify(response.body);
    const expectedEtag = `"${crypto.createHash('sha256').update(bodyText).digest('hex')}"`;
    expect(response.headers['etag']).toBe(expectedEtag);
  });

  // ── Test 7: If-None-Match matching → 304 ──────────────────────────────────
  it('returns 304 Not Modified when If-None-Match matches the current ETag', async () => {
    const response = await request(app)
      .get('/.well-known/capability-issuer')
      .set('If-None-Match', currentEtag);

    expect(response.status).toBe(304);
    // 304 must have no body (Content-Type absent or body empty)
    expect(response.text).toBeFalsy();
  });

  // ── Test 8: If-None-Match mismatch → 200 ─────────────────────────────────
  it('returns 200 with full body when If-None-Match does not match', async () => {
    const response = await request(app)
      .get('/.well-known/capability-issuer')
      .set('If-None-Match', '"0000000000000000000000000000000000000000000000000000000000000000"');

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('schemaVersion', '1.0.0');
  });

  // ── Back-compat: existing fields must still be present ────────────────────
  it('still exposes issuer, schemaVersions, signingAlgorithms, and endpoints', () => {
    expect(body).toHaveProperty('issuer');
    expect(body).toHaveProperty('schemaVersions');
    const sv = body.schemaVersions as Record<string, unknown>;
    expect(sv).toHaveProperty('current');
    expect(Array.isArray(sv.supported)).toBe(true);
    expect(body).toHaveProperty('signingAlgorithms');
    expect(Array.isArray(body.signingAlgorithms)).toBe(true);
    expect(body).toHaveProperty('endpoints');
    const ep = body.endpoints as Record<string, unknown>;
    expect(ep).toHaveProperty('jwks');
    expect(ep).toHaveProperty('publicKey');
    expect(ep).toHaveProperty('didDocument');
    // actionResolverHash is set only after initializeServices() runs; in unit
    // tests the service is not fully initialized, so the field is absent.
    // Its presence is verified by the gateway parity check at startup.
  });
});

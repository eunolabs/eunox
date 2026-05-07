/**
 * Tests for the Prometheus / OpenMetrics surface on the capability issuer
 * (F-5, addresses I-16 in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 */

import request from 'supertest';

// Mock Azure services so the module can be imported without real credentials.
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

describe('Capability Issuer /metrics endpoint (F-5)', () => {
  const ORIGINAL_ENV = process.env;

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    jest.resetModules();
  });

  it('exposes Prometheus metrics with the correct content-type', async () => {
    const { app } = await import('../src/index');

    const res = await request(app).get('/metrics');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/plain/);
    // Standard HTTP middleware series.
    expect(res.text).toContain('euno_http_request_duration_seconds');
    expect(res.text).toContain('euno_http_requests_total');
    // Issuer-specific issuance counter (pre-initialised so series exist
    // even before the first /api/v1/issue call).
    expect(res.text).toContain('euno_issuer_issuance_total');
    expect(res.text).toContain('service="capability-issuer"');
  });

  it('records HTTP samples after handling a request', async () => {
    const { app } = await import('../src/index');

    await request(app).get('/health');
    const res = await request(app).get('/metrics');

    expect(res.status).toBe(200);
    expect(res.text).toMatch(
      /euno_http_requests_total\{[^}]*status_code="200"[^}]*\}\s+\d+/,
    );
  });

  it('does not record observations for the /metrics endpoint itself', async () => {
    const { app } = await import('../src/index');

    await request(app).get('/metrics');
    await request(app).get('/metrics');
    const res = await request(app).get('/metrics');

    expect(res.text).not.toMatch(
      /euno_http_requests_total\{[^}]*route="\/metrics"/,
    );
  });

  it('increments the issuance error counter when issue fails authn', async () => {
    const { app } = await import('../src/index');

    // Missing Authorization header → 401 from the issue handler, which
    // routes through the catch block and bumps the error counter.
    const res = await request(app).post('/api/v1/issue').send({});
    expect(res.status).toBe(401);

    const metrics = await request(app).get('/metrics');
    expect(metrics.status).toBe(200);
    expect(metrics.text).toMatch(
      /euno_issuer_issuance_total\{[^}]*operation="issue"[^}]*outcome="error"[^}]*\}\s+[1-9]\d*/,
    );
  });
});

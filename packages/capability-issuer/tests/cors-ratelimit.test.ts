/**
 * Tests for CORS allowlist parsing and rate-limit configuration
 * in the capability-issuer service.
 */

import request from 'supertest';

// Mock Azure services so the module can be imported without real credentials.
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

describe('CORS configuration', () => {
  const ORIGINAL_ENV = process.env;

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    jest.resetModules();
  });

  it('allows a request from an explicitly listed origin (development default)', async () => {
    process.env.NODE_ENV = 'development';
    delete process.env.ALLOWED_ORIGINS;
    // Re-import so the module picks up the updated env vars.
    const { app } = await import('../src/index');

    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');

    // The Access-Control-Allow-Origin header should be echoed for allowed origins.
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
  });

  it('accepts ALLOWED_ORIGINS with surrounding whitespace on individual entries', async () => {
    // Comma-separated list with spaces – should be trimmed before being passed to cors().
    process.env.ALLOWED_ORIGINS = ' https://app.example.com , https://admin.example.com ';
    const { app } = await import('../src/index');

    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://app.example.com');

    expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
  });

  it('does not leak an empty-string origin when ALLOWED_ORIGINS has trailing comma', async () => {
    process.env.ALLOWED_ORIGINS = 'https://app.example.com,';
    const { app } = await import('../src/index');

    // An empty-string origin should not be echoed.
    const res = await request(app)
      .get('/health')
      .set('Origin', '');

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('Rate-limit env-var validation', () => {
  const ORIGINAL_ENV = process.env;

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    jest.resetModules();
  });

  it('starts successfully when rate-limit env vars are valid numbers', async () => {
    process.env.RATE_LIMIT_WINDOW_MS = '30000';
    process.env.RATE_LIMIT_MAX_REQUESTS = '50';
    // Should not throw during module initialisation.
    await expect(import('../src/index')).resolves.not.toThrow();
  });

  it('falls back to defaults when rate-limit env vars are non-numeric strings', async () => {
    process.env.RATE_LIMIT_WINDOW_MS = 'bad-value';
    process.env.RATE_LIMIT_MAX_REQUESTS = 'also-bad';
    // Should not throw – invalid values are replaced with safe defaults.
    await expect(import('../src/index')).resolves.not.toThrow();
  });

  it('still responds to requests when rate-limit env vars are invalid', async () => {
    process.env.RATE_LIMIT_WINDOW_MS = 'NaN';
    process.env.RATE_LIMIT_MAX_REQUESTS = 'NaN';
    const { app } = await import('../src/index');

    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

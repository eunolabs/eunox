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

  it('starts successfully when issuance rate-limit env vars are valid numbers', async () => {
    process.env.ISSUANCE_RATE_LIMIT_MAX = '30';
    process.env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS = '60';
    const mod = await import('../src/index');
    expect(mod.app).toBeDefined();
  });

  it('fails at startup when ISSUANCE_RATE_LIMIT_MAX is a non-numeric string (strict fail-closed)', async () => {
    // Intercept process.exit so the jest worker is not killed when the
    // config validator rejects the non-integer value.  The schema now
    // validates strictly: non-integer values are rejected at startup
    // rather than silently replaced with safe defaults, so a
    // misconfigured rate limiter is caught early (fail-closed).
    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation((() => {
        throw new Error('process.exit intercepted');
      }) as unknown as (code?: string | number | null) => never);
    try {
      process.env.ISSUANCE_RATE_LIMIT_MAX = 'bad-value';
      process.env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS = 'also-bad';
      // Pin the intended failure mode: startup validation triggers exit(1).
      await expect(import('../src/index')).rejects.toThrow('process.exit intercepted');
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      exitSpy.mockRestore();
    }
  });

  it('still responds to requests when issuance rate-limit env vars are set to minimum valid values', async () => {
    // Confirm the service starts and handles requests normally when valid
    // (but non-default) rate-limit values are provided.
    process.env.ISSUANCE_RATE_LIMIT_MAX = '1';
    process.env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS = '1';
    const { app } = await import('../src/index');

    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

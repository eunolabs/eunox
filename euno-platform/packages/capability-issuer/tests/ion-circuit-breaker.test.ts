/**
 * Task 2 — did:ion productionization
 *
 * Tests for:
 *   1. Circuit breaker wrapping in `resolveDidIon()`:
 *      - Circuit opens after N consecutive failures
 *      - Open circuit → CapabilityError (not unhandled rejection)
 *      - Open circuit → resolveDidIon returns CapabilityError (fail-closed)
 *      - Circuit closes after cooldown + successful probe
 *      - Half-open probe failure re-opens the circuit
 *   2. `GET /healthz/did-ion` health endpoint:
 *      - Returns { status: "ok" } when circuit closed and probe succeeds
 *      - Returns { status: "degraded", reason: "circuit_open" } when circuit is open
 *      - Returns { status: "degraded", reason: "probe_failed" } when probe fails
 *   3. `resolveDidIon` with circuit open throws CapabilityError (not unhandled rejection)
 */

import request from 'supertest';
import { ErrorCode, RedisCircuitBreaker } from '@euno/common';
import { resolveDidIon } from '../src/did-resolver';
import { app } from '../src/index';

jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ION_PROBE_DID = 'did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7iCCg';

function makeMockDIDDocument(did: string) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'test-x', alg: 'EdDSA' },
      },
    ],
  };
}

function mockFetchSuccess(did: string) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ didDocument: makeMockDIDDocument(did) }),
  } as unknown as Response);
}

function mockFetchFailure() {
  global.fetch = jest.fn().mockResolvedValue({
    ok: false,
    status: 503,
    statusText: 'Service Unavailable',
  } as unknown as Response);
}

// ---------------------------------------------------------------------------
// §1 — Circuit breaker unit tests (resolveDidIon with explicit breaker)
// ---------------------------------------------------------------------------

describe('resolveDidIon — circuit breaker wrapping', () => {
  const testDid = 'did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w';
  let originalFetch: typeof global.fetch;
  let cb: RedisCircuitBreaker;

  beforeEach(() => {
    originalFetch = global.fetch;
    // Use a very short window and cooldown to keep tests fast.
    cb = new RedisCircuitBreaker({
      failureThreshold: 3,
      windowMs: 1_000,
      cooldownMs: 50,
    });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // Case 1: happy path with circuit breaker present — succeeds normally
  it('resolves successfully when circuit is closed and fetch succeeds', async () => {
    mockFetchSuccess(testDid);
    const doc = await resolveDidIon(testDid, undefined, cb);
    expect(doc.id).toBe(testDid);
    expect(cb.getState()).toBe('closed');
  });

  // Case 2: circuit opens after threshold consecutive failures
  it('circuit opens after failureThreshold failures', async () => {
    mockFetchFailure();
    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toMatchObject({
        code: ErrorCode.AUTHENTICATION_FAILED,
      });
    }
    expect(cb.getState()).toBe('open');
  });

  // Case 3: when circuit is open, resolveDidIon throws CapabilityError (not CircuitOpenError)
  it('throws CapabilityError (not CircuitOpenError) when circuit is open', async () => {
    mockFetchFailure();
    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toMatchObject({
        code: ErrorCode.AUTHENTICATION_FAILED,
      });
    }
    expect(cb.getState()).toBe('open');

    // Next call must be a CapabilityError, not an unhandled rejection or CircuitOpenError
    const err = await resolveDidIon(testDid, undefined, cb).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe(ErrorCode.AUTHENTICATION_FAILED);
    expect(err.message).toContain('circuit breaker is open');
    // Must not be a raw CircuitOpenError
    expect(err.constructor.name).not.toBe('CircuitOpenError');
  });

  // Case 4: circuit closes after cooldown + successful probe
  it('circuit closes after cooldown elapses and probe succeeds', async () => {
    mockFetchFailure();
    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toBeDefined();
    }
    expect(cb.getState()).toBe('open');

    // Wait for cooldown to elapse
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Now let fetch succeed — probe should close the circuit
    mockFetchSuccess(testDid);
    const doc = await resolveDidIon(testDid, undefined, cb);
    expect(doc.id).toBe(testDid);
    expect(cb.getState()).toBe('closed');
  });

  // Case 5: half-open probe failure re-opens the circuit
  it('re-opens the circuit when the half-open probe fails', async () => {
    mockFetchFailure();
    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toBeDefined();
    }
    expect(cb.getState()).toBe('open');

    // Wait for cooldown
    await new Promise((resolve) => setTimeout(resolve, 100));
    // Still failing — probe should fail and re-open
    await expect(resolveDidIon(testDid, undefined, cb)).rejects.toBeDefined();
    expect(cb.getState()).toBe('open');
  });
});

// ---------------------------------------------------------------------------
// §2 — GET /healthz/did-ion health endpoint
// ---------------------------------------------------------------------------

describe('GET /healthz/did-ion — health endpoint', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // Case 1: probe succeeds and circuit is closed → { status: "ok" }
  it('returns { status: "ok" } when circuit is closed and probe succeeds', async () => {
    mockFetchSuccess(ION_PROBE_DID);
    const response = await request(app).get('/healthz/did-ion');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
  });

  // Case 2: probe fetch fails → { status: "degraded", reason: "probe_failed" }
  it('returns { status: "degraded" } when probe resolution fails', async () => {
    const networkError = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), {
      code: 'ECONNREFUSED',
    });
    global.fetch = jest.fn().mockRejectedValue(networkError);
    const response = await request(app).get('/healthz/did-ion');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('degraded');
  });

  // Case 3: always HTTP 200 even when degraded (so readiness probes pass)
  it('always returns HTTP 200 regardless of degraded state', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network failure'));
    const response = await request(app).get('/healthz/did-ion');
    expect(response.status).toBe(200);
    expect(typeof response.body.status).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// §4 — Non-fault errors (404, ID mismatch) do NOT trip the circuit breaker
// ---------------------------------------------------------------------------

describe('resolveDidIon — non-fault errors do not trip the circuit breaker', () => {
  const testDid = 'did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w';
  let originalFetch: typeof global.fetch;
  let cb: RedisCircuitBreaker;

  beforeEach(() => {
    originalFetch = global.fetch;
    cb = new RedisCircuitBreaker({
      failureThreshold: 3,
      windowMs: 1_000,
      cooldownMs: 60_000,
    });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // Case 1: 404 (DID not found) should NOT open the circuit even after many calls
  it('404 responses (DID not found) do not count toward the failure threshold', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    } as unknown as Response);

    // Call 3x (= failureThreshold), should throw INVALID_TOKEN each time
    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toMatchObject({
        code: ErrorCode.INVALID_TOKEN,
        statusCode: 404,
      });
    }
    // Circuit must remain closed despite 3 calls
    expect(cb.getState()).toBe('closed');
  });

  // Case 2: ID mismatch (INVALID_TOKEN) should NOT open the circuit
  it('DID document ID mismatch does not count toward the failure threshold', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        didDocument: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:ion:different-did',
          verificationMethod: [],
        },
      }),
    } as unknown as Response);

    for (let i = 0; i < 3; i++) {
      await expect(resolveDidIon(testDid, undefined, cb)).rejects.toMatchObject({
        code: ErrorCode.INVALID_TOKEN,
        message: expect.stringContaining('ID mismatch'),
      });
    }
    expect(cb.getState()).toBe('closed');
  });
});

// ---------------------------------------------------------------------------
// §5 — Health endpoint probe does NOT trip the shared circuit breaker
// ---------------------------------------------------------------------------

describe('GET /healthz/did-ion — probe does not affect shared circuit breaker state', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // K8s polling the health endpoint with a failing resolver should not open the
  // shared ionCircuitBreaker and cause all did:ion auth to fast-fail.
  it('repeated probe failures do not cause the probe to return circuit_open', async () => {
    const networkError = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), {
      code: 'ECONNREFUSED',
    });
    global.fetch = jest.fn().mockRejectedValue(networkError);

    // Hit the endpoint 5 times (more than the default failureThreshold of 3)
    for (let i = 0; i < 5; i++) {
      const response = await request(app).get('/healthz/did-ion');
      expect(response.status).toBe(200);
      // Each call should be probe_failed, never circuit_open (because the probe
      // does not run through the shared circuit breaker).
      expect(response.body).toEqual({ status: 'degraded', reason: 'probe_failed' });
    }
  });
});


describe('resolveDidIon — open circuit does not produce unhandled rejection', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('resolveDidIon with an open circuit breaker returns CapabilityError synchronously', async () => {
    const cb = new RedisCircuitBreaker({
      failureThreshold: 1,
      windowMs: 1_000,
      cooldownMs: 60_000,
    });

    const testDid = 'did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w';
    mockFetchFailure();
    // Trip the circuit
    await expect(resolveDidIon(testDid, undefined, cb)).rejects.toBeDefined();
    expect(cb.getState()).toBe('open');

    // Must return a CapabilityError, not an unhandled rejection
    const result = await resolveDidIon(testDid, undefined, cb).catch((e: unknown) => e);
    expect(result).toBeInstanceOf(Error);
    expect((result as { code?: string }).code).toBe(ErrorCode.AUTHENTICATION_FAILED);
    // Confirm the error message clearly indicates the circuit is open
    expect((result as Error).message).toContain('circuit breaker is open');
  });
});

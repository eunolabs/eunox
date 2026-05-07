/**
 * Tests for the built-in OPA HTTP policy backend (R-4 step 2 / F-10).
 *
 * The backend is exercised through the public `'policy'` condition
 * surface so we cover the integration with the registry, not just the
 * backend in isolation.
 */

import {
  enforceCondition,
  validateCondition,
  registerPolicyBackend,
  _resetPolicyBackendRegistry,
  ConditionValidationError,
  CapabilityCondition,
  createOpaHttpBackend,
  OPA_HTTP_BACKEND_NAME,
} from '../src';

type FetchFn = typeof globalThis.fetch;

function jsonResponse(body: unknown, init: { status?: number } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json' },
  });
}

function registerOpa(fetchImpl: FetchFn): void {
  registerPolicyBackend(
    OPA_HTTP_BACKEND_NAME,
    createOpaHttpBackend({ fetch: fetchImpl }),
  );
}

describe('createOpaHttpBackend', () => {
  beforeEach(() => _resetPolicyBackendRegistry());

  describe('validate', () => {
    beforeEach(() => {
      registerOpa(jest.fn() as unknown as FetchFn);
    });

    it('accepts a well-formed config', () => {
      expect(() =>
        validateCondition({
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa:8181/v1/data/euno/allow' },
        } as unknown as CapabilityCondition),
      ).not.toThrow();
    });

    it('rejects non-object config', () => {
      expect(() =>
        validateCondition({
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: 'http://opa',
        } as unknown as CapabilityCondition),
      ).toThrow(ConditionValidationError);
    });

    it('rejects a non-http(s) URL', () => {
      expect(() =>
        validateCondition({
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'ftp://opa/v1/data' },
        } as unknown as CapabilityCondition),
      ).toThrow(/http\(s\) URL/);
    });

    it('rejects bad timeout, decisionField, failClosed, headers', () => {
      const cases: unknown[] = [
        { url: 'http://opa', timeoutMs: 0 },
        { url: 'http://opa', timeoutMs: 1.5 },
        { url: 'http://opa', decisionField: '' },
        { url: 'http://opa', decisionField: 7 },
        { url: 'http://opa', failClosed: 'yes' },
        { url: 'http://opa', headers: 'x' },
        { url: 'http://opa', headers: { auth: 7 } },
      ];
      for (const c of cases) {
        expect(() =>
          validateCondition({
            type: 'policy',
            backend: OPA_HTTP_BACKEND_NAME,
            config: c,
          } as unknown as CapabilityCondition),
        ).toThrow(ConditionValidationError);
      }
    });
  });

  describe('enforce', () => {
    it('allows when OPA returns { result: true }', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({ result: true })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa:8181/v1/data/euno/allow' },
          input: { tenant: 'acme' },
        },
        { sourceIp: '10.0.0.1' },
      );
      expect(r).toEqual({ allow: true });
      const call = (fetchMock as unknown as jest.Mock).mock.calls[0];
      expect(call[0]).toBe('http://opa:8181/v1/data/euno/allow');
      const body = JSON.parse(call[1].body);
      expect(body.input.tenant).toBe('acme');
      expect(body.input.context.sourceIp).toBe('10.0.0.1');
    });

    it('returns deny without calling fetch when config is missing/malformed (defensive guard)', async () => {
      const fetchMock = jest.fn() as unknown as FetchFn;
      registerOpa(fetchMock);
      // A token whose policy condition omits `config` entirely.
      const cases: unknown[] = [
        undefined,
        null,
        'http://opa',
        [],
        { url: 7 },
        { url: 'ftp://opa/v1/data' },
        {},
      ];
      for (const config of cases) {
        const r = await enforceCondition(
          {
            type: 'policy',
            backend: OPA_HTTP_BACKEND_NAME,
            config: config as never,
          },
          {},
        );
        expect(r.allow).toBe(false);
        expect((r as { reason: string }).reason).toMatch(/invalid backend config/);
      }
      expect((fetchMock as unknown as jest.Mock).mock.calls.length).toBe(0);
    });

    it('denies when OPA returns { result: false }', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({ result: false })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa:8181/v1/data/euno/allow' },
        },
        {},
      );
      expect(r.allow).toBe(false);
    });

    it('honours a structured decision { allow: false, reason }', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(
          jsonResponse({ result: { allow: false, reason: 'tenant_not_authorised' } }),
        ) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x' },
        },
        {},
      );
      expect(r.allow).toBe(false);
      expect((r as { reason: string }).reason).toMatch(/tenant_not_authorised/);
    });

    it('fail-closes on HTTP 500 by default', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({}, { status: 500 })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x' },
        },
        {},
      );
      expect(r.allow).toBe(false);
      expect((r as { reason: string }).reason).toMatch(/HTTP 500/);
    });

    it('fail-opens on HTTP error when failClosed=false', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({}, { status: 503 })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x', failClosed: false },
        },
        {},
      );
      expect(r).toEqual({ allow: true });
    });

    it('fail-closes on a network error', async () => {
      const fetchMock = jest
        .fn()
        .mockRejectedValue(new Error('ECONNREFUSED')) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x' },
        },
        {},
      );
      expect(r.allow).toBe(false);
      expect((r as { reason: string }).reason).toMatch(/ECONNREFUSED/);
    });

    it('fail-closes on an unrecognised decision shape under the configured field', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({ verdict: 'maybe' })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x', decisionField: 'verdict' },
        },
        {},
      );
      expect(r.allow).toBe(false);
      expect((r as { reason: string }).reason).toMatch(/unrecognised decision shape/);
    });

    it('uses a custom decisionField when provided', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({ verdict: true })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x', decisionField: 'verdict' },
        },
        {},
      );
      expect(r).toEqual({ allow: true });
    });

    it('forwards configured headers', async () => {
      const fetchMock = jest
        .fn()
        .mockResolvedValue(jsonResponse({ result: true })) as unknown as FetchFn;
      registerOpa(fetchMock);
      await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: {
            url: 'http://opa/v1/data/x',
            headers: { authorization: 'Bearer X' },
          },
        },
        {},
      );
      const call = (fetchMock as unknown as jest.Mock).mock.calls[0];
      expect(call[1].headers.authorization).toBe('Bearer X');
      expect(call[1].headers['content-type']).toBe('application/json');
    });

    it('aborts and fail-closes after timeoutMs', async () => {
      // Resolve the fetch only after the abort signal fires.
      const fetchMock: FetchFn = ((_url: string, init: RequestInit) =>
        new Promise((_, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err = new Error('aborted');
            (err as Error & { name: string }).name = 'AbortError';
            reject(err);
          });
        })) as unknown as FetchFn;
      registerOpa(fetchMock);
      const r = await enforceCondition(
        {
          type: 'policy',
          backend: OPA_HTTP_BACKEND_NAME,
          config: { url: 'http://opa/v1/data/x', timeoutMs: 10 },
        },
        {},
      );
      expect(r.allow).toBe(false);
      expect((r as { reason: string }).reason).toMatch(/timed out after 10ms/);
    });
  });
});

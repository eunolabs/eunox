/**
 * Unit tests for {@link RemoteEnforcerPDP}.
 *
 * Uses an injectable {@link EnforceFetcher} to avoid real network I/O.
 * Covers: allow decision (with and without obligations), deny decision,
 * gateway error handling (fail-closed), protocol header, clock injection,
 * and recipient extraction.
 */

import type { CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import type { EnforceRequest, EnforceResponse, Obligation } from '@euno/common-core';
import { ENFORCE_PROTOCOL_VERSION } from '@euno/common-core';
import { RemoteEnforcerPDP } from '../enforcer/remote';
import type { EnforceFetcher } from '../enforcer/remote';
import type { PdpContext } from '../pdp';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeToolCallRequest(
  name: string,
  args: Record<string, unknown> = {},
): CallToolRequest {
  return {
    method: 'tools/call',
    params: { name, arguments: args },
  };
}

function makePdpContext(overrides: Partial<PdpContext> = {}): PdpContext {
  return {
    sessionId: 'test-session-id',
    ...overrides,
  };
}

function makeAllowResponse(obligations?: Obligation[]): EnforceResponse {
  return {
    requestId: 'req-1',
    decision: 'allow',
    obligations,
    decidedAt: new Date().toISOString(),
  };
}

function makeDenyResponse(
  code = 'AUTHORIZATION_FAILED',
  conditionType = 'policy',
  message = 'Access denied',
): EnforceResponse {
  return {
    requestId: 'req-1',
    decision: 'deny',
    denial: { code, conditionType, message },
    decidedAt: new Date().toISOString(),
  };
}

/** Create a mock fetcher that returns the given response. */
function mockFetcher(
  response: EnforceResponse,
  onRequest?: (url: string, body: EnforceRequest, headers: Record<string, string>) => void,
): EnforceFetcher {
  return async (url, init) => {
    if (onRequest) {
      onRequest(url, JSON.parse(init.body) as EnforceRequest, init.headers);
    }
    return {
      ok: true,
      status: 200,
      json: async () => response,
    };
  };
}

/** Create a mock fetcher that simulates a network error. */
function errorFetcher(error: Error): EnforceFetcher {
  return async () => { throw error; };
}

/** Create a mock fetcher that returns an HTTP error status. */
function httpErrorFetcher(status: number): EnforceFetcher {
  return async () => ({
    ok: false,
    status,
    json: async () => ({}),
  });
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – construction', () => {
  it('throws when url consists entirely of slashes', () => {
    expect(() => new RemoteEnforcerPDP({ url: '///', apiKey: 'sk-test' }))
      .toThrow('url must not consist entirely of slashes');
  });

  it('throws when url is empty', () => {
    expect(() => new RemoteEnforcerPDP({ url: '', apiKey: 'sk-test' }))
      .toThrow('url must be a non-empty string');
  });

  it('throws when apiKey is empty', () => {
    expect(() => new RemoteEnforcerPDP({ url: 'https://gateway.example', apiKey: '' }))
      .toThrow('apiKey must be a non-empty string');
  });

  it('strips trailing slashes from url', async () => {
    let capturedUrl: string | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example///',
      apiKey: 'sk-test',
      fetcher: async (url) => {
        capturedUrl = url;
        return { ok: true, status: 200, json: async () => makeAllowResponse() };
      },
    });
    await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());
    expect(capturedUrl).toBe('https://gateway.example/api/v1/enforce');
  });
});

// ---------------------------------------------------------------------------
// Allow decisions
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – allow decisions', () => {
  it('returns allow with no obligations when gateway allows without obligations', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse()),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(true);
    expect(decision.obligations).toBeUndefined();
  });

  it('returns allow with obligations when gateway returns obligations', async () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['secret', 'password'] },
    ];
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(obligations)),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(true);
    expect(decision.obligations).toEqual(obligations);
  });

  it('returns allow with annotate obligation', async () => {
    const obligations: Obligation[] = [
      { type: 'annotate', key: 'classification', value: 'internal' },
    ];
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(obligations)),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(true);
    expect(decision.obligations).toEqual(obligations);
  });

  it('sets obligations to undefined when gateway returns empty obligations array', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse([])),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(true);
    // Empty array → normalized to undefined (no obligations to apply)
    expect(decision.obligations).toBeUndefined();
  });

  it('does not set denial fields on allow decision', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse()),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.reason).toBeUndefined();
    expect(decision.denialCode).toBeUndefined();
    expect(decision.conditionType).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Deny decisions
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – deny decisions', () => {
  it('returns deny with code and conditionType from gateway', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeDenyResponse('RATE_LIMIT_EXCEEDED', 'maxCalls', 'Too many calls')),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('RATE_LIMIT_EXCEEDED');
    expect(decision.conditionType).toBe('maxCalls');
    expect(decision.reason).toBe('Too many calls');
  });

  it('returns deny with details when gateway provides them', async () => {
    const responseWithDetails: EnforceResponse = {
      requestId: 'req-1',
      decision: 'deny',
      denial: {
        code: 'ARGUMENT_SCHEMA_VIOLATION',
        conditionType: 'argumentSchema',
        message: 'Invalid arguments',
        details: { path: 'args.email', expected: 'string' },
      },
      decidedAt: new Date().toISOString(),
    };

    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(responseWithDetails),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.details).toEqual({ path: 'args.email', expected: 'string' });
  });

  it('does not set obligations on deny decision', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeDenyResponse()),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.obligations).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Fail-closed error handling
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – fail-closed error handling', () => {
  it('returns deny with GATEWAY_UNAVAILABLE when network error occurs', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: errorFetcher(new Error('ECONNREFUSED')),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
    expect(decision.reason).toContain('ECONNREFUSED');
  });

  it('returns deny with GATEWAY_UNAVAILABLE when HTTP 500 returned', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: httpErrorFetcher(500),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
    expect(decision.reason).toContain('500');
  });

  it('returns deny with GATEWAY_UNAVAILABLE when HTTP 401 returned', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: httpErrorFetcher(401),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
  });

  it('returns deny with GATEWAY_UNAVAILABLE when gateway returns malformed response', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ not_a_valid_response: true }),
      }),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
  });

  it('returns deny with GATEWAY_UNAVAILABLE when response body is not an object', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => 'not-an-object',
      }),
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
  });
});

// ---------------------------------------------------------------------------
// Request wire format
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – request wire format', () => {
  it('sends the correct protocol version header', async () => {
    let capturedHeaders: Record<string, string> | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, __, headers) => {
        capturedHeaders = headers;
      }),
    });

    await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(capturedHeaders?.['X-Euno-Protocol-Version']).toBe(String(ENFORCE_PROTOCOL_VERSION));
  });

  it('sends Authorization Bearer header with apiKey', async () => {
    let capturedHeaders: Record<string, string> | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-secret-key',
      fetcher: mockFetcher(makeAllowResponse(), (_, __, headers) => {
        capturedHeaders = headers;
      }),
    });

    await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(capturedHeaders?.['Authorization']).toBe('Bearer sk-secret-key');
  });

  it('sends Content-Type application/json', async () => {
    let capturedHeaders: Record<string, string> | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, __, headers) => {
        capturedHeaders = headers;
      }),
    });

    await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(capturedHeaders?.['Content-Type']).toBe('application/json');
  });

  it('sends sessionId and toolName in request body', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    await pdp.decide(
      makeToolCallRequest('my_special_tool', { arg1: 'value1' }),
      makePdpContext({ sessionId: 'my-session-123' }),
    );

    expect(capturedBody?.sessionId).toBe('my-session-123');
    expect(capturedBody?.toolName).toBe('my_special_tool');
    expect(capturedBody?.arguments).toEqual({ arg1: 'value1' });
  });

  it('includes sourceIp from PdpContext in request context', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    await pdp.decide(
      makeToolCallRequest('my_tool'),
      makePdpContext({ sourceIp: '1.2.3.4' }),
    );

    expect(capturedBody?.context.sourceIp).toBe('1.2.3.4');
  });

  it('extracts recipients from tool arguments and includes them in context', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    await pdp.decide(
      makeToolCallRequest('send_email', {
        to: 'alice@example.com',
        cc: ['bob@example.com', 'charlie@example.com'],
      }),
      makePdpContext(),
    );

    expect(capturedBody?.context.recipients).toEqual([
      'alice@example.com',
      'bob@example.com',
      'charlie@example.com',
    ]);
  });

  it('omits recipients field when no recipient arguments are present', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    await pdp.decide(makeToolCallRequest('query_db', { sql: 'SELECT 1' }), makePdpContext());

    expect(capturedBody?.context.recipients).toBeUndefined();
  });

  it('includes context.now as an ISO-8601 string', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(capturedBody?.context.now).toBeDefined();
    expect(() => new Date(capturedBody!.context.now!)).not.toThrow();
    expect(isNaN(new Date(capturedBody!.context.now!).getTime())).toBe(false);
  });

  it('sends empty object as arguments when tool has no arguments', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => {
        capturedBody = body;
      }),
    });

    // Simulate a request with no arguments (undefined)
    const request: CallToolRequest = {
      method: 'tools/call',
      params: { name: 'my_tool' },
    };
    await pdp.decide(request, makePdpContext());

    expect(capturedBody?.arguments).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – timeout', () => {
  it('fails closed when the gateway does not respond within timeoutMs', async () => {
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      timeoutMs: 50, // very short timeout
      fetcher: async (_url, init) => {
        // Simulate a slow gateway by waiting until the AbortSignal fires.
        return new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            reject(new Error('The operation was aborted'));
          });
        });
      },
    });

    const decision = await pdp.decide(makeToolCallRequest('my_tool'), makePdpContext());

    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('GATEWAY_UNAVAILABLE');
  }, 3000);
});

// ---------------------------------------------------------------------------
// Recipient extraction edge cases
// ---------------------------------------------------------------------------

describe('RemoteEnforcerPDP – recipient extraction', () => {
  it('extracts recipients from bcc field', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => { capturedBody = body; }),
    });

    await pdp.decide(
      makeToolCallRequest('send_msg', { bcc: 'hidden@example.com' }),
      makePdpContext(),
    );

    expect(capturedBody?.context.recipients).toContain('hidden@example.com');
  });

  it('trims whitespace from recipient strings', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => { capturedBody = body; }),
    });

    await pdp.decide(
      makeToolCallRequest('send_msg', { to: '  alice@example.com  ' }),
      makePdpContext(),
    );

    expect(capturedBody?.context.recipients).toEqual(['alice@example.com']);
  });

  it('ignores empty-string recipient values', async () => {
    let capturedBody: EnforceRequest | undefined;
    const pdp = new RemoteEnforcerPDP({
      url: 'https://gateway.example',
      apiKey: 'sk-test',
      fetcher: mockFetcher(makeAllowResponse(), (_, body) => { capturedBody = body; }),
    });

    await pdp.decide(
      makeToolCallRequest('send_msg', { to: '', cc: '  ' }),
      makePdpContext(),
    );

    // Both are whitespace/empty → no recipients extracted
    expect(capturedBody?.context.recipients).toBeUndefined();
  });
});

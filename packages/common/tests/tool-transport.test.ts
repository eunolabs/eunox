/**
 * Tests for the ToolTransport abstraction:
 *   - InProcessToolTransport — in-memory dispatch
 *   - HttpToolTransport — HTTP/1.1 via fetch, including URL construction,
 *     header forwarding, DPoP proof attachment, and error handling
 */

import {
  InProcessToolTransport,
  HttpToolTransport,
  extractStructuredErrorCode,
} from '../src/tool-transport';
import type {
  ToolTransportInvokeRequest,
  ToolTransportProxyRequest,
  TransportCredentials,
  ToolTransportResponse,
} from '../src/tool-transport';

// ── Helper: build minimal credentials ────────────────────────────────────────

function creds(overrides: Partial<TransportCredentials> = {}): TransportCredentials {
  return {
    capabilityToken: 'tok-abc',
    agentId: 'agent-1',
    ...overrides,
  };
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// ── extractStructuredErrorCode ────────────────────────────────────────────────

describe('extractStructuredErrorCode', () => {
  it('extracts code from { error: { code } } envelope', () => {
    expect(extractStructuredErrorCode({ error: { code: 'EXPIRED_TOKEN' } })).toBe('EXPIRED_TOKEN');
  });

  it('extracts code from flat { code } envelope', () => {
    expect(extractStructuredErrorCode({ code: 'INVALID_REQUEST' })).toBe('INVALID_REQUEST');
  });

  it('returns undefined for missing envelope', () => {
    expect(extractStructuredErrorCode({})).toBeUndefined();
    expect(extractStructuredErrorCode(null)).toBeUndefined();
    expect(extractStructuredErrorCode('string')).toBeUndefined();
    expect(extractStructuredErrorCode(undefined)).toBeUndefined();
  });
});

// ── InProcessToolTransport ────────────────────────────────────────────────────

describe('InProcessToolTransport', () => {
  it('dispatches invokeTool to the supplied handler', async () => {
    const handler = jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>()
      .mockResolvedValue({ success: true, data: { result: 42 }, statusCode: 200 });

    const t = new InProcessToolTransport(handler);
    const req: ToolTransportInvokeRequest = { tool: 'add', args: { a: 1, b: 2 } };
    const result = await t.invokeTool(req, creds());

    expect(handler).toHaveBeenCalledWith(req, expect.objectContaining({ capabilityToken: 'tok-abc' }));
    expect(result).toMatchObject({ success: true, data: { result: 42 }, statusCode: 200 });
  });

  it('maps thrown errors in toolHandler to a 500 response (never throws)', async () => {
    const t = new InProcessToolTransport(async () => { throw new Error('handler boom'); });
    const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(500);
    expect(result.error).toContain('handler boom');
  });

  it('dispatches proxyRequest to the optional proxyHandler', async () => {
    const proxyH = jest.fn<Promise<ToolTransportResponse>, [ToolTransportProxyRequest, TransportCredentials]>()
      .mockResolvedValue({ success: true, data: 'proxy ok', statusCode: 200 });

    const t = new InProcessToolTransport(jest.fn(), proxyH);
    const req: ToolTransportProxyRequest = { method: 'GET', url: '/api/data' };
    const result = await t.proxyRequest(req, creds());

    expect(proxyH).toHaveBeenCalledWith(req, expect.any(Object));
    expect(result.success).toBe(true);
  });

  it('returns 501 from proxyRequest when no proxyHandler is configured', async () => {
    const t = new InProcessToolTransport(jest.fn()); // no proxyHandler
    const result = await t.proxyRequest({ method: 'GET', url: '/x' }, creds());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(501);
  });

  it('maps thrown errors in proxyHandler to a 500 response', async () => {
    const t = new InProcessToolTransport(
      jest.fn(),
      async () => { throw new Error('proxy boom'); },
    );
    const result = await t.proxyRequest({ method: 'DELETE', url: '/x' }, creds());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(500);
    expect(result.error).toContain('proxy boom');
  });

  it('passes credentials (including dpopSigner) to both handlers', async () => {
    const signer = jest.fn().mockResolvedValue('mock-proof');
    const toolH = jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>()
      .mockResolvedValue({ success: true, statusCode: 200 });
    const proxyH = jest.fn<Promise<ToolTransportResponse>, [ToolTransportProxyRequest, TransportCredentials]>()
      .mockResolvedValue({ success: true, statusCode: 200 });

    const t = new InProcessToolTransport(toolH, proxyH);
    const c = creds({ dpopSigner: signer });

    await t.invokeTool({ tool: 'x', args: {} }, c);
    expect((toolH.mock.calls[0]![1] as TransportCredentials).dpopSigner).toBe(signer);

    await t.proxyRequest({ method: 'GET', url: '/y' }, c);
    expect((proxyH.mock.calls[0]![1] as TransportCredentials).dpopSigner).toBe(signer);
  });
});

// ── HttpToolTransport ─────────────────────────────────────────────────────────

describe('HttpToolTransport', () => {
  it('throws when no fetch is available and none is injected', () => {
    const origFetch = (globalThis as any).fetch;
    delete (globalThis as any).fetch;
    try {
      expect(() => new HttpToolTransport('http://gw')).toThrow(/no global fetch/);
    } finally {
      (globalThis as any).fetch = origFetch;
    }
  });

  describe('invokeTool', () => {
    it('POSTs to /api/v1/tools/invoke with correct headers and body', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({ ok: true }));
      const t = new HttpToolTransport('http://gateway:3002', { fetch: fetchMock });

      await t.invokeTool({ tool: 'run', args: { x: 1 }, resource: 'api://svc/run' }, creds());

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
      expect(url).toBe('http://gateway:3002/api/v1/tools/invoke');
      expect(init.method).toBe('POST');

      const headers = init.headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer tok-abc');
      expect(headers['X-Agent-ID']).toBe('agent-1');
      expect(headers['Content-Type']).toBe('application/json');

      const body = JSON.parse(init.body as string);
      expect(body).toMatchObject({ tool: 'run', args: { x: 1 }, resource: 'api://svc/run' });
    });

    it('omits resource from body when not provided', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.invokeTool({ tool: 'x', args: {} }, creds());

      const body = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
      expect(body).not.toHaveProperty('resource');
    });

    it('calls dpopSigner with POST + absolute URL and attaches DPoP header', async () => {
      const dpopSigner = jest.fn().mockResolvedValue('proof-abc');
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gateway:3002', { fetch: fetchMock });

      await t.invokeTool({ tool: 'x', args: {} }, creds({ dpopSigner }));

      expect(dpopSigner).toHaveBeenCalledWith('POST', 'http://gateway:3002/api/v1/tools/invoke');
      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['DPoP']).toBe('proof-abc');
    });

    it('merges additionalHeaders into the request', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.invokeTool({ tool: 'x', args: {} }, creds({
        additionalHeaders: { 'traceparent': '00-abc-01', 'tracestate': 'k=v' },
      }));

      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['traceparent']).toBe('00-abc-01');
      expect(headers['tracestate']).toBe('k=v');
    });

    it('additionalHeaders cannot override Authorization, X-Agent-ID, or DPoP', async () => {
      const dpopSigner = jest.fn().mockResolvedValue('real-proof');
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.invokeTool({ tool: 'x', args: {} }, creds({
        dpopSigner,
        additionalHeaders: {
          'Authorization': 'Bearer injected-bad-token',
          'X-Agent-ID': 'evil-agent',
          'DPoP': 'injected-fake-proof',
        },
      }));

      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      // Transport-owned headers must win.
      expect(headers['Authorization']).toBe('Bearer tok-abc');
      expect(headers['X-Agent-ID']).toBe('agent-1');
      expect(headers['DPoP']).toBe('real-proof');
    });

    it('returns statusCode=500 when dpopSigner throws (never throws)', async () => {
      const dpopSigner = jest.fn().mockRejectedValue(new Error('key expired'));
      const fetchMock = jest.fn();
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds({ dpopSigner }));

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(500);
      expect(result.error).toContain('key expired');
      // fetch must not be called when signer failed.
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('returns success=true for 200 response', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({ result: 'ok' }));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(result.success).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(result.data).toMatchObject({ result: 'ok' });
    });

    it('returns success=false for 403 with structured error code', async () => {
      const fetchMock = jest.fn().mockResolvedValue(
        jsonResp({ error: { code: 'AUTHORIZATION_FAILED', message: 'Denied' } }, 403),
      );
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(403);
      expect(result.errorCode).toBe('AUTHORIZATION_FAILED');
      expect(result.error).toBe('Denied');
    });

    it('returns success=false with statusCode=500 on network error (never throws)', async () => {
      const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(500);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('strips trailing slash from gatewayUrl', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw/', { fetch: fetchMock });

      await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(fetchMock.mock.calls[0]![0]).toBe('http://gw/api/v1/tools/invoke');
    });
  });

  describe('proxyRequest – absolute URL', () => {
    it('forwards to /proxy/{host}{path} with X-Target-Host and X-Target-Scheme', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gateway:3002', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: 'http://api.example.com/data/items' }, creds());

      const [url, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
      expect(url).toBe('http://gateway:3002/proxy/api.example.com/data/items');
      expect(init.method).toBe('GET');
      const headers = init.headers as Record<string, string>;
      expect(headers['X-Target-Host']).toBe('api.example.com');
      expect(headers['X-Target-Scheme']).toBe('http');
    });

    it('includes port in host segment for non-default ports', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: 'https://api.example.com:8443/v1/data' }, creds());

      const [url, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
      expect(url).toBe('http://gw/proxy/api.example.com:8443/v1/data');
      const headers = init.headers as Record<string, string>;
      expect(headers['X-Target-Host']).toBe('api.example.com:8443');
      expect(headers['X-Target-Scheme']).toBe('https');
    });

    it('preserves query string from absolute URL', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: 'https://api.example.com/search?q=hello' }, creds());

      expect(fetchMock.mock.calls[0]![0]).toBe('http://gw/proxy/api.example.com/search?q=hello');
    });

    it('calls dpopSigner with the derived proxy URL', async () => {
      const dpopSigner = jest.fn().mockResolvedValue('dpop-proxy');
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: 'https://api.example.com/data' }, creds({ dpopSigner }));

      expect(dpopSigner).toHaveBeenCalledWith('GET', 'http://gw/proxy/api.example.com/data');
      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['DPoP']).toBe('dpop-proxy');
    });

    it('additionalHeaders cannot override Authorization, X-Agent-ID, X-Target-Host, or DPoP', async () => {
      const dpopSigner = jest.fn().mockResolvedValue('real-dpop');
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest(
        { method: 'GET', url: 'https://api.example.com/data' },
        creds({
          dpopSigner,
          additionalHeaders: {
            'Authorization': 'Bearer injected-bad',
            'X-Agent-ID': 'evil',
            'X-Target-Host': 'evil.host',
            'DPoP': 'injected-fake',
          },
        }),
      );

      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer tok-abc');
      expect(headers['X-Agent-ID']).toBe('agent-1');
      expect(headers['X-Target-Host']).toBe('api.example.com');
      expect(headers['DPoP']).toBe('real-dpop');
    });

    it('returns statusCode=500 when dpopSigner throws (never throws)', async () => {
      const dpopSigner = jest.fn().mockRejectedValue(new Error('signing failed'));
      const fetchMock = jest.fn();
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.proxyRequest(
        { method: 'GET', url: 'https://api.example.com/data' },
        creds({ dpopSigner }),
      );

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(500);
      expect(result.error).toContain('signing failed');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('returns statusCode=400 on invalid proxy URL (never throws)', async () => {
      const fetchMock = jest.fn();
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      // 'https://' (no host) is accepted by the /^https?:\/\//i regex but
      // rejected by the WHATWG URL parser, causing buildProxyPath to throw.
      const result = await t.proxyRequest(
        { method: 'GET', url: 'https://' },
        creds(),
      );
      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(400);
      expect(result.error).toMatch(/Invalid proxy target URL/);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe('proxyRequest – relative path', () => {
    it('forwards to /proxy{path} for relative paths starting with /', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'POST', url: '/internal/resource' }, creds());

      expect(fetchMock.mock.calls[0]![0]).toBe('http://gw/proxy/internal/resource');
    });

    it('prepends / to bare relative paths', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: 'no-leading-slash' }, creds());

      expect(fetchMock.mock.calls[0]![0]).toBe('http://gw/proxy/no-leading-slash');
    });

    it('does NOT set X-Target-Host for relative paths', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: '/local/path' }, creds());

      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['X-Target-Host']).toBeUndefined();
      expect(headers['X-Target-Scheme']).toBeUndefined();
    });
  });

  describe('proxyRequest – body and Content-Type', () => {
    it('sets Content-Type and serialises body when data is provided', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'POST', url: '/api', data: { key: 'val' } }, creds());

      const init = fetchMock.mock.calls[0]![1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers['Content-Type']).toBe('application/json');
      expect(JSON.parse(init.body as string)).toMatchObject({ key: 'val' });
    });

    it('does NOT set Content-Type when no data (e.g. GET request)', async () => {
      const fetchMock = jest.fn().mockResolvedValue(jsonResp({}));
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      await t.proxyRequest({ method: 'GET', url: '/api' }, creds());

      const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers['Content-Type']).toBeUndefined();
    });
  });

  describe('response parsing', () => {
    it('parses plain-text response bodies when Content-Type is not JSON', async () => {
      const fetchMock = jest.fn().mockResolvedValue(
        new Response('plain text', { status: 200, headers: { 'content-type': 'text/plain' } }),
      );
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(result.success).toBe(true);
      expect(result.data).toBe('plain text');
    });

    it('returns error field from flat { message } body', async () => {
      const fetchMock = jest.fn().mockResolvedValue(
        jsonResp({ message: 'Something went wrong' }, 500),
      );
      const t = new HttpToolTransport('http://gw', { fetch: fetchMock });

      const result = await t.invokeTool({ tool: 'x', args: {} }, creds());

      expect(result.success).toBe(false);
      expect(result.error).toBe('Something went wrong');
    });
  });
});

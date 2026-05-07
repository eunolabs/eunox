/**
 * ToolTransport — protocol-agnostic abstraction for agent↔gateway communication.
 *
 * Decouples the agent runtime from the gateway's HTTP wire shape so the proxy
 * protocol can evolve (gRPC streaming, mTLS, request signing) without a
 * corresponding agent-runtime release.
 *
 * Two built-in implementations are provided:
 *   - {@link HttpToolTransport} — default; HTTP/1.1 via the Node `fetch` API,
 *     consistent with the `createOpaHttpBackend` pattern already used in this
 *     package.
 *   - {@link InProcessToolTransport} — in-memory dispatch; useful for unit
 *     tests and co-located deployments where the runtime is in the same
 *     process as the gateway.
 */

// ── Shared types ─────────────────────────────────────────────────────────────

/**
 * Uniform response shape returned by every {@link ToolTransport} call.
 *
 * Transport implementations MUST map all outcomes — including network errors
 * and timeouts — to this shape and MUST NOT throw.
 */
export interface ToolTransportResponse {
  /** `true` when the gateway returned a 2xx status. */
  success: boolean;
  /** Parsed response body, when available. */
  data?: unknown;
  /** Human-readable error summary for non-2xx responses. */
  error?: string;
  /** HTTP status code (or 500 for client-side failures such as timeouts). */
  statusCode: number;
  /**
   * Structured error code extracted from the gateway error envelope
   * (`{ error: { code, message } }`).  Lets callers distinguish
   * recoverable failures (e.g. `EXPIRED_TOKEN` → refresh+retry) from
   * terminal ones (`AGENT_TERMINATED` → stop refreshing) without
   * string-matching error messages.
   */
  errorCode?: string;
}

/** Parameters for a named tool invocation. */
export interface ToolTransportInvokeRequest {
  tool: string;
  args: Record<string, unknown>;
  resource?: string;
}

/**
 * Parameters for a raw HTTP proxy call.
 *
 * `url` may be an absolute `http(s)://` URL (the host is extracted and
 * forwarded as `X-Target-Host` so the gateway can derive a host-qualified
 * capability resource) or a relative path (forwarded as-is under the
 * `/proxy` mount point).
 */
export interface ToolTransportProxyRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  data?: unknown;
}

/**
 * Credentials the transport attaches to every outbound request.
 *
 * `dpopSigner`, when provided, is called by the transport with the **actual**
 * HTTP method and URL it is about to use so the proof is bound to the real
 * outbound request.  Different transport implementations bind the proof
 * differently (HTTP `DPoP` header vs gRPC metadata) but the signer contract
 * is transport-agnostic.
 *
 * `additionalHeaders` carries any extra headers the caller wants forwarded
 * verbatim (e.g. W3C trace context headers injected by the runtime).
 * HTTP transports merge them into the request headers; other transports
 * may map them to their equivalent propagation mechanism.
 */
export interface TransportCredentials {
  /** Short-lived capability token acquired from the Capability Issuer. */
  capabilityToken: string;
  /** Agent identifier forwarded as `X-Agent-ID`. */
  agentId: string;
  /**
   * Optional DPoP signer.  When present the transport MUST call
   * `dpopSigner(method, url)` and attach the returned compact JWS as the
   * `DPoP` request header (HTTP) or equivalent metadata field (gRPC).
   */
  dpopSigner?: (method: string, url: string) => Promise<string>;
  /**
   * Additional headers to merge verbatim into the outbound request.
   * Typical use: W3C `traceparent` / `tracestate` for distributed tracing.
   */
  additionalHeaders?: Record<string, string>;
}

// ── Interface ─────────────────────────────────────────────────────────────────

/**
 * Protocol-agnostic interface for sending tool calls to the gateway.
 *
 * Implementations MUST:
 * - Never throw; map all errors to {@link ToolTransportResponse}.
 * - Call `credentials.dpopSigner` (when present) with the actual outbound
 *   method + URL and attach the resulting proof appropriately.
 * - Forward `credentials.additionalHeaders` (when present) to the
 *   corresponding propagation mechanism of the underlying protocol.
 */
export interface ToolTransport {
  /**
   * Invoke a named tool through the gateway.
   *
   * Maps to `POST {gateway}/api/v1/tools/invoke` in the default HTTP
   * implementation; future implementations may use a dedicated gRPC
   * stream or an in-process call.
   */
  invokeTool(
    request: ToolTransportInvokeRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse>;

  /**
   * Forward a raw HTTP request through the gateway's proxy endpoint.
   *
   * Maps to `{method} {gateway}/proxy/{derivedPath}` in the default HTTP
   * implementation.  A gRPC implementation would tunnel the request over a
   * streaming RPC; an in-process implementation dispatches directly.
   */
  proxyRequest(
    request: ToolTransportProxyRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse>;
}

// ── InProcessToolTransport ────────────────────────────────────────────────────

/**
 * Handler signature for {@link InProcessToolTransport} tool invocations.
 */
export type InProcessToolHandler = (
  request: ToolTransportInvokeRequest,
  credentials: TransportCredentials,
) => Promise<ToolTransportResponse> | ToolTransportResponse;

/**
 * Handler signature for {@link InProcessToolTransport} proxy requests.
 */
export type InProcessProxyHandler = (
  request: ToolTransportProxyRequest,
  credentials: TransportCredentials,
) => Promise<ToolTransportResponse> | ToolTransportResponse;

/**
 * In-process transport: dispatches calls to caller-supplied handler functions
 * without any network I/O.
 *
 * Intended for:
 *   - Unit tests — inject exact responses without spinning an HTTP server.
 *   - Co-located deployments — when the runtime and gateway are embedded in
 *     the same process and a direct function call is cheaper than a loopback
 *     HTTP round-trip.
 */
export class InProcessToolTransport implements ToolTransport {
  constructor(
    private readonly toolHandler: InProcessToolHandler,
    private readonly _proxyHandler?: InProcessProxyHandler,
  ) {}

  async invokeTool(
    request: ToolTransportInvokeRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse> {
    try {
      return await this.toolHandler(request, credentials);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      };
    }
  }

  async proxyRequest(
    request: ToolTransportProxyRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse> {
    if (!this._proxyHandler) {
      return {
        success: false,
        error: 'InProcessToolTransport: no proxyHandler configured',
        statusCode: 501,
      };
    }
    try {
      return await this._proxyHandler(request, credentials);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      };
    }
  }
}

// ── HttpToolTransport ─────────────────────────────────────────────────────────

/**
 * Construction options for {@link HttpToolTransport}.
 */
export interface HttpToolTransportOptions {
  /**
   * Override the global `fetch` used for gateway calls.
   *
   * Inject a stub here in tests; production deployments leave it unset and
   * pick up the Node 18+ built-in, matching the pattern used by
   * {@link createOpaHttpBackend}.
   */
  fetch?: typeof globalThis.fetch;
  /**
   * Per-request timeout in milliseconds.  After this duration the
   * `AbortController` fires and the in-flight request is cancelled.
   *
   * Default: 30 000 ms.
   */
  timeoutMs?: number;
}

/**
 * HTTP/1.1 implementation of {@link ToolTransport}.
 *
 * Wire shape:
 * - `invokeTool` → `POST {gatewayUrl}/api/v1/tools/invoke`
 * - `proxyRequest` → `{method} {gatewayUrl}/proxy/{derivedPath}`
 *   with `X-Target-Host` and `X-Target-Scheme` headers for absolute-URL
 *   targets, enabling the gateway to derive host-qualified capability resources.
 *
 * Uses the Node 18+ built-in `fetch` API (or an injected override) so this
 * module has no dependency on any HTTP client library.
 */
export class HttpToolTransport implements ToolTransport {
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;

  constructor(
    private readonly gatewayUrl: string,
    opts: HttpToolTransportOptions = {},
  ) {
    const fetchImpl = opts.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      throw new Error(
        'HttpToolTransport: no global fetch available; pass { fetch } explicitly',
      );
    }
    this.fetchImpl = fetchImpl;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  async invokeTool(
    request: ToolTransportInvokeRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse> {
    const path = '/api/v1/tools/invoke';
    const url = this.absoluteUrl(path);

    let dpopHeaders: Record<string, string> = {};
    if (credentials.dpopSigner) {
      try {
        dpopHeaders = { DPoP: await credentials.dpopSigner('POST', url) };
      } catch (error) {
        return {
          success: false,
          error: `DPoP proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
          statusCode: 500,
        };
      }
    }

    // additionalHeaders are merged FIRST so that transport-owned security
    // headers (Authorization, X-Agent-ID, DPoP) always take precedence and
    // cannot be overridden by callers.
    const headers: Record<string, string> = {
      ...(credentials.additionalHeaders ?? {}),
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${credentials.capabilityToken}`,
      'X-Agent-ID': credentials.agentId,
      ...dpopHeaders,
    };

    return this.send('POST', url, headers, {
      tool: request.tool,
      args: request.args,
      ...(request.resource !== undefined ? { resource: request.resource } : {}),
    });
  }

  async proxyRequest(
    request: ToolTransportProxyRequest,
    credentials: TransportCredentials,
  ): Promise<ToolTransportResponse> {
    let proxyPath: string;
    let extraHeaders: Record<string, string>;
    try {
      ({ proxyPath, extraHeaders } = this.buildProxyPath(request.url));
    } catch (error) {
      return {
        success: false,
        error: `Invalid proxy target URL: ${error instanceof Error ? error.message : String(error)}`,
        statusCode: 400,
      };
    }

    const url = this.absoluteUrl(proxyPath);

    let dpopHeaders: Record<string, string> = {};
    if (credentials.dpopSigner) {
      try {
        dpopHeaders = { DPoP: await credentials.dpopSigner(request.method, url) };
      } catch (error) {
        return {
          success: false,
          error: `DPoP proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
          statusCode: 500,
        };
      }
    }

    // additionalHeaders are merged FIRST so that transport-owned security and
    // routing headers (Authorization, X-Agent-ID, X-Target-*, DPoP) always
    // take precedence and cannot be overridden by callers.
    const headers: Record<string, string> = {
      ...(credentials.additionalHeaders ?? {}),
      'Authorization': `Bearer ${credentials.capabilityToken}`,
      'X-Agent-ID': credentials.agentId,
      ...extraHeaders,
      ...dpopHeaders,
    };
    if (request.data !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    return this.send(request.method, url, headers, request.data);
  }

  // ── private helpers ──────────────────────────────────────────────────────

  /**
   * Derive the gateway-relative proxy path and target-host headers from a
   * caller-supplied URL string.
   *
   * Absolute `http(s)://` URLs are encoded as `/proxy/{host}{path}` so the
   * gateway can bind the validated capability to the intended backend host.
   * Relative paths are forwarded as `/proxy{path}`.
   */
  private buildProxyPath(url: string): {
    proxyPath: string;
    extraHeaders: Record<string, string>;
  } {
    if (/^https?:\/\//i.test(url)) {
      const targetUrl = new URL(url);
      const hostSegment = targetUrl.host; // includes port when non-default
      const pathAndQuery = targetUrl.pathname + targetUrl.search;
      return {
        proxyPath: `/proxy/${hostSegment}${pathAndQuery}`,
        extraHeaders: {
          'X-Target-Host': hostSegment,
          'X-Target-Scheme': targetUrl.protocol.replace(/:$/, ''),
        },
      };
    }
    const path = url.startsWith('/') ? url : `/${url}`;
    return { proxyPath: `/proxy${path}`, extraHeaders: {} };
  }

  /** Compose `gatewayUrl` with a path without doubling slashes. */
  private absoluteUrl(path: string): string {
    const base = this.gatewayUrl.replace(/\/+$/, '');
    const tail = path.startsWith('/') ? path : `/${path}`;
    return `${base}${tail}`;
  }

  /** Fire the fetch request and map the result to {@link ToolTransportResponse}. */
  private async send(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: unknown,
  ): Promise<ToolTransportResponse> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: ac.signal,
      });
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      };
    } finally {
      clearTimeout(timer);
    }

    return this.parseResponse(response);
  }

  /**
   * Parse the fetch {@link Response} into a {@link ToolTransportResponse}.
   *
   * Prefers JSON (`application/json` content-type); falls back to plain text.
   */
  private async parseResponse(response: Response): Promise<ToolTransportResponse> {
    let data: unknown;
    const contentType = response.headers.get('content-type') ?? '';
    try {
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }
    } catch {
      // Unparseable body — leave data undefined.
    }

    const errorCode = extractStructuredErrorCode(data);
    return {
      success: response.status >= 200 && response.status < 300,
      data,
      error:
        response.status >= 400
          ? ((data as any)?.error?.message ??
            (data as any)?.error ??
            (data as any)?.message ??
            undefined)
          : undefined,
      statusCode: response.status,
      errorCode,
    };
  }
}

// ── Shared helper (also used by InProcessToolTransport callers) ───────────────

/**
 * Extract the structured gateway error code from a response body.
 *
 * Supports two gateway envelope shapes:
 *   - `{ error: { code: string, message?: string } }` (preferred, new)
 *   - `{ code: string }` (legacy flat shape)
 *
 * Returns `undefined` when neither shape is present or the body is not an
 * object, so callers can fall back gracefully.
 *
 * @internal exported for use by {@link HttpToolTransport} and unit tests.
 */
export function extractStructuredErrorCode(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const d = data as Record<string, unknown>;
  const err = d['error'];
  if (
    err &&
    typeof err === 'object' &&
    typeof (err as Record<string, unknown>)['code'] === 'string'
  ) {
    return (err as { code: string }).code;
  }
  if (typeof d['code'] === 'string') {
    return d['code'];
  }
  return undefined;
}

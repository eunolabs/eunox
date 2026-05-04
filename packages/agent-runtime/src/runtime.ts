/**
 * Agent Runtime Environment
 *
 * Provides a sandboxed execution environment for AI agents with:
 * - Network egress restrictions (all traffic routed through Tool Gateway)
 * - Capability token management
 * - Secure tool invocation
 */

import axios, { AxiosInstance } from 'axios';
import {
  CapabilityError,
  ErrorCode,
  CapabilityConstraint,
  AgentCapabilityManifest,
  UserConsent,
  getTracer,
  withSpan,
  injectTraceContext,
  EUNO_ATTR,
  SpanKind,
  computeJwkThumbprint,
  createDpopProof,
} from '@euno/common';
import type { JWK, KeyLike } from 'jose';

/**
 * Async provider for short-lived user authentication tokens.
 *
 * Production multi-tenant deployments should plug in an OBO
 * (on-behalf-of) / federated-token exchange here so the agent runtime
 * never persists a long-lived OIDC token in memory: each call returns a
 * freshly-minted, narrowly-scoped assertion that the issuer can validate.
 *
 * If both `authToken` and `authTokenProvider` are supplied, the provider
 * takes precedence and the static `authToken` is ignored.
 */
export type AuthTokenProvider = () => Promise<string>;

/**
 * Per-issuance hints supplied to the Capability Issuer alongside `agentId`.
 *
 * The runtime forwards every populated field to `POST /api/v1/issue`, so
 * deployments can opt into the issuer's manifest- and consent-based
 * issuance hardening (including strict `REQUIRE_USER_CONSENT=true` mode)
 * without bypassing the runtime's refresh / retry logic.
 *
 * Returned synchronously or asynchronously by {@link IssuanceHintsProvider}
 * so callers can mint fresh consent receipts per refresh if they wish.
 */
export interface IssuanceHints {
  /** Specific capabilities the runtime is requesting (subset of role/manifest). */
  requestedCapabilities?: CapabilityConstraint[];
  /** Agent capability manifest — declarative upper bound enforced by the issuer. */
  manifest?: AgentCapabilityManifest;
  /** Explicit user consent record bound to (userId, agentId). */
  consent?: UserConsent;
}

/**
 * Async provider for {@link IssuanceHints}.  Invoked on every issuance and
 * refresh so deployments can supply freshly-signed consent receipts that
 * expire on a tighter schedule than the capability token itself.
 */
export type IssuanceHintsProvider = () => Promise<IssuanceHints> | IssuanceHints;

export interface AgentRuntimeConfig {
  /** Agent identifier */
  agentId: string;

  /** Tool Gateway endpoint (all external calls go through here) */
  gatewayUrl: string;

  /** Capability Issuer endpoint for token acquisition */
  issuerUrl: string;

  /**
   * Initial authentication token (Azure AD token, etc.). Required to
   * authenticate with the Capability Issuer when no
   * {@link authTokenProvider} is configured.
   *
   * NOTE: storing a long-lived user OIDC token in the runtime turns the
   * agent process into a high-value secret holder. Prefer
   * {@link authTokenProvider} which fetches a short-lived token on demand
   * (e.g. via OBO / STS exchange) and avoids in-memory persistence
   * between refresh cycles.
   */
  authToken?: string;

  /**
   * Async provider for fresh, short-lived user assertions. Called on
   * every capability acquisition / refresh; the returned token is used
   * once and not retained.  When supplied, takes precedence over
   * {@link authToken}.
   */
  authTokenProvider?: AuthTokenProvider;

  /**
   * Static issuance hints (`requestedCapabilities`, `manifest`, `consent`)
   * forwarded on every `/api/v1/issue` call.  Use this for deployments
   * that have a fixed manifest and a long-lived consent receipt.
   *
   * If both {@link issuanceHints} and {@link issuanceHintsProvider} are
   * supplied, the provider takes precedence so callers can rotate consent
   * per refresh.
   */
  issuanceHints?: IssuanceHints;

  /**
   * Async provider invoked on every issuance / refresh to produce fresh
   * issuance hints (e.g. a newly-signed consent receipt). Required when
   * the issuer is configured with `REQUIRE_USER_CONSENT=true` *and* the
   * caller wants per-refresh consent rotation.
   */
  issuanceHintsProvider?: IssuanceHintsProvider;

  /** Token refresh interval in seconds (default: 600s = 10 minutes) */
  tokenRefreshInterval?: number;

  /**
   * Optional DPoP (RFC 9449 / F-2) configuration. When supplied the
   * runtime asks the issuer to mint a sender-constrained capability
   * token bound to {@link DpopConfig.publicJwk}, and signs a fresh
   * proof with {@link DpopConfig.privateKey} on every call to the
   * gateway.
   *
   * When omitted, the runtime falls back to plain bearer-token usage
   * (current behaviour, kept for back-compat).
   *
   * Holding the private key inside the runtime process is the entire
   * point: an attacker who exfiltrates only the bearer token cannot
   * use it without also stealing the key.
   */
  dpop?: DpopConfig;
}

/**
 * DPoP keypair material the runtime uses to (a) request a
 * sender-constrained capability token from the issuer and (b) sign a
 * proof on every outbound gateway / proxy call.
 *
 * Production deployments should generate the keypair locally at
 * process start (`jose.generateKeyPair`) and never persist the
 * private key to disk. The public JWK is sent to the issuer once
 * per token-acquisition cycle.
 */
export interface DpopConfig {
  /** Private key handle used to sign proofs (e.g. `crypto.KeyObject`). */
  privateKey: KeyLike | Uint8Array;
  /** Public JWK whose SHA-256 thumbprint will become the token's `cnf.jkt`. */
  publicJwk: JWK;
  /**
   * JWS algorithm — must agree with the key type. Defaults to
   * `'ES256'` (P-256 ECDSA), which the gateway and most cloud KMS
   * providers all accept out of the box.
   */
  algorithm?: string;
}

export interface ToolCallRequest {
  /** Tool/action name */
  tool: string;

  /** Tool arguments */
  args: Record<string, unknown>;

  /** Target resource/endpoint */
  resource?: string;
}

export interface ToolCallResponse {
  /** Success status */
  success: boolean;

  /** Response data */
  data?: unknown;

  /** Error message if failed */
  error?: string;

  /** HTTP status code */
  statusCode: number;

  /**
   * Structured error code from the gateway/issuer (e.g. `EXPIRED_TOKEN`,
   * `TOKEN_REVOKED`, `AGENT_TERMINATED`), when one was returned. Lets
   * callers distinguish recoverable failures (refresh & retry) from
   * terminal ones (kill switch, explicit revocation) without parsing
   * error messages.
   */
  errorCode?: string;
}

/**
 * AgentRuntime - Sandboxed execution environment for AI agents
 *
 * Sprint 1 Requirements:
 * - Network isolation: All external calls go through Tool Gateway
 * - Capability token management: Automatic acquisition and refresh
 * - Secure tool invocation: Attach capability tokens to all requests
 *
 * Sprint 2 Requirements:
 * - Network interception: Ensure ALL HTTP traffic routes through gateway
 * - Token refresh: Handle expiration and re-acquisition
 */
export class AgentRuntime {
  private config: AgentRuntimeConfig;
  private capabilityToken?: string;
  private httpClient: AxiosInstance;
  private tokenRefreshTimer?: NodeJS.Timeout;
  /** AbortController used to cancel any in-flight token acquisition during
   *  shutdown so a refresh racing with shutdown does not resurrect state. */
  private acquireAbortController?: AbortController;
  /** Promise of the currently running token acquisition, if any. Awaited by
   *  shutdown so callers know the in-flight request has fully settled. */
  private pendingAcquire?: Promise<void>;
  /** Set once {@link shutdown} has been invoked; used to short-circuit any
   *  scheduled refresh callback or 401 retry. */
  private shuttingDown = false;
  /**
   * Set to `true` once the gateway has reported that this agent/session has
   * been killed via the control-plane kill switch.  When set, the periodic
   * refresh loop is halted and subsequent tool invocations fail fast — any
   * new capability token would be blocked by the same kill switch, so
   * refreshing is pointless and simply leaks a "doomed" token.
   */
  private terminated: boolean = false;

  /**
   * Cached SHA-256 JWK thumbprint of the agent's DPoP public key
   * (RFC 7638 / F-2). Computed once in {@link initialize} so we don't
   * pay the hashing cost on every issuance refresh. Undefined when
   * DPoP is not configured.
   */
  private dpopJkt?: string;

  /**
   * Tracer used for client spans around outbound issuer / gateway / proxy
   * calls (R-3 in `docs/IMPROVEMENTS_AND_REFACTORING.md`). Always set;
   * resolves to a no-op tracer when no SDK has been registered.
   */
  private tracer = getTracer('agent-runtime');

  constructor(config: AgentRuntimeConfig) {
    if (!config.authToken && !config.authTokenProvider) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'AgentRuntime requires either authToken or authTokenProvider',
        400
      );
    }

    this.config = {
      tokenRefreshInterval: 600, // 10 minutes default
      ...config,
    };

    // Create HTTP client that routes ALL requests through gateway
    this.httpClient = axios.create({
      baseURL: this.config.gatewayUrl,
      timeout: 30000,
      validateStatus: () => true, // Handle all status codes manually
    });

    // R-3: inject the active trace context (W3C `traceparent` / `tracestate`)
    // on every outbound gateway request so the gateway's tracingMiddleware
    // joins the same trace as the agent-side client span. No-op when no
    // SDK is registered (the inject call sees an invalid context and
    // writes nothing).
    this.httpClient.interceptors.request.use((req) => {
      const headers = (req.headers ?? {}) as Record<string, string>;
      injectTraceContext(headers);
      req.headers = headers as typeof req.headers;
      return req;
    });
  }

  /**
   * Initialize the runtime - acquire capability token
   */
  async initialize(): Promise<void> {
    // F-2: precompute the DPoP key thumbprint so the issuer can bind
    // `cnf.jkt` on every refresh without re-hashing.
    if (this.config.dpop) {
      this.dpopJkt = await computeJwkThumbprint(this.config.dpop.publicJwk);
    }
    await this.acquireCapabilityToken();
    this.startTokenRefresh();
  }

  /**
   * Shutdown the runtime - cleanup resources and cancel in-flight work.
   *
   * Aborts any acquireCapabilityToken request currently in flight (so a
   * shutdown that races with a periodic refresh cannot leave a settled-after-
   * shutdown promise to clobber state) and refuses any further refresh or
   * retry attempts.
   */
  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    if (this.tokenRefreshTimer) {
      clearTimeout(this.tokenRefreshTimer);
      this.tokenRefreshTimer = undefined;
    }
    if (this.acquireAbortController) {
      this.acquireAbortController.abort();
    }
    // Wait for the in-flight acquisition (if any) to settle before returning,
    // so the caller is guaranteed no further state mutation will happen.
    if (this.pendingAcquire) {
      try {
        await this.pendingAcquire;
      } catch {
        // The aborted request will reject; that's expected during shutdown.
      }
    }
  }

  /**
   * Returns whether the agent has been terminated by the control plane.
   */
  isTerminated(): boolean {
    return this.terminated;
  }

  /**
   * Resolve the user authentication token used to authenticate to the
   * Capability Issuer.  Prefers the async provider (recommended for OBO /
   * federated short-lived tokens) over the static config value.
   *
   * The returned token is intentionally not cached on the instance so the
   * runtime never holds a user assertion longer than a single issuance call.
   */
  private async resolveAuthToken(): Promise<string> {
    if (this.config.authTokenProvider) {
      const token = await this.config.authTokenProvider();
      if (!token) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'authTokenProvider returned an empty token',
          401
        );
      }
      return token;
    }
    if (!this.config.authToken) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'No authToken or authTokenProvider configured',
        401
      );
    }
    return this.config.authToken;
  }

  /**
   * Resolve issuance hints (`requestedCapabilities` / `manifest` / `consent`)
   * to send with the issuance request.  The async provider takes precedence
   * over the static config so deployments can rotate consent receipts on
   * every refresh.
   */
  private async resolveIssuanceHints(): Promise<IssuanceHints> {
    if (this.config.issuanceHintsProvider) {
      const hints = await this.config.issuanceHintsProvider();
      return hints ?? {};
    }
    return this.config.issuanceHints ?? {};
  }

  /**
   * Acquire a capability token from the Issuer
   */
  private async acquireCapabilityToken(): Promise<void> {
    if (this.shuttingDown) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'AgentRuntime is shutting down; refusing to acquire capability token',
        500
      );
    }
    if (this.terminated) {
      throw new CapabilityError(
        ErrorCode.AGENT_TERMINATED,
        'Agent has been terminated by the control plane; refusing to acquire a new capability token',
        403
      );
    }

    // Single-flight: if an acquisition is already in progress, return the
    // same promise instead of spawning a second concurrent request.  This
    // prevents the periodic refresh and a concurrent 401-triggered refresh
    // from each creating their own AbortController/promise and causing
    // shutdown() to only abort/await the most-recent one.
    if (this.pendingAcquire) {
      return this.pendingAcquire;
    }

    // Track this acquisition so shutdown() can abort + await it.
    const controller = new AbortController();
    this.acquireAbortController = controller;

    const run = async (): Promise<void> => {
      const issuerClient = axios.create({
        baseURL: this.config.issuerUrl,
        timeout: 10000,
        validateStatus: () => true, // Handle all status codes manually
      });

      // R-3: also propagate trace context onto issuer requests.
      issuerClient.interceptors.request.use((req) => {
        const headers = (req.headers ?? {}) as Record<string, string>;
        injectTraceContext(headers);
        req.headers = headers as typeof req.headers;
        return req;
      });

      const userAuthToken = await this.resolveAuthToken();
      const hints = await this.resolveIssuanceHints();

      // Build the request body.  Only include hint fields that were actually
      // supplied so we don't accidentally send `undefined`/`null` values that
      // the issuer's input validators might choke on.
      const body: Record<string, unknown> = { agentId: this.config.agentId };
      if (hints.requestedCapabilities !== undefined) {
        body.requestedCapabilities = hints.requestedCapabilities;
      }
      if (hints.manifest !== undefined) {
        body.manifest = hints.manifest;
      }
      if (hints.consent !== undefined) {
        body.consent = hints.consent;
      }
      // F-2: ask the issuer to bind the token to our DPoP key. We
      // send the precomputed thumbprint to keep the issuer fast (and
      // because some issuer deployments may not import the same `jose`
      // version we did locally). The thumbprint is computed once at
      // construction time and reused for every refresh.
      if (this.dpopJkt !== undefined) {
        body.dpopJkt = this.dpopJkt;
      }

      let response;
      try {
        response = await issuerClient.post('/api/v1/issue', body, {
          headers: {
            'Authorization': `Bearer ${userAuthToken}`,
          },
          signal: controller.signal,
        });
      } catch (error) {
        if (controller.signal.aborted) {
          throw new CapabilityError(
            ErrorCode.INTERNAL_ERROR,
            'Capability token acquisition aborted (runtime shutting down)',
            500
          );
        }
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `Network error contacting Capability Issuer: ${error instanceof Error ? error.message : String(error)}`,
          500
        );
      }

      // If shutdown completed while the network call was in flight, do not
      // mutate state — discard the response.
      if (this.shuttingDown) {
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          'AgentRuntime shut down during token acquisition',
          500
        );
      }

      if (response.status === 401 || response.status === 403) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          `Capability Issuer rejected authentication (HTTP ${response.status})`,
          response.status
        );
      }

      if (response.status !== 200 || !response.data?.token) {
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `Failed to acquire capability token: HTTP ${response.status}`,
          500
        );
      }

      this.capabilityToken = response.data.token;
    };

    const acquirePromise = withSpan(
      this.tracer,
      'agent-runtime.acquireCapabilityToken',
      {
        [EUNO_ATTR.AGENT_ID]: this.config.agentId,
        [EUNO_ATTR.SERVICE]: 'agent-runtime',
      },
      async (span) => {
        // `withSpan` already records exceptions and stamps
        // `euno.outcome = "error"` on a thrown error before re-throwing,
        // so the success-path attribute is the only thing we need to
        // add ourselves here.
        await run();
        span.setAttribute(EUNO_ATTR.OUTCOME, 'success');
      },
      SpanKind.CLIENT,
    );
    // Capture the wrapped promise so the .finally() callback can compare by
    // reference against the *same* object stored in this.pendingAcquire.
    // Previously the callback compared against `acquirePromise` (the unwrapped
    // run() promise), which is a different object from `acquirePromise.finally()`
    // and therefore never cleared pendingAcquire.
    const pending: Promise<void> = acquirePromise.finally(() => {
      // Only clear if we are still the active acquisition.
      if (this.acquireAbortController === controller) {
        this.acquireAbortController = undefined;
      }
      if (this.pendingAcquire === pending) {
        this.pendingAcquire = undefined;
      }
    });
    this.pendingAcquire = pending;

    return this.pendingAcquire;
  }

  /**
   * Start automatic token refresh using self-scheduling setTimeout to avoid
   * overlapping refresh calls if a refresh takes longer than the interval.
   */
  private startTokenRefresh(): void {
    if (this.tokenRefreshTimer) {
      clearTimeout(this.tokenRefreshTimer);
    }

    const interval = (this.config.tokenRefreshInterval || 600) * 1000;

    const refreshCycle = async (): Promise<void> => {
      if (this.shuttingDown) return;
      if (this.terminated) {
        // Control-plane kill switch fired — stop the loop entirely.
        this.tokenRefreshTimer = undefined;
        return;
      }
      try {
        await this.acquireCapabilityToken();
      } catch (error) {
        // If shutdown raced with the refresh, swallow silently — the abort is
        // expected and not an operational failure.
        if (!this.shuttingDown) {
          console.error('Failed to refresh capability token:', error);
        }
      } finally {
        if (!this.shuttingDown && !this.terminated) {
          this.tokenRefreshTimer = setTimeout(() => {
            void refreshCycle();
          }, interval);
        } else {
          this.tokenRefreshTimer = undefined;
        }
      }
    };

    this.tokenRefreshTimer = setTimeout(() => {
      void refreshCycle();
    }, interval);
  }

  /**
   * Extract the structured error code returned by the gateway error
   * middleware, which serializes a `CapabilityError` as
   * `{ error: { code, message } }`.  Returns `undefined` when the body is
   * missing or doesn't carry a code (e.g. proxied upstream error).
   */
  private extractErrorCode(data: unknown): string | undefined {
    if (!data || typeof data !== 'object') return undefined;
    const err = (data as { error?: unknown }).error;
    if (err && typeof err === 'object' && typeof (err as { code?: unknown }).code === 'string') {
      return (err as { code: string }).code;
    }
    if (typeof (data as { code?: unknown }).code === 'string') {
      return (data as { code: string }).code;
    }
    return undefined;
  }

  /**
   * Decide whether a 401 response from the gateway warrants a refresh+retry.
   *
   * - `EXPIRED_TOKEN` → yes, the token simply aged out; refresh and try again.
   * - `TOKEN_REVOKED` → no, an admin has explicitly revoked this token; the
   *   caller must surface the failure rather than silently rotate.
   * - any other code (e.g. `INVALID_TOKEN`) → no, refreshing won't help.
   * - missing/unknown code → fall back to refresh+retry once for back-compat.
   */
  private shouldRefreshOn401(code?: string): boolean {
    if (!code) return true;
    return code === ErrorCode.EXPIRED_TOKEN;
  }

  /**
   * Build the per-request `DPoP` header (F-2). Returns `{}` when DPoP
   * is not configured so the call sites can spread the result
   * unconditionally.
   *
   * The proof binds the request to (`method`, `<gatewayUrl><path>`)
   * — the gateway reconstructs the same canonical URL on its side
   * (honouring `X-Forwarded-*` for TLS-terminating reverse proxies)
   * before comparing.
   */
  private async buildDpopHeader(
    method: string,
    path: string,
  ): Promise<Record<string, string>> {
    if (!this.config.dpop) return {};
    const proof = await createDpopProof({
      privateKey: this.config.dpop.privateKey,
      publicJwk: this.config.dpop.publicJwk,
      algorithm: this.config.dpop.algorithm ?? 'ES256',
      httpMethod: method,
      httpUrl: this.absoluteGatewayUrl(path),
    });
    return { DPoP: proof };
  }

  /**
   * Compose `gatewayUrl` + `path` without double slashes, mirroring how
   * axios's `baseURL` joins them. Used to build the canonical `htu`
   * for DPoP proofs.
   */
  private absoluteGatewayUrl(path: string): string {
    const base = this.config.gatewayUrl.replace(/\/+$/, '');
    const tail = path.startsWith('/') ? path : `/${path}`;
    return `${base}${tail}`;
  }

  /**
   * Build a {@link ToolCallResponse} from a raw axios response, capturing the
   * structured error code when the gateway returned one.
   */
  private buildResponse(response: { status: number; data: any }): ToolCallResponse {
    const code = this.extractErrorCode(response.data);
    return {
      success: response.status >= 200 && response.status < 300,
      data: response.data,
      error: response.status >= 400
        ? (response.data?.error?.message ?? response.data?.error ?? response.data?.message)
        : undefined,
      statusCode: response.status,
      errorCode: code,
    };
  }

  /**
   * Invoke a tool through the gateway
   *
   * This is the primary method agents use to perform actions.
   * All tool calls are:
   * 1. Routed through the Tool Gateway (network boundary enforcement)
   * 2. Authenticated with capability tokens
   * 3. Logged and audited by the gateway
   */
  async invokeTool(request: ToolCallRequest): Promise<ToolCallResponse> {
    return withSpan(
      this.tracer,
      'agent-runtime.invokeTool',
      {
        [EUNO_ATTR.AGENT_ID]: this.config.agentId,
        [EUNO_ATTR.SERVICE]: 'agent-runtime',
        [EUNO_ATTR.RESOURCE]: request.resource ?? `tool://${request.tool}`,
        'euno.tool': request.tool,
      },
      async (span) => {
        const result = await this._invokeToolImpl(request);
        span.setAttribute(
          EUNO_ATTR.OUTCOME,
          result.success ? 'success' : 'failure',
        );
        if (result.statusCode !== undefined) {
          span.setAttribute('http.status_code', result.statusCode);
        }
        if (result.errorCode) {
          span.setAttribute('euno.error_code', result.errorCode);
        }
        return result;
      },
      SpanKind.CLIENT,
    );
  }

  private async _invokeToolImpl(request: ToolCallRequest): Promise<ToolCallResponse> {
    if (this.terminated) {
      return {
        success: false,
        error: 'Agent has been terminated by the control plane',
        statusCode: 403,
        errorCode: ErrorCode.AGENT_TERMINATED,
      };
    }

    if (!this.capabilityToken) {
      // Try to acquire token if we don't have one
      await this.acquireCapabilityToken();

      if (!this.capabilityToken) {
        return {
          success: false,
          error: 'No capability token available',
          statusCode: 401,
        };
      }
    }

    try {
      const toolsPath = '/api/v1/tools/invoke';
      const dpopHeaders = await this.buildDpopHeader('POST', toolsPath);
      const response = await this.httpClient.post(toolsPath, {
        tool: request.tool,
        args: request.args,
        resource: request.resource,
      }, {
        headers: {
          'Authorization': `Bearer ${this.capabilityToken}`,
          'X-Agent-ID': this.config.agentId,
          ...dpopHeaders,
        },
      });

      // Distinguish failure modes via the structured error code returned by
      // the gateway, rather than treating all 401s as "expired".
      const code = this.extractErrorCode(response.data);

      // 403 + AGENT_TERMINATED → kill switch fired.  Stop refreshing and
      // mark the runtime terminated so we don't keep minting doomed tokens.
      if (response.status === 403 && code === ErrorCode.AGENT_TERMINATED) {
        this.terminated = true;
        if (this.tokenRefreshTimer) {
          clearTimeout(this.tokenRefreshTimer);
          this.tokenRefreshTimer = undefined;
        }
        return this.buildResponse(response);
      }

      // 401 → only refresh+retry when the token actually expired.  Revoked,
      // invalid, or otherwise rejected tokens won't be helped by a refresh.
      if (response.status === 401 && this.shouldRefreshOn401(code)) {
        try {
          await this.acquireCapabilityToken();
        } catch (refreshError) {
          // If refresh itself fails (e.g. terminated mid-flight), surface the
          // original 401 with its structured code intact.
          return this.buildResponse(response);
        }

        // F-2: every request — including the retry — needs a fresh
        // DPoP proof; reusing the original would be flagged as a
        // replay by the gateway's jti store.
        const retryDpopHeaders = await this.buildDpopHeader('POST', toolsPath);
        const retryResponse = await this.httpClient.post(toolsPath, {
          tool: request.tool,
          args: request.args,
          resource: request.resource,
        }, {
          headers: {
            'Authorization': `Bearer ${this.capabilityToken}`,
            'X-Agent-ID': this.config.agentId,
            ...retryDpopHeaders,
          },
        });

        const retryCode = this.extractErrorCode(retryResponse.data);
        if (retryResponse.status === 403 && retryCode === ErrorCode.AGENT_TERMINATED) {
          this.terminated = true;
          if (this.tokenRefreshTimer) {
            clearTimeout(this.tokenRefreshTimer);
            this.tokenRefreshTimer = undefined;
          }
        }

        return this.buildResponse(retryResponse);
      }

      return this.buildResponse(response);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      };
    }
  }

  /**
   * Make a raw HTTP request through the gateway's proxy endpoint.
   *
   * Sprint 2: External HTTP(S) requests are routed through the gateway via the
   * `/proxy/<host>/<path>` endpoint.  NetworkPolicy enforcement ensures no
   * direct egress is possible at the kernel level.
   *
   * Host forwarding
   * ---------------
   * For absolute URLs we encode the intended target host in BOTH the proxy
   * path (`/proxy/<host><path>`) AND the `X-Target-Host` / `X-Target-Scheme`
   * headers. This allows the gateway to:
   *
   *   1. Derive a host-qualified resource (e.g. `api://api.example.com/data`)
   *      so capability tokens can be constrained by intended host, not just
   *      path. The previous implementation stripped the host and forwarded
   *      only the path, decoupling the authorized resource (e.g. `api://crm/`)
   *      from the actual destination URL — meaning a token authorising "talk
   *      to CRM" could not be cryptographically bound to "you actually called
   *      CRM and not a look-alike".
   *   2. Cross-check the path-encoded host against the header to detect
   *      tampering.
   *
   * Relative paths (no host known to the agent) are routed under
   * `/proxy/<path>` as before.
   */
  async makeRequest(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    data?: unknown
  ): Promise<ToolCallResponse> {
    return withSpan(
      this.tracer,
      'agent-runtime.makeRequest',
      {
        [EUNO_ATTR.AGENT_ID]: this.config.agentId,
        [EUNO_ATTR.SERVICE]: 'agent-runtime',
        [EUNO_ATTR.ACTION]:
          method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'write',
        [EUNO_ATTR.RESOURCE]: url,
        'http.method': method,
      },
      async (span) => {
        const result = await this._makeRequestImpl(method, url, data);
        span.setAttribute(
          EUNO_ATTR.OUTCOME,
          result.success ? 'success' : 'failure',
        );
        if (result.statusCode !== undefined) {
          span.setAttribute('http.status_code', result.statusCode);
        }
        if (result.errorCode) {
          span.setAttribute('euno.error_code', result.errorCode);
        }
        return result;
      },
      SpanKind.CLIENT,
    );
  }

  private async _makeRequestImpl(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    data?: unknown
  ): Promise<ToolCallResponse> {
    if (this.terminated) {
      return {
        success: false,
        error: 'Agent has been terminated by the control plane',
        statusCode: 403,
        errorCode: ErrorCode.AGENT_TERMINATED,
      };
    }

    if (!this.capabilityToken) {
      await this.acquireCapabilityToken();
    }

    try {
      // Derive the proxy path from the URL so requests are forwarded via
      // the gateway's /proxy/* mount point rather than sent as a JSON payload.
      let proxyPath: string;
      const extraHeaders: Record<string, string> = {};
      if (/^https?:\/\//i.test(url)) {
        const targetUrl = new URL(url);
        // Include the intended target host in the proxy path so the gateway
        // can derive a host-qualified resource identifier. URL.pathname is
        // guaranteed to start with '/' per the WHATWG URL spec, so we can
        // concatenate directly.
        const hostSegment = targetUrl.host; // host:port
        const pathAndQuery = targetUrl.pathname + targetUrl.search;
        proxyPath = `/${hostSegment}${pathAndQuery}`;
        extraHeaders['X-Target-Host'] = hostSegment;
        extraHeaders['X-Target-Scheme'] = targetUrl.protocol.replace(/:$/, '');
      } else {
        proxyPath = url.startsWith('/') ? url : `/${url}`;
      }

      const proxyUrl = `/proxy${proxyPath}`;
      // F-2: bind the proof to the proxy URL the gateway will see.
      const dpopHeaders = await this.buildDpopHeader(method, proxyUrl);
      const response = await this.httpClient.request({
        method,
        url: proxyUrl,
        data,
        headers: {
          'Authorization': `Bearer ${this.capabilityToken}`,
          'X-Agent-ID': this.config.agentId,
          ...extraHeaders,
          ...dpopHeaders,
        },
      });

      const code = this.extractErrorCode(response.data);
      if (response.status === 403 && code === ErrorCode.AGENT_TERMINATED) {
        this.terminated = true;
        if (this.tokenRefreshTimer) {
          clearTimeout(this.tokenRefreshTimer);
          this.tokenRefreshTimer = undefined;
        }
      }

      return this.buildResponse(response);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      };
    }
  }

  /**
   * Get current capability token (for debugging/monitoring)
   */
  getCapabilityToken(): string | undefined {
    return this.capabilityToken;
  }
}

/**
 * Create and initialize an agent runtime
 */
export async function createAgentRuntime(
  config: AgentRuntimeConfig
): Promise<AgentRuntime> {
  const runtime = new AgentRuntime(config);
  await runtime.initialize();
  return runtime;
}

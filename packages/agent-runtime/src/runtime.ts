/**
 * Agent Runtime Environment
 *
 * Provides a sandboxed execution environment for AI agents with:
 * - Network egress restrictions (all traffic routed through Tool Gateway)
 * - Capability token management
 * - Secure tool invocation
 */

import axios, { AxiosInstance } from 'axios';
import { CapabilityError, ErrorCode } from '@euno/common';

export interface AgentRuntimeConfig {
  /** Agent identifier */
  agentId: string;

  /** Tool Gateway endpoint (all external calls go through here) */
  gatewayUrl: string;

  /** Capability Issuer endpoint for token acquisition */
  issuerUrl: string;

  /** Initial authentication token (Azure AD token, etc.). Required to authenticate with the Capability Issuer. */
  authToken: string;

  /** Token refresh interval in seconds (default: 600s = 10 minutes) */
  tokenRefreshInterval?: number;
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

  constructor(config: AgentRuntimeConfig) {
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
  }

  /**
   * Initialize the runtime - acquire capability token
   */
  async initialize(): Promise<void> {
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

    // Track this acquisition so shutdown() can abort + await it.
    const controller = new AbortController();
    this.acquireAbortController = controller;

    const run = async (): Promise<void> => {
      const issuerClient = axios.create({
        baseURL: this.config.issuerUrl,
        timeout: 10000,
        validateStatus: () => true, // Handle all status codes manually
      });

      let response;
      try {
        response = await issuerClient.post('/api/v1/issue', {
          agentId: this.config.agentId,
        }, {
          headers: {
            'Authorization': `Bearer ${this.config.authToken}`,
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

    const acquirePromise = run();
    this.pendingAcquire = acquirePromise.finally(() => {
      // Only clear if we are still the active acquisition.
      if (this.acquireAbortController === controller) {
        this.acquireAbortController = undefined;
      }
      if (this.pendingAcquire === acquirePromise) {
        this.pendingAcquire = undefined;
      }
    });

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
      try {
        await this.acquireCapabilityToken();
      } catch (error) {
        // If shutdown raced with the refresh, swallow silently — the abort is
        // expected and not an operational failure.
        if (!this.shuttingDown) {
          console.error('Failed to refresh capability token:', error);
        }
      } finally {
        if (!this.shuttingDown) {
          this.tokenRefreshTimer = setTimeout(() => {
            void refreshCycle();
          }, interval);
        }
      }
    };

    this.tokenRefreshTimer = setTimeout(() => {
      void refreshCycle();
    }, interval);
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
      const response = await this.httpClient.post('/api/v1/tools/invoke', {
        tool: request.tool,
        args: request.args,
        resource: request.resource,
      }, {
        headers: {
          'Authorization': `Bearer ${this.capabilityToken}`,
          'X-Agent-ID': this.config.agentId,
        },
      });

      // Handle 401 (expired token) by refreshing and retrying once
      if (response.status === 401) {
        await this.acquireCapabilityToken();

        const retryResponse = await this.httpClient.post('/api/v1/tools/invoke', {
          tool: request.tool,
          args: request.args,
          resource: request.resource,
        }, {
          headers: {
            'Authorization': `Bearer ${this.capabilityToken}`,
            'X-Agent-ID': this.config.agentId,
          },
        });

        return {
          success: retryResponse.status >= 200 && retryResponse.status < 300,
          data: retryResponse.data,
          error: retryResponse.status >= 400 ? retryResponse.data?.error : undefined,
          statusCode: retryResponse.status,
        };
      }

      return {
        success: response.status >= 200 && response.status < 300,
        data: response.data,
        error: response.status >= 400 ? response.data?.error : undefined,
        statusCode: response.status,
      };
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

      const response = await this.httpClient.request({
        method,
        url: `/proxy${proxyPath}`,
        data,
        headers: {
          'Authorization': `Bearer ${this.capabilityToken}`,
          'X-Agent-ID': this.config.agentId,
          ...extraHeaders,
        },
      });

      return {
        success: response.status >= 200 && response.status < 300,
        data: response.data,
        error: response.status >= 400 ? response.data?.error : undefined,
        statusCode: response.status,
      };
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

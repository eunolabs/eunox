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
  /**
   * Set to `true` once the gateway has reported that this agent/session has
   * been killed via the control-plane kill switch.  When set, the periodic
   * refresh loop is halted and subsequent tool invocations fail fast — any
   * new capability token would be blocked by the same kill switch, so
   * refreshing is pointless and simply leaks a "doomed" token.
   */
  private terminated: boolean = false;

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
  }

  /**
   * Initialize the runtime - acquire capability token
   */
  async initialize(): Promise<void> {
    await this.acquireCapabilityToken();
    this.startTokenRefresh();
  }

  /**
   * Shutdown the runtime - cleanup resources
   */
  async shutdown(): Promise<void> {
    if (this.tokenRefreshTimer) {
      clearTimeout(this.tokenRefreshTimer);
      this.tokenRefreshTimer = undefined;
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
   * Acquire a capability token from the Issuer
   */
  private async acquireCapabilityToken(): Promise<void> {
    if (this.terminated) {
      throw new CapabilityError(
        ErrorCode.AGENT_TERMINATED,
        'Agent has been terminated by the control plane; refusing to acquire a new capability token',
        403
      );
    }

    const issuerClient = axios.create({
      baseURL: this.config.issuerUrl,
      timeout: 10000,
      validateStatus: () => true, // Handle all status codes manually
    });

    const userAuthToken = await this.resolveAuthToken();

    let response;
    try {
      response = await issuerClient.post('/api/v1/issue', {
        agentId: this.config.agentId,
      }, {
        headers: {
          'Authorization': `Bearer ${userAuthToken}`,
        },
      });
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Network error contacting Capability Issuer: ${error instanceof Error ? error.message : String(error)}`,
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
      if (this.terminated) {
        // Control-plane kill switch fired — stop the loop entirely.
        this.tokenRefreshTimer = undefined;
        return;
      }
      try {
        await this.acquireCapabilityToken();
      } catch (error) {
        console.error('Failed to refresh capability token:', error);
      } finally {
        if (!this.terminated) {
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
   * `/proxy/<path>` endpoint.  NetworkPolicy enforcement ensures no direct egress
   * is possible at the kernel level.
   */
  async makeRequest(
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
      if (/^https?:\/\//i.test(url)) {
        const targetUrl = new URL(url);
        proxyPath = targetUrl.pathname + targetUrl.search;
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

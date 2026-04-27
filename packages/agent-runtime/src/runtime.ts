/**
 * Agent Runtime Environment
 *
 * Provides a sandboxed execution environment for AI agents with:
 * - Network egress restrictions (all traffic routed through Tool Gateway)
 * - Capability token management
 * - Secure tool invocation
 */

import axios, { AxiosInstance } from 'axios';
import { CapabilityToken, CapabilityError } from '@euno/common';

export interface AgentRuntimeConfig {
  /** Agent identifier */
  agentId: string;

  /** Tool Gateway endpoint (all external calls go through here) */
  gatewayUrl: string;

  /** Capability Issuer endpoint for token acquisition */
  issuerUrl: string;

  /** Initial authentication token (Azure AD token, etc.) */
  authToken?: string;

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
   * Shutdown the runtime - cleanup resources
   */
  async shutdown(): Promise<void> {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
      this.tokenRefreshTimer = undefined;
    }
  }

  /**
   * Acquire a capability token from the Issuer
   */
  private async acquireCapabilityToken(): Promise<void> {
    try {
      // In production, this would use the auth token to get a capability token
      // For now, we make a direct call to the issuer (not through gateway)
      const issuerClient = axios.create({
        baseURL: this.config.issuerUrl,
        timeout: 10000,
      });

      const response = await issuerClient.post('/api/v1/issue', {
        agentId: this.config.agentId,
        // In production: pass authToken for verification
      }, {
        headers: this.config.authToken ? {
          'Authorization': `Bearer ${this.config.authToken}`,
        } : {},
      });

      if (response.status === 200 && response.data.token) {
        this.capabilityToken = response.data.token;
      } else {
        throw new CapabilityError(
          'TOKEN_ACQUISITION_FAILED',
          `Failed to acquire capability token: ${response.status}`
        );
      }
    } catch (error) {
      throw new CapabilityError(
        'TOKEN_ACQUISITION_ERROR',
        `Error acquiring capability token: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Start automatic token refresh
   */
  private startTokenRefresh(): void {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
    }

    const interval = (this.config.tokenRefreshInterval || 600) * 1000;
    this.tokenRefreshTimer = setInterval(async () => {
      try {
        await this.acquireCapabilityToken();
      } catch (error) {
        console.error('Failed to refresh capability token:', error);
      }
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
   * Make a raw HTTP request through the gateway
   *
   * Sprint 2: All external HTTP(S) requests should be intercepted
   * and routed through the gateway, even if the agent tries to
   * make direct requests to external services.
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
      const response = await this.httpClient.request({
        method,
        url: `/api/v1/proxy`,
        data: {
          targetUrl: url,
          method,
          data,
        },
        headers: {
          'Authorization': `Bearer ${this.capabilityToken}`,
          'X-Agent-ID': this.config.agentId,
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

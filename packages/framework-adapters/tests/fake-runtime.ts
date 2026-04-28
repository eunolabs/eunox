/**
 * Shared test fixtures for the framework adapters.
 */

import type { CapabilityRuntime, ToolCallRequest, ToolCallResponse } from '../src/types';

export interface FakeRuntimeCall {
  request: ToolCallRequest;
  ts: number;
}

/**
 * Tiny structural stand-in for `AgentRuntime`. Lets every adapter test
 * stay in-process and independent of `@euno/agent-runtime`'s HTTP layer.
 */
export class FakeRuntime implements CapabilityRuntime {
  public calls: FakeRuntimeCall[] = [];
  private terminated = false;
  private nextResponse: ToolCallResponse = {
    success: true,
    data: { ok: true },
    statusCode: 200,
  };

  setNextResponse(response: ToolCallResponse): void {
    this.nextResponse = response;
  }

  setTerminated(value: boolean): void {
    this.terminated = value;
  }

  isTerminated(): boolean {
    return this.terminated;
  }

  async invokeTool(request: ToolCallRequest): Promise<ToolCallResponse> {
    this.calls.push({ request, ts: Date.now() });
    return this.nextResponse;
  }
}

/**
 * Agent Runtime Entry Point
 */

export { AgentRuntime, createAgentRuntime, HttpToolTransport, InProcessToolTransport } from './runtime';
export type {
  AgentRuntimeConfig,
  ToolCallRequest,
  ToolCallResponse,
  // Transport types – re-exported from @euno/common for consumer convenience
  ToolTransport,
  ToolTransportResponse,
  ToolTransportInvokeRequest,
  ToolTransportProxyRequest,
  TransportCredentials,
  HttpToolTransportOptions,
  InProcessToolHandler,
  InProcessProxyHandler,
} from './runtime';

// AGT in-process guard adapter (Task 8 / Stage 5 §4.6)
export { createAgtGuard } from './agt-guard';
export type { AgtGuard, AgtGuardInvokeResponse } from './agt-guard';
// AgtGuardOptions, AgtGuardResult, and AgtGuardDenyReason are Apache-2.0 types
// originally defined in @euno/common-core and re-exported through @euno/common.
// Re-exported here for consumer convenience so callers only need a single import site.
export type { AgtGuardOptions, AgtGuardResult, AgtGuardDenyReason } from '@euno/common';

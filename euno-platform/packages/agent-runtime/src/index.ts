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

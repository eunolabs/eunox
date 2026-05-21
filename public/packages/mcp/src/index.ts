/**
 * @euno/mcp — MCP bridge for Euno capability-native agent governance.
 *
 * Public API surface for Stage 1:
 *
 *   - {@link MCP_PROTOCOL_VERSION} / {@link MCP_SUPPORTED_PROTOCOL_VERSIONS}
 *     — pinned protocol constants (Task 2).
 *   - {@link PolicyDecisionPoint} / {@link AlwaysAllowPDP} / {@link PdpContext}
 *     / {@link PdpDecision} — enforcement seam (Task 3).
 *   - {@link StdioProxy} / {@link StdioProxyOptions} — stdio transport (Task 3).
 *   - {@link HttpProxy} / {@link HttpProxyOptions} — streamable HTTP transport (Task 5).
 *   - {@link createTelemetry} / {@link TelemetryCollector} — opt-in anonymous
 *     usage telemetry (Task 10).
 */

export { MCP_PROTOCOL_VERSION, MCP_SUPPORTED_PROTOCOL_VERSIONS } from './protocol';
export type { PolicyDecisionPoint, PdpContext, PdpDecision, ConditionEnforcerPDPOptions } from './pdp';
export { AlwaysAllowPDP, ConditionEnforcerPDP } from './pdp';
export { RemoteEnforcerPDP } from './enforcer/remote';
export type { RemoteEnforcerOptions, EnforceFetcher } from './enforcer/remote';
export { StdioProxy } from './transport/stdio';
export type { StdioProxyOptions } from './transport/stdio';
export { HttpProxy } from './transport/http';
export type { HttpProxyOptions, KillController } from './transport/http';
export { UpstreamTimeoutError } from './transport/timeout';
export type { LocalPolicySource, FilePolicySourceOptions } from './policy/source';
export { FilePolicySource } from './policy/source';
export * from './audit';
export {
  createTelemetry,
  TelemetryCollector,
  TELEMETRY_EVENT_KEYS,
  sanitizeUpstreamServerName,
  DEFAULT_TELEMETRY_ENDPOINT,
  DEFAULT_LOCAL_TELEMETRY_PATH,
  DEFAULT_TELEMETRY_STATE_PATH,
  NoopTelemetryEmitter,
  LocalFileTelemetryEmitter,
  HttpTelemetryEmitter,
} from './telemetry';
export type {
  TelemetryEvent,
  TelemetryHooks,
  OsFamily,
  TelemetryState,
  TelemetryEmitter,
  TelemetryEventBase,
  CreateTelemetryOptions,
} from './telemetry';
export { buildPdp } from './cli/pdp-factory';
export type { EnforcementMode, BuildPdpResult } from './cli/pdp-factory';

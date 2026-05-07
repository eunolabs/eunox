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
 */

export { MCP_PROTOCOL_VERSION, MCP_SUPPORTED_PROTOCOL_VERSIONS } from './protocol';
export type { PolicyDecisionPoint, PdpContext, PdpDecision } from './pdp';
export { AlwaysAllowPDP } from './pdp';
export { StdioProxy } from './transport/stdio';
export type { StdioProxyOptions } from './transport/stdio';

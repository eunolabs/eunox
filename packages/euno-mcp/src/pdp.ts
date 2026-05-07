/**
 * PolicyDecisionPoint (PDP) — the single enforcement seam for @euno/mcp.
 *
 * Every `tools/call` request passes through the PDP before being forwarded to
 * the upstream MCP server.  The interface is intentionally narrow so that:
 *
 *   - Stage 1 ships {@link AlwaysAllowPDP} (no policy, transparent passthrough).
 *   - Phase B wires in the real condition-registry backed PDP.
 *   - Stage 3 replaces the policy source with a JWT loader — without touching
 *     this interface or the transport layer.
 *
 * @module
 */

import type { CallToolRequest } from '@modelcontextprotocol/sdk/dist/cjs/types';

/**
 * Context supplied to every PDP decision call.
 *
 * Kept intentionally small for Stage 1.  Phase B extends this with the
 * resolved {@link AgentCapabilityManifest}, the matched
 * {@link CapabilityConstraint}, and the counter key so the real enforcer can
 * check `maxCalls` and `timeWindow` conditions.
 */
export interface PdpContext {
  /**
   * Unique identifier for the current MCP session.  For stdio the session is
   * the lifetime of the proxy process; for HTTP it is one
   * `initialize` → `shutdown` cycle (see Task 5).
   */
  readonly sessionId: string;
}

/**
 * Decision returned by the PDP for a single `tools/call` invocation.
 */
export interface PdpDecision {
  /** Whether the call is permitted. */
  readonly allow: boolean;
  /**
   * Human-readable explanation — included in the MCP error response when
   * `allow` is `false`.
   */
  readonly reason?: string;
  /**
   * Machine-readable denial code (e.g. `CAPABILITY_DENIED`, `KILL_SWITCH`,
   * `MAX_CALLS_EXCEEDED`).  Only set when `allow` is `false`.
   */
  readonly denialCode?: string;
}

/**
 * The PolicyDecisionPoint interface.
 *
 * Implementations must be safe to call concurrently for different requests in
 * the same session.
 */
export interface PolicyDecisionPoint {
  /**
   * Evaluate a `tools/call` request against the active policy.
   *
   * @param request - The incoming `tools/call` request from the MCP client.
   * @param ctx     - Session context (session id, etc.).
   * @returns A decision — synchronous or asynchronous.
   */
  decide(
    request: CallToolRequest,
    ctx: PdpContext,
  ): PdpDecision | Promise<PdpDecision>;
}

/**
 * Transparent PDP that always permits calls.
 *
 * Used during Stage 1 before Phase B wires the real condition-registry
 * enforcer.  Replacing this with the real PDP is a one-line swap in the proxy
 * factory.
 */
export class AlwaysAllowPDP implements PolicyDecisionPoint {
  decide(_request: CallToolRequest, _ctx: PdpContext): PdpDecision {
    return { allow: true };
  }
}

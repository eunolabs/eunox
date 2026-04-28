/**
 * Shared types for the framework adapters.
 *
 * The Euno capability gateway exposes one cloud-agnostic SDK
 * (`@euno/agent-runtime`, the `AgentRuntime` class). The three framework
 * adapters in this package — LangChain, Microsoft Agent Framework (MAF),
 * and CrewAI — wrap that SDK so that tool calls executed by each
 * framework are routed through the gateway with a valid capability
 * token attached, and so denials surface as structured errors that the
 * framework can react to.
 *
 * All three adapters share a small set of integration concerns captured
 * here:
 *
 *   - Mapping a "framework tool name" to a gateway tool name + resource.
 *   - Surfacing the `correlationId` used by the audit log so downstream
 *     framework callbacks can attach it to traces.
 *   - Translating gateway denials into framework-native errors.
 */

import type { ToolCallRequest, ToolCallResponse, AgentRuntime } from '@euno/agent-runtime';

/**
 * Subset of the `AgentRuntime` API the adapters depend on.
 *
 * Declared as a structural interface (rather than importing the concrete
 * class) so tests can inject a stub and so the adapters never accidentally
 * grow a dependency on internal runtime state.
 */
export interface CapabilityRuntime {
  invokeTool(request: ToolCallRequest): Promise<ToolCallResponse>;
  isTerminated(): boolean;
}

/**
 * Type-narrow check for objects that satisfy {@link CapabilityRuntime}.
 * Used at the public-API boundary so we accept either a real
 * {@link AgentRuntime} instance or a structural stand-in.
 */
export function isCapabilityRuntime(value: unknown): value is CapabilityRuntime {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { invokeTool?: unknown }).invokeTool === 'function' &&
    typeof (value as { isTerminated?: unknown }).isTerminated === 'function'
  );
}

/**
 * Re-export so callers don't have to depend on `@euno/agent-runtime`
 * directly when they only want the structural adapter interface.
 */
export type { ToolCallRequest, ToolCallResponse, AgentRuntime };

/**
 * Per-tool registration shared by all three framework adapters.
 *
 * `frameworkToolName` is the name the LLM uses (the symbol it sees in
 * the tools list); `gatewayTool` and `gatewayResource` are how the call
 * is described to the Tool Gateway when the capability check runs.
 *
 * Keeping these orthogonal lets a single Euno capability authorize
 * multiple framework-side tools (e.g. several LangChain `Tool` objects
 * that all funnel into the same `crm.read` capability), and lets a
 * single framework tool be re-pointed at a different gateway resource
 * without changing the agent code.
 */
export interface ToolBinding {
  /** Name presented to the framework / LLM. */
  frameworkToolName: string;
  /** Gateway-side tool identifier expected by the enforcement engine. */
  gatewayTool: string;
  /** Optional resource URI (e.g. `api://crm/contacts`). */
  gatewayResource?: string;
  /**
   * Optional human-readable description forwarded to the framework's
   * tool registry. Most LLMs use this to decide when to call the tool.
   */
  description?: string;
  /**
   * Optional argument-shape hint forwarded to the framework's tool
   * registry. The gateway's argument validator is the source of truth
   * for what is *allowed*; this field is purely advisory.
   */
  argsSchema?: Record<string, unknown>;
  /**
   * Optional argument transform. Useful when the framework's tool
   * convention differs from the gateway's expected shape (e.g.
   * LangChain's stringly-typed `ToolInput`).
   */
  transformArgs?: (frameworkArgs: unknown) => Record<string, unknown>;
}

/**
 * Structured error thrown when the gateway denies a tool call.
 *
 * Adapters throw this (rather than the raw `ToolCallResponse`) so that
 * each framework's error-handling pipeline (LangChain's tool error
 * callbacks, MAF's middleware short-circuit, CrewAI's task `on_error`)
 * sees a single recognizable type.
 *
 * The `errorCode` and `statusCode` are passed through verbatim from the
 * gateway, preserving the distinction between "expired token" (recoverable
 * by the runtime), "kill switch fired" (terminal), and "missing scope"
 * (configuration bug).
 */
export class CapabilityDenialError extends Error {
  public readonly statusCode: number;
  public readonly errorCode?: string;
  public readonly tool: string;
  public readonly resource?: string;
  public readonly correlationId?: string;

  constructor(opts: {
    message: string;
    statusCode: number;
    errorCode?: string;
    tool: string;
    resource?: string;
    correlationId?: string;
  }) {
    super(opts.message);
    this.name = 'CapabilityDenialError';
    this.statusCode = opts.statusCode;
    this.errorCode = opts.errorCode;
    this.tool = opts.tool;
    this.resource = opts.resource;
    this.correlationId = opts.correlationId;
  }
}

/**
 * Generate a correlation ID used to tie framework-side traces to the
 * gateway-side audit log entry. The ID is opaque to the gateway but is
 * surfaced via the `X-Correlation-ID` header (when supported) and
 * recorded by each adapter's lifecycle hooks.
 *
 * Implementation note: we deliberately avoid pulling in `uuid` to keep
 * this package dependency-light. `crypto.randomUUID` has been available
 * in Node ≥ 14.17, which is well below the monorepo's `>=18.0.0`
 * `engines.node` floor.
 */
export function newCorrelationId(): string {
  // `globalThis.crypto` is the standards-track location and is present
  // on all supported Node versions. Falling back via `require('crypto')`
  // would defeat structural-typing tests in environments that stub it.
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c && typeof c.randomUUID === 'function') {
    return c.randomUUID();
  }
  // Last-ditch fallback: timestamp + random. Not RFC 4122 compliant but
  // sufficiently unique for audit correlation in dev environments where
  // `crypto.randomUUID` is unavailable.
  return `corr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Lookup helper used by all three adapters to resolve a framework-side
 * tool name back to its {@link ToolBinding}.
 *
 * Returns `undefined` rather than throwing so callers can decide between
 * deny-by-default ("unknown tool → throw") and pass-through semantics.
 */
export function findBinding(
  bindings: readonly ToolBinding[],
  frameworkToolName: string
): ToolBinding | undefined {
  return bindings.find((b) => b.frameworkToolName === frameworkToolName);
}

/**
 * Internal helper used by every adapter: invoke the gateway with the
 * binding's `(tool, resource)` pair and translate the response into
 * either the raw `data` (success) or a {@link CapabilityDenialError}
 * (failure).
 *
 * Adapters call this so that the denial-translation policy lives in
 * exactly one place — keeping LangChain / MAF / CrewAI behaviours
 * identical at the wire level.
 */
export async function invokeBoundTool(
  runtime: CapabilityRuntime,
  binding: ToolBinding,
  rawArgs: unknown,
  correlationId: string
): Promise<unknown> {
  const args =
    typeof binding.transformArgs === 'function'
      ? binding.transformArgs(rawArgs)
      : (rawArgs as Record<string, unknown>) ?? {};

  const response = await runtime.invokeTool({
    tool: binding.gatewayTool,
    args,
    resource: binding.gatewayResource,
  });

  if (!response.success) {
    throw new CapabilityDenialError({
      message:
        response.error ??
        `Gateway denied call to ${binding.gatewayTool}` +
          (binding.gatewayResource ? ` on ${binding.gatewayResource}` : ''),
      statusCode: response.statusCode,
      errorCode: response.errorCode,
      tool: binding.gatewayTool,
      resource: binding.gatewayResource,
      correlationId,
    });
  }

  return response.data;
}

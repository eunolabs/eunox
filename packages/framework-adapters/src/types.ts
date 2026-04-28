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
 * gateway-side audit log entry. The ID is opaque to the gateway and is
 * carried through adapter flows (recorded by the LangChain / MAF /
 * CrewAI lifecycle hooks and attached to translated denial errors via
 * {@link CapabilityDenialError.correlationId}) for framework-side
 * correlation. This module does not itself read or write an
 * `X-Correlation-ID` header — wiring the ID into outbound requests is
 * the integrator's responsibility.
 *
 * Uses `globalThis.crypto.randomUUID`, which is guaranteed available on
 * the monorepo's `engines.node >=18.0.0` floor.
 */
export function newCorrelationId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (!c || typeof c.randomUUID !== 'function') {
    // Should never happen on Node ≥ 18; fail loud rather than silently
    // produce non-RFC-4122 IDs that downstream systems may treat as a
    // different kind of identifier.
    throw new Error(
      'newCorrelationId: globalThis.crypto.randomUUID is unavailable; Node >= 18 required.'
    );
  }
  return c.randomUUID();
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
 * True when `value` is a plain JSON-shaped object (`{}` or
 * `Object.create(null)`), as opposed to an array, primitive, function,
 * or class instance.  Used by {@link invokeBoundTool} to enforce that
 * arguments forwarded to the gateway match the
 * `Record<string, unknown>` contract on `ToolCallRequest.args`.
 */
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
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
 *
 * Argument-shape contract:
 *   - When `binding.transformArgs` is supplied it MUST return a plain
 *     object; anything else is a programming error and raises
 *     `TypeError` at the wrapper boundary (vs. silently violating
 *     `ToolCallRequest.args` deeper in the stack).
 *   - When no transform is supplied, plain-object inputs are forwarded
 *     verbatim; non-object inputs (strings, numbers, arrays — common in
 *     legacy LangChain `Tool` calls) are coerced to `{}` so the gateway
 *     still receives a well-typed payload. Bindings that need to
 *     forward the raw input MUST declare a `transformArgs`.
 */
export async function invokeBoundTool(
  runtime: CapabilityRuntime,
  binding: ToolBinding,
  rawArgs: unknown,
  correlationId: string
): Promise<unknown> {
  let args: Record<string, unknown>;
  if (typeof binding.transformArgs === 'function') {
    const transformed = binding.transformArgs(rawArgs);
    if (!isPlainRecord(transformed)) {
      throw new TypeError(
        `Tool binding "${binding.frameworkToolName}" transformArgs must return a plain object.`
      );
    }
    args = transformed;
  } else {
    args = isPlainRecord(rawArgs) ? rawArgs : {};
  }

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

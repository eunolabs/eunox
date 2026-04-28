/**
 * Microsoft Agent Framework (MAF) adapter.
 *
 * Sprint-2 DX deliverable: *"MAF agent-run middleware and
 * function/tool-calling middleware"* (see `docs/execution-plan.md`,
 * Sprint 2 Team DX).
 *
 * MAF exposes two well-defined extension points:
 *
 *   - **Function/tool-calling middleware**: invoked around every
 *     function tool the model calls. The middleware receives a
 *     `(context, next)` pair, can inspect/mutate `context.arguments`,
 *     short-circuit by setting `context.result`, and observe the
 *     downstream call by calling `next()`.
 *
 *   - **Agent-run middleware**: invoked around an entire agent
 *     `run()` / `chat()` invocation. Useful for tagging the run with a
 *     correlation ID and for emitting a single audit event covering
 *     the whole multi-turn conversation.
 *
 * Both middlewares produced by this adapter are framework-shape
 * compatible (structurally typed) and don't import MAF directly, so the
 * adapter can be used with whichever MAF release the host project has
 * installed.
 */

import {
  CapabilityRuntime,
  ToolBinding,
  CapabilityDenialError,
  invokeBoundTool,
  newCorrelationId,
  findBinding,
  isCapabilityRuntime,
} from './types';

/**
 * Structural type of the MAF function-tool middleware context.
 *
 * MAF passes `function.name` (the model-visible tool name), the parsed
 * `arguments`, and a mutable `result` slot. Setting `result` short-
 * circuits the call without invoking the underlying function, which is
 * exactly the hook we need to either substitute the gateway response
 * (success path) or surface a denial (failure path).
 */
export interface MAFFunctionInvocationContext {
  function: { name: string };
  arguments: Record<string, unknown>;
  result?: unknown;
  /**
   * Optional metadata bag MAF threads through. We attach the Euno
   * correlation ID here so downstream middlewares (tracing, etc.) can
   * pick it up.
   */
  metadata?: Record<string, unknown>;
}

export type MAFNext = () => Promise<void>;

export type MAFFunctionMiddleware = (
  context: MAFFunctionInvocationContext,
  next: MAFNext
) => Promise<void>;

/**
 * Behaviour switch for unknown tools. MAF agents typically register a
 * mix of "Euno-governed" and "trusted local" tools (e.g. an in-process
 * calculator). The middleware needs a clear policy for what to do when
 * the model calls a tool not covered by any {@link ToolBinding}.
 *
 *   - `'pass-through'` (default): call `next()` and let the local
 *     implementation run. Use this when only a subset of tools is
 *     gateway-governed.
 *   - `'deny'`: throw {@link CapabilityDenialError} so unknown tools
 *     become a hard failure. Use this in deny-by-default deployments.
 */
export type UnknownToolPolicy = 'pass-through' | 'deny';

export interface MAFFunctionMiddlewareOptions {
  /** What to do when the model calls a tool not in `bindings`. */
  unknownToolPolicy?: UnknownToolPolicy;
  /**
   * Optional emitter invoked for every governed tool call. Mirrors the
   * LangChain callback handler so the same observability layer can
   * cover both frameworks.
   */
  onAuditEvent?: (event: MAFAuditEvent) => void;
}

export interface MAFAuditEvent {
  phase: 'tool-start' | 'tool-end' | 'tool-error' | 'run-start' | 'run-end';
  toolName?: string;
  correlationId: string;
  ts: string;
  errorCode?: string;
  statusCode?: number;
  errorMessage?: string;
}

/**
 * Create a MAF function-tool middleware that routes every governed call
 * through the Euno gateway.
 *
 * The returned function is the value the application passes to the MAF
 * agent builder — typically `agent.use(createEunoFunctionToolMiddleware(...))`.
 */
export function createEunoFunctionToolMiddleware(
  runtime: CapabilityRuntime,
  bindings: readonly ToolBinding[],
  options: MAFFunctionMiddlewareOptions = {}
): MAFFunctionMiddleware {
  if (!isCapabilityRuntime(runtime)) {
    throw new TypeError(
      'createEunoFunctionToolMiddleware: `runtime` must satisfy the CapabilityRuntime interface.'
    );
  }
  const policy: UnknownToolPolicy = options.unknownToolPolicy ?? 'pass-through';
  const audit = options.onAuditEvent;

  return async (context, next) => {
    const toolName = context?.function?.name;
    const binding = toolName ? findBinding(bindings, toolName) : undefined;

    if (!binding) {
      if (policy === 'deny') {
        const correlationId = newCorrelationId();
        const message = `Unknown tool '${toolName ?? '<missing>'}' rejected by Euno deny-by-default policy.`;
        audit?.({
          phase: 'tool-error',
          toolName,
          correlationId,
          ts: new Date().toISOString(),
          statusCode: 403,
          errorMessage: message,
        });
        throw new CapabilityDenialError({
          message,
          statusCode: 403,
          tool: toolName ?? '<missing>',
          correlationId,
        });
      }
      // pass-through: run the underlying tool unchanged.
      await next();
      return;
    }

    const correlationId = newCorrelationId();
    // `metadata` is optional on the MAF context; initialize it so the
    // correlation ID is always surfaced to downstream middlewares
    // regardless of whether the caller supplied a metadata bag.
    context.metadata = context.metadata ?? {};
    context.metadata.eunoCorrelationId = correlationId;

    audit?.({
      phase: 'tool-start',
      toolName: binding.frameworkToolName,
      correlationId,
      ts: new Date().toISOString(),
    });

    try {
      const result = await invokeBoundTool(
        runtime,
        binding,
        context.arguments,
        correlationId
      );
      // Short-circuit MAF's downstream call: the gateway *is* the tool.
      // Setting `context.result` is MAF's documented convention for a
      // middleware that supplies the answer itself; we deliberately do
      // not call `next()` because the local function (if any) would
      // otherwise double-execute.
      context.result = result;
      audit?.({
        phase: 'tool-end',
        toolName: binding.frameworkToolName,
        correlationId,
        ts: new Date().toISOString(),
      });
    } catch (err) {
      const denial = err instanceof CapabilityDenialError ? err : undefined;
      audit?.({
        phase: 'tool-error',
        toolName: binding.frameworkToolName,
        correlationId,
        ts: new Date().toISOString(),
        errorCode: denial?.errorCode,
        statusCode: denial?.statusCode,
        errorMessage: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  };
}

/**
 * Structural type of the MAF agent-run middleware context.
 *
 * MAF passes the inbound message(s) and a mutable `metadata` bag. We
 * use the bag to attach a per-run correlation ID and to detect when the
 * Euno control plane has terminated the agent (kill switch fired).
 */
export interface MAFAgentRunContext {
  metadata?: Record<string, unknown>;
}

export type MAFAgentRunMiddleware = (
  context: MAFAgentRunContext,
  next: MAFNext
) => Promise<void>;

export interface MAFAgentRunMiddlewareOptions {
  onAuditEvent?: (event: MAFAuditEvent) => void;
}

/**
 * Create a MAF agent-run middleware that:
 *
 *   - Refuses to start a new run when the runtime has been terminated
 *     by the control plane (so the kill switch is honoured at the
 *     outermost layer, not just inside individual tool calls).
 *   - Tags the run with a stable correlation ID for cross-tool audit
 *     correlation.
 *   - Emits run-start / run-end audit events.
 */
export function createEunoAgentRunMiddleware(
  runtime: CapabilityRuntime,
  options: MAFAgentRunMiddlewareOptions = {}
): MAFAgentRunMiddleware {
  if (!isCapabilityRuntime(runtime)) {
    throw new TypeError(
      'createEunoAgentRunMiddleware: `runtime` must satisfy the CapabilityRuntime interface.'
    );
  }
  const audit = options.onAuditEvent;

  return async (context, next) => {
    if (runtime.isTerminated()) {
      const correlationId = newCorrelationId();
      audit?.({
        phase: 'run-start',
        correlationId,
        ts: new Date().toISOString(),
        statusCode: 403,
        errorMessage: 'Agent terminated by control plane.',
      });
      throw new CapabilityDenialError({
        message: 'Agent has been terminated by the Euno control plane; refusing to start agent run.',
        statusCode: 403,
        tool: '<agent-run>',
        correlationId,
      });
    }

    const correlationId = newCorrelationId();
    if (context && typeof context === 'object') {
      context.metadata = context.metadata ?? {};
      context.metadata.eunoCorrelationId = correlationId;
    }

    audit?.({
      phase: 'run-start',
      correlationId,
      ts: new Date().toISOString(),
    });

    try {
      await next();
    } finally {
      audit?.({
        phase: 'run-end',
        correlationId,
        ts: new Date().toISOString(),
      });
    }
  };
}

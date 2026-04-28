/**
 * LangChain adapter: tool wrapper + callback handler.
 *
 * Sprint-2 DX deliverable: *"LangChain callback handlers and tool
 * wrappers"* (see `docs/execution-plan.md`, Sprint 2 Team DX).
 *
 * The adapter targets LangChain's stable tool/callback surface
 * structurally so it works with both the JS LangChain (`@langchain/core`)
 * and any reasonably API-compatible fork — we don't import LangChain
 * directly. Two artifacts are exported:
 *
 *   1. `wrapAsLangChainTool(runtime, binding)` — produces an object that
 *      satisfies the `Tool` interface (`name`, `description`, `schema`,
 *      `invoke`/`call`/`func`). Each invocation routes through the
 *      Euno gateway with the configured capability tool / resource.
 *
 *   2. `EunoLangChainCallbackHandler` — implements the structurally
 *      typed `BaseCallbackHandler` surface, so it can be plugged into
 *      any `RunnableConfig.callbacks` array. It emits
 *      `correlationId`-tagged events so the framework's tracing layer
 *      can be joined back to the Tool Gateway audit log.
 *
 * Cloud-agnosticism: neither the wrapper nor the handler reference
 * Azure / AWS / GCP — they delegate to `AgentRuntime` (or any
 * structural `CapabilityRuntime`), which the application has already
 * configured with its preferred identity / signer / logging stack.
 */

import {
  CapabilityRuntime,
  ToolBinding,
  CapabilityDenialError,
  invokeBoundTool,
  newCorrelationId,
  isCapabilityRuntime,
} from './types';

/**
 * Minimal structural type of a LangChain `StructuredTool`-compatible
 * object. We declare only the fields LangChain's own callers read so
 * the wrapper plugs into both the legacy `Tool` interface and the
 * newer `RunnableLike` surface.
 */
export interface LangChainCompatibleTool {
  name: string;
  description: string;
  schema?: Record<string, unknown>;
  /**
   * The Runnable / Tool entry point. LangChain passes either a plain
   * string (legacy `Tool`) or a structured object (`StructuredTool`)
   * here, so we accept `unknown` and let the binding's
   * `transformArgs` normalize it.
   */
  invoke(input: unknown, runConfig?: { callbacks?: unknown }): Promise<string>;
  /** Legacy alias — `Tool.call(input)` was the v0 entry point. */
  call(input: unknown): Promise<string>;
  /** Internal entry point used by `Tool` subclasses that override `_call`. */
  func(input: unknown): Promise<string>;
}

/**
 * Wrap a single Euno {@link ToolBinding} as a LangChain-compatible tool.
 *
 * The returned object is intentionally a plain literal (rather than a
 * subclass of LangChain's `Tool`) so this package doesn't pull
 * `@langchain/core` in as a runtime dependency. Application code that
 * already uses LangChain can pass the returned object directly into any
 * API that accepts a `Tool` / `StructuredTool` / `RunnableLike`.
 *
 * The tool's `invoke()` returns the gateway response coerced to a
 * string — LangChain agents consume tool output as strings by
 * convention, and gateway responses are already JSON-serializable.
 *
 * @throws {Error} synchronously when `runtime` does not satisfy
 *   {@link CapabilityRuntime}, so misconfiguration fails at wiring time
 *   rather than at first agent step.
 */
export function wrapAsLangChainTool(
  runtime: CapabilityRuntime,
  binding: ToolBinding
): LangChainCompatibleTool {
  if (!isCapabilityRuntime(runtime)) {
    throw new TypeError(
      'wrapAsLangChainTool: `runtime` must satisfy the CapabilityRuntime interface (invokeTool + isTerminated).'
    );
  }
  if (!binding || typeof binding.frameworkToolName !== 'string' || !binding.frameworkToolName) {
    throw new TypeError('wrapAsLangChainTool: `binding.frameworkToolName` is required.');
  }
  if (typeof binding.gatewayTool !== 'string' || !binding.gatewayTool) {
    throw new TypeError('wrapAsLangChainTool: `binding.gatewayTool` is required.');
  }

  const run = async (input: unknown): Promise<string> => {
    const correlationId = newCorrelationId();
    const result = await invokeBoundTool(runtime, binding, input, correlationId);
    return typeof result === 'string' ? result : JSON.stringify(result);
  };

  return {
    name: binding.frameworkToolName,
    description:
      binding.description ??
      `Euno-governed tool: ${binding.gatewayTool}` +
        (binding.gatewayResource ? ` (${binding.gatewayResource})` : ''),
    schema: binding.argsSchema,
    invoke: (input) => run(input),
    call: (input) => run(input),
    func: (input) => run(input),
  };
}

/**
 * Bulk-wrap helper for the common case where an agent has many tools.
 */
export function wrapAsLangChainTools(
  runtime: CapabilityRuntime,
  bindings: readonly ToolBinding[]
): LangChainCompatibleTool[] {
  return bindings.map((b) => wrapAsLangChainTool(runtime, b));
}

/**
 * Structural shape of LangChain's `BaseCallbackHandler`. We declare only
 * the methods the Euno handler needs to implement — LangChain's runtime
 * uses duck-typing, so any object exposing the right method names will
 * be invoked.
 *
 * `runId`, `parentRunId`, etc. are passed by LangChain at run time; we
 * surface them on the audit event so distributed traces can be joined
 * with the gateway's session log.
 */
export interface LangChainCallbacks {
  handleToolStart?(
    tool: { name: string },
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>
  ): Promise<void> | void;
  handleToolEnd?(
    output: string,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> | void;
  handleToolError?(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> | void;
}

/**
 * Audit-event payload emitted by the callback handler. Consumers can
 * forward these to OpenTelemetry, Application Insights, CloudWatch, or
 * Cloud Logging — the structure is cloud-agnostic and parallels the
 * `AuditLogEntry` schema used inside the gateway.
 */
export interface EunoCallbackEvent {
  phase: 'tool-start' | 'tool-end' | 'tool-error';
  toolName: string;
  runId: string;
  parentRunId?: string;
  correlationId: string;
  ts: string;
  /** Set on `tool-error` events. */
  errorCode?: string;
  /** Set on `tool-error` events from {@link CapabilityDenialError}. */
  statusCode?: number;
  /** Set on `tool-error` events; the error message. */
  errorMessage?: string;
}

export type EunoCallbackSink = (event: EunoCallbackEvent) => void;

/**
 * LangChain callback handler that emits Euno-correlated audit events.
 *
 * Two responsibilities:
 *
 *   1. Issue a fresh `correlationId` per tool run and remember it so
 *      `tool-end` / `tool-error` events can carry the same ID.
 *   2. Translate any thrown {@link CapabilityDenialError} into a
 *      structured `tool-error` event with `errorCode` / `statusCode`,
 *      so monitoring can distinguish denials from incidental tool bugs.
 */
export class EunoLangChainCallbackHandler implements LangChainCallbacks {
  /** LangChain looks at `name` to namespace handler logs. */
  public readonly name = 'EunoLangChainCallbackHandler';
  private readonly sink: EunoCallbackSink;
  private readonly runCorrelations = new Map<string, string>();

  constructor(sink: EunoCallbackSink) {
    if (typeof sink !== 'function') {
      throw new TypeError(
        'EunoLangChainCallbackHandler: `sink` must be a function (event) => void.'
      );
    }
    this.sink = sink;
  }

  handleToolStart(tool: { name: string }, _input: string, runId: string, parentRunId?: string): void {
    const correlationId = newCorrelationId();
    this.runCorrelations.set(runId, correlationId);
    this.sink({
      phase: 'tool-start',
      toolName: tool?.name ?? '<unknown>',
      runId,
      parentRunId,
      correlationId,
      ts: new Date().toISOString(),
    });
  }

  handleToolEnd(_output: string, runId: string, parentRunId?: string): void {
    const correlationId = this.runCorrelations.get(runId) ?? newCorrelationId();
    this.runCorrelations.delete(runId);
    this.sink({
      phase: 'tool-end',
      toolName: '<resolved-by-runId>',
      runId,
      parentRunId,
      correlationId,
      ts: new Date().toISOString(),
    });
  }

  handleToolError(err: Error, runId: string, parentRunId?: string): void {
    const correlationId = this.runCorrelations.get(runId) ?? newCorrelationId();
    this.runCorrelations.delete(runId);
    const denial = err instanceof CapabilityDenialError ? err : undefined;
    this.sink({
      phase: 'tool-error',
      toolName: denial?.tool ?? '<resolved-by-runId>',
      runId,
      parentRunId,
      correlationId,
      ts: new Date().toISOString(),
      errorCode: denial?.errorCode,
      statusCode: denial?.statusCode,
      errorMessage: err?.message,
    });
  }
}

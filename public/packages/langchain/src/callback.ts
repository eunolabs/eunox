/**
 * EunoLangChainCallbackHandler — LangChain callback handler that emits
 * Euno-correlated audit events.
 *
 * Plugs into LangChain's `RunnableConfig.callbacks` array. Because this
 * package does not import `@langchain/core`, the handler is a structural
 * implementation — any LangChain version that duck-types callbacks will invoke
 * it automatically.
 *
 * The handler has two responsibilities:
 *
 *   1. Issue a fresh `correlationId` per tool run and carry it through
 *      `tool-start` → `tool-end` / `tool-error` events so distributed traces
 *      can be joined with the local JSONL audit log.
 *
 *   2. Translate any thrown {@link CapabilityDenialError} into a structured
 *      `tool-error` event with `errorCode` / `statusCode` / `conditionType`,
 *      so monitoring can distinguish Euno denials from incidental tool bugs.
 *
 * @module
 */

import { CapabilityDenialError, newCorrelationId } from './types';

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/**
 * Audit-event payload emitted by the callback handler.
 *
 * Consumers can forward these to OpenTelemetry, Datadog, CloudWatch, etc.
 * The structure is cloud-agnostic and parallels the OCSF record shape written
 * by the local audit sink.
 */
export interface EunoCallbackEvent {
  /** Lifecycle phase. */
  phase: 'tool-start' | 'tool-end' | 'tool-error';
  /** Tool name from LangChain's tool descriptor. */
  toolName: string;
  /** LangChain run identifier (UUID). */
  runId: string;
  /** Parent run identifier, when the tool was called from a chain/agent. */
  parentRunId?: string;
  /** Euno correlation identifier — same across start/end/error for one invocation. */
  correlationId: string;
  /** ISO-8601 timestamp of the event. */
  ts: string;
  /** Set on `tool-error` events — the error code. */
  errorCode?: string;
  /** Set on `tool-error` events from {@link CapabilityDenialError} — HTTP-style status. */
  statusCode?: number;
  /** Set on `tool-error` events from {@link CapabilityDenialError} — condition type. */
  conditionType?: string;
  /** Set on `tool-error` events — the error message. */
  errorMessage?: string;
}

/** Callback function that receives audit events. */
export type EunoCallbackSink = (event: EunoCallbackEvent) => void;

// ---------------------------------------------------------------------------
// LangChain structural interface
// ---------------------------------------------------------------------------

/**
 * Structural shape of LangChain's `BaseCallbackHandler`.
 *
 * We declare only the methods the Euno handler needs to implement — LangChain's
 * runtime uses duck-typing, so any object exposing the right method names will
 * be invoked.
 */
export interface LangChainCallbacks {
  handleToolStart?(
    tool: { name: string },
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void> | void;
  handleToolEnd?(
    output: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void> | void;
  handleToolError?(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void> | void;
}

// ---------------------------------------------------------------------------
// EunoLangChainCallbackHandler
// ---------------------------------------------------------------------------

/**
 * LangChain callback handler that emits Euno-correlated audit events.
 *
 * @example
 * ```ts
 * const handler = new EunoLangChainCallbackHandler((event) => {
 *   if (event.phase === 'tool-error' && event.errorCode) {
 *     myMonitoring.recordDenial(event);
 *   }
 * });
 *
 * await agent.invoke(input, { callbacks: [handler] });
 * ```
 */
export class EunoLangChainCallbackHandler implements LangChainCallbacks {
  /** LangChain looks at `name` to namespace handler logs. */
  public readonly name = 'EunoLangChainCallbackHandler';

  private readonly sink: EunoCallbackSink;

  /**
   * Per-runId state captured at `tool-start` so `tool-end` and `tool-error`
   * events can carry the same correlation ID and tool name (LangChain only
   * passes the tool object to `handleToolStart`, so we cache it here).
   */
  private readonly runState = new Map<string, { correlationId: string; toolName: string }>();

  constructor(sink: EunoCallbackSink) {
    if (typeof sink !== 'function') {
      throw new TypeError(
        'EunoLangChainCallbackHandler: `sink` must be a function (event: EunoCallbackEvent) => void.',
      );
    }
    this.sink = sink;
  }

  handleToolStart(
    tool: { name: string },
    _input: string,
    runId: string,
    parentRunId?: string,
  ): void {
    const correlationId = newCorrelationId();
    const toolName = tool?.name ?? '<unknown>';
    this.runState.set(runId, { correlationId, toolName });
    this.sink({
      phase: 'tool-start',
      toolName,
      runId,
      parentRunId,
      correlationId,
      ts: new Date().toISOString(),
    });
  }

  handleToolEnd(_output: string, runId: string, parentRunId?: string): void {
    const state = this.runState.get(runId);
    this.runState.delete(runId);
    this.sink({
      phase: 'tool-end',
      toolName: state?.toolName ?? '<unknown>',
      runId,
      parentRunId,
      correlationId: state?.correlationId ?? newCorrelationId(),
      ts: new Date().toISOString(),
    });
  }

  handleToolError(err: Error, runId: string, parentRunId?: string): void {
    const state = this.runState.get(runId);
    this.runState.delete(runId);
    const denial = err instanceof CapabilityDenialError ? err : undefined;
    this.sink({
      phase: 'tool-error',
      toolName: state?.toolName ?? denial?.tool ?? '<unknown>',
      runId,
      parentRunId,
      correlationId: state?.correlationId ?? newCorrelationId(),
      ts: new Date().toISOString(),
      errorCode: denial?.errorCode,
      statusCode: denial?.statusCode,
      conditionType: denial?.conditionType,
      errorMessage: err?.message,
    });
  }
}

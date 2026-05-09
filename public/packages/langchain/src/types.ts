/**
 * Shared types for @euno/langchain.
 *
 * These types form the structural interface between LangChain tools, the local
 * enforcement runtime, and the callback handler. They are intentionally kept
 * small and free of @langchain/core imports — the adapter works with any object
 * that satisfies the structural shapes defined here.
 *
 * @module
 */

// ---------------------------------------------------------------------------
// LangChain structural interface
// ---------------------------------------------------------------------------

/**
 * Minimal structural type of a LangChain `StructuredTool`-compatible object.
 *
 * We declare only the fields LangChain's own callers read so the wrapper plugs
 * into both the legacy `Tool` interface and the newer `RunnableLike` surface.
 * No `@langchain/core` import is required.
 */
export interface LangChainCompatibleTool {
  /** Tool name exposed to the LLM. */
  name: string;
  /** Human-readable description the LLM uses to decide when to call the tool. */
  description: string;
  /** Optional JSON Schema describing the tool's expected arguments. */
  schema?: Record<string, unknown>;
  /**
   * Primary entry point (LangChain ≥ v0.2 Runnable interface).
   *
   * Accepts either a structured object (`StructuredTool`) or a plain string
   * (legacy `Tool`) and returns a string result. LangChain agents consume tool
   * output as strings.
   */
  invoke(input: unknown, runConfig?: { callbacks?: unknown }): Promise<string>;
  /** Legacy alias — `Tool.call(input)` was the v0 entry point. */
  call(input: unknown): Promise<string>;
  /** Internal entry point used by `Tool` subclasses that override `_call`. */
  func(input: unknown): Promise<string>;
}

// ---------------------------------------------------------------------------
// Capability denial error
// ---------------------------------------------------------------------------

/**
 * Thrown when the local enforcement runtime denies a tool call.
 *
 * Consumers can inspect `errorCode` / `statusCode` to distinguish between
 * different denial reasons (kill switch, max-calls, argument schema, etc.)
 * and surface them to LangChain's error-handling pipeline.
 */
export class CapabilityDenialError extends Error {
  /** HTTP-style status code (403 for policy denial, 429 for rate limiting). */
  public readonly statusCode: number;
  /** Machine-readable denial code (e.g. `'MAX_CALLS_EXCEEDED'`). */
  public readonly errorCode: string;
  /** The MCP/tool name that was denied. */
  public readonly tool: string;
  /** Optional resource URI associated with the tool call. */
  public readonly resource?: string;
  /** Optional correlation identifier linking this event to the audit log. */
  public readonly correlationId?: string;
  /**
   * Structured details about the denial cause. Populated for `argumentSchema`
   * denials and contains `{ path, expected, got }`.
   */
  public readonly details?: Record<string, unknown>;
  /**
   * The condition type that triggered the denial (e.g. `'maxCalls'`,
   * `'ipRange'`, `'argumentSchema'`).
   */
  public readonly conditionType?: string;

  constructor(opts: {
    message: string;
    statusCode: number;
    errorCode: string;
    tool: string;
    resource?: string;
    correlationId?: string;
    details?: Record<string, unknown>;
    conditionType?: string;
  }) {
    super(opts.message);
    this.name = 'CapabilityDenialError';
    this.statusCode = opts.statusCode;
    this.errorCode = opts.errorCode;
    this.tool = opts.tool;
    this.resource = opts.resource;
    this.correlationId = opts.correlationId;
    this.details = opts.details;
    this.conditionType = opts.conditionType;
  }
}

// ---------------------------------------------------------------------------
// Correlation helpers
// ---------------------------------------------------------------------------

/**
 * Generate a UUID v4 correlation identifier.
 *
 * Uses `globalThis.crypto.randomUUID`, guaranteed available on Node ≥ 18.
 * The ID is used to tie LangChain callback events to audit log entries.
 */
export function newCorrelationId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (!c || typeof c.randomUUID !== 'function') {
    throw new Error(
      'newCorrelationId: globalThis.crypto.randomUUID is unavailable; Node >= 18 required.',
    );
  }
  return c.randomUUID();
}

// ---------------------------------------------------------------------------
// Runtime interface
// ---------------------------------------------------------------------------

/**
 * Request shape passed to {@link LocalCapabilityRuntime.invokeTool}.
 */
export interface LocalToolInvocationRequest {
  /** The tool name as it appears in the capability manifest. */
  tool: string;
  /** Arguments passed to the tool by the LLM or calling code. */
  args: Record<string, unknown>;
  /** Optional resource URI (e.g. `mcp-tool://query_db`). */
  resource?: string;
  /** Optional source IP for `ipRange` condition enforcement. */
  sourceIp?: string;
  /**
   * Optional correlation identifier. When provided, it is stored as
   * `requestId` on the audit record so that LangChain callback events and
   * OCSF audit entries can be joined in external tracing systems.
   */
  correlationId?: string;
}

/**
 * Result returned by {@link LocalCapabilityRuntime.invokeTool}.
 */
export interface LocalToolInvocationResult {
  /** Whether the call was permitted by the policy. */
  success: boolean;
  /** Machine-readable denial code when `success` is `false`. */
  denialCode?: string;
  /** Human-readable denial reason when `success` is `false`. */
  denialReason?: string;
  /** The condition type that triggered the denial. */
  conditionType?: string;
  /** Structured details for `argumentSchema` denials. */
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

/**
 * Inline tool definition passed to {@link wrapAsLangChainTool}.
 */
export interface LocalToolDefinition {
  /** Tool name. Must match a resource entry in the capability manifest. */
  name: string;
  /** Human-readable description forwarded to LangChain's tool registry. */
  description: string;
  /**
   * Optional JSON Schema describing the arguments. Used by LangChain's
   * `StructuredTool` interface to validate and parse LLM output.
   */
  schema?: Record<string, unknown>;
  /**
   * Optional implementation function called when the enforcement runtime
   * permits the invocation. Return value is coerced to a string for
   * compatibility with LangChain's string-typed tool output convention.
   *
   * When absent the tool returns an empty string on every allowed call.
   */
  handler?: (args: Record<string, unknown>) => Promise<unknown> | unknown;
  /**
   * Optional argument transform. Applied before enforcement — useful when the
   * LangChain calling convention differs from the manifest's expected schema
   * (e.g. stringly-typed legacy `Tool` inputs).
   */
  transformArgs?: (input: unknown) => Record<string, unknown>;
  /**
   * Optional source IP address forwarded to `ipRange` conditions. Only
   * relevant when the capability manifest includes `ipRange` conditions.
   */
  sourceIp?: string;
  /**
   * Optional resource URI forwarded to the PDP (e.g. `mcp-tool://query_db`).
   * Defaults to `mcp-tool://<name>` when not supplied.
   */
  resource?: string;
}

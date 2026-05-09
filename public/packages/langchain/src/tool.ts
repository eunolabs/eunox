/**
 * wrapAsLangChainTool — wrap a governed tool as a LangChain-compatible object.
 *
 * Each call to the returned tool's `invoke()` / `call()` / `func()` methods:
 *   1. Enforces the capability manifest via the {@link LocalCapabilityRuntime}.
 *   2. Records the decision to the local audit log (done inside the runtime).
 *   3. On allow — calls the optional `handler` and returns its result as a string.
 *   4. On deny  — throws a {@link CapabilityDenialError} so LangChain's tool
 *      error callbacks fire with structured information about why the call was
 *      blocked.
 *
 * @module
 */

import {
  CapabilityDenialError,
  newCorrelationId,
  type LangChainCompatibleTool,
  type LocalToolDefinition,
} from './types';
import type { LocalCapabilityRuntime } from './runtime';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Coerce a raw `invoke()` input to the `Record<string, unknown>` shape
 * expected by the enforcement runtime and the optional handler.
 *
 * - If a `transformArgs` function is provided it is called first. Its return
 *   value must be a plain object; a non-object return throws `TypeError`.
 * - If no transform is provided, plain-object inputs are forwarded verbatim;
 *   non-object inputs (strings, numbers, arrays) are coerced to `{}`.
 */
function normalizeArgs(
  input: unknown,
  transform?: (input: unknown) => Record<string, unknown>,
): Record<string, unknown> {
  if (transform) {
    const transformed = transform(input);
    if (
      typeof transformed !== 'object' ||
      transformed === null ||
      Array.isArray(transformed)
    ) {
      throw new TypeError(
        'wrapAsLangChainTool: `transformArgs` must return a plain object.',
      );
    }
    return transformed;
  }
  if (
    typeof input === 'object' &&
    input !== null &&
    !Array.isArray(input)
  ) {
    return input as Record<string, unknown>;
  }
  return {};
}

/**
 * Coerce any value returned by a `handler` to a string for LangChain
 * consumption.
 *
 * - Strings pass through unchanged.
 * - `undefined` / `null` become the empty string.
 * - Everything else is JSON-serialised.
 */
function coerceToString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  return JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// wrapAsLangChainTool
// ---------------------------------------------------------------------------

/**
 * Wrap a single tool definition as a LangChain-compatible, Euno-governed tool.
 *
 * The returned object satisfies the structural `Tool` / `StructuredTool` /
 * `RunnableLike` interface — it can be plugged into any LangChain agent without
 * importing `@langchain/core`.
 *
 * @throws {TypeError} synchronously when `runtime` is not a
 *   {@link LocalCapabilityRuntime} or when required fields are missing.
 *
 * @example
 * ```ts
 * const tool = wrapAsLangChainTool(runtime, {
 *   name:        'query_db',
 *   description: 'Run a read-only SQL query',
 *   schema:      { type: 'object', properties: { sql: { type: 'string' } } },
 *   handler:     async ({ sql }) => db.query(String(sql)),
 * });
 * ```
 */
export function wrapAsLangChainTool(
  runtime: LocalCapabilityRuntime,
  definition: LocalToolDefinition,
): LangChainCompatibleTool {
  // Guard: runtime must look like a LocalCapabilityRuntime.
  if (
    !runtime ||
    typeof runtime !== 'object' ||
    typeof (runtime as { invokeTool?: unknown }).invokeTool !== 'function' ||
    typeof (runtime as { isTerminated?: unknown }).isTerminated !== 'function'
  ) {
    throw new TypeError(
      'wrapAsLangChainTool: `runtime` must be a LocalCapabilityRuntime ' +
        '(invokeTool + isTerminated methods required).',
    );
  }

  // Guard: name is required.
  if (!definition || typeof definition.name !== 'string' || !definition.name.trim()) {
    throw new TypeError('wrapAsLangChainTool: `definition.name` is required.');
  }

  const { name, description, schema, handler, transformArgs, sourceIp, resource } = definition;

  const run = async (input: unknown): Promise<string> => {
    // 1. Normalise arguments.
    let args: Record<string, unknown>;
    try {
      args = normalizeArgs(input, transformArgs);
    } catch (err) {
      throw err; // TypeError from normalizeArgs propagates directly.
    }

    // 2. Enforce via the runtime. Generate the correlation ID here so it is
    //    shared between the audit record (via requestId) and the thrown
    //    CapabilityDenialError — enabling exact join between callback events
    //    and OCSF entries.
    const correlationId = newCorrelationId();
    const result = await runtime.invokeTool({
      tool: name,
      args,
      resource: resource ?? `mcp-tool://${name}`,
      sourceIp,
      correlationId,
    });

    if (!result.success) {
      // Map denial to a numeric status code roughly matching HTTP semantics.
      const statusCode = mapDenialCodeToStatus(result.denialCode);
      throw new CapabilityDenialError({
        message: result.denialReason ?? `Tool call '${name}' was denied by policy`,
        statusCode,
        errorCode: result.denialCode ?? 'CAPABILITY_DENIED',
        tool: name,
        resource: resource ?? `mcp-tool://${name}`,
        correlationId,
        details: result.details,
        conditionType: result.conditionType,
      });
    }

    // 3. Call the optional handler.
    if (typeof handler === 'function') {
      const handlerResult = await handler(args);
      return coerceToString(handlerResult);
    }

    // No handler — return empty string (useful for enforcement-only wrappers).
    return '';
  };

  return {
    name,
    description,
    schema,
    invoke: (input) => run(input),
    call: (input) => run(input),
    func: (input) => run(input),
  };
}

/**
 * Bulk-wrap helper for the common case where an agent registers many tools.
 *
 * @example
 * ```ts
 * const tools = wrapAsLangChainTools(runtime, [
 *   { name: 'query_db', description: '…', handler: queryDb },
 *   { name: 'send_email', description: '…', handler: sendEmail },
 * ]);
 * ```
 */
export function wrapAsLangChainTools(
  runtime: LocalCapabilityRuntime,
  definitions: readonly LocalToolDefinition[],
): LangChainCompatibleTool[] {
  return definitions.map((d) => wrapAsLangChainTool(runtime, d));
}

// ---------------------------------------------------------------------------
// Denial → HTTP status mapping
// ---------------------------------------------------------------------------

/** Map a machine-readable denial code to an approximate HTTP status code. */
function mapDenialCodeToStatus(denialCode: string | undefined): number {
  const MAP: Record<string, number> = {
    KILL_SWITCH: 503,
    MAX_CALLS_EXCEEDED: 429,
    TIME_WINDOW_DENIED: 403,
    OPERATION_NOT_ALLOWED: 403,
    EXTENSION_NOT_ALLOWED: 403,
    TABLE_NOT_ALLOWED: 403,
    VALUE_NOT_ALLOWED: 403,
    IP_RANGE_DENIED: 403,
    RECIPIENT_DOMAIN_DENIED: 403,
    POLICY_BACKEND_DENIED: 403,
    ARGUMENT_VALIDATION_FAILED: 422,
    CAPABILITY_DENIED: 403,
    CONDITION_NOT_SATISFIED: 403,
  };
  return MAP[denialCode ?? ''] ?? 403;
}

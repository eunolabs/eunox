/**
 * Shared upstream-timeout utilities used by both StdioProxy and HttpProxy.
 *
 * Keeping the timeout logic in one place ensures that any future changes
 * (e.g. cancellation, error-message format) land consistently across
 * both transports.
 */

/**
 * Thrown (via a rejected Promise) when the upstream MCP server does not
 * respond to a `tools/call` within the configured timeout window.
 *
 * Use `instanceof UpstreamTimeoutError` to distinguish timeouts from other
 * upstream errors — this is more reliable than parsing `Error.message`.
 */
export class UpstreamTimeoutError extends Error {
  /** The tool name that timed out. */
  readonly toolName: string;
  /** The timeout that elapsed (milliseconds). */
  readonly timeoutMs: number;

  constructor(toolName: string, timeoutMs: number) {
    super(`Upstream did not respond to tool "${toolName}" within ${timeoutMs} ms`);
    this.name = 'UpstreamTimeoutError';
    this.toolName = toolName;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Race an async operation against a millisecond timeout.
 *
 * When `timeoutMs` is `undefined` (or ≤ 0) the operation is returned
 * as-is with no timeout applied.
 *
 * On timeout, the returned promise rejects with an {@link UpstreamTimeoutError}.
 * Use `instanceof UpstreamTimeoutError` to detect timeouts reliably.
 */
export function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number | undefined,
  toolName: string,
): Promise<T> {
  if (timeoutMs === undefined || timeoutMs <= 0) {
    return operation;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new UpstreamTimeoutError(toolName, timeoutMs));
    }, timeoutMs);
    // Allow Node.js to exit even if the timer is still pending.
    timer.unref();
  });
  return Promise.race([operation, timeoutPromise]).finally(() => {
    clearTimeout(timer);
  });
}

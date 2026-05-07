/**
 * Response-redaction strategies
 * ---------------------------------------------------------------------------
 * The buffered-proxy path applies a `redactFields` (or any other response-time)
 * obligation to upstream bodies before forwarding. Different content-types
 * require different parsers and serializers — JSON today, NDJSON / CSV /
 * Parquet potentially in the future. Rather than burning a fresh `if` ladder
 * into the proxy interceptor each time, the dispatcher consults a small
 * registry of `RedactionStrategy` instances and picks the first one whose
 * `canHandle(contentType)` returns true.
 *
 * Today there is exactly one built-in strategy ({@link JsonRedactionStrategy}),
 * which preserves the previous behaviour (RFC-6839 `+json` allowlist, parse →
 * apply → re-serialize). The seam exists so that adding a future content-type
 * (e.g. `application/x-ndjson` for line-delimited JSON exports, or
 * `text/csv` with column-header awareness) is a matter of dropping a new
 * `RedactionStrategy` into {@link DEFAULT_REDACTION_STRATEGIES} — the
 * dispatcher in `proxy.ts` is unchanged.
 *
 * **Streaming fail-closed:** `text/event-stream` (Server-Sent Events) is
 * intentionally surfaced as a *separate* unsupported case
 * ({@link isStreamingMediaType}) rather than the generic content-type
 * mismatch, because SSE redaction would require frame-level parsing that we
 * do not currently support. Operators get a distinct audit code
 * (`REDACTION_STREAM_UNSUPPORTED`) so an attacker probing for SSE bypass is
 * visible in the audit trail.
 */
/**
 * Permissive value type matching what the upstream JSON parser produces.
 * Mirrors the shape `EnforcementResult.applyResponseRedactions` operates on
 * (the obligation closure is itself untyped wrt. body shape).
 */
export type RedactableValue = unknown;

/**
 * One per-content-class redactor. `canHandle` is consulted in registration
 * order; the first match wins. `apply` is invoked once per response and is
 * expected to be CPU-bound (no I/O) — the dispatcher already enforces the
 * size cap before calling.
 */
export interface RedactionStrategy {
  /** Stable, human-readable name used in audit/log entries. */
  readonly name: string;
  /**
   * Return true when this strategy knows how to parse + re-serialize bodies
   * with the given (already lower-cased and parameter-stripped) MIME type.
   */
  canHandle(mimeType: string): boolean;
  /**
   * Apply the supplied redactor to the body. Implementations MUST throw on
   * parse failure so the dispatcher can emit the canonical
   * `REDACTION_PARSE_ERROR` 502 — never silently pass the original buffer
   * through (that would defeat the obligation).
   */
  apply(body: Buffer, redactor: (value: RedactableValue) => RedactableValue): Buffer;
}

/**
 * Strip parameters (e.g. `; charset=utf-8`) from a Content-Type header and
 * lower-case the result. Returns `''` when the header is absent or empty so
 * callers can compare against a known set without further normalization.
 */
export function normalizeMimeType(rawContentType: string | undefined): string {
  if (!rawContentType) return '';
  const head = rawContentType.split(';')[0];
  return (head ?? '').trim().toLowerCase();
}

/**
 * True when the upstream MIME type denotes a streaming/event-oriented
 * payload that the buffered-redaction path cannot meaningfully handle.
 *
 * Surfaced as a dedicated unsupported case (vs. a generic content-type
 * mismatch) so audit consumers can distinguish "backend returned a PDF"
 * from "backend opened an SSE channel" — the latter is far more likely
 * to be a deliberate redaction-bypass attempt.
 */
export function isStreamingMediaType(mimeType: string): boolean {
  return mimeType === 'text/event-stream';
}

/**
 * Built-in strategy for `application/json` (and any `+json` structured-suffix
 * media type, per RFC 6839 §3.1, e.g. `application/hal+json`,
 * `application/problem+json`).
 */
export class JsonRedactionStrategy implements RedactionStrategy {
  readonly name = 'json';

  canHandle(mimeType: string): boolean {
    return mimeType === 'application/json' || mimeType.endsWith('+json');
  }

  apply(body: Buffer, redactor: (value: RedactableValue) => RedactableValue): Buffer {
    const parsed = JSON.parse(body.toString('utf8')) as RedactableValue;
    const redacted = redactor(parsed);
    return Buffer.from(JSON.stringify(redacted), 'utf8');
  }
}

/**
 * Convenience helper exposed primarily for tests: parse-redact-serialize
 * with a caller-supplied redactor closure.
 */
export function applyJsonRedaction(
  body: Buffer,
  redactor: (value: RedactableValue) => RedactableValue,
): Buffer {
  return new JsonRedactionStrategy().apply(body, redactor);
}

/**
 * Default strategy registry. Order matters: the dispatcher uses the first
 * `canHandle` match. JSON is the only built-in today.
 */
export const DEFAULT_REDACTION_STRATEGIES: ReadonlyArray<RedactionStrategy> = Object.freeze([
  new JsonRedactionStrategy(),
]);

/** Look up the strategy for a normalized MIME type, or `undefined` when none. */
export function selectRedactionStrategy(
  mimeType: string,
  strategies: ReadonlyArray<RedactionStrategy> = DEFAULT_REDACTION_STRATEGIES,
): RedactionStrategy | undefined {
  return strategies.find((s) => s.canHandle(mimeType));
}

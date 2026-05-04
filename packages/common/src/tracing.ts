/**
 * OpenTelemetry context propagation primitives for Euno services.
 *
 * R-3 in `docs/IMPROVEMENTS_AND_REFACTORING.md`:
 *
 *   "Adopt `@opentelemetry/api` in `@euno/common` and propagate a single
 *    `traceparent` header from the agent runtime through the gateway to
 *    the backend. Each of issuer / gateway / runtime emits one span per
 *    request with attributes `euno.agent_id`, `euno.jti`, `euno.action`,
 *    `euno.resource`, `euno.outcome`. The audit logger consumes the
 *    active span context so every audit event carries `trace_id` and
 *    `span_id`. This is invasive at the *integration* level but additive
 *    at the *type* level; it should not break existing callers."
 *
 * Implementation strategy
 * -----------------------
 * We depend on `@opentelemetry/api` only — the *contract* package, not an
 * SDK. When no SDK is registered (the default for the unit-test run, the
 * existing `npm test` flows, and any caller that has not wired in an
 * exporter), every operation here is a no-op:
 *
 *   * `getTracer()` returns the global proxy tracer, whose spans are
 *     non-recording and whose `spanContext()` is invalid.
 *   * `getCurrentTraceContext()` returns `null` for invalid contexts, so
 *     audit logs simply omit the `trace_id` / `span_id` fields rather
 *     than carrying placeholder zeros.
 *   * `tracingMiddleware` still parses an inbound `traceparent` so a
 *     downstream span — once an SDK *is* attached — observes the same
 *     trace ID even if the local process is not exporting.
 *
 * This keeps the change additive at the type level (no breaking API in
 * the rest of the monorepo) while making the wiring real, so flipping on
 * an SDK in a deployment is a config-only change.
 */

import {
  trace,
  context,
  propagation,
  SpanKind,
  SpanStatusCode,
  type Span,
  type SpanContext,
  type Tracer,
  type Context,
  type Attributes,
  type TextMapGetter,
  type TextMapSetter,
} from '@opentelemetry/api';
import {
  W3CTraceContextPropagator,
  CompositePropagator,
  W3CBaggagePropagator,
} from '@opentelemetry/core';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';

export { SpanKind, SpanStatusCode, type Span, type Tracer };

/**
 * Register a default W3C trace-context + baggage propagator AND a real
 * async-local-storage context manager on first import.
 *
 * The `@opentelemetry/api` package ships no-op defaults out of the box,
 * which would silently make `propagation.extract` / `propagation.inject`
 * and `context.with(...)` no-ops — so any deployment that adopts an SDK
 * later would still not propagate either the `traceparent` header *or*
 * the active span context across async boundaries.
 *
 * Registering both at module load time guarantees:
 *
 *   - **Without an SDK:** spans are non-recording but the trace IDs in
 *     `traceparent` flow end-to-end (issuer → gateway → runtime), and
 *     `context.active()` correctly returns the request's parent span
 *     inside async handlers — so the audit logger picks up `trace_id`
 *     and `span_id` automatically.
 *   - **With an SDK:** callers can override either the propagator or
 *     the context manager via `propagation.setGlobalPropagator(...)` /
 *     `context.setGlobalContextManager(...)`. These defaults are not
 *     authoritative; they just provide a sensible baseline.
 */
function ensureDefaults(): void {
  // 1. Propagator: probe with `propagation.fields()`. The no-op
  //    propagator returns no fields; the W3C composite returns
  //    `traceparent`, `tracestate`, `baggage`.
  const fields = propagation.fields();
  if (!fields || fields.length === 0) {
    propagation.setGlobalPropagator(
      new CompositePropagator({
        propagators: [
          new W3CTraceContextPropagator(),
          new W3CBaggagePropagator(),
        ],
      }),
    );
  }

  // 2. Context manager: probe by activating a context with a sentinel
  //    value and reading it back. The no-op manager won't preserve it.
  //    Wrapping in try/catch so a misbehaving custom manager doesn't
  //    crash the import.
  try {
    const sentinelKey = Symbol.for('euno.tracing.contextProbe');
    const probed = context
      .with(context.active().setValue(sentinelKey, 1), () =>
        context.active().getValue(sentinelKey),
      );
    if (probed !== 1) {
      const mgr = new AsyncLocalStorageContextManager();
      mgr.enable();
      context.setGlobalContextManager(mgr);
    }
  } catch {
    /* leave context manager as-is on probe failure */
  }
}
ensureDefaults();

/**
 * Standard `euno.*` span/log attribute names. Centralised so producers
 * and consumers cannot drift on spelling.
 */
export const EUNO_ATTR = {
  AGENT_ID: 'euno.agent_id',
  JTI: 'euno.jti',
  ACTION: 'euno.action',
  RESOURCE: 'euno.resource',
  OUTCOME: 'euno.outcome',
  SERVICE: 'euno.service',
  REASON: 'euno.reason',
  /**
   * Logical region tag for the issuer or gateway instance handling the
   * request. Set by {@link tracingMiddleware} from its `region`
   * option (operators thread it from `ISSUER_REGION` / `GATEWAY_REGION`).
   * F-7 in `docs/IMPROVEMENTS_AND_REFACTORING.md` — required so a
   * trace recorded during a regional failover can be attributed to the
   * region that actually served it.
   */
  REGION: 'euno.region',
} as const;

/** Allowed values for the `euno.outcome` attribute. */
export type EunoOutcome = 'allow' | 'deny' | 'error' | 'success' | 'failure';

/**
 * A subset of {@link Attributes} with strongly-typed Euno attribute keys.
 * Callers can pass either string literals or this typed shape.
 */
export interface EunoSpanAttributes {
  [EUNO_ATTR.AGENT_ID]?: string;
  [EUNO_ATTR.JTI]?: string;
  [EUNO_ATTR.ACTION]?: string;
  [EUNO_ATTR.RESOURCE]?: string;
  [EUNO_ATTR.OUTCOME]?: EunoOutcome;
  [EUNO_ATTR.SERVICE]?: string;
  [EUNO_ATTR.REASON]?: string;
  [EUNO_ATTR.REGION]?: string;
  [key: string]: string | number | boolean | undefined;
}

/** Per-process cache of tracers by service name. */
const tracerCache: Map<string, Tracer> = new Map();

/**
 * Obtain a tracer scoped to the given service.  The returned tracer is
 * shared per process so callers do not hold onto stale references after a
 * later SDK registration.  When no SDK is registered the OTel API
 * returns a no-op proxy tracer; we still cache it so behaviour is stable
 * during a process lifetime.
 */
export function getTracer(serviceName: string): Tracer {
  let t = tracerCache.get(serviceName);
  if (!t) {
    t = trace.getTracer(serviceName);
    tracerCache.set(serviceName, t);
  }
  return t;
}

/**
 * Reset cached tracers. Intended for tests that want a clean slate after
 * registering / unregistering a tracer provider; production code never
 * needs to call this.
 */
export function _resetTracerCacheForTesting(): void {
  tracerCache.clear();
}

/**
 * The active span context, if any, in a form that is safe to embed in a
 * structured log entry.  Returns `null` when there is no active span or
 * the context is the invalid context (which is what the no-op SDK
 * returns).  The `traceFlags` field is included so downstream samplers
 * have the full W3C trace-context information to decide whether to
 * forward the trace.
 */
export interface TraceContextSnapshot {
  trace_id: string;
  span_id: string;
  trace_flags: number;
}

/**
 * Returns the active trace context, or `null` if there isn't one.
 * Does not throw.
 */
export function getCurrentTraceContext(
  ctx: Context = context.active(),
): TraceContextSnapshot | null {
  const span = trace.getSpan(ctx);
  if (!span) return null;
  const sc = span.spanContext();
  if (!isValidSpanContext(sc)) return null;
  return {
    trace_id: sc.traceId,
    span_id: sc.spanId,
    trace_flags: sc.traceFlags,
  };
}

/**
 * Local validity check that does not require pulling in the
 * trace.isSpanContextValid helper; matches its semantics. Both fields
 * must be non-zero hex strings of the canonical W3C lengths.
 *
 * Exported so tests can assert on extracted contexts.
 */
export function isValidSpanContext(sc: SpanContext | undefined): boolean {
  if (!sc) return false;
  return (
    typeof sc.traceId === 'string' &&
    typeof sc.spanId === 'string' &&
    sc.traceId.length === 32 &&
    sc.spanId.length === 16 &&
    sc.traceId !== '00000000000000000000000000000000' &&
    sc.spanId !== '0000000000000000'
  );
}

// ---------------------------------------------------------------------------
// Header propagation (W3C traceparent / tracestate)
// ---------------------------------------------------------------------------

/**
 * `TextMapGetter` for header bags whose values can be `string |
 * string[] | undefined` — i.e. the shape Node's `IncomingMessage.headers`
 * exposes.  We normalise array headers to their first element because
 * `traceparent` is a single-valued header per RFC.
 */
const headerGetter: TextMapGetter<Record<string, string | string[] | undefined>> = {
  keys(carrier) {
    return Object.keys(carrier);
  },
  get(carrier, key) {
    // Header lookups must be case-insensitive (HTTP/1.1 §3.2).  Try the
    // exact key first (fast path) then a case-insensitive match.
    const direct = carrier[key];
    if (direct !== undefined) {
      return Array.isArray(direct) ? direct[0] : direct;
    }
    const lower = key.toLowerCase();
    for (const k of Object.keys(carrier)) {
      if (k.toLowerCase() === lower) {
        const v = carrier[k];
        return Array.isArray(v) ? v[0] : v;
      }
    }
    return undefined;
  },
};

/**
 * `TextMapSetter` for plain string-valued header bags. We always write
 * canonical lowercase header names so duplicate-with-different-case
 * issues cannot surface downstream.
 */
const headerSetter: TextMapSetter<Record<string, string>> = {
  set(carrier, key, value) {
    carrier[key.toLowerCase()] = value;
  },
};

/**
 * Extract a propagated context from an HTTP-style header bag and return
 * a Context with that propagated context as its parent.
 *
 * Falls back to the active context (preserving any process-local span)
 * when the header bag does not contain a valid `traceparent`.
 *
 * Safe to call even when no propagator has been registered — the global
 * propagator defaults to W3C trace-context and `tracestate`.
 */
export function extractTraceContext(
  headers: Record<string, string | string[] | undefined>,
  parent: Context = context.active(),
): Context {
  return propagation.extract(parent, headers, headerGetter);
}

/**
 * Inject the current (or supplied) context into the supplied header bag
 * so it can be forwarded over HTTP. Mutates and returns `headers` for
 * call-site convenience.
 */
export function injectTraceContext(
  headers: Record<string, string> = {},
  ctx: Context = context.active(),
): Record<string, string> {
  propagation.inject(ctx, headers, headerSetter);
  return headers;
}

// ---------------------------------------------------------------------------
// Span helpers
// ---------------------------------------------------------------------------

/**
 * Set every supplied attribute on the span, skipping `undefined` values
 * so we don't emit empty attributes that would later show up as
 * `"euno.jti": undefined` in exporters that serialise them eagerly.
 */
export function setEunoAttributes(span: Span, attrs: EunoSpanAttributes): void {
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined) continue;
    span.setAttribute(k, v);
  }
}

/**
 * Run `fn` inside a new span. The span is ended automatically; on
 * thrown error the span records the exception and is marked as ERROR
 * before the error is re-thrown.
 *
 * No-op-friendly: when no SDK is registered the underlying span is a
 * non-recording span and this is a thin wrapper around `fn()`.
 */
export async function withSpan<T>(
  tracer: Tracer,
  name: string,
  attrs: EunoSpanAttributes,
  fn: (span: Span) => Promise<T> | T,
  kind: SpanKind = SpanKind.INTERNAL,
): Promise<T> {
  const span = tracer.startSpan(name, { kind, attributes: stripUndefined(attrs) });
  try {
    return await context.with(trace.setSpan(context.active(), span), () => fn(span));
  } catch (err) {
    span.recordException(err as Error);
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: err instanceof Error ? err.message : String(err),
    });
    setEunoAttributes(span, { [EUNO_ATTR.OUTCOME]: 'error' });
    throw err;
  } finally {
    span.end();
  }
}

function stripUndefined(attrs: EunoSpanAttributes): Attributes {
  const out: Attributes = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined) {
      out[k] = v as string | number | boolean;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

/**
 * Minimal duck-typed Express handler signatures so we don't pull
 * `@types/express` into `@euno/common` (which has no other Express
 * dependency).
 */
interface IncomingLike {
  method?: string;
  path?: string;
  url?: string;
  originalUrl?: string;
  route?: { path?: string };
  headers: Record<string, string | string[] | undefined>;
}

interface OutgoingLike {
  statusCode?: number;
  setHeader: (name: string, value: string) => void;
  getHeader?: (name: string) => string | number | string[] | undefined;
  on: (event: string, listener: () => void) => void;
}

type NextFn = (err?: unknown) => void;

/**
 * Express middleware that:
 *
 *   1. Extracts a propagated trace context from the inbound request
 *      headers (W3C `traceparent` / `tracestate`).
 *   2. Starts a SERVER span named `<METHOD> <route|path>` with the
 *      `euno.service` attribute pre-set.
 *   3. Activates the new span as the current context for the duration
 *      of the request, so anything downstream — handlers, audit logger,
 *      outbound `injectTraceContext()` calls — observes it.
 *   4. Echoes the resulting `traceparent` back on the response so
 *      clients can correlate without an exporter on the server side.
 *   5. Ends the span on response `finish`/`close`, recording the HTTP
 *      status as the `euno.outcome` (success/failure) when no
 *      enforcement decision has overridden it.
 *
 * The middleware itself never throws; tracing failures must not break
 * the request path.
 */
/**
 * Options for {@link tracingMiddleware}. Kept as a separate object so
 * back-compat callers (`tracingMiddleware(serviceName)` with a single
 * string argument) continue to work unchanged.
 */
export interface TracingMiddlewareOptions {
  /**
   * Logical region tag for the service instance handling the request
   * (F-7). When supplied, every request span is stamped with
   * `euno.region`. Plumbed by the issuer from `ISSUER_REGION` and by
   * the gateway from `GATEWAY_REGION`. Empty string is treated as
   * "not configured" and the attribute is omitted.
   */
  region?: string;
}

export function tracingMiddleware(
  serviceName: string,
  options: TracingMiddlewareOptions = {},
) {
  const tracer = getTracer(serviceName);
  // Match createAuditLogger's whitespace handling — region tags are
  // user-supplied env vars (`ISSUER_REGION` / `GATEWAY_REGION`) and a
  // stray newline from a templating tool would otherwise produce a
  // surprisingly-formatted span attribute.
  const trimmedRegion = options.region?.trim();
  const region = trimmedRegion && trimmedRegion.length > 0 ? trimmedRegion : undefined;

  return function tracingMw(req: IncomingLike, res: OutgoingLike, next: NextFn): void {
    let parentCtx: Context;
    try {
      parentCtx = extractTraceContext(req.headers);
    } catch {
      parentCtx = context.active();
    }

    const method = (req.method || 'GET').toUpperCase();
    const routePath = req.route?.path || req.path || req.originalUrl || req.url || '/';
    const spanName = `${method} ${routePath}`;

    const baseAttrs: Record<string, string> = {
      [EUNO_ATTR.SERVICE]: serviceName,
      'http.method': method,
      'http.target': req.originalUrl || req.url || routePath,
    };
    if (region) baseAttrs[EUNO_ATTR.REGION] = region;

    const span = tracer.startSpan(
      spanName,
      {
        kind: SpanKind.SERVER,
        attributes: baseAttrs,
      },
      parentCtx,
    );

    // If no SDK is registered the started span is non-recording with an
    // invalid (all-zero) span context. In that case we still want
    // downstream code (audit logger, outbound `injectTraceContext`) to
    // see the IDs the upstream propagated to us, so fall back to a
    // non-recording span that *wraps the inbound remote context* and
    // make that the active span instead. When an SDK is registered, the
    // started span has a valid context and we use it directly.
    let activeSpan: Span = span;
    if (!isValidSpanContext(span.spanContext())) {
      const parentSpan = trace.getSpan(parentCtx);
      const parentSc = parentSpan?.spanContext();
      if (parentSc && isValidSpanContext(parentSc)) {
        activeSpan = trace.wrapSpanContext(parentSc);
      }
    }

    // Echo the trace context back on the response so a client without
    // its own SDK can still correlate. Wrapped in try/catch because some
    // response objects (e.g. early-closed sockets) reject `setHeader`.
    try {
      const echoHeaders: Record<string, string> = {};
      injectTraceContext(echoHeaders, trace.setSpan(parentCtx, activeSpan));
      const tp = echoHeaders.traceparent;
      if (tp) res.setHeader('traceparent', tp);
      const ts = echoHeaders.tracestate;
      if (ts) res.setHeader('tracestate', ts);
    } catch {
      /* response already sent / detached — ignore */
    }

    let ended = false;
    const finish = () => {
      if (ended) return;
      ended = true;
      const status = res.statusCode ?? 0;
      try {
        span.setAttribute('http.status_code', status);
        // Only stamp an outcome if a more specific producer (the
        // enforcement engine, the issuer, etc.) hasn't already set one
        // via {@link setEunoAttributes}. We can't read attributes off
        // a Span via the public API, so we default-stamp from status
        // and let later setAttribute calls win (they would have run
        // synchronously inside the request handler before `finish`).
        if (status >= 500) {
          span.setAttribute(EUNO_ATTR.OUTCOME, 'error');
          span.setStatus({ code: SpanStatusCode.ERROR });
        } else if (status >= 400) {
          // 4xx is a client-side issue, not a server failure — keep the
          // span status OK but mark the outcome as `deny` so dashboards
          // can split allow vs deny vs error.
          span.setAttribute(EUNO_ATTR.OUTCOME, 'deny');
        }
      } finally {
        span.end();
      }
    };

    res.on('finish', finish);
    res.on('close', finish);

    // Run the rest of the middleware chain inside the span context so
    // anything that grabs `context.active()` (audit logger, outbound
    // axios interceptor, etc.) sees the right trace IDs.
    context.with(trace.setSpan(parentCtx, activeSpan), () => next());
  };
}

/**
 * Convenience: returns the active span (if any) so handlers can stamp
 * `euno.*` attributes on the request span without re-extracting context.
 */
export function getActiveSpan(): Span | undefined {
  return trace.getSpan(context.active());
}

/**
 * Stamp `euno.*` attributes onto the active span. No-op when there is
 * no active span. Intended as a one-liner for handlers / enforcement
 * sites that learn the agent ID, capability ID, etc. mid-request.
 */
export function setActiveSpanEunoAttributes(attrs: EunoSpanAttributes): void {
  const span = getActiveSpan();
  if (!span) return;
  setEunoAttributes(span, attrs);
}

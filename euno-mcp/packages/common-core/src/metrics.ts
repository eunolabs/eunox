/**
 * Prometheus / OpenMetrics surface  (F-5, addresses I-16)
 * ---------------------------------------------------------------------------
 * Provides a small, framework-agnostic helper layer on top of `prom-client`
 * so each Euno service (Capability Issuer, Tool Gateway, …) can expose a
 * standard `/metrics` endpoint without re-implementing the same boilerplate.
 *
 * The contract intentionally stays minimal:
 *
 *   - {@link createMetricsRegistry}     builds a `prom-client` Registry with
 *                                       `service` as a default label and
 *                                       Node.js process metrics enabled.
 *   - {@link createHttpMetricsMiddleware} returns an Express-compatible
 *                                       middleware that records request
 *                                       duration + counts, labelled by
 *                                       method / route / status_code.
 *   - {@link createMetricsHandler}      returns an Express handler exposing
 *                                       `GET /metrics` in the Prometheus
 *                                       text exposition format.
 *
 * Services may register additional metrics (counters, gauges, histograms)
 * directly on the returned registry — for example the Tool Gateway adds a
 * `euno_gateway_revocation_list_size` gauge and a
 * `euno_gateway_decisions_total` counter, and the Capability Issuer adds an
 * `euno_issuer_issuance_total` counter.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § F-5.
 */

import {
  collectDefaultMetrics,
  Counter,
  Histogram,
  Registry,
} from 'prom-client';

/* ---------------- Types kept loose so we don't pull in @types/express ---------- */

/** Minimal request shape this module relies on. */
interface MetricsHttpRequest {
  method?: string;
  path?: string;
  route?: { path?: string };
  baseUrl?: string;
  originalUrl?: string;
}

/** Minimal response shape this module relies on. */
interface MetricsHttpResponse {
  statusCode: number;
  on(event: 'finish' | 'close', listener: () => void): unknown;
  setHeader(name: string, value: string): void;
  status(code: number): MetricsHttpResponse;
  end(body?: string): void;
}

/** Minimal Express-style next callback. */
type MetricsNextFn = () => void;

/** Express-style middleware signature without depending on @types/express. */
export type MetricsMiddleware = (
  req: MetricsHttpRequest,
  res: MetricsHttpResponse,
  next: MetricsNextFn,
) => void;

/* ---------------- Registry -------------------------------------------------- */

export interface CreateRegistryOptions {
  /**
   * Service name attached as a default label on every metric so multi-service
   * Prometheus scrapes can be filtered with `service="capability-issuer"` etc.
   */
  serviceName: string;
  /**
   * When `true` (default) registers Node.js process collectors
   * (`process_cpu_seconds_total`, `nodejs_eventloop_lag_seconds`, …).
   * Set `false` in unit tests if you want a deterministic, empty registry.
   */
  collectDefaults?: boolean;
}

/**
 * Build a fresh `prom-client` Registry pre-configured with the service-name
 * default label and (optionally) Node.js process metrics. Each service should
 * own exactly one of these so the metric namespace cannot leak between tests.
 */
export function createMetricsRegistry(opts: CreateRegistryOptions): Registry {
  const registry = new Registry();
  registry.setDefaultLabels({ service: opts.serviceName });
  if (opts.collectDefaults !== false) {
    collectDefaultMetrics({ register: registry });
  }
  return registry;
}

/* ---------------- HTTP middleware ------------------------------------------ */

export interface HttpMetricsOptions {
  registry: Registry;
  /**
   * Histogram buckets in seconds. Defaults to a spread suitable for
   * latency-sensitive HTTP APIs (1ms … 10s).
   */
  buckets?: number[];
  /**
   * Path pattern for the `/metrics` scrape endpoint itself. Excluded from
   * the histogram so scrapes don't dominate the latency series.
   * Defaults to `/metrics`.
   */
  excludeRoute?: string;
}

const DEFAULT_BUCKETS = [
  0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
];

/**
 * Determine a bounded-cardinality route label for an Express request.
 *
 * Prefers the matched route pattern (e.g. `/api/v1/issue`) over the raw URL
 * so dynamic path segments (token JTIs, agent IDs) do not explode the metric
 * cardinality. Falls back to `'unmatched'` when the request never reached a
 * route handler (e.g. 404).
 */
function deriveRouteLabel(req: MetricsHttpRequest): string {
  const matched = req.route?.path;
  if (matched) {
    const base = req.baseUrl ?? '';
    return base + matched;
  }
  return 'unmatched';
}

/**
 * Build an Express middleware that records request count + duration.
 *
 * Registers (idempotently) the following metrics on the supplied registry:
 *
 *   - `euno_http_request_duration_seconds`  histogram
 *     labels: method, route, status_code
 *   - `euno_http_requests_total`            counter
 *     labels: method, route, status_code
 *
 * The combination supports operator queries such as a P99 latency SLO,
 * per-route deny-rate (`status_code=~"4.."`), and traffic mix.
 */
export function createHttpMetricsMiddleware(
  opts: HttpMetricsOptions,
): MetricsMiddleware {
  const { registry } = opts;
  const excludeRoute = opts.excludeRoute ?? '/metrics';

  const histogram =
    (registry.getSingleMetric('euno_http_request_duration_seconds') as
      | Histogram<string>
      | undefined) ??
    new Histogram({
      name: 'euno_http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds, labelled by method, route and status code.',
      labelNames: ['method', 'route', 'status_code'],
      buckets: opts.buckets ?? DEFAULT_BUCKETS,
      registers: [registry],
    });

  const counter =
    (registry.getSingleMetric('euno_http_requests_total') as
      | Counter<string>
      | undefined) ??
    new Counter({
      name: 'euno_http_requests_total',
      help: 'Total HTTP requests handled, labelled by method, route and status code.',
      labelNames: ['method', 'route', 'status_code'],
      registers: [registry],
    });

  return function httpMetricsMiddleware(req, res, next): void {
    // Skip the scrape endpoint to avoid self-reporting and keep latency
    // histograms focused on real traffic.
    if (req.path === excludeRoute || req.originalUrl === excludeRoute) {
      next();
      return;
    }

    const start = process.hrtime.bigint();
    const finalize = () => {
      const route = deriveRouteLabel(req);
      const labels = {
        method: (req.method ?? 'GET').toUpperCase(),
        route,
        status_code: String(res.statusCode),
      };
      const elapsedSeconds =
        Number(process.hrtime.bigint() - start) / 1_000_000_000;
      histogram.observe(labels, elapsedSeconds);
      counter.inc(labels);
    };

    // `finish` covers the normal write-end path. Some clients hang up before
    // the response is flushed (especially long proxy reads); `close` ensures
    // we still record those, while `once`-style guards prevent double-counts.
    let recorded = false;
    const recordOnce = () => {
      if (recorded) return;
      recorded = true;
      finalize();
    };
    res.on('finish', recordOnce);
    res.on('close', recordOnce);
    next();
  };
}

/* ---------------- /metrics router ------------------------------------------ */

/**
 * Express-style router signature. We reproduce the very small subset of the
 * `Router` shape we need so this module does not need a runtime dependency
 * on Express. Callers (`tool-gateway`, `capability-issuer`) pass the result
 * straight to `app.use(...)`.
 */
export interface MetricsRouter {
  (req: MetricsHttpRequest, res: MetricsHttpResponse, next: MetricsNextFn): void;
}

/**
 * Build a tiny Express handler that serves `GET /metrics` from the supplied
 * registry. Returns 405 for any other method so misuses are easy to spot.
 *
 * This intentionally does not pull in `express.Router()` — the handler is
 * a plain function so callers can mount it with either `app.get('/metrics', …)`
 * or `app.use(…)`. Both wire-ups are exercised by the unit tests.
 */
export function createMetricsHandler(registry: Registry): MetricsRouter {
  return function metricsHandler(req, res, next): void {
    // When mounted as `app.use(handler)`, only respond to `/metrics` so the
    // handler can sit alongside other routes without intercepting traffic.
    // When mounted as `app.get('/metrics', handler)` the path check is a
    // no-op (Express has already filtered).
    const path = req.path ?? req.originalUrl ?? '';
    if (path !== '/metrics') {
      next();
      return;
    }

    if ((req.method ?? 'GET').toUpperCase() !== 'GET') {
      res.status(405).end('Method Not Allowed');
      return;
    }

    registry
      .metrics()
      .then((body) => {
        res.setHeader('Content-Type', registry.contentType);
        res.status(200).end(body);
      })
      .catch((err) => {
        res.status(500).end(
          `# Failed to collect metrics: ${
            err instanceof Error ? err.message : String(err)
          }\n`,
        );
      });
  };
}

/* ---------------- Re-exports ----------------------------------------------- */

// Re-export the prom-client primitives so callers don't need to add
// `prom-client` to their own `package.json` just to register a counter.
export { Counter, Gauge, Histogram, Registry, Summary } from 'prom-client';

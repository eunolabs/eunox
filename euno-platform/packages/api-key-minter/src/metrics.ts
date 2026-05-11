/**
 * Minter Prometheus metrics (Task 11, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * All minter metrics use a shared `prometheus.Registry` instance so that
 * the `/metrics` endpoint can be served independently of the default global
 * registry (which may be shared across packages in a monolith deployment).
 *
 * ## Metrics exposed
 *
 * | Metric | Type | Labels | Description |
 * |---|---|---|---|
 * | `euno_minter_mint_total` | Counter | `tenant`, `result` | Total mint requests by tenant and result (`minted` / `authentication_failed` / `rate_limited` / `invalid_request`) |
 * | `euno_minter_mint_latency_seconds` | Histogram | `tenant` | End-to-end mint request latency in seconds |
 * | `euno_minter_kms_error_total` | Counter | `provider`, `operation` | KMS call errors (sign / get_public_key / get_key_id) by provider |
 * | `euno_minter_anomaly_alerts_total` | Counter | `tenant`, `kind` | Mint anomaly alerts (e.g. `burst_detected`, `cross_tenant_probe`) |
 *
 * ## Usage
 *
 * ```typescript
 * import { minterMetrics } from '@euno/api-key-minter';
 *
 * // Record a successful mint
 * minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'minted' });
 *
 * // Record KMS signing latency
 * const end = minterMetrics.mintLatencySeconds.startTimer({ tenant: 'acme' });
 * await signToken(...);
 * end();
 *
 * // Expose /metrics endpoint (add to Express app)
 * app.get('/metrics', async (_req, res) => {
 *   res.set('Content-Type', minterMetrics.registry.contentType);
 *   res.send(await minterMetrics.registry.metrics());
 * });
 * ```
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
const promClient: typeof import('prom-client') = require('prom-client');

// ── Registry ──────────────────────────────────────────────────────────────────

/**
 * Isolated Prometheus registry for the minter service.
 *
 * Using an isolated registry (rather than the default global) prevents
 * metric name collisions in monolith deployments where multiple packages
 * share the same Node.js process.
 */
export const minterRegistry = new promClient.Registry();

// Default labels applied to every metric in this registry.
minterRegistry.setDefaultLabels({ service: 'euno-minter' });

// ── Counters and Histograms ───────────────────────────────────────────────────

/**
 * Total mint requests, partitioned by tenant and result.
 *
 * `result` label values:
 * - `'minted'`                — token successfully issued
 * - `'authentication_failed'` — API key not recognised / invalid signature
 * - `'rate_limited'`          — per-tenant rate limit exceeded
 * - `'invalid_request'`       — missing / malformed request body
 * - `'kms_error'`             — KMS signing call failed
 * - `'internal_error'`        — unexpected server error
 */
export const mintTotal = new promClient.Counter({
  name: 'euno_minter_mint_total',
  help: 'Total mint requests by tenant and result',
  labelNames: ['tenant', 'result'] as const,
  registers: [minterRegistry],
});

/**
 * End-to-end mint request latency histogram (seconds).
 *
 * Buckets are tuned for typical HSM latencies (2–50 ms for software keys,
 * 50–500 ms for cloud HSM with regional routing).
 */
export const mintLatencySeconds = new promClient.Histogram({
  name: 'euno_minter_mint_latency_seconds',
  help: 'End-to-end mint request latency in seconds',
  labelNames: ['tenant'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [minterRegistry],
});

/**
 * KMS call errors, partitioned by provider and operation.
 *
 * `operation` label values: `'sign'`, `'get_public_key'`, `'get_key_id'`
 */
export const kmsErrorTotal = new promClient.Counter({
  name: 'euno_minter_kms_error_total',
  help: 'KMS call errors by provider and operation',
  labelNames: ['provider', 'operation'] as const,
  registers: [minterRegistry],
});

/**
 * Mint anomaly alerts.
 *
 * `kind` label values:
 * - `'burst_detected'`      — per-tenant mint rate far above baseline
 * - `'cross_tenant_probe'`  — same key prefix tried across tenants
 * - `'sequential_jti'`      — suspicious sequential JTI pattern
 */
export const anomalyAlertsTotal = new promClient.Counter({
  name: 'euno_minter_anomaly_alerts_total',
  help: 'Mint anomaly alerts by tenant and kind',
  labelNames: ['tenant', 'kind'] as const,
  registers: [minterRegistry],
});

// ── Bundled export ────────────────────────────────────────────────────────────

/**
 * Convenience bundle of all minter metrics.  Import this instead of the
 * individual counters/histograms to avoid N separate imports in call sites.
 */
export const minterMetrics = {
  registry: minterRegistry,
  mintTotal,
  mintLatencySeconds,
  kmsErrorTotal,
  anomalyAlertsTotal,
} as const;

/**
 * Minter Prometheus metrics (Task 12, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * All minter metrics use a shared `prometheus.Registry` instance so that
 * the `/metrics` endpoint can be served independently of the default global
 * registry (which may be shared across packages in a monolith deployment).
 *
 * ## Metrics exposed
 *
 * | Metric | Type | Labels | Description |
 * |---|---|---|---|
 * | `euno_minter_mint_total` | Counter | `tenant`, `result` | Total mint requests by tenant and result (`minted` / `authentication_failed` / `rate_limited` / `invalid_request` / `kms_error` / `internal_error`) |
 * | `euno_minter_mint_latency_seconds` | Histogram | `tenant` | End-to-end mint request latency in seconds |
 * | `euno_minter_kms_sign_latency_seconds` | Histogram | `provider` | HSM sign operation latency in seconds |
 * | `euno_minter_kms_error_total` | Counter | `provider`, `error_class` | KMS call errors (`sign_failed` / `auth_error` / `timeout` / `unavailable`) by provider |
 * | `euno_minter_anomaly_alerts_total` | Counter | `tenant`, `rule` | Mint anomaly alerts by tenant and rule name |
 * | `euno_minter_key_rotation_total` | Counter | `kid`, `reason` | Key rotation events (`scheduled` / `emergency` / `completed`) |
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
 * const end = minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'azure-keyvault' });
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
 * HSM sign operation latency histogram (seconds), partitioned by provider.
 *
 * Tracks only the cloud KMS/HSM signing call, excluding overhead such as
 * API-key verification, rate-limit checks, and audit writes.  This is the
 * metric to alert on when the HSM SLA degrades.
 *
 * `provider` label values: `'azure-keyvault'`, `'aws-kms'`, `'gcp-cloudkms'`, `'local'`
 */
export const kmsSignLatencySeconds = new promClient.Histogram({
  name: 'euno_minter_kms_sign_latency_seconds',
  help: 'HSM sign operation latency in seconds, partitioned by provider',
  labelNames: ['provider'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [minterRegistry],
});

/**
 * KMS call errors, partitioned by provider and error class.
 *
 * `error_class` label values:
 * - `'sign_failed'`  — the HSM rejected or failed the sign call
 * - `'auth_error'`   — workload identity was rejected (IAM/token expiry)
 * - `'timeout'`      — the HSM call timed out
 * - `'unavailable'`  — the KMS endpoint was unreachable (network partition / provider outage)
 */
export const kmsErrorTotal = new promClient.Counter({
  name: 'euno_minter_kms_error_total',
  help: 'KMS call errors by provider and error class',
  labelNames: ['provider', 'error_class'] as const,
  registers: [minterRegistry],
});

/**
 * Mint anomaly alerts, partitioned by tenant, rule name, and replica.
 *
 * Incremented by {@link AnomalyDetector} (and {@link RedisAnomalyDetector})
 * whenever a rule fires in-process.  The Prometheus alerting rules in
 * `prometheus/minter-alert-rules.yaml` provide the production alert routing;
 * this counter provides defence-in-depth and enables per-tenant anomaly
 * dashboards without complex PromQL.
 *
 * `rule` label values:
 * - `'rate_spike'`            — per-tenant mint rate far above baseline (Rule 1)
 * - `'off_hours_low_activity'`— off-hours mint for low-activity tenant (Rule 2)
 * - `'failure_clustering'`    — mint failure rate spike for tenant (Rule 3)
 *
 * `replica` label (CR-4):
 * The replica identifier — set from `MINTER_REPLICA_ID` env var or
 * `os.hostname()`.  An empty string `''` indicates the replica ID was not
 * configured.  The `replica` label allows operators to compare per-instance
 * anomaly rates in Prometheus; discrepancies between replicas indicate that
 * the anomaly detector is seeing only a fraction of fleet traffic (the
 * per-replica limitation described in docs/architecture-review-2026-05.md
 * CR-4).
 */
export const anomalyAlertsTotal = new promClient.Counter({
  name: 'euno_minter_anomaly_alerts_total',
  help: 'Mint anomaly alerts by tenant, rule name, and replica',
  labelNames: ['tenant', 'rule', 'replica'] as const,
  registers: [minterRegistry],
});

/**
 * Key rotation events, partitioned by key ID and reason.
 *
 * Incremented by {@link KeyRotationManager} at the start and completion of
 * each rotation. The `MinterEmergencyKeyRotation` Prometheus alert rule
 * fires when `reason="emergency"` increases.
 *
 * `reason` label values:
 * - `'scheduled'`  — routine key rotation initiated
 * - `'emergency'`  — compromise-response emergency rotation initiated
 * - `'completed'`  — rotation completed and old key retired
 */
export const keyRotationTotal = new promClient.Counter({
  name: 'euno_minter_key_rotation_total',
  help: 'Key rotation events by key ID and reason',
  labelNames: ['kid', 'reason'] as const,
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
  kmsSignLatencySeconds,
  kmsErrorTotal,
  anomalyAlertsTotal,
  keyRotationTotal,
} as const;

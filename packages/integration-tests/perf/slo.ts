/**
 * Service-level objectives (SLOs) for every Euno control-plane route.
 *
 * Implements I-22 ("set and defend SLOs") from
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`. This file is the **single source
 * of truth** for the targets the autocannon runner asserts in CI **and**
 * the thresholds the k6 scripts apply when run against deployed targets.
 * The TypeScript constant is consumed directly by the autocannon runner;
 * the same shape is mirrored to `slo.json` (see `bin/emit-slo-json.ts`)
 * so k6 can `open()` it without a Node toolchain.
 *
 * ### How these numbers were chosen
 *
 * The targets are **regression budgets**, not production capacity claims.
 * They are calibrated against a single Node 20 process running on a
 * commodity CI runner (2 vCPU, 7 GB RAM, no external Redis, no real
 * KMS) and rounded up to the nearest sensible humane number so the suite
 * tolerates ~2× ambient noise on a busy runner. Each scenario records
 * its observed p50/p99/throughput on every run so a sustained shift in
 * the median (faster or slower) shows up in PR diffs and lets the team
 * reason about whether to *raise* the bar (an improvement worth
 * defending) or *investigate* (a regression).
 *
 * ### How to defend / change an SLO
 *
 * 1. Run `npm run perf -- --json reports/before.json` on `main`.
 * 2. Apply the change.
 * 3. Run `npm run perf -- --json reports/after.json`.
 * 4. Compare. If a route gets faster, **lower** its `p99LatencyMs` here
 *    so the new floor is enforced. If a route legitimately needs more
 *    headroom (new crypto, new condition lobe), raise the budget and
 *    explain why in the PR description.
 *
 * Anything more aggressive than these defaults belongs in a scenario
 * override (see `lib/runner.ts`'s `runScenario`).
 */

/**
 * The contract every scenario asserts after autocannon completes. Any
 * absent field is interpreted as "unconstrained".
 */
export interface ScenarioSlo {
  /**
   * Hard ceiling on the 99th-percentile observed end-to-end latency, in
   * milliseconds (clock at the load generator). Asserted on the *post*
   * value autocannon reports.
   */
  p99LatencyMs?: number;
  /**
   * Hard ceiling on the 50th-percentile latency, in milliseconds. Used
   * to detect "fat-tail-only" regressions where the median creeps up
   * even when p99 stays inside its budget.
   */
  p50LatencyMs?: number;
  /**
   * Floor on sustained throughput (requests / second, mean across the
   * run). Routes whose purpose is to be cheap (health, metrics) carry
   * an explicit floor so a regression that quintuples per-request
   * cost is caught even when latency stays nominally inside p99.
   */
  minRequestsPerSecond?: number;
  /**
   * Ceiling on the rate of non-2xx / non-expected responses. Expressed
   * as a fraction in [0, 1]. Defaults to `0` so any unexpected error
   * fails the run; explicit-deny scenarios override to allow 4xx as
   * the *expected* outcome.
   */
  maxErrorRate?: number;
}

/**
 * Default duration / connection profile used by every scenario unless
 * overridden. Kept low enough that the full perf suite fits inside a
 * single CI step (~1 minute total) while still producing enough
 * samples (~5k–50k requests per scenario) for the percentiles to
 * stabilise.
 */
export const DEFAULT_LOAD_PROFILE = {
  /** Concurrent open connections. */
  connections: 20,
  /** Concurrent in-flight pipelined requests per connection. */
  pipelining: 1,
  /** Wall-clock seconds per scenario. */
  durationSeconds: 5,
} as const;

/**
 * SLOs per scenario. Keys are the canonical scenario names (also used
 * by `--scenario <name>` on the CLI and by the k6 scripts).
 *
 * The numbers here are the **observed-then-rounded-up** values from a
 * baseline `npm run perf` on a 2-vCPU CI runner. Tighten them when an
 * optimisation lands; loosen them only when the cost is justified
 * (new crypto, new condition lobe). See the change-management recipe
 * in the file header.
 */
export const SLOS: Readonly<Record<string, ScenarioSlo>> = {
  // ── Tool Gateway ────────────────────────────────────────────────────────
  'gateway-health-live': {
    p50LatencyMs: 15,
    p99LatencyMs: 50,
    minRequestsPerSecond: 1500,
    maxErrorRate: 0,
  },
  'gateway-health-ready': {
    p50LatencyMs: 15,
    p99LatencyMs: 50,
    minRequestsPerSecond: 1500,
    maxErrorRate: 0,
  },
  'gateway-health': {
    // Aliased to liveness in production; same budget.
    p50LatencyMs: 15,
    p99LatencyMs: 50,
    minRequestsPerSecond: 1500,
    maxErrorRate: 0,
  },
  'gateway-metrics': {
    p50LatencyMs: 30,
    p99LatencyMs: 150,
    minRequestsPerSecond: 500,
    maxErrorRate: 0,
  },
  'gateway-tools-invoke-allow': {
    p50LatencyMs: 30,
    p99LatencyMs: 100,
    minRequestsPerSecond: 500,
    maxErrorRate: 0,
  },
  'gateway-tools-invoke-deny': {
    p50LatencyMs: 30,
    p99LatencyMs: 100,
    minRequestsPerSecond: 500,
    // The deny path returns 403 on every request — that's the point
    // of the scenario, not an error from the runner's perspective.
    // The runner classifies "expected" status codes per scenario;
    // see `lib/runner.ts`.
    maxErrorRate: 0,
  },
  'gateway-validate': {
    p50LatencyMs: 30,
    p99LatencyMs: 100,
    minRequestsPerSecond: 500,
    maxErrorRate: 0,
  },
  'gateway-proxy-get': {
    // The proxy hot path is dominated by http-proxy-middleware's
    // upstream connection handling; on loopback the per-request cost
    // is meaningfully higher than the in-process routes above. The
    // SLO floor on req/s is the honest signal — regressions in
    // *connection reuse* show up here first.
    p50LatencyMs: 400,
    p99LatencyMs: 600,
    minRequestsPerSecond: 200,
    maxErrorRate: 0,
  },
  'gateway-proxy-post': {
    p50LatencyMs: 400,
    p99LatencyMs: 600,
    minRequestsPerSecond: 200,
    maxErrorRate: 0,
  },
  'gateway-admin-status': {
    // Auth header check + KillSwitchManager.getStatus() in-memory lookup.
    p50LatencyMs: 20,
    p99LatencyMs: 75,
    minRequestsPerSecond: 1000,
    maxErrorRate: 0,
  },
  // ── Capability Issuer ───────────────────────────────────────────────────
  'issuer-health': {
    p50LatencyMs: 15,
    p99LatencyMs: 50,
    minRequestsPerSecond: 1500,
    maxErrorRate: 0,
  },
  'issuer-metrics': {
    p50LatencyMs: 30,
    p99LatencyMs: 150,
    minRequestsPerSecond: 500,
    maxErrorRate: 0,
  },
  'issuer-jwks': {
    // Live key-distribution path. JWK encoding is cached-friendly,
    // but every request still re-exports the SPKI through Node crypto.
    p50LatencyMs: 15,
    p99LatencyMs: 75,
    minRequestsPerSecond: 1000,
    maxErrorRate: 0,
  },
  'issuer-public-key': {
    p50LatencyMs: 10,
    p99LatencyMs: 50,
    minRequestsPerSecond: 5000,
    maxErrorRate: 0,
  },
  'issuer-well-known-did': {
    p50LatencyMs: 15,
    p99LatencyMs: 75,
    minRequestsPerSecond: 1000,
    maxErrorRate: 0,
  },
  'issuer-well-known-meta': {
    // Static metadata document — should be the cheapest issuer route.
    p50LatencyMs: 10,
    p99LatencyMs: 50,
    minRequestsPerSecond: 5000,
    maxErrorRate: 0,
  },
  'issuer-issue': {
    // RSA-2048 sign dominates. Numbers reflect a software signer; an
    // HSM-backed signer will shift these by 5-10× and operators are
    // expected to override the SLO for their concrete deployment.
    p50LatencyMs: 30,
    p99LatencyMs: 100,
    minRequestsPerSecond: 500,
    maxErrorRate: 0,
  },
  'issuer-attenuate': {
    // Verify parent (RSA verify) + sign child (RSA sign) — roughly
    // double the issuance hot path's crypto cost.
    p50LatencyMs: 50,
    p99LatencyMs: 150,
    minRequestsPerSecond: 250,
    maxErrorRate: 0,
  },
  'issuer-renew': {
    // Verify current + sign renewed — same cost shape as attenuate.
    p50LatencyMs: 50,
    p99LatencyMs: 150,
    minRequestsPerSecond: 250,
    maxErrorRate: 0,
  },

  // ── Profiled issuance: KMS + stacked optionals ──────────────────────────
  //
  // Each scenario name follows the pattern `issuer-issue:<profile-tag>`.
  // Profile tags map to the definitions in `profiles/definitions.ts`.
  //
  // ### How these budgets were derived
  //
  // Budget = KMS_P95_LATENCY + optional_component_P95s + NODE_JS_OVERHEAD
  //
  // NODE_JS_OVERHEAD ≈ 50 ms (the existing `issuer-issue` baseline p99 — see
  // `profiles/definitions.ts` NODE_OVERHEAD_MS constant).
  //
  // Optional-component P95 estimates = 2× their simulated p50 latency
  // (conservative: accounts for realistic tail latency). Per-component values
  // from `profiles/definitions.ts` OPTIONAL_LATENCIES_MS:
  //   - cosigner:           2 ms p50 → 4 ms p95
  //   - sideCredentialsBroker: 8 ms p50 → 16 ms p95
  //   - transparencyLog:    3 ms p50 →  6 ms p95
  //
  // Full-stack profiles target ≤ 500 ms to defend the README claim.
  //
  // The throughput floors are intentionally lower than the baseline because
  // each request spends wall-clock time in the simulated delay, so concurrency
  // alone cannot sustain the same RPS as the software-signer path.
  //
  // ### Azure Key Vault
  'issuer-issue:azure': {
    // 100 (KMS p95) + 50 (Node overhead) = 150 ms
    p99LatencyMs: 150,
    maxErrorRate: 0,
  },
  'issuer-issue:azure+cosign': {
    // 100 (KMS p95) + 4 (cosign p95: 2×2) + 50 = 154 ms
    p99LatencyMs: 154,
    maxErrorRate: 0,
  },
  'issuer-issue:azure+sidecreds': {
    // 100 (KMS p95) + 16 (side-creds p95: 2×8) + 50 = 166 ms
    p99LatencyMs: 166,
    maxErrorRate: 0,
  },
  'issuer-issue:azure+full': {
    // Maximum stacked optionals. Budget = 500 ms to match the README
    // "Token issuance < 500 ms (p95)" claim for a fully loaded stack.
    p99LatencyMs: 500,
    maxErrorRate: 0,
  },

  // ### AWS KMS
  'issuer-issue:aws': {
    // 80 (KMS p95) + 50 = 130 ms
    p99LatencyMs: 130,
    maxErrorRate: 0,
  },
  'issuer-issue:aws+cosign': {
    // 80 + 4 (cosign p95: 2×2) + 50 = 134 ms
    p99LatencyMs: 134,
    maxErrorRate: 0,
  },
  'issuer-issue:aws+sidecreds': {
    // 80 + 16 (side-creds p95: 2×8) + 50 = 146 ms
    p99LatencyMs: 146,
    maxErrorRate: 0,
  },
  'issuer-issue:aws+full': {
    p99LatencyMs: 500,
    maxErrorRate: 0,
  },

  // ### GCP Cloud KMS
  'issuer-issue:gcp': {
    // 90 (KMS p95) + 50 = 140 ms
    p99LatencyMs: 140,
    maxErrorRate: 0,
  },
  'issuer-issue:gcp+cosign': {
    // 90 + 4 (cosign p95: 2×2) + 50 = 144 ms
    p99LatencyMs: 144,
    maxErrorRate: 0,
  },
  'issuer-issue:gcp+sidecreds': {
    // 90 + 16 (side-creds p95: 2×8) + 50 = 156 ms
    p99LatencyMs: 156,
    maxErrorRate: 0,
  },
  'issuer-issue:gcp+full': {
    p99LatencyMs: 500,
    maxErrorRate: 0,
  },
};

/** Type-safe access to the canonical scenario name list. */
export type ScenarioName = keyof typeof SLOS;

/** All known scenario names, in display order. */
export const SCENARIO_NAMES: readonly string[] = Object.keys(SLOS);

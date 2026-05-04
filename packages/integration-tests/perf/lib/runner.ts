/**
 * Autocannon-based scenario runner.
 *
 * Wraps `autocannon` so each scenario contributes:
 *
 *   1. A canonical name (matches `slo.ts`).
 *   2. A request shape (URL, method, headers, body, expected status).
 *   3. Optional load-profile overrides.
 *
 * The runner returns a normalised `ScenarioResult` and asserts the
 * scenario's `ScenarioSlo` against autocannon's reported percentiles.
 * Any breach is collected into the result's `failures` array — the CLI
 * (`bin/run-perf.ts`) aggregates those and exits non-zero on regression.
 */

import autocannon, { Options as AutocannonOptions, Result as AutocannonResult } from 'autocannon';
import { DEFAULT_LOAD_PROFILE, ScenarioSlo, SLOS } from '../slo';

export interface ScenarioRequest {
  /** Path *relative* to the harness URL chosen for this scenario. */
  path: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  /** Pre-serialised request body. */
  body?: string;
}

export interface ScenarioDefinition {
  /** Canonical name; must be a key in `SLOS`. */
  name: string;
  /** One-line description for the report. */
  description: string;
  /** Which harness URL the request hits — affects metric attribution. */
  target: 'gateway' | 'issuer';
  /** Shape of the request to repeat. */
  request: ScenarioRequest;
  /**
   * Status codes the runner treats as "expected success" — anything
   * else is counted as a runner-level error and feeds `maxErrorRate`.
   * Defaults to `[200]`.
   */
  expectedStatusCodes?: number[];
  /** Override the default load profile for this scenario. */
  load?: Partial<typeof DEFAULT_LOAD_PROFILE>;
  /**
   * Override the SLO for this scenario. Merged with the file-level
   * defaults; field-level `undefined` clears that constraint.
   */
  sloOverride?: Partial<ScenarioSlo>;
}

export interface ScenarioResult {
  name: string;
  description: string;
  target: 'gateway' | 'issuer';
  /** Total requests autocannon issued. */
  requests: number;
  /** Mean throughput (req/s). */
  requestsPerSecond: number;
  latencyMsP50: number;
  latencyMsP90: number;
  latencyMsP99: number;
  latencyMsMax: number;
  /** Non-2xx (or non-expected) responses observed. */
  errors: number;
  /** Errors as a fraction in [0, 1]. */
  errorRate: number;
  /** SLO that was applied. */
  slo: ScenarioSlo;
  /** Human-readable list of breaches; empty when the run passed. */
  failures: string[];
  /** Pass/fail derived from `failures.length === 0`. */
  passed: boolean;
}

export interface RunScenarioOptions {
  /** Resolves the absolute URL for the request. */
  baseUrlFor: (target: 'gateway' | 'issuer') => string;
  /** Override default duration; useful for `--quick` smoke runs. */
  durationSeconds?: number;
  /** Override default connection count. */
  connections?: number;
}

/**
 * Run one scenario end-to-end and assert its SLO. Throws only on
 * setup misuse (no SLO defined) — runtime perf failures land in the
 * result's `failures` array so the caller can decide how to surface
 * them.
 */
export async function runScenario(
  def: ScenarioDefinition,
  opts: RunScenarioOptions,
): Promise<ScenarioResult> {
  const baseSlo = SLOS[def.name];
  if (!baseSlo) {
    throw new Error(
      `runScenario: no SLO declared for "${def.name}" in slo.ts. ` +
        'Every scenario must have an entry so regressions can be defended.',
    );
  }
  const slo: ScenarioSlo = { ...baseSlo, ...(def.sloOverride ?? {}) };

  const profile = { ...DEFAULT_LOAD_PROFILE, ...(def.load ?? {}) };
  const duration = opts.durationSeconds ?? profile.durationSeconds;
  const connections = opts.connections ?? profile.connections;
  const expected = new Set(def.expectedStatusCodes ?? [200]);

  const url = opts.baseUrlFor(def.target) + def.request.path;
  const acOpts: AutocannonOptions = {
    url,
    method: def.request.method ?? 'GET',
    headers: def.request.headers,
    body: def.request.body,
    duration,
    connections,
    pipelining: profile.pipelining,
    // We classify status codes ourselves below; turn off autocannon's
    // built-in `expectBody` / status assertions so it never bails early.
  };

  const result: AutocannonResult = await autocannon(acOpts);

  // Autocannon reports `non2xx` plus a per-status-code histogram. We
  // re-classify against the scenario's expectedStatusCodes so a
  // deny-only scenario can mark `403` as success.
  let errors = 0;
  if (result.errors) errors += result.errors;
  if (result.timeouts) errors += result.timeouts;
  // statusCodeStats may be sparse — iterate keys defensively.
  const statusStats = (result as unknown as {
    statusCodeStats?: Record<string, { count: number }>;
  }).statusCodeStats;
  if (statusStats) {
    for (const [code, info] of Object.entries(statusStats)) {
      const n = Number(code);
      if (!expected.has(n)) errors += info.count;
    }
  } else {
    // Older autocannon shapes only expose `non2xx`; fall back to that
    // when the scenario expects 2xx codes only.
    if (!def.expectedStatusCodes && result.non2xx) errors += result.non2xx;
  }

  const totalRequests = result.requests.total;
  const errorRate = totalRequests > 0 ? errors / totalRequests : 0;

  const r: Omit<ScenarioResult, 'failures' | 'passed'> = {
    name: def.name,
    description: def.description,
    target: def.target,
    requests: totalRequests,
    requestsPerSecond: result.requests.average,
    latencyMsP50: result.latency.p50,
    latencyMsP90: result.latency.p90,
    latencyMsP99: result.latency.p99,
    latencyMsMax: result.latency.max,
    errors,
    errorRate,
    slo,
  };

  const failures = assertSlo(r, slo);
  return { ...r, failures, passed: failures.length === 0 };
}

function assertSlo(
  r: Omit<ScenarioResult, 'failures' | 'passed'>,
  slo: ScenarioSlo,
): string[] {
  const failures: string[] = [];
  if (slo.p50LatencyMs !== undefined && r.latencyMsP50 > slo.p50LatencyMs) {
    failures.push(
      `p50 latency ${r.latencyMsP50.toFixed(2)}ms exceeds budget ${slo.p50LatencyMs}ms`,
    );
  }
  if (slo.p99LatencyMs !== undefined && r.latencyMsP99 > slo.p99LatencyMs) {
    failures.push(
      `p99 latency ${r.latencyMsP99.toFixed(2)}ms exceeds budget ${slo.p99LatencyMs}ms`,
    );
  }
  if (
    slo.minRequestsPerSecond !== undefined &&
    r.requestsPerSecond < slo.minRequestsPerSecond
  ) {
    failures.push(
      `throughput ${r.requestsPerSecond.toFixed(0)} req/s below floor ` +
        `${slo.minRequestsPerSecond} req/s`,
    );
  }
  const errorBudget = slo.maxErrorRate ?? 0;
  if (r.errorRate > errorBudget) {
    failures.push(
      `error rate ${(r.errorRate * 100).toFixed(2)}% exceeds budget ` +
        `${(errorBudget * 100).toFixed(2)}% (errors=${r.errors}/${r.requests})`,
    );
  }
  return failures;
}

/** Pretty single-line summary suitable for CI logs. */
export function formatScenarioLine(r: ScenarioResult): string {
  const status = r.passed ? 'PASS' : 'FAIL';
  return (
    `[${status}] ${r.name.padEnd(28)} ` +
    `req=${String(r.requests).padStart(6)} ` +
    `rps=${r.requestsPerSecond.toFixed(0).padStart(6)} ` +
    `p50=${r.latencyMsP50.toFixed(1).padStart(6)}ms ` +
    `p99=${r.latencyMsP99.toFixed(1).padStart(6)}ms ` +
    `max=${r.latencyMsMax.toFixed(1).padStart(6)}ms ` +
    `err=${r.errors}`
  );
}

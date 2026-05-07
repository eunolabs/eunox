// Shared k6 helper: loads `slo.json` (generated from `../slo.ts` by
// `npm run perf:slo:emit`) and exposes a uniform helper to translate a
// scenario's `ScenarioSlo` into k6 `thresholds`.
//
// Keeping the translation in one place means the scenario files stay
// declarative and any change to the SLO shape (new field, new check)
// only needs editing once.
//
// k6 runs in Goja, not Node — `open()` reads the JSON file relative to
// the script's directory, so the path here is sibling-relative.

import http from 'k6/http';

const SLO = JSON.parse(open('../slo.json'));

/**
 * Build k6 `options` for a scenario name, including thresholds and the
 * default load profile (mapped to k6's vus + duration). Mirrors what
 * the autocannon CLI applies in `lib/runner.ts`.
 *
 * Side-effect: also installs a global `responseCallback` so non-200
 * "expected" status codes (e.g. 403 for the deny scenario) don't
 * inflate `http_req_failed` and cause the threshold to trip
 * spuriously.
 *
 * @param {string} name canonical scenario name (must exist in slo.json)
 * @param {{ expectedStatusCodes?: number[] }} [opts]
 * @returns {{ vus: number, duration: string, thresholds: Record<string, string[]>, expectedStatusCodes: number[] }}
 */
export function k6OptionsFor(name, opts) {
  opts = opts || {};
  const slo = SLO.scenarios[name];
  if (!slo) {
    throw new Error(
      'k6OptionsFor: no SLO declared for "' +
        name +
        '" in slo.json. Re-run `npm run perf:slo:emit` after adding it to slo.ts.',
    );
  }
  const profile = SLO.defaultLoadProfile;
  const expected = opts.expectedStatusCodes || [200];

  // Tell k6 which status codes count as "success" for the
  // `http_req_failed` metric. Without this, a deny-only scenario
  // would compute a 100% failure rate even though every response is
  // exactly what we asked for.
  http.setResponseCallback(http.expectedStatuses.apply(null, expected));

  const thresholds = {};
  if (slo.p50LatencyMs !== undefined || slo.p99LatencyMs !== undefined) {
    thresholds.http_req_duration = [];
    if (slo.p50LatencyMs !== undefined) {
      thresholds.http_req_duration.push('p(50)<' + slo.p50LatencyMs);
    }
    if (slo.p99LatencyMs !== undefined) {
      thresholds.http_req_duration.push('p(99)<' + slo.p99LatencyMs);
    }
  }
  if (slo.minRequestsPerSecond !== undefined) {
    thresholds.http_reqs = ['rate>' + slo.minRequestsPerSecond];
  }
  if (slo.maxErrorRate !== undefined) {
    thresholds.http_req_failed = ['rate<=' + slo.maxErrorRate];
  }

  return {
    vus: profile.connections,
    duration: profile.durationSeconds + 's',
    thresholds: thresholds,
    expectedStatusCodes: expected,
  };
}

/** Returns true when the response status is in the expected set. */
export function isExpected(res, expected) {
  return expected.indexOf(res.status) !== -1;
}

// k6 scenario — gateway-tools-invoke-allow (auto-generated companion to autocannon).
// See `scenarios/index.ts` for the canonical description and
// `slo.ts` for the threshold definitions. Regenerate `slo.json`
// via `npm run perf:slo:emit` after editing `slo.ts`.

import http from 'k6/http';
import { check } from 'k6';
import { k6OptionsFor, isExpected } from './lib/slo.js';

const SCENARIO = 'gateway-tools-invoke-allow';
const cfg = k6OptionsFor(SCENARIO});

export const options = {
  vus: cfg.vus,
  duration: cfg.duration,
  thresholds: cfg.thresholds,
};

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const HEADERS = Object.assign({ "content-type": "application/json", "x-agent-id": __ENV.AGENT_ID || "k6-agent" }, { "authorization": "Bearer " + (__ENV.CAPABILITY_TOKEN || "missing-token") });
const BODY = JSON.stringify({ tool: "read_file", args: { path: "/data/perf.json" } });

export default function () {
  const res = http.post(BASE + '/api/v1/tools/invoke', BODY, { headers: HEADERS });
  check(res, {
    'status is expected': (r) => isExpected(r, cfg.expectedStatusCodes),
  });
}

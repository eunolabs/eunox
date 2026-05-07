// k6 scenario — gateway-health-ready (auto-generated companion to autocannon).
// See `scenarios/index.ts` for the canonical description and
// `slo.ts` for the threshold definitions. Regenerate `slo.json`
// via `npm run perf:slo:emit` after editing `slo.ts`.

import http from 'k6/http';
import { check } from 'k6';
import { k6OptionsFor, isExpected } from './lib/slo.js';

const SCENARIO = 'gateway-health-ready';
const cfg = k6OptionsFor(SCENARIO});

export const options = {
  vus: cfg.vus,
  duration: cfg.duration,
  thresholds: cfg.thresholds,
};

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const HEADERS = {};

export default function () {
  const res = http.get(BASE + '/health/ready', { headers: HEADERS });
  check(res, {
    'status is expected': (r) => isExpected(r, cfg.expectedStatusCodes),
  });
}

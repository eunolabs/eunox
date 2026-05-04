// k6 scenario — gateway-health-live
//
// Run against a deployed gateway:
//   k6 run -e GATEWAY_URL=https://gw.example.com perf/k6/gateway-health-live.js
//
// Thresholds derive from `slo.json` (regenerate via
// `npm run perf:slo:emit` after editing `slo.ts`).

import http from 'k6/http';
import { check } from 'k6';
import { k6OptionsFor, isExpected } from './lib/slo.js';

const SCENARIO = 'gateway-health-live';
const cfg = k6OptionsFor(SCENARIO);

export const options = {
  vus: cfg.vus,
  duration: cfg.duration,
  thresholds: cfg.thresholds,
};

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';

export default function () {
  const res = http.get(BASE + '/health/live');
  check(res, {
    'status is expected': (r) => isExpected(r, cfg.expectedStatusCodes),
  });
}

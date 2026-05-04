// k6 scenario — issuer-renew (auto-generated companion to autocannon).
// See `scenarios/index.ts` for the canonical description and
// `slo.ts` for the threshold definitions. Regenerate `slo.json`
// via `npm run perf:slo:emit` after editing `slo.ts`.

import http from 'k6/http';
import { check } from 'k6';
import { k6OptionsFor, isExpected } from './lib/slo.js';

const SCENARIO = 'issuer-renew';
const cfg = k6OptionsFor(SCENARIO});

export const options = {
  vus: cfg.vus,
  duration: cfg.duration,
  thresholds: cfg.thresholds,
};

const BASE = __ENV.ISSUER_URL || 'http://127.0.0.1:8080';
const HEADERS = Object.assign({ "content-type": "application/json" }, { "authorization": "Bearer " + (__ENV.CAPABILITY_TOKEN_RENEWABLE || __ENV.CAPABILITY_TOKEN || "missing-token") });
const BODY = JSON.stringify({ ttl: 600 });

export default function () {
  const res = http.post(BASE + '/api/v1/renew', BODY, { headers: HEADERS });
  check(res, {
    'status is expected': (r) => isExpected(r, cfg.expectedStatusCodes),
  });
}

// k6 scenario — gateway-proxy-post (auto-generated companion).
// Body-less: see scenarios/index.ts for why a JSON body is not sent.

import http from 'k6/http';
import { check } from 'k6';
import { k6OptionsFor, isExpected } from './lib/slo.js';

const SCENARIO = 'gateway-proxy-post';
const cfg = k6OptionsFor(SCENARIO);

export const options = {
  vus: cfg.vus,
  duration: cfg.duration,
  thresholds: cfg.thresholds,
};

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const HEADERS = { authorization: 'Bearer ' + (__ENV.CAPABILITY_TOKEN || 'missing-token') };

export default function () {
  const res = http.post(BASE + '/proxy/api/perf/orders', null, { headers: HEADERS });
  check(res, {
    'status is expected': (r) => isExpected(r, cfg.expectedStatusCodes),
  });
}

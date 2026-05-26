// Eunox Gateway Load Test — k6 script
// Targets: /api/v1/enforce endpoint
//
// Run: k6 run --env BASE_URL=http://localhost:3002 deploy/loadtest/gateway.js
//
// SLO targets (p99 < 50ms, error rate < 0.1% at 1000 RPS):
//   k6 run --env BASE_URL=http://gateway:3002 \
//          --env TARGET_RPS=1000 \
//          deploy/loadtest/gateway.js

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// Custom metrics
const errorRate = new Rate("errors");
const enforceDuration = new Trend("enforce_duration", true);

// Configuration from environment
const BASE_URL = __ENV.BASE_URL || "http://localhost:3002";
const TARGET_RPS = parseInt(__ENV.TARGET_RPS || "100", 10);

export const options = {
  scenarios: {
    // Ramp-up scenario for sustained load testing.
    sustained_load: {
      executor: "ramping-arrival-rate",
      startRate: 10,
      timeUnit: "1s",
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: "30s", target: TARGET_RPS / 2 },
        { duration: "2m", target: TARGET_RPS },
        { duration: "30s", target: TARGET_RPS },
        { duration: "30s", target: 0 },
      ],
    },
    // Spike scenario to validate auto-scaling.
    spike: {
      executor: "ramping-arrival-rate",
      startRate: 0,
      timeUnit: "1s",
      preAllocatedVUs: 100,
      maxVUs: 1000,
      startTime: "4m",
      stages: [
        { duration: "10s", target: TARGET_RPS * 3 },
        { duration: "30s", target: TARGET_RPS * 3 },
        { duration: "10s", target: 0 },
      ],
    },
  },
  thresholds: {
    // SLO: p99 enforce latency < 50ms
    enforce_duration: ["p(99)<50"],
    // SLO: error rate < 0.1%
    errors: ["rate<0.001"],
    // SLO: p95 response time < 30ms
    http_req_duration: ["p(95)<30", "p(99)<50"],
  },
};

// Sample enforce payload — minimal valid request.
const ENFORCE_PAYLOAD = JSON.stringify({
  subject: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  resource: "tool://code-assistant/edit",
  action: "execute",
  context: {
    tool_name: "edit",
    server_name: "code-assistant",
  },
});

const HEADERS = {
  "Content-Type": "application/json",
  Authorization: "******",
};

export default function () {
  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/v1/enforce`, ENFORCE_PAYLOAD, {
    headers: HEADERS,
    timeout: "10s",
  });
  const duration = Date.now() - start;

  enforceDuration.add(duration);

  const success = check(res, {
    "status is 2xx or 4xx (not 5xx)": (r) => r.status < 500,
    "response has body": (r) => r.body && r.body.length > 0,
    "latency under 100ms": () => duration < 100,
  });

  errorRate.add(!success);
}

export function handleSummary(data) {
  const p99 = data.metrics.enforce_duration
    ? data.metrics.enforce_duration.values["p(99)"]
    : "N/A";
  const errRate = data.metrics.errors
    ? data.metrics.errors.values.rate
    : "N/A";

  console.log(`\n=== Eunox Gateway Load Test Results ===`);
  console.log(`  Enforce p99 latency: ${p99}ms`);
  console.log(`  Error rate: ${(errRate * 100).toFixed(4)}%`);
  console.log(`  SLO pass: p99<50ms=${p99 < 50}, errors<0.1%=${errRate < 0.001}`);
  console.log(`=======================================\n`);

  return {
    stdout: JSON.stringify(data, null, 2),
  };
}

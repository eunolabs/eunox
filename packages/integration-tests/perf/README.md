# Perf scenarios — load-test artefacts

This directory provides load-test artefacts so the team can set and defend SLOs.

It ships **two complementary toolchains** that share a single SLO
source-of-truth ([`slo.ts`](./slo.ts)):

| Toolchain | Use case | How it runs |
| --- | --- | --- |
| **autocannon** (Node lib) | CI gates, regression hunting, local dev | `npm run perf` — spins up real services in-process via `createApp(deps)` and a thin issuer HTTP wrapper, then exercises every route end-to-end |
| **k6** (standalone) | Ops perf testing against deployed envs (staging, prod-rehearsal) | `k6 run perf/k6/<scenario>.js` against `GATEWAY_URL` / `ISSUER_URL` |

Both toolchains assert the **same SLOs** so a regression caught in CI
also fails when ops re-runs the scenario against a deployed cluster.

## Layout

```
perf/
├── slo.ts                     ← single source of truth (TS)
├── lib/
│   ├── harness.ts             ← in-process services (gateway + issuer + backend)
│   └── runner.ts              ← autocannon wrapper + SLO assertion
├── scenarios/
│   └── index.ts               ← per-route scenario definitions
├── bin/
│   ├── run-perf.ts            ← CLI (`npm run perf`)
│   └── emit-slo-json.ts       ← writes k6/slo.json
└── k6/
    ├── slo.json               ← generated for k6 (`npm run perf:slo:emit`)
    ├── lib/slo.js             ← shared k6 thresholds derived from slo.json
    ├── README.md              ← env-var contract for ops use
    └── <scenario>.js          ← one file per scenario, mirrors autocannon
```

## Routes covered

Every externally observable HTTP route on the Tool Gateway and
Capability Issuer has a scenario; adding a route without a scenario
is a regression — the SLO list in `slo.ts` is the contract.

| Scenario | Route | Why we measure it |
| --- | --- | --- |
| `gateway-health-live` | `GET /health/live` | Kubernetes liveness — must stay cheap |
| `gateway-health-ready` | `GET /health/ready` | Readiness — gates Service endpoints |
| `gateway-health` | `GET /health` | Legacy alias of liveness |
| `gateway-metrics` | `GET /metrics` | Prometheus scrapes happen on a tight schedule |
| `gateway-tools-invoke-allow` | `POST /api/v1/tools/invoke` (Administrator) | Hot path: JWT verify + action resolver + enforcement |
| `gateway-tools-invoke-deny` | `POST /api/v1/tools/invoke` (Viewer → 403) | Cost of a synchronous deny |
| `gateway-validate` | `POST /api/v1/validate` | Same enforcement cost without a proxy hop |
| `gateway-proxy-get` | `GET /proxy/*` | Full middleware + http-proxy-middleware path |
| `gateway-proxy-post` | `POST /proxy/*` (no body) | POST decision path through the proxy middleware. JSON body parsing/forwarding is **not** exercised — see scenario doc-comment for why |
| `gateway-admin-status` | `GET /admin/kill-switch/status` | Admin-API auth + KillSwitchManager lookup (operators poll this during incidents) |
| `issuer-health` | `GET /health` | Issuer liveness probe |
| `issuer-metrics` | `GET /metrics` | Issuer Prometheus scrape |
| `issuer-jwks` | `GET /.well-known/jwks.json` | **Live** key-distribution path used by gateway boot/refresh (R-6) |
| `issuer-public-key` | `GET /api/v1/public-key` | Deprecated legacy fetch (kept under SLO during deprecation window) |
| `issuer-well-known-did` | `GET /.well-known/did.json` | DID document fetch used by external verifiers |
| `issuer-well-known-meta` | `GET /.well-known/capability-issuer` | Issuer metadata document |
| `issuer-issue` | `POST /api/v1/issue` | Identity validate → policy → RSA-2048 sign |
| `issuer-attenuate` | `POST /api/v1/attenuate` | Verify parent → check subset → mint child |
| `issuer-renew` | `POST /api/v1/renew` | Verify current → build renewed → sign |

## Running

```bash
cd packages/integration-tests

# All scenarios, default load profile (5 s × 20 connections each).
npm run perf

# One scenario only.
npm run perf -- --scenario gateway-tools-invoke-allow

# Quick smoke for CI.
npm run perf -- --quick

# Capture full results for diffing.
npm run perf -- --json reports/$(git rev-parse --short HEAD).json

# List scenario names.
npm run perf -- --list
```

The CLI exits **non-zero** if any scenario breaches its SLO, so it
slots straight into a CI gate.

### k6 against a deployed environment

```bash
# 1. Make sure slo.json is in sync with slo.ts.
npm run perf:slo:emit

# 2. Run a scenario against staging.
k6 run \
  -e GATEWAY_URL=https://gw.staging.example.com \
  -e CAPABILITY_TOKEN=$EUNO_CAP_TOKEN \
  perf/k6/gateway-tools-invoke-allow.js
```

The k6 thresholds come from the same `slo.json`, so the run fails the
same way the autocannon CI run does.

## How the SLOs were chosen

The targets in `slo.ts` are **regression budgets**, not production
capacity claims. They are calibrated against a single Node 20 process
on a 2 vCPU / 7 GB CI runner, no external Redis, no real KMS, with
~2× headroom for ambient noise. Each run records its observed
p50 / p99 / req-s into the `--json` output — diff two runs to decide
whether to **lower** the budget (defend a real improvement) or
**investigate** (regression).

See the doc-comment at the top of `slo.ts` for the change-management
recipe.

## Adding a scenario

1. Add an entry in `SLOS` (`slo.ts`) keyed by canonical name.
2. Add a `ScenarioDefinition` in `scenarios/index.ts`.
3. (Optional) add a matching k6 file under `k6/`.
4. Re-run `npm run perf:slo:emit` so `slo.json` is back in sync.
5. Run the new scenario and tune the SLO until it passes with
   ~2× headroom.

## Why not run perf in `jest`?

`jest` parallelism would corrupt the throughput numbers; load tests
need the full machine. The runner is a dedicated CLI invoked via
`ts-node` with its own NODE_ENV so `jest`-only side effects (e.g.
fake timers) don't leak in.

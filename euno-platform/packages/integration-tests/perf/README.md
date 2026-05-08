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
├── profiles/
│   ├── definitions.ts         ← KMS + optional-component profiles (Azure/AWS/GCP)
│   └── stubs.ts               ← latency-injecting stubs (KMS signer, cosigner,
│                                  posture emitter, side-credential broker, transparency log)
├── lib/
│   ├── harness.ts             ← in-process services (gateway + issuer + backend
│   │                             + one profiled issuer per ISSUANCE_PROFILES entry)
│   └── runner.ts              ← autocannon wrapper + SLO assertion
├── scenarios/
│   └── index.ts               ← per-route scenario definitions (baseline + profiled)
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

## Profiled issuance scenarios (KMS + stacked optionals)

These scenarios defend the README claim _"Token issuance < 500 ms (p95)"_ by
testing the issuance hot path with each cloud KMS profile and combinations of
the optional components the issuer may call.

Because CI cannot contact real Azure, AWS, or GCP endpoints, each optional
component is replaced by a **latency-injecting stub** that:

1. Does the minimum real work to produce a structurally valid return value
   (so the issuer's correctness checks pass), and
2. Sleeps for a configurable number of milliseconds to model the typical
   same-region network RTT of the real component.

### Simulated latencies

| Component | Simulated p50 | Source |
| --- | --- | --- |
| Azure Key Vault (sign) | 40 ms | Azure docs §Perf; community benchmarks |
| AWS KMS (sign) | 25 ms | AWS KMS SLA; community benchmarks |
| GCP Cloud KMS (sign) | 30 ms | GCP KMS docs |
| Software cosigner (Ed25519) | 2 ms | Measured in-process |
| Side-credential broker stub | 8 ms | Measured in-process |
| Transparency-log witness | 3 ms | Measured in-process |
| Posture emitter | fire-and-forget | Does not appear in p99 |

### Profiled scenarios

Each scenario name follows `issuer-issue:<profile-tag>`:

| Scenario | Components | p99 budget |
| --- | --- | --- |
| `issuer-issue:azure` | Azure KMS | 150 ms |
| `issuer-issue:azure+cosign` | Azure KMS + Ed25519 cosigner | 154 ms |
| `issuer-issue:azure+sidecreds` | Azure KMS + side-credential broker | 166 ms |
| `issuer-issue:azure+full` | Azure KMS + cosigner + side creds + posture + witness | **500 ms** |
| `issuer-issue:aws` | AWS KMS | 130 ms |
| `issuer-issue:aws+cosign` | AWS KMS + Ed25519 cosigner | 134 ms |
| `issuer-issue:aws+sidecreds` | AWS KMS + side-credential broker | 146 ms |
| `issuer-issue:aws+full` | AWS KMS + cosigner + side creds + posture + witness | **500 ms** |
| `issuer-issue:gcp` | GCP Cloud KMS | 140 ms |
| `issuer-issue:gcp+cosign` | GCP Cloud KMS + Ed25519 cosigner | 144 ms |
| `issuer-issue:gcp+sidecreds` | GCP Cloud KMS + side-credential broker | 156 ms |
| `issuer-issue:gcp+full` | GCP Cloud KMS + cosigner + side creds + posture + witness | **500 ms** |

The `+full` profiles target exactly 500 ms to defend the README claim. If any
`+full` scenario fails CI, the stacked overhead has grown beyond what the
README documents.

### How budgets are derived

```
p99_budget = KMS_P95_LATENCY + sum(optional_component_P95s) + NODE_JS_OVERHEAD
```

where:
- `KMS_P95_LATENCY` is the typical worst-case (p95) same-region latency for
  the cloud provider (Azure: ~100 ms, AWS: ~80 ms, GCP: ~90 ms).
- `optional_component_P95s` uses 2× each component's simulated p50 latency as
  a conservative tail-latency estimate.
- `NODE_JS_OVERHEAD` ≈ 50 ms — the `issuer-issue` baseline p99 on a 2-vCPU
  CI runner with a software key (see `profiles/definitions.ts`'s
  `NODE_OVERHEAD_MS` constant).

All full-stack profiles give a comfortable margin under 500 ms. If they ever
breach 500 ms, a future change has added unexpected blocking work and should
be investigated.

## Running

```bash
cd euno-platform/packages/integration-tests

# All scenarios, default load profile (5 s × 20 connections each).
npm run perf

# One scenario only.
npm run perf -- --scenario gateway-tools-invoke-allow

# One profiled issuance scenario.
npm run perf -- --scenario 'issuer-issue:azure+full'

# Quick smoke for CI (1-second runs — completes in ~30 s).
npm run perf -- --quick

# Capture full results for diffing.
npm run perf -- --json reports/$(git rev-parse --short HEAD).json

# List all scenario names (including profiled).
npm run perf -- --list
```

The CLI exits **non-zero** if any scenario breaches its SLO, so it
slots straight into a CI gate.

You can also run from the repo root:

```bash
npm run perf          # all scenarios
npm run perf:quick    # --quick smoke run
```

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

### Adding a new cloud KMS profile

1. Add a new `KmsProfile` entry in `profiles/definitions.ts`.
2. Add `IssuanceProfile` entries for `<cloud>`, `<cloud>+cosign`,
   `<cloud>+sidecreds`, `<cloud>+full`.
3. Add matching SLO entries in `slo.ts` (follow the budget derivation
   formula above).
4. Run `npm run perf -- --scenario 'issuer-issue:<cloud>+full'` and
   confirm the scenario stays under 500 ms on a cold CI runner.

## Why not run perf in `jest`?

`jest` parallelism would corrupt the throughput numbers; load tests
need the full machine. The runner is a dedicated CLI invoked via
`ts-node` with its own NODE_ENV so `jest`-only side effects (e.g.
fake timers) don't leak in.

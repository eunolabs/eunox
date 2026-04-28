# Item #6 — Performance & Scalability Test Suite

**Plan reference:** `docs/execution-plan.md` Sprint 4 → Team DP →
"Performance & Scalability Testing" (line 294):
> Simulate 50 concurrent agents making rapid tool requests. Measure
> overhead of capability checks and cryptographic operations.
> Confirm 95th percentile latency within acceptable limits.

**Files affected:** new top-level `tests/load/` directory (separate
from the per-package `tests/` so it isn't picked up by Jest), CI
workflow under `.github/workflows/` (if one exists; otherwise
documented as a manual run).

## Problem

There are no load tests in the repo today. Functional correctness is
well-covered by Jest unit and integration tests, but we have no
empirical answer to the plan's questions:

- What is the issuer's `/issue` p95/p99 at 50 concurrent agents?
- What is the gateway's `/validate` p95/p99 at the same rate?
- How does latency change when JWT signing uses local Ed25519 vs.
  Azure Key Vault vs. AWS KMS?
- What is the failure mode at 2×, 5×, 10× the target load?

Without this baseline, any future change (e.g. items #3, #4, #7, #8
all add work to the issuance path) ships blind.

## Goals

- Reproducible load profile for "50 concurrent agents" defined as a
  versioned scenario file.
- p50 / p95 / p99 latency, throughput, and error-rate output in a
  machine-readable format (JSON) suitable for trend tracking.
- Two scenarios: **steady-state** (50 VUs, 5 minutes) and **ramp**
  (0 → 200 VUs over 5 minutes to find the knee).
- Runnable locally against `docker compose` and in CI as a manual
  workflow_dispatch (not on every PR — too slow / noisy).
- Acceptance gate documented (e.g. p95 issuance < 200ms, p95
  validation < 50ms — numbers TBD by first run, then locked).

## Non-goals

- Sustained capacity / soak testing (24h+) — Sprint 5 concern.
- Geographic distribution / multi-region latency.
- Load testing the cloud-credential minting paths from #7/#8 against
  real cloud APIs (rate-limit + cost risk; use mocks in load
  scenarios).

## Design

### 1. Choice of tool: k6

Comparison:

- **k6 (Grafana):** JavaScript scenario language, great built-in
  metrics, first-class Prometheus + JSON output, Docker image, free.
  Engineers already write JS/TS.
- **Locust:** Python; another language to support.
- **autocannon:** Node-based, simple, but weak scenario modelling and
  no built-in trends/percentiles for multi-endpoint flows.

**Choice: k6.** It matches the team's TS skill set, has the cleanest
metrics story, and runs as a single binary or container.

### 2. Directory layout

```
tests/load/
  README.md
  docker-compose.load.yml      # issuer + gateway + redis (mocked deps)
  scenarios/
    steady-50vu.js              # 50 VUs, 5 min, mixed issuance + validation
    ramp-to-200vu.js            # 0 → 200 over 5 min, find the knee
    issuance-only.js            # isolate /issue cost
    validation-only.js          # isolate /validate cost
  lib/
    auth.js                     # generates synthetic OIDC tokens (signed
                                # with a test JWKS the issuer trusts in
                                # LOAD_MODE=true)
    capabilities.js             # request payload builder
  thresholds.js                 # shared SLO thresholds (p95 etc)
  results/                      # gitignored; JSON output lands here
```

### 3. Mixed-traffic scenario shape (`steady-50vu.js`)

50 virtual users, each looping:

1. POST `/issue` with a fresh agent ID and a small capability set
   (≈70% of requests).
2. POST `/validate` with the freshly issued token against an allowed
   action (≈30% of requests).

Mix matches the plan's "rapid tool requests" framing: many more
validation calls than issuances in a real workload, but issuance
dominates p95 (it's heavier), so the mix is slightly issuance-skewed
to surface that.

### 4. Metrics & thresholds

`thresholds.js` defines:

```
http_req_duration{endpoint:issue}: ['p(95)<200', 'p(99)<400']
http_req_duration{endpoint:validate}: ['p(95)<50', 'p(99)<150']
http_req_failed: ['rate<0.001']
checks: ['rate>0.999']
```

These numbers are **placeholders** to be replaced with the first
clean baseline. The k6 run fails CI if thresholds breach.

### 5. Test-mode hooks in services

The issuer and gateway must accept synthetic auth tokens during load
runs without weakening production code paths. Pattern (already used
by some services in the repo; verify):

- Issuer reads `LOAD_TEST_MODE=true` from env.
- When set, registers an additional identity provider (`load-test`)
  that validates against a hard-coded JWKS shipped with the load
  package. Production deployments never set this var.

Document this clearly in `tests/load/README.md` and add a startup
log line `WARNING: load-test identity provider enabled` when active.

### 6. Output

k6's `--summary-export=results/summary.json` plus
`--out json=results/raw.jsonl`. A small Node script
(`tests/load/scripts/summarize.js`) reduces these to a one-page
markdown report suitable for PR comments.

### 7. CI integration

New workflow `.github/workflows/load-test.yml`:

- Trigger: `workflow_dispatch` (manual) and weekly schedule.
- Runs on `ubuntu-latest`, brings up
  `tests/load/docker-compose.load.yml`, runs the steady scenario,
  uploads `results/` as an artifact, posts the summary as a
  workflow summary.
- The ramp scenario is `workflow_dispatch` only (slow, noisy).

## Test strategy

The load tests *are* the tests. Their own correctness is verified
by:

- A "smoke" k6 run with `--vus 1 --iterations 5` that runs as part
  of normal CI on changes to `tests/load/**` to catch syntax errors.
- A `tests/load/scenarios/__tests__/scenarios.spec.js` Node test
  that imports each scenario file and asserts the exported `options`
  block has thresholds defined.

## Rollout

- Land the harness with placeholder thresholds set generously
  (e.g. p95 < 1000ms) so the first run baselines green.
- Run weekly for two weeks to characterize natural variance.
- Tighten thresholds to `baseline_p95 * 1.25` and lock.
- Wire to the manual workflow as a release gate before tagging.

## Risks

- **CI runner variability.** Hosted GitHub runners have variable
  CPU; absolute thresholds can flake. Mitigation: run on a
  larger-tier runner or a self-hosted runner; alternatively express
  thresholds as relative to the previous baseline (k6 doesn't do
  this natively — would need a small wrapper).
- **Mocked dependencies hide real cost.** The load harness mocks the
  signer, OIDC provider, and (eventually) cloud-credential APIs.
  Document loudly that load numbers are "code-path overhead", not
  "end-to-end production latency".
- **Scope creep into production observability.** Resist the urge to
  re-wire k6 metrics into Prometheus/Grafana production dashboards.
  Load runs are episodic; production telemetry already exists.

## Open questions

- Self-hosted vs. hosted runner? Recommend hosted with the
  `large` size to start; revisit if variance > 15%.
- Should the harness include a "chaos" variant (random 500s, slow
  signer)? Not for Sprint 4 — Sprint 5 concern.

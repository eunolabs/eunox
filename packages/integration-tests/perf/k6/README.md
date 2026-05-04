# k6 scenarios

Each `.js` file here is the k6 companion of an autocannon scenario in
[`scenarios/index.ts`](../scenarios/index.ts). Both toolchains share
the **same SLOs** via `slo.json` (regenerate with
`npm run perf:slo:emit` after editing `slo.ts`), so a regression caught
in CI also fails when ops re-runs the scenario against a deployed
cluster.

## Running

```bash
# Liveness — no auth required.
k6 run -e GATEWAY_URL=https://gw.staging.example.com gateway-health-live.js

# Hot path — needs a real capability token + agent id.
k6 run \
  -e GATEWAY_URL=https://gw.staging.example.com \
  -e CAPABILITY_TOKEN="$EUNO_CAP_TOKEN" \
  -e AGENT_ID=bench-agent-1 \
  gateway-tools-invoke-allow.js

# Issuer.
k6 run \
  -e ISSUER_URL=https://issuer.staging.example.com \
  -e USER_AUTH_TOKEN="$EUNO_USER_TOKEN" \
  -e AGENT_ID=bench-agent-1 \
  issuer-issue.js
```

## Environment variables

| Var | Used by | Description |
| --- | --- | --- |
| `GATEWAY_URL` | All `gateway-*` scripts | Base URL of the Tool Gateway under test |
| `ISSUER_URL` | All `issuer-*` scripts | Base URL of the Capability Issuer under test |
| `CAPABILITY_TOKEN` | gateway invoke (allow) / validate / proxy / attenuate | Bearer capability token with the rights the scenario exercises |
| `CAPABILITY_TOKEN_VIEWER` | `gateway-tools-invoke-deny` | Read-only token used to drive the deny path |
| `CAPABILITY_TOKEN_RENEWABLE` | `issuer-renew` | Token to renew (falls back to `CAPABILITY_TOKEN`) |
| `USER_AUTH_TOKEN` | `issuer-issue` | Identity-provider bearer accepted by the issuer |
| `ADMIN_API_KEY` | `gateway-admin-status` | Value of the `x-admin-api-key` header |
| `AGENT_ID` | scenarios that mint or invoke under an agent identity | Defaults to `k6-agent` |

## Why some scripts share env vars

Several scripts read the same `CAPABILITY_TOKEN` env so a single ops
run can mint one short-lived token at the start of a session and
exercise multiple routes against it (`tools/invoke`, `validate`,
`proxy`, `attenuate`). The deny scenario uses a *different* var so
operators don't need to mint a viewer token unless they want the
synchronous-deny SLO checked too.

## Adding a scenario

1. Add it to `scenarios/index.ts` and `slo.ts` (autocannon side).
2. `npm run perf:slo:emit` to refresh `slo.json`.
3. Copy the closest `.js` file in this directory and tweak the request
   shape. Reuse `k6OptionsFor()` from `lib/slo.js` so thresholds stay
   in lock-step with the autocannon runner.

# Eunox Load Test Harness

Load tests use [k6](https://k6.io/) to validate SLO compliance under production-level traffic.

## Prerequisites

```bash
# Install k6
brew install grafana/k6/k6    # macOS
# or
go install go.k6.io/k6@latest  # from source
```

## Running

### Gateway Enforce Endpoint

```bash
# Local testing (100 RPS default)
k6 run --env BASE_URL=http://localhost:3002 deploy/loadtest/gateway.js

# Production-level (1000 RPS target)
k6 run --env BASE_URL=http://gateway:3002 \
       --env TARGET_RPS=1000 \
       deploy/loadtest/gateway.js
```

## SLO Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Enforce p99 latency | < 50ms | Real-time policy enforcement must not add perceptible delay |
| Enforce p95 latency | < 30ms | Typical request should be very fast |
| Error rate | < 0.1% | High availability required for enforcement path |

## Test Scenarios

1. **Sustained Load** — Ramps to target RPS over 30s, holds for 2 minutes, then ramps down.
2. **Spike** — After the sustained load scenario, sends 3x target RPS for 30s to validate auto-scaling and graceful degradation.

## CI Integration

Add to CI pipeline for regression detection:

```yaml
- name: Load Test
  run: |
    k6 run --env BASE_URL=${{ secrets.STAGING_URL }} \
           --env TARGET_RPS=500 \
           --out json=results.json \
           deploy/loadtest/gateway.js
```

## Interpreting Results

k6 will exit with non-zero code if any threshold is violated. The summary handler prints a concise pass/fail for each SLO target.

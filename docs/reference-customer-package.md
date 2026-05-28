# Reference Customer Readiness Package

> **Audience:** Customer Success, Sales Engineering, and the first production
> customer preparing to serve as a reference for Eunox.
>
> **Purpose:** Template for documenting a reference customer's deployment topology,
> observed performance, test results, and operational record. When a customer
> completes this package and consents to its use, Sales can share it with prospects
> as concrete evidence that Eunox performs as documented.

---

## Package Overview

A completed reference package demonstrates:

1. **Deployment topology** — the customer's actual infrastructure configuration
2. **Observed performance** — P50/P99 enforcement latency under real workloads
3. **Kill-switch test results** — evidence that the sub-second propagation guarantee holds
4. **Incident response record** — incidents, resolutions, and RTO evidence
5. **Compliance posture** — which regulatory frameworks the customer operates under

This document is a template. Fill in each section for the specific customer. Sections
marked `[REQUIRED]` must be completed before the package is considered ready to share.

---

## Section 1: Customer Overview [REQUIRED]

| Field | Value |
|-------|-------|
| Customer name | `<company name>` |
| Industry | `<industry>` |
| Compliance frameworks | `<SOC 2 / HIPAA / PCI-DSS / NIST 800-207>` |
| Production start date | `<YYYY-MM-DD>` |
| Package preparation date | `<YYYY-MM-DD>` |
| Eunox version | `<version tag>` |
| Primary use case | `<description of AI agent workload>` |

---

## Section 2: Deployment Topology [REQUIRED]

### Infrastructure

| Component | Configuration |
|-----------|--------------|
| Cloud provider | `<AWS / GCP / Azure / on-prem>` |
| Region(s) | `<list of regions>` |
| Number of AZs | `<count>` |
| Gateway replicas | `<count>` |
| Gateway CPU/memory per replica | `<mCPU> / <MiB>` |
| Redis topology | `<Sentinel 3-node / Cluster 6-node / other>` |
| Redis instance type | `<instance type>` |
| PostgreSQL configuration | `<primary + N read replicas / RDS Multi-AZ / etc.>` |
| Deployment model | `<centralized / sidecar / hybrid>` |

### Network topology diagram

```
[Insert ASCII or link to topology diagram]
```

*Minimum required: show gateway replicas, Redis nodes, PostgreSQL, and labeled failure domains.*

### Kubernetes configuration

| Setting | Value |
|---------|-------|
| Gateway HPA min/max replicas | `<min> / <max>` |
| PodDisruptionBudget minAvailable | `<count or percentage>` |
| TopologySpreadConstraints | `<zone spread / host spread>` |
| Resource requests: CPU / memory | `<mCPU> / <MiB>` |
| Resource limits: CPU / memory | `<mCPU> / <MiB>` |

---

## Section 3: Observed Performance [REQUIRED]

Run the latency measurement procedure in `docs/gateway-operator-runbook.md §Performance
Baseline` and record the results here.

### Enforcement latency (production, P-percentiles)

| Scenario | P50 | P95 | P99 | P999 |
|----------|-----|-----|-----|------|
| Token cache enabled (cache hit) | — | — | — | — |
| Token cache enabled (cache miss) | — | — | — | — |
| Token cache disabled (full path) | — | — | — | — |

*Measurement method: `GATEWAY_OTEL_EXPORTER_OTLP_ENDPOINT` + Prometheus histogram
`enforce_duration_seconds`; or `internal/gateway/enforce_benchmark_test.go` run against
staging with representative token shapes.*

### Throughput

| Metric | Value |
|--------|-------|
| Peak RPS observed in production | `<RPS>` |
| Sustained RPS (30-min window) | `<RPS>` |
| Number of active agents at peak | `<count>` |

### Token cache configuration

| Setting | Value |
|---------|-------|
| `GATEWAY_TOKEN_CACHE_TTL_SECONDS` | `<seconds>` |
| `GATEWAY_TOKEN_CACHE_MAX_SIZE` | `<entries>` |
| Cache hit rate (production average) | `<percentage>` |

---

## Section 4: Kill-Switch Test Results [REQUIRED]

Run each test in a staging environment that mirrors production topology. Record
the results. These results are the evidence that the sub-second propagation
guarantee holds in the customer's specific infrastructure.

### Test procedure

```bash
# 1. Start a continuous enforcement request loop (background)
while true; do
  curl -s -o /dev/null -w "%{time_total}\n" \
    -X POST https://<gateway>/api/v1/enforce \
    -H "Authorization: ******" \
    -H "Content-Type: application/json" \
    -d '{"tool":"test","action":"read","context":{}}' &
  sleep 0.1
done

# 2. Activate agent kill-switch and measure time to first 503
START=$(date +%s%3N)
curl -s -X POST https://<gateway-admin>/admin/v1/kill-switch/agents/<agent-id> \
  -H "X-Admin-Api-Key: <key>"
# Record time of first 503 response in the enforcement loop
```

### Results

| Test | Expected | Observed | Pass/Fail |
|------|----------|----------|-----------|
| Agent kill → first block | < 1 000 ms | `<ms>` | |
| Global kill → first block | < 1 000 ms | `<ms>` | |
| Agent revive → first allow | < 1 000 ms | `<ms>` | |
| Kill-switch state after Redis restart | Fail-closed | `<observed>` | |
| Kill-switch state after gateway restart | Correct (loaded from Redis) | `<observed>` | |

### Chaos test results

Run `make test` in the `internal/chaos/` package against the staging environment.

| Test suite | Tests passed | Tests failed | Notes |
|------------|-------------|-------------|-------|
| Kill-switch resilience | `<count>` / `<total>` | `<count>` | |
| Revocation resilience | `<count>` / `<total>` | `<count>` | |
| Circuit breaker scenarios | `<count>` / `<total>` | `<count>` | |
| Redis failure modes | `<count>` / `<total>` | `<count>` | |

*See `docs/chaos-results.md` for the baseline pass matrix (43/43).*

---

## Section 5: Incident Response Record [REQUIRED after 3 months of production]

### Incident log

| Incident ID | Date | Severity | Component | Duration | RTO achieved | Root cause | Resolution |
|-------------|------|----------|-----------|----------|-------------|-----------|-----------|
| `<ID>` | `<date>` | `<P1-P4>` | `<gateway/redis/postgres>` | `<minutes>` | `<yes/no>` | `<brief>` | `<brief>` |

*Minimum: log all incidents that resulted in enforcement unavailability or
incorrect enforcement decisions. P1 incidents (enforcement unavailable) and
P2 incidents (degraded performance > 5 min) are required entries.*

### SLA performance

| SLA target | Measurement period | Achieved |
|------------|-------------------|---------|
| P99 enforce latency < 50 ms | `<period>` | `<ms>` |
| 99.9% availability (enforce endpoint) | `<period>` | `<%>` |
| Kill-switch propagation < 1 s | `<period>` | `<ms P99>` |

### Lessons learned

*Fill in after at least one incident or after 6 months of operation. Document
what the incident revealed about the deployment topology and what was changed.*

---

## Section 6: Compliance Posture

### Framework coverage

For each framework the customer operates under, confirm that the Eunox controls
in `docs/compliance-alignment.md` are in place.

| Framework | Status | Evidence location | Auditor-ready |
|-----------|--------|------------------|--------------|
| SOC 2 Type II CC6 | `<in place / partial / N/A>` | `<location>` | `<yes/no>` |
| HIPAA §164.312 | `<in place / partial / N/A>` | `<location>` | `<yes/no>` |
| NIST 800-207 | `<in place / partial / N/A>` | `<location>` | `<yes/no>` |
| PCI-DSS 10 | `<in place / partial / N/A>` | `<location>` | `<yes/no>` |

### Audit chain verification

Record the output of a chain proof verification run against the production audit store.

```bash
# Verify the audit chain for a 30-day period
curl -s "https://<gateway>/api/v1/audit/chain-proof?from=<ISO8601>&to=<ISO8601>" \
  -H "Authorization: ******" | jq .
```

Expected output:
```json
{
  "valid": true,
  "recordCount": <count>,
  "firstRecord": "<ISO8601>",
  "lastRecord": "<ISO8601>",
  "chainHash": "<sha256>"
}
```

| Verification run date | Record count | `valid` field | Chain hash |
|-----------------------|-------------|--------------|-----------|
| `<date>` | `<count>` | `<true/false>` | `<hash>` |

---

## Section 7: Customer Testimonial [OPTIONAL]

*To be completed only with explicit customer consent and legal review.*

**Quote for use in sales materials:**

> "[Customer quote about Eunox in production — latency, reliability, compliance
> value, or operational experience.]"
>
> — [Name, Title, Company]

**Use approved for:** `<case study / sales deck / website / press release>`

---

## Package Completion Checklist

- [ ] Section 1: Customer Overview complete
- [ ] Section 2: Deployment topology diagram provided
- [ ] Section 2: Kubernetes configuration table complete
- [ ] Section 3: Latency numbers measured and recorded
- [ ] Section 4: Kill-switch test results recorded (all pass)
- [ ] Section 4: Chaos test results recorded
- [ ] Section 5: Incident log current (or "no incidents" confirmed)
- [ ] Section 5: SLA performance recorded for ≥ 3 months
- [ ] Section 6: Compliance posture table complete
- [ ] Section 6: Audit chain verification run recorded
- [ ] Customer legal review of any externally shared sections complete
- [ ] Eunox Customer Success approval

---

## References

- `docs/deployment.md §Multi-AZ Reference Architecture`
- `docs/gateway-operator-runbook.md`
- `docs/chaos-results.md`
- `docs/compliance-alignment.md`
- `docs/runbooks/gateway-triage.md`

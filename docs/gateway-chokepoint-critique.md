# Gateway-as-Chokepoint: Critique and Execution Plan

> **Date:** 2026-05-28
> **Status:** P2 tasks completed — see implementation notes below

---

## Part 1 — Critique of the Analysis

### What the analysis gets right

**1. The single-point-of-failure framing is accurate and important.**
The gateway being on the hot path of every tool call is not incidental; it is
the design. The security guarantee (every action is mediated and audited) and
the operational liability (the gateway going down stops all agents) are the same
property viewed from two angles. The analysis is correct that this needs a
direct, prepared answer in sales conversations — reassurances are not enough.

**2. The latency tax on pipeline agents is a real, distinct concern.**
The analysis correctly distinguishes conversational agents (3–4 calls per turn,
latency acceptable) from agentic pipelines (hundreds of sequential calls, where
per-call overhead compounds). This distinction is absent from the current
architecture documentation and deserves its own section in the performance
story.

**3. The blast radius description is directionally correct.**
A gateway that proxies all agent traffic becomes a highly privileged network
node. The current architecture concentrates this risk; that is worth documenting
explicitly as a threat model entry rather than leaving it implicit.

**4. The debugging complexity point is valid and underserved.**
When a tool call fails, the failure could be policy, availability, token expiry,
a condition violation, or a backend error. The analysis is correct that adding a
proxy layer increases diagnostic surface. Distributed tracing (OQ-2 from the
Cycle 2 architecture review) and a triage runbook are the concrete mitigations,
and neither is published yet.

**5. The API gateway historical comparison is apt.**
Kong/Apigee/AWS API Gateway survived the same operational objection because
the value proposition was clear and the reliability track record accumulated.
Eunox is at the "no track record yet" stage of that same curve.

**6. The regulated enterprise paradox is the sharpest observation.**
Regulated enterprises are the most likely adopters (compliance requirement
drives adoption) and the least tolerant of unproven critical-path dependencies.
This is a real tension and the plan below addresses it directly.

---

### Where the analysis oversimplifies or is wrong

**1. The sidecar model proposal is underbaked on its hardest problem: kill-switch
propagation.**
The analysis says "same enforcement logic, same cryptographic guarantees" but
does not explain how revocation and kill-switch state propagates to N sidecars.
The current Redis pub/sub design works well for a small gateway fleet (2–5
replicas). In a sidecar model with one process per agent pod, a kill switch
issued against a compromised agent must propagate to potentially hundreds of
independent subscribers within the sub-second SLA the architecture requires.
This is solvable (each sidecar maintains its own pub/sub subscription; Redis
fan-out handles the rest) but the latency and connection-count implications are
non-trivial and must be designed explicitly before recommending the model. The
Envoy/Istio analogy is useful marketing, but those proxies enforce routing rules,
not cryptographic capability verification — the implementation complexity is
materially higher.

**2. Bypass/advisory mode would structurally undermine the compliance value
proposition.**
The analysis presents this as a clean "get you in the door" strategy. But the
organizations most likely to adopt Eunox — those facing SOC 2 Type II, HIPAA,
or PCI-DSS audits — need hard, auditable enforcement. Advisory-only controls do
not satisfy audit requirements. Offering bypass mode risks training the market
that enforcement is optional, and creates a permanent install base of
advisory-mode deployments that never graduate. The correct alternative for
evaluation is a safe sandbox topology (dev mode, read-only backends,
non-production data), not weakened enforcement semantics.

**3. The audit-enforcement coupling concern may be largely already addressed.**
`docs/redis-failure-modes.md` documents that the rate limiter and call counter
use fail-open policies precisely because audit/accounting writes should not block
enforcement. The analysis presents the synchronous audit write problem as
entirely unresolved, which is not accurate. What is missing is documentation of
the async audit path's consistency guarantees (write-ahead log behavior under
load) and a customer-facing description of what "audit write failure" means for
the cryptographic audit chain.

**4. The "five-nines availability" problem is an operational commitment gap, not
an architecture gap.**
The gateway already supports HPA, PDB, and multi-AZ topology. The chaos
engineering framework (`internal/chaos/`) and documented failure modes
(`docs/redis-failure-modes.md`, `docs/chaos-testing-strategy.md`) provide the
technical foundation. What does not exist is an externally published SLA with
numeric commitments, an incident response runbook in operator-accessible form,
and published chaos engineering results. The analysis correctly identifies this
gap but misdiagnoses it as architectural — it is a documentation and commitment
gap.

**5. The analysis was written without reference to the existing failure-mode
documentation.**
`docs/redis-failure-modes.md` defines precise fail-closed vs fail-open policies
for kill switch, revocation, rate limiter, and call counter. `docs/chaos-testing-
strategy.md` defines a coverage matrix and release gates. The degraded-mode
behavior the analysis calls for largely exists; it simply isn't published in a
customer-facing form.

**6. Centralization is the compliance feature, not just a liability.**
NIST 800-207 (Zero Trust Architecture), SOC 2 CC6.1–CC6.8, and HIPAA §164.312
all require a centralized access control decision point and a complete, tamper-
evident audit trail. A sidecar model trades a centralized gateway outage for a
distributed, per-agent audit fragmentation problem: compliance reviewers now
need to aggregate and verify completeness of audit logs from N independent
processes. The analysis does not account for this. Centralization is not a
concession to operational complexity — for the target buyer, it is the product.

---

### What the analysis omits

- **Quantified latency data.** The concern is stated but ungrounded. Before
  proposing architectural changes, measure actual P50/P99 enforcement latency
  end-to-end. The bottleneck is almost certainly Redis round-trips (2–5 ms in
  the same region), not the enforcement engine itself (sub-millisecond in-
  process). Capability token caching would address the hot-path concern without
  any architectural change.

- **The existing in-process fallback for evaluation.** `GATEWAY_NODE_ENV=
  development` runs the gateway without Redis, with no external dependencies.
  The "every agent stops" worst-case requires a production Redis outage, which is
  a different risk profile than the analysis implies for new evaluators.

- **Reference architecture for the HA deployment.** The docs describe components
  but do not provide a complete multi-AZ topology diagram with labeled failure
  domains, expected RTO, and recovery procedure. This is what a skeptical
  enterprise architect actually wants to see.

---

## Part 2 — Execution Plan

Tasks are grouped by theme and assigned priorities. **P1** must be complete
before any enterprise sales conversation enters proof-of-concept stage. **P2**
unblocks production deployments at scale. **P3** expands the deployment surface
for the next adoption wave. **P4** is strategic positioning work with no hard
deadline dependency.

Dependencies are noted where a task must follow another.

---

### P1 — Operational Credibility (prerequisite for enterprise PoC)

These items close the gap between the technical foundation that exists and the
customer-facing evidence that does not. They are primarily documentation and
commitment work, not engineering.

| ID | Task | Effort | Depends on |
|----|------|--------|-----------|
| P1-1 | Publish **gateway degraded-mode specification**: for each failure mode (Redis outage, PostgreSQL outage, DPoP store unavailable, DID endpoint unavailable), document the exact HTTP behavior, which requests succeed/fail, and why. Extend `docs/redis-failure-modes.md` to cover non-Redis failure paths. | S | — |
| P1-2 | Write **gateway operator runbook** (parallel to `docs/issuer-operator-runbook.md`): SLA targets, health check endpoints, alert thresholds, escalation steps, and recovery procedures for each degraded mode. | M | P1-1 |
| P1-3 | Publish **chaos engineering results**: run the existing chaos framework against a staging environment, capture results, and add a `docs/chaos-results.md` with pass/fail matrix. This is the evidence that converts "we have chaos tests" into "the tests pass." | M | — |
| P1-4 | Add a **multi-AZ reference architecture diagram** to `docs/deployment.md` or `docs/diagrams.md`: two gateway replicas across two AZs, Redis Sentinel or Cluster, PostgreSQL primary + read replica, labeled failure domains, RTO/RPO table. | S | — |
| P1-5 | Write a **gateway triage runbook** for agent-workflow failures: decision tree covering "was it the gateway policy / gateway availability / backend / token expiry / rate limit / condition violation," with the exact log fields and metrics to inspect at each branch. This directly addresses the debugging complexity objection. | M | P1-1 |

---

### P2 — Latency and Hot-Path Performance (prerequisite for pipeline-agent use cases)

These items address the "latency tax compounds at scale" concern without
requiring architectural changes. They should be executed before the first
production customer with a pipeline-agent workload.

| ID | Task | Effort | Depends on | Status |
|----|------|--------|-----------|--------|
| P2-1 | **Measure enforcement hot-path latency** end-to-end: P50, P99, P999 for `/api/v1/enforce` under realistic token shapes and Redis topology. Publish the numbers in `docs/architecture.md` §Performance. Until this exists, latency discussions are speculative. | S | — | ✅ Done — benchmarks in `internal/gateway/enforce_benchmark_test.go`; numbers in `docs/architecture.md §11` |
| P2-2 | **In-process capability token cache with background TTL refresh**: cache verified capability tokens in the gateway process for the duration of their remaining TTL. On a cache hit, skip the Redis revocation lookup and re-verification for tokens seen within the last N seconds (configurable). This eliminates the Redis round-trip for the common case on repeated calls within a single agentic pipeline. Fail closed on cache miss. | M | P2-1 | ✅ Done — `pkg/capability.TokenCache`; env vars `GATEWAY_TOKEN_CACHE_TTL_SECONDS` / `GATEWAY_TOKEN_CACHE_MAX_SIZE` |
| P2-3 | **Decouple audit writes from enforcement response**: the enforcement path must not block on audit write completion. Implement a write-ahead buffer (bounded channel + background flusher) so the audit write is enqueued before the HTTP response is sent. Document the consistency guarantee: audit writes are durable within one flush interval or on graceful shutdown. | M | — | ✅ Done — `pkg/audit.AsyncPipeline`; wired in `handleEnforce` via `emitEnforceAuditEvent()` |
| P2-4 | **OTLP/distributed tracing support** (OQ-2 from Cycle 2 architecture review): add `OTEL_EXPORTER_OTLP_ENDPOINT` support and trace-context propagation across gateway → issuer → minter. Without this, diagnosing latency anomalies across service boundaries requires log correlation by `X-Request-Id`, which is expensive. Document in `docs/deployment.md`. | M | P2-1 | ✅ Done — `tracingTransport` in `jwks_verifier.go`; per-step spans in `handleEnforce`; `docs/architecture.md §11` |

#### P2 implementation notes

**P2-1 — Benchmarks**  
Three benchmark scenarios in `internal/gateway/enforce_benchmark_test.go`:

- `BenchmarkHandleEnforce_NoCache` — full JWKS verify + engine eval path (~208 µs/op)
- `BenchmarkHandleEnforce_CacheHit` — token already in cache (~164 µs/op, ~20% faster)
- `BenchmarkHandleEnforce_CacheMiss_Concurrent` — 8 goroutines contending (~147 µs/op amortised)

Full analysis in `docs/architecture.md §11`.

**P2-2 — Token cache security trade-off**  
On a cache hit, the Redis revocation check is skipped. Revoked tokens remain valid
until their cache entry expires (controlled by `GATEWAY_TOKEN_CACHE_TTL_SECONDS`,
default 30 s) or until a subsequent request triggers eager eviction via `Invalidate()`.
Operators with sub-30 s revocation SLAs should lower this value accordingly.

**P2-3 — Consistency guarantee**  
`pkg/audit.AsyncPipeline.Close()` drains all buffered entries before closing the
inner pipeline. Events are durable within one flush interval or on graceful
shutdown. Events can be lost only on `SIGKILL` while the buffer is non-empty.
The buffer size is configurable (`AsyncPipelineConfig.BufferSize`); when full,
`Append` returns `ErrAsyncPipelineBufferFull` and logs a warning instead of
blocking the caller.

**P2-4 — Span inventory**  
`handleEnforce` emits child spans for each enforcement sub-step:
`verify_token`, `revocation_check`, `dpop_check`, `kill_switch_check`,
`engine_eval`. The JWKS HTTP client propagates W3C TraceContext + Baggage
headers outbound via `tracingTransport`.


### P3 — Deployment Flexibility (prerequisite for next adoption wave)

These items expand the deployment surface and directly address the
single-point-of-failure objection. P3-1 is the architectural design work that
must precede any sidecar implementation.

| ID | Task | Effort | Depends on |
|----|------|--------|-----------|
| P3-1 | **Sidecar deployment model design document**: write an architecture decision record (ADR) for `docs/adr/` that covers: (a) kill-switch propagation latency and connection-count implications at N=100 and N=1000 sidecars, (b) revocation state bootstrapping on sidecar startup, (c) policy update atomicity vs per-agent policy drift, (d) audit log aggregation and completeness verification, (e) compliance implications for SOC 2 / HIPAA reviewers. This ADR must exist before implementation begins. | M | P1-1, P2-1 |
| P3-2 | **Implement sidecar deployment mode**, scoped initially to single-agent pods with independent Redis subscriptions. The kill-switch and revocation paths must use the same sub-second propagation guarantee as the centralized model. Validate with the chaos framework. | L | P3-1, P2-3 |
| P3-3 | **Evaluation sandbox topology document**: a documented topology for new evaluators that uses dev mode (no Redis, no external deps, embedded SQLite) against read-only, non-production backends. This is the correct alternative to advisory/bypass mode — isolate the blast radius through topology, not through weakened enforcement semantics. | S | — |
| P3-4 | **Per-agent failure domain isolation in the centralized model**: add a gateway config option to partition enforcement contexts by agent identity, so that a Redis subscription failure for one agent's kill-switch subscription degrades only that agent rather than the entire gateway. | M | P1-1 |

---

### P4 — Strategic Positioning (no hard dependency, improves win rate)

| ID | Task | Effort | Depends on |
|----|------|--------|-----------|
| P4-1 | **Enforcement latency benchmark report**: publish measured P99 latency comparisons for: no gateway (baseline), centralized gateway (current), gateway with token cache (P2-2), sidecar (P3-2). This converts the "latency tax" objection from a concern into a calibrated engineering decision. | S | P2-1, P2-2, P3-2 |
| P4-2 | **"Eunox vs API gateway" positioning doc**: document why agent governance requires a capability-native model rather than request routing, and why the operational objections to Eunox apply equally (or more) to API gateways that are already in the customer's stack. | S | P1-2 |
| P4-3 | **Compliance alignment matrix**: map Eunox controls to specific requirements in SOC 2 CC6, HIPAA §164.312, NIST 800-207, and PCI-DSS 10.x. The centralized audit trail and cryptographic capability chain satisfy requirements that a sidecar model complicates. This document is the answer to "why can't we just use our existing API gateway?" | M | P1-1 |
| P4-4 | **Reference customer readiness package**: a template for reference customers documenting their topology, observed latency, kill-switch test results, and incident response record. Target: first reference customer with six months of production operation. | S | P1-2, P1-3 |

---

## Priority and dependency summary

```
P1-1 (degraded-mode spec)
  └── P1-2 (operator runbook) ──── P4-2
  └── P1-5 (triage runbook)
  └── P3-1 (sidecar ADR) ─────── P3-2
  └── P3-4 (per-agent isolation)
P1-3 (chaos results)
P1-4 (HA reference diagram)

P2-1 (latency measurement)
  └── P2-2 (token cache) ───────── P4-1
  └── P2-4 (OTLP tracing)
  └── P3-1 (sidecar ADR)
P2-3 (async audit writes) ──────── P3-2

P3-3 (eval sandbox doc)           [no dependencies]

P4-3 (compliance matrix)          [after P1-1]
P4-4 (reference customer pkg)     [after P1-2, P1-3]
```

**Effort key:** S = 1–2 days · M = 3–5 days · L = 1+ week

**What is explicitly not in this plan:**
- Advisory/bypass enforcement mode. The compliance value proposition requires
  hard enforcement. Evaluation should use the sandbox topology (P3-3), not
  weakened semantics.
- Rewriting the gateway to a sidecar-first model before the ADR (P3-1) is
  complete and the latency data (P2-1) exists.
- A visual policy editor. Correct sequencing places this after the operational
  credibility and latency work is done and enterprise adoption is established.

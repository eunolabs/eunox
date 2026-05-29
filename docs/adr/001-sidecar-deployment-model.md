# ADR-001: Sidecar Deployment Model

**Status:** Accepted  
**Date:** 2026-05-28  
**Depends on:** P1-1 (degraded-mode spec), P2-1 (latency measurement)

---

## Context

The current Eunox gateway is deployed as a shared, centralized service: all agent traffic
from all agents in a tenant passes through a fleet of gateway replicas. This is the
_centralized model_ documented in `docs/deployment.md`.

The gateway-chokepoint critique (P3-1 in `docs/gateway-chokepoint-critique.md`) asks
whether the gateway should also support a _sidecar model_: one gateway instance deployed
alongside each agent pod, enforcing policy only for that agent. This ADR documents the
design decision, its constraints, and the implementation boundaries.

---

## Decision

Implement a sidecar deployment mode for the Eunox gateway, initially scoped to
single-agent pods. The sidecar mode is **additive**: it does not replace the centralized
model. Operators choose per-workload which topology to use.

The sidecar mode is enabled by setting `GATEWAY_SIDECAR_MODE=true` and
`GATEWAY_SIDECAR_AGENT_ID=<agent-id>` in the gateway container's environment.

---

## Sidecar Deployment Topology

```
┌──────────────────────────────────────────────────────────────────┐
│  Kubernetes Pod                                                  │
│                                                                  │
│  ┌─────────────────┐        ┌─────────────────────────────────┐  │
│  │  Agent Container│──────► │  Gateway Sidecar Container      │  │
│  │                 │        │  GATEWAY_SIDECAR_MODE=true      │  │
│  │  agent-id: acme │        │  GATEWAY_SIDECAR_AGENT_ID=acme  │  │
│  └─────────────────┘        └────────────┬────────────────────┘  │
│                                          │                       │
└──────────────────────────────────────────┼───────────────────────┘
                                           │
                              ┌────────────┼────────────────────┐
                              │            ▼                    │
                              │   ┌─────────────────────┐       │
                              │   │  Redis              │       │
                              │   │  (Sentinel/Cluster) |       │
                              │   └─────────────────────┘       │
                              │                                 │
                              │   Shared infrastructure         │
                              │   (Redis, PostgreSQL, Issuer)   │
                              └─────────────────────────────────┘
```

In sidecar mode:

- The gateway listens on `127.0.0.1:3002` (loopback only, unreachable from outside the pod)
- The agent is configured to send all tool calls to `http://127.0.0.1:3002/api/v1/enforce`
  (use `127.0.0.1` explicitly, not `localhost`, to avoid DNS resolution to `::1` in IPv6-first environments)
- Policy, revocation, and kill-switch state are still stored in shared Redis
- Each sidecar has its own independent Redis pub/sub subscription

---

## Design Analysis

### (a) Kill-Switch Propagation: Latency and Connection Count

**Problem.** The centralized model uses a single Redis pub/sub channel
(`killswitch:events`) shared by all gateway replicas. A kill-switch command issued
against any agent propagates to all replicas via that channel within the Redis
fan-out latency (typically < 5 ms in the same region).

In the sidecar model, each agent pod has an independent sidecar with its own Redis
connection and pub/sub subscription. For N agents:

| N agents | Redis connections (centralized) | Redis connections (sidecar)     |
| -------- | ------------------------------- | ------------------------------- |
| 10       | 2–5 (one per replica)           | 10–20 (one per sidecar + spare) |
| 100      | 2–5                             | 100–200                         |
| 1 000    | 2–5                             | 1 000–2 000                     |

**Implication.** Redis Cluster and Redis Sentinel both support tens of thousands of
concurrent connections. Connection count is not a limiting factor up to ~1 000 agents on
a standard 4-CPU Redis node. At N=1 000, the connection overhead is ~100 MB of Redis
memory and ~20 MB of sidecar process memory across all pods.

**Propagation latency.** Kill-switch events propagate independently to each sidecar via
its own subscription. The sub-second guarantee is preserved: each sidecar's subscription
receives the event within the same Redis pub/sub round-trip as in the centralized model.
There is no broadcast fan-out delay because Redis delivers messages to all subscribers
concurrently; N sidecars each receive the event in the same wall-clock time as 1 replica.

**Failure isolation.** If one sidecar's Redis connection is interrupted:

- That sidecar's kill-switch becomes stale (fail-closed after TTL; see P3-4)
- All other sidecars are unaffected
- Compare with centralized: if the shared subscription fails, all agents are potentially
  stale simultaneously

This is the principal availability advantage of the sidecar model.

### (b) Revocation State Bootstrapping on Startup

**Problem.** When a sidecar starts, it must acquire the current revocation and
kill-switch state before serving its first enforcement request. If it begins serving
requests with an empty local cache, it is momentarily fail-open (treating un-revoked
all tokens).

**Mitigation implemented.**

1. On startup, the sidecar performs a synchronous state refresh from Redis before the
   HTTP listener binds. If the refresh fails, the sidecar exits rather than starting
   fail-open (configurable via `GATEWAY_FAIL_OPEN_ON_STARTUP=false`, default `false`).
2. The kill-switch `Redis.Start()` loads initial state synchronously, then subscribes
   in the background. The readiness probe (`GET /health/ready`) returns 503 until the
   initial load completes, preventing Kubernetes from routing traffic prematurely.
3. Revocation state is stored in Redis as a set; the sidecar scans the full revocation
   set on startup (same code path as the centralized gateway's `ResilientRedis`).

**Bootstrap time.** For a revocation set of 10 000 entries, the SCAN loop completes in
< 200 ms on a co-located Redis node. For production deployments, the revocation set is
typically < 1 000 entries (tokens expire via TTL).

### (c) Policy Update Atomicity vs Per-Agent Policy Drift

**Problem.** In the centralized model, a policy update (e.g., `PolicyStore.Reload()`)
is applied atomically to all enforcement contexts simultaneously because all requests
share one process. In the sidecar model, policy updates are applied to each sidecar
independently as each pod's `PolicyReloader` fires its hot-reload tick.

**Drift window.** The worst-case drift window is one policy-reload interval (default:
30 s, configurable via `GATEWAY_POLICY_RELOAD_INTERVAL_SECONDS`). During this window,
different agents may evaluate requests against different policy versions.

**Acceptable conditions:**

- Policy updates are additive (granting new permissions) or restrictive (revoking).
- Additive updates: brief window where some agents lack the new permission. Acceptable.
- Restrictive updates: brief window where some agents retain a revoked permission.
  **Not acceptable for security-critical revocations.** Use the kill-switch for
  immediate revocation; policy hot-reload is for non-emergency updates.

**Mitigation:** Document in operator guide that security-critical revocations must go
through the kill-switch (`KillAgent`) rather than waiting for policy hot-reload.
Policy hot-reload is for routine capability updates, not emergency revocations.

### (d) Audit Log Aggregation and Completeness Verification

**Problem.** The centralized model produces a single tamper-evident audit chain from
one (or a small fleet of) gateway replicas. In the sidecar model, each sidecar
produces an independent audit chain for its agent.

**For compliance purposes:**

- Each sidecar's audit chain is complete and tamper-evident for its agent's traffic
- The HMAC chain guarantees completeness within a sidecar
- Across sidecars, an operator must aggregate chains and verify no gaps exist for
  any agent that should have been active

**Aggregation approach:**

1. All sidecars write to the same PostgreSQL audit database (shared backend)
2. Audit records carry `agent_id` and `sidecar_id` fields (set from `GATEWAY_SIDECAR_AGENT_ID`)
3. Completeness query: `SELECT agent_id, COUNT(*) FROM audit_records GROUP BY agent_id`
   can confirm no agent has zero records during a period of expected activity
4. Chain proof verification: `GET /api/v1/audit/chain-proof` returns the Merkle proof
   for the sidecar's local chain; operators can independently verify each chain

**Compliance implication:** Centralized model produces one chain; auditors inspect one
proof. Sidecar model produces N chains; auditors must verify N proofs. The
`/api/v1/audit/chain-proof` endpoint is unchanged; a compliance script must call it
once per active sidecar. `docs/runbooks/audit-aggregation.md` documents this procedure.

### (e) Compliance Implications for SOC 2 / HIPAA Reviewers

**SOC 2 CC6.1–CC6.8 (Logical Access Controls)**

| Control                              | Centralized                                 | Sidecar                                                                         |
| ------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------- |
| CC6.1: Access control decision point | Single gateway, auditors inspect one system | Per-pod gateway; auditors must enumerate all pods                               |
| CC6.2: Authentication                | Identical (shared issuer JWKS)              | Identical                                                                       |
| CC6.3: Authorization records         | One audit chain per cluster                 | N audit chains; aggregation required                                            |
| CC6.6: Restrict access by network    | Gateway is the single ingress               | Each pod has a sidecar; network policy must block pod-to-pod enforcement bypass |
| CC6.8: Detection controls            | One log stream                              | N log streams; must route to shared SIEM                                        |

**HIPAA §164.312(a)(1) — Access Control**
Both models satisfy the access control requirement. The sidecar model adds the
administrative burden of ensuring each sidecar is configured consistently and all
sidecars are running (a stopped sidecar would block agent requests, not allow them —
fail-closed default).

**NIST 800-207 (Zero Trust) §3.3**
Both models comply. The sidecar model aligns more closely with the "micro-perimeter"
ZTA pattern where the enforcement point is as close as possible to the resource.
However, NIST 800-207 §5.2 notes that the PEP and PDP should be separate components;
in the sidecar model the enforcement engine (PEP) and policy evaluation (PDP) are
co-located in the sidecar, which is acceptable per §5.2's exception for "simplified
deployment topologies" with shared policy storage.

**Recommendation for regulated enterprises:** Continue with centralized model for
environments requiring a single, auditable enforcement point and SOC 2 compliance.
Use sidecar model for developer environments, sandboxes, or workloads where per-agent
blast radius isolation outweighs audit consolidation simplicity.

---

## Implementation Scope (Initial)

The initial implementation (P3-2) is scoped to:

1. **`GATEWAY_SIDECAR_MODE=true`** — enables sidecar mode
2. **`GATEWAY_SIDECAR_AGENT_ID=<id>`** — required when sidecar mode is enabled
3. **Agent identity enforcement** — in sidecar mode, enforcement requests for agents
   other than `GATEWAY_SIDECAR_AGENT_ID` are rejected with 403
4. **Per-agent kill-switch partitioning (P3-4)** — a `PartitionedKillSwitch` that
   tracks kill-switch subscription health per agent, so one failed subscription only
   degrades that agent
5. **Startup readiness gate** — readiness probe blocks until initial state is loaded
6. **Chaos test coverage** — two new scenarios:
   - Sidecar kill-switch isolation: kill agent A does not affect agent B's sidecar
   - Sidecar startup resilience: sidecar starts fail-closed when Redis is unavailable

**Out of scope (future):**

- Multi-agent sidecar (shared sidecar for a small pod group)
- Sidecar-to-centralized migration path
- Helm chart sidecar injection template (tracked separately)

---

## Consequences

**Positive:**

- Blast radius of a single gateway failure is one agent, not all agents
- Independent Redis subscriptions provide genuine failure domain isolation
- Aligns with Kubernetes sidecar pattern; no changes to agent containers
- Existing enforcement engine, policy engine, and audit code are unchanged

**Negative:**

- N sidecars require N Redis connections (acceptable up to ~1 000 agents per Redis node)
- Policy drift window of up to one reload interval (mitigated: use kill-switch for
  immediate security-critical revocations)
- Audit aggregation requires per-sidecar chain verification (mitigated: script in
  `docs/runbooks/audit-aggregation.md`)
- Kubernetes resource overhead: one gateway pod per agent pod (~50 MB RAM, ~0.1 CPU)

**Neutral:**

- Centralized model continues to be the default and the recommendation for regulated
  enterprises requiring a single audit chain
- Both models share identical enforcement semantics, JWKS verification, and DPoP logic

---

## Alternatives Considered

**1. Envoy/Istio external authorization.**
Rejected. External authorization via `ext_authz` provides request routing decisions
but not capability verification. The Eunox enforcement engine performs cryptographic
verification of capability tokens (JWS signature + revocation check + DPoP binding)
that cannot be delegated to a generic proxy filter without shipping the enforcement
logic as an Envoy WASM filter. The WASM sandbox adds memory and latency constraints
that conflict with the sub-millisecond enforcement target.

**2. Advisory (non-enforcing) mode for evaluation.**
Rejected. See `docs/gateway-chokepoint-critique.md §Where the analysis is wrong §2`.
The evaluation topology is the sandbox topology documented in `docs/eval-sandbox.md`,
not weakened enforcement semantics.

**3. Per-agent dedicated centralized gateway.**
Equivalent to the sidecar model from an isolation standpoint but without co-location.
No meaningful advantage over sidecar; sidecar is simpler to operate in Kubernetes.

---

## References

- `docs/deployment.md §Multi-AZ Reference Architecture` — centralized topology
- `docs/redis-failure-modes.md` — failure policies for each Redis dependency
- `docs/gateway-operator-runbook.md` — SLA targets and recovery procedures
- `docs/chaos-results.md` — existing chaos test pass matrix
- `docs/eval-sandbox.md` — evaluation sandbox topology (P3-3)
- `pkg/killswitch/partitioned.go` — per-agent kill-switch partitioning (P3-4)
- `internal/gateway/sidecar.go` — sidecar mode agent identity middleware

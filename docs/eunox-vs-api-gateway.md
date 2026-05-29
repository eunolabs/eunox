# Eunox vs. API Gateway

> **Audience:** Enterprise architects, security teams, and procurement evaluators
> comparing Eunox with existing API gateway solutions (Kong, AWS API Gateway,
> Azure APIM, Apigee).

---

## Summary

API gateways are purpose-built for _request routing_ and _service-level policy_:
rate limiting, authentication, TLS termination, and traffic shaping between services.

Eunox is purpose-built for _agent governance_: enforcing which AI agent is allowed
to call which tool, with which arguments, under which conditions, with a tamper-evident
audit trail of every decision.

These are different problems. The operational concerns that apply to API gateways —
single point of failure, latency on the critical path, blast radius on outage — also
apply to every API gateway already in your stack. The fact that you already accept
those trade-offs for request routing is evidence that the trade-off is manageable when
the value is clear.

---

## What API Gateways Do

| Capability                                                     | Kong / Apigee / AWS APIM |
| -------------------------------------------------------------- | ------------------------ |
| TLS termination                                                | ✅                       |
| Rate limiting (service-to-service)                             | ✅                       |
| Authentication (API key, OAuth 2.0)                            | ✅                       |
| Request routing and load balancing                             | ✅                       |
| Caching, circuit breaking                                      | ✅                       |
| Plugin ecosystem                                               | ✅                       |
| Per-request capability verification                            | ❌                       |
| Cryptographic agent identity                                   | ❌                       |
| Kill-switch (sub-second propagation)                           | ❌                       |
| Tamper-evident audit chain (HMAC)                              | ❌                       |
| Condition-based enforcement (time, count, approval)            | ❌                       |
| Obligation enforcement (redaction, rate limits per capability) | ❌                       |
| Revocation of individual capability tokens                     | ❌                       |
| DPoP proof binding (prevents replay across agents)             | ❌                       |

**API gateways enforce policy at the service boundary.** They can check whether a
caller has a valid API key or OAuth token. They cannot check whether the AI agent
making the request is within the capability bounds granted to it, whether its
session has been revoked, or whether the specific action it is requesting is
permitted for this agent at this moment.

---

## The Central Distinction: Routing vs. Governance

### Request routing (API gateway)

```
Request ──► API Gateway ──► Backend service
              │
              └── Is the API key valid?
                  Is the OAuth scope correct?
                  Is the rate limit exceeded?
```

The API gateway makes a binary allow/deny on whether the _caller is authenticated_.
It does not know what the caller is trying to do, which agent generated the request,
or whether the specific action is within the caller's granted capabilities.

### Agent governance (Eunox)

```
Request ──► Eunox Gateway ──► Backend service
              │
              └── Is the capability token cryptographically valid?
                  Is this token revoked?
                  Is the calling agent killed?
                  Does this agent's capability cover this tool + action?
                  Are all conditions satisfied (time window, call count, approval)?
                  Is the DPoP proof bound to this request?
                  Append audit record to tamper-evident chain.
```

Eunox makes a _governance decision_: does this specific agent, in this specific
session, have the right to take this specific action right now? That decision
is recorded in an immutable audit chain regardless of outcome.

---

## "Can't We Just Add a Plugin to Kong/Apigee?"

This question comes up frequently. The answer is: technically yes, but the resulting
system inherits the plugin execution model's constraints.

| Constraint                                                    | Impact                                                                                                           |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Plugin execution is sandboxed (limited to request/response)   | Cannot maintain shared kill-switch state across requests                                                         |
| Plugins run in the gateway process; state is per-instance     | Redis pub/sub kill-switch cannot propagate sub-second across plugin instances without custom plumbing            |
| Plugin SDKs do not expose DPoP binding primitives             | DPoP proof verification (nonce, `jkt` confirmation) requires custom crypto not available in standard plugin SDKs |
| HMAC audit chain requires sequential, stateful write ordering | Plugin model processes requests independently; chaining requires a separate write-ordering service               |
| Plugin upgrade and rollout is tied to gateway version         | Capability token schema migrations are blocked on gateway upgrades                                               |

A Kong or Apigee plugin that replicated Eunox's full enforcement model would
effectively be re-implementing Eunox inside a plugin sandbox with fewer primitives.
The operational objections do not disappear — they shift to the plugin.

---

## "Why Not Just Use Your Existing API Gateway?"

The question "why add another gateway?" deserves a direct answer.

**Your existing API gateway already accepts the latency and availability trade-off.**
Kong, Apigee, and AWS API Gateway are on the hot path of every service call.
They are single points of failure. You have already decided that the value (consistent
authentication, routing policy, observability) justifies the risk and the latency.
Eunox applies the same reasoning to a layer your existing gateway cannot address:
per-agent capability governance.

**The layers are complementary, not redundant.**

```
Internet ──► Load Balancer ──► API Gateway ──► Eunox Gateway ──► Tool Backend
                                    │                │
                               Service-level    Agent-level
                               policy           governance
                               (auth, routing)  (capabilities, audit)
```

In practice, many production deployments run Eunox behind the API gateway, using the
API gateway for TLS termination and network-level authentication, and Eunox for
per-request governance. The API gateway does not replace Eunox; Eunox does not
replace the API gateway.

---

## Availability: The Track Record Argument

The most common objection: "What if Eunox goes down?"

This is the right question. The honest answer:

1. **The gateway supports HPA, PDB, and multi-AZ topology.** A properly deployed
   gateway fleet with Redis Sentinel and PodDisruptionBudgets has the same
   availability profile as any other critical-path Kubernetes service. See
   `docs/deployment.md §Multi-AZ Reference Architecture`.

2. **Failure modes are documented and bounded.** `docs/redis-failure-modes.md`
   specifies exactly what HTTP behavior each dependency failure produces.
   "Gateway goes down" is not a single monolithic failure; each component has an
   independent failure mode and recovery procedure.

3. **The sidecar model isolates blast radius to one agent.** For workloads where
   per-agent availability isolation matters more than audit consolidation,
   `docs/adr/001-sidecar-deployment-model.md` describes the sidecar topology.

4. **The same question applies to your existing API gateway.** If Kong or Apigee
   goes down, all service-to-service traffic stops. The operational discipline for
   managing a critical-path gateway is identical. Eunox adds agent governance to
   a layer you already accept for service routing.

---

## Compliance: Why Centralization is a Feature

For regulated enterprises, centralization is not a liability — it is the compliance
requirement.

| Requirement                                       | Decentralized / per-service enforcement      | Eunox centralized enforcement             |
| ------------------------------------------------- | -------------------------------------------- | ----------------------------------------- |
| SOC 2 CC6.1: Single access control decision point | No — each service enforces independently     | Yes — one gateway evaluates every request |
| HIPAA §164.312: Complete audit trail              | Fragmented — each service logs independently | Yes — single tamper-evident chain         |
| NIST 800-207 §3: Policy Enforcement Point         | Distributed PEP — harder to audit            | Centralized PEP — single audit scope      |
| PCI-DSS 10.x: Log all access to cardholder data   | Per-service audit logs — no chain proof      | Cryptographic chain proof per request     |

A compliance reviewer auditing "which AI agents had access to PHI last quarter"
needs a single, complete, verifiable answer. Eunox provides it. Distributed
enforcement across N services with N log aggregation pipelines does not.

---

## Decision Guidance

| If your primary concern is...                          | Recommendation                               |
| ------------------------------------------------------ | -------------------------------------------- |
| Adding authentication to existing services             | API gateway                                  |
| Routing traffic between microservices                  | API gateway                                  |
| Governing which AI agents can call which tools         | Eunox                                        |
| Creating a tamper-evident audit trail of agent actions | Eunox                                        |
| Satisfying SOC 2 / HIPAA for AI agent access           | Eunox                                        |
| Reducing per-agent blast radius                        | Eunox sidecar mode                           |
| All of the above                                       | API gateway (upstream) + Eunox (agent layer) |

---

## References

- `docs/deployment.md §Multi-AZ Reference Architecture`
- `docs/redis-failure-modes.md`
- `docs/gateway-operator-runbook.md`
- `docs/adr/001-sidecar-deployment-model.md`
- `docs/compliance-alignment.md`

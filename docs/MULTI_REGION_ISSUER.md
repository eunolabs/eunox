# Multi-Region Active/Active Issuer (F-7)

Status: implemented in this PR.
Cross-references:

- `docs/IMPROVEMENTS_AND_REFACTORING.md` § 5 (F-7), § 6.1 (sequencing
  rules — F-7 ships only after F-1 is tenant-aware, which it is).
- `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md` (region-related items).
- `docs/openapi/capability-issuer.yaml` — `region` in the
  `/.well-known/capability-issuer` discovery doc and the
  `RATE_LIMIT_EXCEEDED` (`429 Too Many Requests` + `Retry-After`)
  response.

This document is the operator's guide to running Euno's
capability-issuer and tool-gateway in an **active/active**
multi-region topology. Active/passive failover is a strict subset of
the contract here and needs no additional configuration.

---

## 1. Goals & non-goals

**Goals**

- Survive a regional outage with **no token re-issuance** required and
  **no per-token revocation gap**.
- Keep the F-1 issuance rate-limit budget shared across regions for
  any single `(tenantId, userId, agentId)` so a compromised account
  cannot escape its budget by hopping regions.
- Preserve audit attribution: every record can be traced back to the
  region that produced it, even after a failover.
- Allow a token minted in region A to be validated and enforced in
  region B without round-tripping back to A.

**Non-goals (explicitly)**

- Single-write-region designs (active/passive) — supported but not the
  primary target; everything in this document still applies.
- Region-pinning enforcement at the gateway (rejecting a token
  because its `region` claim does not match the gateway's region) —
  not enforced. The `region` claim is informational; layer pinning on
  top with a deployment-specific policy if you need it.
- Cross-region distributed transactions — Euno's data model is
  CRDT-friendly enough that we never require them.

---

## 2. Topology

```
                 ┌──────────────────────┐
                 │   Global LB / DNS    │
                 └─────────┬────────────┘
           ┌───────────────┼─────────────────┐
           │               │                 │
   ┌───────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
   │  Region A    │ │   Region B    │ │   Region N    │
   │  (eastus2)   │ │ (westeurope)  │ │   (...)       │
   │              │ │               │ │               │
   │  Issuer-A    │ │   Issuer-B    │ │   Issuer-N    │
   │  Gateway-A   │ │   Gateway-B   │ │   Gateway-N   │
   │      │       │ │       │       │ │       │       │
   └──────┼───────┘ └───────┼───────┘ └───────┼───────┘
          │                 │                 │
          └─────────┬───────┴─────────────────┘
                    ▼
        Globally-replicated Redis (or Redis Enterprise CRDB,
        Azure Cache for Redis Geo-replication, AWS ElastiCache
        Global Datastore, GCP Memorystore active-active, etc.)
        ─────────────────────────────────────────────────────
        Stores (write-through, region-agnostic):
          - F-1 issuance rate-limit counters    (key: tenant|user|agent)
          - revocation list                     (key: revoked:<jti>)
          - kill-switch state                   (key: killswitch:*)
          - maxCalls call-counter store         (key: capcall:*)
```

Each region is a **complete** Euno deployment: an issuer, a gateway,
and the backend(s) the gateway proxies to. Redis is the only required
cross-region resource, and only because every shared safety primitive
is built on top of it.

---

## 3. Replication contract

The cross-region contract is, deliberately, **just Redis**. Euno makes
no other replication guarantees and depends on no other shared store.

| Primitive             | Key shape                       | Convergence requirement                   | Failure mode if Redis is partitioned                                                |
| --------------------- | ------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------- |
| F-1 rate-limit (INCR) | `issrl:<tenant>\|<user>\|<agent>` | "Eventually consistent within `windowSeconds`" — a brief budget over-spend after a partition heal is acceptable. | Issuer fails closed (denies with `RATE_LIMIT_EXCEEDED`). Operators can flip `ISSUANCE_RATE_LIMIT_FAIL_CLOSED=false` for the duration of the incident if degraded service is preferable to denial. |
| Revocation list       | `revoked:<jti>`                  | Strong consistency on read of any region's value within RTO. | Gateway fails closed by default (no token validates). Operators may flip the documented fail-open knob; doing so accepts that revoked tokens are honoured during the incident. |
| Kill-switch           | `killswitch:agent:<id>`, `killswitch:tenant:<id>` | Convergence within `KILL_SWITCH_REFRESH_INTERVAL_MS` (default 5 s) — see RedisKillSwitchManager. | Last known state is served from the per-process cache; a partition makes the kill-switch read-only until it heals. |
| maxCalls counters     | `capcall:<jti>`                  | Eventually consistent within the call-counter window. | Engine fails closed on the affected token (deny). |

### What MUST be true of the Redis tier

1. A write in region A is observable in region B "soon" — for our
   purposes "soon" means **bounded by the F-1 window length**
   (default 60 s). Redis Enterprise active-active CRDB, Azure Cache
   for Redis Geo-replication, ElastiCache Global Datastore, and
   Memorystore active-active all meet this with a typical lag in the
   tens of milliseconds.
2. `INCR` is atomic per key (true of every Redis-compatible product).
3. `EXPIRE` (PTTL) is honoured globally — keys expire once,
   everywhere. (CRDB does this; geo-replicated read replicas
   inherit it.)

If your Redis tier cannot promise (1)–(3), do **not** run F-7. Run
active/passive instead and route all writes to the active region.

---

## 4. Configuration per region

Each region's deployment **must** set:

- Issuer:
  - `ISSUER_REGION=<short region tag>` (e.g. `eastus2`, `westeurope`).
    Surfaced on:
    - the `region` claim of every minted capability token,
    - every `AuditLogEntry.region`,
    - every request span as the `euno.region` attribute,
    - the `/.well-known/capability-issuer` discovery doc.
  - `REDIS_URL` pointing at the regional Redis endpoint of the
    globally-replicated tier.
  - `ISSUANCE_RATE_LIMIT_*` — at least
    `ISSUANCE_RATE_LIMIT_ENABLED=true` and operationally-tuned
    `ISSUANCE_RATE_LIMIT_MAX` / `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS`.
- Gateway:
  - `GATEWAY_REGION=<short region tag>` (use the same tag as the
    co-located issuer).
  - `REDIS_URL` pointing at the regional Redis endpoint.
  - Existing `KILL_SWITCH_*`, `REVOCATION_*`, `CALL_COUNTER_*` env
    vars — they all become cross-region the moment they share
    Redis. No code changes are required.

### Signing keys

You have two viable patterns. Pick one explicitly; do not mix them.

- **Shared key (simplest).** Every region's issuer uses the same KMS
  key (e.g. an Azure Key Vault key with cross-region replication, an
  AWS multi-Region KMS key, or a GCP Cloud KMS key with
  `replicationStatus`). Every region's `getKeyId()` returns the same
  `kid`. The JWKS at every region's `/.well-known/jwks.json` is
  identical. Gateways do not need to know which region issued a
  token.
- **Per-region key (more isolation).** Each region uses its own KMS
  key with its own globally-unique `kid` (KMS-issued kids are already
  globally unique in practice — Azure Key Vault key URIs, AWS KMS
  ARN-derived kids, GCP CryptoKeyVersion paths). The gateway's JWKS
  cache (R-6) is configured with the JWKS endpoint of every region;
  the cache picks the matching `kid` per inbound token. The token's
  `region` claim is informational; it does **not** change which key
  is selected (`kid` does that), but it gives operators a fast way
  to spot mismatches.

`ISSUER_REGION_KID_PREFIX` is **not** a configuration knob — it would
add nothing on top of the KMS-issued unique kids the gateway already
selects on.

---

## 5. Token lineage across regions

The `region` claim on a `CapabilityTokenPayload` records the region
that minted the **root** of the lineage. Attenuation and renewal in a
different region **preserve** the parent's `region` value
unchanged. Concretely:

```text
Region A issues  → token T1   { region: "A", jti: "j1" }
Region B renews  → token T2   { region: "A", jti: "j2", parent: "j1" }
Region B attenuates T2
                 → token T3   { region: "A", jti: "j3", parent: "j2" }
```

This is deliberate. The `region` claim documents *who first vouched
for this lineage*, which is the question audit and compliance ask. If
you also want to know *which region most recently extended the
lineage*, look at the `region` field on the corresponding
`AuditLogEntry` — it is stamped from the **executing** region.

Tokens with no `region` claim are valid and behave exactly as they did
before F-7. Single-region deployments need not configure anything.

---

## 6. RTO / RPO targets

These are operator targets, not guarantees Euno can enforce on its
own — they depend on the underlying Redis tier and the global LB's
health-check policy. Euno's own design adds no latency to either.

| Failure mode                                | Target RPO       | Target RTO        | Notes                                                                                              |
| ------------------------------------------- | ---------------- | ----------------- | -------------------------------------------------------------------------------------------------- |
| Single issuer pod loss                      | 0                | < 30 s            | Standard k8s rolling/replacement. No per-region action required.                                   |
| Single region loss (issuer + gateway down)  | 0 (Redis CRDB)   | < global LB TTL   | Operator action: pull the region from the global LB / DNS. Tokens in flight remain valid in other regions. |
| Redis tier partial outage (one region)      | 0                | < 30 s            | The losing region's issuer fails closed. Gateways in other regions are unaffected if their Redis stays healthy. |
| Total Redis tier outage                     | up to one window | depends on tier   | F-1, revocation, kill-switch all fail closed by default. Operators may temporarily flip fail-open knobs (documented per primitive). |

---

## 7. Failover drill checklist

Run this once per quarter against a non-production region and once per
year against production. Time-box each step; don't skip the
verification rows.

1. **Pre-flight**
   - [ ] Confirm `ISSUER_REGION` and `GATEWAY_REGION` are set in every
         region (curl `/.well-known/capability-issuer` — the `region`
         field MUST be present and correct).
   - [ ] Confirm Redis cross-region replication is healthy (provider
         dashboard, lag < 1 s).
   - [ ] Confirm both regions accept a freshly-minted test token from
         either region (issue in A, validate via gateway in B).

2. **Failover**
   - [ ] Pull region A from the global LB.
   - [ ] Verify all in-flight tokens stamped `region: "A"` continue
         to validate at gateway B (look for them in B's audit logs).
   - [ ] Issue a new token in region B; verify its `region` claim is
         `"B"`.
   - [ ] Trigger the F-1 limit on a single subject from region B;
         confirm the next attempt **from region A** is still denied
         (proves the budget is shared via Redis).

3. **Failback**
   - [ ] Re-add region A to the LB.
   - [ ] Verify split traffic returns to both regions (decisions
         counter labelled by `euno.region` shows both).
   - [ ] Verify a `revoke` in region A is honoured in region B
         within one revocation refresh interval.

4. **Post-mortem**
   - [ ] Capture the F-1 deny rate, decision deny rate, and audit
         volume from both regions for the duration. Diff against the
         pre-flight baseline; explain any unexplained delta.

Keep the run-log in your incident-management system; the regional
attribution that F-7 adds to audit and tracing is what makes the
diff above meaningful.

---

## 8. Limitations & open follow-ups

- The token `region` claim records the **originating** region, not the
  enforcing one. If you need region-pinning (reject this token at
  gateway X because it was minted in region Y), you must add a
  deployment-specific policy condition; Euno does not enforce
  pinning in the default code path. This is a deliberate design
  choice — pinning trades availability for auditability and the
  right answer is workload-specific.
- A multi-region deployment without a globally-replicated Redis tier
  is **not supported**. If you only have per-region Redis, run
  active/passive: writes go to the home region, the standby region
  is read-only until promoted.
- Cross-region revocation latency is bounded by the Redis replication
  lag, not by Euno. Treat RTOs above as upper bounds; the actual
  numbers are dominated by your Redis tier.

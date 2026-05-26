# Stage 5 Design RFC — "Enterprise + Full Vision"

> **Status:** Ready for committee sign-off. The authoring work (Task 0) is complete.
> The gate condition — approved by ≥2 engineers + 1 security reviewer — must be
> met before any Task 3+ implementation begins. See §7 Review Checklist.
>
> **Last updated:** 2026-05-19
>
> **Authors:** _(add names at review)_
>
> **Reviewers:** _(add names + dates at sign-off)_
>
> **MVP anchors satisfied:** All decisions below cross-link to
> `docs/mvp.md` sections where they are required. The anchor tag and line
> range appear after each decision header.

---

## 0. Purpose and Scope

This document is the Stage 5 design freeze for `eunox`. It captures every
architectural decision that Tasks 2–13 must implement — and nothing else. The goal is
to make implementation choices explicit, reviewable, and traceable before code is
written, not discovered during code review.

**What this document decides:**

1. Priority order for un-quarantining the four frozen packages.
2. SCIM group-to-role mapping contract (env-var-managed vs. admin-API-managed table).
3. Helm chart dependency strategy (bitnami subcharts vs. externally-provisioned
   Postgres/Redis).
4. `did:ion` resolver SLA decision (hosted Microsoft ION vs. bundled sidecar for
   air-gapped deployments).
5. `@euno/common-core` seam additions — the exact three types Stage 5 adds to the
   Apache-2.0 tier.

**What this document does not decide:**

- Implementation details covered by individual task specifications in
  `docs/stage5executionplan.md`.
- Pricing tier changes beyond the feature matrix update in `docs/stage-4-design.md` §2.
  Stage 5 enterprise tier is described in `docs/mvp.md` §"Pricing & business model
  sketch" (lines 826–844) and is unchanged by this RFC.
- Python SDK, public-chain smart contracts, or a graphical policy editor (explicitly
  listed as non-goals in `docs/stage5executionplan.md` §"Non-goals").
- Separate AGT SDK npm package distribution (non-goal; the existing
  `InProcessToolTransport` / `InProcessProxyHandler` in `agent-runtime` is used as-is).

---

## 1. Quarantined Package Priority Order

> **MVP anchor:** `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" (lines 769–788) —
> "The strong signal you've reached Stage 5 successfully: a customer asks for a feature
> that's *already in the repository* but was quarantined back in Stage 0."
> `docs/stage5executionplan.md` §4.1 "Component map".

### 1.1 Decision

Un-quarantine in this order:

| Phase | Package | Rationale |
|---|---|---|
| **1st** | `partner-issuer-sim` | Opens the partner-federation revenue conversation. Security teams reviewing DID-based token acceptance will ask for a reference simulator first; shipping the simulator simultaneously with the resolver hardening removes the "can we test this end-to-end?" objection. |
| **2nd** | `posture-emitter` | Required for SOC2 evidence export (Task 6). The `DurablePostureEmitter` is the gateway shim's dependency; it must be stable before the export endpoint is built. |
| **3rd (parallel)** | `db-token-service` | No sequencing dependency on `posture-emitter`; can start immediately after Task 4. |
| **3rd (parallel)** | `storage-grant-service` | Same phase as `db-token-service`; both services share the same gateway verifier integration pattern. |

### 1.2 Rationale

The ordering follows the expected security-review conversation sequence:

1. **DID federation first.** The enterprise CISO conversation typically begins with
   "how do we trust tokens from our own issuer?" — the `partner-issuer-sim` directly
   answers that. It must be production-ready before the partner trust registry is
   promoted (Task 3).
2. **Audit evidence second.** After DID federation is cleared, the next CISO question
   is "where is the tamper-evident audit trail?" — `posture-emitter` powers that
   answer via the SOC2 export endpoint. It must be stable before Task 6.
3. **Data-service grants in parallel.** The `db-token-service` and
   `storage-grant-service` are operationally independent; they both exchange a
   capability token for a short-lived service credential and both depend only on the
   gateway verifier path, which is unchanged in Stage 5. Parallel un-quarantine is
   safe.

### 1.3 Un-quarantine procedure (applies to all four packages)

For each package:

1. Remove the `STATUS.md` quarantine notice; replace with `CHANGELOG.md` entry
   marking the `1.0.0` milestone and the date.
2. Verify CI (`npm test`) is green in the package's own test suite.
3. Add the package to the `full` docker-compose profile (`infra/docker-compose.yml`).
4. Confirm the package builds cleanly in the workspace root (`npm run build`).
5. Add the integration test listed in `docs/stage5executionplan.md` for the package.

No NOTICE changes are required for the quarantine removal itself; the packages were
already listed in `NOTICE` at their initial BSL check-in. Each new feature added
during Stage 5 polish must add a NOTICE entry per §7.8 of
`docs/stage5executionplan.md`.

---

## 2. SCIM Group-to-Role Mapping Contract

> **MVP anchor:** `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" (line 775) —
> "SSO with SCIM". `docs/stage5executionplan.md` §4.8 "SCIM 2.0 provisioning".

### 2.1 Decision

**`ISSUER_SCIM_GROUP_ROLE_MAP` — static JSON environment variable (v1).**

The SCIM group-to-role mapping is configured via a single JSON env var:

```
ISSUER_SCIM_GROUP_ROLE_MAP='{"engineering":"developer","product":"reader"}'
```

> **Note:** Mapping a SCIM group to the `operator` role (e.g.
> `"security-ops":"operator"`) is rejected at boot unless
> `ISSUER_SCIM_ALLOW_OPERATOR_ROLE_MAPPING=true` is also set — see §2.3.
> The example above intentionally omits an `operator` mapping to avoid
> operators copy-pasting an invalid default configuration.

The key is the SCIM group `displayName` (case-sensitive); the value is a role key
present in the issuer's `RoleCapabilityPolicy` (i.e. a key in
`DEFAULT_ROLE_CAPABILITY_MAP` or a custom role defined in the operator's
role-policy file).

An admin-API-managed mapping table is **explicitly deferred** to a post-Stage-5
iteration.

### 2.2 Rationale

| Dimension | Env-var (v1 — chosen) | Admin-API-managed table |
|---|---|---|
| Operational surface | Minimal — config change requires a deploy, which is the existing operator change-management workflow for secrets | Adds a new admin endpoint, a new Postgres table, a new migration, and a new test surface |
| Security review time | Zero new auth surface; the existing `IssuerConfigSchema` validation catches malformed JSON at boot | New admin endpoint must be reviewed against SCIM privilege-escalation threat (§5 of the execution plan) |
| Audit trail | Mapping change is a deploy event, already in the operator's change log | Requires per-mapping-change audit events in the issuer (new work) |
| Flexibility | Sufficient for v1 — enterprise IdP teams can update via Terraform/Helm values; mapping changes do not require code changes | Necessary if mapping must change at runtime without a deploy |
| Stage 5 threat model constraint | Simpler to reason about in `docs/security/enterprise-federation-threat-model.md` §"SCIM privilege escalation": no dynamic mapping means no runtime escalation vector | Dynamic mapping introduces a runtime escalation path that requires the approval workflow described in the threat model |

The admin-API-managed table will be the right investment once a named customer reports
that the env-var approach requires too many deploys. The seam for it already exists —
`IssueController.handleFromUserContext()` calls `getScimGroupMemberships()` (Task 10
addition); migrating the lookup to a DB-backed map is a single-function change.

### 2.3 Constraint: no `operator` role via SCIM without explicit approval

Per `docs/stage5executionplan.md` §5 ("SCIM privilege escalation"):

> The `ISSUER_SCIM_GROUP_ROLE_MAP` must not permit mapping a SCIM group to `operator`
> without explicit operator-JWT authorization for that mapping.

Implementation: `IssuerConfigSchema` validates `ISSUER_SCIM_GROUP_ROLE_MAP` at boot
time and rejects any entry whose value is `operator` unless the
`ISSUER_SCIM_ALLOW_OPERATOR_ROLE_MAPPING=true` flag is also set (defaulting to `false`).
This flag is documented as a deliberate escape hatch; operators who use it must
acknowledge in their security posture that SCIM group membership can elevate to
`operator` without a deploy-time review step.

---

## 3. Helm Chart Dependency Strategy

> **MVP anchor:** `docs/stage5executionplan.md` §4.9 "On-prem deployment bundle
> (Task 11)"; `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" (line 774) — "on-prem
> deployment".

### 3.1 Decision

**External operator-provisioned Postgres and Redis are the default for the `k8s/helm/euno/` chart. Bitnami subcharts are included but disabled by default.**

Helm chart `values.yaml` default:

```yaml
postgresql:
  enabled: false   # set to true only for quick evaluation / CI
  auth:
    existingSecret: ""

redis:
  enabled: false   # set to true only for quick evaluation / CI
  auth:
    existingSecret: ""
```

When `enabled: false`, the chart requires the operator to supply:
- `POSTGRES_URL` (or individual `POSTGRES_HOST`, `POSTGRES_PORT`, etc.) via a
  Kubernetes `Secret` referenced in `envFrom`.
- `REDIS_URL` via the same or a separate `Secret`.

The chart documents a recipe for AWS RDS, Azure Database for PostgreSQL Flexible Server,
and GCP Cloud SQL in `docs/DEPLOYMENT.md` §"Stage 5 on-prem deployment".

### 3.2 Rationale

| Dimension | External (chosen) | Bitnami enabled by default |
|---|---|---|
| Enterprise production posture | Enterprises run managed DB services (RDS, Azure DB, Cloud SQL) with their own HA, backup, and compliance requirements; embedding a stateful DB operator in the chart creates an unsupported operational surface | Bitnami PG/Redis are suitable for demos but require separate HA tuning for production |
| Helm chart complexity | Chart contains no stateful workloads; upgrade and rollback are purely stateless | Bitnami subchart lifecycle (PVC management, version lock) increases chart maintenance overhead |
| Security baseline | All DB credentials live in operator-managed Kubernetes Secrets (or external secret managers via External Secrets Operator); no risk of default passwords | Bitnami auto-generates passwords into Helm-managed Secrets; operators frequently forget to rotate them |
| Quick-evaluation path | `enabled: true` on both subcharts gives a single-command `helm install` demo; this is still documented as the non-production path | Already the default |
| CI smoke testing | CI uses `enabled: true` for the smoke compose profile; the Helm chart CI test (Task 11) uses `enabled: true` for Kubernetes validation | Same |

### 3.3 Bitnami subchart versions (pinned at chart authoring time)

| Subchart | Version | Notes |
|---|---|---|
| `bitnami/postgresql` | 15.x (latest stable at Task 11) | Pin the minor version in `Chart.yaml`; bump with Dependabot |
| `bitnami/redis` | 19.x (latest stable at Task 11) | Same pinning strategy |

The pinned versions are validated against CVE advisories before the initial chart
release (Task 11) and rechecked on every Dependabot PR.

---

## 4. `did:ion` Resolver SLA Decision

> **MVP anchor:** `docs/stage5executionplan.md` §4.10 "`did:ion` productionization
> (Task 12)"; `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" (lines 771–772) —
> "W3C DID (`did:web`, `did:ion`, `did:key`)".

### 4.1 Decision

**Hosted Microsoft ION is the default resolver with a `RedisCircuitBreaker` wrapper.
A bundled sidecar recipe for air-gapped deployments is documented but not shipped
as a container image.**

Configuration:

```
# Default (hosted):
ION_RESOLVER_URL=https://ion.msidentity.com/api/v1.0/identifiers

# Air-gapped (documented recipe, operator-managed):
ION_RESOLVER_URL=https://ion.internal.corp.example.com/api/v1.0/identifiers
```

The `ION_RESOLVER_URL` env var is part of issuer configuration (see
`pkg/config/issuer.go`). Stage 5 promotes it to a documented,
operator-facing configuration point.

### 4.2 Rationale

| Dimension | Hosted ION (chosen) | Bundled sidecar image |
|---|---|---|
| Maintenance | Microsoft maintains the hosted resolver SLA; no euno ops burden | Operator must provision and maintain an ION node (Bitcoin full node + IPFS + ION service; ~100 GB storage) |
| Enterprise air-gap concern | Addressed by circuit breaker: if resolver is unreachable, `did:ion` resolution fails closed (partner-issued tokens using `did:ion` DIDs are denied), which is safer than an unknown trust state | Required for strict no-egress environments, but the documentation recipe covers this without euno shipping a container |
| Time-to-value | Ops-free for the majority of deployments; the hosted resolver handles most enterprise evaluations | Significant operator effort before a demo is possible |
| Stage 5 risk | Circuit breaker (Task 12) already protects against hosted outages; SLA is documented as "best-effort, not contractual" in `docs/issuer-idp-setup.md` | Ships new container image with its own CVE surface |
| Air-gap path forward | `docs/DEPLOYMENT.md` §"Stage 5 on-prem" will document the open-source ION sidecar setup (bitcoin + IPFS + `decentralized-identity/ion` Docker image); operators follow those steps; euno does not ship or support the sidecar | euno would own the image |

### 4.3 Circuit-breaker configuration (Task 12 additions to `IssuerConfigSchema`)

New env vars added in Task 12:

| Env var | Default | Meaning |
|---|---|---|
| `ION_CB_FAILURE_THRESHOLD` | `5` | Consecutive failures before the circuit opens |
| `ION_CB_COOLDOWN_SECONDS` | `60` | Duration the circuit stays open before attempting a half-open probe |

Both follow the naming pattern of `PARTNER_DID_CB_FAILURE_THRESHOLD` and
`PARTNER_DID_CB_COOLDOWN_SECONDS` already in `GatewayConfigSchema`.

### 4.4 Health check

A new `GET /healthz/did-ion` endpoint (Task 12) resolves a known stable ION document
(`did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7iCCg`) and returns
`{ status: "ok" | "degraded" }`. When the circuit is open the endpoint returns
`{ status: "degraded" }` immediately (no network call). The existing
`GET /healthz` composite endpoint will include this check's result.

---

## 5. `@euno/common-core` Seam Additions

> **MVP anchor:** `docs/stage5executionplan.md` §4.6 "AGT in-process guard adapter
> (Task 8)" — "Types land in `@euno/common-core`".
> `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" (line 776) —
> "AGT-style in-process guard for defense-in-depth".

### 5.1 Decision

**Three new types, nothing else.**

| Type | Module | Description |
|---|---|---|
| `AgtGuardOptions` | `internal/agentruntime` (`internal/agentruntime/types.go`) | Runtime construction options and related types |
| `AgtGuardResult` | same | Verdict returned by an in-process guard evaluation (`'allow' \| 'deny'`) |
| `AgtGuardDenyReason` | same | Reason codes passed to `AgtGuardOptions.onDeny` |

These types are implemented and exported in this PR (Task 0). Tests for the runtime
guard path are under `internal/agentruntime/`.

The guard/runtime implementation lives in the **BSL-licensed**
`internal/agentruntime/` package.

### 5.2 Type definitions (canonical)

```typescript
/** Structured reason codes for in-process guard denials. */
export type AgtGuardDenyReason =
  | 'capability_not_found'
  | 'constraint_violated'
  | 'policy_evaluation_error';

/** Verdict from an in-process guard evaluation. */
export type AgtGuardResult = 'allow' | 'deny';

/** Construction options for createAgtGuard() in agent-runtime. */
export interface AgtGuardOptions {
  tokenSupplier: () => string | Promise<string>;
  policy: AgentCapabilityManifest;
  onDeny?: (toolName: string, reason: AgtGuardDenyReason) => void;
  onGatewayDeny?: (toolName: string, gatewayErrorCode: string) => void;
}
```

### 5.3 License boundary

These three types are Apache-2.0 (`pkg//`). All other Stage-5
types are extensions of existing `@euno/common-core` types and do not require new
seam additions. The Stage 0 Substage 0.4 CI dependency-direction gate enforces that
BSL packages import from `@euno/common-core`, never the reverse.

### 5.4 No additional seam additions expected

All other Stage-5 concepts reuse existing seams:

| Stage-5 concept | Existing seam used | Location |
|---|---|---|
| Partner DID resolution | `PartnerIssuerResolver`, `PartnerDidRegistry` | `tool-gateway` (BSL) |
| Cross-chain anchor | `CrossChainAnchor`, `SignedCrossChainCommitment` | `@euno/common` / `tool-gateway` |
| Posture emitter plugin | `PostureEmitterPlugin`, `AgentInventoryRecord` | `@euno/common` |
| SCIM user/group store | Postgres-backed tables, issuer-local types | `capability-issuer` (BSL) |
| SOC2 export response | `SignedAuditEvidence` (existing wire type) | `@euno/common-core` |
| DB token exchange | `DbTokenServiceConfigSchema` (existing) | `@euno/common` |
| Storage grant exchange | `StorageGrantServiceConfigSchema` (existing) | `@euno/common` |

If a gap is identified during Tasks 2–13 implementation, the task author must raise
the gap as a PR comment against this document and obtain sign-off from the Task 0 RFC
authors before adding any new type to `@euno/common-core`. The CI gate will catch
accidental cross-license additions.

---

## 6. Cross-Links to `docs/mvp.md` Stage 5 Anchors

| Decision | `docs/mvp.md` anchor |
|---|---|
| Quarantine removal — partner federation first | §"Stage 5: Enterprise + Full Vision" lines 784–788 |
| Quarantine removal — posture emitter second | §"Stage 5: Enterprise + Full Vision" line 776 — "SOC2 audit-trail export" |
| Quarantine removal — DB + storage in parallel | §"Stage 5: Enterprise + Full Vision" lines 773–774 |
| SCIM group-to-role via env var (v1) | §"Stage 5: Enterprise + Full Vision" line 775; §"Pricing" line 844 — "SCIM" |
| Helm chart — external Postgres/Redis by default | §"Stage 5: Enterprise + Full Vision" line 774 — "on-prem deployment" |
| `did:ion` — hosted with circuit breaker | §"Stage 5: Enterprise + Full Vision" lines 771–772 |
| `@euno/common-core` additions — three types only | `docs/stage5executionplan.md` §4.6, §"Cross-cutting obligations" §1–2 |
| No additional seam types | `docs/stage5executionplan.md` §"Cross-cutting obligations" §2 |
| License boundary Apache-2.0 / BSL | `docs/stage5executionplan.md` §"Cross-cutting obligations" §5 |

---

## 7. Review Checklist

Sign-off requires ≥2 engineers + 1 security reviewer outside the implementer.
Each reviewer should verify:

- [ ] **§1 (Quarantine order):** Priority sequence is consistent with the expected
  CISO conversation sequence; no sequencing dependency is violated.
- [ ] **§2 (SCIM mapping):** Env-var approach is sufficient for v1; the
  `ISSUER_SCIM_ALLOW_OPERATOR_ROLE_MAPPING` escape-hatch constraint is present and
  will be enforced in `IssuerConfigSchema`.
- [ ] **§3 (Helm strategy):** External-by-default aligns with enterprise production
  posture; the quick-evaluation path via `enabled: true` is documented and not the
  default.
- [ ] **§4 (`did:ion`):** Circuit-breaker parameters are consistent with
  `PARTNER_DID_CB_*` naming already in `GatewayConfigSchema`; air-gap recipe is
  documented without introducing a new euno-owned container image.
- [ ] **§5 (Seam additions):** Exactly three new types confirmed; all are Apache-2.0;
  gap-escalation procedure is documented; CI dependency gate is referenced.
- [ ] **Threat model gate:** `docs/security/enterprise-federation-threat-model.md`
  (Task 1 — placeholder exists; full document to be completed in Task 1) must be
  approved before Tasks 3, 6, or 10 merge. This RFC does not substitute for the
  threat model.
- [ ] **`@euno/common-core` tests green:** `npm test` in `pkg/`
  passes with the three new type tests.

| Reviewer | Role | Date | Notes |
|---|---|---|---|
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Security | _(date)_ | |

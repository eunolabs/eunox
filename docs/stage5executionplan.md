# Stage 5 Execution Plan — "Enterprise + Full Vision"

**Source.** `docs/mvp.md` § "Stage 5: Enterprise + Full Vision" (lines 769–790),
§ "Gate to Stage 5 — measurable" (lines 762–766), § "Pricing & business model
sketch" (lines 822–845), and the quarantined-package policy in
§ "Stage 0" (lines 200–216). Cross-references: `docs/diagrams.md` Set D
(AGT integration), `docs/stage-4-design.md`, and
`euno-platform/packages/{partner-issuer-sim,db-token-service,storage-grant-service,posture-emitter}/STATUS.md`.

**Predecessor status.** Stage 4 is complete (Tasks 0–13 in `docs/mvp.md`
§ "Stage 4" are all checked off). The capability issuer with enterprise-IdP
SSO (Entra ID + AWS Cognito), KMS-signed manifest templates, the issuer admin
UI, the cross-stage parity test suite, and the Stage-5 readiness signal are
all live. Stage 5 builds on the entire Stage 1–4 service plane; no component
is rewritten.

**Stage-5 thesis (preserve when assigning tasks).** Stage 4 converted an
individual developer's grassroots pull into an engineering-org procurement
conversation. Stage 5 converts that procurement conversation into a
compliance-signed contract. The buyer is no longer the tech lead — it is the
CISO and the external auditor. The signal that Stage 5 has begun
(`scripts/stage5-readiness.ts` exits 0) is that an enterprise inbound
has asked about compliance, on-prem, or "our CISO needs to review this." Every
decision below should be read against that buyer profile.

The strong signal that Stage 5 has been completed successfully:
a customer asks for a feature that is *already in the repository* — the
`partner-issuer-sim`, `db-token-service`, `storage-grant-service`, or the
cross-chain anchor — having never been told it was quarantined. That is the
moment to un-quarantine, polish, and ship.

---

## 1. Goal

Promote the four quarantined packages and the five undocumented
enterprise features from "design-partner driven, not on the roadmap" to
**production-ready, contractually supportable, documented enterprise
capabilities**, such that:

1. A partner organization can issue capability tokens from their own W3C
   DID-backed issuer and have those tokens accepted and cryptographically
   verified by the euno gateway — without sharing keys — using the
   **partner-federation trust model** (`partner-issuer-resolver.ts` +
   un-quarantined `partner-issuer-sim`).

2. Every gateway audit event is anchored to an **immutable, cross-chain
   tamper-evident log** (the `CrossChainAnchor` + Azure Confidential Ledger
   or `PerReplicaPostgresLedgerBackend` — both already in the codebase)
   and is exportable as a **SOC2-scoped OCSF evidence bundle** via a
   documented, authenticated export endpoint (built on the un-quarantined
   `posture-emitter` / `DurablePostureEmitter`).

3. A database-backed service (`db-token-service`) issues short-lived
   database credentials scoped to the agent's current capability set, and
   a storage-grant service (`storage-grant-service`) issues short-lived
   blob/bucket grants — both verified by the same gateway verifier and
   audited by the same pipeline.

4. An AGT-style **in-process policy guard** can be wired into the agent
   runtime (`agent-runtime`) as a defense-in-depth inner guard (as shown
   in `docs/diagrams.md` Set D), so the architecture satisfies "layered
   enforcement" requirements raised by security teams.

5. The platform ships with a **production-grade on-prem deployment bundle**
   (Kubernetes manifests, Helm chart, air-gap image registry guide, and a
   restricted-network deployment runbook) that lets a self-hosting enterprise
   run the complete stack inside their own VPC or private cloud with zero
   outbound traffic.

6. **SCIM 2.0 user/group provisioning** is supported on the capability
   issuer so enterprise identity teams can push users and group memberships
   directly from Okta, Entra ID, or Ping Identity, eliminating manual role
   assignment.

7. The `/.well-known/capability-issuer` discovery endpoint is **promoted
   to a documented, stable contract** (currently implemented but not
   published as an enterprise integration point), and `did:ion` resolution
   is productionized with a documented SLA-backed resolver configuration.

8. All Stage-5 features ship in **both** the hosted product and the
   self-host bundle, at parity, with the same compliance evidence
   guarantees. No hosted-only capabilities.

### Non-goals (explicit)

- **Python SDK.** Stage 5 does not introduce a Python SDK; telemetry data
  from Stage 4 must show clear Python usage before that investment is made.
- **Blockchain consensus.** The cross-chain anchor is a tamper-evident hash
  chain across multiple storage backends (Postgres replicas + Azure
  Confidential Ledger). It is not a public-chain smart contract and does
  not introduce a consensus dependency.
- **Visual policy editor UX.** Stage 5 surfaces the manifest-template
  admin API and the SCIM-provisioned role model. A graphical drag-and-drop
  policy editor is a future investment post-Stage-5.
- **Managed multi-tenancy as a hyperscaler service.** The BSL license
  explicitly prevents a competing hyperscaler launch. Stage 5 does not
  change the license or add capabilities that weaken that protection.
- **AGT SDK distribution.** Stage 5 wires the existing
  `InProcessToolTransport` / `InProcessProxyHandler` (already in
  `agent-runtime`) into a documented AGT adapter. It does not ship a
  separate AGT SDK npm package.

---

## 2. Exit Criteria (Stage 5 is "shipped" when ALL are true)

**E1.** **Tasks 0–14 below are all checked off** in a `> **Stage 5 status**`
block added to `docs/mvp.md` § "Stage 5", in the same format used for Stages
1–4.

**E2.** **Partner federation works end-to-end in the hosted product**: an
operator can register a partner DID, the partner issues a JWT from their
own simulated or real issuer, and the gateway accepts and audits the token.
The `partner-issuer-sim` docker image builds and runs as a standalone
reference. Integration test coverage in
`euno-platform/packages/integration-tests/` covers the full cross-org
round-trip including a circuit-breaker open/close cycle.

**E3.** **SOC2 audit-trail export is live**: a `GET /api/v1/audit/export`
endpoint (new, authenticated with the admin operator-JWT pattern from Stage
4) returns a paginated OCSF evidence bundle that a compliance team can hand
to an auditor. The `DurablePostureEmitter` from `posture-emitter` is wired
into the gateway's issuance audit pipeline. Every signed evidence record is
verifiable offline with the issuer's public JWKS.

**E4.** **Cross-chain audit anchor is documented and demonstrably active**:
`AUDIT_LEDGER_BACKEND=per-replica-postgres` + `ENABLE_CROSS_CHAIN_ANCHOR=true`
produces a hash chain whose integrity is verifiable by the existing
`GET /api/v1/audit/records` query endpoint plus a new
`GET /api/v1/audit/chain-proof` endpoint (new, see Task 5). Azure Confidential
Ledger integration is documented as an alternative. The `CrossChainAnchor`
goes from internal wiring to a first-class operator-facing feature.

**E5.** **`db-token-service` and `storage-grant-service` are production-ready
and documented**: both services build, have ≥85% branch coverage, are
described in `docs/self-host.md` §"Stage 5 service extensions", and are
included in the `full` docker-compose profile. An integration test in
`euno-platform/packages/integration-tests/` demonstrates a round-trip
(issue capability token → exchange for DB credential → use credential →
credential expires after capability TTL).

**E6.** **On-prem deployment bundle ships**: `k8s/` has production-ready
Helm chart values files, an air-gap image list, and a `docs/DEPLOYMENT.md`
Stage-5 section covering the restricted-network checklist. The
`infra/docker-compose.yml` `full` profile includes all Stage-5 services.
A single-command `helm install euno ./k8s/helm/euno` on a vanilla cluster
with only a Postgres and Redis dependency produces a running stack.

**E7.** **AGT in-process guard adapter is documented and tested**:
`euno-platform/packages/agent-runtime/` exposes `createAgtGuard()` (new)
which wires a capability-check hook into the LLM reasoning loop via the
`InProcessToolTransport`. The integration matches the architecture in
`docs/diagrams.md` Set D. At least one integration test uses the guard
to block a tool call that the outer gateway would have allowed (defense-
in-depth scenario).

**E8.** **SCIM 2.0 provisioning endpoint is live**: the capability issuer
exposes `/scim/v2/Users` and `/scim/v2/Groups` endpoints (authenticated
via the existing `ISSUER_ADMIN_JWKS_URI` operator-JWT path). A user pushed
via SCIM is queryable via the issuer admin API and its SCIM-provisioned
group membership is honored by the role-to-capability policy. Integration
test covers push → issuance → capability reflects group membership.

**E9.** **`/.well-known/capability-issuer` is a stable, documented contract**:
the discovery document is versioned (`schemaVersion: "1.0.0"`), covers all
Stage-5 endpoint extensions, and is the authoritative integration point for
security teams and partner issuers. The gateway can consume it to
auto-configure partner trust (bootstrap shortcut for E2).

**E10.** **Schema parity invariants still hold** (all exit criteria from
Stage 4 §E8 continue to be true). No net-new types appear outside
`@euno/common-core`. CI dependency-direction gate (Stage 0 Substage 0.4)
is green on every Stage-5 PR.

**E11.** **`did:ion` resolution is productionized**: `DID_ION_RESOLVER_URL`
is a documented env var with a default pointing to the hosted ION resolver.
A fallback health-check and circuit breaker are in place (reuse
`RedisCircuitBreaker` from `@euno/common`). Docs include how to run a
private ION node for air-gapped deployments.

**E12.** **Enterprise threat model addendum is reviewed and signed off**
(`docs/security/enterprise-federation-threat-model.md`), covering all
questions in § 5 of this document. No partner-federation or SCIM code
merges to `main` before this is approved.

---

## 3. Test Coverage Requirements

The same discipline from Stages 3 and 4 applies across all Stage-5 tasks.
For every task the PR must add:

1. **Unit tests** in the owning package's `tests/` (or `src/__tests__/`)
   directory, colocated with the changed source.
2. **An integration test** in `euno-platform/packages/integration-tests/`
   for every cross-process or network boundary (partner issuer ↔ gateway,
   SCIM push ↔ issuance, DB service ↔ gateway, posture emitter ↔ export
   endpoint).
3. **A cross-stage parity test entry** (in
   `euno-platform/packages/integration-tests/tests/cross-stage-parity.test.ts`)
   whenever the change touches token shape, audit shape, or policy shape.
   Stage-5 tokens (partner-issued) must produce identical gateway decisions
   as Stage-4 tokens for the same manifest — the **only** structural
   difference is `iss` pointing to the partner DID.
4. **A negative test** proving fail-closed behaviour:
   - partner DID not in trust registry → deny
   - circuit breaker open for partner DID → deny (no silent fall-through)
   - SCIM group removed → next issuance reflects reduced capabilities
   - DB credential TTL expired → DB access denied
   - Cross-chain anchor hash mismatch → audit verification failure (not
     silenced)
   - AGT guard blocks → gateway still logs the attempt
5. **A schema-version backward-compat test**: an old client presenting a
   Stage-4 token to a Stage-5 gateway must receive the documented error
   class (if the token is outside the supported window), not a 500.

Aggregate coverage targets (measured on changed lines):

| Package | Line | Branch |
|---|---|---|
| `partner-issuer-sim` (un-quarantined) | ≥ 90 % | ≥ 85 % |
| `db-token-service` (un-quarantined) | ≥ 90 % | ≥ 85 % |
| `storage-grant-service` (un-quarantined) | ≥ 90 % | ≥ 85 % |
| `posture-emitter` (un-quarantined) | ≥ 90 % | ≥ 85 % |
| `tool-gateway` (cross-chain anchor, SCIM proxy) | ≥ 90 % | ≥ 85 % |
| `capability-issuer` (SCIM endpoints, discovery) | ≥ 90 % | ≥ 85 % |
| `agent-runtime` (AGT guard adapter) | ≥ 90 % | ≥ 85 % |

CI job order is unchanged: lint → typecheck → unit → integration → smoke
(docker-compose `smoke` profile). Stage-5 PRs that touch `infra/` or `k8s/`
must be smoke-tested locally before merge. The smoke profile is the gate.

---

## 4. Detailed Design

### 4.1 Component map

Stage 5 **un-quarantines four packages** and **adds six capabilities** to
existing packages. No new packages are created.

#### Un-quarantined packages

| Package | Current status | After Stage 5 |
|---|---|---|
| `euno-platform/packages/partner-issuer-sim` | Quarantined; simulates partner DID issuer | Production reference simulator + integration harness; first-class CI component |
| `euno-platform/packages/db-token-service` | Quarantined; DB credential issuance stub | Production service: exchanges capability token for scoped DB credentials; included in `full` compose profile |
| `euno-platform/packages/storage-grant-service` | Quarantined; storage grant stub | Production service: exchanges capability token for scoped blob/S3 grants; included in `full` compose profile |
| `euno-platform/packages/posture-emitter` | Quarantined; WAL-queue durable emitter | Production OCSF export pipeline: `DurablePostureEmitter` wired into gateway audit; powers the `GET /api/v1/audit/export` endpoint |

#### New capabilities in existing packages

| Package | New capability |
|---|---|
| `euno-platform/packages/tool-gateway` | Cross-chain anchor GA (`ENABLE_CROSS_CHAIN_ANCHOR`, `GET /api/v1/audit/chain-proof`); partner-federation documentation; per-DID circuit-breaker Prometheus metrics published |
| `euno-platform/packages/capability-issuer` | SCIM 2.0 endpoints (`/scim/v2/Users`, `/scim/v2/Groups`); `/.well-known/capability-issuer` promoted to stable v1.0.0 contract; `did:ion` circuit breaker + health-check |
| `euno-platform/packages/agent-runtime` | `createAgtGuard()` — in-process capability-check hook for defense-in-depth (Set D architecture) |
| `euno-platform/packages/integration-tests` | Cross-org federation suite; SOC2 export verification; AGT guard defense-in-depth scenario |
| `infra/` | `full` compose profile gains `db-token-service`, `storage-grant-service`, `posture-emitter`; smoke-test extended |
| `k8s/` | Helm chart (`k8s/helm/euno/`) covering all Stage-5 services; air-gap image list; restricted-network values file |

### 4.2 Partner federation (Task 3)

The implementation seam already exists:

- `euno-platform/packages/tool-gateway/src/partner-issuer-resolver.ts` —
  `PartnerIssuerResolver` with `PartnerDidRegistry`, per-DID
  `RedisCircuitBreaker`, negative-cache, and positive-cache TTL.
- `euno-platform/packages/tool-gateway/src/partner-did-registry.ts` —
  two-eyes registration workflow with optional pin attestation.
- `euno-platform/packages/capability-issuer/src/did-resolver.ts` —
  `resolveDID()` supporting `did:web`, `did:ion`, `did:key`.
- `euno-platform/packages/partner-issuer-sim/` — simulates the partner-org
  issuer end of the trust chain.

Stage-5 work is:

1. **Remove the `STATUS.md` quarantine gate** from `partner-issuer-sim` and
   replace it with a `CHANGELOG.md` entry marking the `1.0.0` milestone.
2. **Production-harden `PartnerIssuerResolver`**:
   - Expose per-DID circuit-breaker state as Prometheus gauge
     (`euno_partner_did_circuit_breaker_state{did="…", state="open|closed|half-open"}`)
     via the gateway's existing `/metrics` endpoint.
   - Add `PARTNER_DID_CACHE_TTL_MS` and `PARTNER_DID_NEGATIVE_CACHE_TTL_MS`
     env vars to `GatewayConfigSchema` (currently hard-coded defaults).
   - Add `PARTNER_DID_CIRCUIT_BREAKER_FAILURE_THRESHOLD` and
     `PARTNER_DID_CIRCUIT_BREAKER_RESET_TIMEOUT_MS` env vars.
3. **`/.well-known/capability-issuer` auto-bootstrap** (see § 4.7): a
   partner operator can supply a `PARTNER_ISSUER_DISCOVERY_URL` env var;
   the gateway fetches the discovery document at startup, extracts the
   partner's `did` and `jwks` fields, and auto-registers the partner in
   `PartnerDidRegistry`.
4. **Operator documentation**: `docs/ADAPTERS.md` §"Partner Federation" and
   the new `docs/self-host.md` §"Stage 5 partner trust" covering: DID
   registration workflow, pin attestation for production, circuit-breaker
   tuning, and revocation flow when a partner is off-boarded.
5. **Integration tests** in `integration-tests/tests/partner-federation.test.ts`:
   - Happy path: `partner-issuer-sim` issues a token → gateway accepts it.
   - Circuit-breaker trip: DID document returns 503 N times → gateway
     denies with `partner_did_resolution_failed`, circuit opens.
   - Circuit-breaker half-open probe: after reset timeout, next request
     probes and succeeds, circuit closes.
   - Un-trusted DID: token with `iss` not in registry → 401 immediately.
   - Pin mismatch: DID document returned but pin hash does not match →
     deny and increment `euno_partner_did_circuit_breaker_state`.

### 4.3 Cross-chain audit anchor GA (Task 5)

The `CrossChainAnchor` is already imported and used in
`audit-module.ts` and `bootstrap.ts`, but is not exposed as an
operator-facing feature — there is no documentation, no dedicated env var,
and no verification endpoint.

Stage-5 work:

1. **Env var promotion**: add `ENABLE_CROSS_CHAIN_ANCHOR=true/false`
   (default `false`) and `CROSS_CHAIN_ANCHOR_INTERVAL_MS` (default 60 000)
   to `GatewayConfigSchema`. When enabled with
   `AUDIT_LEDGER_BACKEND=per-replica-postgres`, the anchor is started
   automatically in `bootstrap.ts` — the current behavior is unchanged
   (wired only when `crossChainAnchorOverride` is supplied).
2. **Chain-proof endpoint**: `GET /api/v1/audit/chain-proof?since=<ISO>&until=<ISO>`
   returns a JSON object `{ commits: SignedBatchCommitment[], chainHead: string }`.
   The `SignedBatchCommitment` type already exists in `@euno/common`.
   Authentication: same admin operator-JWT as `GET /api/v1/audit/records`.
3. **Azure Confidential Ledger toggle**: add `AUDIT_LEDGER_BACKEND=azure-confidential`
   as a documented value (the `AzureConfidentialLedgerBackend` already exists
   in `audit-module.ts` but is not in `GatewayConfigSchema`). Document the
   Azure managed identity / service principal auth requirements.
4. **Operator docs**: `docs/issuer-operator-runbook.md` §"Cross-chain anchor"
   covering: what the anchor does, how to verify integrity offline, key
   rotation procedure (a HMAC secret already in `docs/security/ledger-hmac-rotation.md`),
   and alerting wiring (anchor lag gauge).
5. **Tests**:
   - Unit: `AuditModule` with `ENABLE_CROSS_CHAIN_ANCHOR=true` starts anchor
     and stops it on teardown.
   - Unit: `GET /api/v1/audit/chain-proof` returns `SignedBatchCommitment[]`
     matching inserted records.
   - Integration: full gateway round-trip with anchor enabled; call
     `GET /api/v1/audit/chain-proof`; verify the chain head is monotonically
     increasing across the session.

### 4.4 SOC2 audit-trail export (Task 6)

The `posture-emitter` package contains `DurablePostureEmitter` — a
WAL-mode SQLite durable queue that fans out to plugins asynchronously.
The `PostureEmitterPlugin` interface allows arbitrary consumers.

Stage-5 work:

1. **Un-quarantine `posture-emitter`**: remove the quarantine gate from
   `STATUS.md` and mark `1.0.0` stable.
2. **Wire `DurablePostureEmitter` into the gateway's audit pipeline**:
   add a `PostureEmitterPlugin` shim that converts `SignedAuditEvidence`
   (from the existing `onSigned` callback in `AuditPipeline`) into the
   `AgentInventoryRecord` shape consumed by the emitter. The shim lives in
   `tool-gateway/src/posture-emitter-plugin.ts`.
3. **OCSF export endpoint**: `GET /api/v1/audit/export` (paginated, cursor-
   based, authenticated via admin operator-JWT). Returns:
   ```json
   {
     "cursor": "...",
     "records": [ /* SignedAuditEvidence[] */ ],
     "verificationUri": "/.well-known/jwks.json"
   }
   ```
   Page size max: 1 000 records. Cursor is opaque (base64-encoded
   `{ lastRowId, expiresAt }`). Export cursor expires after 24 h.
4. **Compliance scope filter**: `?scope=soc2-cc6` query param (initial
   values: `soc2-cc6` = logical access controls; `soc2-cc7` = system
   operations; `all` = no filter). The filter maps to OCSF `class_uid`
   values and is documented in `docs/security/soc2-mapping.md` (new).
5. **Tests**: unit tests for `PostureEmitterPlugin` shim; route tests for
   `GET /api/v1/audit/export` including cursor pagination, auth rejection,
   and scope filtering; integration test that verifies a signed record can
   be offline-verified against the issuer's JWKS.

### 4.5 DB Token Service and Storage Grant Service GA (Task 7)

Both services already have full Express apps, typed config, and unit tests.
Stage-5 work is production-hardening, integration, and documentation — not
new feature code.

**`db-token-service`**:
1. Remove quarantine gate. Mark `1.0.0` stable.
2. Verify that all config fields are present in `GatewayConfigSchema` and
   `DbTokenServiceConfigSchema` (they are, per `public/packages/common/src/config/schema.ts`).
3. Add to `infra/docker-compose.yml` `full` profile with a `DB_URL` pointing
   to the compose Postgres.
4. Integration test (in `integration-tests/tests/db-token-service.test.ts`):
   - Issue a capability token via the issuer.
   - POST the token to `db-token-service /exchange` → receive short-lived
     DB credentials.
   - Credentials expire after the capability token TTL.
   - A capability token without a DB-scope constraint → 403.
5. Add `docs/self-host.md` §"Stage 5 — DB Token Service".

**`storage-grant-service`**:
1. Remove quarantine gate. Mark `1.0.0` stable.
2. Add to `infra/docker-compose.yml` `full` profile.
3. Integration test (in `integration-tests/tests/storage-grant-service.test.ts`):
   - Issue a capability token with a `storageGrant` constraint.
   - POST to `storage-grant-service /grant` → receive short-lived
     presigned URL or SAS token.
   - Grant is for the exact bucket/container in the constraint only.
4. Add `docs/self-host.md` §"Stage 5 — Storage Grant Service".

### 4.6 AGT in-process guard adapter (Task 8)

The `agent-runtime` package already exposes `InProcessToolTransport`
and `InProcessProxyHandler`. The diagrams in `docs/diagrams.md` Set D
(D1–D4) describe the complete integration.

Stage-5 work:

1. **`createAgtGuard(options: AgtGuardOptions): AgtGuard`** in
   `euno-platform/packages/agent-runtime/src/agt-guard.ts` (new file).
   `AgtGuardOptions`:
   ```typescript
   interface AgtGuardOptions {
     /** Capability token supplier (function or pre-loaded token). */
     tokenSupplier: () => string | Promise<string>;
     /** Policy to evaluate in-process (AgentCapabilityManifest). */
     policy: AgentCapabilityManifest;
     /** Called when the guard blocks a tool call (for logging). */
     onDeny?: (toolName: string, reason: string) => void;
   }
   ```
   `AgtGuard` wraps an `InProcessProxyHandler` and checks tool calls
   against the manifest's `requiredCapabilities` before forwarding them
   to the outer gateway. It is a soft guard only — it does **not** replace
   the gateway verifier. If the guard allows but the outer gateway denies,
   the denial is logged by the gateway as usual.

2. **Types land in `@euno/common-core`** (`public/packages/common/src/`):
   `AgtGuardOptions`, `AgtGuardResult` (`allow | deny`), `AgtGuardDenyReason`.
   These are Apache-2.0; the implementation in `agent-runtime` is BSL.

3. **Tests** in `euno-platform/packages/agent-runtime/tests/agt-guard.test.ts`:
   - Guard allows a tool call in scope → forwarded to transport.
   - Guard denies a tool call out of scope → `onDeny` called, transport
     not invoked.
   - Guard allows but gateway denies → gateway deny event is audited,
     guard allow event is separately recorded via `onDeny(…, 'gateway_denied')`.
   - Integration test: the full Set-D2 flow (guard → gateway → API).

4. **Documentation**: `docs/agent-sdk.md` §"AGT in-process guard" with
   architecture diagram reference to Set D in `docs/diagrams.md`, example
   wiring code, and the trade-off section ("why two guards?").

### 4.7 `/.well-known/capability-issuer` discovery v1.0.0 (Task 9)

The endpoint already exists at
`euno-platform/packages/capability-issuer/src/index.ts:1242`. It returns:

```json
{
  "issuer": "…",
  "jwks": "/.well-known/jwks.json",
  "didDocument": "/.well-known/did.json",
  …
}
```

Stage-5 work:

1. **Versioned schema**: add `"schemaVersion": "1.0.0"` to the response.
   Add new Stage-5 fields:
   ```json
   {
     "schemaVersion": "1.0.0",
     "partnerFederation": {
       "registrationEndpoint": "/api/v1/admin/partners",
       "discoveryParam": "?partnerDid="
     },
     "scim": {
       "baseUri": "/scim/v2"
     },
     "auditExport": {
       "endpoint": "/api/v1/audit/export",
       "chainProof": "/api/v1/audit/chain-proof"
     },
     "capabilities": ["partner-federation", "scim-provisioning", "cross-chain-anchor", "db-token-service", "storage-grant-service"]
   }
   ```
2. **Stability contract**: add an `ETag` header (hash of the response body)
   and `Cache-Control: max-age=300`. Document the stability contract:
   fields present in `1.0.0` will not be removed before `2.0.0`.
3. **Gateway auto-bootstrap shortcut** (referenced in § 4.2): when
   `PARTNER_ISSUER_DISCOVERY_URL` is set, the gateway fetches the discovery
   document and uses `partnerFederation.registrationEndpoint` to
   auto-register the partner.
4. **OpenAPI spec**: add the endpoint to `docs/openapi/` (new YAML file
   `docs/openapi/capability-issuer-discovery.yaml`) with the full schema.
5. **Tests**: GET `/. well-known/capability-issuer` returns `schemaVersion`
   field; caching headers are correct; `ETag` changes when JWKS rotates.

### 4.8 SCIM 2.0 provisioning (Task 10)

The capability issuer already stores per-user issuance records and per-tenant
role assignments. SCIM provisioning replaces manual role assignments with
push-based group memberships from the enterprise IdP.

Endpoints (mounted at `/scim/v2/` in the issuer's Express process):

```
POST   /scim/v2/Users              — provision a new user
GET    /scim/v2/Users?filter=…     — search users (SCIM filter syntax)
GET    /scim/v2/Users/:id          — fetch user
PUT    /scim/v2/Users/:id          — replace user
PATCH  /scim/v2/Users/:id          — update user attributes or active status
DELETE /scim/v2/Users/:id          — deprovision user (soft-delete)

POST   /scim/v2/Groups             — provision a new group
GET    /scim/v2/Groups?filter=…    — search groups
GET    /scim/v2/Groups/:id         — fetch group
PUT    /scim/v2/Groups/:id         — replace group (full membership)
PATCH  /scim/v2/Groups/:id         — update membership delta
DELETE /scim/v2/Groups/:id         — remove group
```

Design constraints:

1. **SCIM bearer token** is a static secret (`ISSUER_SCIM_BEARER_TOKEN`)
   validated with constant-time comparison. This is the IdP's outbound
   credential, separate from the admin operator-JWT. Add to
   `IssuerConfigSchema`.
2. **Group → role mapping** is configured in the issuer's role policy
   (`RoleCapabilityPolicy`). A SCIM group name maps to a role key.
   Mapping lives in `ISSUER_SCIM_GROUP_ROLE_MAP` (JSON env var or file).
3. **Issuance uses SCIM group membership**: when a user authenticates via
   IdP, `IssueController.handleFromUserContext()` additionally queries the
   SCIM user record for the caller's group memberships and merges them
   with the IdP-provided roles. SCIM groups take precedence on conflict
   (IdP claims are the primary authentication signal; SCIM groups are the
   authoritative authorization model).
4. **SCIM store**: Postgres table `scim_users` + `scim_groups` +
   `scim_group_members`. Migrations live alongside the existing issuer
   migrations in `src/migrations/`.
5. **Idempotency**: `PUT` and `PATCH` are idempotent; re-provisioning the
   same user produces the same user record.

Tests:

- Push a user via SCIM → user appears in issuance with the mapped role.
- Remove user from SCIM group → next issuance reflects reduced capabilities.
- PATCH group membership → issuance capability set updated within 30 s
  (the next issuance, since tokens are short-lived).
- SCIM bearer token wrong → 401 with `WWW-Authenticate: Bearer realm="SCIM"`.
- SCIM filter query → returns matching users only.

### 4.9 On-prem deployment bundle (Task 11)

The `k8s/` directory already contains initial Kubernetes manifests.
Stage-5 work:

1. **Helm chart** at `k8s/helm/euno/` covering: `tool-gateway`,
   `capability-issuer`, `api-key-minter`, `db-token-service`,
   `storage-grant-service`, `posture-emitter`. External dependencies
   (Postgres, Redis) are declared as Helm subcharts (bitnami/postgresql,
   bitnami/redis) but disabled by default so self-hosters can supply
   their own.
2. **Air-gap image list** at `k8s/air-gap-images.txt`: all container
   images required for a full deployment, pinned by digest. Script
   `scripts/pull-air-gap-images.sh` to download and retag for a private
   registry.
3. **Restricted-network checklist** in `docs/DEPLOYMENT.md` §"Stage 5
   on-prem deployment": covers egress requirements (KMS endpoint URLs,
   ION resolver URL, optional telemetry), mTLS between services,
   network-policy templates for the Helm chart, and the
   `DID_WEB_ALLOW_HTTP_FOR_HOSTS` allowlist for self-hosted DID docs.
4. **`infra/docker-compose.yml` `full` profile update**: add
   `db-token-service`, `storage-grant-service`, `posture-emitter`.
5. **`infra/smoke-test.sh` update**: extend to cover issuance → DB
   credential exchange → storage grant round-trip.
6. **Docs**: `docs/DEPLOYMENT.md` §"Stage 5" + `docs/self-host.md`
   §"Stage 5 service extensions" (cross-linked).

### 4.10 `did:ion` productionization (Task 12)

The `resolveDidIon()` function exists in `capability-issuer/src/did-resolver.ts`.
It calls an external resolver but has no circuit breaker or health check.

Stage-5 work:

1. Add `DID_ION_CIRCUIT_BREAKER_FAILURE_THRESHOLD` and
   `DID_ION_CIRCUIT_BREAKER_RESET_TIMEOUT_MS` to `IssuerConfigSchema`.
   Wire a `RedisCircuitBreaker` (reuse from `@euno/common`) around
   `resolveDidIon()`.
2. Add `GET /healthz/did-ion` health check to the capability issuer:
   resolves `did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7iCCg`
   (a known ION document); returns `{ status: "ok" | "degraded" }`.
3. Add `DID_ION_RESOLVER_URL` to `IssuerConfigSchema` with default
   `https://discover.did.msidentity.com/1.0/identifiers/`. Document how
   to run a private Azure ION node or the open-source ION sidecar for
   air-gapped deployments.
4. Update `docs/issuer-idp-setup.md` §"DID-based partner issuers" with
   the `did:ion` configuration recipe.
5. Tests: circuit breaker opens after N failures; health check returns
   `degraded` when circuit is open; circuit closes after reset timeout.

---

## 5. Enterprise Threat Model Addendum (BLOCKING — Task 1)

A new document `docs/security/enterprise-federation-threat-model.md`
must be produced, reviewed, and signed off by ≥2 engineers + 1 security
reviewer outside the implementer before Tasks 3, 6, and 10 merge to `main`.

The following questions must be answered verbatim in that document:

| Question | Required answer |
|---|---|
| **Partner DID compromise** | If a partner's signing key is compromised, what capability tokens can an attacker mint? What is the blast radius across partner-issued sessions? What is the detection path (circuit breaker fires, Prometheus alert fires, admin is notified) and the revocation path (remove partner DID from registry → circuit breaker forces re-evaluation on next request)? |
| **DID document spoofing** | A `did:web` document is served over HTTPS. What happens if the partner's TLS certificate is MiTM'd or the domain is hijacked? Document the pin-attestation workflow (`verifyPinAttestation` in `partner-did-registry.ts`) and mandate its use for production partner registrations. |
| **SCIM bearer token exposure** | The `ISSUER_SCIM_BEARER_TOKEN` is a long-lived static secret. Document its required rotation cadence, storage (secret manager, not env file), and the consequence of exposure (all provisioned users/groups must be considered attacker-controlled until token is rotated). |
| **SCIM privilege escalation** | A SCIM push can assign a user to an admin group. Document the approval workflow required before a SCIM group is mapped to an elevated role (`admin`, `operator`). The `ISSUER_SCIM_GROUP_ROLE_MAP` must not permit mapping a SCIM group to `operator` without explicit operator-JWT authorization for that mapping. |
| **Cross-chain anchor tampering** | The cross-chain anchor's HMAC secret is already documented in `docs/security/ledger-hmac-rotation.md`. For Stage 5, document what an attacker who obtains the HMAC secret can do (forge commitments, not forge individual signed evidence records — the evidence is separately KMS-signed), and the impact of the Azure Confidential Ledger backend versus the per-replica-postgres backend. |
| **SOC2 export endpoint exposure** | The `GET /api/v1/audit/export` endpoint returns all signed audit evidence. Document the authorization model (admin operator-JWT, not user token), the rate limit, the cursor expiry (24 h), and the data-residency implications (no audit data leaves the on-prem deployment unless the operator explicitly calls the endpoint). |
| **DB credential blast radius** | If a `db-token-service`-issued credential is stolen, what DB access does the attacker have? Document the minimum-privilege DB role provisioned by the service, the credential TTL (must be ≤ capability token TTL), and the connection-level audit trail at the DB layer. |
| **In-process guard bypass** | The AGT guard is a soft guard. Document explicitly that an attacker who can modify the agent's in-process state can bypass the guard, and that the outer gateway is the only hard enforcement boundary. The threat model must not imply that the in-process guard is a security boundary. |
| **Air-gapped key management** | In an air-gapped on-prem deployment without an HSM, operators may use file-based EC keys. Document the required file permissions (`0400`), the key derivation procedure, the offline backup requirements, and the explicit statement that file-based keys are not supported for multi-tenant cloud deployments. |

Sign-off process: same as Stage 4 Task 1. No partner-federation code,
SCIM code, or SOC2 export code merges to `main` before this document is
approved.

---

## 6. Tasks

### Phase A — Pre-flight (gating; must complete before enterprise code ships)

#### Task 0 — Stage 5 design freeze & RFC

Author `docs/stage-5-design.md` capturing:

- The priority order of the four quarantined packages (recommend:
  `partner-issuer-sim` first, then `posture-emitter`, then
  `db-token-service` + `storage-grant-service` in parallel, based on
  the expected security-review conversation sequence: DID federation →
  audit evidence → DB/storage grants).
- The SCIM group-to-role mapping contract (static env var vs. admin-API-
  managed mapping table — recommend env var for v1 to minimize surface).
- The Helm chart dependency strategy (bitnami subcharts vs. external
  operator-provisioned Postgres/Redis — recommend external for enterprise,
  bitnami disabled by default for quick evaluation).
- The `did:ion` resolver SLA decision (hosted Microsoft ION vs. bundled
  sidecar for air-gap — document both, default to hosted with circuit
  breaker).
- Any `@euno/common-core` seam additions (expected: `AgtGuardOptions`,
  `AgtGuardResult`, `AgtGuardDenyReason` — three types only).
- Cross-link every decision back to `docs/mvp.md` Stage 5 anchors.

**Gate:** RFC reviewed and merged before Tasks 3+ start.

#### Task 1 — Enterprise federation threat model (BLOCKING per § 5)

Produce `docs/security/enterprise-federation-threat-model.md` answering
every question in § 5 verbatim. Reviewed and signed off by ≥2 engineers +
1 security reviewer outside the implementer.

**Gate:** No partner-federation code (Task 3), SCIM code (Task 10), or
SOC2 export code (Task 6) merges to `main` before this document is approved.

---

### Phase B — Foundation: quarantine removal + cross-chain

#### Task 2 — `did:ion` productionization

Per § 4.10. Circuit-breaker wrapping, health endpoint, env-var documentation,
and air-gap resolver recipe. No API surface changes outside the health
endpoint.

- **Tests**: circuit breaker unit test (5 cases); health endpoint test
  (3 cases); `resolveDidIon` with circuit open returns `CapabilityError`
  not an unhandled rejection.
- **Docs**: update `docs/issuer-idp-setup.md` §"DID-based partner issuers".

**Gate:** must be merged before Task 3 (partner federation) to ensure
`did:ion` DIDs in partner trust registrations are circuit-breaker protected.

#### Task 3 — Partner federation GA

Per § 4.2. Un-quarantine `partner-issuer-sim`, production-harden
`PartnerIssuerResolver`, add Prometheus metrics, add env vars to schema.

- **Tests**: `tests/partner-federation.test.ts` — 20+ cases covering
  happy path, circuit-breaker open/close cycle, un-trusted DID, pin
  mismatch.
- **Docs**: `docs/ADAPTERS.md` §"Partner Federation";
  `docs/self-host.md` §"Stage 5 partner trust".
- **STATUS.md** in `partner-issuer-sim`: replace quarantine notice with
  `1.0.0` stable marking.

#### Task 4 — `posture-emitter` un-quarantine + gateway wiring

Per § 4.4 (partial — just the emitter and the gateway shim; the export
endpoint comes in Task 6). Un-quarantine `posture-emitter`, wire
`DurablePostureEmitter` into the gateway's `onSigned` callback via
`PostureEmitterPlugin`.

- **Tests**: `PostureEmitterPlugin` shim unit test — 8 cases; integration
  test confirming a gateway enforcement event lands in the emitter's queue
  and is acknowledged.
- **STATUS.md** in `posture-emitter`: replace quarantine notice with
  `1.0.0` stable marking.

#### Task 5 — Cross-chain audit anchor GA

Per § 4.3. Env-var promotion, `GET /api/v1/audit/chain-proof` endpoint,
Azure Confidential Ledger documentation, anchor lag Prometheus gauge.

- **Tests**: 12 cases covering `ENABLE_CROSS_CHAIN_ANCHOR` start/stop,
  chain-proof endpoint, and offline-verification logic.
- **Docs**: `docs/issuer-operator-runbook.md` §"Cross-chain anchor".

---

### Phase C — SOC2 export + data services

#### Task 6 — SOC2 audit-trail export endpoint

Per § 4.4 (export endpoint). `GET /api/v1/audit/export` with cursor
pagination, compliance scope filter, OCSF response shape, and offline-
verification instructions.

- **Tests**: route tests (8 cases: pagination, auth, scope filter,
  cursor expiry); integration test that verifies signed record offline.
- **Docs**: `docs/security/soc2-mapping.md` (new); `docs/openapi/`
  addition for the export endpoint.

#### Task 7 — `db-token-service` + `storage-grant-service` GA

Per § 4.5. Remove quarantine gates, add to `full` compose profile,
add integration tests, add self-host docs.

- **Tests**: `tests/db-token-service.test.ts` (12 cases);
  `tests/storage-grant-service.test.ts` (10 cases).
- **Docs**: `docs/self-host.md` §"Stage 5 — DB Token Service" and
  §"Stage 5 — Storage Grant Service".

---

### Phase D — Enterprise integrations

#### Task 8 — AGT in-process guard adapter

Per § 4.6. `createAgtGuard()` in `agent-runtime`, types in
`@euno/common-core`, integration test covering Set-D2 flow.

- **Tests**: `tests/agt-guard.test.ts` (10 cases); integration test for
  Set-D2 architecture (guard + gateway dual-enforcement).
- **Docs**: `docs/agent-sdk.md` §"AGT in-process guard".

#### Task 9 — `/.well-known/capability-issuer` discovery v1.0.0

Per § 4.7. `schemaVersion`, Stage-5 fields, ETag, `Cache-Control`,
OpenAPI spec.

- **Tests**: 6 route tests.
- **Docs**: `docs/openapi/capability-issuer-discovery.yaml` (new).

#### Task 10 — SCIM 2.0 provisioning

Per § 4.8. SCIM endpoints, Postgres migrations, `ISSUER_SCIM_BEARER_TOKEN`
env var, group → role mapping, issuance integration.

- **Tests**: `tests/scim.test.ts` (25 cases: CRUD Users, CRUD Groups,
  auth, filter, issuance integration); migration test.
- **Docs**: `docs/issuer-idp-setup.md` §"SCIM provisioning" covering
  Okta, Entra ID, and Ping Identity setup recipes.

---

### Phase E — Infrastructure + parity

#### Task 11 — On-prem deployment bundle (Helm + air-gap)

Per § 4.9. Helm chart, air-gap image list, restricted-network checklist,
`full` compose profile update, smoke-test extension.

- **Tests**: smoke profile green in CI with all Stage-5 services.
- **Docs**: `docs/DEPLOYMENT.md` §"Stage 5 on-prem";
  `docs/self-host.md` §"Stage 5 service extensions".

#### Task 12 — Cross-stage parity extension (Stage 5 scenarios)

Extend `euno-platform/packages/integration-tests/tests/cross-stage-parity.test.ts`
with two Stage-5 scenarios:

1. A partner-issued token (from `partner-issuer-sim`) for the same
   `AgentCapabilityManifest` must produce the same gateway decision as a
   Stage-4 issuer-issued token. The only structural difference is `iss`
   pointing to the partner DID.
2. An agent that passes the AGT guard but is denied by the outer gateway
   results in exactly one denial audit entry (not two — the guard's
   allow is not a gateway decision, only the gateway's deny is audited).

- **Tests**: 8 new parity assertions.

#### Task 13 — `docs/self-host.md` Stage 5 consolidated section

Consolidate all Stage-5 self-host documentation into a single
§"Stage 5 — Enterprise Deployment" section in `docs/self-host.md`.
Cross-links to individual task docs. Covers: service topology diagram,
minimum viable air-gapped setup, compliance checklist (SOC2 controls
surfaced, DID federation checklist, SCIM provisioning checklist).

#### Task 14 — Stage 5 status block + reference materials

- Add `> **Stage 5 status**` block to `docs/mvp.md` §"Stage 5" with
  one bullet per task (Tasks 0–13) above. This is the last thing merged.
- Update `README.md` with a Stage-5 enterprise section.
- Update `public/packages/cli/README.md` with partner-federation and
  SOC2 export CLI references.
- Add `CHANGELOG.md` entries for all four un-quarantined packages.

---

## 7. Cross-cutting Obligations (apply to every task above)

These mirror Stage 4 §7 and are non-negotiable in Stage 5:

1. **Schema parity is non-negotiable** (`docs/mvp.md` §"Policy and audit
   schema parity"). Any change to policy or audit shape lands in
   `@euno/common-core` first, with a parity test added in the same PR.

2. **No Stage-5-only types outside `@euno/common-core`**. The three new
   AGT guard types are the only expected seam additions. All other Stage-5
   types must be extensions of existing `@euno/common-core` types.

3. **Fail-closed defaults**:
   - Partner DID not in registry → deny.
   - `did:ion` circuit breaker open → deny partner-issued token.
   - SCIM service unavailable → use last-known group memberships (TTL
     configurable, default 5 min; zero TTL = deny on SCIM outage).
   - Posture emitter queue full → log error, do not block gateway response.
   - Cross-chain anchor lag > threshold → alert, do not block gateway.
   - DB credential exchange failure → deny, do not return partial credential.

4. **Per-task PR contents**: unit tests, integration test exercising the
   new wire path, a README/section update, and CHANGELOG entries for
   every affected package.

5. **License boundary**: the four un-quarantined packages and all new
   gateway/issuer runtime code remain **BSL** under `euno-platform/packages/`.
   The three new `@euno/common-core` AGT guard types are **Apache-2.0**
   under `public/packages/`. CI dependency enforcement (Stage 0 Substage
   0.4) is the mechanical gate.

6. **Status tracking format**: mirror Stages 1–4 — add the
   `> **Stage 5 status**` block to `docs/mvp.md` and check items off as
   they land. Individual sub-tasks within a task may be tracked in the PR
   body but must roll up to a single task checkbox in `docs/mvp.md`.

7. **Stage 1–4 components are not modified** unless the task explicitly
   names them. The gateway verifier path, the minter mint path, the issuer
   IdP wiring, and the manifest template store are all out of scope for
   changes; they are only consumed.

8. **BSL commercial disclosure**: any new feature added to a BSL-licensed
   package must be accompanied by a `NOTICE` update listing the change
   date, consistent with the four-year Apache-2.0 conversion schedule.

---

## 8. Task Dependencies

### 8.1 Dependency graph (textual)

```
Task 0 (RFC) ──────────┬──► Task 3 (partner federation GA)
                       │
Task 1 (threat model) ─┘
                       │
                       ├──► Task 6 (SOC2 export endpoint)
                       │
                       └──► Task 10 (SCIM provisioning)

Task 2 (did:ion hardening) ──► Task 3 (partner federation GA)

Task 3 ──► Task 9 (discovery v1.0.0 — partner-federation field)
Task 3 ──► Task 12 (parity — partner-issued token scenario)

Task 4 (posture-emitter wiring) ──► Task 6 (SOC2 export endpoint)

Task 5 (cross-chain anchor GA) ──► Task 6 (SOC2 export — chain-proof field)
Task 5 ──► Task 9 (discovery v1.0.0 — auditExport field)

Task 7 (db/storage GA) ──► Task 11 (compose + Helm — service inclusion)

Task 8 (AGT guard) ──► Task 12 (parity — guard + gateway dual-enforcement)

Task 6 + Task 7 + Task 8 + Task 9 + Task 10 ──► Task 11 (infra bundle)

Task 11 + Task 12 ──► Task 13 (self-host docs consolidated)

ALL of 0–13 ──► Task 14 (status block + reference materials)
```

### 8.2 Hard gates (cannot be relaxed)

- **Task 0 gates Tasks 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14.** No
  implementation work begins until the RFC is merged.
- **Task 1 gates Tasks 3, 6, and 10.** Partner federation, SOC2 export,
  and SCIM provisioning are the three highest-risk new attack surfaces.
  None merge before the threat model is signed off.
- **Task 2 gates Task 3.** `did:ion` must be circuit-breaker protected
  before partner federation can be promoted to GA.
- **Task 4 gates Task 6.** The export endpoint requires the emitter to
  be wired into the pipeline first.
- **Task 5 gates Task 6.** The chain-proof field on the export response
  requires the anchor to be a first-class feature.
- **Task 12 (parity) is a hard gate before declaring Stage 5 shipped.**
  E10 cannot be checked off without Task 12 green in CI.
- **Task 14 is last by definition** (it documents the completion of
  the others).

### 8.3 Suggested sequencing for three parallel tracks

**Track A — Gateway + audit infrastructure (~3 engineers):**

Tasks 0 → 1 (parallel with 0) →
Tasks 2, 4, 5 (parallel) →
Task 3 (requires 2) → Task 6 (requires 4 + 5) → Task 12 (requires 3 + 8)

**Track B — Issuer + enterprise integrations (~2 engineers):**

Wait on Task 0 + 1 →
Tasks 8, 9, 10 (parallel, after 0 and relevant dependency) →
Task 13 (after 9 + 10)

**Track C — Infrastructure + data services (~2 engineers):**

Wait on Task 0 →
Task 7 (after 0 only) →
Task 11 (after 5, 7, 8, 9, 10)

**Convergence:** Task 14 wraps all three tracks.

### 8.4 Stage-5 shipped definition

All of the following are simultaneously true:

1. Tasks 0–14 are checked off in `docs/mvp.md` §"Stage 5".
2. Cross-stage parity test (Task 12) is green in CI, including the
   partner-issued token scenario and the AGT guard + gateway dual-
   enforcement scenario.
3. Enterprise threat model (Task 1) is signed off.
4. A real enterprise customer can:
   a. Register a partner DID and have tokens from that partner accepted
      by the production gateway.
   b. Export a SOC2-scoped OCSF evidence bundle from
      `GET /api/v1/audit/export` and verify every record offline against
      the issuer's public JWKS.
   c. Run `helm install euno ./k8s/helm/euno` on a clean cluster with
      external Postgres + Redis and reach a working gateway + issuer.
   d. Push users and groups via SCIM and have their group memberships
      reflected in the next capability token issuance.
5. The `posture-emitter`, `db-token-service`, `storage-grant-service`,
   and `partner-issuer-sim` packages have `STATUS.md` files marking
   them `1.0.0 stable` with no quarantine language.
6. `scripts/stage5-readiness.ts` reports `READY` and the
   `docs/mvp.md` §"Stage 5" block has all tasks checked off.

# Stage 4 Execution Plan — "Capability Issuer + Identity"

**Source.** `docs/mvp.md` § "Stage 4: Capability Issuer + Identity" (lines
724–748), with hard dependencies on § "Policy and audit schema parity"
(line 507), § "Critical risks" → "@euno/mcp" rule (line 851), and the
two-folder repository structure ([§ Repository structure](./mvp.md#repository-structure-public--private)).

**Predecessor status.** Stage 3 is complete (Tasks 0–20 in `docs/mvp.md`
are all checked off). The hosted gateway, the API-key minter, persistent
audit query, KMS-signed evidence, RedisHA distributed state, and the
single-config-change upgrade are all live. Stage 4 builds on top of that
service plane; no Stage-3 component is rewritten.

---

## 1. Goal

Promote `euno-platform/packages/capability-issuer` from "internal token
factory used by the API-key minter" to **a first-class user-facing
identity-bound issuance service** that:

1. Accepts authenticated end-users (humans and service principals) via
   real enterprise Identity Providers (Entra ID + at minimum one of AWS
   Cognito or GCP Cloud Identity), and translates their authenticated
   identity + role into a **signed capability token** scoped to one or
   more agents.
2. Exposes the already-implemented attenuation and renewal flows as
   live, supported, documented endpoints reachable from the `euno` CLI
   and from agent SDKs.
3. Lets a tech lead author a **capability-manifest template** once and
   bind it to many agents (and many users) instead of editing config
   files per agent.
4. Ships in **both** the hosted product **and** the self-host bundle —
   parity with Stage 3 — so that the BYO-GW path documented in
   `docs/self-host.md` can be extended to BYO-Issuer without an
   architectural rewrite.

The Stage-4 thesis (preserve when assigning tasks): in Stage 3, the
caller authenticated with an opaque API key and the *minter* held the
managed signing key. In Stage 4, the caller authenticates as a *real
user* against an *enterprise IdP*, and the issuer mints a token bound to
that identity — with role-to-capability mapping, attenuation, renewal,
and template-driven assignment all available as live endpoints. The
existing API-key minter is **not removed**: it remains the upgrade
on-ramp and the agent-to-agent path. The two issuance front doors
coexist behind the same KMS-backed signer and the same gateway verifier.

### Non-goals (explicit)

- **Cross-chain audit anchors** (Stage 5).
- **W3C DID partner-issuer federation with per-DID circuit breakers**
  (Stage 5; the existing `did-identity-provider.ts` stays in place but
  is not promoted to a documented enterprise feature).
- **AGT-style in-process guard** (Stage 5).
- **On-prem deployment hardening for restricted networks** beyond the
  existing `infra/docker-compose.yml` (Stage 5).
- **A second "policy authoring" UX** beyond manifest templates. Stage
  4 surfaces templates; deeper visual policy editors are Stage 5.
- **Migrating the API-key minter behind the issuer.** The minter stays
  as-is; Stage 4 adds a parallel SSO path, it does not replace the
  Stage-3 path.

---

## 2. Exit Criteria (Stage 4 is "shipped" when ALL are true)

E1. **Tasks 0–13 below are all checked off** in a `> **Stage 4 status**`
    block added to `docs/mvp.md` § "Stage 4", in the same format used
    for Stage 1, Stage 2, and Stage 3.

E2. **Two IdPs work end-to-end in the hosted product**: Entra ID
    plus the second IdP chosen in Task 0 (AWS Cognito **or** GCP Cloud
    Identity). "End-to-end" means an unauthenticated user can run
    `euno request --idp <name>` from a clean machine, complete the IdP
    auth flow in a browser, and receive a working signed capability
    token that the production gateway accepts.

E3. **`euno request` and `euno validate-token` are no longer
    "scaffold-only"**: both commands are wired to a live issuer URL by
    default in hosted mode, return real tokens (request) and real
    JWKS-verified validation results (validate-token), and have happy-
    path + error-path integration tests in
    `euno-platform/packages/integration-tests/`.

E4. **Manifest templates are usable**: a tech lead can `POST` a template
    via the issuer admin API, assign it to ≥1 agent, and a user with
    the bound role gets a token whose embedded `AgentCapabilityManifest`
    matches the template. Round-trip is covered by an integration test
    in `euno-platform/packages/integration-tests/`. The admin UI is
    served by the issuer's own Express process at `/admin/` (four
    server-rendered pages: list, create, detail/version-history,
    assignment) — it is **not** a separate deployment under `web/`.
    All UI calls go through the `/api/v1/admin/templates` endpoints;
    no UI-specific endpoints exist.

E5. **Self-host parity**: `infra/docker-compose.yml` gains an `issuer`
    service in the `full` profile; `docs/self-host.md` is updated with
    a "Stage 4 self-host" section covering issuer config, IdP wiring,
    and the minimum viable single-tenant issuer setup. `infra/smoke-
    test.sh` exercises one issuance round-trip against the docker
    issuer.

E6. **Cross-stage parity test suite passes**:
    `euno-platform/packages/integration-tests/tests/cross-stage-parity.test.ts`
    is extended with a Stage-4 scenario (issuer-minted token) and asserts
    the same decisions, obligations, and OCSF pre-signature record
    contents as the Stage-3 minter-minted token for the same manifest.

E7. **Stage-5 readiness signal is wired**:
    `scripts/stage5-readiness.ts` (new) reports green when the Stage-5
    gate signal — "enterprise inbound from a company with a security
    team, mentioning compliance, on-prem, or 'our CISO needs to review
    this'" — is recorded. This is a documentation/telemetry tracker;
    no change to the gate definition itself.

E8. **Schema parity invariants from `docs/mvp.md` § "Policy and audit
    schema parity" still hold.** No new types appear in the issuer or
    in the CLI that are not also in `@euno/common-core`. CI dependency-
    direction enforcement (Stage 0 Substage 0.4) continues to pass.

E9. **Threat model addendum** (`docs/security/issuer-identity-threat-
    model.md`) is reviewed and signed off by ≥2 engineers + 1 security
    reviewer, addressing every question in § 5 below. No Stage-4
    customer-facing IdP integration ships before this is approved.

E10. **Pricing and billing plumbing extended**: per-user issuance counts
     are metered through the same `UsageMeter` interface used in Stage 3
     (`public/packages/common/src/usage-meter.ts`). No new metering
     interface is introduced.

---

## 3. Test Coverage Requirements

The same coverage discipline used in Stage 3 applies. For every task
below, the PR must add:

1. **Unit tests** in the owning package's `tests/` (or `src/__tests__/`)
   directory.
2. **An integration test** in `euno-platform/packages/integration-tests/`
   when the change crosses a process or network boundary (CLI ↔ issuer,
   issuer ↔ IdP, issuer ↔ gateway, issuer ↔ manifest-template store).
3. **A cross-stage parity test entry** when the change touches token
   shape, audit shape, or policy shape (per `docs/mvp.md` § "Policy
   and audit schema parity").
4. **A negative test** that proves fail-closed behaviour: unknown IdP
   → deny; revoked role → deny; expired template → deny; KMS error
   → deny; IdP unreachable → deny.
5. **A schema-version test**: running an old client against the new
   issuer (and vice versa within the documented compat window) returns
   the documented error class, not a 500.

Aggregate coverage targets (mirroring Stage 3's discipline; *measured
on changed lines, not whole-package*):

- Issuer (new code): ≥90% lines, ≥85% branches.
- CLI (changed commands): ≥90% lines on the `request` and
  `validate-token` action handlers.
- Hosted UI (manifest templates view): playwright/component test that
  exercises list, create, assign, delete; no coverage % gate (UI), but
  the test must be in CI.

The CI job order is unchanged from Stage 3: lint → typecheck → unit →
integration → smoke (docker-compose `smoke` profile). Stage 4 PRs that
touch `infra/` must be smoke-tested locally before merge; the smoke
profile is the gate.

---

## 4. Detailed Design

### 4.1 Component map

Stage 4 adds **no new packages**. It does promote three existing
artifacts to first-class status:

| Artifact | Today | After Stage 4 |
|---|---|---|
| `euno-platform/packages/capability-issuer/` | Internal lib used by the API-key minter; standalone Express app exists but is not exposed as a hosted product surface | Hosted service (HA, KMS-signed, IdP-authenticated) **and** self-host docker image |
| `public/packages/cli/` `request` / `validate-token` commands | Implemented and usable against explicitly configured issuer/JWKS endpoints today; not yet PKCE/SSO-bound and no hosted-default issuer wiring | Live, documented, end-to-end tested commands; default issuer URL configurable per environment |
| `web/` (static landing site) | Marketing pages | Adds a (still simple, server-rendered or SPA, decided in Task 0) authenticated **manifest templates** view |

Stage 4 introduces **no new seam types** in `@euno/common-core` unless a
gap is identified during Task 0. Specifically:

- `IdentityAdapter` (`@euno/common`) is the IdP seam — already exists.
- `TokenSigner` (`@euno/common`) is the KMS seam — already exists,
  reused from Stage 3 via `KmsTokenSigner` in `@euno/common-infra`.
- `RoleCapabilityPolicy` and `DEFAULT_ROLE_CAPABILITY_MAP` already
  encode role-to-capability mapping; the manifest-template store layers
  on top of them.

Any divergence from this rule must be raised in Task 0's RFC and signed
off before code lands.

### 4.2 IdP integration (Task 2)

Both IdPs already have adapter implementations:

- `euno-platform/packages/capability-issuer/src/azure-identity-provider.ts`
  (Entra ID — production-ready)
- `euno-platform/packages/capability-issuer/src/aws-cognito-identity-provider.ts`
- `euno-platform/packages/capability-issuer/src/gcp-identity-provider.ts`

Stage 4 work is **wiring, configuration, and operator-facing
documentation**, not new adapter code. Concretely:

1. **Hosted product**: Entra ID + (Cognito **or** GCP Cloud Identity,
   chosen in Task 0). Both must be available in the hosted region.
2. **Self-host bundle**: same two IdPs are configurable; operator
   selects via env var (`ISSUER_IDP_PROVIDER=azure|cognito|gcp` plus
   provider-specific tenant/issuer URL/client-id/JWKS-URI).
3. **Discovery**: the issuer's `GET /.well-known/openid-configuration`
   is published per-tenant (multi-tenant deployments) and at the root
   (single-tenant deployments). Existing `GET /.well-known/jwks.json`
   stays unchanged — this is what the gateway already consumes.

The `IdentityAdapter` contract guarantees that the issuer's
`IssueController` receives a normalised `(subject, tenantId, roles[])`
tuple regardless of provider. **No** provider-specific code lands in
the issuance pipeline.

### 4.3 CLI wiring (Task 5)

`public/packages/cli/src/index.ts` already declares the `request` and
`validate-token` commands. Stage 4 work:

1. **`euno request`** accepts `--issuer-url`, `--idp <name>`,
   `--agent-id`, `--scope`, `--role`, and an optional `--template-id`.
   Default `--issuer-url` resolves from `~/.euno/config` (created by
   `euno init` and updated by `euno config set`), then falls back to
   the hosted production URL constant defined in `@euno/common-core`.
   The command opens an OS browser to the IdP authorisation endpoint
   (PKCE), receives the code on a localhost loopback, exchanges it via
   the issuer's `POST /api/v1/issue`, persists the resulting token to
   `~/.euno/tokens/<agent-id>.jwt` with `0600` perms, and prints the
   `jti` + expiry. Implementation pattern: copy `oauth4webapi` PKCE
   flow already used by the Stage 3 `upgrade-to-hosted` interactive
   command (`public/packages/mcp/src/cli/upgrade-to-hosted.ts`).
2. **`euno validate-token`** fetches the issuer's JWKS over HTTPS,
   verifies signature, expiry, and `aud`/`iss`, prints the decoded
   payload, and exits non-zero on any failure. Existing
   `public/packages/mcp/src/__tests__/validate-token.test.ts` provides
   the test fixture pattern.
3. **Refresh path**: `euno request --refresh` calls `POST
   /api/v1/renew` with the stored token. **No** silent refresh in the
   CLI — explicit by design (the renewal endpoint is exposed; the agent
   SDK in `public/packages/mcp/` already handles automatic refresh).
4. **Revocation path**: `euno revoke <jti>` (new subcommand) calls the
   issuer's existing revocation endpoint. The revocation list is
   already mirrored to the gateway via Stage 3 Task 6.

All three commands fail fast on `network`, `idp_unreachable`,
`token_invalid`, `permission_denied`, and `quota_exceeded` with the
error-class taxonomy already documented in
`docs/stage-3-gateway-protocol.md`. The taxonomy is reused, not forked.

### 4.4 Manifest templates (Task 6)

A **manifest template** is a stored, named, versioned
`AgentCapabilityManifest` (the existing type from `@euno/common-core`)
plus binding metadata: `(templateId, name, version, manifest,
ownerTenantId, createdBy, createdAt, updatedAt)`. Templates live in
the issuer's Postgres (new tables; migration ships in Task 6). They
are immutable per-version: editing produces a new version; previously
issued tokens that reference the old version remain valid until expiry.

Lifecycle:

1. `POST /api/v1/admin/templates` — create (operator role required).
2. `GET /api/v1/admin/templates?ownerTenantId=…` — list.
3. `GET /api/v1/admin/templates/:templateId` — fetch (latest version).
4. `GET /api/v1/admin/templates/:templateId/versions/:version` —
   fetch specific version.
5. `POST /api/v1/admin/templates/:templateId/versions` — append a
   new version (atomic; old version remains).
6. `POST /api/v1/admin/templates/:templateId/assign` — bind to one
   or more `(tenantId, agentId, role)` triples. Stored in a separate
   `template_assignments` table.
7. `DELETE /api/v1/admin/templates/:templateId` — soft-delete (mark
   `deletedAt`); existing assignments continue to honour the last
   non-deleted version until cycled out.

Issuance flow when a template is in scope:

1. Caller authenticates via IdP (§ 4.2).
2. `IssueController` resolves the user's `(tenantId, role)` pair.
3. If a template assignment exists for `(tenantId, agentId, role)`,
   the resolved manifest **is** the template's manifest at the bound
   version. `RoleCapabilityPolicy` is **not** consulted in this branch
   — templates are the authoritative source when present.
4. If no assignment exists, fall back to the existing
   `RoleCapabilityPolicy` + `DEFAULT_ROLE_CAPABILITY_MAP` path. This
   preserves backward compat: deployments that don't author templates
   keep working.
5. The signed token's top-level `policyHash` claim is computed over
   the **resolved manifest** (not the template metadata) and stamped
   onto the JWT as a top-level claim, so the gateway's verifier path
   is unchanged.

UI surface (Task 7):

- Add an authenticated "Templates" section to `web/`. The simplest
  shipping shape (and the one Task 0 should adopt unless a stronger
  reason emerges) is a server-rendered page set under `web/admin/`
  served by the issuer itself behind the same IdP guard, not a separate
  SPA. This keeps the auth story trivial (the user is already
  authenticated to the issuer to issue tokens) and avoids spinning up a
  new build/deploy pipeline for a UI that has four pages: list, create,
  detail/version-history, assignment.
- All UI calls go through the admin API endpoints above. No
  UI-specific endpoints.

### 4.5 Hosted product deployment shape

The issuer becomes a sibling service to the gateway and the minter:

```
           ┌──────────────────┐
 user ─►  │ web (templates UI │  (authenticated, IdP-bound)
           └────────┬─────────┘
                    │ admin API
                    ▼
           ┌──────────────────┐      ┌───────────┐
 user ─►  │ capability-issuer │ ──► │ KMS HSM   │
           │  - /api/v1/issue  │      │ (per-     │
           │  - /attenuate     │      │  tenant   │
           │  - /renew         │      │  signing) │
           │  - /revoke        │      └───────────┘
           │  - /admin/*       │      ┌───────────┐
           └────────┬──────────┘  ──► │ Postgres  │
                    │ JWKS              │ (templates,│
                    ▼                   │  assignmts)│
           ┌──────────────────┐         └───────────┘
 agent ─► │  tool-gateway     │  (verifier path unchanged)
           └──────────────────┘
```

The API-key minter (Stage 3) sits to the left of the issuer; both feed
the same gateway. They share the KMS-backed `KmsTokenSigner` so token
shape is byte-identical (the gateway's verifier does not need to
distinguish the two issuance paths — and explicitly should not).

### 4.6 Self-host bundle

`infra/docker-compose.yml` already has `dev`, `full`, and `smoke`
profiles (Stage 3 Task 13). Stage 4 work:

1. Add an `issuer` service under the `full` and `smoke` profiles.
   The Dockerfile already exists at
   `euno-platform/packages/capability-issuer/Dockerfile`.
2. Bind-mount a `policies/` directory (RoleCapabilityPolicy + initial
   templates seed) at startup; document the layout in `docs/self-
   host.md`.
3. The smoke profile additionally seeds one IdP — the simplest is a
   **Cognito-compatible mock** (a single-tenant local OIDC server)
   purely for the smoke test; this is the same pattern Stage 3 used
   for KMS via LocalStack. **Do not** ship a real cloud IdP in the
   smoke profile.
4. Wire `infra/smoke-test.sh` to perform: `euno request` →
   token in hand → `tools/call` against the gateway → audit row visible
   via `GET /api/v1/audit/records`. This is the operational proof of
   end-to-end readiness.

### 4.7 Token shape and policy parity

Token claim set is **unchanged** from Stage 3:

- `iss` = the issuer DID (`issuerDid`).
- `sub` = the agent ID.
- `authorizedBy.userId` = the user identity. In Stage 3, the minter
  carries `apiKeyPrefix`; in Stage 4, the issuer carries the
  IdP-resolved `userId`.
- `vc` = the VC envelope built by `payload-builder.ts`. Schema
  unchanged.
- `policyHash` = canonical hash of the resolved manifest (template
  in Stage 4; role-resolved in Stage 3 and pre-template Stage 4).
- `cnf.jkt` = sender-constrained binding (preserved across attenuation
  and renewal — see `payload-builder.ts:245`).
- `region` = preserved across attenuation/renewal (F-7).

Audit record shape (OCSF API Activity, class_uid 6003) is **unchanged**.
The only new field on issuance audit rows is `idpProvider`
(`"azure" | "cognito" | "gcp"`), which is logged in the existing
`AuditEntry.context` map — **not** as a new top-level field. This
keeps the parity invariant from `docs/mvp.md` § "Policy and audit
schema parity" intact.

---

## 5. Threat Model Addendum (BLOCKING — Task 1)

The Stage-3 minter threat model (`docs/security/minter-threat-
model.md`) covered the case where a managed signing key with platform-
wide blast radius signs tokens on behalf of opaque API keys. Stage 4
expands the attack surface in three ways that must be analysed before
any customer-facing IdP integration ships:

| Question | Required answer in `docs/security/issuer-identity-threat-model.md` |
|---|---|
| **IdP compromise** | If an attacker compromises a tenant's Entra ID app registration, what tokens can they obtain? What is the blast radius? What detection capability exists? Document required tenant-side IdP hygiene (conditional access, app-role review cadence). |
| **IdP-token replay against the issuer** | Confirm the issuer rejects re-used IdP authorization codes (PKCE state binding), enforces `nonce`, and validates `aud`/`iss`/`exp`/`iat` of the IdP's ID token before consulting the role mapping. |
| **Role-mapping privilege escalation** | A user with role X requests a token; can they craft a request that resolves to role Y's manifest? The `IssueController` must derive the role from the verified IdP token, never from the request body. Test: a request that includes `role: admin` but whose IdP token contains `role: viewer` resolves to viewer. |
| **Manifest template tampering** | Templates are admin-mutable. Document the admin-role authorisation model (must reuse the operator-JWT pattern from `api-key-minter` admin routes per `MinterConfigSchema` admin JWT auth — see Stage 3 admin JWT integration), the audit trail per template mutation, and the rollback procedure if a malicious template is published. |
| **Cross-tenant template leakage** | A template owned by tenant A must never be assignable, listable, or fetchable by tenant B. Test boundary explicitly. |
| **Per-tenant signing-key isolation** | Re-affirm the Stage-3 decision (per-tenant KMS keys behind a single root) holds for Stage 4. If the hosted deployment uses platform-wide signing for cost reasons, document the explicit blast-radius trade-off and the compensating controls. |
| **Self-host operator key management** | Single-tenant self-host operators may not have an HSM. Document the supported degraded mode (file-based EC key with strong file perms + offline backup) and explicitly mark it "not supported for multi-tenant". |
| **CLI token storage at rest** | `~/.euno/tokens/<agent-id>.jwt` written `0600`. Document the trade-off vs. an OS keychain integration (rejected for v1: keytar/keychain integration is Stage 5; document this explicitly so it is not relitigated). |

Sign-off process is identical to Stage 3 Task 1: ≥2 engineers + 1
security reviewer outside the implementer. **No customer-facing IdP
integration code merges to `main` until this document is approved.**

---

## 6. Tasks

Phase A — Pre-flight (gating; must complete before customer-facing code ships)

### Task 0 — Stage 4 design freeze & RFC
Author `docs/stage-4-design.md` capturing:
- The second IdP choice (AWS Cognito vs GCP Cloud Identity), with rationale tied to a named design partner if possible. Default if no signal: **AWS Cognito**, on the grounds of broader install base in the early-stage segment Stage 3 served.
- The hosted-vs-self-host feature matrix for the issuer (mirror the matrix already present in `docs/stage-3-design.md`).
- The Postgres schema for `templates`, `template_versions`, and `template_assignments`, including indexes and the soft-delete strategy.
- The exact contract of the seven admin API endpoints in § 4.4.
- The decision on UI shape (server-rendered admin pages under `web/admin/` vs separate SPA). Default: server-rendered, per § 4.4.
- The decision on whether the API-key minter and the issuer share the same KMS root key alias or use distinct aliases (recommend distinct, for blast-radius separation; document either way).
- Any seam additions in `@euno/common-core` (expected: zero; if non-zero, justify each).
- Cross-link every decision back to `docs/mvp.md` Stage 4 anchors.

**Gate:** RFC reviewed and merged before Tasks 2+ start.

### Task 1 — Issuer identity threat model (BLOCKING per § 5)
Produce `docs/security/issuer-identity-threat-model.md` answering every question in § 5 verbatim. Reviewed and signed off by ≥2 engineers + 1 security reviewer outside the implementer.

**Gate:** No IdP wiring code (Tasks 2, 3) merges to `main` until this doc is approved.

Phase B — Issuer service hardening

### Task 2 — Hosted IdP wiring (Entra ID + second IdP) ✅
Wire both `AzureADIdentityProvider` and the Task-0-chosen second IdP into the issuer's bootstrap (`euno-platform/packages/capability-issuer/src/index.ts`). Configuration via env (`IDENTITY_PROVIDER`, provider-specific config). Per-tenant config supported via `TenantIdpRegistry` (`src/tenant-idp-config.ts`) — file-based JSON mapping with hot-reload. `GET /.well-known/openid-configuration` with optional `?tenantId=` scoping.

`POST /api/v1/oidc/token` endpoint: accepts a pre-exchanged `idToken` (client performs PKCE code exchange), enforces nonce-claim binding, authorization-code replay prevention (eager fail-closed `OidcStateStore`), and issues a capability token via `issueCapabilityFromUserContext` (skips re-validation).

New schema fields: `ISSUER_PUBLIC_URL`, `ISSUER_TENANT_IDP_CONFIG_FILE`, `OIDC_CODE_TTL_SECONDS`.

New public service APIs: `CapabilityIssuerService.getIdentityProvider()`, `CapabilityIssuerService.issueCapabilityFromUserContext()`, `IssueController.handleFromUserContext()`, `IssueFromUserContextRequest`.

- **Tests**: `tests/idp-wiring.test.ts` — 42 tests covering: OIDC discovery document, `GET /authorize` state/nonce generation, field-validation rejections, Azure AD token nonce-claim check, AWS Cognito token nonce-claim check, code-replay prevention, state/nonce binding round-trip, role-from-token invariant. Unit tests for `OidcStateStore` (13 cases) and `TenantIdpRegistry` (10 cases). Total: 491 passing.
- **Docs**: `docs/issuer-idp-setup.md` — Entra ID app registration, Cognito user pool setup, per-tenant config file format, OIDC discovery, replay-prevention TTL, client flow, security checklist.

### Task 3 — Role-to-capability mapping production hardening ✅ COMPLETE
The existing `RoleCapabilityPolicy` machinery is already implemented. Production-harden it:
- Move the active mapping out of `DEFAULT_ROLE_CAPABILITY_MAP` (which is documentation-grade) into a Postgres-backed `role_policies` table loaded at issuer startup, with a documented hot-reload signal.
- Authorise mutations via the same operator-JWT pattern used in the minter admin routes (see the stored fact about admin JWT auth in the minter — apply the same pattern here; do not reinvent).
- Audit log every role-policy mutation with operator identity (mirror `mintTotal` audit pattern).
- **Tests**: unit tests for hot-reload; integration test for unauthorized mutation returning 401; OCSF authorization event test.

**Implemented in this PR:**
- `src/admin-jwt-verifier.ts` — JWKS-backed JWT verifier for the admin API (same pattern as minter's `AdminJwtVerifier`); `createAdminJwtVerifierFromEnv` reads `ISSUER_ADMIN_JWKS_URI` / `ISSUER_ADMIN_JWT_AUDIENCE` / `ISSUER_ADMIN_JWT_ISSUER`.
- `src/postgres-role-policy-store.ts` — `PostgresRolePolicyStore` persists policy versions to an append-only `role_policies` table; `ensureSchema()` / `loadLatest()` / `save(policy, operatorId)`.
- `src/routes/admin-role-policy.ts` — `PUT /api/v1/admin/role-policy` + `GET /api/v1/admin/role-policy`; JWT primary + X-Admin-Key fallback; `validateRoleCapabilityPolicy`; persists to store; calls `onPolicyUpdated` hot-reload callback; emits structured OCSF-shaped audit log entry.
- `src/issuance/minting-pipeline.ts` — `policy` + `cachedPolicyHash` made mutable; `updatePolicy()` added.
- `src/issuance/issue-controller.ts` — `policy` made mutable; `updatePolicy()` added.
- `src/issuer-service.ts` — `updatePolicy()` propagates to both pipeline and controller.
- `src/index.ts` — Postgres store init, SIGHUP hot-reload handler, admin routes mounted after `express.json()`.
- `public/packages/common/src/config/schema.ts` — `ISSUER_ROLE_POLICY_DB_URL`, `ISSUER_ADMIN_API_KEY`, `ISSUER_ADMIN_JWKS_URI`, `ISSUER_ADMIN_JWT_AUDIENCE`, `ISSUER_ADMIN_JWT_ISSUER` added to `IssuerConfigSchema`.
- Tests (57 new): `tests/postgres-role-policy-store.test.ts`, `tests/admin-role-policy.test.ts`, `tests/hot-reload.test.ts`; 5 new config schema tests in `euno-platform/packages/common/tests/config.test.ts`.
- Total: 506 capability-issuer tests pass, 936 common tests pass.

### Task 4 — Token attenuation & renewal as live, supported endpoints
The endpoints exist. The Stage-4 work is to:
- Confirm rate limiting (F-1) is active in the hosted deployment with parameters published in `docs/issuer-operator-runbook.md` (new).
- Confirm `cnf.jkt` and `region` claims are preserved across attenuate and renew (already implemented; add explicit tests to `cross-stage-parity.test.ts`).
- Document the developer-facing flow in `docs/agent-sdk.md` (a developer reading the docs should be able to call `/attenuate` and `/renew` from a non-CLI client).
- **Tests**: parity tests; rate-limit boundary tests.

Phase C — Developer surface

### Task 5 — `euno request` and `euno validate-token` wired to live issuer
Per § 4.3. Includes `euno revoke` as a new subcommand.
- **Tests**: integration test for the full PKCE flow against a mock IdP; `validate-token` test against a real JWKS endpoint.
- **Docs**: `public/packages/cli/README.md` updated; `docs/quickstart-stage-4.md` walks a new user from `npm install -g @euno/cli` to first issued token.

### Task 6 — Manifest template store + admin API ✅ COMPLETE
Per § 4.4. Postgres migrations land in `euno-platform/packages/capability-issuer/src/migrations/` (use the same migration pattern Stage 3 added for the audit ledger).
- The issuance branch in `IssueController` that consults templates is the only change to existing issuance code.
- **Tests**: round-trip CRUD on templates; assignment-driven issuance test; immutability-of-versions test; cross-tenant access denial test; soft-delete semantics test.

### Task 7 — Manifest templates UI under `web/admin/`
Per § 4.4 closing paragraph and Task 0's UI decision. Server-rendered pages by default. Authenticated via the same IdP path as `euno request` (the page-load hits `/api/v1/admin/templates` with the user's bearer token).
- **Tests**: playwright (or equivalent) smoke covering list → create → assign → list-assignments. Page-level access control test.

Phase D — Self-host parity

### Task 8 — Issuer in `infra/docker-compose.yml` + smoke wiring
Per § 4.6. The Dockerfile exists; this is compose + env + seed-data work. `infra/smoke-test.sh` is extended to include one issuance round-trip end-to-end.
- **Tests**: smoke profile passes in CI.

### Task 9 — `docs/self-host.md` Stage-4 section
Add a "Stage 4 self-host" section covering: issuer config, IdP wiring (single-tenant Cognito recipe + Entra ID recipe), template seed-data file format, KMS-vs-local-key trade-off pointer to threat model § "Self-host operator key management", admin operator-JWT setup. Update the BYO-GW table to clarify that BYO-Issuer is now in scope.

Phase E — Telemetry, billing, parity, gate

### Task 10 — Telemetry continuity
Extend `GatewayTelemetryCollector` (Stage 3 Task 16) to recognise issuance events from the issuer (same per-tenant 5-min flush, same JSON event schema, **no** new event names). Wire issuance counts and renewal counts into the `UsageMeter` interface. Per-user metering granularity — but always aggregated at the tenant level for billing (the per-user dimension is for support/forensics, not invoicing).
- **Tests**: meter dual-write test; tenant aggregation test.

### Task 11 — Cross-stage parity test extension ✅ COMPLETE
Extend `euno-platform/packages/integration-tests/tests/cross-stage-parity.test.ts` with a Stage-4 scenario: the same `AgentCapabilityManifest` issued via (a) Stage-3 minter and (b) Stage-4 issuer must produce identical decisions, identical obligations, and identical OCSF pre-signature record contents on the gateway. This is the operational proof of E6.
- The intentional divergence is `authorizedBy.userId`: the minter carries the API-key prefix (a synthetic identifier, e.g. `"sk-abc12345"`); the issuer carries the IdP-resolved user identity (e.g. `"user@corp.com"`). The `sub` claim is identical in both paths (sub = agentId). Document this in the test's comment and in `docs/stage-3-gateway-protocol.md` so the gateway operator knows to expect it.

### Task 12 — Stage-5 readiness instrumentation
Add `scripts/stage5-readiness.ts` modeled on `scripts/stage4-readiness.ts`. Single signal: `EUNO_TELEMETRY_API /v1/stats/stage5-gate` returns ≥1 enterprise inbound matching the criteria in `docs/mvp.md` line 748. Exit codes: 0=READY, 1=NOT READY, 2=UNKNOWN. This is the gate tracker; it does not unilaterally start Stage 5.

### Task 13 — Stage-4 status block + reference materials
Add the `> **Stage 4 status**` block to `docs/mvp.md` § "Stage 4" with one bullet per task above. Add `docs/issuer-operator-runbook.md` (operator runbook: deployment topology, KMS key rotation procedure carried over from minter Task 11, alerting wiring, on-call playbook for IdP outages — fail-closed semantics). Update `README.md` and `public/packages/cli/README.md` with a Stage-4 hosted section.

---

## 7. Cross-cutting Obligations (apply to every task above)

These mirror Stage 3 §"Cross-cutting obligations" and are non-negotiable
in Stage 4:

1. **Schema parity is non-negotiable** (`docs/mvp.md` § "Policy and audit
   schema parity"). Any change to policy or audit shape lands in
   `@euno/common-core` first, with a parity test added in the same PR.
2. **No Stage-4-only types in CLI, web, or issuer that aren't in
   `@euno/common-core`** (`docs/mvp.md` § "Critical risks" → "@euno/mcp"
   rule extends to all leaf packages by virtue of the dependency-
   direction CI gate from Stage 0 Substage 0.4).
3. **Fail-closed defaults**: IdP unreachable → deny issuance; KMS
   unavailable → deny issuance; template lookup failure → fall back to
   `RoleCapabilityPolicy` only if the failure is `template_not_found`,
   otherwise deny; admin operator-JWT verification failure → deny
   mutation.
4. **Per-task PR contents**: unit tests, an integration test exercising
   the new wire path, a README/section update, and a CHANGELOG entry
   under the `@euno/capability-issuer 0.1.0` and `@euno/cli 0.1.0`
   headings.
5. **License boundary**: the issuer service runtime (the Express app,
   the admin API, the templates store) is **BSL** under
   `euno-platform/packages/capability-issuer/`. The CLI commands and
   any types added to `@euno/common-core` are **Apache-2.0** under
   `public/packages/`. The two-folder structure is the mechanical
   gate; CI dependency enforcement (Stage 0 Substage 0.4) catches
   accidental cross-license imports.
6. **Status tracking format**: mirror Stage 1, 2, 3 — add the `>
   **Stage 4 status**` block to `docs/mvp.md` and check items off as
   they land.
7. **Stage-3 components are not modified** unless the task explicitly
   names them. The minter's mint path, the gateway's verifier path,
   and the audit query API are all out of scope for changes; they are
   only consumed.

---

## 8. Task Dependencies

This section is the authoritative ordering for parallel execution. A
task may start once **all** of its predecessors are checked off.

### 8.1 Dependency graph (textual)

```
Task 0 (RFC) ──────────┬──► Task 2 (IdP wiring)
                       │
Task 1 (threat model) ─┘
                       │
                       ├──► Task 6 (templates store + admin API)
                       │
                       └──► Task 3 (role mapping prod hardening)

Task 2 ──► Task 5 (CLI wiring)
Task 2 ──► Task 4 (attenuate/renew docs + parity)
Task 2 ──► Task 8 (compose + smoke)

Task 6 ──► Task 7 (UI)
Task 6 ──► Task 11 (cross-stage parity extension)

Task 3 + Task 6 ──► Task 9 (self-host docs)

Task 4 + Task 5 + Task 6 + Task 7 + Task 8 ──► Task 10 (telemetry/billing)

Task 10 + Task 11 ──► Task 12 (Stage-5 readiness script)

ALL of 0–12 ──► Task 13 (status block + runbook + README)
```

### 8.2 Hard gates (cannot be relaxed)

- **Task 0 gates Tasks 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13.** No
  implementation work begins until the RFC is merged. (Threat-model
  authoring in Task 1 may proceed in parallel with Task 0 because it
  does not depend on the RFC's concrete decisions; it depends on § 5
  of this document.)
- **Task 1 gates Tasks 2 and 3.** IdP wiring and admin-mutation paths
  do not merge before threat-model sign-off.
- **Task 6 gates Task 7.** No UI before the API exists.
- **Task 11 (parity) is a hard gate before declaring Stage 4 shipped.**
  E6 cannot be checked off without Task 11 green in CI.
- **Task 13 is last by definition** (it documents the completion of
  the others).

### 8.3 Suggested sequencing for two parallel tracks

Track A (issuer + backend, ~3 engineers):
Tasks 0 → 1 (parallel) → Tasks 2, 3, 6 (parallel) → Tasks 4, 8 (parallel) → Task 10 → Task 11.

Track B (developer surface + UI, ~2 engineers):
Wait on Task 0 → Task 5 (after Task 2) → Task 7 (after Task 6) → Task 9 (after Tasks 3, 6).

Convergence:
Task 12 once Tasks 10 + 11 done. Task 13 wraps both tracks.

### 8.4 Stage-4 shipped definition

All of the following are simultaneously true:

1. Tasks 0–13 are checked off in `docs/mvp.md` § "Stage 4".
2. Cross-stage parity test (Task 11) is green in CI.
3. Threat model (Task 1) is signed off and the issuer's monitoring
   rules (carried over from minter Task 12, extended by Task 4 docs)
   are firing on a test tenant.
4. A real customer can run `euno request` against the hosted issuer,
   complete an IdP flow, receive a token, exercise it against the
   gateway, and view the resulting audit row via the Stage-3 audit
   query API — end-to-end, with no operator intervention.
5. The hosted templates UI demonstrably round-trips a template through
   list → create → assign → issuance, with the resulting token's
   embedded manifest matching the template byte-for-byte.
6. `scripts/stage5-readiness.ts` (Task 12) reports the Stage-5 gate
   status (READY / NOT READY / UNKNOWN) without erroring.

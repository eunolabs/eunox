# Stage 4 Design RFC — "Capability Issuer + Identity"

> **Status:** Ready for committee sign-off. The authoring work (Task 0) is complete.
> The gate condition — approved by ≥2 engineers + 1 security reviewer — must be
> met before any Task 2+ implementation begins. See §9 Review Checklist.
>
> **Last updated:** 2026-05-13
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

This document is the Stage 4 design freeze for `euno-platform`. It captures every
architectural decision that Tasks 2–13 must implement — and nothing else. The goal is
to make implementation choices explicit, reviewable, and traceable before code is
written, not discovered during code review.

**What this document decides:**

1. Second IdP selection (AWS Cognito vs. GCP Cloud Identity), with rationale.
2. Hosted-vs-self-host feature matrix for the issuer service.
3. Postgres schema for `templates`, `template_versions`, and `template_assignments`.
4. Exact contract of the seven manifest-template admin API endpoints.
5. UI shape decision (server-rendered vs. separate SPA).
6. KMS key alias isolation between the minter and the issuer.
7. Seam additions in `@euno/common-core` (expected: zero).

**What this document does not decide:**

- Implementation details covered by individual task specs in
  `docs/stage4executionplan.md`.
- Pricing changes beyond the feature matrix update in §2.
- Stage 5 federation / partner-issuer / cross-chain anchors (explicitly deferred
  in `docs/stage4executionplan.md` §"Non-goals").
- Migration path from the API-key minter to the issuer (no such migration is planned;
  they coexist per the Stage 4 thesis).

---

## 1. Second IdP Selection — AWS Cognito

> **MVP anchor:** `docs/mvp.md` §"Stage 4: What ships" (lines 724–748) — "Entra ID +
> at minimum one other identity provider (AWS Cognito or GCP Cloud Identity — pick
> whichever the design partners ask for)."

### 1.1 Decision

**Primary (hosted service):** Microsoft Entra ID (Azure AD), using the already-implemented
`AzureADIdentityProvider` (`euno-platform/packages/capability-issuer/src/azure-identity-provider.ts`).

**Second IdP (hosted service + self-host bundle):** **AWS Cognito**, using the already-implemented
`AWSCognitoIdentityProvider` (`euno-platform/packages/capability-issuer/src/aws-cognito-identity-provider.ts`).

GCP Cloud Identity is explicitly **not** selected as the second IdP for Stage 4. The GCP
provider implementation (`gcp-identity-provider.ts`) remains in place and fully usable by
self-hosters, but it is not activated in the hosted product for Stage 4.

### 1.2 Rationale

| Dimension | AWS Cognito | GCP Cloud Identity |
|---|---|---|
| Early-stage startup adoption | Broad — the AWS developer segment overlaps with the Stage 3 team-lead buyer | Narrower — GCP-native organisations tend to enter later in the maturity curve |
| Operator self-serve setup | Cognito User Pools have a documented, low-friction App Client + hosted-UI setup path; no specialised admin required | Cloud Identity / Workspace Admin SDK onboarding requires Google Workspace admin access, which small teams often don't have |
| OIDC discovery | Cognito publishes per-pool JWKS and OIDC discovery at stable well-known endpoints; no Graph API required | OIDC discovery is available but role/group resolution requires Cloud Directory API calls similar in complexity to Graph |
| Existing adapter completeness | `AWSCognitoIdentityProvider` validates JWKS-signed tokens, reads `cognito:groups` / `groups` claims, maps to `UserContext` — no new adapter code | `GCPIdentityProvider` is implemented; parity with Cognito adapter in terms of Stage 4 readiness |
| Design-partner signal | No direct signal received as of Task 0 freeze; AWS Cognito selected as the default per `docs/stage4executionplan.md` §Task 0 guidance | — |

The decision may be revised before merge if a named design partner requests GCP Cloud
Identity. In that case, GCP becomes the second IdP and Cognito remains supported but
non-primary for Stage 4 hosted.

### 1.3 Configuration surface

Both IdPs are activated via the `ISSUER_IDP_PROVIDER` environment variable and their
respective provider-specific variables. The config schema (`MinterConfigSchema`-equivalent
for the issuer, to be finalised in Task 2) handles both:

```
# Select the primary IdP for this deployment
ISSUER_IDP_PROVIDER=azure|cognito|gcp

# Azure AD (Entra ID)
ISSUER_AZURE_TENANT_ID=<guid>
ISSUER_AZURE_CLIENT_ID=<guid>
ISSUER_AZURE_CLIENT_SECRET=<secret>   # injected from secret manager, not baked in
ISSUER_AZURE_AUDIENCE=<app-id-uri>
ISSUER_AZURE_JWKS_URI=https://login.microsoftonline.com/<tid>/discovery/v2.0/keys

# AWS Cognito
ISSUER_COGNITO_USER_POOL_ID=<region>_<id>
ISSUER_COGNITO_CLIENT_ID=<client-id>
ISSUER_COGNITO_REGION=<region>
ISSUER_COGNITO_TOKEN_USE=id|access   # default: id
```

Per-tenant IdP overrides follow the same tenant-config loader pattern used in
`api-key-minter` (loaded from the Postgres tenant-config table at bootstrap;
refreshed on SIGHUP).

---

## 2. Hosted-vs-Self-Host Feature Matrix

> **MVP anchor:** `docs/mvp.md` §"Stage 4: Capability Issuer + Identity" (lines 724–748)
> and §"Pricing & business model sketch" (lines 791–808). Mirrors the matrix in
> `docs/stage-3-design.md` §4.

The matrix below extends the Stage 3 matrix with Stage 4 issuer features. Stage 3
features are reproduced for reference; their tier assignments are **unchanged**.

| Feature | OSS (`@euno/mcp` only) | Self-Host (BSL image) | Cloud Free | Cloud Team | Cloud Enterprise |
|---|:---:|:---:|:---:|:---:|:---:|
| Local enforcement (in-process PDP) | ✅ | ✅ | ✅ | ✅ | ✅ |
| stdio + HTTP proxy transports | ✅ | ✅ | ✅ | ✅ | ✅ |
| All condition types (Stages 1–2) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Local HMAC audit log | ✅ | ✅ | ✅ | ✅ | ✅ |
| Remote enforcer mode | — | ✅ | ✅ | ✅ | ✅ |
| KMS-backed audit signer | — | ✅ (BYO KMS) | ✅ | ✅ | ✅ |
| Redis call-counter / kill-switch | — | ✅ (BYO Redis) | ✅ | ✅ | ✅ |
| Postgres audit ledger | — | ✅ (BYO Postgres) | ✅ | ✅ | ✅ |
| Audit query API | — | ✅ | 7-day | 90-day | Configurable |
| Kill-switch admin API | — | ✅ | Session-scoped | ✅ | ✅ |
| API-key minter façade | — | — | ✅ | ✅ | ✅ |
| **Capability Issuer service** | — | ✅ (BYO KMS + IdP) | — | ✅ | ✅ |
| **SSO via Entra ID** | — | ✅ (BYO tenant) | — | ✅ | ✅ |
| **SSO via AWS Cognito** | — | ✅ (BYO pool) | — | ✅ | ✅ |
| **SSO via GCP Cloud Identity** | — | ✅ (BYO org) | — | — | ✅ |
| **Token attenuation + renewal** | — | ✅ | — | ✅ | ✅ |
| **Manifest templates (CRUD + assign)** | — | ✅ | — | ✅ | ✅ |
| **Manifest templates UI (`web/admin/`)** | — | — | — | ✅ | ✅ |
| **`euno request` (PKCE CLI flow)** | ✅ | ✅ | — | ✅ | ✅ |
| **`euno validate-token`** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **`euno revoke`** | — | ✅ | — | ✅ | ✅ |
| Per-user issuance metering | — | — | — | ✅ (support/forensics) | ✅ |
| Evidence export (signed OCSF) | — | — | — | — | ✅ |
| On-prem signing key (BYO HSM) | — | ✅ | — | — | ✅ |
| SOC2 attestation docs | — | — | — | — | ✅ |
| Cross-chain audit anchor (Stage 5) | — | — | — | — | ✅ |

**Notes:**

- The Capability Issuer self-host image ships in `infra/docker-compose.yml` under
  the `full` and `smoke` profiles (Task 8).
- Cloud Free does not include the Capability Issuer; Free users continue to use the
  API-key minter path. The upgrade path from Free → Team is documented in
  `docs/upgrade-to-hosted.md` (to be updated in Task 13).
- `euno request` and `euno validate-token` are OSS commands; they connect to
  self-configured issuer URLs. The hosted default URL is injected from `~/.euno/config`
  (written by `euno init`); Team/Enterprise plans pre-populate it.

---

## 3. Postgres Schema — Templates, Versions, Assignments

> **MVP anchor:** `docs/stage4executionplan.md` §4.4 (manifest templates), §Task 6.

### 3.1 Tables

All three tables live in the issuer's Postgres instance, in the `euno_issuer` schema
(configurable via `ISSUER_DB_SCHEMA`; default `euno_issuer`). Migrations are managed by
the same migration runner already used in `api-key-minter` and `tool-gateway` — the
`migrate()` pattern in `ledger-signer.ts`.

#### 3.1.1 `templates`

```sql
-- One row per template identity (not per version).
-- The "active version" is resolved via template_versions.
CREATE TABLE euno_issuer.templates (
  template_id    TEXT        NOT NULL,          -- URL-safe random ID, e.g. "tmpl_<base58:20>"
  owner_tenant_id TEXT       NOT NULL,          -- tenant that created this template
  name           TEXT        NOT NULL,          -- human display name (≤ 255 chars)
  created_by     TEXT        NOT NULL,          -- operatorId from admin JWT
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at     TIMESTAMPTZ,                   -- soft-delete sentinel; NULL = active
  PRIMARY KEY (template_id)
);

CREATE INDEX idx_templates_owner
  ON euno_issuer.templates (owner_tenant_id)
  WHERE deleted_at IS NULL;
```

**Soft-delete semantics:** setting `deleted_at` prevents new assignments but does not
invalidate existing assignments or in-flight tokens. Tokens that reference the last
non-deleted version remain valid until their `exp`. Once `deleted_at` is set, the
template does not appear in list results and cannot accept new version appends.

#### 3.1.2 `template_versions`

```sql
-- Immutable per (template_id, version). Editing creates a new version.
CREATE TABLE euno_issuer.template_versions (
  template_id    TEXT        NOT NULL REFERENCES euno_issuer.templates (template_id),
  version        INTEGER     NOT NULL,          -- monotonically increasing; 1-based
  manifest       JSONB       NOT NULL,          -- canonical AgentCapabilityManifest
  policy_hash    TEXT        NOT NULL,          -- SHA-256 of canonical manifest JSON
  created_by     TEXT        NOT NULL,          -- operatorId from admin JWT
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (template_id, version)
);

CREATE INDEX idx_template_versions_template_id
  ON euno_issuer.template_versions (template_id, version DESC);
```

**Immutability:** existing rows are never updated. A `POST /versions` call inserts a new
row with `version = max(version) + 1` under an `EXCLUSIVE` row-level lock on the parent
`templates` row (acquired via `SELECT ... FOR UPDATE` on `templates WHERE template_id = $1`),
preventing duplicate-version races without a separate sequence.

**`policy_hash`:** computed by the issuer application layer over the canonical JSON of
`manifest` (RFC 8785 JSON Canonicalization Scheme), identical to the hash embedded in
tokens (`policyHash` claim). This lets an operator compare the hash in a token to the
template version that produced it without decoding the JSONB.

#### 3.1.3 `template_assignments`

```sql
-- Binds a template version to a (tenantId, agentId, role) triple.
-- Multiple assignments may reference different versions; the "active" assignment
-- is the one with the highest version for a given triple.
CREATE TABLE euno_issuer.template_assignments (
  assignment_id   TEXT        NOT NULL,         -- URL-safe random ID, e.g. "asgn_<base58:20>"
  template_id     TEXT        NOT NULL REFERENCES euno_issuer.templates (template_id),
  template_version INTEGER    NOT NULL,
  tenant_id       TEXT        NOT NULL,         -- tenant being bound (may differ from owner)
  agent_id        TEXT        NOT NULL,
  role            TEXT        NOT NULL,         -- role name as returned by the IdP
  assigned_by     TEXT        NOT NULL,         -- operatorId from admin JWT
  assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at      TIMESTAMPTZ,                  -- NULL = active; set to soft-revoke
  FOREIGN KEY (template_id, template_version)
    REFERENCES euno_issuer.template_versions (template_id, version),
  PRIMARY KEY (assignment_id)
);

-- Fast lookup on the hot path: given (tenantId, agentId, role) → find active assignment
CREATE INDEX idx_template_assignments_lookup
  ON euno_issuer.template_assignments (tenant_id, agent_id, role)
  WHERE revoked_at IS NULL;

-- Audit: all assignments per template
CREATE INDEX idx_template_assignments_template
  ON euno_issuer.template_assignments (template_id, assigned_at DESC);
```

**Uniqueness constraint:** at most one active assignment per `(tenant_id, agent_id, role)`
triple at any point in time. Enforced at the application layer (check before insert;
return 409 Conflict if an active assignment already exists) rather than a database unique
constraint, so that revoked assignments remain visible in the audit trail.

**Cross-tenant binding:** The `owner_tenant_id` on `templates` and the `tenant_id` on
`template_assignments` may differ — a platform operator may own the template but bind it
to a customer tenant. The admin API MUST enforce that only the owner tenant (or a
platform-level super-admin identity) can manage a template's versions and assignments;
cross-tenant reads are denied (§7.2).

### 3.2 Migration

The three tables are created by `IssuerMigrationRunner.migrate()` — a new class in
`euno-platform/packages/capability-issuer/src/migrations/` modeled on
`PostgresLedgerBackend.migrate()` in `common-infra/src/ledger-signer.ts`. The migration
is idempotent (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`). The issuer
bootstrap calls it on startup when `ISSUER_DB_SCHEMA_INIT=true`.

---

## 4. Admin API Contract — Seven Endpoints

> **MVP anchor:** `docs/stage4executionplan.md` §4.4.

All endpoints are under `/api/v1/admin/templates` and require an operator JWT (same
`Authorization: Bearer <jwt>` pattern as the minter admin routes). The `operatorId` claim
from the JWT is persisted in every mutation as `created_by` / `assigned_by`.

Tenant-scoping is enforced by the issuer: the bearer JWT carries the `tenantId` claim;
every read and write operation is filtered to `owner_tenant_id = :tenantId`.

### 4.1 `POST /api/v1/admin/templates` — Create template

**Request:**
```typescript
{
  name: string;             // ≤ 255 chars, required
  manifest: AgentCapabilityManifest;  // first version (v1) is created atomically
}
```

**Response (201 Created):**
```typescript
{
  templateId: string;
  version: 1;
  policyHash: string;       // SHA-256 of canonical manifest
  createdAt: string;        // ISO-8601
}
```

**Errors:** 400 if `name` is blank or `manifest` fails schema validation; 409 if a
non-deleted template with the same name already exists in the tenant.

**Audit:** `TEMPLATE_CREATED` OCSF authorization event (class_uid 3003) written for
every successful call, including `operatorId`, `templateId`, and `policyHash`.

### 4.2 `GET /api/v1/admin/templates` — List templates

**Query parameters:**
```
ownerTenantId   string    (ignored if present; tenant derived from JWT)
cursor          string    (opaque pagination cursor; base64url of last seen templateId)
limit           integer   (default 50, max 200)
includeDeleted  boolean   (default false)
```

**Response (200 OK):**
```typescript
{
  items: Array<{
    templateId: string;
    name: string;
    latestVersion: number;
    policyHash: string;       // hash of the latest version's manifest
    createdAt: string;
    deletedAt: string | null;
  }>;
  nextCursor: string | null;
}
```

### 4.3 `GET /api/v1/admin/templates/:templateId` — Fetch latest version

**Response (200 OK):**
```typescript
{
  templateId: string;
  name: string;
  version: number;
  manifest: AgentCapabilityManifest;
  policyHash: string;
  createdAt: string;
  createdBy: string;
  deletedAt: string | null;
}
```

**Errors:** 404 if the template does not exist or belongs to a different tenant.

### 4.4 `GET /api/v1/admin/templates/:templateId/versions/:version` — Fetch specific version

Same response shape as §4.3 but for the requested `version`. Returns 404 if the version
does not exist.

### 4.5 `POST /api/v1/admin/templates/:templateId/versions` — Append new version

**Request:**
```typescript
{
  manifest: AgentCapabilityManifest;
}
```

**Response (201 Created):**
```typescript
{
  templateId: string;
  version: number;          // new version number (previous + 1)
  policyHash: string;
  createdAt: string;
}
```

**Errors:** 404 if template not found; 409 if the template is soft-deleted (must undelete
via a separate operation, not yet part of Stage 4 scope); 400 on manifest schema failure.

**Audit:** `TEMPLATE_VERSION_APPENDED` event.

### 4.6 `POST /api/v1/admin/templates/:templateId/assign` — Assign to agents

**Request:**
```typescript
{
  bindings: Array<{
    tenantId: string;       // may equal ownerTenantId or a managed customer tenant
    agentId: string;
    role: string;
    version?: number;       // defaults to latest non-deleted version
  }>;
}
```

**Response (200 OK):**
```typescript
{
  created: Array<{ assignmentId: string; tenantId: string; agentId: string; role: string; version: number }>;
  skipped: Array<{ tenantId: string; agentId: string; role: string; reason: 'already_assigned' }>;
}
```

**Errors:** 404 if template not found; 400 if `bindings` is empty or any binding fails
validation; 409 (surfaced in `skipped`, not as an HTTP error) for duplicates.

**Cross-tenant guard:** if any `tenantId` in `bindings` differs from the operator's own
tenant, the operator JWT must carry the `platformAdmin: true` claim; otherwise the
endpoint returns 403 for the offending bindings and does not create any.

**Audit:** one `TEMPLATE_ASSIGNED` OCSF event per created binding.

### 4.7 `DELETE /api/v1/admin/templates/:templateId` — Soft-delete

**Response (200 OK):**
```typescript
{
  templateId: string;
  deletedAt: string;
}
```

**Behaviour:** sets `deleted_at = NOW()` on the `templates` row. Existing assignments and
in-flight tokens are unaffected. After deletion, no new assignments may be created and no
new version may be appended to this template.

**Errors:** 404 if not found; 409 if already deleted (idempotent-safe: clients may treat
409 as success when the deletion was already complete).

**Audit:** `TEMPLATE_DELETED` OCSF event.

---

## 5. UI Shape — Server-Rendered Admin Pages

> **MVP anchor:** `docs/stage4executionplan.md` §4.4 (closing paragraph), §Task 7.

### 5.1 Decision

**Server-rendered pages under `web/admin/`**, served by the issuer's Express process
behind the same IdP guard as `POST /api/v1/issue`.

### 5.2 Rationale

| Criterion | Server-rendered (`web/admin/` in issuer) | Separate SPA |
|---|---|---|
| Auth story | User is already authenticated to the issuer (OAuth session from `euno request` or direct IdP login); session cookie flows naturally | Requires a separate PKCE flow or token hand-off between the SPA origin and the issuer |
| Build pipeline | No additional build/deploy pipeline; HTML is rendered by the existing Express server | New build step (Vite/Next/etc.), new deployment target, new CDN config |
| Scope alignment | Four pages: list, create, detail/version-history, assignment. Does not justify a full SPA pipeline | — |
| Stage 5 SPA option | Decision preserved: if the UI grows beyond four pages or a design partner requests a polished SPA, the migration path is to extract the admin pages into a Next.js app that calls the same admin API endpoints (contract-stable) | — |

The four pages are:

1. **List** — table of templates for the authenticated tenant, with pagination, delete
   action, and a "New template" button.
2. **Create / edit** — form with `name` + a JSONB/YAML editor for `manifest`.
3. **Version history** — list of versions for a template with `policyHash` and `createdAt`.
4. **Assignments** — form to assign the template to `(agentId, role)` pairs; table of
   active assignments with revoke action.

All UI calls go through the admin API endpoints documented in §4. There are no
UI-specific endpoints.

---

## 6. KMS Key Alias Isolation

> **MVP anchor:** `docs/stage4executionplan.md` §Task 0 — "The decision on whether the
> API-key minter and the issuer share the same KMS root key alias or use distinct aliases."
> `docs/mvp.md` §"Minter threat model" (lines 660–691).

### 6.1 Decision

**Distinct key aliases per service.** The API-key minter and the capability issuer use
separate key aliases in the HSM:

| Service | Key alias convention |
|---|---|
| API-key minter | `euno-minter-tenant-<tenantId>` (unchanged from Stage 3) |
| Capability Issuer | `euno-issuer-tenant-<tenantId>` |

### 6.2 Rationale

**Blast-radius separation:** a compromise of the issuer's workload identity (which holds
`sign` permission on issuer keys) does not grant the ability to forge minter-signed tokens,
and vice versa. This is the primary motivation.

**Operational separation:** key rotation for the issuer can proceed independently from
the minter. A minter key rotation (e.g., due to API-key leak forensics) does not require
touching issuer keys.

**Token distinguishability:** tokens minted by the minter and tokens minted by the issuer
carry different `kid` values. The gateway verifier already resolves keys by `kid` from the
JWKS endpoint — no gateway change is needed. Both services publish to the same JWKS
endpoint (or distinct ones — to be confirmed in Task 2), but their keys are distinct
entries.

**Cost trade-off acknowledged:** per-tenant key creation is `O(tenants)` for each
service, so two services means `O(2 × tenants)` HSM keys. Azure Managed HSM, AWS KMS,
and GCP Cloud KMS all support thousands of keys without additional hardware cost
penalties; latency is per-operation, not per-key. The blast-radius benefit outweighs
the modest cost increase.

**Self-host degraded mode (single-tenant):** self-host operators who cannot afford two
key aliases may reuse the same local EC key for both services. This is explicitly only
supported for single-tenant deployments and is documented with a warning in
`docs/security/issuer-identity-threat-model.md` §"Self-host operator key management".

---

## 7. Seam Additions in `@euno/common-core`

> **MVP anchor:** `docs/stage4executionplan.md` §4.1 — "Stage 4 introduces no new seam
> types in `@euno/common-core` unless a gap is identified during Task 0."

### 7.1 Decision

**Zero new seam types.** All Stage 4 functionality fits within the existing seams:

| Seam | Used by Stage 4 | Location |
|---|---|---|
| `IdentityAdapter` | IdP integration (Task 2) | `@euno/common` |
| `TokenSigner` / `KmsTokenSigner` | Issuer signing (reused from Stage 3) | `@euno/common-infra` |
| `RoleCapabilityPolicy` + `DEFAULT_ROLE_CAPABILITY_MAP` | Role-to-capability mapping (Task 3) | `@euno/common` |
| `AgentCapabilityManifest` | Template manifest type | `@euno/common-core` |
| `UsageMeter` | Per-user issuance metering (Task 10) | `@euno/common` |
| `AuditEntry` / `AuditLogEntry` | Issuer audit trail (existing) | `@euno/common` |

No new types are introduced in `@euno/common-core`. All template-specific types
(`TemplateRecord`, `TemplateVersionRecord`, `TemplateAssignment`) are local to the
issuer package (`euno-platform/packages/capability-issuer/`) and do not need to be
shared across the dependency boundary.

**If a gap is identified during Task 2–6 implementation:** the task author must raise the
gap as a PR comment against this document and obtain sign-off from the Task 0 RFC authors
before adding any type to `@euno/common-core`. The dependency-direction CI gate from
Stage 0 Substage 0.4 will catch accidental cross-license additions.

---

## 8. Cross-Links to `docs/mvp.md` Stage 4 Anchors

| Decision | `docs/mvp.md` anchor |
|---|---|
| Entra ID + AWS Cognito as the two hosted IdPs | §"Stage 4: What ships" lines 724–748 |
| Token attenuation and renewal as live, supported endpoints | §"Stage 4: What ships" line 736 |
| Role-to-capability mapping | §"Stage 4: What ships" line 737 |
| `euno request` / `euno validate-token` wired to live issuer | §"Stage 4: What ships" lines 738–740 |
| Manifest templates surfaced in the UI | §"Stage 4: What ships" lines 741–742 |
| Self-host parity (issuer in docker-compose) | §"Stage 4: What ships" (implicit); `docs/stage4executionplan.md` §4.6 |
| Per-user metering via existing `UsageMeter` interface | `docs/stage4executionplan.md` §Exit Criteria E10 |
| Zero new seam types in `@euno/common-core` | `docs/stage4executionplan.md` §4.1 + §"Cross-cutting obligations" §1–2 |
| KMS key alias isolation | `docs/stage4executionplan.md` §Task 0 |
| Server-rendered UI shape | `docs/stage4executionplan.md` §4.4, §Task 7 |

---

## 9. Review Checklist

Sign-off requires ≥2 engineers + 1 security reviewer outside the implementer. Each
reviewer should verify:

- [ ] **§1 (IdP):** Cognito selection is justified; no additional adapter work is required
  before Task 2 starts; the configuration surface is complete.
- [ ] **§2 (Feature matrix):** Tier assignments are consistent with `docs/mvp.md`
  §"Pricing & business model sketch"; no Stage 3 tier assignment has regressed.
- [ ] **§3 (Postgres schema):** Tables are normalised; indexes cover the hot-path
  issuance query (`template_assignments_lookup`); cross-tenant isolation is enforced
  at the application layer and documented.
- [ ] **§4 (Admin API):** All seven endpoints are specified to the same precision as
  `docs/stage-3-design.md` §6; error cases and audit events are enumerated.
- [ ] **§5 (UI shape):** Server-rendered decision is consistent with Stage 4 scope; the
  path to SPA in Stage 5 is not blocked.
- [ ] **§6 (KMS isolation):** Distinct aliases are operationally feasible; self-host
  degraded mode is correctly scoped to single-tenant only.
- [ ] **§7 (Seam additions):** Zero additions confirmed; gap-escalation procedure is
  documented.
- [ ] **Threat model:** `docs/security/issuer-identity-threat-model.md` is approved
  (Task 1 gate) before any IdP wiring code (Tasks 2, 3) merges.

| Reviewer | Role | Date | Notes |
|---|---|---|---|
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Security | _(date)_ | |

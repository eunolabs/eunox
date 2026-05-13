# Issuer Identity Threat Model

> **Status:** Pending sign-off (requires ≥2 engineers + 1 security reviewer outside the
> implementer before any customer-facing IdP integration code merges to `main` —
> see [stage4executionplan.md §Task 1](../stage4executionplan.md).
>
> **Last updated:** 2026-05-13
>
> **Authors:** _(add names at review)_
>
> **Reviewers:** _(add names + dates at sign-off)_

---

## Background

The API-key minter threat model ([`docs/security/minter-threat-model.md`](./minter-threat-model.md))
covered the case where a managed signing authority with high blast radius if the minter
service identity is compromised signs tokens on behalf of opaque API keys (the minter
uses per-tenant HSM keys, so the blast radius of an individual key compromise is one
tenant, but a compromise of the minter *service identity* can request signatures across
all tenants that identity can reach). Stage 4 promotes the capability issuer from an
internal token factory to a first-class user-facing service that accepts authenticated
end-users via enterprise Identity Providers (Entra ID, AWS Cognito) and mints signed
capability tokens bound to their verified identity and role.

This changes the attack surface in three important ways relative to Stage 3:

1. **A new authentication path** (IdP OAuth/OIDC) is now on the critical path to token
   issuance. A compromise of the IdP's app registration or OIDC endpoint is now a direct
   capability-token issuance vector.
2. **Human user identity is now embedded in tokens** (`authorizedBy.userId`). Privilege
   escalation via role-mapping manipulation is a meaningful new attack class.
3. **Admin-mutable manifest templates** are introduced. A malicious or misconfigured
   template can silently widen every user's capability set for a given `(tenantId,
   agentId, role)` triple.

This document answers every question required by
[`docs/stage4executionplan.md` §5](../stage4executionplan.md#5-threat-model-addendum-blocking--task-1)
before customer-facing IdP integration may ship. The question headers below are verbatim
from §5 of the execution plan.

---

## 1. IdP Compromise

**Question from §5:** *If an attacker compromises a tenant's Entra ID app registration,
what tokens can they obtain? What is the blast radius? What detection capability exists?
Document required tenant-side IdP hygiene (conditional access, app-role review cadence).*

### 1.1 What tokens can an attacker obtain?

The issuer's `IssueController` issues tokens only after successfully completing all of
the following steps in order (see `issuance/issue-controller.ts`):

1. **IdP token validation** — the caller's `authToken` is verified against the IdP's JWKS.
2. **Role resolution** — roles are read from the verified IdP token's claims.
3. **Rate-limit enforcement** — per `(tenantId, userId, agentId, ip)` budget checked.
4. **Manifest/consent/Conditional Access validation** — capabilities derived from roles,
   not from the request body.
5. **KMS signing** — only after all checks pass.

If an attacker has compromised a tenant's Entra ID app registration to the degree that
they can obtain valid ID tokens bearing a real user's roles (e.g., by registering a
redirect URI for their own server), they can:

- Obtain capability tokens for **any user and role** reachable through that app
  registration, subject to the issuer's rate limits.
- Specifically: if the app registration has no Conditional Access policy restricting
  sign-in, the attacker can obtain tokens for all users in the tenant directory.

What the attacker **cannot** do via IdP compromise alone:

- Elevate roles beyond what the IdP token claims — the issuer always derives roles from
  the verified token, never from the request body (§3).
- Bypass issuance rate limits (§3.1 in this document).
- Sign tokens outside the tenant's registered capability scope.
- Access the KMS signing key directly — the issuer's workload identity holds only
  `sign` permission on the issuer's keys, not the minter's keys (distinct aliases, per
  `docs/stage-4-design.md` §6).

### 1.2 Blast radius

| Compromised entity | Blast radius |
|---|---|
| Tenant's Entra ID app client secret | Attacker can impersonate any user in the tenant's directory and obtain capability tokens at the roles that user holds. Bounded by the issuer's per-user rate limit and token TTL (≤ 15 min default). |
| Tenant's Entra ID app registration redirect URI | Code-injection attack on the PKCE flow: attacker can steal auth codes when users are tricked into a login flow. Mitigated by PKCE S256 (the issuer enforces `code_challenge_method=S256`; stolen codes are useless without the `code_verifier`). |
| Entra ID tenant admin account (full directory access) | Attacker can modify app roles, add users to roles, or bypass Conditional Access policies. This is a platform-level IdP compromise; the issuer's controls cannot substitute for IdP hygiene (§1.4 below). |
| AWS Cognito User Pool admin credentials | Attacker can add users to groups (which map to roles). Same scope as Entra admin account compromise — bounded per-tenant by Cognito pool separation. |

**Per-tenant containment:** each tenant's app registration is scoped to that tenant's
directory or Cognito pool. A compromise of one tenant's IdP configuration does not
affect other tenants' tokens unless the issuer's multi-tenant deployment shares a
single app registration (which it must not — see §1.4).

### 1.3 Detection capability

| Signal | Source | Alert threshold |
|---|---|---|
| Issuance volume spike | `euno_issuer_issue_total{tenantId}` Prometheus counter | >2× 1-hour moving average for the tenant → PagerDuty |
| Issuance from new `userId` | Issuer audit log `ISSUANCE` events | First appearance of a `userId` not seen in the prior 30 days → low-priority alert for operator review |
| Issuance outside business hours | Issuer audit log time-of-day | Off-hours spikes combined with new userId trigger medium-priority alert |
| IdP sign-in anomaly | Azure AD Sign-in Logs / Cognito CloudTrail | Cross-reference with issuer audit log to confirm whether anomalous sign-in resulted in a capability token |
| KMS sign operation count | Azure Monitor / CloudTrail / Cloud Audit Logs | KMS sign-ops per tenant > threshold → same PagerDuty escalation as for the minter |
| `kid` mismatches in gateway | `euno_gateway_token_verify_error_total` | A surge in `JWKS_KEY_NOT_FOUND` errors suggests tokens are being produced with an unknown key |

The issuer writes one `ISSUANCE` audit row per token (logged as `AuditLogEntry` via the
`auditLogger` injected into `IssueController`). The row includes:
`userId`, `agentId`, `tenantId`, `tokenId` (jti), `capabilities`, `iat`, `exp`, and the
`idpProvider` label (`"azure"` or `"cognito"`) in the `context` map — see
`docs/stage4executionplan.md` §4.7.

### 1.4 Required tenant-side IdP hygiene

**Mandatory (operator must verify at onboarding):**

1. **Distinct app registration per tenant.** The issuer's hosted deployment creates one
   Entra ID app registration per tenant and one Cognito app client per User Pool. A
   shared registration would collapse all tenants' blast radii into one.

2. **App roles are reviewed at onboarding and on a defined cadence (90 days).** The
   operator must document which app roles map to which issuer capability roles in the
   tenant's onboarding runbook. Any role not in the issuer's `RoleCapabilityPolicy` is
   silently dropped at token issuance (the issuer does not fail on unknown roles; it
   simply issues no capabilities for them). Stale roles that map to sensitive capabilities
   must be pruned.

3. **Conditional Access policy is required for Team/Enterprise tenants.** The Entra ID
   app registration MUST be protected by a Conditional Access policy that enforces MFA
   for all sign-ins. The `AzureADIdentityProvider` already evaluates the
   `AzureADConfig.conditionalAccess` block; operators who leave it unconfigured get a
   warning log at startup.

4. **PKCE with S256 only.** The issuer's OAuth callback enforces `code_challenge_method=S256`.
   Implicit flow and `response_type=token` are not permitted. The app registration in
   Entra ID must have "Allow public client flows" disabled (or set to "No") to prevent
   silent fallback to the implicit flow.

5. **Redirect URI allowlist.** Only `http://localhost:<port>/callback` (for `euno request`)
   and the issuer's own `https://issuer.euno.example/api/v1/callback` may appear in the
   app registration's redirect URI list. Wildcards are forbidden.

6. **Client-secret rotation.** App client secrets must be rotated on a 90-day schedule
   and on any suspected exposure. The issuer's bootstrap validates that the configured
   client secret is not the default placeholder.

---

## 2. IdP-Token Replay Against the Issuer

**Question from §5:** *Confirm the issuer rejects re-used IdP authorization codes (PKCE
state binding), enforces `nonce`, and validates `aud`/`iss`/`exp`/`iat` of the IdP's ID
token before consulting the role mapping.*

### 2.1 PKCE state binding and authorization code single-use

The `euno request` CLI command implements the PKCE S256 flow:

1. A cryptographically random `code_verifier` (≥ 43 characters of URL-safe base64url
   entropy) is generated per authorization session.
2. `code_challenge = BASE64URL(SHA256(code_verifier))` is sent to the IdP in the
   authorization request.
3. The token exchange at the issuer's callback (`POST /api/v1/issue` or the OAuth
   redirect handler) sends the `code_verifier` alongside the `code`.
4. The IdP verifies `SHA256(code_verifier) == code_challenge` before issuing an ID token.
   A replayed authorization `code` without the matching `code_verifier` is rejected by
   the IdP. Because the `code_verifier` is ephemeral in the CLI process and never
   persisted to disk, an attacker who intercepts the authorization `code` (e.g., via
   redirect-URI manipulation) cannot exchange it for a token.

The issuer itself does not store or re-verify authorization codes after the IdP exchange
completes; all replay protection for `code` exchange lives at the IdP. The issuer receives
the post-exchange ID token and applies the validations below.

### 2.2 `nonce` enforcement

The issuer includes a `nonce` claim in every authorization request sent to the IdP:
`nonce = BASE64URL(RANDOM_32_BYTES)`, stored in the ephemeral PKCE state.

On receiving the ID token from the IdP, the issuer verifies:
- `nonce` in the ID token matches the `nonce` sent in the authorization request.
- The `nonce` has not been seen before. The nonce deduplication store operates in one
  of two modes:
  - **Redis not configured** (single-replica deployments): an in-process LRU cache
    with TTL = max IdP token lifetime + 60 seconds is used. This provides adequate
    replay protection for single-process deployments and is acceptable in development.
  - **Redis configured**: the nonce is checked and recorded in Redis with the same TTL.
    This is required for multi-replica hosted deployments, where an in-process cache
    would miss replays routed to a different pod.

**Fail-closed when Redis is configured but unavailable:** if the issuer is configured
to use Redis for nonce deduplication (`ISSUER_NONCE_REDIS_URL` or `REDIS_URL` is set)
and the Redis connection fails at issuance time, the issuer rejects the request with
`NONCE_STORE_UNAVAILABLE` → 503. Falling back to the in-process cache when Redis is
down would allow replay across pods, which defeats the purpose of Redis deduplication.
The in-process fallback is **only** active when Redis is not configured at all.

### 2.3 ID-token claim validation

The `AzureADIdentityProvider` and `AWSCognitoIdentityProvider` both perform full
JOSE validation via the `jose` library before returning a `UserContext`:

| Claim | Validation |
|---|---|
| `aud` | Must exactly match the configured `AZURE_AD_CLIENT_ID` (for Entra ID) or `AWS_COGNITO_CLIENT_ID` (for Cognito ID tokens; access tokens are verified via the `client_id` claim instead). Validation rejects the token if the audience is absent or is an array that does not include the expected value. |
| `iss` | Must exactly match the tenant's configured OIDC issuer URL (e.g., `https://login.microsoftonline.com/<tid>/v2.0` or `https://cognito-idp.<region>.amazonaws.com/<poolId>`). |
| `exp` | Must be in the future; the issuer applies a 60-second clock-skew tolerance. Tokens more than 60 seconds past their `exp` are rejected. |
| `iat` | Must be in the past; the issuer rejects tokens with an `iat` more than 60 seconds in the future (anti-clockskew-future). |
| Signature | Verified against the IdP's JWKS endpoint. The `AzureADIdentityProvider` and `AWSCognitoIdentityProvider` use `jose.createRemoteJWKSet()`, which handles caching and refresh internally. The gateway's own JWKS verifier (for capability tokens) uses `EUNO_JWKS_CACHE_TTL_SECONDS` (existing config, default 300 s; defined in `public/packages/common/src/config/schema.ts`). The IdP-side JWKS refresh interval for the issuer's identity providers is controlled by `jose.createRemoteJWKSet()`'s internal defaults; Task 2 must wire an explicit cache TTL option and document the corresponding env var if configurable behaviour is required. A failed JWKS refresh does not invalidate the current cache (fail-safe for JWKS endpoint flaps); the issuer rejects tokens only if no cached JWKS is available at all. |
| `alg` | Only `RS256` and `ES256` are accepted. `none` and symmetric algorithms (`HS256`, etc.) are explicitly rejected. |

Validation is performed **before** any role lookup or capability derivation. If any
claim fails, the issuer returns 401 and logs the rejection without consulting the
`RoleCapabilityPolicy`.

---

## 3. Role-Mapping Privilege Escalation

**Question from §5:** *A user with role X requests a token; can they craft a request that
resolves to role Y's manifest? The `IssueController` must derive the role from the
verified IdP token, never from the request body. Test: a request that includes
`role: admin` but whose IdP token contains `role: viewer` resolves to viewer.*

### 3.1 Role derivation is always from the verified IdP token

The issuance pipeline in `IssueController.handle()` derives capabilities as follows:

```typescript
// Step 1: Validate the user's authentication token (IdP JWKS verification)
const userContext = await this.identityProvider.validateToken(request.authToken);

// Step 2: Map roles from the VERIFIED userContext to capabilities
let capabilities = mapRolesToCapabilitiesForPolicy(
  userContext.roles,   // <── from IdP token, never from request body
  this.policy,
  userContext.tenantId,
);
```

The `request.authToken` is the caller's IdP-issued token. The caller may not supply
`roles` or `tenantId` directly; those are extracted from the token by the identity
provider. The only caller-supplied fields that influence capability scope are:

- `request.requestedCapabilities`: the caller may request a **subset** of their
  role-derived capabilities (attenuation). The issuer validates that every requested
  capability is within the role-derived set (`assertRequestedWithinRoleScope`). A caller
  who requests a capability not in their role-derived set receives 403.

There is no API field that accepts a caller-supplied role name.

### 3.2 Required test (verbatim from §5)

A request where the JSON body includes `role: "admin"` (or any `requestedCapabilities`
derived from admin roles) but whose IdP token contains only `roles: ["viewer"]` MUST
resolve to the `viewer` capability set, not the `admin` set.

This is covered by `euno-platform/packages/capability-issuer/tests/issuer-role-privilege-escalation.test.ts`
(to be created in Task 2 as part of the negative-test requirement). The test:

1. Mocks an IdP token with `roles: ["viewer"]`.
2. Sends a `POST /api/v1/issue` request body that includes `requestedCapabilities`
   corresponding to admin-role capabilities.
3. Asserts the response is 403 (`INSUFFICIENT_PERMISSIONS`).
4. Asserts no KMS signing call was made.

### 3.3 Template-assignment escalation path

When a template assignment exists for `(tenantId, agentId, role)`, the resolved manifest
comes from the template, not from `RoleCapabilityPolicy`. The role used for the template
lookup comes from the verified IdP token (`userContext.roles`) — not from the request
body. The issuance flow (Stage 4 Task 6 addition to `IssueController`) is:

1. Resolve `userContext.roles` from the verified IdP token.
2. For each role in `userContext.roles`, query `template_assignments` for
   `(tenantId = userContext.tenantId, agentId = request.agentId, role = :role)`.
3. If an active assignment exists, use that template's manifest.
4. Otherwise fall back to `RoleCapabilityPolicy`.

A caller who supplies `agentId` in the request body but whose IdP token does not
authorise them for that agent receives 403 (no matching capabilities in either branch).
The `agentId` is validated against the role-derived capability set in
`assertRequestedWithinRoleScope` — a caller cannot request an agent they are not
authorised for.

---

## 4. Manifest Template Tampering

**Question from §5:** *Templates are admin-mutable. Document the admin-role authorisation
model (must reuse the operator-JWT pattern from `api-key-minter` admin routes per
`MinterConfigSchema` admin JWT auth — see Stage 3 admin JWT integration), the audit trail
per template mutation, and the rollback procedure if a malicious template is published.*

### 4.1 Admin-role authorisation model

The template admin API (§4 of `docs/stage-4-design.md`) is protected by the same
operator-JWT guard used in `api-key-minter` admin routes:

- **Bearer token:** `Authorization: Bearer <jwt>` where the JWT is issued by an
  operator identity provider configured via `ISSUER_ADMIN_JWKS_URI` +
  `ISSUER_ADMIN_JWT_AUDIENCE` (mirroring `MINTER_ADMIN_JWKS_URI` /
  `MINTER_ADMIN_JWT_AUDIENCE` in the minter).
- **Required claims:** `sub` (operatorId, persisted in audit), `aud` (must match
  `ISSUER_ADMIN_JWT_AUDIENCE`), `iss` (must match the configured admin JWKS issuer),
  `exp` (must be in the future).
- **`platformAdmin` claim:** required for cross-tenant assignment operations (per
  `docs/stage-4-design.md` §4.6).
- **Fallback:** `X-Admin-Key` header is accepted only as a deprecated fallback for
  self-hosters who have not yet configured an admin JWKS. It emits a `warn` log and is
  rejected in production (`NODE_ENV=production`) unless `ISSUER_ADMIN_API_KEY` is set
  and the value is ≥32 characters and not the literal `dev-admin-key`.

Every admin JWT verification failure returns 401; no mutation is performed.

### 4.2 Audit trail per template mutation

Every mutation to the template store writes an OCSF authorization event (class_uid 3003)
to the issuer's audit log (same `PostgresLedgerBackend` as the gateway, per
`docs/stage4executionplan.md` §4.7):

| Operation | `eventType` | Fields logged |
|---|---|---|
| Create template | `TEMPLATE_CREATED` | `operatorId`, `templateId`, `name`, `policyHash` |
| Append version | `TEMPLATE_VERSION_APPENDED` | `operatorId`, `templateId`, `version`, `policyHash` |
| Assign | `TEMPLATE_ASSIGNED` | `operatorId`, `assignmentId`, `templateId`, `version`, `tenantId`, `agentId`, `role` |
| Soft-delete | `TEMPLATE_DELETED` | `operatorId`, `templateId`, `deletedAt` |

The audit log is append-only (same tamper-evident HMAC chain as the gateway's
`LedgerAuditEvidenceSigner`). An attacker who can write to the Postgres database
directly cannot forge valid HMAC values without also compromising the audit sidecar's
secret (two separate compromises required — per `docs/security/minter-threat-model.md`
§6).

### 4.3 Rollback procedure for a malicious or misconfigured template

If a malicious template is published (e.g., via a compromised operator JWT or a
misconfigured manifest that widens capabilities):

1. **Immediate:** Soft-delete the offending template via
   `DELETE /api/v1/admin/templates/:templateId`. This prevents the template from
   being used for new issuances immediately (the issuer checks `deleted_at IS NULL` on
   every issuance lookup).

2. **Active tokens:** Existing tokens already issued under the malicious template remain
   valid until their `exp`. Use the issuer's audit log to enumerate all `jti` values
   issued with the affected `policyHash` (the `ISSUANCE` audit row includes `policyHash`
   in its `payload` JSONB). The issuer writes to the same `euno_audit_ledger` table used
   by the gateway (configurable via `PostgresLedgerOptions.table`; default
   `euno_audit_ledger`):

   ```sql
   SELECT payload->>'capabilityId' AS token_id,
          payload->>'userId'       AS user_id,
          payload->>'agentId'      AS agent_id
   FROM euno_audit_ledger
   WHERE payload->>'policyHash' = :affected_policy_hash
     AND payload->>'decision'   = 'allow'
   ORDER BY created_at DESC;
   ```

3. **Revoke in-flight tokens:** Post each `jti` to the gateway's revocation endpoint
   (the same bulk-revoke path used for minter key rotation in
   `docs/security/minter-threat-model.md` §3).

4. **Kill switch (if scope is broad):** If the number of affected tokens is large or
   the compromise window is unclear, activate a tenant-scoped kill switch
   (`POST /admin/v1/kill-switch/tenant`) immediately, then revoke individual JTIs and
   lift the kill switch once the revocation set is confirmed complete.

5. **Audit and notify:** The soft-delete is logged (`TEMPLATE_DELETED`) with the
   `operatorId` who performed it and a reason code. Affected users (as resolved from the
   `userId` fields in the issuance audit) are notified per the tenant's incident response
   procedure.

6. **Republish corrected template:** Once the malicious template is deleted and in-flight
   tokens are revoked, a corrected template may be published as a new `templateId` (not
   a new version of the deleted one, since the deleted template cannot accept new versions).

---

## 5. Cross-Tenant Template Leakage

**Question from §5:** *A template owned by tenant A must never be assignable, listable,
or fetchable by tenant B. Test boundary explicitly.*

### 5.1 Tenant isolation design

All template admin API endpoints derive the acting tenant from the operator JWT's `sub` /
`tenantId` claim, not from the URL or request body:

```
operator JWT.tenantId  →  filter all DB queries by owner_tenant_id = :tenantId
```

The Postgres queries use parameterised `WHERE owner_tenant_id = $1` clauses on every
read and write. A tenant that does not own a template receives 404 (not 403) on any
per-template endpoint, so the existence of other tenants' templates is not disclosed.

Assignment cross-tenant writes (where `bindings[].tenantId` differs from the operator's
tenant) require `platformAdmin: true` in the JWT. Without this claim, the issuer filters
out all cross-tenant bindings from the request and returns 403 for each.

### 5.2 Required tests (verbatim from §5)

The following negative tests MUST be present in
`euno-platform/packages/capability-issuer/tests/template-cross-tenant.test.ts`
(to be created in Task 6):

| Scenario | Expected result |
|---|---|
| Tenant B requests `GET /api/v1/admin/templates/:templateIdOwnedByA` | 404 — template existence not disclosed |
| Tenant B requests `GET /api/v1/admin/templates?ownerTenantId=A` | 200 with empty list — B's JWT filters the query to B's own templates |
| Tenant B attempts `POST /api/v1/admin/templates/:templateIdOwnedByA/versions` | 404 |
| Tenant B attempts `POST /api/v1/admin/templates/:templateIdOwnedByA/assign` | 404 |
| Tenant B (without `platformAdmin`) assigns a template they own to tenant A's agents | 403 — cross-tenant binding requires `platformAdmin` |
| Tenant B (with `platformAdmin`) assigns a template to tenant A's agents | 200 — platform admin may perform cross-tenant operations |

These tests use two distinct `operatorId`/`tenantId` pairs and run against the same
in-memory Postgres instance (using `pg-mem` or a local test schema, matching the
pattern in `capability-issuer/tests/`).

### 5.3 Row-level security consideration

The Stage 4 implementation uses application-layer tenant filtering (parameterised
`WHERE owner_tenant_id = $1` in every query). PostgreSQL Row Level Security (RLS) is
explicitly **not** used in Stage 4 because:

1. The issuer connects with a single service identity that manages the full schema.
2. Adding RLS would require per-tenant connection pooling or `SET LOCAL app.tenant_id`
   gymnastics, complicating PgBouncer integration.
3. Application-layer filtering is audited at the code level via PR review and the
   cross-tenant tests in §5.2.

Stage 5 may revisit RLS if the deployment topology evolves to a multi-tenant managed
Postgres service where row-level isolation is enforced by the database engine.

---

## 6. Per-Tenant Signing-Key Isolation

**Question from §5:** *Re-affirm the Stage-3 decision (per-tenant KMS keys behind a
single root) holds for Stage 4. If the hosted deployment uses platform-wide signing for
cost reasons, document the explicit blast-radius trade-off and the compensating controls.*

### 6.1 Re-affirmation

The Stage-3 decision holds for Stage 4: **per-tenant signing keys, single HSM root.**
Each tenant's issuer tokens are signed by a distinct `euno-issuer-tenant-<tenantId>` key
(see `docs/stage-4-design.md` §6). This is the same architecture as the minter, using
the same three KMS backends (Azure Managed HSM primary, AWS KMS and GCP Cloud KMS
supported).

The issuer uses **distinct key aliases from the minter** (`euno-issuer-tenant-*` vs.
`euno-minter-tenant-*`). A compromise of the issuer's workload identity does not grant
signing rights on minter keys, and vice versa.

### 6.2 Blast radius (hosted product)

| Layer | Mechanism |
|---|---|
| **Per-tenant key isolation** | A compromise of one tenant's signing key cannot forge tokens for another tenant. The gateway's verifier validates `aud`/`iss`/`kid` and rejects tokens whose `kid` does not correspond to the presenting tenant. |
| **Short TTL** | Default token TTL is 15 minutes (900 seconds). Even with a compromised key, the window for valid-but-attacker-controlled tokens is bounded. |
| **Revocation** | The gateway's `RevocationStore` covers the unexpired window. On key compromise, bulk-revoke all JTIs in the issuer audit log signed with the compromised `kid`. |
| **Issuer workload identity segmentation** | The issuer's workload identity holds `sign` permission only on `euno-issuer-tenant-*` keys — not on `euno-minter-tenant-*` keys or any other tenant's issuer key. |
| **HSM admin identity separation** | Key creation, rotation, and access-policy changes require the separate HSM admin identity (two-person approval) per `docs/security/minter-threat-model.md` §1. |

### 6.3 Deferred platform-wide signing option (explicitly rejected for hosted)

Using a single platform-wide signing key for cost reasons is explicitly **rejected** for
the hosted product:

- Blast radius: a single compromised key can forge tokens for all tenants.
- Audit granularity: a per-tenant key allows correlating HSM sign operations to a
  specific tenant in the cloud provider's audit log.
- Regulatory: several enterprise compliance frameworks (SOC 2, ISO 27001) require
  per-customer key material separation for SaaS platforms with signing authority.

If a future cost analysis shows per-tenant KMS keys are prohibitively expensive at scale
(>10,000 tenants), the preferred mitigation is a hardware-backed key hierarchy
(per-tenant derived keys from a root key held in an HSM), not collapsing to a single key.
This decision point would be documented at Stage 5 design time.

---

## 7. Self-Host Operator Key Management

**Question from §5:** *Single-tenant self-host operators may not have an HSM. Document
the supported degraded mode (file-based EC key with strong file perms + offline backup)
and explicitly mark it "not supported for multi-tenant".*

### 7.1 Supported degraded mode — file-based EC key (single-tenant only)

When no KMS provider is configured (`ISSUER_KMS_PROVIDER` is absent), the issuer falls
back to a local EC P-256 key stored as a PEM file:

```
ISSUER_SIGNING_KEY_FILE=/run/secrets/issuer-signing-key.pem
# OR
ISSUER_SIGNING_KEY_PEM=<base64url of PEM>
```

**Required file permissions:** `0600` (owner read/write only). The issuer startup routine
checks the file permissions and refuses to start if the file is group- or world-readable:

```
Error: ISSUER_SIGNING_KEY_FILE has unsafe permissions (got 0644, want 0600).
  Fix: chmod 0600 /run/secrets/issuer-signing-key.pem
```

**Key generation (operator runbook):**

```bash
# Generate a P-256 EC key
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt -out issuer-signing-key.pem
chmod 0600 issuer-signing-key.pem

# Verify the key type before use
openssl pkey -in issuer-signing-key.pem -noout -text | grep "Private-Key"
# Expected: Private-Key: (256 bit)
```

**Offline backup:** the PEM file MUST be backed up to an offline medium (encrypted
USB, printed QR code in a physically locked location) before the issuer starts serving
traffic. Loss of the signing key means:
- All in-flight tokens become unverifiable once the JWKS endpoint changes.
- A replacement key must be published to the JWKS endpoint and all previously issued
  tokens must be revoked.

The self-host documentation (`docs/self-host.md`, Stage 4 section) includes a recovery
procedure for key loss scenarios.

### 7.2 Explicit: "Not supported for multi-tenant"

> ⚠️ **File-based EC key storage is not supported for multi-tenant deployments.**
>
> In a multi-tenant deployment, all tenants' tokens would be signed by the same key.
> A single file-permission error, container escape, or backup leak exposes a key that
> can forge tokens for every tenant in the deployment. Multi-tenant deployments MUST
> use a KMS-backed signing key (`ISSUER_KMS_PROVIDER=azure|aws|gcp`) with per-tenant
> key aliases.

Self-hosters operating a single-tenant deployment (one company, one set of users) may
use the file-based mode for development and for production deployments where HSM cost
is prohibitive. They must acknowledge this trade-off in their deployment configuration
(a boolean `ISSUER_ACCEPT_FILE_KEY_FOR_SINGLE_TENANT=true` env var that the startup
guard requires when no KMS provider is configured, ensuring the operator has read the
warning).

### 7.3 OS keychain integration (Stage 5)

OS keychain integration (macOS Keychain, Linux `libsecret`, Windows DPAPI) is explicitly
**deferred to Stage 5**:

- The `keytar` / `@aws-sdk/credential-provider-node` ecosystem varies in reliability
  and CI support across platforms.
- For a server-side issuer process, OS keychain integration provides minimal additional
  security over a `0600` PEM file on a dedicated server (both require root access to
  extract).
- The more valuable control for Stage 5 is a lightweight self-host HSM option
  (e.g., YubiHSM 2 or AWS CloudHSM local client), which is documented as a Stage 5
  goal in `docs/stage4executionplan.md` §"Non-goals".

This decision is documented here so it is not relitigated in Stage 4 task PRs.

---

## 8. CLI Token Storage at Rest

**Question from §5:** *`~/.euno/tokens/<agent-id>.jwt` written `0600`. Document the
trade-off vs. an OS keychain integration (rejected for v1: keytar/keychain integration
is Stage 5; document this explicitly so it is not relitigated).*

### 8.1 Storage mechanism

Tokens issued by `euno request` are persisted to
`~/.euno/tokens/<agent-id>.jwt` with `0600` permissions (owner read/write only).

The write sequence:

1. Write token to a temporary file in the same directory (`~/.euno/tokens/<agent-id>.jwt.tmp`).
2. `chmod 0600` the temporary file before any content is written.
3. Rename (atomic on POSIX) to the final path.
4. Verify the final file has `0600` permissions; abort and delete if not.

This sequence prevents a race window where the file exists but has world-readable
permissions.

### 8.2 Threat assessment

| Threat | Mitigation |
|---|---|
| Local attacker with access to the developer's home directory | `0600` prevents other users from reading the file. Requires root or the same OS user to extract the token. |
| Malicious process running as the same OS user | Cannot be prevented by file permissions alone. Mitigated by short token TTL (default 15 min) and the fact that the token is scoped to a specific `agentId`. |
| Backup / sync tools (Time Machine, Dropbox, iCloud Drive) | If `~/.euno/tokens/` is inside a synced directory, tokens may be exfiltrated via the sync provider. Operators should add `~/.euno/tokens/` to their `.gitignore` and backup-exclusion list. `euno init` prints a warning if the tokens directory appears to be under a known sync root. |
| Theft of the developer's machine | Disk encryption (FileVault, BitLocker, LUKS) protects at-rest tokens against physical theft. `euno` documentation recommends enabling full-disk encryption. Tokens expire within 15 minutes regardless. |

### 8.3 OS keychain integration explicitly deferred to Stage 5

OS keychain integration (`keytar` for cross-platform, or platform-native DPAPI/Keychain
APIs) is explicitly **not implemented in Stage 4**:

1. **Reliability:** `keytar` and similar wrappers are brittle in CI and in headless
   server environments (e.g., an engineer running `euno request` in a devcontainer or
   remote SSH session has no accessible keychain).
2. **Marginal benefit for short-lived tokens:** a 15-minute token stored in a `0600`
   file provides security equivalent to a keychain entry for the duration of the token's
   usefulness. The keychain adds complexity without a proportionate security gain for this
   TTL.
3. **Not blocking for Stage 4 use cases:** The primary audience for `euno request` is
   developers obtaining tokens for local agent testing. The token is used within minutes
   and discarded.
4. **Stage 5 alignment:** Keychain integration belongs with the broader "enterprise
   developer UX" hardening in Stage 5 (on-prem, SCIM, SOC 2). Implementing it now would
   create a platform-support matrix (macOS/Linux/Windows keychain APIs, CI bypass modes)
   that is out of scope for Stage 4.

This decision is recorded here to prevent it from being raised in code review for every
Stage 4 PR that touches `euno request`.

---

## 9. Sign-Off Process

Sign-off requires ≥2 engineers + 1 security reviewer outside the implementer, identical
to the Stage 3 minter threat model process (`docs/security/minter-threat-model.md`).

**No customer-facing IdP integration code (Tasks 2, 3) merges to `main` until this
document carries all three sign-offs.**

Each reviewer should verify:

- [ ] **§1 (IdP compromise):** blast-radius analysis is complete; tenant-side hygiene
  requirements are enforceable and documented in `docs/issuer-idp-setup.md` (Task 2).
- [ ] **§2 (IdP-token replay):** PKCE S256 is correctly enforced; `nonce` replay
  protection is fail-closed; all five ID-token claims (`aud`, `iss`, `exp`, `iat`,
  `alg`) are validated before role lookup.
- [ ] **§3 (Role-mapping escalation):** `IssueController` never reads roles from the
  request body; the required negative test is committed; template-assignment path
  also derives roles from verified IdP token.
- [ ] **§4 (Template tampering):** admin-route protection reuses operator-JWT pattern;
  every mutation is audited with an OCSF event; rollback procedure is actionable.
- [ ] **§5 (Cross-tenant leakage):** application-layer filtering is correct;
  cross-tenant negative tests are committed; RLS deferral rationale is accepted.
- [ ] **§6 (Per-tenant key isolation):** Stage-3 decision re-affirmed; distinct issuer
  key aliases confirmed in `docs/stage-4-design.md`; platform-wide signing explicitly
  rejected.
- [ ] **§7 (Self-host key management):** file-based degraded mode is correctly scoped
  to single-tenant; startup permission guard is specified; offline backup requirement
  is documented.
- [ ] **§8 (CLI token storage):** `0600` semantics are correctly implemented;
  keychain-deferral rationale is documented; TTL-based mitigations are accurate.

| Reviewer | Role | Date | Notes |
|---|---|---|---|
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Security | _(date)_ | |

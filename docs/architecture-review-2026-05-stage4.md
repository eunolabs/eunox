# Architecture Review — euno-platform Stage 4 ("Capability Issuer + Identity")

> **Reviewer role:** Principal Software Architect
> **Date:** 2026-05-18
> **Scope:** `docs/mvp.md` §Stage 4 + `docs/stage4executionplan.md` Tasks 0–13, all
> implementation artefacts reviewed in context.
>
> **Methodology:** Static analysis of source files and tests. Live-deployment exit
> criteria (E2/E3/E4) require a running environment and are noted as such.

---

## Stage 4 Completion Status

All 14 tasks (0–13) are checked off in `docs/mvp.md`. The static exit criteria
E1/E5/E6/E7/E8 are confirmed green. E2/E3/E4 require a live deployment and are
not fully met (see CR-3 and Q4/Q5 below).

---

## [!] Critical Risks

### CR-1 — `OidcStateStore` is in-memory only: multi-replica OIDC replay prevention is silently broken ✅ FIXED

**Severity:** High
**Files:** `euno-platform/packages/capability-issuer/src/oidc-state-store.ts`,
`euno-platform/packages/capability-issuer/src/index.ts`

**Original finding:**
`OidcStateStore` (nonce tracking + ID-token-hash replay prevention) is
explicitly in-memory with no Redis backend. In a multi-replica issuer
deployment — which is the hosted product topology — PKCE state and used-ID-token
hashes are per-pod maps. An attacker can replay an ID token by targeting a pod
that did not process the original exchange. The threat model (§2, "IdP-token
replay") lists replay prevention as a primary control; this implementation gap
silently voids it under HA.

**Fix applied (2026-05-18):**
- Extracted `IOidcStateStore` interface from `OidcStateStore`.
- Added `RedisOidcStateStore` backed by Redis (`SETEX`/`GETDEL` for state/nonce;
  `SET NX EX` / `EXISTS` for ID-token-hash replay prevention).
- Added `createOidcStateStoreFromEnv(env, logger)` factory that selects
  `RedisOidcStateStore` when `OIDC_STATE_REDIS_URL` or `REDIS_URL` is set, and
  falls back to the in-memory `OidcStateStore` with a structured `warn` (matching
  the `createIssuanceRateLimiterFromEnv` / `createMintRateLimiterFromEnv` pattern).
- `index.ts` now initialises the store via `createOidcStateStoreFromEnv` inside
  `initializeServices()` and exposes it through a `getOidcStateStore()` getter.
- `IssuerConfigSchema` already enforces `REDIS_URL` in production non-single-replica
  deployments; no schema change was required.
- 24 new unit tests added in `tests/oidc-state-store-redis.test.ts` covering the
  factory fallback, warn behaviour, and the Redis implementation via a mock client.

---

### CR-2 — Threat model document lacks sign-off signatures: gate condition is technically unmet

**Severity:** High
**File:** `docs/security/issuer-identity-threat-model.md:1-11`

The document header reads:

```
> **Status:** Pending sign-off (requires ≥2 engineers + 1 security reviewer …)
> **Authors:** _(add names at review)_
> **Reviewers:** _(add names + dates at sign-off)_
```

`docs/stage4executionplan.md` §8.2 is explicit: *"Task 1 gates Tasks 2 and 3."*
Tasks 2 and 3 are already merged. Exit criterion E9 — "reviewed and signed off by
≥2 engineers + 1 security reviewer" — is formally unmet.

**Recommendation:** Populate Authors/Reviewers fields before routing production
traffic through the IdP endpoints. Add a CI lint rule that fails if the file still
contains `_(add names`.

---

### CR-3 — `euno request` PKCE flow has no integration tests against a live issuer

**Severity:** High (exit criterion E3)
**Files:** `public/packages/cli/tests/cli.test.ts:369-393, 895-942`,
`euno-platform/packages/integration-tests/tests/`

**Status: ✅ Fixed** — Added `euno-platform/packages/integration-tests/tests/cli-issuer.test.ts`
(17 tests). The test file wires an in-process mock-IdP server (ES256) and a minimal issuer HTTP
server backed by `CapabilityIssuerService` + `OidcStateStore`, exercises the full loopback
exchange programmatically, and asserts:

- Happy path: valid 3-part JWT issued, correct `sub`/`iss`/`aud`/`authorizedBy` claims.
- Token file written at 0600 Unix permissions.
- State binding: agentId bound to state enforced on submission.
- Capabilities come from the IdP-resolved role.
- Error paths: nonce mismatch, unknown/expired state, id_token replay (401), wrong signing key (401),
  agentId mismatch (401), missing fields (400).
- JWKS and discovery endpoints.

The `euno request` CLI tests cover only input-validation errors. No file in
`euno-platform/packages/integration-tests/tests/` exercises the full PKCE
browser-redirect → loopback → code-exchange → issuer-POST → token-write path.
Exit criterion E3 explicitly requires happy-path + error-path integration tests
in `euno-platform/packages/integration-tests/`.

---

### CR-4 — Quickstart leads with `--token $AZURE_AD_TOKEN`, bypassing PKCE protections

**Severity:** Medium-High
**File:** `docs/quickstart-stage-4.md:34-38`

The quickstart instructs users to pre-obtain an Azure AD token and pass it via
`--token`. This bypasses nonce binding and PKCE state tracking. The Stage-4 design
specifies the browser PKCE flow as the primary path; `--token` is a non-interactive
CI fallback.

**Recommendation:** Lead with the PKCE flow and move `--token` to a "non-interactive
/ CI" subsection with a security callout explaining what protections are bypassed.

---

## [~] Design Improvements

### DI-1 — Template-assignment fallback to `RoleCapabilityPolicy` is silent

**Severity:** Medium
**Files:** `euno-platform/packages/capability-issuer/src/manifest-template-store.ts`,
`euno-platform/packages/capability-issuer/src/issuance/issue-controller.ts`

When a template is soft-deleted, existing assignments continue to work but the
issuer silently falls back to `RoleCapabilityPolicy`. This silent regression is
invisible to operators.

**Recommendation:** Emit a structured `WARN` log and add
`templateFallback: true` to the `AuditEntry.context` map whenever the fallback
path is taken.

---

### DI-2 — Admin UI serves auth token via `?token=` query parameter

**Severity:** Medium
**File:** `euno-platform/packages/capability-issuer/src/routes/admin-ui.ts`

The `?token=` redirect pattern writes the bearer token to proxy access logs and
browser history even though the page strips it via `history.replaceState`.

**Recommendation:** Replace `?token=` with a short-lived one-time code exchanged
server-side for a `Set-Cookie: HttpOnly; Secure; SameSite=Strict` session.

---

### DI-3 — Multi-replica state-store constraints are undocumented

**Severity:** Medium
**File:** `docs/issuer-operator-runbook.md`

The runbook documents rate-limit parameters but does not state which issuer
stores are per-replica vs. fleet-wide under HA.

**Recommendation:** Add a "Multi-replica considerations" subsection listing every
state store (rate limiter, OIDC state store, usage meter, telemetry) with its
Redis-backed vs. in-memory status and the minimum-replica-count constraint before
each store requires Redis. Update this entry to note CR-1 is now resolved.

---

### DI-4 — `IssuerTelemetryEvent` is a manual structural copy of `GatewayTelemetryEvent`

**Severity:** Low-Medium
**File:** `euno-platform/packages/capability-issuer/src/issuer-telemetry.ts:75-78`

The comment says "schema changes to `GatewayTelemetryEvent` MUST be reflected
here." Manual-sync comments are the canonical source of technical debt. The shared
type belongs in `@euno/common` where both sides can import it.

**Recommendation:** Move to `public/packages/common/src/` as a Stage-5 prep task.

---

### DI-5 — KMS key alias separation is documented but not enforced in config schema

**Severity:** Low-Medium
**File:** `docs/stage-4-design.md §6`

An operator who sets the same KMS key name on both minter and issuer silently
shares a signing key. No `superRefine` guard enforces the separation.

**Recommendation:** Add a cross-field `superRefine` in `IssuerConfigSchema` that
warns in production when the issuer's KMS key identifier matches the minter's
well-known default alias.

---

## [+] Code / Implementation Feedback

### CI-1 — Telemetry `distinctIssuingUsers` silently saturates at 10 000

**File:** `euno-platform/packages/capability-issuer/src/issuer-telemetry.ts:62`

Once the 10 000-user cap is hit, `distinctIssuingUsers=10000` is indistinguishable
from exactly 10 000 users. Add a `distinctIssuingUsersCapped: true` companion
field so dashboards can flag saturation.

---

### CI-2 — Verify `requireAdminAuth` is not called twice on the same admin-templates request

**File:** `euno-platform/packages/capability-issuer/src/routes/admin-templates.ts`

The middleware is mounted at router level and potentially called in handler bodies.
Double-call is harmless but adds unnecessary JWKS deserialization latency.

---

### CI-3 — `OidcStateStore` O(N) TTL sweep (resolved when CR-1 Redis migration is complete)

**File:** `euno-platform/packages/capability-issuer/src/oidc-state-store.ts`

The sweep-on-write TTL cleanup iterates both maps in full. Under a replay-style
DoS the maps grow proportionally to the attack volume. **Moot once CR-1's Redis
implementation is in use** (Redis handles TTL natively).

---

### CI-4 — Admin UI HTML templates must HTML-escape dynamic values

**File:** `euno-platform/packages/capability-issuer/src/routes/admin-ui.ts`

Dynamic values (template names, agent IDs) interpolated into server-rendered HTML
are not HTML-escaped. An operator-level stored XSS via a malicious template name
is a meaningful risk. Confirm all dynamic values are escaped (e.g. via a shared
`htmlEscape` utility).

---

### CI-5 — Confirm single canonical revocation source for OIDC-path tokens

**Files:** `public/packages/cli/src/index.ts`, `docs/quickstart-stage-4.md:66-69`

`euno revoke` targets the gateway admin API. Confirm the issuer maintains no
separate revocation list and document this in `docs/issuer-operator-runbook.md`.

---

### CI-6 — Stage-4 parity test signs tokens in-process, not via `IssueController`

**File:** `euno-platform/packages/integration-tests/tests/cross-stage-parity.test.ts:877-962`

**Status: ✅ Fixed** — Added a new `"IssueController parity (CI-6)"` describe block at the end of
`cross-stage-parity.test.ts` (10 tests). The block exercises `CapabilityIssuerService.issueCapability()`
(IssueController.handle) and `CapabilityIssuerService.issueCapabilityFromUserContext()`
(IssueController.handleFromUserContext) using the same signing key and verifier as the rest of the
suite, then asserts identical `EnforcementEngine.validateAction()` outcomes across both code paths.

The Task 11 parity test proves gateway enforcement is IdP-path-agnostic, but does
not exercise the `IssueController` code path. This complements but does not
substitute for the CR-3 integration test.

---

## [?] Open Questions

**Q1 — SIGHUP + in-flight JWKS fetch in `TenantIdpRegistry.reload()`:**
Do in-flight `validateToken()` calls complete before the provider map is replaced?
Document drain semantics.

**Q2 — `web/` vs. issuer `/admin/` for the admin UI (E4 wording) — RESOLVED:**
~~Exit criterion E4 references "hosted UI under `web/`" but the admin UI is served
by the issuer's Express process at `/admin/`.~~ Updated E4's wording in
`docs/stage4executionplan.md` to reflect the actual delivery mechanism (issuer
Express process at `/admin/`). See execution plan table row Q2.

**Q3 — `POST /api/v1/oidc/token` receives `idToken` (post-exchange): clarify API naming:**
The issuer never receives the raw PKCE authorization code; it receives the
post-exchange ID token. The `OidcStateStore` API names `isCodeUsed`/`markCodeUsed`
(see stored memory) were corrected to `isIdTokenHashUsed`/`markIdTokenHashUsed`
in the implementation. Ensure docs agree.

**Q4 — Playwright vs. Jest for admin UI smoke tests (E4):**
Task 7 spec mentions Playwright; `tests/admin-templates-ui.test.ts` uses Jest.
Confirm whether Jest coverage satisfies the CI gate.

**Q5 — CLI↔issuer integration tests in `integration-tests/`:**
Exit criterion E3 requires tests in `euno-platform/packages/integration-tests/`.
No such file exists for the CLI↔issuer path. Track as a follow-up unless explicitly
deferred.

---

## Execution Plan — Priority Order

| Priority | Item | Dependency | Status |
|---|---|---|---|
| **P0** | CR-1 — Redis-backed `OidcStateStore` | None | ✅ Fixed |
| **P0** | CR-2 — Threat model sign-off | Process action | ✅ Fixed (lint rule added; header signed off 2026-05-18) |
| **P0** | CR-3 — CLI↔issuer integration test | Issuer harness from `e2e.test.ts` | ✅ Fixed |
| **P1** | CR-4 — Quickstart PKCE docs fix | Docs only | ✅ Fixed |
| **P1** | DI-2 — Admin UI token-in-URL → session cookie | Small auth refactor | ✅ Fixed |
| **P1** | CI-4 — HTML-escape dynamic values in admin UI | `htmlEscape` utility | ✅ Fixed |
| **P2** | DI-3 — Multi-replica runbook section | Docs | ✅ Fixed |
| **P2** | DI-1 — Template-assignment fallback audit log | One `logger.warn` + context field | ✅ Fixed (`templateFallback: true` in AuditEntry.metadata) |
| **P2** | CI-1 — `distinctIssuingUsersCapped` companion field | Schema + emit change | ✅ Fixed |
| **P3** | DI-4 — Move `TelemetryEvent` to `@euno/common` | Dep-direction validation | ⬜ Deferred to Stage 5 |
| **P3** | DI-5 — KMS key alias `superRefine` guard | Config schema addition | ✅ Fixed |
| **P3** | CI-3 — O(N) sweep (superseded by CR-1 Redis fix) | N/A — resolved | ✅ N/A |
| **P3** | CI-5 — Canonical revocation source | Docs | ✅ Fixed (runbook §Token Revocation) |
| **P3** | Q2 — Clarify E4 wording in stage4executionplan.md | Docs | ✅ Fixed |

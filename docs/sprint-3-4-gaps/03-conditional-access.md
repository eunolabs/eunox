# Item #3 — Conditional Access Policy Enforcement

**Plan reference:** `docs/execution-plan.md` Sprint 4 → Team CP →
"Enterprise IAM Full Integration" (line 281):
> Azure: ... honor **Conditional Access policies** plus Privileged
> Identity Management (PIM) activations ...

**Files affected:** `packages/capability-issuer/src/azure-identity-provider.ts`
(primary), `packages/common/src/types.ts` (config + error code).

## Problem

`AzureADIdentityProvider.validateToken()` today verifies the JWT
signature, issuer, and audience, then extracts `oid`, `email`, `roles`,
and `tid`. It does **not** look at any Conditional Access (CA) signal,
so a token that Azure AD issued under a CA policy that *should* have
required step-up MFA, a compliant device, or a specific named
location can still mint a capability.

CA decisions are surfaced in two complementary places:

1. **Token claims set by Azure AD when CA was satisfied** —
   `acrs` / `acr` (authentication context references), `amr`
   (authentication method references, e.g. `mfa`, `hwk`),
   `xms_cc` (client capabilities), and the absence of `acrs` when a
   given protected action requires one.
2. **Microsoft Graph `conditionalAccess/evaluate` API** — given a
   user, app, and signal context, returns the policies that would
   apply and whether they are satisfied. This is the authoritative
   path for *current* state (CA can change between sign-in and
   capability-issuance).

For an issuer running close to login (sign-in token < ~5 minutes old),
inspecting claims is sufficient and cheap. For longer-lived tokens or
high-sensitivity capabilities, an explicit Graph evaluation is the
right answer.

## Goals

- Reject token validation when a CA policy required for the requested
  capability is not satisfied.
- Allow operators to declare *per-capability-tier* CA requirements
  (e.g. `write` and `admin` actions require `acrs=urn:euno:mfa`).
- Keep the existing fast path (claim inspection only) as the default;
  Graph evaluation is opt-in for high-risk tiers.
- Fail closed: if CA cannot be evaluated, deny.

## Non-goals

- Authoring CA policies in Azure AD (operator concern).
- Evaluating CA for non-Azure providers (#3 is Azure-only by the plan;
  AWS / GCP have their own equivalents tracked elsewhere).

## Design

### 1. New configuration on `AzureADConfig`

In `packages/common/src/types.ts`, extend `AzureADConfig`:

```
conditionalAccess?: {
  // When true, validateToken() requires the listed acrs values to be
  // present in the token's `acrs` claim. Maps action tier → required
  // acrs reference. Tiers match the existing SENSITIVE_ACTIONS set in
  // issuer-service.ts (read | write | delete | admin).
  requiredAcrsByTier?: Record<'read'|'write'|'delete'|'admin', string[]>;

  // When true, after claim-based checks pass, call Microsoft Graph
  // `identityProtection/riskyUsers/{id}` and
  // `conditionalAccess/namedLocations` (or `auditLogs/signIns` lookup
  // by sign-in id) to confirm the sign-in that produced this token
  // has not been flagged. Default false. Requires Graph permissions
  // `IdentityRiskyUser.Read.All` and `Policy.Read.All`.
  requireFreshGraphCheck?: boolean;

  // Maximum age (seconds) of the underlying sign-in (`auth_time` claim)
  // beyond which the token is rejected for sensitive tiers regardless
  // of `acrs`. Default 3600.
  maxSignInAgeSeconds?: number;
};
```

### 2. New error code

Add to `ErrorCode` enum (in `packages/common/src/types.ts`):
`CONDITIONAL_ACCESS_REQUIRED` — HTTP 403, audit reason
`"conditional_access_unsatisfied"`.

### 3. `validateToken()` flow change

After the existing `jose.jwtVerify(...)`:

1. **Tier inference.** The provider does not yet know which capability
   tier the caller is asking for, so the existing `validateToken()`
   contract returns a `UserContext`. Extend `UserContext` (also in
   `types.ts`) with an optional `caEvaluation` field that records what
   was checked and what was satisfied. The issuer service then
   consults `caEvaluation` against the requested capabilities' actions
   in `issueCapability()` (around line 156 of `issuer-service.ts`) and
   denies the issuance with `CONDITIONAL_ACCESS_REQUIRED` if a
   required `acrs` is missing for the tier being requested.
2. **Sign-in age check.** If `payload.auth_time` is older than
   `maxSignInAgeSeconds`, mark the tier `admin`/`delete` as
   unsatisfied (still allowing `read`).
3. **Optional Graph check.** If `requireFreshGraphCheck` is true,
   call Graph for the user's risk state and the most recent sign-in
   matching `payload.sid` (session ID claim). Cache results in-memory
   for `min(remaining-token-lifetime, 60s)` to avoid hammering Graph.

### 4. Issuer-service hook

Inside `CapabilityIssuerService.issueCapability()`:

- After role mapping and consent validation, walk the resolved
  `CapabilityConstraint[]` and compute the highest-sensitivity action
  among them.
- Compare against `userContext.caEvaluation.satisfiedTiers`.
- If a required tier is missing, throw `CapabilityError(
  CONDITIONAL_ACCESS_REQUIRED, ...)` and emit an audit entry with
  `decision: 'deny'`, `reason: 'conditional_access_unsatisfied'`,
  `metadata.requiredAcrs`, `metadata.presentedAcrs`.

### 5. Caching & rate

Graph calls are cached per `(userId, sessionId)` for ≤60 seconds. The
cache is bounded (LRU, default 1024 entries) and lives on the
provider instance — the existing `jwks` field is the precedent.

## Test strategy

- **Unit (`packages/capability-issuer/tests/azure-identity-provider.test.ts`):**
  - Token without required `acrs` → `caEvaluation.satisfiedTiers`
    excludes `write`/`admin`/`delete`.
  - Token with required `acrs` → satisfiedTiers includes them.
  - `maxSignInAgeSeconds` exceeded → admin tier unsatisfied.
  - Graph mock returns `riskState: 'atRisk'` → all tiers unsatisfied.
- **Unit (`issuer-service.test.ts`):**
  - Requesting `write` capability with a context whose
    `satisfiedTiers` lacks `write` → throws `CONDITIONAL_ACCESS_REQUIRED`,
    audit entry written.
- **Integration:** mocked Graph server (msw or `nock`) wired into the
  existing e2e test for the Azure path.

## Rollout

- Default off (`conditionalAccess` undefined) — existing deployments
  see no behavior change.
- Documented in `docs/THIRD_PARTY_PROVIDERS.md` Azure section with a
  recommended baseline (`write`/`delete`/`admin` require
  `urn:euno:mfa`).

## Risks

- **Tenant misconfiguration.** If an operator enables
  `requiredAcrsByTier` without adding a matching CA policy in Azure
  AD, *all* sensitive issuance fails. Mitigation: feature flag is
  per-tier, and the audit log records exactly which `acrs` was
  expected so operators can diagnose quickly.
- **Graph permission sprawl.** Optional path requires high-trust
  Graph scopes. Keep it opt-in and document the principle of least
  privilege.
- **Latency.** Graph adds 50–300ms to issuance when enabled. The
  60-second cache amortizes this for repeated issuances per session.

## Open questions

- Should the per-tier mapping also be expressible per-resource (e.g.
  `storage://hr-data/**` requires `mfa` regardless of action)? This
  composes naturally with the existing `CapabilityCondition` registry
  — could also be implemented as a new `requireAcrs` condition type
  rather than provider-side. See discussion in #4 (PIM) where the same
  question recurs; recommend addressing both with one new condition
  type if we go that route.

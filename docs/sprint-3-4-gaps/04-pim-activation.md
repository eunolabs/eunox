# Item #4 — PIM Activation Checks

**Plan reference:** `docs/execution-plan.md` Sprint 4 → Team CP, line
281 — Azure provider must honor "Privileged Identity Management (PIM)
activations for time-bound elevated permissions".

**Files affected:** `packages/capability-issuer/src/azure-identity-provider.ts`
(primary), `packages/common/src/types.ts`, possibly
`packages/common/src/role-mapping.ts`.

## Problem

`AzureADIdentityProvider.getUserRoles()` calls Graph
`/users/{id}/memberOf` and returns *all* roles the user is a member
of, including roles that are **PIM-eligible but not currently
activated**. Mapping those roles via `mapRolesToCapabilities()`
silently grants elevated capabilities that the user has not actually
activated — defeating the entire point of PIM (just-in-time elevation
with bounded duration).

## Goals

- Roles obtained via PIM are only mapped to capabilities **while the
  PIM activation is currently active**.
- Capability TTL is upper-bounded by the remaining PIM activation
  window (a 1-hour capability cannot outlive a 30-minute activation).
- Roles that are *permanently assigned* (non-PIM) continue to work as
  today.
- Fail closed: if PIM state cannot be determined and the role is on
  the operator-declared "PIM-protected" list, deny.

## Non-goals

- Initiating a PIM activation on the user's behalf (out of scope —
  user must activate via Azure portal / API before requesting).
- Equivalent JIT elevation for AWS (IAM Identity Center session
  policies) or GCP (privileged-access-manager) — tracked separately;
  the same `RoleSource` concept below leaves room for them.

## Design

### 1. Distinguish role sources

Today `getUserRoles()` returns `string[]`. Replace its internal use
with a richer shape (kept private; the public method can still return
`string[]` for back-compat) that records *how* each role was obtained:

```
type RoleSource =
  | { kind: 'permanent' }
  | { kind: 'pim-active'; assignmentId: string; endDateTime: string }
  | { kind: 'pim-eligible-not-active' };

interface ResolvedRole {
  name: string;
  source: RoleSource;
}
```

### 2. New Graph queries

In addition to `/users/{id}/memberOf`, query:

- `/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{oid}'`
  → currently active assignments (covers permanent and active-PIM,
  distinguished by `assignmentType` field: `Assigned` vs
  `Activated`).
- `/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{oid}'`
  → PIM-eligible but not active.

Roles appearing only in `memberOf` (group memberships) are
`permanent`. Roles appearing in
`roleAssignmentScheduleInstances` with `assignmentType=Activated`
are `pim-active` and carry an `endDateTime`. Roles in
`roleEligibilityScheduleInstances` (and not in active) are
`pim-eligible-not-active` — these MUST be filtered out before role
mapping.

Each role's display name is resolved via
`/roleManagement/directory/roleDefinitions/{id}` (cached
indefinitely; role definitions are stable).

### 3. New configuration

Extend `AzureADConfig`:

```
pim?: {
  // When true, roles in pim-eligible-not-active state are stripped
  // before mapping to capabilities. Default true when this block is
  // present.
  enforceActivation?: boolean;

  // Operator-declared list of role display names that MUST be PIM-
  // activated to grant any capability — even if the role somehow
  // appears as permanent (defense in depth against
  // misconfigured permanent assignments to highly privileged roles).
  // Example: ["Global Administrator", "Privileged Role Administrator"].
  pimRequiredRoles?: string[];

  // Cap capability TTL at the PIM activation's remaining lifetime.
  // Default true.
  capTtlToActivation?: boolean;
};
```

### 4. Issuer-service hook

`CapabilityIssuerService.issueCapability()` receives the resolved
role list. Two changes:

1. Pass `ResolvedRole[]` (or an equivalent map of `roleName ->
   sourceMetadata`) into the issuer so it can compute an upper-bound
   TTL.
2. After computing the requested TTL via `getExpirationTimestamp()`,
   take `min(requestedTtl, minRemainingPimWindow)` where
   `minRemainingPimWindow` is the smallest `endDateTime - now` across
   all roles that contributed to the granted capabilities and have
   `source.kind === 'pim-active'`. Audit log records both the
   requested and capped TTL.

If `pimRequiredRoles` enforcement applies and a required role is not
in `pim-active` state, throw `CapabilityError(AUTHORIZATION_FAILED,
"PIM activation required for role X", 403)`.

### 5. Caching

PIM state is short-lived by definition. Cache per `(userId)` for
≤30 seconds with a hard TTL. Invalidate the cache entry on any audit
log write that records `pim_required_role_denied` for that user (so a
fresh activation is picked up immediately on retry).

### 6. Interaction with #3 (Conditional Access)

CA and PIM are evaluated independently and both must pass. CA is
about *how* the user authenticated; PIM is about *which roles are
currently elevated*. The two checks live in the same provider but
in distinct methods (`evaluateConditionalAccess`, `resolveActivePimRoles`)
sharing one Graph client.

## Test strategy

- **Unit:**
  - Mocked Graph returns role X as `roleEligibilityScheduleInstances`
    only → `resolveActivePimRoles()` excludes X.
  - Mocked Graph returns role X as `roleAssignmentScheduleInstances`
    with `assignmentType=Activated, endDateTime=now+10min` →
    included, with `endDateTime` recorded.
  - Cap-TTL: requested 60-min capability + 10-min remaining
    activation → granted token has `exp - iat == 600`.
  - `pimRequiredRoles` containing "Global Administrator" + Graph
    returns it as `Assigned` (permanent) → still denied unless also
    active.
- **Integration:** existing Azure e2e test extended with a PIM
  scenario.

## Rollout

- Off by default (`pim` undefined). Operators turn it on after
  confirming all sensitive roles in their tenant are PIM-managed.
- Document required Graph permissions: `RoleManagement.Read.Directory`
  (sufficient for both eligibility and assignment schedule reads).

## Risks

- **Clock skew.** PIM `endDateTime` is server time; the issuer's
  clock may differ. Subtract a 30-second safety margin when computing
  the TTL cap.
- **Pagination.** A user with many directory roles may have paginated
  Graph responses. Use the Graph SDK's pageIterator; cap total roles
  fetched at 100 per user (the practical limit) and log a warning if
  truncated.
- **PIM activation churn.** A user reactivating mid-session: the
  30-second cache TTL means the worst-case stale-deny window is 30s.
  Acceptable; alternative is a webhook from Azure AD which is heavy.

## Open questions

- Should we surface "you have role X eligible but not activated" as a
  structured error so the agent UI can prompt the user to activate?
  Recommend yes — add `metadata.eligibleButInactive: string[]` to the
  error payload.

/**
 * Issuance — role resolution and role-derived enforcement.
 *
 * Wraps the {@link IdentityProvider} role-source data and the role →
 * capability policy with the four checks that depend on it:
 *
 *  1. {@link enforcePimRequiredRoles} — operator-declared roles that
 *     MUST be PIM-activated at issuance time.
 *  2. {@link enforceConditionalAccess} — Conditional Access tier
 *     enforcement against the granted capability set.
 *  3. {@link computePimCappedExpiry} — caps capability TTL to the
 *     smallest remaining `pim-active` window of the *contributing*
 *     roles.
 *  4. {@link filterRolesContributingToCapabilities} — narrows the
 *     PIM-cap input set to roles that actually contribute to the
 *     granted capability set, so an unrelated short-lived activation
 *     doesn't shorten unrelated tokens.
 *
 * Extracted from `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  AuditLogEntry,
  CaActionTier,
  CaEvaluation,
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  Logger,
  RoleCapabilityPolicy,
  ResolvedRole,
  UserContext,
  generateId,
  mapRolesToCapabilitiesForPolicy,
  matchesResource,
} from '@euno/common';

/** Margin (seconds) subtracted from a PIM `endDateTime` when capping
 *  capability TTL, to account for clock skew between the issuer and
 *  Azure AD. */
export const PIM_TTL_SAFETY_MARGIN_SECONDS = 30;

/**
 * Map a capability action to its Conditional Access tier. Unknown
 * verbs (e.g. resource-specific actions like `db:select`) fall back
 * to the closest legacy category they imply: any verb containing
 * `delete` maps to `delete`, anything containing `admin` to `admin`,
 * anything containing `write`/`put`/`update`/`create` to `write`,
 * everything else to `read`. This keeps CA enforcement meaningful
 * for the resource-specific verbs that {@link Action} now permits
 * without requiring operators to enumerate every possible verb.
 */
export function actionToCaTier(action: string): CaActionTier {
  const a = action.toLowerCase();
  if (a === 'delete' || a.includes('delete') || a.includes('drop') || a.includes('remove')) {
    return 'delete';
  }
  if (a === 'admin' || a.includes('admin')) return 'admin';
  if (
    a === 'write' ||
    a.includes('write') ||
    a.includes('put') ||
    a.includes('update') ||
    a.includes('create') ||
    a.includes('insert') ||
    a === 'execute' ||
    a.includes('publish')
  ) {
    return 'write';
  }
  return 'read';
}

/**
 * Enforce operator-declared `pimRequiredRoles`. When the user holds
 * a role on the list but its source is not `pim-active`, deny
 * issuance with `AUTHORIZATION_FAILED` (HTTP 403). The list is
 * ignored if the identity provider does not populate `roleSources`,
 * preserving back-compat with non-Azure providers.
 *
 * Also surfaces "you have role X eligible but not activated" via the
 * audit log so the agent UI can prompt the user to activate.
 */
export function enforcePimRequiredRoles(
  userContext: UserContext,
  agentId: string,
  pimRequiredRoles: string[],
  auditLogger: Logger,
): void {
  if (pimRequiredRoles.length === 0) return;
  if (!userContext.roleSources) return; // Provider doesn't support PIM.

  const sourceByRole = new Map<string, ResolvedRole['source']>();
  for (const r of userContext.roleSources) sourceByRole.set(r.name, r.source);

  const requiredButInactive: string[] = [];
  const eligibleButInactive: string[] = [];
  for (const roleName of pimRequiredRoles) {
    const src = sourceByRole.get(roleName);
    if (!src) continue; // User does not hold this role at all — fine.
    if (src.kind !== 'pim-active') {
      requiredButInactive.push(roleName);
      if (src.kind === 'pim-eligible-not-active') eligibleButInactive.push(roleName);
    }
  }

  if (requiredButInactive.length === 0) return;

  const auditEntry: AuditLogEntry = {
    id: generateId(),
    timestamp: new Date(),
    eventType: 'issuance',
    agentId,
    userId: userContext.userId,
    decision: 'deny',
    metadata: {
      reason: 'pim_required_role_not_activated',
      pimRequiredRoles: requiredButInactive,
      eligibleButInactive,
    },
  };
  auditLogger.warn('Capability issuance denied: PIM activation required', auditEntry);

  throw new CapabilityError(
    ErrorCode.AUTHORIZATION_FAILED,
    `PIM activation required for role(s): ${requiredButInactive.join(', ')}`,
    403,
  );
}

/**
 * Enforce Conditional Access against the final capability set. The
 * union of action tiers across every granted capability is computed
 * (read < write < delete < admin); each tier in that union must be
 * present in `userContext.caEvaluation.satisfiedTiers`. If any
 * required tier is unsatisfied, issuance is denied with
 * `CONDITIONAL_ACCESS_REQUIRED` and an audit entry recording the
 * full set of unsatisfied tiers, the required acrs values, and the
 * acrs values actually presented in the token. When the provider
 * has not populated `caEvaluation` (non-Azure providers, or Azure
 * deployments without the `conditionalAccess` block), this function
 * is a no-op — preserving back-compat.
 */
export function enforceConditionalAccess(
  userContext: UserContext,
  capabilities: CapabilityConstraint[],
  agentId: string,
  auditLogger: Logger,
): void {
  const ca: CaEvaluation | undefined = userContext.caEvaluation;
  if (!ca) return; // Provider doesn't participate in CA enforcement.

  const satisfied = new Set<CaActionTier>(ca.satisfiedTiers);

  // Compute the unique set of required tiers actually being requested.
  const requiredTiers = new Set<CaActionTier>();
  for (const cap of capabilities) {
    for (const action of cap.actions) {
      requiredTiers.add(actionToCaTier(action));
    }
  }

  const unsatisfied: CaActionTier[] = [];
  for (const tier of requiredTiers) {
    if (!satisfied.has(tier)) unsatisfied.push(tier);
  }

  if (unsatisfied.length === 0) return;

  const auditEntry: AuditLogEntry = {
    id: generateId(),
    timestamp: new Date(),
    eventType: 'issuance',
    agentId,
    userId: userContext.userId,
    decision: 'deny',
    metadata: {
      reason: 'conditional_access_unsatisfied',
      unsatisfiedTiers: unsatisfied,
      requiredAcrs: unsatisfied
        .map((tier) => ca.requiredAcrsByTier?.[tier] ?? [])
        .reduce<string[]>((acc, list) => {
          for (const v of list) if (!acc.includes(v)) acc.push(v);
          return acc;
        }, []),
      presentedAcrs: ca.presentedAcrs,
      satisfiedTiers: ca.satisfiedTiers,
    },
  };
  auditLogger.warn('Capability issuance denied: Conditional Access not satisfied', auditEntry);

  throw new CapabilityError(
    ErrorCode.CONDITIONAL_ACCESS_REQUIRED,
    `Conditional Access policy not satisfied for tier(s): ${unsatisfied.join(', ')}`,
    403,
  );
}

/**
 * Compute an upper-bound expiry timestamp based on the smallest
 * remaining `pim-active` window across the supplied roles. Returns
 * `undefined` when capping is disabled, the list is empty, or none
 * of the supplied roles is `pim-active`.
 *
 * Subtracts a 30-second safety margin to account for clock skew
 * between the issuer and Azure AD. The returned value MAY be in the
 * past — the caller is responsible for treating that as an
 * already-expired activation and denying issuance rather than
 * minting an immediately-unusable token.
 */
export function computePimCappedExpiry(
  roleSources: ResolvedRole[] | undefined,
  capTtlToPimActivation: boolean,
  requestedExpiry: number,
): number | undefined {
  if (!capTtlToPimActivation) return undefined;
  if (!roleSources || roleSources.length === 0) return undefined;

  let minEndSeconds: number | undefined;
  for (const r of roleSources) {
    if (r.source.kind !== 'pim-active') continue;
    const endMs = Date.parse(r.source.endDateTime);
    if (Number.isNaN(endMs)) continue;
    const endSec = Math.floor(endMs / 1000) - PIM_TTL_SAFETY_MARGIN_SECONDS;
    if (minEndSeconds === undefined || endSec < minEndSeconds) {
      minEndSeconds = endSec;
    }
  }

  if (minEndSeconds === undefined) return undefined;
  return Math.min(minEndSeconds, requestedExpiry);
}

/**
 * Return the subset of `userContext.roleSources` whose role names
 * actually contribute to at least one of the granted capabilities
 * under the configured role→capability policy. A role contributes
 * when mapping it through the policy yields any capability whose
 * resource pattern covers a granted capability's resource AND whose
 * action set intersects that granted capability's actions.
 *
 * Returns `undefined` (not `[]`) when `roleSources` is itself
 * undefined, so the caller can distinguish "no PIM data from
 * provider" from "no contributing PIM-active role".
 */
export function filterRolesContributingToCapabilities(
  userContext: UserContext,
  capabilities: CapabilityConstraint[],
  policy: RoleCapabilityPolicy,
): ResolvedRole[] | undefined {
  if (!userContext.roleSources) return undefined;
  if (capabilities.length === 0) return [];

  const contributing: ResolvedRole[] = [];
  for (const r of userContext.roleSources) {
    const mapped = mapRolesToCapabilitiesForPolicy(
      [r.name],
      policy,
      userContext.tenantId,
    );
    if (mapped.length === 0) continue;
    const overlaps = capabilities.some((granted) =>
      mapped.some((m) => {
        if (!matchesResource(granted.resource, m.resource)) return false;
        const grantedActions = new Set(granted.actions);
        for (const a of m.actions) {
          if (grantedActions.has(a)) return true;
        }
        return false;
      }),
    );
    if (overlaps) contributing.push(r);
  }
  return contributing;
}

/**
 * Provider-agnostic role → capability mapping.
 *
 * Sprint 1 of the execution plan calls for a "simple static mapping" from
 * identity-provider roles to capability constraints. The original
 * implementation lived inside the Azure AD identity provider, which forced
 * the issuer service to special-case Azure (`instanceof
 * AzureADIdentityProvider`). To bring AWS Cognito / IAM Identity Center and
 * Google Cloud Identity to parity with Azure AD, the mapping has been
 * lifted into a shared module so every identity provider — and any future
 * third-party provider — uses the same Sprint 1 mapping logic without the
 * issuer needing to know which provider produced the roles.
 *
 * The default role names follow the example mapping documented in
 * `docs/execution-plan.md` Sprint 1 (`SalesManager`, `Viewer`,
 * `DataScientist`, `Administrator`). Custom mappings can be supplied at
 * issuer construction time for production deployments.
 */

import { CapabilityConstraint, Action } from './types';

/**
 * Mapping from a role name to the set of capability constraints that role
 * grants.
 */
export type RoleCapabilityMap = Record<string, CapabilityConstraint[]>;

/**
 * Default Sprint 1 role → capability mapping. Intentionally identical to the
 * mapping previously hard-coded inside `AzureADIdentityProvider` so that
 * existing Azure deployments observe no behavioural change.
 */
export const DEFAULT_ROLE_CAPABILITY_MAP: RoleCapabilityMap = {
  SalesManager: [
    { resource: 'api://crm/customers', actions: ['read' as Action, 'write' as Action] },
    { resource: 'api://crm/reports', actions: ['read' as Action] },
    { resource: 'storage://sales-data/**', actions: ['read' as Action, 'write' as Action] },
  ],
  Viewer: [
    { resource: 'api://crm/customers', actions: ['read' as Action] },
    { resource: 'api://crm/reports', actions: ['read' as Action] },
    { resource: 'storage://sales-data/**', actions: ['read' as Action] },
  ],
  DataScientist: [
    { resource: 'api://analytics/**', actions: ['read' as Action, 'write' as Action] },
    { resource: 'storage://datasets/**', actions: ['read' as Action] },
    { resource: 'api://ml-models/**', actions: ['read' as Action, 'execute' as Action] },
  ],
  Administrator: [
    { resource: 'api://**', actions: ['read' as Action, 'write' as Action, 'admin' as Action] },
    { resource: 'storage://**', actions: ['read' as Action, 'write' as Action, 'delete' as Action] },
  ],
};

/**
 * Map a list of role names to the union of capability constraints they grant
 * under the supplied (or default) role-capability map. Unknown roles are
 * silently ignored, matching the original Azure-only behaviour.
 */
export function mapRolesToCapabilities(
  roles: string[],
  map: RoleCapabilityMap = DEFAULT_ROLE_CAPABILITY_MAP,
): CapabilityConstraint[] {
  const capabilities: CapabilityConstraint[] = [];
  for (const role of roles) {
    const roleCaps = map[role];
    if (roleCaps) {
      capabilities.push(...roleCaps);
    }
  }
  return capabilities;
}

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
 * `DataScientist`, `Administrator`). For deployments that need to treat
 * the policy as data rather than code (per-tenant overrides, hot-reloadable
 * policy bundles, integration with an external policy engine), the
 * {@link RoleCapabilityPolicy} type and {@link loadRoleCapabilityPolicyFromFile}
 * loader allow the mapping to be sourced from a JSON file at startup. The
 * file may declare a `default` map applied to every tenant plus per-tenant
 * overrides keyed by `tenants`. Per-tenant entries are merged into the
 * default on a per-role basis so operators can override individual roles
 * for a specific tenant without restating the entire policy.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CapabilityConstraint, Action, CapabilityCondition } from './types';
import { validateConditions } from './condition-registry';

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

/**
 * A data-driven role → capability policy. Holds the global `default`
 * mapping plus optional per-tenant overrides. Each tenant override is
 * merged on top of the default on a per-role basis, so a tenant entry only
 * needs to declare the roles whose capabilities differ from the defaults.
 *
 * Roles set to `null` (or an empty array) in a tenant override remove the
 * default capabilities for that role, allowing operators to suppress a
 * default role for a specific tenant.
 */
export interface RoleCapabilityPolicy {
  /** Default role → capability map applied to every tenant. */
  default: RoleCapabilityMap;
  /**
   * Per-tenant overrides keyed by the tenant identifier emitted by the
   * identity provider (e.g. Azure AD `tid`, Cognito `cognito:groups`
   * tenant claim, GCP project ID).
   */
  tenants?: Record<string, RoleCapabilityMap>;
  /**
   * Optional mapping from role name → IAM-mapped database principal name.
   * Consumed by the DB-token issuance pipeline (see
   * `docs/sprint-3-4-gaps/08-db-token-issuance.md` § 5) to look up which
   * `dbUsername` to bind a minted credential to. The agent never supplies
   * this — it is resolved from the requesting user's roles, eliminating
   * the privilege-escalation vector of agent-chosen DB principals.
   *
   * When a user has multiple roles with `dbUsername` entries, the first
   * one in `userContext.roles` order wins (matching the deterministic
   * iteration order of {@link mapRolesToCapabilities}).
   */
  dbUsernamesByRole?: Record<string, string>;
}

/**
 * Resolve the effective role → capability map for a tenant. Combines the
 * policy's `default` map with the tenant-specific overrides (if any). The
 * returned map is a deep copy of the source data — both the role keys and
 * the capability arrays/objects underneath them — so callers can mutate
 * the result without affecting the source policy or other tenants.
 */
export function resolveRoleCapabilityMap(
  policy: RoleCapabilityPolicy,
  tenantId?: string,
): RoleCapabilityMap {
  const cloneCapability = (cap: CapabilityConstraint): CapabilityConstraint => ({
    resource: cap.resource,
    actions: [...cap.actions],
    // Conditions are now a typed array of {type, ...} payloads. Each
    // entry is shallow-cloned so callers can mutate the result without
    // affecting the source policy. The condition payloads themselves
    // are treated as immutable value objects (issuer + gateway only
    // ever read them), so a shallow clone is sufficient.
    ...(cap.conditions !== undefined
      ? { conditions: cap.conditions.map((c) => ({ ...c })) as CapabilityCondition[] }
      : {}),
  });
  const cloneCapabilityArray = (caps: CapabilityConstraint[]): CapabilityConstraint[] =>
    caps.map(cloneCapability);

  const merged: RoleCapabilityMap = {};
  for (const [role, caps] of Object.entries(policy.default)) {
    merged[role] = cloneCapabilityArray(caps);
  }
  if (tenantId && policy.tenants && policy.tenants[tenantId]) {
    const overrides = policy.tenants[tenantId];
    for (const role of Object.keys(overrides)) {
      const caps = overrides[role];
      // Empty array (and `null` after JSON load coerced to []) removes the role.
      if (Array.isArray(caps) && caps.length === 0) {
        delete merged[role];
      } else if (Array.isArray(caps)) {
        merged[role] = cloneCapabilityArray(caps);
      }
    }
  }
  return merged;
}

/**
 * Convenience wrapper that resolves the per-tenant map and applies
 * {@link mapRolesToCapabilities}.
 */
export function mapRolesToCapabilitiesForPolicy(
  roles: string[],
  policy: RoleCapabilityPolicy,
  tenantId?: string,
): CapabilityConstraint[] {
  return mapRolesToCapabilities(roles, resolveRoleCapabilityMap(policy, tenantId));
}

/**
 * Validate that an arbitrary value conforms to {@link CapabilityConstraint}.
 * Throws a descriptive `Error` if the value is malformed so policy file
 * loaders fail fast at startup rather than producing silently-permissive
 * mappings at request time.
 */
function validateCapabilityConstraint(value: unknown, contextPath: string): CapabilityConstraint {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${contextPath}: capability entry must be an object`);
  }
  const obj = value as Record<string, unknown>;
  if (typeof obj.resource !== 'string' || obj.resource.length === 0) {
    throw new Error(`${contextPath}: capability 'resource' must be a non-empty string`);
  }
  if (!Array.isArray(obj.actions) || obj.actions.length === 0) {
    throw new Error(`${contextPath}: capability 'actions' must be a non-empty array`);
  }
  // `Action` is now `string` so resource-specific verbs (e.g.
  // `db:select`, `s3:putObject`) are first-class. We still reject
  // empty strings and non-string entries so policy files cannot
  // accidentally smuggle structural junk into the action set.
  for (const action of obj.actions) {
    if (typeof action !== 'string' || action.length === 0) {
      throw new Error(
        `${contextPath}: capability 'actions' contains invalid action '${String(action)}' ` +
          `(actions must be non-empty strings)`,
      );
    }
  }
  const out: CapabilityConstraint = {
    resource: obj.resource,
    actions: obj.actions as Action[],
  };
  if (obj.conditions !== undefined) {
    if (!Array.isArray(obj.conditions)) {
      throw new Error(
        `${contextPath}: capability 'conditions' must be an array of typed condition objects`,
      );
    }
    try {
      validateConditions(obj.conditions as CapabilityCondition[]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`${contextPath}: ${msg}`);
    }
    out.conditions = obj.conditions as CapabilityCondition[];
  }
  return out;
}

function validateRoleCapabilityMap(value: unknown, contextPath: string): RoleCapabilityMap {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${contextPath}: must be an object mapping role names to capability arrays`);
  }
  const result: RoleCapabilityMap = {};
  for (const [role, caps] of Object.entries(value as Record<string, unknown>)) {
    if (caps === null) {
      // Treat null as an explicit "remove this role" marker for tenant overrides.
      result[role] = [];
      continue;
    }
    if (!Array.isArray(caps)) {
      throw new Error(`${contextPath}.${role}: capabilities must be an array`);
    }
    result[role] = caps.map((c, i) =>
      validateCapabilityConstraint(c, `${contextPath}.${role}[${i}]`),
    );
  }
  return result;
}

/**
 * Validate and normalise an arbitrary parsed JSON value into a
 * {@link RoleCapabilityPolicy}. Exposed separately from the file loader so
 * deployments that fetch policy from a config service (Consul, App Config,
 * etc.) can reuse the same validation.
 */
export function validateRoleCapabilityPolicy(value: unknown): RoleCapabilityPolicy {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('role capability policy: must be a JSON object with a "default" property');
  }
  const obj = value as Record<string, unknown>;
  if (obj.default === undefined) {
    throw new Error("role capability policy: missing required 'default' property");
  }
  const policy: RoleCapabilityPolicy = {
    default: validateRoleCapabilityMap(obj.default, 'default'),
  };
  if (obj.tenants !== undefined) {
    if (typeof obj.tenants !== 'object' || obj.tenants === null || Array.isArray(obj.tenants)) {
      throw new Error("role capability policy: 'tenants' must be an object keyed by tenant ID");
    }
    const tenants: Record<string, RoleCapabilityMap> = {};
    for (const [tenantId, tenantMap] of Object.entries(obj.tenants as Record<string, unknown>)) {
      tenants[tenantId] = validateRoleCapabilityMap(tenantMap, `tenants.${tenantId}`);
    }
    policy.tenants = tenants;
  }
  if (obj.dbUsernamesByRole !== undefined) {
    if (
      typeof obj.dbUsernamesByRole !== 'object' ||
      obj.dbUsernamesByRole === null ||
      Array.isArray(obj.dbUsernamesByRole)
    ) {
      throw new Error("role capability policy: 'dbUsernamesByRole' must be an object keyed by role name");
    }
    const dbUsernames: Record<string, string> = {};
    for (const [role, name] of Object.entries(obj.dbUsernamesByRole as Record<string, unknown>)) {
      if (typeof name !== 'string' || name.length === 0) {
        throw new Error(
          `role capability policy: dbUsernamesByRole.${role} must be a non-empty string`,
        );
      }
      dbUsernames[role] = name;
    }
    policy.dbUsernamesByRole = dbUsernames;
  }
  return policy;
}

/**
 * Load a {@link RoleCapabilityPolicy} from a JSON file on disk. Throws if
 * the file is missing, unparseable, or fails schema validation so misconfigured
 * deployments fail fast at startup rather than serving with an empty policy.
 */
export function loadRoleCapabilityPolicyFromFile(filePath: string): RoleCapabilityPolicy {
  const resolved = path.resolve(filePath);
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(
      `Failed to read role capability policy file '${resolved}': ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Role capability policy file '${resolved}' is not valid JSON: ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  return validateRoleCapabilityPolicy(parsed);
}

/**
 * Issuance — attenuation subset validation.
 *
 * Validates that a child (attenuated) capability set is a strict
 * subset of the parent's, including matching `argumentSchema`
 * constraints. Extracted from `issuer-service.ts` per refactor R-1
 * in `docs/IMPROVEMENTS_AND_REFACTORING.md` so the rules sit next
 * to the rest of the issuance pipeline rather than inside the
 * orchestrator.
 */

import {
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  matchesResource,
} from '@euno/common';

/**
 * Validate that requested capabilities are a subset of allowed
 * capabilities. Throws {@link CapabilityError} on the first violation.
 *
 *  - Resource matching uses {@link matchesResource} so wildcard
 *    parents (`storage://datasets/**`) correctly cover concrete
 *    children.
 *  - Action sets are unioned across all matching parents.
 *  - `argumentSchema` constraints, when present on any matching
 *    parent, MUST be reproduced verbatim by the child (deep equal via
 *    a stable JSON serialiser). The child may introduce a *new*
 *    schema only when no matching parent has one (introducing a
 *    constraint is a tightening, which is always sound).
 */
export function validateCapabilitySubset(
  parentCapabilities: CapabilityConstraint[],
  requestedCapabilities: CapabilityConstraint[],
): void {
  for (const requested of requestedCapabilities) {
    const matchingParents = parentCapabilities.filter((cap) =>
      matchesResource(requested.resource, cap.resource),
    );

    if (matchingParents.length === 0) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        `Cannot attenuate: resource '${requested.resource}' not in parent capability`,
        403,
      );
    }

    const allowedActions = new Set<string>();
    for (const cap of matchingParents) {
      for (const action of cap.actions) {
        allowedActions.add(action);
      }
    }

    for (const action of requested.actions) {
      if (!allowedActions.has(action)) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Cannot attenuate: action '${action}' on resource '${requested.resource}' not in parent capability`,
          403,
        );
      }
    }

    // Attenuation must not LOOSEN argument-level constraints declared
    // on the parent. If any matching parent capability has an
    // `argumentSchema`, the child must carry the same schema (deep
    // equal). The child is allowed to introduce a new schema only when
    // no matching parent has one.
    const parentsWithSchema = matchingParents.filter((p) => p.argumentSchema);
    if (parentsWithSchema.length > 0) {
      const requestedSchemaSerialized = stableStringify(requested.argumentSchema);
      const matchesAnyParent = parentsWithSchema.some(
        (p) => stableStringify(p.argumentSchema) === requestedSchemaSerialized,
      );
      if (!matchesAnyParent) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Cannot attenuate: argumentSchema on resource '${requested.resource}' must match the parent capability's argumentSchema`,
          403,
        );
      }
    }
  }
}

/**
 * Deterministic JSON serialiser used to compare `argumentSchema`
 * objects across capability boundaries. Object keys are sorted
 * recursively so the comparison is independent of property order.
 */
function stableStringify(value: unknown): string {
  if (value === undefined) {
    return 'undefined';
  }
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys((v as Record<string, unknown>)).sort()) {
        sorted[k] = (v as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return v;
  });
}

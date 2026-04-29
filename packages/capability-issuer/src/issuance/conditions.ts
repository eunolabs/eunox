/**
 * Issuance — typed-condition validation.
 *
 * Validates the typed conditions on every capability prior to signing,
 * so unknown / malformed conditions are rejected at mint time rather
 * than silently round-tripping into a signed token. Extracted from
 * `issuer-service.ts` per refactor R-1.
 */

import {
  CapabilityConstraint,
  CapabilityError,
  ConditionValidationError,
  ErrorCode,
  validateConditions,
} from '@euno/common';

/**
 * Validate every typed condition on every capability in the list,
 * raising a structured {@link CapabilityError} (`INVALID_REQUEST` /
 * 400) on the first failure. Replaces the old fail-open posture
 * where unknown or malformed conditions were silently signed into
 * tokens.
 */
export function validateConditionsForCapabilities(
  capabilities: CapabilityConstraint[],
): void {
  for (let i = 0; i < capabilities.length; i++) {
    const cap = capabilities[i]!;
    if (!cap.conditions) continue;
    try {
      validateConditions(cap.conditions);
    } catch (err) {
      const detail =
        err instanceof ConditionValidationError || err instanceof Error
          ? err.message
          : String(err);
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Invalid condition on capability[${i}] (resource '${cap.resource}'): ${detail}`,
        400,
      );
    }
  }
}

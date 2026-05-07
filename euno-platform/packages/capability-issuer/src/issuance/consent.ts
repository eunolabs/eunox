/**
 * Issuance — user consent validation.
 *
 * Owns the {@link SENSITIVE_ACTIONS} gate and the {@link validateConsent}
 * function. Extracted from `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`: keeping consent rules in one
 * cohesive module makes them easy to audit and unit-test in isolation
 * from the issuer orchestrator.
 */

import {
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  UserConsent,
  getCurrentTimestamp,
  matchesResource,
} from '@euno/common';

/**
 * Actions which always require an explicit, validated user consent record
 * regardless of the issuer's `requireConsent` mode.
 */
export const SENSITIVE_ACTIONS: ReadonlySet<string> = new Set([
  'write',
  'delete',
  'admin',
]);

/**
 * Validate an explicit user consent record against the requested capabilities.
 *
 * Consent must be:
 *   - present (when required),
 *   - bound to the same `userId` as the authenticated user,
 *   - bound to the same `agentId` as the request,
 *   - not expired,
 *   - covering every requested capability (resource + every requested action).
 *
 * Throws {@link CapabilityError} with an appropriate {@link ErrorCode} and
 * HTTP status when validation fails.
 */
export function validateConsent(
  consent: UserConsent | undefined,
  userId: string,
  agentId: string,
  requested: CapabilityConstraint[],
): void {
  if (!consent) {
    throw new CapabilityError(
      ErrorCode.INSUFFICIENT_PERMISSIONS,
      'Explicit user consent is required for the requested capabilities',
      403,
    );
  }

  if (consent.userId !== userId) {
    throw new CapabilityError(
      ErrorCode.INSUFFICIENT_PERMISSIONS,
      'User consent does not match the authenticated user',
      403,
    );
  }

  if (consent.agentId !== agentId) {
    throw new CapabilityError(
      ErrorCode.INSUFFICIENT_PERMISSIONS,
      'User consent was not granted to this agent',
      403,
    );
  }

  // Validate `grantedAt` is a finite unix-seconds number that isn't in the
  // future.  Without this check a missing/invalid `grantedAt` would be
  // silently accepted from the untyped HTTP body and then written into the
  // audit log as-is, undermining its evidentiary value.
  const now = getCurrentTimestamp();
  if (typeof consent.grantedAt !== 'number' || !Number.isFinite(consent.grantedAt)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'User consent grantedAt must be a finite unix-seconds number',
      400,
    );
  }
  // Allow a small skew window for clock drift between the consent UI and
  // the issuer (60 seconds), but reject obviously fabricated future dates.
  if (consent.grantedAt > now + 60) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'User consent grantedAt is in the future',
      400,
    );
  }

  // `expiresAt` is optional, but when present it must be a finite number.
  // Reject non-undefined non-number values so callers can't bypass the
  // expiry check by sending e.g. a string or boolean.
  if (consent.expiresAt !== undefined) {
    if (typeof consent.expiresAt !== 'number' || !Number.isFinite(consent.expiresAt)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'User consent expiresAt must be a finite unix-seconds number when provided',
        400,
      );
    }
    if (consent.expiresAt <= now) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'User consent has expired',
        403,
      );
    }
  }

  if (!Array.isArray(consent.grantedCapabilities) || consent.grantedCapabilities.length === 0) {
    throw new CapabilityError(
      ErrorCode.INSUFFICIENT_PERMISSIONS,
      'User consent does not list any granted capabilities',
      403,
    );
  }

  for (const req of requested) {
    const matching = consent.grantedCapabilities.filter((cap) =>
      matchesResource(req.resource, cap.resource),
    );
    if (matching.length === 0) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        `User did not consent to resource: ${req.resource}`,
        403,
      );
    }

    const grantedActions = new Set<string>();
    for (const cap of matching) {
      for (const action of cap.actions) {
        grantedActions.add(action);
      }
    }

    for (const action of req.actions) {
      if (!grantedActions.has(action)) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `User did not consent to action '${action}' on resource: ${req.resource}`,
          403,
        );
      }
    }
  }
}

/**
 * Returns true when at least one of the requested capabilities includes
 * an action listed in {@link SENSITIVE_ACTIONS}. Used by the issuer to
 * decide whether consent is required even outside strict mode.
 */
export function requestedCapabilitiesIncludeSensitive(
  requested: CapabilityConstraint[],
): boolean {
  return requested.some((cap) =>
    cap.actions.some((action) => SENSITIVE_ACTIONS.has(action)),
  );
}

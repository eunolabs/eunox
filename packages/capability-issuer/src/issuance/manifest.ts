/**
 * Issuance — agent capability manifest enforcement.
 *
 * Owns the {@link validateAgainstManifest} function, extracted from
 * `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 *
 * The manifest is the developer-published upper bound on what an agent
 * may ever request. Even if the user's roles permit a broader scope,
 * the issuer must refuse to mint a token that exceeds the manifest;
 * otherwise a compromised agent could request capabilities its
 * declaration never advertised.
 */

import {
  AgentCapabilityManifest,
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  matchesResource,
} from '@euno/common';

/**
 * Validate that every requested capability falls within the agent's
 * declared manifest (the union of `requiredCapabilities` and
 * `optionalCapabilities`).
 *
 * Throws {@link CapabilityError} on:
 *  - manifest agentId mismatch (`INVALID_REQUEST` / 400),
 *  - empty manifest (`INVALID_REQUEST` / 400),
 *  - resource outside manifest (`INSUFFICIENT_PERMISSIONS` / 403),
 *  - action not declared in manifest (`INSUFFICIENT_PERMISSIONS` / 403).
 */
export function validateAgainstManifest(
  manifest: AgentCapabilityManifest,
  agentId: string,
  requested: CapabilityConstraint[],
): void {
  if (manifest.agentId && manifest.agentId !== agentId) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Manifest agentId '${manifest.agentId}' does not match request agentId '${agentId}'`,
      400,
    );
  }

  const allowed: CapabilityConstraint[] = [
    ...(manifest.requiredCapabilities ?? []),
    ...(manifest.optionalCapabilities ?? []),
  ];

  if (allowed.length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Agent manifest declares no capabilities; cannot issue a token against it',
      400,
    );
  }

  for (const req of requested) {
    const matching = allowed.filter((cap) =>
      matchesResource(req.resource, cap.resource),
    );
    if (matching.length === 0) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        `Requested resource '${req.resource}' is outside the agent manifest`,
        403,
      );
    }

    const allowedActions = new Set<string>();
    for (const cap of matching) {
      for (const action of cap.actions) {
        allowedActions.add(action);
      }
    }

    for (const action of req.actions) {
      if (!allowedActions.has(action)) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Action '${action}' on '${req.resource}' is not declared in the agent manifest`,
          403,
        );
      }
    }
  }
}

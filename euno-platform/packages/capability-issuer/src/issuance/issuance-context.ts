/**
 * Issuance — signing intent context builder.
 *
 * Computes the {@link IssuanceContext} that is threaded from the issuance
 * orchestrator into the signing adapter so KMS back-ends can enforce
 * per-policy grants.  Centralising the hash computation here keeps the
 * `canonicalSha256` algorithm consistent across issue, attenuate, and renew
 * paths and makes the input/output contract testable in isolation.
 *
 * @see {@link IssuanceContext} in `@euno/common` for the full rationale.
 */

import {
  AgentCapabilityManifest,
  IssuanceContext,
  RoleCapabilityPolicy,
  canonicalSha256,
} from '@euno/common';

/**
 * Compute a stable SHA-256 digest of the capability-granting portions of a
 * {@link RoleCapabilityPolicy}.
 *
 * **Scope**: only `policy.default` and `policy.tenants` are included in the
 * digest.  The `dbUsernamesByRole` field is deliberately excluded because it
 * controls credential-minting (which DB principal to bind) rather than which
 * capabilities are granted.  A change to `dbUsernamesByRole` that leaves every
 * capability set unchanged MUST NOT invalidate existing KMS grants or Key
 * Vault key mappings.
 *
 * **Determinism**: uses {@link canonicalSha256} (sorted-key canonical JSON →
 * SHA-256 hex) so the digest is stable across JS runtimes and matches any
 * out-of-band operator tool that implements the same algorithm.
 *
 * Call this once at service start-up (or when the policy changes) and cache
 * the result — hashing the full policy on every sign operation adds O(policy
 * size) cost to the hot path for no benefit.
 */
export function computeCapabilityPolicyHash(policy: RoleCapabilityPolicy): string {
  const capabilitySlice: Pick<RoleCapabilityPolicy, 'default' | 'tenants'> = {
    default: policy.default,
    ...(policy.tenants !== undefined ? { tenants: policy.tenants } : {}),
  };
  return canonicalSha256(capabilitySlice);
}

/**
 * Inputs for {@link buildIssuanceContext}.
 */
export interface IssuanceContextInputs {
  /**
   * Pre-computed capability policy hash (from {@link computeCapabilityPolicyHash}).
   * Pass the value cached at service startup rather than passing the full
   * policy object — the hash is computed once there and reused on every call.
   */
  policyHash: string;

  /**
   * Optional agent capability manifest submitted with the request.  When
   * provided, its canonical SHA-256 becomes {@link IssuanceContext.manifestHash}.
   * Omit (or pass `undefined`) for attenuation, renewal, or deployments that
   * do not require manifests.
   */
  manifest?: AgentCapabilityManifest;

  /**
   * Agent identifier — stamped as {@link IssuanceContext.subject}.
   */
  subject: string;

  /**
   * Gateway audience — stamped as {@link IssuanceContext.audience}.
   */
  audience: string;
}

/**
 * Build an {@link IssuanceContext} from the inputs available at signing time.
 *
 * The manifest hash (when supplied) is produced with {@link canonicalSha256}
 * (sorted-key canonical JSON → SHA-256 hex) so the digest is deterministic
 * across JS runtimes and matches any out-of-band verification tool that
 * implements the same algorithm.
 *
 * The `policyHash` field should be the pre-computed value from
 * {@link computeCapabilityPolicyHash} cached at service startup.
 */
export function buildIssuanceContext(inputs: IssuanceContextInputs): IssuanceContext {
  return {
    policyHash: inputs.policyHash,
    ...(inputs.manifest !== undefined
      ? { manifestHash: canonicalSha256(inputs.manifest) }
      : {}),
    subject: inputs.subject,
    audience: inputs.audience,
  };
}

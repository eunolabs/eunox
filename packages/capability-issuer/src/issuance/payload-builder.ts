/**
 * Issuance — token payload builder.
 *
 * Pure functions: inputs → signed payload struct (no I/O, no signing).
 * Owns the W3C Verifiable Credential envelope so that any code path
 * minting a {@link CapabilityTokenPayload} (issuance, attenuation,
 * renewal) sees the same authoritative {@link CapabilityTokenPayload.vc}
 * view in lock-step with the JWT claims.
 *
 * Extracted from `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  CapabilityConstraint,
  CapabilityTokenPayload,
  UserContext,
} from '@euno/common';

/**
 * W3C Verifiable Credentials Data Model `@context`.  Per
 * `docs/execution-plan.md` Sprint 4 (Team CP, "Verifiable Credential
 * Issuance"), capability tokens carry a W3C VC envelope so that
 * verifiers built around standard VC libraries (e.g. `@digitalbazaar/vc`,
 * Microsoft Entra Verified ID) can consume them without bespoke code.
 *
 * The base context (`https://www.w3.org/2018/credentials/v1`) is
 * required by the spec; the second URI namespaces our
 * `CapabilityCredential` type and its `capabilities` /
 * `parentCapabilityId` fields so they are unambiguous when the token
 * is presented to a third party.
 */
export const VC_CONTEXT: readonly string[] = [
  'https://www.w3.org/2018/credentials/v1',
  'https://schemas.euno.dev/capability-credential/v1',
];

/** W3C VC `type` array used by every capability token. */
export const VC_TYPE: readonly string[] = [
  'VerifiableCredential',
  'CapabilityCredential',
];

/**
 * Build the W3C Verifiable Credential envelope embedded in a
 * capability token.  The envelope mirrors the JWT claims so that a
 * verifier inspecting only the `vc` object (e.g. a `@digitalbazaar/vc`
 * presentation pipeline) sees the same authoritative subject,
 * issuer, validity window, and capability constraints as a verifier
 * inspecting only the JWT claims.  Both views MUST stay in sync —
 * any change to the JWT claim set on issuance / attenuation /
 * renewal must be reflected here.
 *
 * The `id` field is the JWT id (`jti`) prefixed with `urn:uuid:` so
 * the resulting credential identifier is a valid URI per the VC
 * Data Model § 4.2.
 */
export function buildVerifiableCredential(
  payload: Omit<CapabilityTokenPayload, 'vc'>,
): NonNullable<CapabilityTokenPayload['vc']> {
  const credentialSubject: Record<string, unknown> = {
    id: payload.sub,
    capabilities: payload.capabilities,
  };
  if (payload.parentCapabilityId !== undefined) {
    credentialSubject.parentCapabilityId = payload.parentCapabilityId;
  }
  if (payload.authorizedBy !== undefined) {
    credentialSubject.authorizedBy = payload.authorizedBy;
  }
  return {
    '@context': [...VC_CONTEXT],
    // W3C VC Data Model § 4.2: `id` MUST be a single URI.  Use the
    // RFC-4122 `urn:uuid:` namespace so a VC-only verifier sees the
    // same authoritative credential id as a JWT-only verifier reading
    // `jti`.  Keeping `jti` itself as a bare UUID preserves
    // compatibility with verifiers that index revocations by the raw
    // JWT id.
    id: `urn:uuid:${payload.jti}`,
    type: [...VC_TYPE],
    credentialSubject,
  };
}

/** Inputs for {@link buildIssuancePayload}. */
export interface IssuancePayloadInputs {
  issuerDid: string;
  agentId: string;
  /** Audience claim. Defaults to `'tool-gateway'`. */
  audience?: string;
  /** Issued-at timestamp (unix seconds). */
  iat: number;
  /** Expiry timestamp (unix seconds). */
  exp: number;
  /** Pre-generated JWT id (UUID). */
  jti: string;
  capabilities: CapabilityConstraint[];
  userContext: Pick<UserContext, 'userId' | 'roles' | 'tenantId'>;
  /**
   * Optional logical region of the issuer instance. When supplied,
   * stamped into the `region` claim so consumers can attribute the
   * token to its originating region (F-7 multi-region active/active).
   */
  region?: string;
}

/**
 * Build a fully-formed {@link CapabilityTokenPayload} for a fresh
 * issuance, with the VC envelope attached. This is a pure function:
 * given identical inputs it produces identical output, with no side
 * effects.
 */
export function buildIssuancePayload(
  inputs: IssuancePayloadInputs,
): CapabilityTokenPayload {
  const payload: CapabilityTokenPayload = {
    iss: inputs.issuerDid,
    sub: inputs.agentId,
    aud: inputs.audience ?? 'tool-gateway',
    iat: inputs.iat,
    exp: inputs.exp,
    jti: inputs.jti,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: inputs.capabilities,
    authorizedBy: {
      userId: inputs.userContext.userId,
      roles: inputs.userContext.roles,
      tenantId: inputs.userContext.tenantId,
    },
  };
  if (inputs.region) payload.region = inputs.region;
  payload.vc = buildVerifiableCredential(payload);
  return payload;
}

/** Inputs for {@link buildAttenuatedPayload}. */
export interface AttenuatedPayloadInputs {
  issuerDid: string;
  parent: CapabilityTokenPayload;
  iat: number;
  exp: number;
  jti: string;
  capabilities: CapabilityConstraint[];
}

/**
 * Build a child (attenuated) {@link CapabilityTokenPayload}. Inherits
 * `sub`, `aud`, `schemaVersion`, and `authorizedBy` from the parent;
 * narrows the capability set; records `parentCapabilityId`.
 */
export function buildAttenuatedPayload(
  inputs: AttenuatedPayloadInputs,
): CapabilityTokenPayload {
  const childPayload: CapabilityTokenPayload = {
    iss: inputs.issuerDid,
    sub: inputs.parent.sub,
    aud: inputs.parent.aud,
    iat: inputs.iat,
    exp: inputs.exp,
    jti: inputs.jti,
    schemaVersion: inputs.parent.schemaVersion,
    capabilities: inputs.capabilities,
    parentCapabilityId: inputs.parent.jti,
    authorizedBy: inputs.parent.authorizedBy,
  };
  // Preserve the parent token's `region` claim (F-7) — attenuating in
  // a different region does not retroactively change the originating
  // region of the chain.
  if (inputs.parent.region) childPayload.region = inputs.parent.region;
  // Re-build the VC envelope from the *attenuated* claim set so the
  // VC view of the token reflects the narrowed capabilities, not
  // the parent's broader set.
  childPayload.vc = buildVerifiableCredential(childPayload);
  return childPayload;
}

/** Inputs for {@link buildRenewedPayload}. */
export interface RenewedPayloadInputs {
  issuerDid: string;
  current: CapabilityTokenPayload;
  iat: number;
  exp: number;
  jti: string;
}

/**
 * Build a renewed {@link CapabilityTokenPayload}. Same capabilities,
 * same `authorizedBy`, fresh `iat`/`exp`/`jti`, with the previous
 * token id recorded as `parentCapabilityId` for audit traceability.
 * Always stamps the *current* `CAPABILITY_TOKEN_SCHEMA_VERSION` so a
 * renewal acts as a schema upgrade.
 */
export function buildRenewedPayload(
  inputs: RenewedPayloadInputs,
): CapabilityTokenPayload {
  const renewedPayload: CapabilityTokenPayload = {
    iss: inputs.issuerDid,
    sub: inputs.current.sub,
    aud: inputs.current.aud,
    iat: inputs.iat,
    exp: inputs.exp,
    jti: inputs.jti,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: inputs.current.capabilities,
    parentCapabilityId: inputs.current.jti,
    authorizedBy: inputs.current.authorizedBy,
  };
  // Preserve the originating `region` claim across renewal (F-7) so
  // the audit chain can attribute every link to its source region.
  if (inputs.current.region) renewedPayload.region = inputs.current.region;
  // Re-build the VC envelope so its `id` (urn:uuid:<jti>) and
  // `parentCapabilityId` reference the new token, not the previous
  // one.
  renewedPayload.vc = buildVerifiableCredential(renewedPayload);
  return renewedPayload;
}

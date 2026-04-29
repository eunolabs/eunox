/**
 * Strip optional fields from an {@link AgentInventoryRecord} before
 * shipping to a posture-management surface.
 *
 * Posture surfaces are typically visible to a wider operator audience
 * than audit logs, so the default policy is **minimum five fields
 * only** — the parity set called out in the design doc, plus the
 * envelope (`schemaVersion`, `firstSeen`, `lastSeen`, `revokedAt`).
 * Operators can opt in to richer payloads via config.
 */
import { AgentInventoryRecord } from '@euno/common';

export interface RedactOptions {
  /** Include the optional `cloudAccount` field. */
  includeCloudAccount?: boolean;
  /** Include the optional `manifestUri` field. */
  includeManifestUri?: boolean;
  /** Include the granted `capabilities` array. */
  includeCapabilities?: boolean;
}

/**
 * Return a copy of `record` containing only the parity-set fields,
 * the envelope, and any optional fields explicitly enabled via
 * `opts`. Never mutates the input.
 */
export function redactForPosture(
  record: AgentInventoryRecord,
  opts: RedactOptions = {},
): AgentInventoryRecord {
  const out: AgentInventoryRecord = {
    schemaVersion: record.schemaVersion,
    agentId: record.agentId,
    owningTeam: record.owningTeam,
    capabilityManifestHash: record.capabilityManifestHash,
    runtime: record.runtime,
    region: record.region,
    firstSeen: record.firstSeen,
    lastSeen: record.lastSeen,
  };
  if (record.revokedAt !== undefined) out.revokedAt = record.revokedAt;
  if (opts.includeCloudAccount && record.cloudAccount !== undefined) {
    out.cloudAccount = record.cloudAccount;
  }
  if (opts.includeManifestUri && record.manifestUri !== undefined) {
    out.manifestUri = record.manifestUri;
  }
  if (opts.includeCapabilities && record.capabilities !== undefined) {
    out.capabilities = record.capabilities;
  }
  return out;
}

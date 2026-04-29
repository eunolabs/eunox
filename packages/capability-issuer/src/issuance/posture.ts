/**
 * Issuance — AI posture inventory emission.
 *
 * Owns the {@link PostureEmitterLike} integration: builds an
 * {@link AgentInventoryRecord} from an issuance and dispatches it to
 * the configured emitter. Fire-and-forget — emitter failures never
 * fail the originating issuance. See
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 5.
 *
 * Extracted from `issuer-service.ts` per refactor R-1 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import {
  AgentCapabilityManifest,
  AgentInventoryRecord,
  CapabilityConstraint,
  Logger,
  PostureEmitterLike,
  canonicalSha256,
} from '@euno/common';

/**
 * Build and dispatch an {@link AgentInventoryRecord} to the supplied
 * posture emitter, if any. Caller MUST NOT await — the function
 * returns synchronously and any emit failure is logged at warn-level.
 *
 * The five required parity fields (`agentId`, `owningTeam`,
 * `capabilityManifestHash`, `runtime`, `region`) flow through to each
 * downstream cloud surface under their canonical names; see
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 1.
 *
 * Manifest hashing reuses the shared {@link canonicalSha256} helper so
 * the posture record's `capabilityManifestHash` matches the value
 * recorded in audit-log evidence for the same manifest.
 */
export function emitPostureRecord(
  emitter: PostureEmitterLike | undefined,
  logger: Logger,
  args: {
    agentId: string;
    manifest?: AgentCapabilityManifest;
    capabilities: CapabilityConstraint[];
    region: string;
  },
): void {
  if (!emitter || !emitter.isEnabled()) return;

  let record: AgentInventoryRecord;
  try {
    const nowIso = new Date().toISOString();
    const manifest = args.manifest;
    const owningTeam = manifest?.metadata?.owner ?? 'unknown';
    const runtime = manifest?.metadata?.runtime ?? 'unknown';
    const capabilityManifestHash = manifest
      ? canonicalSha256(manifest)
      : canonicalSha256({ agentId: args.agentId });
    record = {
      schemaVersion: '1.0',
      agentId: args.agentId,
      owningTeam,
      capabilityManifestHash,
      runtime,
      region: args.region,
      capabilities: args.capabilities,
      firstSeen: nowIso,
      lastSeen: nowIso,
    };
  } catch (err) {
    logger.warn('posture record build failed', {
      agentId: args.agentId,
      error: err instanceof Error ? err.message : 'Unknown error',
    });
    return;
  }

  // Intentionally not awaited — best-effort.
  emitter.emitObserved(record).catch((err) => {
    logger.warn('posture emit failed', {
      agentId: args.agentId,
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  });
}

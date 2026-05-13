/**
 * Issuance — AI posture inventory emission.
 *
 * Owns the {@link PostureEmitterLike} integration: builds an
 * {@link AgentInventoryRecord} from an issuance and enqueues it with
 * the configured emitter. With {@link DurablePostureEmitter} the
 * enqueue is a synchronous SQLite WAL write that completes before the
 * function resolves, so the caller can `await` it inside the issuance
 * critical path and be confident the record is durable before the HTTP
 * response is sent. Emitter failures are caught and logged but never
 * propagate — posture is observability-only, not a control-plane gate.
 * See `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 5.
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
 * Build and durably enqueue an {@link AgentInventoryRecord} with the
 * supplied posture emitter, if any.
 *
 * **Callers MUST `await` this function** so that the enqueue is
 * confirmed before the HTTP response is sent. With
 * {@link DurablePostureEmitter} the enqueue is a synchronous SQLite
 * WAL write (< 1 ms); with the basic {@link PostureEmitter} it fans
 * out to cloud plugins and adds their round-trip to the issuance
 * latency — see `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`
 * § 5 for guidance on which emitter to use in production.
 *
 * Any error thrown by the emitter is caught and logged at warn-level
 * so that issuance always succeeds even when the posture surface is
 * temporarily unavailable.
 *
 * The five required parity fields (`agentId`, `owningTeam`,
 * `capabilityManifestHash`, `runtime`, `region`) flow through to each
 * downstream cloud surface under their canonical names; see
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 1.
 *
 * Manifest hashing reuses the shared {@link canonicalSha256} helper so
 * the posture record's `capabilityManifestHash` matches the value
 * recorded in audit-log evidence for the same manifest.
 *
 * **⚠ Single-writer constraint (HA deployments):**
 * {@link DurablePostureEmitter} uses SQLite in WAL mode, which allows
 * concurrent readers but only a single writer at a time. In
 * multi-replica (HA) issuer deployments, only **one** replica should
 * have an active `DurablePostureEmitter`; all other replicas should use
 * a no-op or network-forwarding emitter. Running `DurablePostureEmitter`
 * on multiple replicas targeting the same SQLite file over a shared
 * filesystem produces write contention and eventual data loss.
 *
 * Recommended HA pattern: dedicate one sidecar (or Kubernetes Job) as
 * the sole SQLite writer; have all issuer replicas enqueue records into
 * a shared queue (e.g. Redis Stream) that the sidecar drains and writes
 * to SQLite. See `docs/DEPLOYMENT.md §"Posture-emitter queue topology
 * for HA issuers"` for the reference architecture.
 */
export async function emitPostureRecord(
  emitter: PostureEmitterLike | undefined,
  logger: Logger,
  args: {
    agentId: string;
    manifest?: AgentCapabilityManifest;
    capabilities: CapabilityConstraint[];
    region: string;
  },
): Promise<void> {
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

  // Await the enqueue so the caller can be sure the record is durable
  // before the HTTP response is sent. With DurablePostureEmitter this
  // is a sub-millisecond synchronous SQLite write. Any error from the
  // emitter is caught here and logged — this is intentional: posture
  // is observability-only and must never fail the originating issuance.
  try {
    await emitter.emitObserved(record);
  } catch (err) {
    logger.warn('posture emit failed', {
      agentId: args.agentId,
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  }
}

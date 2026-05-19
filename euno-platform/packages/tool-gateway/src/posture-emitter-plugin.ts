/**
 * Gateway bridge between the AuditPipeline `onSigned` callback and the
 * DurablePostureEmitter.
 *
 * Each `SignedAuditEvidence` record that the audit pipeline successfully
 * signs is converted to an `AgentInventoryRecord` and enqueued in the
 * durable emitter for fan-out to the configured posture surface (Defender
 * CSPM, Security Hub, SCC, or stdout).
 *
 * Wiring in `audit-module.ts`: the `postureSink` option is fed into the
 * pipeline's `onSigned` callback so that every signed enforcement event
 * is observed by posture surfaces without adding latency to the request
 * critical path (the enqueue is a synchronous SQLite WAL write, typically
 * < 1 ms).
 *
 * Error contract: any failure in `emitObserved` is caught and logged at
 * `warn` level — posture emission is best-effort observability and MUST
 * NOT affect the enforcement outcome.
 *
 * ## Field mapping from `SignedAuditEvidence` to `AgentInventoryRecord`
 *
 * | Evidence field   | Inventory field          | Notes                              |
 * |------------------|--------------------------|------------------------------------|
 * | `agentId`        | `agentId`                | Direct 1:1 mapping.                |
 * | `tenantId`       | `owningTeam`             | Falls back to `'unknown'` when     |
 * |                  |                          | absent (token had no tenantId).    |
 * | `capabilityId`   | `capabilityManifestHash` | Token JTI — best proxy available   |
 * | (token JTI)      |                          | at enforcement time; the actual    |
 * |                  |                          | manifest hash is not carried in    |
 * |                  |                          | the token. Operators correlate     |
 * |                  |                          | with issuer-side posture records   |
 * |                  |                          | (which carry the real hash) via    |
 * |                  |                          | `agentId`.                         |
 * | `ts`             | `firstSeen`, `lastSeen`  | Both set to the evidence timestamp.|
 * | n/a              | `runtime`, `region`      | `'unknown'` — not carried in       |
 * |                  |                          | enforcement evidence; accurate     |
 * |                  |                          | values are in issuer-side records. |
 */

import { AgentInventoryRecord, SignedAuditEvidence, createLogger } from '@euno/common';
import { DurablePostureEmitter } from '@euno/posture-emitter';

type Logger = ReturnType<typeof createLogger>;

/**
 * Options for the gateway posture-emitter bridge.
 */
export interface PostureEmitterPluginOptions {
  /**
   * The durable emitter to enqueue records into.  The emitter must
   * already be started (`emitter.start()`) before `onSigned` is
   * first called; starting is the caller's responsibility (bootstrap.ts).
   */
  emitter: DurablePostureEmitter;
  /**
   * Optional logger for `warn`-level error reporting when `emitObserved`
   * rejects.  When omitted, errors are silently swallowed (still
   * non-fatal per the posture best-effort contract).
   */
  logger?: Logger;
}

/**
 * Gateway shim that translates signed audit evidence into posture inventory
 * records and forwards them to a {@link DurablePostureEmitter}.
 *
 * The class is intentionally stateless — the emitter owns all persistence.
 * A single instance is safe to share across multiple `onSigned` call sites.
 */
export class PostureEmitterPlugin {
  private readonly emitter: DurablePostureEmitter;
  private readonly logger?: Logger;

  constructor(opts: PostureEmitterPluginOptions) {
    this.emitter = opts.emitter;
    this.logger = opts.logger;
  }

  /**
   * Called from the audit pipeline's `onSigned` callback for each
   * successfully signed enforcement record.  The call is synchronous
   * from the caller's perspective — `emitObserved` is called with
   * `.catch()` so any I/O errors are fire-and-forget.
   *
   * Short-circuits immediately when the emitter reports `isEnabled()`
   * is false — this avoids the `evidenceToInventoryRecord` allocation
   * on the hot path for disabled deployments.
   */
  onSigned(signed: SignedAuditEvidence): void {
    if (!this.emitter.isEnabled()) return;

    const record = evidenceToInventoryRecord(signed);
    this.emitter.emitObserved(record).catch((err) => {
      this.logger?.warn?.('posture-emitter: failed to enqueue enforcement event', {
        agentId: signed.agentId,
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }
}

/**
 * Convert a `SignedAuditEvidence` record to an `AgentInventoryRecord`.
 *
 * Exported separately so it can be unit-tested in isolation and reused
 * in any future context that needs the same field mapping.
 *
 * See the module-level JSDoc for the full field-mapping table.
 */
export function evidenceToInventoryRecord(signed: SignedAuditEvidence): AgentInventoryRecord {
  return {
    schemaVersion: '1.0',
    agentId: signed.agentId,
    // tenantId is the best available proxy for owningTeam at enforcement
    // time. Issuer-side posture records carry the accurate value from
    // manifest.metadata.owner; enforcement records use tenantId as a
    // fallback so posture surfaces can at least group records by tenant.
    owningTeam: signed.tenantId ?? 'unknown',
    // capabilityId is the token JTI (not the manifest hash). At enforcement
    // time the gateway has the JTI but not the manifest. Issuer records
    // carry the correct SHA-256(canonical(manifest)) under the same agentId
    // for correlation.
    capabilityManifestHash: signed.capabilityId,
    // runtime and region are not present in enforcement evidence; the
    // 'unknown' sentinel satisfies the parity-field contract while
    // accurately representing what we know at this point.
    runtime: 'unknown',
    region: 'unknown',
    firstSeen: signed.ts,
    lastSeen: signed.ts,
  };
}

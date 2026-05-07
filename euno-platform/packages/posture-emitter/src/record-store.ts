/**
 * Local in-memory store of recently-observed agent inventory records.
 *
 * Two responsibilities:
 *
 *   1. **Dedupe** — a second `emitObserved` for an agent already seen
 *      within the dedupe window updates `lastSeen` in the cache and
 *      returns `false`, telling the facade to skip network I/O.
 *   2. **Periodic refresh source** — the facade walks all
 *      non-revoked records on the refresh interval and re-emits
 *      them so cloud surfaces (Security Hub findings expire after
 *      90 days; SCC reports `eventTime` staleness) don't age them
 *      out.
 *
 * Records are keyed by `agentId`. Revoked records remain in the store
 * with `revokedAt` set, so the periodic refresh does not "resurrect"
 * an agent that was revoked between refresh ticks.
 */
import { AgentInventoryRecord } from '@euno/common';

export interface RecordStoreOptions {
  /** Window during which a duplicate `emitObserved` is suppressed. */
  dedupeWindowMs: number;
}

export class RecordStore {
  private readonly records = new Map<string, AgentInventoryRecord>();
  private readonly dedupeWindowMs: number;

  constructor(opts: RecordStoreOptions) {
    this.dedupeWindowMs = Math.max(0, opts.dedupeWindowMs);
  }

  /**
   * Insert or refresh a record.
   *
   * Returns `true` when the caller SHOULD propagate the record to
   * downstream plugins, `false` when the record is a duplicate that
   * arrived within the dedupe window. In the duplicate case the
   * stored `lastSeen` is still updated.
   */
  upsert(record: AgentInventoryRecord, nowMs: number = Date.now()): boolean {
    const existing = this.records.get(record.agentId);
    if (!existing) {
      this.records.set(record.agentId, { ...record });
      return true;
    }
    const lastEmittedMs = Date.parse(existing.lastSeen);
    const ageMs = Number.isFinite(lastEmittedMs) ? nowMs - lastEmittedMs : Infinity;
    // Always update lastSeen + capability snapshot so the periodic
    // refresh emits a fresh timestamp later.
    const merged: AgentInventoryRecord = {
      ...existing,
      ...record,
      // Preserve the original firstSeen — a re-issuance does not
      // change when the agent was first observed.
      firstSeen: existing.firstSeen,
    };
    // Once revoked, do not silently un-revoke on a subsequent observe.
    // Revocations are sticky in this store unless the record is
    // explicitly cleared/reset (no un-revoke API is exposed on
    // purpose). This protects against a stale periodic refresh
    // racing a revocation.
    if (existing.revokedAt && !record.revokedAt) {
      merged.revokedAt = existing.revokedAt;
    }
    this.records.set(record.agentId, merged);
    return ageMs >= this.dedupeWindowMs;
  }

  /** Mark an agent as revoked. Returns the updated record, if any. */
  markRevoked(agentId: string, revokedAt: string): AgentInventoryRecord | undefined {
    const existing = this.records.get(agentId);
    if (!existing) return undefined;
    const updated: AgentInventoryRecord = { ...existing, revokedAt };
    this.records.set(agentId, updated);
    return updated;
  }

  /** Snapshot of all currently-known, non-revoked records. */
  listActive(): AgentInventoryRecord[] {
    const out: AgentInventoryRecord[] = [];
    for (const r of this.records.values()) {
      if (!r.revokedAt) out.push(r);
    }
    return out;
  }

  /** Snapshot of all records, used for tests / introspection. */
  listAll(): AgentInventoryRecord[] {
    return Array.from(this.records.values());
  }

  get size(): number {
    return this.records.size;
  }

  clear(): void {
    this.records.clear();
  }
}

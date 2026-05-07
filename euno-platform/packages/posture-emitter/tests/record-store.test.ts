/**
 * Unit tests for the local in-memory record store used by the
 * PostureEmitter facade for dedupe + periodic refresh.
 */
import { AgentInventoryRecord } from '@euno/common';
import { RecordStore } from '../src/record-store';

function makeRecord(overrides: Partial<AgentInventoryRecord> = {}): AgentInventoryRecord {
  const now = '2026-04-29T00:00:00.000Z';
  return {
    schemaVersion: '1.0',
    agentId: 'agent-1',
    owningTeam: 'team-a',
    capabilityManifestHash: 'deadbeef',
    runtime: 'node:20',
    region: 'eastus2',
    firstSeen: now,
    lastSeen: now,
    ...overrides,
  };
}

describe('RecordStore', () => {
  it('returns true on first insert', () => {
    const store = new RecordStore({ dedupeWindowMs: 1000 });
    expect(store.upsert(makeRecord())).toBe(true);
  });

  it('suppresses duplicate emits inside the dedupe window', () => {
    const store = new RecordStore({ dedupeWindowMs: 60_000 });
    const t0 = Date.parse('2026-04-29T00:00:00.000Z');
    store.upsert(makeRecord({ lastSeen: '2026-04-29T00:00:00.000Z' }), t0);
    // 30 seconds later - within window
    expect(store.upsert(makeRecord({ lastSeen: '2026-04-29T00:00:30.000Z' }), t0 + 30_000))
      .toBe(false);
  });

  it('allows re-emit once outside the dedupe window', () => {
    const store = new RecordStore({ dedupeWindowMs: 60_000 });
    const t0 = Date.parse('2026-04-29T00:00:00.000Z');
    store.upsert(makeRecord({ lastSeen: '2026-04-29T00:00:00.000Z' }), t0);
    expect(store.upsert(makeRecord({ lastSeen: '2026-04-29T00:01:01.000Z' }), t0 + 61_000))
      .toBe(true);
  });

  it('preserves firstSeen across upserts', () => {
    const store = new RecordStore({ dedupeWindowMs: 0 });
    store.upsert(makeRecord({ firstSeen: 'first', lastSeen: 'a' }));
    store.upsert(makeRecord({ firstSeen: 'second', lastSeen: 'b' }));
    expect(store.listAll()[0]!.firstSeen).toBe('first');
    expect(store.listAll()[0]!.lastSeen).toBe('b');
  });

  it('does not silently un-revoke', () => {
    const store = new RecordStore({ dedupeWindowMs: 0 });
    store.upsert(makeRecord());
    store.markRevoked('agent-1', '2026-04-29T01:00:00.000Z');
    store.upsert(makeRecord());
    expect(store.listAll()[0]!.revokedAt).toBe('2026-04-29T01:00:00.000Z');
    expect(store.listActive()).toHaveLength(0);
  });

  it('listActive excludes revoked records', () => {
    const store = new RecordStore({ dedupeWindowMs: 0 });
    store.upsert(makeRecord({ agentId: 'a' }));
    store.upsert(makeRecord({ agentId: 'b' }));
    store.markRevoked('a', '2026-04-29T01:00:00.000Z');
    expect(store.listActive().map((r) => r.agentId).sort()).toEqual(['b']);
  });
});

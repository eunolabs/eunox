/**
 * Tests for InMemoryUsageMeter.
 */

import { InMemoryUsageMeter } from '../usage-meter';

describe('InMemoryUsageMeter', () => {
  let meter: InMemoryUsageMeter;

  beforeEach(() => {
    meter = new InMemoryUsageMeter();
  });

  // ── getUsage: never-seen tenant ────────────────────────────────────────────

  describe('getUsage() for an unknown tenant', () => {
    it('returns a zero-count snapshot', () => {
      const snap = meter.getUsage('tenant-x');
      expect(snap.tenantId).toBe('tenant-x');
      expect(snap.enforcementEvents).toBe(0);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(0);
      expect(snap.killSwitchInvocations).toBe(0);
    });

    it('returns a valid ISO-8601 periodStart', () => {
      const snap = meter.getUsage('tenant-x');
      expect(() => new Date(snap.periodStart)).not.toThrow();
      expect(new Date(snap.periodStart).toISOString()).toBe(snap.periodStart);
    });

    it('does not persist the phantom tenant (getAllUsage stays empty)', () => {
      meter.getUsage('tenant-x');
      expect(meter.getAllUsage()).toHaveLength(0);
    });
  });

  // ── recordEnforcement ──────────────────────────────────────────────────────

  describe('recordEnforcement()', () => {
    it('increments enforcementEvents and allowDecisions on allow', () => {
      meter.recordEnforcement('t1', 'allow');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.allowDecisions).toBe(1);
      expect(snap.denyDecisions).toBe(0);
    });

    it('increments enforcementEvents and denyDecisions on deny', () => {
      meter.recordEnforcement('t1', 'deny');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(1);
    });

    it('accumulates across multiple calls', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'deny');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(3);
      expect(snap.allowDecisions).toBe(2);
      expect(snap.denyDecisions).toBe(1);
    });

    it('keeps tenants isolated', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      expect(meter.getUsage('t1').allowDecisions).toBe(1);
      expect(meter.getUsage('t1').denyDecisions).toBe(0);
      expect(meter.getUsage('t2').allowDecisions).toBe(0);
      expect(meter.getUsage('t2').denyDecisions).toBe(1);
    });
  });

  // ── recordKillSwitchInvocation ─────────────────────────────────────────────

  describe('recordKillSwitchInvocation()', () => {
    it('increments killSwitchInvocations', () => {
      meter.recordKillSwitchInvocation('t1');
      expect(meter.getUsage('t1').killSwitchInvocations).toBe(1);
    });

    it('accumulates across calls', () => {
      meter.recordKillSwitchInvocation('t1');
      meter.recordKillSwitchInvocation('t1');
      expect(meter.getUsage('t1').killSwitchInvocations).toBe(2);
    });

    it('does not affect enforcement counters', () => {
      meter.recordKillSwitchInvocation('t1');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(0);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(0);
    });
  });

  // ── getAllUsage ────────────────────────────────────────────────────────────

  describe('getAllUsage()', () => {
    it('returns an empty array when no events have been recorded', () => {
      expect(meter.getAllUsage()).toHaveLength(0);
    });

    it('returns one entry per active tenant', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      meter.recordKillSwitchInvocation('t3');

      const all = meter.getAllUsage();
      expect(all).toHaveLength(3);

      const ids = all.map((s) => s.tenantId).sort();
      expect(ids).toEqual(['t1', 't2', 't3']);
    });

    it('snaps are consistent with getUsage()', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'deny');
      meter.recordKillSwitchInvocation('t1');

      const fromGetAll = meter.getAllUsage().find((s) => s.tenantId === 't1')!;
      const fromGetSingle = meter.getUsage('t1');

      expect(fromGetAll.enforcementEvents).toBe(fromGetSingle.enforcementEvents);
      expect(fromGetAll.allowDecisions).toBe(fromGetSingle.allowDecisions);
      expect(fromGetAll.denyDecisions).toBe(fromGetSingle.denyDecisions);
      expect(fromGetAll.killSwitchInvocations).toBe(fromGetSingle.killSwitchInvocations);
    });
  });

  // ── resetPeriod ────────────────────────────────────────────────────────────

  describe('resetPeriod()', () => {
    it('resets all tenants when called without tenantId', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      meter.recordKillSwitchInvocation('t2');

      meter.resetPeriod();

      expect(meter.getUsage('t1').enforcementEvents).toBe(0);
      expect(meter.getUsage('t2').enforcementEvents).toBe(0);
      expect(meter.getUsage('t2').killSwitchInvocations).toBe(0);
    });

    it('resets only the specified tenant when called with tenantId', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'allow');

      meter.resetPeriod('t1');

      expect(meter.getUsage('t1').enforcementEvents).toBe(0);
      expect(meter.getUsage('t2').enforcementEvents).toBe(1);
    });

    it('is a no-op for a tenantId that has never been seen', () => {
      expect(() => meter.resetPeriod('nonexistent')).not.toThrow();
    });

    it('advances periodStart after a full reset', () => {
      meter.recordEnforcement('t1', 'allow');
      const before = meter.getUsage('t1').periodStart;

      // Advance time by at least 1 ms.
      jest.useFakeTimers();
      jest.advanceTimersByTime(5);
      meter.resetPeriod();
      jest.useRealTimers();

      const after = meter.getUsage('t1').periodStart;
      expect(new Date(after).getTime()).toBeGreaterThanOrEqual(new Date(before).getTime());
    });

    it('preserves tenant entry in getAllUsage after reset', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.resetPeriod('t1');
      const all = meter.getAllUsage();
      expect(all).toHaveLength(1);
      expect(all[0]!.tenantId).toBe('t1');
    });

    it('accumulates again after reset', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.resetPeriod('t1');
      meter.recordEnforcement('t1', 'deny');

      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(1);
    });
  });

  // ── Snapshot immutability ──────────────────────────────────────────────────

  describe('snapshot immutability', () => {
    it('mutating the returned snapshot does not affect the store', () => {
      meter.recordEnforcement('t1', 'allow');
      const snap = meter.getUsage('t1') as { enforcementEvents: number };
      snap.enforcementEvents = 999;

      // Original store must be unchanged.
      expect(meter.getUsage('t1').enforcementEvents).toBe(1);
    });
  });
});

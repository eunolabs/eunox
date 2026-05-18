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
      expect(snap.issuanceEvents).toBe(0);
      expect(snap.renewalEvents).toBe(0);
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

    it('advances periodStart on back-to-back resets without time moving', () => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
      try {
        meter.recordEnforcement('t1', 'allow');
        const before = meter.getUsage('t1').periodStart;

        meter.resetPeriod('t1');
        const first = meter.getUsage('t1').periodStart;

        meter.resetPeriod('t1');
        const second = meter.getUsage('t1').periodStart;

        expect(new Date(first).getTime()).toBeGreaterThan(new Date(before).getTime());
        expect(new Date(second).getTime()).toBeGreaterThan(new Date(first).getTime());
      } finally {
        jest.useRealTimers();
      }
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

  // ── recordIssuance ─────────────────────────────────────────────────────────

  describe('recordIssuance()', () => {
    it('increments issuanceEvents', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      expect(meter.getUsage('t1').issuanceEvents).toBe(1);
    });

    it('accumulates across multiple calls', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t1', 'bob@example.com');
      expect(meter.getUsage('t1').issuanceEvents).toBe(3);
    });

    it('does not affect enforcement counters', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(0);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(0);
    });

    it('keeps tenants isolated', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t2', 'bob@example.com');
      expect(meter.getUsage('t1').issuanceEvents).toBe(1);
      expect(meter.getUsage('t2').issuanceEvents).toBe(1);
    });

    it('tracks per-user breakdown in issuancesByUser', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t1', 'bob@example.com');
      const snap = meter.getUsage('t1');
      expect(snap.issuancesByUser?.['alice@example.com']).toBe(2);
      expect(snap.issuancesByUser?.['bob@example.com']).toBe(1);
    });
  });

  // ── recordRenewal ──────────────────────────────────────────────────────────

  describe('recordRenewal()', () => {
    it('increments renewalEvents', () => {
      meter.recordRenewal('t1', 'alice@example.com');
      expect(meter.getUsage('t1').renewalEvents).toBe(1);
    });

    it('accumulates across multiple calls', () => {
      meter.recordRenewal('t1', 'alice@example.com');
      meter.recordRenewal('t1', 'alice@example.com');
      meter.recordRenewal('t1', 'bob@example.com');
      expect(meter.getUsage('t1').renewalEvents).toBe(3);
    });

    it('does not affect enforcement or issuance counters', () => {
      meter.recordRenewal('t1', 'alice@example.com');
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(0);
      expect(snap.issuanceEvents).toBe(0);
    });

    it('tracks per-user breakdown in renewalsByUser', () => {
      meter.recordRenewal('t1', 'alice@example.com');
      meter.recordRenewal('t1', 'bob@example.com');
      meter.recordRenewal('t1', 'bob@example.com');
      const snap = meter.getUsage('t1');
      expect(snap.renewalsByUser?.['alice@example.com']).toBe(1);
      expect(snap.renewalsByUser?.['bob@example.com']).toBe(2);
    });
  });

  // ── Meter dual-write test (Task 10) ────────────────────────────────────────

  describe('dual-write: enforcement + issuance + renewal on same meter', () => {
    it('enforcement and issuance are tracked independently on the same tenant', () => {
      // Dual-write: both enforcement decisions AND issuance events go through
      // the same meter instance for the same tenant.
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'deny');
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordRenewal('t1', 'alice@example.com');

      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(2);
      expect(snap.allowDecisions).toBe(1);
      expect(snap.denyDecisions).toBe(1);
      expect(snap.issuanceEvents).toBe(1);
      expect(snap.renewalEvents).toBe(1);
    });

    it('writing enforcement for t1 does not affect issuance counter for t1', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'allow');
      expect(meter.getUsage('t1').issuanceEvents).toBe(0);
      expect(meter.getUsage('t1').renewalEvents).toBe(0);
    });

    it('writing issuance for t1 does not affect enforcement counter for t1', () => {
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordIssuance('t1', 'alice@example.com');
      expect(meter.getUsage('t1').enforcementEvents).toBe(0);
      expect(meter.getUsage('t1').allowDecisions).toBe(0);
    });

    it('getAllUsage() reflects all three event types simultaneously', () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordIssuance('t1', 'alice@example.com');
      meter.recordRenewal('t1', 'alice@example.com');
      meter.recordKillSwitchInvocation('t1');

      const all = meter.getAllUsage();
      expect(all).toHaveLength(1);
      const snap = all[0]!;
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.issuanceEvents).toBe(1);
      expect(snap.renewalEvents).toBe(1);
      expect(snap.killSwitchInvocations).toBe(1);
    });
  });

  // ── Tenant aggregation test (Task 10) ─────────────────────────────────────

  describe('tenant aggregation: multiple users aggregate at tenant level', () => {
    it('issuances from 5 distinct users aggregate into a single tenant issuanceEvents total', () => {
      const users = ['alice', 'bob', 'carol', 'dave', 'eve'];
      for (const user of users) {
        meter.recordIssuance('acme', `${user}@acme.com`);
        meter.recordIssuance('acme', `${user}@acme.com`); // 2 issuances each
      }

      const snap = meter.getUsage('acme');
      // Billing aggregate: 5 users × 2 issuances = 10
      expect(snap.issuanceEvents).toBe(10);
      // Per-user forensics breakdown
      for (const user of users) {
        expect(snap.issuancesByUser?.[`${user}@acme.com`]).toBe(2);
      }
    });

    it('issuances for different tenants do not leak across tenant boundaries', () => {
      meter.recordIssuance('tenant-a', 'user-a@corp.com');
      meter.recordIssuance('tenant-a', 'user-a@corp.com');
      meter.recordIssuance('tenant-b', 'user-b@other.com');

      expect(meter.getUsage('tenant-a').issuanceEvents).toBe(2);
      expect(meter.getUsage('tenant-b').issuanceEvents).toBe(1);
      // Cross-contamination check: tenant-a's per-user data has no trace of tenant-b users
      expect(meter.getUsage('tenant-a').issuancesByUser?.['user-b@other.com']).toBeUndefined();
    });

    it('renewals from multiple users aggregate at the tenant level', () => {
      meter.recordRenewal('t1', 'alice@corp.com');
      meter.recordRenewal('t1', 'alice@corp.com');
      meter.recordRenewal('t1', 'bob@corp.com');
      meter.recordRenewal('t1', 'carol@corp.com');

      const snap = meter.getUsage('t1');
      expect(snap.renewalEvents).toBe(4);
      expect(snap.renewalsByUser?.['alice@corp.com']).toBe(2);
      expect(snap.renewalsByUser?.['bob@corp.com']).toBe(1);
      expect(snap.renewalsByUser?.['carol@corp.com']).toBe(1);
    });

    it('resetPeriod() clears per-user breakdowns along with aggregate counts', () => {
      meter.recordIssuance('t1', 'alice@corp.com');
      meter.recordRenewal('t1', 'alice@corp.com');
      meter.resetPeriod('t1');

      const snap = meter.getUsage('t1');
      expect(snap.issuanceEvents).toBe(0);
      expect(snap.renewalEvents).toBe(0);
      expect(snap.issuancesByUser).toEqual({});
      expect(snap.renewalsByUser).toEqual({});
    });
  });
});

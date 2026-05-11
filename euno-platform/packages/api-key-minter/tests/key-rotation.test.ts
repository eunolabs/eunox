/**
 * KeyRotationManager — unit tests (Task 11, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. **initiateRotation()** — Writes a `rotation_start` audit row, adds the
 *      new key to the JWKS store; is idempotent on duplicate calls.
 *
 *   2. **Emergency rotation** — `reason: 'emergency'` stamps the audit row
 *      with `result: 'rotation_emergency'`.
 *
 *   3. **completeRotation()** — Removes the old key from the JWKS store, writes
 *      a `rotation_complete` audit row.
 *
 *   4. **JWKS store state** — After initiate, both old and new keys are in
 *      JWKS; after complete, only the new key remains.
 *
 *   5. **Audit trail completeness** — Audit rows have correct fields (tenantId,
 *      kid, result, reason, non-empty jti).
 */

import {
  KeyRotationManager,
  InMemoryJwksStore,
} from '../src/key-rotation';
import { InMemoryMintAuditStore } from '../src/mint-audit';
import type { JwksKeyEntry, RotationOptions } from '../src/key-rotation';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeKey(kid: string, alg = 'ES256'): JwksKeyEntry {
  return { kid, alg, kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y' };
}

function makeRotationManager(tenantId = 'tenant-acme'): {
  manager: KeyRotationManager;
  auditStore: InMemoryMintAuditStore;
  jwksStore: InMemoryJwksStore;
} {
  const auditStore = new InMemoryMintAuditStore();
  const jwksStore = new InMemoryJwksStore();
  const manager = new KeyRotationManager({ auditStore, jwksStore, tenantId });
  return { manager, auditStore, jwksStore };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('KeyRotationManager', () => {
  // ── initiateRotation ──────────────────────────────────────────────────────

  describe('initiateRotation()', () => {
    it('writes a rotation_start audit row', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const rows = auditStore.getAll();
      const rotRow = rows.find(r => r.result === 'rotation_start');
      expect(rotRow).toBeDefined();
    });

    it('audit row has the correct fields', async () => {
      const { manager, auditStore } = makeRotationManager('tenant-abc');
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const row = auditStore.getAll().find(r => r.result === 'rotation_start')!;
      expect(row.tenantId).toBe('tenant-abc');
      expect(row.kid).toBe('new-key-v2');
      expect(row.jti).toBeTruthy();
      expect(row.reason).toMatch(/old-key-v1/); // retiring message includes old kid
    });

    it('adds the new key to the JWKS store', async () => {
      const { manager, jwksStore } = makeRotationManager();
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const keys = await jwksStore.listKeys();
      expect(keys.some(k => k.kid === 'new-key-v2')).toBe(true);
    });

    it('leaves the old key in JWKS after initiation (transition window)', async () => {
      const { manager, jwksStore } = makeRotationManager();
      await jwksStore.addKey(makeKey('old-key-v1'));
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const keys = await jwksStore.listKeys();
      expect(keys.some(k => k.kid === 'old-key-v1')).toBe(true);
      expect(keys.some(k => k.kid === 'new-key-v2')).toBe(true);
    });

    it('returns the audit JTI and kind=scheduled', async () => {
      const { manager } = makeRotationManager();
      const result = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      expect(result.auditJti).toBeTruthy();
      expect(result.kind).toBe('scheduled');
    });

    it('is idempotent — duplicate call returns same auditJti without writing a new row', async () => {
      const { manager, auditStore } = makeRotationManager();
      const r1 = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const r2 = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      expect(r2.auditJti).toBe(r1.auditJti);
      const rotRows = auditStore.getAll().filter(r => r.result === 'rotation_start');
      expect(rotRows).toHaveLength(1);
    });

    it('includes initiatedBy in the audit reason when provided', async () => {
      const { manager, auditStore } = makeRotationManager();
      const opts: RotationOptions = { reason: 'scheduled', initiatedBy: 'alice' };
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', opts);
      const row = auditStore.getAll().find(r => r.result === 'rotation_start')!;
      expect(row.reason).toMatch(/alice/);
    });
  });

  // ── Emergency rotation ───────────────────────────────────────────────────

  describe('initiateRotation() — emergency', () => {
    it('writes a rotation_emergency audit row when reason=emergency', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', {
        reason: 'emergency',
      });
      const row = auditStore.getAll().find(r => r.result === 'rotation_emergency');
      expect(row).toBeDefined();
    });

    it('returns kind=emergency', async () => {
      const { manager } = makeRotationManager();
      const result = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', {
        reason: 'emergency',
      });
      expect(result.kind).toBe('emergency');
    });

    it('does NOT write rotation_start for emergency rotations', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', {
        reason: 'emergency',
      });
      const startRows = auditStore.getAll().filter(r => r.result === 'rotation_start');
      expect(startRows).toHaveLength(0);
    });

    it('emergency is idempotent — duplicate call for same new kid returns same jti', async () => {
      const { manager } = makeRotationManager();
      const r1 = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', {
        reason: 'emergency',
      });
      const r2 = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1', {
        reason: 'emergency',
      });
      expect(r2.auditJti).toBe(r1.auditJti);
    });
  });

  // ── completeRotation ─────────────────────────────────────────────────────

  describe('completeRotation()', () => {
    it('removes the old key from the JWKS store', async () => {
      const { manager, jwksStore } = makeRotationManager();
      await jwksStore.addKey(makeKey('old-key-v1'));
      await jwksStore.addKey(makeKey('new-key-v2'));
      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const keys = await jwksStore.listKeys();
      expect(keys.some(k => k.kid === 'old-key-v1')).toBe(false);
    });

    it('leaves the new key in JWKS after completion', async () => {
      const { manager, jwksStore } = makeRotationManager();
      await jwksStore.addKey(makeKey('old-key-v1'));
      await jwksStore.addKey(makeKey('new-key-v2'));
      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const keys = await jwksStore.listKeys();
      expect(keys.some(k => k.kid === 'new-key-v2')).toBe(true);
    });

    it('writes a rotation_complete audit row', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const row = auditStore.getAll().find(r => r.result === 'rotation_complete');
      expect(row).toBeDefined();
    });

    it('rotation_complete audit row has correct fields', async () => {
      const { manager, auditStore } = makeRotationManager('tenant-xyz');
      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const row = auditStore.getAll().find(r => r.result === 'rotation_complete')!;
      expect(row.tenantId).toBe('tenant-xyz');
      expect(row.kid).toBe('new-key-v2');
      expect(row.reason).toMatch(/old-key-v1/);
    });

    it('returns the audit JTI and the retired kid', async () => {
      const { manager } = makeRotationManager();
      const result = await manager.completeRotation('new-key-v2', 'old-key-v1');
      expect(result.auditJti).toBeTruthy();
      expect(result.retiredKid).toBe('old-key-v1');
    });

    it('includes initiatedBy in the completion audit reason', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.completeRotation('new-key-v2', 'old-key-v1', { initiatedBy: 'bob' });
      const row = auditStore.getAll().find(r => r.result === 'rotation_complete')!;
      expect(row.reason).toMatch(/bob/);
    });
  });

  // ── Full rotation flow ───────────────────────────────────────────────────

  describe('full rotation flow (initiate → complete)', () => {
    it('JWKS has both keys after initiate, only new key after complete', async () => {
      const { manager, jwksStore } = makeRotationManager();
      await jwksStore.addKey(makeKey('old-key-v1'));

      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const duringRotation = await jwksStore.listKeys();
      expect(duringRotation.map(k => k.kid)).toContain('old-key-v1');
      expect(duringRotation.map(k => k.kid)).toContain('new-key-v2');

      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const afterRotation = await jwksStore.listKeys();
      expect(afterRotation.map(k => k.kid)).not.toContain('old-key-v1');
      expect(afterRotation.map(k => k.kid)).toContain('new-key-v2');
    });

    it('audit trail has rotation_start then rotation_complete rows', async () => {
      const { manager, auditStore } = makeRotationManager();
      await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      await manager.completeRotation('new-key-v2', 'old-key-v1');
      const rows = auditStore.getAll();
      const start = rows.find(r => r.result === 'rotation_start');
      const complete = rows.find(r => r.result === 'rotation_complete');
      expect(start).toBeDefined();
      expect(complete).toBeDefined();
      // start row precedes complete row in the audit trail
      expect(start!.id!).toBeLessThan(complete!.id!);
    });

    it('each rotation generates unique JTIs', async () => {
      const { manager } = makeRotationManager();
      const r1 = await manager.initiateRotation(makeKey('new-key-v2'), 'old-key-v1');
      const r2 = await manager.completeRotation('new-key-v2', 'old-key-v1');
      expect(r1.auditJti).not.toBe(r2.auditJti);
    });
  });

  // ── InMemoryJwksStore ────────────────────────────────────────────────────

  describe('InMemoryJwksStore', () => {
    it('addKey stores a key', async () => {
      const store = new InMemoryJwksStore();
      await store.addKey(makeKey('k1'));
      const keys = await store.listKeys();
      expect(keys).toHaveLength(1);
      expect(keys[0]!.kid).toBe('k1');
    });

    it('addKey replaces existing key with same kid (upsert)', async () => {
      const store = new InMemoryJwksStore();
      await store.addKey({ kid: 'k1', alg: 'ES256', kty: 'EC' });
      await store.addKey({ kid: 'k1', alg: 'RS256', kty: 'RSA' }); // same kid
      const keys = await store.listKeys();
      expect(keys).toHaveLength(1);
      expect(keys[0]!.alg).toBe('RS256');
    });

    it('removeKey removes the key', async () => {
      const store = new InMemoryJwksStore();
      await store.addKey(makeKey('k1'));
      await store.addKey(makeKey('k2'));
      await store.removeKey('k1');
      const keys = await store.listKeys();
      expect(keys.map(k => k.kid)).toEqual(['k2']);
    });

    it('removeKey on non-existent kid is a no-op', async () => {
      const store = new InMemoryJwksStore();
      await expect(store.removeKey('nonexistent')).resolves.not.toThrow();
    });

    it('listKeys returns all keys', async () => {
      const store = new InMemoryJwksStore();
      await store.addKey(makeKey('k1'));
      await store.addKey(makeKey('k2'));
      await store.addKey(makeKey('k3'));
      const keys = await store.listKeys();
      expect(keys.map(k => k.kid).sort()).toEqual(['k1', 'k2', 'k3']);
    });
  });
});

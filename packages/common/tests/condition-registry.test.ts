/**
 * Tests for the shared condition registry: validation at issuance,
 * enforcement at request, and the deny-by-default treatment of
 * unknown / unregistered condition types.
 */

import {
  validateCondition,
  validateConditions,
  enforceCondition,
  enforceConditions,
  registerCustomCondition,
  _resetCustomConditionRegistry,
  ConditionValidationError,
  ConditionContext,
  CallCounterStore,
  isValidCidr,
  ipMatchesCidr,
  CapabilityCondition,
  InMemoryCallCounterStore,
} from '../src';

describe('validateCondition', () => {
  beforeEach(() => _resetCustomConditionRegistry());

  it('rejects non-objects and missing type discriminators', () => {
    expect(() => validateCondition(null)).toThrow(ConditionValidationError);
    expect(() => validateCondition({} as unknown)).toThrow(/missing a 'type'/);
    expect(() => validateCondition({ type: '' } as unknown)).toThrow(/missing a 'type'/);
  });

  it('rejects unknown discriminators (deny-by-default at mint time)', () => {
    expect(() => validateCondition({ type: 'rateLimit' } as unknown)).toThrow(
      /unrecognized condition type 'rateLimit'/,
    );
  });

  describe('timeWindow', () => {
    it('requires at least one boundary', () => {
      expect(() => validateCondition({ type: 'timeWindow' })).toThrow(
        /at least one of 'notBefore' or 'notAfter'/,
      );
    });
    it('requires full ISO timestamps (rejects calendar-only)', () => {
      expect(() =>
        validateCondition({ type: 'timeWindow', notAfter: '2026-01-01' }),
      ).toThrow(/full ISO 8601 datetime/);
    });
    it('rejects non-string, non-parseable values', () => {
      expect(() =>
        validateCondition({ type: 'timeWindow', notAfter: 12345 } as unknown),
      ).toThrow(/must be a string/);
      expect(() =>
        validateCondition({ type: 'timeWindow', notAfter: 'T-not-a-date' }),
      ).toThrow(/not a valid ISO 8601/);
    });
    it('rejects an inverted window', () => {
      expect(() =>
        validateCondition({
          type: 'timeWindow',
          notBefore: '2027-01-01T00:00:00Z',
          notAfter: '2026-01-01T00:00:00Z',
        }),
      ).toThrow(/notAfter must be on or after .*notBefore/);
    });
    it('accepts a valid window', () => {
      expect(() =>
        validateCondition({
          type: 'timeWindow',
          notBefore: '2026-01-01T00:00:00Z',
          notAfter: '2027-01-01T00:00:00Z',
        }),
      ).not.toThrow();
    });
  });

  describe('ipRange', () => {
    it('rejects empty / non-array CIDRs', () => {
      expect(() => validateCondition({ type: 'ipRange', cidrs: [] })).toThrow();
      expect(() =>
        validateCondition({ type: 'ipRange', cidrs: 'not-an-array' as unknown as string[] }),
      ).toThrow();
    });
    it('rejects malformed CIDR entries', () => {
      expect(() =>
        validateCondition({ type: 'ipRange', cidrs: ['10.0.0.0/33'] }),
      ).toThrow(/invalid CIDR/);
      expect(() =>
        validateCondition({ type: 'ipRange', cidrs: ['not-a-cidr'] }),
      ).toThrow(/invalid CIDR/);
    });
    it('accepts IPv4 and IPv6 CIDRs', () => {
      expect(() =>
        validateCondition({ type: 'ipRange', cidrs: ['10.0.0.0/8', '2001:db8::/32'] }),
      ).not.toThrow();
    });
  });

  describe('maxCalls', () => {
    it('rejects non-positive integers', () => {
      expect(() =>
        validateCondition({ type: 'maxCalls', count: 0, windowSeconds: 60 }),
      ).toThrow(/positive integer/);
      expect(() =>
        validateCondition({ type: 'maxCalls', count: 1.5, windowSeconds: 60 }),
      ).toThrow(/positive integer/);
      expect(() =>
        validateCondition({ type: 'maxCalls', count: 5, windowSeconds: 0 }),
      ).toThrow(/positive integer/);
    });
    it('accepts positive integer count and window', () => {
      expect(() =>
        validateCondition({ type: 'maxCalls', count: 10, windowSeconds: 60 }),
      ).not.toThrow();
    });
  });

  describe('recipientDomain', () => {
    it('rejects entries containing @ (looks like an address)', () => {
      expect(() =>
        validateCondition({ type: 'recipientDomain', domains: ['user@example.com'] }),
      ).toThrow(/bare domain/);
    });
    it('accepts bare domains', () => {
      expect(() =>
        validateCondition({ type: 'recipientDomain', domains: ['example.com', 'corp.example'] }),
      ).not.toThrow();
    });
  });

  describe('allowedTables', () => {
    it('validates the optional columns map', () => {
      expect(() =>
        validateCondition({
          type: 'allowedTables',
          tables: ['customers'],
          columns: { customers: [] },
        }),
      ).toThrow(/non-empty array/);
      expect(() =>
        validateCondition({
          type: 'allowedTables',
          tables: ['customers'],
          columns: 'invalid' as unknown as Record<string, string[]>,
        }),
      ).toThrow(/must be an object/);
    });
  });

  describe('custom', () => {
    it('rejects custom conditions with no registered handler', () => {
      expect(() =>
        validateCondition({ type: 'custom', name: 'foo', config: {} }),
      ).toThrow(/no registered handler/);
    });
    it('delegates to a registered handler', () => {
      let validated: unknown;
      registerCustomCondition('foo', {
        validate: (cfg) => {
          validated = cfg;
          if (typeof cfg !== 'object' || cfg === null) throw new Error('cfg must be object');
        },
        enforce: () => ({ allow: true }),
      });
      expect(() =>
        validateCondition({ type: 'custom', name: 'foo', config: { x: 1 } }),
      ).not.toThrow();
      expect(validated).toEqual({ x: 1 });
      expect(() =>
        validateCondition({ type: 'custom', name: 'foo', config: 'not-an-object' }),
      ).toThrow(/cfg must be object/);
    });
  });

  describe('validateConditions', () => {
    it('annotates the failing index in the error message', () => {
      expect(() =>
        validateConditions([
          { type: 'timeWindow', notAfter: '2027-01-01T00:00:00Z' },
          { type: 'ipRange', cidrs: ['bad'] },
        ] as unknown as CapabilityCondition[]),
      ).toThrow(/conditions\[1\]/);
    });
    it('treats a non-array as a hard validation error', () => {
      expect(() =>
        validateConditions('not-an-array' as unknown as CapabilityCondition[]),
      ).toThrow(/must be an array/);
    });
  });
});

describe('enforceCondition', () => {
  beforeEach(() => _resetCustomConditionRegistry());

  it('denies unknown types (deny-by-default at request time)', async () => {
    const result = await enforceCondition(
      { type: 'mystery' } as unknown as CapabilityCondition,
      {},
    );
    expect(result).toEqual({ allow: false, reason: expect.stringMatching(/mystery/) });
  });

  describe('timeWindow', () => {
    it('denies before notBefore', async () => {
      const r = await enforceCondition(
        { type: 'timeWindow', notBefore: '2030-01-01T00:00:00Z' },
        { now: new Date('2026-01-01T00:00:00Z') },
      );
      expect(r.allow).toBe(false);
    });
    it('denies after notAfter', async () => {
      const r = await enforceCondition(
        { type: 'timeWindow', notAfter: '2024-01-01T00:00:00Z' },
        { now: new Date('2026-01-01T00:00:00Z') },
      );
      expect(r.allow).toBe(false);
    });
    it('allows inside the window', async () => {
      const r = await enforceCondition(
        {
          type: 'timeWindow',
          notBefore: '2024-01-01T00:00:00Z',
          notAfter: '2030-01-01T00:00:00Z',
        },
        { now: new Date('2026-01-01T00:00:00Z') },
      );
      expect(r.allow).toBe(true);
    });
  });

  describe('ipRange', () => {
    it('denies when sourceIp is missing from context', async () => {
      const r = await enforceCondition({ type: 'ipRange', cidrs: ['10.0.0.0/8'] }, {});
      expect(r.allow).toBe(false);
    });
    it('matches IPv4 inside range, denies outside', async () => {
      const cond = { type: 'ipRange' as const, cidrs: ['10.0.0.0/8', '192.168.1.0/24'] };
      expect((await enforceCondition(cond, { sourceIp: '10.5.6.7' })).allow).toBe(true);
      expect((await enforceCondition(cond, { sourceIp: '192.168.1.42' })).allow).toBe(true);
      expect((await enforceCondition(cond, { sourceIp: '11.0.0.1' })).allow).toBe(false);
      expect((await enforceCondition(cond, { sourceIp: '192.168.2.1' })).allow).toBe(false);
    });
    it('matches IPv6 inside range', async () => {
      const cond = { type: 'ipRange' as const, cidrs: ['2001:db8::/32'] };
      expect((await enforceCondition(cond, { sourceIp: '2001:db8:1:2::3' })).allow).toBe(true);
      expect((await enforceCondition(cond, { sourceIp: '2001:db9::1' })).allow).toBe(false);
    });
    it('denies on family mismatch', async () => {
      expect(
        (
          await enforceCondition(
            { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
            { sourceIp: '2001:db8::1' },
          )
        ).allow,
      ).toBe(false);
    });
  });

  describe('allowedOperations', () => {
    const cond = { type: 'allowedOperations' as const, operations: ['SELECT', 'EXPLAIN'] };
    it('allows when operation is in the allowlist (case-insensitive)', async () => {
      expect((await enforceCondition(cond, { operation: 'select' })).allow).toBe(true);
      expect((await enforceCondition(cond, { operation: 'EXPLAIN' })).allow).toBe(true);
    });
    it('denies otherwise', async () => {
      expect((await enforceCondition(cond, { operation: 'DROP' })).allow).toBe(false);
    });
    it('denies when operation missing', async () => {
      expect((await enforceCondition(cond, {})).allow).toBe(false);
    });
  });

  describe('allowedExtensions', () => {
    const cond = { type: 'allowedExtensions' as const, extensions: ['.txt', 'json'] };
    it('matches extensions with or without dot, case-insensitive', async () => {
      expect((await enforceCondition(cond, { filePath: '/x/y.TXT' })).allow).toBe(true);
      expect((await enforceCondition(cond, { filePath: 'a.json' })).allow).toBe(true);
    });
    it('denies on mismatch', async () => {
      expect((await enforceCondition(cond, { filePath: 'a.exe' })).allow).toBe(false);
    });
  });

  describe('allowedTables', () => {
    const cond = {
      type: 'allowedTables' as const,
      tables: ['customers', 'orders'],
      columns: { customers: ['id', 'name'], orders: ['*'] },
    };
    it('allows tables in the list', async () => {
      expect(
        (await enforceCondition(cond, { tables: [{ table: 'customers' }] })).allow,
      ).toBe(true);
    });
    it('denies tables outside the list', async () => {
      expect(
        (await enforceCondition(cond, { tables: [{ table: 'secret' }] })).allow,
      ).toBe(false);
    });
    it('honors per-table column allowlists', async () => {
      expect(
        (
          await enforceCondition(cond, {
            tables: [{ table: 'customers', columns: ['id', 'name'] }],
          })
        ).allow,
      ).toBe(true);
      expect(
        (
          await enforceCondition(cond, {
            tables: [{ table: 'customers', columns: ['id', 'ssn'] }],
          })
        ).allow,
      ).toBe(false);
    });
    it("treats '*' as wildcard for columns", async () => {
      expect(
        (
          await enforceCondition(cond, {
            tables: [{ table: 'orders', columns: ['amount', 'currency', 'whatever'] }],
          })
        ).allow,
      ).toBe(true);
    });
  });

  describe('maxCalls', () => {
    it('denies without a counter store / key (deny-by-default)', async () => {
      const r = await enforceCondition({ type: 'maxCalls', count: 1, windowSeconds: 60 }, {});
      expect(r.allow).toBe(false);
    });
    it('allows up to the budget then denies', async () => {
      const store = new InMemoryCallCounterStore();
      const cond = { type: 'maxCalls' as const, count: 2, windowSeconds: 60 };
      const ctx: ConditionContext = { counterStore: store, counterKey: 'cap-1' };
      expect((await enforceCondition(cond, ctx)).allow).toBe(true);
      expect((await enforceCondition(cond, ctx)).allow).toBe(true);
      expect((await enforceCondition(cond, ctx)).allow).toBe(false);
    });
  });

  describe('recipientDomain', () => {
    const cond = { type: 'recipientDomain' as const, domains: ['example.com'] };
    it('allows when every recipient is in an allowed domain', async () => {
      expect(
        (
          await enforceCondition(cond, {
            recipients: ['alice@EXAMPLE.com', 'bob@example.com'],
          })
        ).allow,
      ).toBe(true);
    });
    it('denies if any recipient is not', async () => {
      expect(
        (
          await enforceCondition(cond, {
            recipients: ['alice@example.com', 'eve@evil.com'],
          })
        ).allow,
      ).toBe(false);
    });
    it('denies a recipient with no @', async () => {
      expect(
        (await enforceCondition(cond, { recipients: ['no-at-symbol'] })).allow,
      ).toBe(false);
    });
    it('denies when no recipients in context', async () => {
      expect((await enforceCondition(cond, {})).allow).toBe(false);
    });
  });

  describe('redactFields', () => {
    it('always allows (the obligation is enforced by the response post-processor)', async () => {
      expect(
        (await enforceCondition({ type: 'redactFields', fields: ['ssn'] }, {})).allow,
      ).toBe(true);
    });
  });

  describe('custom', () => {
    it('denies when no handler is registered', async () => {
      const r = await enforceCondition(
        { type: 'custom', name: 'unknown', config: {} },
        {},
      );
      expect(r.allow).toBe(false);
    });
    it('delegates to the registered handler', async () => {
      registerCustomCondition('always-deny', {
        validate: () => undefined,
        enforce: () => ({ allow: false, reason: 'nope' }),
      });
      const r = await enforceCondition(
        { type: 'custom', name: 'always-deny', config: {} },
        {},
      );
      expect(r).toEqual({ allow: false, reason: 'nope' });
    });
    it('honors a per-context handler map override', async () => {
      const handlers: Map<string, import('../src').CustomConditionHandler> = new Map();
      handlers.set('scoped', {
        validate: () => undefined,
        enforce: () => ({ allow: true }),
      });
      const r = await enforceCondition(
        { type: 'custom', name: 'scoped', config: {} },
        { customHandlers: handlers },
      );
      expect(r.allow).toBe(true);
    });
  });

  describe('enforceConditions', () => {
    it('returns allow on an empty list', async () => {
      expect((await enforceConditions(undefined, {})).allow).toBe(true);
      expect((await enforceConditions([], {})).allow).toBe(true);
    });

    it('short-circuits on the first denial', async () => {
      const store = new InMemoryCallCounterStore();
      const conds: CapabilityCondition[] = [
        { type: 'timeWindow', notAfter: '2024-01-01T00:00:00Z' }, // will deny
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ];
      const r = await enforceConditions(conds, {
        now: new Date('2026-01-01T00:00:00Z'),
        counterStore: store,
        counterKey: 'k',
      });
      expect(r.allow).toBe(false);
      // The maxCalls handler must not have been called (counter remains 0).
      expect(store.size()).toBe(0);
    });

    it('scopes maxCalls counters per condition index so multiple maxCalls do not collide', async () => {
      const store = new InMemoryCallCounterStore();
      const conds: CapabilityCondition[] = [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
        { type: 'maxCalls', count: 5, windowSeconds: 60 },
      ];
      const ctx: ConditionContext = { counterStore: store, counterKey: 'cap' };
      // First call: both counters = 1, both allow.
      expect((await enforceConditions(conds, ctx)).allow).toBe(true);
      // Second call: first counter would tick to 2 > 1 → deny.
      expect((await enforceConditions(conds, ctx)).allow).toBe(false);
      expect(store.size()).toBe(2); // distinct keys per index
    });
  });
});

describe('CIDR helpers', () => {
  it('isValidCidr accepts canonical forms and rejects the rest', () => {
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('0.0.0.0/0')).toBe(true);
    expect(isValidCidr('255.255.255.255/32')).toBe(true);
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
    expect(isValidCidr('256.0.0.0/8')).toBe(false);
    expect(isValidCidr('no-slash')).toBe(false);
    expect(isValidCidr('2001:db8::/32')).toBe(true);
    expect(isValidCidr('2001:db8::/129')).toBe(false);
    expect(isValidCidr('::/0')).toBe(true);
    expect(isValidCidr('::ffff:192.168.0.1/128')).toBe(true);
  });

  it('ipMatchesCidr handles boundary cases', () => {
    expect(ipMatchesCidr('10.255.255.255', '10.0.0.0/8')).toBe(true);
    expect(ipMatchesCidr('11.0.0.0', '10.0.0.0/8')).toBe(false);
    expect(ipMatchesCidr('10.0.0.0', '10.0.0.0/32')).toBe(true);
    expect(ipMatchesCidr('10.0.0.1', '10.0.0.0/32')).toBe(false);
    expect(ipMatchesCidr('1.2.3.4', '0.0.0.0/0')).toBe(true);
    expect(ipMatchesCidr('2001:db8:1::1', '2001:db8::/32')).toBe(true);
    expect(ipMatchesCidr('2001:db9::1', '2001:db8::/32')).toBe(false);
    expect(ipMatchesCidr('2001:db8::1', '2001:db8::1/128')).toBe(true);
  });
});

describe('counter store interface plumbing', () => {
  it('uses the per-call counterKey suffix so different conditions on the same capability do not share a budget', async () => {
    const seen: string[] = [];
    const store: CallCounterStore = {
      async incrementAndGet(key) {
        seen.push(key);
        return 1;
      },
    };
    await enforceConditions(
      [
        { type: 'maxCalls', count: 10, windowSeconds: 1 },
        { type: 'maxCalls', count: 10, windowSeconds: 1 },
      ],
      { counterStore: store, counterKey: 'cap' },
    );
    expect(new Set(seen).size).toBe(2);
  });
});

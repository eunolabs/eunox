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
    // Regression: an issuer that authored the columns map with a
    // different casing than the request (e.g. `{"Customers": [...]}`
    // matched against a request that uses `customers`) must still
    // have the column allowlist applied. Earlier behavior silently
    // skipped the check when keys did not match exactly — a fail-open
    // path that has now been closed by case-insensitive lookup on the
    // columns map.
    it('applies column allowlist case-insensitively to the columns map keys', async () => {
      const mixedCaseCond = {
        type: 'allowedTables' as const,
        tables: ['customers'],
        columns: { Customers: ['id', 'name'] },
      };
      expect(
        (
          await enforceCondition(mixedCaseCond, {
            tables: [{ table: 'customers', columns: ['ssn'] }],
          })
        ).allow,
      ).toBe(false);
      expect(
        (
          await enforceCondition(mixedCaseCond, {
            tables: [{ table: 'customers', columns: ['id'] }],
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
    // An empty local-part (`@example.com`) or empty domain
    // (`alice@`) is not a usable address; both must deny rather than
    // accidentally pass the domain check on a degenerate string.
    it('denies recipients with empty local-part or empty domain', async () => {
      expect(
        (await enforceCondition(cond, { recipients: ['@example.com'] })).allow,
      ).toBe(false);
      expect(
        (await enforceCondition(cond, { recipients: ['alice@'] })).allow,
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
    // Reject leading-zero octets (`010` is octal `8` in some host
    // resolvers): the textual CIDR must have one canonical
    // interpretation regardless of which runtime parses it.
    expect(isValidCidr('010.0.0.0/8')).toBe(false);
    expect(isValidCidr('192.168.001.1/32')).toBe(false);
    // The literal `0` (no leading zero) is still valid.
    expect(isValidCidr('0.0.0.0/0')).toBe(true);
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

// ---------------------------------------------------------------------------
// R-4 step 1 — redact lobe + redactConditions response post-processor
// ---------------------------------------------------------------------------

describe('redactConditions (R-4 step 1)', () => {
  const { redactConditions } = require('../src') as typeof import('../src');

  it('returns the body unchanged when no conditions declare redact', () => {
    const body = { id: 1, ssn: 'x' };
    expect(redactConditions(undefined, body)).toBe(body);
    expect(redactConditions([], body)).toBe(body);
    expect(
      redactConditions([{ type: 'timeWindow', notAfter: '2999-01-01T00:00:00Z' }], body),
    ).toBe(body);
  });

  it('strips top-level fields named in redactFields', () => {
    const body = { id: 1, ssn: '111-22-3333', name: 'Alice' };
    const out = redactConditions(
      [{ type: 'redactFields', fields: ['ssn'] }],
      body,
    ) as Record<string, unknown>;
    expect(out).toEqual({ id: 1, name: 'Alice' });
    // never mutates input
    expect(body).toEqual({ id: 1, ssn: '111-22-3333', name: 'Alice' });
  });

  it('strips dotted paths and descends into arrays element-wise', () => {
    const body = {
      users: [
        { id: 1, profile: { ssn: 'a', name: 'A' } },
        { id: 2, profile: { ssn: 'b', name: 'B' } },
      ],
    };
    const out = redactConditions(
      [{ type: 'redactFields', fields: ['users.profile.ssn'] }],
      body,
    );
    expect(out).toEqual({
      users: [
        { id: 1, profile: { name: 'A' } },
        { id: 2, profile: { name: 'B' } },
      ],
    });
  });

  it('tolerates missing path segments as no-ops', () => {
    const body = { a: 1 };
    const out = redactConditions(
      [{ type: 'redactFields', fields: ['x.y.z'] }],
      body,
    );
    expect(out).toEqual({ a: 1 });
  });

  it('applies multiple redactFields conditions in declaration order', () => {
    const body = { ssn: 1, dob: 2, name: 'A' };
    const out = redactConditions(
      [
        { type: 'redactFields', fields: ['ssn'] },
        { type: 'redactFields', fields: ['dob'] },
      ],
      body,
    );
    expect(out).toEqual({ name: 'A' });
  });

  it('applies a custom condition handler that declares a redact lobe', () => {
    const { registerCustomCondition, _resetCustomConditionRegistry } =
      require('../src') as typeof import('../src');
    _resetCustomConditionRegistry();
    registerCustomCondition('upper-name', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, body) => {
        if (
          body &&
          typeof body === 'object' &&
          'name' in (body as Record<string, unknown>)
        ) {
          const out = { ...(body as Record<string, unknown>) };
          out.name = String(out.name).toUpperCase();
          return out;
        }
        return body;
      },
    });
    const out = redactConditions(
      [{ type: 'custom', name: 'upper-name', config: {} }],
      { name: 'alice' },
    );
    expect(out).toEqual({ name: 'ALICE' });
  });

  it('honours a per-context customHandlers override for redaction', () => {
    const reg = require('../src') as typeof import('../src');
    reg._resetCustomConditionRegistry();
    // Register a global handler that should NOT be consulted when an
    // override map is supplied.
    reg.registerCustomCondition('mark', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, body) => ({ ...(body as object), source: 'global' }),
    });
    const overrides = new Map<string, import('../src').CustomConditionHandler>();
    overrides.set('mark', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, body) => ({ ...(body as object), source: 'override' }),
    });
    const out = reg.redactConditions(
      [{ type: 'custom', name: 'mark', config: {} }],
      { x: 1 },
      { customHandlers: overrides },
    );
    expect(out).toEqual({ x: 1, source: 'override' });
  });

  it('honours a per-context policyBackends override for redaction', () => {
    const reg = require('../src') as typeof import('../src');
    reg._resetPolicyBackendRegistry();
    reg.registerPolicyBackend('p', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, _input, body) => ({ ...(body as object), source: 'global' }),
    });
    const overrides = new Map<string, import('../src').PolicyBackend>();
    overrides.set('p', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, _input, body) => ({ ...(body as object), source: 'override' }),
    });
    const out = reg.redactConditions(
      [{ type: 'policy', backend: 'p' }],
      { x: 1 },
      { policyBackends: overrides },
    );
    expect(out).toEqual({ x: 1, source: 'override' });
  });
});

describe('hasRedactObligation', () => {
  const reg = require('../src') as typeof import('../src');

  beforeEach(() => {
    reg._resetCustomConditionRegistry();
    reg._resetPolicyBackendRegistry();
  });

  it('returns false for empty / undefined / pure-authorization conditions', () => {
    expect(reg.hasRedactObligation(undefined)).toBe(false);
    expect(reg.hasRedactObligation([])).toBe(false);
    expect(
      reg.hasRedactObligation([
        { type: 'timeWindow', notAfter: '2999-01-01T00:00:00Z' },
        { type: 'allowedOperations', operations: ['read'] },
      ]),
    ).toBe(false);
  });

  it('returns true when at least one redactFields condition is present', () => {
    expect(
      reg.hasRedactObligation([
        { type: 'timeWindow', notAfter: '2999-01-01T00:00:00Z' },
        { type: 'redactFields', fields: ['ssn'] },
      ]),
    ).toBe(true);
  });

  it('reflects per-context custom-handler overrides', () => {
    // Global has no redact lobe; override does.
    reg.registerCustomCondition('plain', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
    });
    expect(
      reg.hasRedactObligation([{ type: 'custom', name: 'plain', config: {} }]),
    ).toBe(false);
    const overrides = new Map<string, import('../src').CustomConditionHandler>();
    overrides.set('plain', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_cfg, body) => body,
    });
    expect(
      reg.hasRedactObligation(
        [{ type: 'custom', name: 'plain', config: {} }],
        { customHandlers: overrides },
      ),
    ).toBe(true);
  });

  it('reflects per-context policy-backend overrides', () => {
    reg.registerPolicyBackend('p', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
    });
    expect(reg.hasRedactObligation([{ type: 'policy', backend: 'p' }])).toBe(false);
    const overrides = new Map<string, import('../src').PolicyBackend>();
    overrides.set('p', {
      validate: () => undefined,
      enforce: () => ({ allow: true }),
      redact: (_c, _i, body) => body,
    });
    expect(
      reg.hasRedactObligation([{ type: 'policy', backend: 'p' }], {
        policyBackends: overrides,
      }),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// R-4 step 2 / F-10 — policy condition + pluggable PolicyBackend
// ---------------------------------------------------------------------------

describe("policy condition + pluggable backend (R-4 step 2 / F-10)", () => {
  const reg = require('../src') as typeof import('../src');

  beforeEach(() => reg._resetPolicyBackendRegistry());

  it('rejects validation when no backend is registered', () => {
    expect(() =>
      reg.validateCondition({
        type: 'policy',
        backend: 'absent',
        config: {},
      } as unknown as CapabilityCondition),
    ).toThrow(/no registered handler/);
  });

  it('rejects validation when backend is missing or empty', () => {
    expect(() =>
      reg.validateCondition({ type: 'policy', backend: '' } as unknown as CapabilityCondition),
    ).toThrow(/backend must be a non-empty string/);
  });

  it('delegates validate, enforce, and redact to the registered backend', async () => {
    const calls: string[] = [];
    reg.registerPolicyBackend('demo', {
      validate(config) {
        calls.push('validate');
        if (typeof config !== 'object' || config === null) {
          throw new reg.ConditionValidationError('bad config');
        }
      },
      enforce(config, input, _ctx) {
        calls.push(`enforce:${JSON.stringify({ config, input })}`);
        return { allow: true };
      },
      redact(_config, _input, body) {
        calls.push('redact');
        return { ...(body as object), redacted: true };
      },
    });

    expect(() =>
      reg.validateCondition({
        type: 'policy',
        backend: 'demo',
        config: { x: 1 },
      } as unknown as CapabilityCondition),
    ).not.toThrow();

    const r = await reg.enforceCondition(
      { type: 'policy', backend: 'demo', config: { x: 1 }, input: { y: 2 } },
      {},
    );
    expect(r.allow).toBe(true);

    const out = reg.redactConditions(
      [{ type: 'policy', backend: 'demo', config: { x: 1 } }],
      { foo: 'bar' },
    );
    expect(out).toEqual({ foo: 'bar', redacted: true });

    expect(calls).toContain('validate');
    expect(calls).toContain('redact');
    expect(calls.some((c) => c.startsWith('enforce:'))).toBe(true);
  });

  it('denies at enforcement when the named backend is not registered', async () => {
    const r = await reg.enforceCondition(
      { type: 'policy', backend: 'never-registered' },
      {},
    );
    expect(r.allow).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/never-registered/);
  });

  it('honours a per-context policy-backend override map', async () => {
    const map = new Map<string, import('../src').PolicyBackend>();
    map.set('scoped', {
      validate: () => undefined,
      enforce: () => ({ allow: false, reason: 'scoped-deny' }),
    });
    const r = await reg.enforceCondition(
      { type: 'policy', backend: 'scoped' },
      { policyBackends: map },
    );
    expect(r).toEqual({ allow: false, reason: 'scoped-deny' });
  });

  it('rejects validation if the backend itself rejects the config', () => {
    reg.registerPolicyBackend('strict', {
      validate(config) {
        if (!(config as { url?: string })?.url) {
          throw new reg.ConditionValidationError('strict.url required');
        }
      },
      enforce: () => ({ allow: true }),
    });
    expect(() =>
      reg.validateCondition({
        type: 'policy',
        backend: 'strict',
        config: {},
      } as unknown as CapabilityCondition),
    ).toThrow(/strict.url required/);
  });
});

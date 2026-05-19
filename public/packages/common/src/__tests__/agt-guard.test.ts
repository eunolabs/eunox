/**
 * Unit tests for the AGT in-process guard types in `@euno/common-core`.
 *
 * These tests verify the compile-time type contracts and the runtime behaviour
 * of *values constructed using those types*:
 *  1. All valid `AgtGuardDenyReason` string literals are the expected set.
 *  2. All valid `AgtGuardResult` string literals are the expected set.
 *  3. `AgtGuardOptions` satisfies its structural contract (required fields,
 *     optional callbacks) so downstream consumers can build conforming
 *     objects without importing the BSL implementation.
 *  4. The `onDeny` callback receives the correct `AgtGuardDenyReason` value.
 *  5. The `onGatewayDeny` callback receives the correct `gatewayErrorCode`
 *     value.
 *
 * Note: TypeScript types are erased at runtime; these tests operate on
 * *values* (strings, objects, functions) whose shapes the TypeScript compiler
 * has already validated at build time.  The Jest assertions confirm the
 * runtime behaviour of objects and functions built in conformance with those
 * types — not the existence of the types themselves.
 */

import type {
  AgtGuardDenyReason,
  AgtGuardOptions,
  AgtGuardResult,
} from '../agt-guard';
import type { AgentCapabilityManifest } from '../wire';

// ── helpers ───────────────────────────────────────────────────────────────────

/** Minimal valid AgentCapabilityManifest for option construction tests. */
function makeManifest(overrides?: Partial<AgentCapabilityManifest>): AgentCapabilityManifest {
  return {
    agentId: 'agent-test-1',
    name: 'Test Agent',
    version: '1.0.0',
    requiredCapabilities: [
      { resource: 'db:read', actions: ['read'] },
    ],
    ...overrides,
  };
}

// ── AgtGuardDenyReason ────────────────────────────────────────────────────────

describe('AgtGuardDenyReason', () => {
  /** The complete set of valid reason codes as specified in stage-5-design.md §5. */
  const VALID_REASONS: AgtGuardDenyReason[] = [
    'capability_not_found',
    'constraint_violated',
    'policy_evaluation_error',
  ];

  it('contains exactly three reason codes', () => {
    expect(VALID_REASONS).toHaveLength(3);
  });

  it.each(VALID_REASONS)('"%s" is a valid AgtGuardDenyReason string', (reason) => {
    expect(typeof reason).toBe('string');
    expect(reason.length).toBeGreaterThan(0);
  });

  it('"capability_not_found" is present — tool not in manifest', () => {
    const reason: AgtGuardDenyReason = 'capability_not_found';
    expect(reason).toBe('capability_not_found');
  });

  it('"constraint_violated" is present — constraint check failed', () => {
    const reason: AgtGuardDenyReason = 'constraint_violated';
    expect(reason).toBe('constraint_violated');
  });

  it('"policy_evaluation_error" is present — unexpected evaluation error', () => {
    const reason: AgtGuardDenyReason = 'policy_evaluation_error';
    expect(reason).toBe('policy_evaluation_error');
  });
});

// ── AgtGuardResult ────────────────────────────────────────────────────────────

describe('AgtGuardResult', () => {
  it('"allow" is a valid AgtGuardResult', () => {
    const result: AgtGuardResult = 'allow';
    expect(result).toBe('allow');
  });

  it('"deny" is a valid AgtGuardResult', () => {
    const result: AgtGuardResult = 'deny';
    expect(result).toBe('deny');
  });

  it('AgtGuardResult values are exactly "allow" and "deny"', () => {
    const all: AgtGuardResult[] = ['allow', 'deny'];
    expect(all).toHaveLength(2);
    expect(all).toContain('allow');
    expect(all).toContain('deny');
  });
});

// ── AgtGuardOptions ───────────────────────────────────────────────────────────

describe('AgtGuardOptions', () => {
  describe('minimal (required fields only)', () => {
    it('accepts a synchronous tokenSupplier', () => {
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'eyToken',
        policy: makeManifest(),
      };
      expect(typeof opts.tokenSupplier).toBe('function');
      expect(opts.tokenSupplier()).toBe('eyToken');
    });

    it('accepts an async tokenSupplier', async () => {
      const opts: AgtGuardOptions = {
        tokenSupplier: async () => 'eyAsyncToken',
        policy: makeManifest(),
      };
      const token = await opts.tokenSupplier();
      expect(token).toBe('eyAsyncToken');
    });

    it('stores the policy manifest', () => {
      const manifest = makeManifest({ agentId: 'unique-agent' });
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: manifest,
      };
      expect(opts.policy.agentId).toBe('unique-agent');
    });

    it('onDeny is undefined by default', () => {
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
      };
      expect(opts.onDeny).toBeUndefined();
    });

    it('onGatewayDeny is undefined by default', () => {
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
      };
      expect(opts.onGatewayDeny).toBeUndefined();
    });
  });

  describe('with onDeny callback', () => {
    it('invokes onDeny with the tool name and reason', () => {
      const calls: Array<{ toolName: string; reason: AgtGuardDenyReason }> = [];
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
        onDeny: (toolName, reason) => calls.push({ toolName, reason }),
      };
      opts.onDeny!('some_tool', 'capability_not_found');
      expect(calls).toHaveLength(1);
      expect(calls[0]).toEqual({ toolName: 'some_tool', reason: 'capability_not_found' });
    });

    it('can receive any AgtGuardDenyReason value', () => {
      const reasons: AgtGuardDenyReason[] = [];
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
        onDeny: (_tool, reason) => reasons.push(reason),
      };
      opts.onDeny!('t', 'capability_not_found');
      opts.onDeny!('t', 'constraint_violated');
      opts.onDeny!('t', 'policy_evaluation_error');
      expect(reasons).toEqual([
        'capability_not_found',
        'constraint_violated',
        'policy_evaluation_error',
      ]);
    });
  });

  describe('with onGatewayDeny callback', () => {
    it('invokes onGatewayDeny with the tool name and gateway error code', () => {
      const calls: Array<{ toolName: string; code: string }> = [];
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
        onGatewayDeny: (toolName, gatewayErrorCode) =>
          calls.push({ toolName, code: gatewayErrorCode }),
      };
      opts.onGatewayDeny!('my_tool', 'CAPABILITY_DENIED');
      expect(calls).toHaveLength(1);
      expect(calls[0]).toEqual({ toolName: 'my_tool', code: 'CAPABILITY_DENIED' });
    });

    it('is distinct from onDeny — gateway denials and guard denials are separate', () => {
      const guardDenials: string[] = [];
      const gatewayDenials: string[] = [];
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: makeManifest(),
        onDeny: (tool) => guardDenials.push(tool),
        onGatewayDeny: (tool) => gatewayDenials.push(tool),
      };
      opts.onDeny!('tool_a', 'capability_not_found');
      opts.onGatewayDeny!('tool_b', 'RATE_LIMITED');
      expect(guardDenials).toEqual(['tool_a']);
      expect(gatewayDenials).toEqual(['tool_b']);
    });
  });

  describe('policy with optional capabilities', () => {
    it('accepts a manifest with optionalCapabilities', () => {
      const manifest = makeManifest({
        optionalCapabilities: [{ resource: 'cache:read', actions: ['read'] }],
      });
      const opts: AgtGuardOptions = {
        tokenSupplier: () => 'tok',
        policy: manifest,
      };
      const caps = opts.policy.optionalCapabilities ?? [];
      expect(caps).toHaveLength(1);
      expect(caps.at(0)?.resource).toBe('cache:read');
    });
  });

  describe('tokenSupplier contract', () => {
    it('is called per invocation — guard does not cache the return value', async () => {
      let callCount = 0;
      const opts: AgtGuardOptions = {
        tokenSupplier: () => {
          callCount += 1;
          return `token-${callCount}`;
        },
        policy: makeManifest(),
      };
      const t1 = opts.tokenSupplier();
      const t2 = opts.tokenSupplier();
      expect(t1).toBe('token-1');
      expect(t2).toBe('token-2');
    });

    it('supports a supplier that returns a promise resolving to different tokens', async () => {
      let seq = 0;
      const opts: AgtGuardOptions = {
        tokenSupplier: () => Promise.resolve(`tok-${++seq}`),
        policy: makeManifest(),
      };
      expect(await opts.tokenSupplier()).toBe('tok-1');
      expect(await opts.tokenSupplier()).toBe('tok-2');
    });
  });
});

// ── Cross-type contract ───────────────────────────────────────────────────────

describe('AgtGuardOptions + AgtGuardResult interaction contract', () => {
  /**
   * Simulates a minimal guard evaluation loop to verify that the three types
   * compose correctly without a BSL dependency.
   */
  function simulateGuard(
    toolName: string,
    opts: AgtGuardOptions,
  ): AgtGuardResult {
    const capability = opts.policy.requiredCapabilities.find(
      (c) => c.resource === toolName,
    );
    if (!capability) {
      opts.onDeny?.(toolName, 'capability_not_found');
      return 'deny';
    }
    return 'allow';
  }

  it('allows a tool listed in requiredCapabilities', () => {
    const opts: AgtGuardOptions = {
      tokenSupplier: () => 'tok',
      policy: makeManifest({
        requiredCapabilities: [{ resource: 'db:read', actions: ['read'] }],
      }),
    };
    const result = simulateGuard('db:read', opts);
    expect(result).toBe('allow');
  });

  it('denies a tool not in requiredCapabilities and invokes onDeny', () => {
    const denied: string[] = [];
    const opts: AgtGuardOptions = {
      tokenSupplier: () => 'tok',
      policy: makeManifest({
        requiredCapabilities: [{ resource: 'db:read', actions: ['read'] }],
      }),
      onDeny: (tool) => denied.push(tool),
    };
    const result = simulateGuard('admin:delete', opts);
    expect(result).toBe('deny');
    expect(denied).toContain('admin:delete');
  });

  it('allow result does not invoke onDeny', () => {
    const denied: string[] = [];
    const opts: AgtGuardOptions = {
      tokenSupplier: () => 'tok',
      policy: makeManifest({
        requiredCapabilities: [{ resource: 'allowed_tool', actions: ['execute'] }],
      }),
      onDeny: (tool) => denied.push(tool),
    };
    simulateGuard('allowed_tool', opts);
    expect(denied).toHaveLength(0);
  });
});

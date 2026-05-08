/**
 * Unit tests for ConditionEnforcerPDP (Task 8 acceptance criteria).
 *
 * Test matrix
 * -----------
 * ✓ maxCalls — allows up to N calls then denies (sliding-window across calls)
 * ✓ maxCalls — counter resets after the window expires (fake timers)
 * ✓ timeWindow — denies calls outside the allowed window
 * ✓ allowedOperations — allows SELECT, denies DROP
 * ✓ allowedExtensions — allows .csv, denies .exe
 * ✓ allowedTables — allows reports table, denies users table
 * ✓ argumentSchema — allows conforming args, denies non-conforming args
 * ✓ unknown condition type injected at runtime → deny (defence-in-depth)
 * ✓ kill switch (session) flipped mid-session → denies all subsequent calls
 * ✓ kill switch (global) → denies all calls in all sessions
 * ✓ no matching constraint → allow (manifest only restricts listed tools)
 * ✓ policy source with multiple constraints — matches correct one
 * ✓ mcp-tool:// scheme normalization — plain tool name matches scheme-qualified pattern
 * ✓ different-scheme pattern does not match plain tool names
 */

import { ConditionEnforcerPDP } from '../pdp';
import { InMemoryCallCounterStore, DefaultKillSwitchManager } from '@euno/common-core';
import type { AgentCapabilityManifest, CapabilityConstraint, CapabilityCondition } from '@euno/common-core';
import type { LocalPolicySource } from '../policy/source';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Build a minimal CallToolRequest for the given tool name and arguments. */
function makeRequest(toolName: string, args: Record<string, unknown> = {}) {
  return {
    method: 'tools/call' as const,
    params: { name: toolName, arguments: args },
  };
}

/** Build a minimal PdpContext with a fixed session id. */
function makeCtx(sessionId = 'test-session-1') {
  return { sessionId };
}

/** Create an in-memory LocalPolicySource from a literal manifest. */
function staticPolicySource(manifest: AgentCapabilityManifest): LocalPolicySource {
  return {
    load: async () => manifest,
  };
}

/**
 * Build a manifest with a single required capability for `toolName`.
 * The `resource` is set to the tool name directly so the PDP's matching
 * logic finds it via the `call` action.
 */
function singleToolManifest(
  toolName: string,
  conditions: CapabilityCondition[],
  extra?: Partial<CapabilityConstraint>,
): AgentCapabilityManifest {
  return {
    agentId: 'test-agent',
    name: 'Test Agent',
    version: '1.0.0',
    requiredCapabilities: [
      {
        resource: toolName,
        actions: ['call'],
        conditions: conditions.length > 0 ? conditions : undefined,
        ...extra,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// maxCalls
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — maxCalls condition', () => {
  it('allows calls up to the limit and denies on the (limit + 1)th call', async () => {
    const counterStore = new InMemoryCallCounterStore();
    const manifest = singleToolManifest('query_db', [
      { type: 'maxCalls', count: 3, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    const req = makeRequest('query_db');
    const ctx = makeCtx();

    // First three calls should be allowed.
    for (let i = 0; i < 3; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }

    // The fourth call should be denied.
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('counter resets after the window expires', async () => {
    jest.useFakeTimers();
    try {
      const counterStore = new InMemoryCallCounterStore();
      const manifest = singleToolManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 1 } as CapabilityCondition,
      ]);
      const pdp = new ConditionEnforcerPDP({
        policySource: staticPolicySource(manifest),
        counterStore,
      });

      const req = makeRequest('query_db');
      const ctx = makeCtx();

      // First call consumes the quota.
      const first = await pdp.decide(req, ctx);
      expect(first.allow).toBe(true);

      // Second call within the same 1-second window → denied.
      const denied = await pdp.decide(req, ctx);
      expect(denied.allow).toBe(false);

      // Advance the fake clock past the 1-second window.
      jest.advanceTimersByTime(1100);

      // Third call opens a fresh window → allowed.
      const third = await pdp.decide(req, ctx);
      expect(third.allow).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  it('counters are isolated per session', async () => {
    const counterStore = new InMemoryCallCounterStore();
    const manifest = singleToolManifest('query_db', [
      { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    const req = makeRequest('query_db');

    // Session A exhausts its quota.
    await pdp.decide(req, { sessionId: 'session-a' });
    const deniedA = await pdp.decide(req, { sessionId: 'session-a' });
    expect(deniedA.allow).toBe(false);

    // Session B still has its own fresh quota.
    const allowedB = await pdp.decide(req, { sessionId: 'session-b' });
    expect(allowedB.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// timeWindow
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — timeWindow condition', () => {
  it('denies calls before notBefore', async () => {
    const futureTime = new Date(Date.now() + 60_000).toISOString();
    const manifest = singleToolManifest('echo', [
      { type: 'timeWindow', notBefore: futureTime } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('TIME_WINDOW_DENIED');
  });

  it('denies calls after notAfter', async () => {
    const pastTime = new Date(Date.now() - 60_000).toISOString();
    const manifest = singleToolManifest('echo', [
      { type: 'timeWindow', notAfter: pastTime } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('TIME_WINDOW_DENIED');
  });

  it('allows calls within the time window', async () => {
    const pastTime = new Date(Date.now() - 60_000).toISOString();
    const futureTime = new Date(Date.now() + 60_000).toISOString();
    const manifest = singleToolManifest('echo', [
      { type: 'timeWindow', notBefore: pastTime, notAfter: futureTime } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// allowedOperations
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — allowedOperations condition', () => {
  it('allows SELECT and EXPLAIN operations', async () => {
    const manifest = singleToolManifest('query_db', [
      { type: 'allowedOperations', operations: ['SELECT', 'EXPLAIN'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const allowedSelect = await pdp.decide(
      makeRequest('query_db', { sql: 'SELECT * FROM users' }),
      makeCtx(),
    );
    expect(allowedSelect.allow).toBe(true);

    const allowedExplain = await pdp.decide(
      makeRequest('query_db', { sql: 'EXPLAIN SELECT * FROM users' }),
      makeCtx(),
    );
    expect(allowedExplain.allow).toBe(true);
  });

  it('denies DROP TABLE operation', async () => {
    const manifest = singleToolManifest('query_db', [
      { type: 'allowedOperations', operations: ['SELECT'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(
      makeRequest('query_db', { sql: 'DROP TABLE users' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('denies when no SQL argument is provided (operation missing from context)', async () => {
    const manifest = singleToolManifest('query_db', [
      { type: 'allowedOperations', operations: ['SELECT'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // No sql/query/statement argument — operation cannot be extracted.
    const d = await pdp.decide(makeRequest('query_db', {}), makeCtx());
    expect(d.allow).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// allowedExtensions
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — allowedExtensions condition', () => {
  it('allows .csv and .json file extensions', async () => {
    const manifest = singleToolManifest('read_file', [
      { type: 'allowedExtensions', extensions: ['.csv', '.json'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const allowedCsv = await pdp.decide(
      makeRequest('read_file', { path: 'data/report.csv' }),
      makeCtx(),
    );
    expect(allowedCsv.allow).toBe(true);

    const allowedJson = await pdp.decide(
      makeRequest('read_file', { path: 'config.json' }),
      makeCtx(),
    );
    expect(allowedJson.allow).toBe(true);
  });

  it('denies .exe file extension', async () => {
    const manifest = singleToolManifest('read_file', [
      { type: 'allowedExtensions', extensions: ['.csv', '.json'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(
      makeRequest('read_file', { path: 'malware.exe' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });
});

// ---------------------------------------------------------------------------
// allowedTables
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — allowedTables condition', () => {
  it('allows access to the reports table', async () => {
    const manifest = singleToolManifest('query_db', [
      {
        type: 'allowedTables',
        tables: ['reports', 'metrics'],
      } as unknown as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(
      makeRequest('query_db', { table: 'reports' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('denies access to the users table (not in allowlist)', async () => {
    const manifest = singleToolManifest('query_db', [
      {
        type: 'allowedTables',
        tables: ['reports', 'metrics'],
      } as unknown as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(
      makeRequest('query_db', { table: 'users' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('TABLE_NOT_ALLOWED');
  });

  it('denies when no table argument is provided (tables missing from context)', async () => {
    const manifest = singleToolManifest('query_db', [
      {
        type: 'allowedTables',
        tables: ['reports'],
      } as unknown as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('query_db', {}), makeCtx());
    expect(d.allow).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// argumentSchema
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — argumentSchema', () => {
  it('allows calls whose arguments conform to the schema', async () => {
    const manifest = singleToolManifest('echo', [], {
      argumentSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo', { text: 'hello' }), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('denies calls whose arguments do not conform to the schema', async () => {
    const manifest = singleToolManifest('echo', [], {
      argumentSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // Missing required 'text' property.
    const d = await pdp.decide(makeRequest('echo', { other: 'value' }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
  });

  it('denies calls with a disallowed extra property (additionalProperties defaults to false)', async () => {
    const manifest = singleToolManifest('echo', [], {
      argumentSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
        additionalProperties: false,
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(
      makeRequest('echo', { text: 'hello', extra: 'not-allowed' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
  });
});

// ---------------------------------------------------------------------------
// Unknown condition type at runtime → deny (defence-in-depth)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — unknown condition type at runtime', () => {
  it('denies when an unrecognized condition type is present in a constraint', async () => {
    // Inject a future / vendor-extension condition type directly into the manifest
    // object, bypassing FilePolicySource validation.  The PDP must still deny.
    const manifest = singleToolManifest('echo', [
      { type: 'futureConditionType', someField: 'value' } as unknown as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.reason).toMatch(/unrecognized condition type/i);
  });
});

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — kill switch', () => {
  it('denies all calls in a session after killSession() is called', async () => {
    const manifest = singleToolManifest('echo', []);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const req = makeRequest('echo');
    const ctx = makeCtx('session-to-kill');

    // Call is allowed before the kill.
    const before = await pdp.decide(req, ctx);
    expect(before.allow).toBe(true);

    // Kill the session.
    pdp.killSession('session-to-kill');

    // All subsequent calls in this session are denied.
    const after = await pdp.decide(req, ctx);
    expect(after.allow).toBe(false);
    expect(after.denialCode).toBe('KILL_SWITCH');

    // A different session is unaffected.
    const other = await pdp.decide(req, { sessionId: 'other-session' });
    expect(other.allow).toBe(true);
  });

  it('denies all calls after killAll() is called (global kill switch)', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'ga',
      name: 'GA',
      version: '1.0.0',
      requiredCapabilities: [],
    };
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    pdp.killAll();

    // Any session, any tool — all denied.
    const d1 = await pdp.decide(makeRequest('echo'), { sessionId: 'session-1' });
    expect(d1.allow).toBe(false);
    expect(d1.denialCode).toBe('KILL_SWITCH');

    const d2 = await pdp.decide(makeRequest('query_db'), { sessionId: 'session-2' });
    expect(d2.allow).toBe(false);
    expect(d2.denialCode).toBe('KILL_SWITCH');

    // After reviveAll(), calls are allowed again.
    pdp.reviveAll();
    const d3 = await pdp.decide(makeRequest('echo'), { sessionId: 'session-1' });
    expect(d3.allow).toBe(true);
  });

  it('uses a caller-supplied KillSwitchManager', async () => {
    const killSwitch = new DefaultKillSwitchManager();
    const manifest = singleToolManifest('echo', []);
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      killSwitchManager: killSwitch,
    });

    // Activate via the external manager.
    killSwitch.activateGlobalKill();
    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('KILL_SWITCH');
  });
});

// ---------------------------------------------------------------------------
// No matching constraint → allow
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — no matching constraint', () => {
  it('allows a tool call when the manifest has no constraint for that tool', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'pa',
      name: 'Partial Agent',
      version: '1.0.0',
      requiredCapabilities: [
        // Only constrains 'query_db', not 'echo'.
        { resource: 'query_db', actions: ['call'], conditions: undefined },
      ],
    };
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // echo is not in the manifest → unconstrained → allow.
    const d = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('allows a tool call when the manifest is empty (no capabilities)', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'ea',
      name: 'Empty Agent',
      version: '1.0.0',
      requiredCapabilities: [],
    };
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('any_tool'), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('also checks optionalCapabilities for a match', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'oa',
      name: 'Optional Agent',
      version: '1.0.0',
      requiredCapabilities: [],
      optionalCapabilities: [
        {
          resource: 'optional_tool',
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };
    const counterStore = new InMemoryCallCounterStore();
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    // First call allowed.
    const first = await pdp.decide(makeRequest('optional_tool'), makeCtx());
    expect(first.allow).toBe(true);

    // Second call denied (maxCalls=1 exhausted).
    const second = await pdp.decide(makeRequest('optional_tool'), makeCtx());
    expect(second.allow).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Wildcard resource matching (mcp-tool:// scheme normalization)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — wildcard resource matching', () => {
  it('matches a plain tool name against a mcp-tool:// scheme wildcard pattern', async () => {
    // Real MCP tools/call requests use plain tool names (e.g. "echo"), not
    // "mcp-tool://echo".  The PDP normalizes the tool name to the
    // mcp-tool:// scheme when matching against scheme-qualified patterns.
    const counterStore = new InMemoryCallCounterStore();
    const manifest: AgentCapabilityManifest = {
      agentId: 'wc',
      name: 'Wildcard Agent',
      version: '1.0.0',
      requiredCapabilities: [
        {
          // mcp-tool://* matches any single tool name (single-segment wildcard).
          resource: 'mcp-tool://*',
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    // Plain MCP tool name (as used in real tools/call requests).
    const first = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(first.allow).toBe(true);

    // Second call for the same tool exhausts the maxCalls limit.
    const denied = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(denied.allow).toBe(false);

    // A different plain tool name also matches the wildcard but has its own counter.
    const firstOther = await pdp.decide(makeRequest('query_db'), makeCtx());
    expect(firstOther.allow).toBe(true);
  });

  it('does not match a plain tool name against a different-scheme pattern', async () => {
    // An api:// pattern must not constrain plain MCP tool names — scheme
    // parity is enforced by matchesResource.
    const manifest: AgentCapabilityManifest = {
      agentId: 'wc2',
      name: 'Wrong-Scheme Agent',
      version: '1.0.0',
      requiredCapabilities: [
        {
          resource: 'api://*', // different scheme — must NOT match plain tool names
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // No constraint matches → unconstrained → allow.
    const d = await pdp.decide(makeRequest('any_tool'), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('matches a plain tool name via exact mcp-tool:// manifest entry', async () => {
    // resource: "mcp-tool://echo" should match tool name "echo".
    const manifest: AgentCapabilityManifest = {
      agentId: 'exact-scheme',
      name: 'Exact Scheme Agent',
      version: '1.0.0',
      requiredCapabilities: [
        {
          resource: 'mcp-tool://echo',
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };
    const counterStore = new InMemoryCallCounterStore();
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    const first = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(first.allow).toBe(true);

    const denied = await pdp.decide(makeRequest('echo'), makeCtx());
    expect(denied.allow).toBe(false);

    // A different tool name is not constrained.
    const other = await pdp.decide(makeRequest('query_db'), makeCtx());
    expect(other.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Policy source lazy load and hot reload
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — policy source lifecycle', () => {
  it('loads the manifest lazily on the first decide() call', async () => {
    let loadCount = 0;
    const policySource: LocalPolicySource = {
      load: async () => {
        loadCount++;
        return {
          agentId: 'lazy',
          name: 'Lazy',
          version: '1.0.0',
          requiredCapabilities: [],
        };
      },
    };
    const pdp = new ConditionEnforcerPDP({ policySource });

    expect(loadCount).toBe(0);
    await pdp.decide(makeRequest('echo'), makeCtx());
    expect(loadCount).toBe(1);
    // Second call uses the cached manifest.
    await pdp.decide(makeRequest('echo'), makeCtx());
    expect(loadCount).toBe(1);
  });

  it('forwards the error when load() rejects', async () => {
    const policySource: LocalPolicySource = {
      load: async () => { throw new Error('load failed'); },
    };
    const pdp = new ConditionEnforcerPDP({ policySource });

    await expect(pdp.decide(makeRequest('echo'), makeCtx())).rejects.toThrow('load failed');
  });

  it('refreshes the manifest when watch() notifies a change', async () => {
    let onChange: ((m: AgentCapabilityManifest) => void) | undefined;
    let loadCount = 0;

    const initial: AgentCapabilityManifest = {
      agentId: 'live',
      name: 'Live',
      version: '1.0.0',
      requiredCapabilities: [
        {
          resource: 'query_db',
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 1, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };

    const updated: AgentCapabilityManifest = {
      ...initial,
      requiredCapabilities: [
        // Relax the constraint to count=5.
        {
          resource: 'query_db',
          actions: ['call'],
          conditions: [
            { type: 'maxCalls', count: 5, windowSeconds: 60 } as CapabilityCondition,
          ],
        },
      ],
    };

    const policySource: LocalPolicySource = {
      load: async () => { loadCount++; return initial; },
      watch: (cb) => {
        onChange = cb;
        return () => { onChange = undefined; };
      },
    };

    const counterStore = new InMemoryCallCounterStore();
    const pdp = new ConditionEnforcerPDP({ policySource, counterStore });

    const req = makeRequest('query_db');
    const ctx = makeCtx('reload-session');

    // Initial policy: count=1 → second call is denied.
    const first = await pdp.decide(req, ctx);
    expect(first.allow).toBe(true);
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);

    // Hot-reload with relaxed policy + fresh counter store.
    counterStore.reset();
    onChange!(updated);

    // After reload, the new constraint (count=5) applies — 5 calls allowed.
    for (let i = 0; i < 5; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied2 = await pdp.decide(req, ctx);
    expect(denied2.allow).toBe(false);

    pdp.dispose();
  });
});

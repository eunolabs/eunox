/**
 * Unit tests for ConditionEnforcerPDP (Task 8 acceptance criteria +
 * Task 3 recipientDomain condition + Task 4 redactFields condition).
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
 * ✓ argumentSchema — structured error: details.path, details.expected, details.got (Task 1)
 * ✓ unknown condition type injected at runtime → deny (defence-in-depth)
 * ✓ kill switch (session) flipped mid-session → denies all subsequent calls
 * ✓ kill switch (global) → denies all calls in all sessions
 * ✓ no matching constraint → allow (manifest only restricts listed tools)
 * ✓ policy source with multiple constraints — matches correct one
 * ✓ mcp-tool:// scheme normalization — plain tool name matches scheme-qualified pattern
 * ✓ different-scheme pattern does not match plain tool names
 * ✓ recipientDomain — allows calls when all recipient domains are in allowlist
 * ✓ recipientDomain — denies when any recipient domain is outside the allowlist
 * ✓ recipientDomain — denies when no recipients are provided in the args
 * ✓ extractRecipients — recognises to (string), to (string[]), recipients, cc, bcc
 * ✓ extractRecipients — combines multiple recipient fields
 * ✓ extractRecipients — returns undefined when no recognised fields present
 * ✓ redactFields — enforce lobe always allows (never denies)
 * ✓ redactFields — matchedConditions populated on allow with conditions
 * ✓ redactFields — matchedConditions undefined when no constraint matches
 * ✓ redactFields — matchedConditions undefined when constraint has no conditions
 * ✓ redactFields — matchedConditions carries all conditions (not just redactFields)
 * ✓ redactFields — matchedConditions undefined on deny decisions
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
    version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
      version: '0.1.0',
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
          version: '0.1.0',
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
      version: '0.1.0',
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

// ---------------------------------------------------------------------------
// ipRange condition (Stage 2)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — ipRange condition', () => {
  /** Build a PdpContext with an optional sourceIp. */
  function makeCtxWithIp(sourceIp?: string, sessionId = 'ip-session') {
    return { sessionId, sourceIp };
  }

  it('allows a request when sourceIp matches an allowed CIDR', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'ipRange', cidrs: ['127.0.0.0/8', '10.0.0.0/8'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('127.0.0.1'));
    expect(d.allow).toBe(true);
  });

  it('allows a request when sourceIp matches the second CIDR in the list', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'ipRange', cidrs: ['192.168.0.0/16', '10.0.0.0/8'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('10.1.2.3'));
    expect(d.allow).toBe(true);
  });

  it('denies a request when sourceIp is not in any allowed CIDR', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'ipRange', cidrs: ['192.168.0.0/16'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('198.51.100.1'));
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('IP_RANGE_DENIED');
    expect(d.conditionType).toBe('ipRange');
    expect(d.reason).toMatch(/198\.51\.100\.1/);
  });

  it('denies when sourceIp is undefined (no IP available — e.g. stdio transport)', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'ipRange', cidrs: ['127.0.0.0/8'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // No sourceIp in context — mirrors stdio transport behaviour.
    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp(undefined));
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('IP_RANGE_DENIED');
    expect(d.reason).toMatch(/sourceIp/i);
  });

  it('allows an exact /32 CIDR match', async () => {
    const manifest = singleToolManifest('admin_tool', [
      { type: 'ipRange', cidrs: ['10.0.0.5/32'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const allowed = await pdp.decide(makeRequest('admin_tool'), makeCtxWithIp('10.0.0.5'));
    expect(allowed.allow).toBe(true);

    const denied = await pdp.decide(makeRequest('admin_tool'), makeCtxWithIp('10.0.0.6'));
    expect(denied.allow).toBe(false);
  });

  it('is evaluated before maxCalls (cheaper stateless condition wins first)', async () => {
    // ipRange has priority 1, maxCalls has priority 5 — ipRange runs first.
    const manifest = singleToolManifest('secure_tool', [
      { type: 'maxCalls', count: 100, windowSeconds: 60 } as CapabilityCondition,
      { type: 'ipRange', cidrs: ['192.168.0.0/16'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // Disallowed IP → denied with ipRange code, not maxCalls.
    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('8.8.8.8'));
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('ipRange');
    expect(d.denialCode).toBe('IP_RANGE_DENIED');
  });

  it('allows when both ipRange and maxCalls are satisfied', async () => {
    const counterStore = new InMemoryCallCounterStore();
    const manifest = singleToolManifest('secure_tool', [
      { type: 'maxCalls', count: 3, windowSeconds: 60 } as CapabilityCondition,
      { type: 'ipRange', cidrs: ['10.0.0.0/8'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest), counterStore });

    for (let i = 0; i < 3; i++) {
      const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('10.1.2.3'));
      expect(d.allow).toBe(true);
    }
    // 4th call is denied by maxCalls (ipRange still passes).
    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('10.1.2.3'));
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('maxCalls');
  });

  it('denies with ipRange even when maxCalls quota is not yet exhausted', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'maxCalls', count: 10, windowSeconds: 60 } as CapabilityCondition,
      { type: 'ipRange', cidrs: ['10.0.0.0/8'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // Wrong IP — denied before maxCalls counter is checked.
    const d = await pdp.decide(makeRequest('secure_tool'), makeCtxWithIp('1.2.3.4'));
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('ipRange');
  });

  it('tools not covered by the manifest are allowed regardless of IP', async () => {
    const manifest = singleToolManifest('secure_tool', [
      { type: 'ipRange', cidrs: ['192.168.0.0/16'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // 'unrestricted_tool' is not in the manifest → allowed with any IP.
    const d = await pdp.decide(makeRequest('unrestricted_tool'), makeCtxWithIp('1.2.3.4'));
    expect(d.allow).toBe(true);
  });

  it('passes sourceIp into the condition context from PdpContext', async () => {
    // Verify that PdpContext.sourceIp is the field used by the condition registry.
    const manifest = singleToolManifest('t', [
      { type: 'ipRange', cidrs: ['172.16.0.0/12'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // 172.31.255.255 is the last address in 172.16.0.0/12.
    const last = await pdp.decide(makeRequest('t'), { sessionId: 's', sourceIp: '172.31.255.255' });
    expect(last.allow).toBe(true);

    // 172.32.0.0 is one beyond the /12 range.
    const beyond = await pdp.decide(makeRequest('t'), { sessionId: 's', sourceIp: '172.32.0.0' });
    expect(beyond.allow).toBe(false);
    expect(beyond.denialCode).toBe('IP_RANGE_DENIED');
  });
});

// ---------------------------------------------------------------------------
// argumentSchema — structured error reporting (Task 1)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — argumentSchema structured error reporting', () => {
  it('returns details.path, details.expected, details.got for a type mismatch', async () => {
    const manifest = singleToolManifest('echo', [], {
      argumentSchema: {
        type: 'object',
        properties: { count: { type: 'integer' } },
        required: ['count'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo', { count: 'not-a-number' }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
    expect(d.conditionType).toBe('argumentSchema');
    expect(d.details).toBeDefined();
    expect(d.details!['path']).toBe('args.count');
    expect(d.details!['expected']).toContain('integer');
    expect(d.details!['got']).toBe('string');
  });

  it('returns details for a missing required property', async () => {
    const manifest = singleToolManifest('create_user', [], {
      argumentSchema: {
        type: 'object',
        properties: { email: { type: 'string' } },
        required: ['email'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('create_user', {}), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.email');
    expect(d.details!['expected']).toBe('present');
    expect(d.details!['got']).toBe('absent');
  });

  it('returns details for a disallowed additional property', async () => {
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
      makeRequest('echo', { text: 'hello', secret: 'bad' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.secret');
    expect(d.details!['expected']).toBe('absent');
    expect(d.details!['got']).toBe('present');
  });

  it('returns details for an enum mismatch', async () => {
    const manifest = singleToolManifest('set_mode', [], {
      argumentSchema: {
        type: 'object',
        properties: { mode: { enum: ['read', 'write'] } },
        required: ['mode'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('set_mode', { mode: 'delete' }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.mode');
    expect(d.details!['expected']).toContain('"read"');
    expect(d.details!['got']).toBe('delete');
  });

  it('returns details for a string minLength violation', async () => {
    const manifest = singleToolManifest('search', [], {
      argumentSchema: {
        type: 'object',
        properties: { query: { type: 'string', minLength: 3 } },
        required: ['query'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('search', { query: 'ab' }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.query');
    expect(d.details!['expected']).toContain('>= 3');
    expect(d.details!['got']).toBe(2);
  });

  it('returns details for a string maxLength violation', async () => {
    const manifest = singleToolManifest('tag', [], {
      argumentSchema: {
        type: 'object',
        properties: { name: { type: 'string', maxLength: 10 } },
        required: ['name'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('tag', { name: 'a'.repeat(11) }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.name');
    expect(d.details!['expected']).toContain('<= 10');
    expect(d.details!['got']).toBe(11);
  });

  it('returns details for a number minimum violation', async () => {
    const manifest = singleToolManifest('paginate', [], {
      argumentSchema: {
        type: 'object',
        properties: { page: { type: 'integer', minimum: 1 } },
        required: ['page'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('paginate', { page: 0 }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.page');
    expect(d.details!['expected']).toContain('>= 1');
    expect(d.details!['got']).toBe(0);
  });

  it('returns details for a number maximum violation', async () => {
    const manifest = singleToolManifest('paginate', [], {
      argumentSchema: {
        type: 'object',
        properties: { limit: { type: 'integer', maximum: 100 } },
        required: ['limit'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('paginate', { limit: 200 }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.limit');
    expect(d.details!['expected']).toContain('<= 100');
    expect(d.details!['got']).toBe(200);
  });

  it('returns details for an array maxItems violation', async () => {
    const manifest = singleToolManifest('batch', [], {
      argumentSchema: {
        type: 'object',
        properties: { ids: { type: 'array', maxItems: 5 } },
        required: ['ids'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('batch', { ids: [1, 2, 3, 4, 5, 6] }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.ids');
    expect(d.details!['expected']).toContain('at most 5');
    expect(d.details!['got']).toBe(6);
  });

  it('returns details for a pattern mismatch', async () => {
    const manifest = singleToolManifest('send', [], {
      argumentSchema: {
        type: 'object',
        properties: { code: { type: 'string', pattern: '[A-Z]{3}' } },
        required: ['code'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('send', { code: 'abc' }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.code');
    expect(d.details!['expected']).toContain('[A-Z]{3}');
    expect(d.details!['got']).toBe('abc');
  });

  it('returns details with the nested path for array item type violations', async () => {
    const manifest = singleToolManifest('process', [], {
      argumentSchema: {
        type: 'object',
        properties: {
          tags: { type: 'array', items: { type: 'string' } },
        },
        required: ['tags'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('process', { tags: ['ok', 123] }), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.tags[1]');
    expect(d.details!['expected']).toContain('string');
    expect(d.details!['got']).toBe('number');
  });

  it('does NOT set details on allow decisions', async () => {
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
    expect(d.details).toBeUndefined();
  });

  it('does NOT set details on non-argumentSchema denials (e.g. maxCalls)', async () => {
    const manifest = singleToolManifest('limited', [
      { type: 'maxCalls', count: 0, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('limited'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.denialCode).not.toBe('ARGUMENT_VALIDATION_FAILED');
    expect(d.details).toBeUndefined();
  });

  it('details message is compatible with human-readable reason string', async () => {
    const manifest = singleToolManifest('echo', [], {
      argumentSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('echo', {}), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.reason).toMatch(/Argument validation failed/);
    expect(d.details).toBeDefined();
    // The reason string should embed the same path as details.path
    expect(d.reason).toContain('text');
  });

  it('handles deeply nested schema failures (3 levels deep)', async () => {
    const manifest = singleToolManifest('nested_op', [], {
      argumentSchema: {
        type: 'object',
        properties: {
          body: {
            type: 'object',
            properties: {
              user: {
                type: 'object',
                properties: { id: { type: 'integer' } },
                required: ['id'],
              },
            },
            required: ['user'],
          },
        },
        required: ['body'],
      },
    });
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // Pass a string where integer is expected
    const d = await pdp.decide(
      makeRequest('nested_op', { body: { user: { id: 'not-an-int' } } }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.details!['path']).toBe('args.body.user.id');
    expect(d.details!['expected']).toContain('integer');
    expect(d.details!['got']).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// recipientDomain condition (Task 3)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — recipientDomain condition', () => {
  function makeRecipientManifest(domains: string[]): AgentCapabilityManifest {
    return singleToolManifest('send_email', [
      { type: 'recipientDomain', domains } as CapabilityCondition,
    ]);
  }

  it('allows a call when the to field contains an address in the allowed domain', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: 'alice@example.com' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('denies a call when the to field contains an address outside the allowed domain', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: 'evil@attacker.example' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('denies when no recipient arguments are present', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { subject: 'Hello', body: 'World' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('denies when the to field is an empty string', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: '' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('allows when all addresses in a to array are in the allowed domain', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: ['alice@example.com', 'bob@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('denies when one address in a to array is outside the allowed domain', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: ['alice@example.com', 'spy@attacker.example'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
  });

  it('uses the recipients field when to is absent', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['trusted.org'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { recipients: 'user@trusted.org' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('collects cc addresses and enforces the domain check', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', {
        to: 'alice@example.com',
        cc: 'external@outsider.io',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('collects bcc addresses and enforces the domain check', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', {
        to: 'alice@example.com',
        bcc: 'hidden@leak.example',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('allows when to, cc, and bcc are all in the allowed domains', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com', 'partner.org'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', {
        to: ['alice@example.com', 'bob@partner.org'],
        cc: 'carol@example.com',
        bcc: 'dave@partner.org',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('is case-insensitive on domain names', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['EXAMPLE.COM'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: 'alice@example.com' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('allows multiple domains in the allow list', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com', 'trusted.org'])),
    });
    const allowed1 = await pdp.decide(
      makeRequest('send_email', { to: 'alice@example.com' }),
      makeCtx('s1'),
    );
    const allowed2 = await pdp.decide(
      makeRequest('send_email', { to: 'bob@trusted.org' }),
      makeCtx('s2'),
    );
    expect(allowed1.allow).toBe(true);
    expect(allowed2.allow).toBe(true);
  });

  it('denies an address without an @ sign', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { to: 'notanemail' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('recipientDomain condition does not block an unrelated tool', async () => {
    // The constraint is only on send_email; calling another tool is allowed.
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('query_db', { sql: 'SELECT * FROM users' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('recipientDomain combined with maxCalls: both are enforced', async () => {
    const counterStore = new InMemoryCallCounterStore();
    const manifest = singleToolManifest('send_email', [
      { type: 'recipientDomain', domains: ['example.com'] } as CapabilityCondition,
      { type: 'maxCalls', count: 2, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
      counterStore,
    });

    const req = makeRequest('send_email', { to: 'alice@example.com' });
    const ctx = makeCtx('combined-session');

    const first = await pdp.decide(req, ctx);
    expect(first.allow).toBe(true);

    const second = await pdp.decide(req, ctx);
    expect(second.allow).toBe(true);

    // Third call exceeds maxCalls.
    const third = await pdp.decide(req, ctx);
    expect(third.allow).toBe(false);
    expect(third.conditionType).toBe('maxCalls');

    // Domain violation is caught even before maxCalls check.
    counterStore.reset();
    const domainDenied = await pdp.decide(
      makeRequest('send_email', { to: 'evil@attacker.example' }),
      ctx,
    );
    expect(domainDenied.allow).toBe(false);
    expect(domainDenied.conditionType).toBe('recipientDomain');
  });

  it('recipients field as an array of strings all in allowlist → allow', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { recipients: ['a@example.com', 'b@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('cc field as array with one blocked domain → deny', async () => {
    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(makeRecipientManifest(['example.com'])),
    });
    const d = await pdp.decide(
      makeRequest('send_email', { cc: ['good@example.com', 'bad@external.io'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
  });

  it('a domain entry containing @ is treated as a literal domain string at enforcement time', async () => {
    // The condition handler's validate() phase (called via validateCondition())
    // rejects '@' in domain entries. However, enforceCondition() skips validate()
    // and calls enforce() directly. At enforcement time the malformed entry is
    // therefore treated as the literal string 'user@example.com' in the allowed-
    // domains set — so a legitimate recipient whose domain is 'example.com'
    // will be denied because 'example.com' ≠ 'user@example.com'.
    const manifest = singleToolManifest('send_email', [
      { type: 'recipientDomain', domains: ['user@example.com'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // 'example.com' is NOT in the allowed set (only 'user@example.com' is).
    const denied = await pdp.decide(
      makeRequest('send_email', { to: 'alice@example.com' }),
      makeCtx(),
    );
    expect(denied.allow).toBe(false);
    expect(denied.conditionType).toBe('recipientDomain');
  });
});

// ---------------------------------------------------------------------------
// extractRecipients helper (tested via ConditionEnforcerPDP.decide)
// ---------------------------------------------------------------------------

describe('extractRecipients (via ConditionEnforcerPDP)', () => {
  // We test the helper indirectly through the PDP to avoid exporting
  // an internal module-level function, while still getting full coverage.

  const allowedManifest = singleToolManifest('notify', [
    { type: 'recipientDomain', domains: ['example.com'] } as CapabilityCondition,
  ]);

  function buildPdp(): ConditionEnforcerPDP {
    return new ConditionEnforcerPDP({ policySource: staticPolicySource(allowedManifest) });
  }

  it('extracts a single string from "to"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(makeRequest('notify', { to: 'user@example.com' }), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('extracts an array from "to"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { to: ['a@example.com', 'b@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts a single string from "recipients"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { recipients: 'r@example.com' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts an array from "recipients"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { recipients: ['r1@example.com', 'r2@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts a single string from "cc"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { cc: 'cc@example.com' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts an array from "cc"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { cc: ['cc1@example.com', 'cc2@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts a single string from "bcc"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { bcc: 'bcc@example.com' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('extracts an array from "bcc"', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { bcc: ['bcc1@example.com', 'bcc2@example.com'] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('combines to + recipients + cc + bcc when all present', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', {
        to: 'a@example.com',
        recipients: 'b@example.com',
        cc: 'c@example.com',
        bcc: 'd@example.com',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('denies if any combined field contains a blocked domain', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', {
        to: 'a@example.com',
        bcc: 'spy@attacker.example',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('returns undefined (no recipients) when none of the recognised fields are present', async () => {
    const pdp = buildPdp();
    // No to/recipients/cc/bcc — the condition should deny due to missing context.
    const d = await pdp.decide(
      makeRequest('notify', { subject: 'test', body: 'hello' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('recipientDomain');
  });

  it('ignores non-string array entries in "to"', async () => {
    const pdp = buildPdp();
    // Mixed array — only the string entries should be extracted.
    // The valid entry is in allowlist; invalid entries are ignored.
    const d = await pdp.decide(
      makeRequest('notify', { to: ['user@example.com', 42, null, true] }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('trims whitespace from extracted addresses', async () => {
    const pdp = buildPdp();
    const d = await pdp.decide(
      makeRequest('notify', { to: '  user@example.com  ' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// redactFields condition (Task 4)
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — redactFields condition', () => {
  it('allows a call when a redactFields condition is present (enforce always allows)', async () => {
    const manifest = singleToolManifest('get_user', [
      { type: 'redactFields', fields: ['ssn', 'dob'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('get_user', { userId: '123' }), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('populates matchedConditions on an allow decision when conditions are present', async () => {
    const manifest = singleToolManifest('get_user', [
      { type: 'redactFields', fields: ['ssn'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('get_user', {}), makeCtx());
    expect(d.allow).toBe(true);
    expect(d.matchedConditions).toBeDefined();
    expect(d.matchedConditions).toHaveLength(1);
    expect(d.matchedConditions![0]!.type).toBe('redactFields');
  });

  it('matchedConditions is undefined when no constraint matches the tool', async () => {
    const manifest = singleToolManifest('restricted_tool', [
      { type: 'redactFields', fields: ['secret'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // 'other_tool' is not constrained — no matchedConditions.
    const d = await pdp.decide(makeRequest('other_tool'), makeCtx());
    expect(d.allow).toBe(true);
    expect(d.matchedConditions).toBeUndefined();
  });

  it('matchedConditions is undefined when the matched constraint has no conditions', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'no-cond-agent',
      name: 'No Conditions',
      version: '0.1.0',
      requiredCapabilities: [{ resource: 'read_public', actions: ['call'] }],
    };
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('read_public'), makeCtx());
    expect(d.allow).toBe(true);
    expect(d.matchedConditions).toBeUndefined();
  });

  it('matchedConditions carries ALL conditions (not just redactFields)', async () => {
    // When a constraint has both maxCalls and redactFields, matchedConditions
    // includes both so the transport can pass the full list to redactConditions.
    const manifest = singleToolManifest('mixed_tool', [
      { type: 'maxCalls', count: 10, windowSeconds: 60 } as CapabilityCondition,
      { type: 'redactFields', fields: ['internal'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('mixed_tool'), makeCtx());
    expect(d.allow).toBe(true);
    expect(d.matchedConditions).toHaveLength(2);
    expect(d.matchedConditions!.map((c) => c.type)).toContain('redactFields');
    expect(d.matchedConditions!.map((c) => c.type)).toContain('maxCalls');
  });

  it('matchedConditions is undefined when the call is denied', async () => {
    const manifest = singleToolManifest('locked', [
      { type: 'maxCalls', count: 0, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    const d = await pdp.decide(makeRequest('locked'), makeCtx());
    expect(d.allow).toBe(false);
    expect(d.matchedConditions).toBeUndefined();
  });

  it('redactFields does not deny — a constraint with only redactFields allows the call', async () => {
    const manifest = singleToolManifest('sensitive_query', [
      { type: 'redactFields', fields: ['password', 'credit_card'] } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });

    // Multiple calls all succeed (no call counter involved).
    for (let i = 0; i < 5; i++) {
      const d = await pdp.decide(makeRequest('sensitive_query', { id: i }), makeCtx());
      expect(d.allow).toBe(true);
    }
  });
});

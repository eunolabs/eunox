/**
 * Tests for LocalCapabilityRuntime and createLocalRuntime.
 *
 * All tests use an in-memory policy source and a NullAuditSink to avoid
 * touching the filesystem.
 */

import * as crypto from 'crypto';

import {
  InMemoryCallCounterStore,
  DefaultKillSwitchManager,
} from '@euno/common-core';
import type { AgentCapabilityManifest, CapabilityCondition } from '@euno/common-core';
import {
  ConditionEnforcerPDP,
  NullAuditSink,
} from '@euno/mcp';
import type { McpAuditRecord } from '@euno/mcp';

import { LocalCapabilityRuntime } from '../runtime';
import type { LocalToolInvocationRequest } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeManifest(
  toolName: string,
  conditions: CapabilityCondition[] = [],
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
      },
    ],
  };
}

function staticPolicySource(manifest: AgentCapabilityManifest) {
  return { load: async () => manifest };
}

function makeRuntime(
  manifest: AgentCapabilityManifest,
  opts: {
    sessionId?: string;
    counterStore?: InMemoryCallCounterStore;
    killSwitchManager?: DefaultKillSwitchManager;
    auditSink?: NullAuditSink | RecordingAuditSink;
  } = {},
): LocalCapabilityRuntime {
  const pdp = new ConditionEnforcerPDP({
    policySource: staticPolicySource(manifest),
    counterStore: opts.counterStore,
    killSwitchManager: opts.killSwitchManager,
  });
  const auditSink = opts.auditSink ?? new NullAuditSink();
  const sessionId = opts.sessionId ?? crypto.randomUUID();
  return new LocalCapabilityRuntime(pdp, auditSink, sessionId);
}

function makeRequest(
  tool: string,
  args: Record<string, unknown> = {},
  extra: Partial<LocalToolInvocationRequest> = {},
): LocalToolInvocationRequest {
  return { tool, args, ...extra };
}

// ---------------------------------------------------------------------------
// Recording audit sink for assertion
// ---------------------------------------------------------------------------

class RecordingAuditSink extends NullAuditSink {
  public readonly records: McpAuditRecord[] = [];
  override async record(entry: McpAuditRecord): Promise<void> {
    this.records.push(entry);
  }
}

// ---------------------------------------------------------------------------
// Basic invokeTool tests
// ---------------------------------------------------------------------------

describe('LocalCapabilityRuntime', () => {
  describe('invokeTool — basic allow/deny', () => {
    it('allows a call when no conditions are on the matching constraint', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.success).toBe(true);
    });

    it('allows a call for a tool not listed in the manifest', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const result = await runtime.invokeTool(makeRequest('unlisted_tool'));
      expect(result.success).toBe(true);
    });

    it('denies a call that exceeds maxCalls', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 2, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      await runtime.invokeTool(makeRequest('query_db'));
      await runtime.invokeTool(makeRequest('query_db'));
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('MAX_CALLS_EXCEEDED');
    });

    it('returns denialReason on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      await runtime.invokeTool(makeRequest('query_db'));
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.success).toBe(false);
      expect(typeof result.denialReason).toBe('string');
      expect(result.denialReason!.length).toBeGreaterThan(0);
    });

    it('returns conditionType on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      await runtime.invokeTool(makeRequest('query_db'));
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.conditionType).toBe('maxCalls');
    });

    it('denies due to allowedOperations condition', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'allowedOperations', operations: ['SELECT'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', { sql: 'DROP TABLE users' }),
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('OPERATION_NOT_ALLOWED');
    });

    it('allows a SELECT operation when allowedOperations includes SELECT', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'allowedOperations', operations: ['SELECT'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', { sql: 'SELECT 1' }),
      );
      expect(result.success).toBe(true);
    });

    it('denies due to allowedExtensions condition', async () => {
      const manifest = makeManifest('read_file', [
        { type: 'allowedExtensions', extensions: ['.txt', '.csv'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('read_file', { path: '/data/file.exe' }),
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('EXTENSION_NOT_ALLOWED');
    });

    it('allows an allowed extension', async () => {
      const manifest = makeManifest('read_file', [
        { type: 'allowedExtensions', extensions: ['.txt', '.csv'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('read_file', { path: '/data/report.csv' }),
      );
      expect(result.success).toBe(true);
    });

    it('denies due to argumentSchema condition', async () => {
      // Use argumentSchema at constraint level
      const manifestWithSchema: AgentCapabilityManifest = {
        agentId: 'test-agent',
        name: 'Test Agent',
        version: '1.0.0',
        requiredCapabilities: [
          {
            resource: 'send_email',
            actions: ['call'],
            argumentSchema: {
              type: 'object',
              required: ['to'],
              properties: {
                to: { type: 'string' },
              },
            },
          },
        ],
      };
      const runtime = makeRuntime(manifestWithSchema);
      const result = await runtime.invokeTool(
        makeRequest('send_email', { to: 123 }), // wrong type
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
      expect(result.conditionType).toBe('argumentSchema');
    });

    it('populates details for argumentSchema denial', async () => {
      const manifestWithSchema: AgentCapabilityManifest = {
        agentId: 'test-agent',
        name: 'Test Agent',
        version: '1.0.0',
        requiredCapabilities: [
          {
            resource: 'send_email',
            actions: ['call'],
            argumentSchema: {
              type: 'object',
              required: ['to'],
              properties: {
                to: { type: 'string' },
              },
            },
          },
        ],
      };
      const runtime = makeRuntime(manifestWithSchema);
      const result = await runtime.invokeTool(
        makeRequest('send_email', { to: 123 }),
      );
      expect(result.success).toBe(false);
      expect(result.details).toBeDefined();
    });

    it('allows when argumentSchema is satisfied', async () => {
      const manifestWithSchema: AgentCapabilityManifest = {
        agentId: 'test-agent',
        name: 'Test Agent',
        version: '1.0.0',
        requiredCapabilities: [
          {
            resource: 'send_email',
            actions: ['call'],
            argumentSchema: {
              type: 'object',
              required: ['to'],
              properties: {
                to: { type: 'string' },
              },
            },
          },
        ],
      };
      const runtime = makeRuntime(manifestWithSchema);
      const result = await runtime.invokeTool(
        makeRequest('send_email', { to: 'user@example.com' }),
      );
      expect(result.success).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Session ID
  // ---------------------------------------------------------------------------

  describe('sessionId', () => {
    it('exposes the session ID set in the constructor', () => {
      const sessionId = 'fixed-session-42';
      const runtime = makeRuntime(makeManifest('tool'), { sessionId });
      expect(runtime.sessionId).toBe(sessionId);
    });

    it('session IDs are different across runtime instances', () => {
      const r1 = makeRuntime(makeManifest('tool'));
      const r2 = makeRuntime(makeManifest('tool'));
      expect(r1.sessionId).not.toBe(r2.sessionId);
    });
  });

  // ---------------------------------------------------------------------------
  // Kill switch
  // ---------------------------------------------------------------------------

  describe('terminate / isTerminated', () => {
    it('starts as not terminated', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      expect(runtime.isTerminated()).toBe(false);
    });

    it('isTerminated returns true after terminate()', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      runtime.terminate();
      expect(runtime.isTerminated()).toBe(true);
    });

    it('invokeTool returns KILL_SWITCH denial after terminate()', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      runtime.terminate();
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('KILL_SWITCH');
    });

    it('all subsequent invocations fail after terminate()', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      runtime.terminate();
      for (let i = 0; i < 5; i++) {
        const result = await runtime.invokeTool(makeRequest('query_db'));
        expect(result.success).toBe(false);
        expect(result.denialCode).toBe('KILL_SWITCH');
      }
    });

    it('conditionType is kill for KILL_SWITCH denial', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      runtime.terminate();
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.conditionType).toBe('kill');
    });
  });

  // ---------------------------------------------------------------------------
  // Audit recording
  // ---------------------------------------------------------------------------

  describe('audit recording', () => {
    it('records an allow decision to the audit sink', async () => {
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('query_db'), { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records).toHaveLength(1);
      expect(sink.records[0]!.decision).toBe('allow');
    });

    it('records a deny decision to the audit sink', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db'));
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records).toHaveLength(2);
      expect(sink.records[0]!.decision).toBe('allow');
      expect(sink.records[1]!.decision).toBe('deny');
    });

    it('records the correct toolName', async () => {
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('my_special_tool'), { auditSink: sink });
      await runtime.invokeTool(makeRequest('my_special_tool'));
      expect(sink.records[0]!.toolName).toBe('my_special_tool');
    });

    it('records the sessionId', async () => {
      const sessionId = 'audit-session-test';
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('query_db'), { sessionId, auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records[0]!.sessionId).toBe(sessionId);
    });

    it('records the resource when supplied', async () => {
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('query_db'), { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db', {}, { resource: 'mcp-tool://query_db' }));
      expect(sink.records[0]!.resource).toBe('mcp-tool://query_db');
    });

    it('records denialCode on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db'));
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records[1]!.denialCode).toBe('MAX_CALLS_EXCEEDED');
    });

    it('records conditionType on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db'));
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records[1]!.conditionType).toBe('maxCalls');
    });

    it('records KILL_SWITCH audit on terminated runtime', async () => {
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('query_db'), { auditSink: sink });
      runtime.terminate();
      await runtime.invokeTool(makeRequest('query_db'));
      expect(sink.records[0]!.decision).toBe('deny');
      expect(sink.records[0]!.denialCode).toBe('KILL_SWITCH');
    });

    it('records multiple calls in sequence', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'allowedOperations', operations: ['SELECT'] },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      await runtime.invokeTool(makeRequest('query_db', { sql: 'SELECT 1' }));
      await runtime.invokeTool(makeRequest('query_db', { sql: 'DELETE FROM t' }));
      expect(sink.records).toHaveLength(2);
      expect(sink.records[0]!.decision).toBe('allow');
      expect(sink.records[1]!.decision).toBe('deny');
    });
  });

  // ---------------------------------------------------------------------------
  // sourceIp forwarding
  // ---------------------------------------------------------------------------

  describe('sourceIp forwarding', () => {
    it('passes sourceIp to the PDP context (ipRange condition)', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', {}, { sourceIp: '10.1.2.3' }),
      );
      expect(result.success).toBe(true);
    });

    it('denies when sourceIp is outside the allowed range', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', {}, { sourceIp: '192.168.1.1' }),
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('IP_RANGE_DENIED');
    });

    it('denies when sourceIp is absent and ipRange condition is present', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(makeRequest('query_db'));
      expect(result.success).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // dispose
  // ---------------------------------------------------------------------------

  describe('dispose', () => {
    it('dispose() resolves without error', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      await expect(runtime.dispose()).resolves.not.toThrow();
    });

    it('dispose() can be called multiple times safely', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      await runtime.dispose();
      await expect(runtime.dispose()).resolves.not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // concurrent invocations
  // ---------------------------------------------------------------------------

  describe('concurrent invocations', () => {
    it('handles concurrent allowed calls correctly', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const results = await Promise.all([
        runtime.invokeTool(makeRequest('query_db')),
        runtime.invokeTool(makeRequest('query_db')),
        runtime.invokeTool(makeRequest('query_db')),
      ]);
      expect(results.every((r) => r.success)).toBe(true);
    });

    it('maxCalls counter is accurate under concurrent calls', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 3, windowSeconds: 60 },
      ]);
      const counterStore = new InMemoryCallCounterStore();
      const runtime = makeRuntime(manifest, { counterStore });

      // Serial calls to get a deterministic test
      const results: boolean[] = [];
      for (let i = 0; i < 5; i++) {
        const r = await runtime.invokeTool(makeRequest('query_db'));
        results.push(r.success);
      }

      const allowed = results.filter(Boolean).length;
      const denied = results.filter((r) => !r).length;
      expect(allowed).toBe(3);
      expect(denied).toBe(2);
    });
  });

  // ---------------------------------------------------------------------------
  // recipientDomain condition
  // ---------------------------------------------------------------------------

  describe('recipientDomain condition', () => {
    it('allows when all recipients are in allowed domains', async () => {
      const manifest = makeManifest('send_email', [
        { type: 'recipientDomain', domains: ['example.com'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('send_email', { to: 'user@example.com' }),
      );
      expect(result.success).toBe(true);
    });

    it('denies when a recipient is outside allowed domains', async () => {
      const manifest = makeManifest('send_email', [
        { type: 'recipientDomain', domains: ['example.com'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('send_email', { to: 'attacker@evil.com' }),
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
    });
  });

  // ---------------------------------------------------------------------------
  // allowedTables condition
  // ---------------------------------------------------------------------------

  describe('allowedTables condition', () => {
    it('allows access to an allowed table', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'allowedTables', tables: ['reports'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', { table: 'reports' }),
      );
      expect(result.success).toBe(true);
    });

    it('denies access to a restricted table', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'allowedTables', tables: ['reports'] },
      ]);
      const runtime = makeRuntime(manifest);
      const result = await runtime.invokeTool(
        makeRequest('query_db', { table: 'users' }),
      );
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('TABLE_NOT_ALLOWED');
    });
  });
});

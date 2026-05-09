/**
 * Tests for wrapAsLangChainTool and wrapAsLangChainTools.
 */

import * as crypto from 'crypto';

import type { AgentCapabilityManifest, CapabilityCondition } from '@euno/common-core';
import {
  ConditionEnforcerPDP,
  NullAuditSink,
} from '@euno/mcp';
import type { McpAuditRecord } from '@euno/mcp';

import { LocalCapabilityRuntime } from '../runtime';
import { wrapAsLangChainTool, wrapAsLangChainTools } from '../tool';
import { CapabilityDenialError } from '../types';
import type { LocalToolDefinition } from '../types';

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

class RecordingAuditSink extends NullAuditSink {
  public readonly records: McpAuditRecord[] = [];
  override async record(entry: McpAuditRecord): Promise<void> {
    this.records.push(entry);
  }
}

function makeRuntime(
  manifest: AgentCapabilityManifest,
  opts: { auditSink?: RecordingAuditSink } = {},
): LocalCapabilityRuntime {
  const pdp = new ConditionEnforcerPDP({ policySource: staticPolicySource(manifest) });
  return new LocalCapabilityRuntime(pdp, opts.auditSink ?? new NullAuditSink(), crypto.randomUUID());
}

// ---------------------------------------------------------------------------
// wrapAsLangChainTool — validation
// ---------------------------------------------------------------------------

describe('wrapAsLangChainTool', () => {
  describe('validation', () => {
    it('throws TypeError when runtime is null', () => {
      expect(() =>
        wrapAsLangChainTool(null as never, { name: 't', description: 'd' }),
      ).toThrow(TypeError);
    });

    it('throws TypeError when runtime is undefined', () => {
      expect(() =>
        wrapAsLangChainTool(undefined as never, { name: 't', description: 'd' }),
      ).toThrow(TypeError);
    });

    it('throws TypeError when runtime is a plain object without invokeTool', () => {
      expect(() =>
        wrapAsLangChainTool({} as never, { name: 't', description: 'd' }),
      ).toThrow(TypeError);
    });

    it('throws TypeError when runtime is missing isTerminated', () => {
      expect(() =>
        wrapAsLangChainTool(
          { invokeTool: () => {} } as never,
          { name: 't', description: 'd' },
        ),
      ).toThrow(TypeError);
    });

    it('throws TypeError when definition name is empty string', () => {
      const runtime = makeRuntime(makeManifest('tool'));
      expect(() =>
        wrapAsLangChainTool(runtime, { name: '', description: 'd' }),
      ).toThrow(TypeError);
    });

    it('throws TypeError when definition name is whitespace only', () => {
      const runtime = makeRuntime(makeManifest('tool'));
      expect(() =>
        wrapAsLangChainTool(runtime, { name: '   ', description: 'd' }),
      ).toThrow(TypeError);
    });

    it('throws TypeError when definition is null', () => {
      const runtime = makeRuntime(makeManifest('tool'));
      expect(() =>
        wrapAsLangChainTool(runtime, null as never),
      ).toThrow(TypeError);
    });

    it('does not throw when all required fields are present', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      expect(() =>
        wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' }),
      ).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Returned object shape
  // ---------------------------------------------------------------------------

  describe('returned tool object', () => {
    it('exposes name from the definition', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      expect(tool.name).toBe('query_db');
    });

    it('exposes description from the definition', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'Run a SQL query',
      });
      expect(tool.description).toBe('Run a SQL query');
    });

    it('exposes schema when provided', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const schema = { type: 'object', properties: { sql: { type: 'string' } } };
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        schema,
      });
      expect(tool.schema).toEqual(schema);
    });

    it('schema is undefined when not provided', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      expect(tool.schema).toBeUndefined();
    });

    it('exposes invoke() method', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      expect(typeof tool.invoke).toBe('function');
    });

    it('exposes call() method', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      expect(typeof tool.call).toBe('function');
    });

    it('exposes func() method', () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      expect(typeof tool.func).toBe('function');
    });
  });

  // ---------------------------------------------------------------------------
  // Allow path — handler invocation
  // ---------------------------------------------------------------------------

  describe('allow path', () => {
    it('returns empty string when no handler is provided and call is allowed', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      const result = await tool.invoke({});
      expect(result).toBe('');
    });

    it('calls the handler with the normalized args when allowed', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      let capturedArgs: Record<string, unknown> | undefined;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async (args) => {
          capturedArgs = args;
          return 'ok';
        },
      });
      await tool.invoke({ sql: 'SELECT 1' });
      expect(capturedArgs).toEqual({ sql: 'SELECT 1' });
    });

    it('returns the handler result as a string', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => ({ rows: 3 }),
      });
      const result = await tool.invoke({});
      expect(result).toBe(JSON.stringify({ rows: 3 }));
    });

    it('returns a string handler result as-is (no double JSON-encoding)', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => 'plain text result',
      });
      const result = await tool.invoke({});
      expect(result).toBe('plain text result');
    });

    it('coerces undefined handler result to empty string', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => undefined,
      });
      const result = await tool.invoke({});
      expect(result).toBe('');
    });

    it('coerces null handler result to empty string', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => null,
      });
      const result = await tool.invoke({});
      expect(result).toBe('');
    });

    it('coerces numeric handler result to JSON string', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => 42,
      });
      const result = await tool.invoke({});
      expect(result).toBe('42');
    });

    it('handler can be a sync function (returns non-Promise)', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: () => 'sync result',
      });
      const result = await tool.invoke({});
      expect(result).toBe('sync result');
    });
  });

  // ---------------------------------------------------------------------------
  // Deny path — CapabilityDenialError
  // ---------------------------------------------------------------------------

  describe('deny path', () => {
    it('throws CapabilityDenialError when policy denies the call', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({}); // first call — allowed
      await expect(tool.invoke({})).rejects.toThrow(CapabilityDenialError);
    });

    it('thrown CapabilityDenialError has correct errorCode', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.errorCode).toBe('MAX_CALLS_EXCEEDED');
    });

    it('thrown CapabilityDenialError has correct statusCode for rate-limit', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.statusCode).toBe(429);
    });

    it('thrown CapabilityDenialError has correct tool name', async () => {
      const manifest = makeManifest('my_tool', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'my_tool', description: 'desc' });

      await tool.invoke({});
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.tool).toBe('my_tool');
    });

    it('thrown CapabilityDenialError has correlationId', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(typeof caught!.correlationId).toBe('string');
      expect(caught!.correlationId!.length).toBeGreaterThan(0);
    });

    it('thrown CapabilityDenialError has conditionType', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.conditionType).toBe('maxCalls');
    });

    it('does NOT call the handler when the call is denied', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      let handlerCalled = 0;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: async () => {
          handlerCalled++;
          return 'ok';
        },
      });

      await tool.invoke({});
      try {
        await tool.invoke({});
      } catch {
        /* expected */
      }
      expect(handlerCalled).toBe(1);
    });

    it('throws CapabilityDenialError (503) after terminate()', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      runtime.terminate();
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      await expect(tool.invoke({})).rejects.toThrow(CapabilityDenialError);
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.errorCode).toBe('KILL_SWITCH');
      expect(caught!.statusCode).toBe(503);
    });

    it('ARGUMENT_VALIDATION_FAILED has 422 status', async () => {
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
              properties: { to: { type: 'string' } },
            },
          },
        ],
      };
      const runtime = makeRuntime(manifestWithSchema);
      const tool = wrapAsLangChainTool(runtime, { name: 'send_email', description: 'desc' });
      let caught: CapabilityDenialError | undefined;
      try {
        await tool.invoke({ to: 12345 });
      } catch (e) {
        caught = e as CapabilityDenialError;
      }
      expect(caught!.statusCode).toBe(422);
      expect(caught!.errorCode).toBe('ARGUMENT_VALIDATION_FAILED');
    });
  });

  // ---------------------------------------------------------------------------
  // Argument normalisation
  // ---------------------------------------------------------------------------

  describe('argument normalisation', () => {
    it('forwards plain objects verbatim to the handler', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      let received: Record<string, unknown> | undefined;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: (args) => { received = args; return 'ok'; },
      });
      await tool.invoke({ a: 1, b: 'two' });
      expect(received).toEqual({ a: 1, b: 'two' });
    });

    it('coerces a string input to {} when no transformArgs', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      let received: Record<string, unknown> | undefined;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: (args) => { received = args; return 'ok'; },
      });
      await tool.invoke('plain-string-input');
      expect(received).toEqual({});
    });

    it('coerces an array input to {} when no transformArgs', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      let received: Record<string, unknown> | undefined;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: (args) => { received = args; return 'ok'; },
      });
      await tool.invoke([1, 2, 3]);
      expect(received).toEqual({});
    });

    it('applies transformArgs before calling the handler', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      let received: Record<string, unknown> | undefined;
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        transformArgs: (raw) => ({ wrapped: raw }),
        handler: (args) => { received = args; return 'ok'; },
      });
      await tool.invoke('plain input');
      expect(received).toEqual({ wrapped: 'plain input' });
    });

    it('throws TypeError when transformArgs returns a non-object', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        transformArgs: () => 'not-an-object' as never,
      });
      await expect(tool.invoke({})).rejects.toThrow(TypeError);
    });

    it('throws TypeError when transformArgs returns an array', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        transformArgs: () => [] as never,
      });
      await expect(tool.invoke({})).rejects.toThrow(TypeError);
    });
  });

  // ---------------------------------------------------------------------------
  // call() and func() aliases
  // ---------------------------------------------------------------------------

  describe('call() and func() aliases', () => {
    it('call() produces the same result as invoke()', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: () => 'response',
      });
      const r1 = await tool.invoke({});
      const r2 = await tool.call({});
      expect(r1).toBe(r2);
    });

    it('func() produces the same result as invoke()', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        handler: () => 'response',
      });
      const r1 = await tool.invoke({});
      const r2 = await tool.func({});
      expect(r1).toBe(r2);
    });

    it('call() also throws CapabilityDenialError on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.call({});
      await expect(tool.call({})).rejects.toThrow(CapabilityDenialError);
    });

    it('func() also throws CapabilityDenialError on deny', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.func({});
      await expect(tool.func({})).rejects.toThrow(CapabilityDenialError);
    });
  });

  // ---------------------------------------------------------------------------
  // resource forwarding
  // ---------------------------------------------------------------------------

  describe('resource forwarding', () => {
    it('uses mcp-tool://<name> as default resource', async () => {
      // Verify the default resource doesn't cause issues when passed to audit
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });
      await expect(tool.invoke({})).resolves.not.toThrow();
    });

    it('accepts a custom resource in the definition', async () => {
      const runtime = makeRuntime(makeManifest('query_db'));
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        resource: 'custom://resource/path',
      });
      await expect(tool.invoke({})).resolves.not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // sourceIp forwarding
  // ---------------------------------------------------------------------------

  describe('sourceIp forwarding', () => {
    it('allows calls when sourceIp matches the ipRange condition', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        sourceIp: '10.5.6.7',
      });
      await expect(tool.invoke({})).resolves.not.toThrow();
    });

    it('denies calls when sourceIp is outside the ipRange', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
      ]);
      const runtime = makeRuntime(manifest);
      const tool = wrapAsLangChainTool(runtime, {
        name: 'query_db',
        description: 'desc',
        sourceIp: '192.168.1.1',
      });
      await expect(tool.invoke({})).rejects.toThrow(CapabilityDenialError);
    });
  });

  // ---------------------------------------------------------------------------
  // correlationId forwarding to invokeTool
  // ---------------------------------------------------------------------------

  describe('correlationId forwarding', () => {
    it('passes a correlationId to invokeTool so audit requestId matches denial error', async () => {
      // Use a recording sink to capture the requestId written to the audit log.
      // The CapabilityDenialError's correlationId must match that requestId.
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      // First call — allowed; record the requestId from the audit log.
      await tool.invoke({});
      const allowRequestId = sink.records[0]!.requestId;
      expect(typeof allowRequestId).toBe('string');

      // Second call — denied; capture the CapabilityDenialError.
      let denial: CapabilityDenialError | undefined;
      try {
        await tool.invoke({});
      } catch (e) {
        denial = e as CapabilityDenialError;
      }

      // The denial error's correlationId must match the requestId on the audit record.
      const denyRequestId = sink.records[1]!.requestId;
      expect(typeof denyRequestId).toBe('string');
      expect(denial!.correlationId).toBe(denyRequestId);
    });

    it('correlationId is a UUID v4', async () => {
      const manifest = makeManifest('query_db', [
        { type: 'maxCalls', count: 1, windowSeconds: 60 },
      ]);
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(manifest, { auditSink: sink });
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      expect(sink.records[0]!.requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('each tool invocation gets a distinct correlationId', async () => {
      const sink = new RecordingAuditSink();
      const runtime = makeRuntime(makeManifest('query_db'), { auditSink: sink });
      const tool = wrapAsLangChainTool(runtime, { name: 'query_db', description: 'desc' });

      await tool.invoke({});
      await tool.invoke({});
      await tool.invoke({});

      const ids = sink.records.map((r) => r.requestId);
      const unique = new Set(ids);
      expect(unique.size).toBe(3);
    });
  });
});

// ---------------------------------------------------------------------------
// wrapAsLangChainTools
// ---------------------------------------------------------------------------

describe('wrapAsLangChainTools', () => {
  it('returns an array of the same length as the definitions', () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    const defs: LocalToolDefinition[] = [
      { name: 'tool_a', description: 'A' },
      { name: 'tool_b', description: 'B' },
      { name: 'tool_c', description: 'C' },
    ];
    const tools = wrapAsLangChainTools(runtime, defs);
    expect(tools).toHaveLength(3);
  });

  it('each tool has the correct name', () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    const defs: LocalToolDefinition[] = [
      { name: 'tool_a', description: 'A' },
      { name: 'tool_b', description: 'B' },
    ];
    const tools = wrapAsLangChainTools(runtime, defs);
    expect(tools[0]!.name).toBe('tool_a');
    expect(tools[1]!.name).toBe('tool_b');
  });

  it('each tool has the correct description', () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    const defs: LocalToolDefinition[] = [
      { name: 'tool_a', description: 'Desc A' },
      { name: 'tool_b', description: 'Desc B' },
    ];
    const tools = wrapAsLangChainTools(runtime, defs);
    expect(tools[0]!.description).toBe('Desc A');
    expect(tools[1]!.description).toBe('Desc B');
  });

  it('returns an empty array for an empty definitions list', () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    const tools = wrapAsLangChainTools(runtime, []);
    expect(tools).toEqual([]);
  });

  it('each tool is independently invocable', async () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    const results: string[] = [];
    const defs: LocalToolDefinition[] = [
      { name: 'tool_a', description: 'A', handler: () => 'result_a' },
      { name: 'tool_b', description: 'B', handler: () => 'result_b' },
    ];
    const tools = wrapAsLangChainTools(runtime, defs);
    for (const tool of tools) {
      results.push(await tool.invoke({}));
    }
    expect(results).toEqual(['result_a', 'result_b']);
  });

  it('throws for the failing definition when one is invalid', () => {
    const runtime = makeRuntime(makeManifest('query_db'));
    expect(() =>
      wrapAsLangChainTools(runtime, [
        { name: 'tool_a', description: 'A' },
        { name: '', description: 'B' }, // invalid
      ]),
    ).toThrow(TypeError);
  });
});

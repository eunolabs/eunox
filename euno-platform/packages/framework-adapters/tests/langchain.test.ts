import { wrapAsLangChainTool, wrapAsLangChainTools, EunoLangChainCallbackHandler } from '../src/langchain';
import { CapabilityDenialError, ToolBinding } from '../src/types';
import { FakeRuntime } from './fake-runtime';

describe('LangChain adapter', () => {
  describe('wrapAsLangChainTool', () => {
    it('routes invoke() calls through the runtime with the bound tool/resource', async () => {
      const runtime = new FakeRuntime();
      runtime.setNextResponse({ success: true, data: { rows: 3 }, statusCode: 200 });
      const binding: ToolBinding = {
        frameworkToolName: 'lookup_customer',
        gatewayTool: 'crm.read',
        gatewayResource: 'api://crm/contacts',
        description: 'Lookup a customer by id',
      };

      const tool = wrapAsLangChainTool(runtime, binding);

      expect(tool.name).toBe('lookup_customer');
      expect(tool.description).toBe('Lookup a customer by id');

      const result = await tool.invoke({ id: 42 });

      expect(runtime.calls).toHaveLength(1);
      expect(runtime.calls[0]!.request).toEqual({
        tool: 'crm.read',
        args: { id: 42 },
        resource: 'api://crm/contacts',
      });
      expect(JSON.parse(result)).toEqual({ rows: 3 });
    });

    it('uses transformArgs when provided', async () => {
      const runtime = new FakeRuntime();
      const binding: ToolBinding = {
        frameworkToolName: 'lookup',
        gatewayTool: 'crm.read',
        transformArgs: (raw) => ({ wrapped: raw }),
      };
      const tool = wrapAsLangChainTool(runtime, binding);
      await tool.invoke('plain-string');
      expect(runtime.calls[0]!.request.args).toEqual({ wrapped: 'plain-string' });
    });

    it('returns string output as-is (no double JSON-encoding)', async () => {
      const runtime = new FakeRuntime();
      runtime.setNextResponse({ success: true, data: 'plain text', statusCode: 200 });
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
      });
      await expect(tool.invoke({})).resolves.toBe('plain text');
    });

    it('throws CapabilityDenialError on gateway failure with errorCode preserved', async () => {
      const runtime = new FakeRuntime();
      runtime.setNextResponse({
        success: false,
        error: 'Token revoked',
        errorCode: 'TOKEN_REVOKED',
        statusCode: 401,
      });
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
        gatewayResource: 'api://x',
      });

      let caught: unknown;
      try {
        await tool.invoke({});
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(CapabilityDenialError);
      const denial = caught as CapabilityDenialError;
      expect(denial.errorCode).toBe('TOKEN_REVOKED');
      expect(denial.statusCode).toBe(401);
      expect(denial.tool).toBe('gw');
      expect(denial.resource).toBe('api://x');
      expect(denial.correlationId).toBeTruthy();
    });

    it('rejects misconfigured runtimes synchronously', () => {
      expect(() =>
        wrapAsLangChainTool({} as never, { frameworkToolName: 't', gatewayTool: 'gw' })
      ).toThrow(TypeError);
    });

    it('rejects bindings missing required fields', () => {
      const runtime = new FakeRuntime();
      expect(() =>
        wrapAsLangChainTool(runtime, { frameworkToolName: '', gatewayTool: 'gw' })
      ).toThrow(TypeError);
      expect(() =>
        wrapAsLangChainTool(runtime, { frameworkToolName: 't', gatewayTool: '' })
      ).toThrow(TypeError);
    });

    it('exposes call() and func() aliases for legacy LangChain Tool callers', async () => {
      const runtime = new FakeRuntime();
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
      });
      await tool.call({ a: 1 });
      await tool.func({ b: 2 });
      expect(runtime.calls).toHaveLength(2);
    });
  });

  describe('wrapAsLangChainTools', () => {
    it('bulk-wraps an array of bindings', () => {
      const runtime = new FakeRuntime();
      const tools = wrapAsLangChainTools(runtime, [
        { frameworkToolName: 'a', gatewayTool: 'ga' },
        { frameworkToolName: 'b', gatewayTool: 'gb' },
      ]);
      expect(tools.map((t) => t.name)).toEqual(['a', 'b']);
    });
  });

  describe('EunoLangChainCallbackHandler', () => {
    it('emits start/end events with the same correlationId AND toolName per runId', () => {
      const events: any[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'lookup_customer' }, 'in', 'run-1');
      handler.handleToolEnd('out', 'run-1');
      expect(events).toHaveLength(2);
      expect(events[0].phase).toBe('tool-start');
      expect(events[1].phase).toBe('tool-end');
      expect(events[0].correlationId).toBe(events[1].correlationId);
      // tool-end must surface the same tool name captured at tool-start
      expect(events[0].toolName).toBe('lookup_customer');
      expect(events[1].toolName).toBe('lookup_customer');
    });

    it('emits error events with structured fields from CapabilityDenialError', () => {
      const events: any[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 't' }, 'in', 'run-2');
      const denial = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'INSUFFICIENT_SCOPE',
        tool: 'gw',
        correlationId: 'ignored',
      });
      handler.handleToolError(denial, 'run-2');
      const err = events[1];
      expect(err.phase).toBe('tool-error');
      expect(err.errorCode).toBe('INSUFFICIENT_SCOPE');
      expect(err.statusCode).toBe(403);
      expect(err.errorMessage).toBe('denied');
      // correlation should match the start
      expect(err.correlationId).toBe(events[0].correlationId);
    });

    it('rejects non-function sinks', () => {
      expect(() => new EunoLangChainCallbackHandler(undefined as never)).toThrow(TypeError);
    });

    it('also propagates toolName on tool-error events', () => {
      const events: any[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'crm_lookup' }, 'in', 'run-3');
      handler.handleToolError(new Error('boom'), 'run-3');
      expect(events[1].toolName).toBe('crm_lookup');
    });
  });

  describe('argument validation (invokeBoundTool)', () => {
    it('coerces non-object inputs to {} when no transformArgs is supplied', async () => {
      const runtime = new FakeRuntime();
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
      });
      await tool.invoke('plain-string');
      expect(runtime.calls[0]!.request.args).toEqual({});
    });

    it('forwards plain objects verbatim when no transformArgs is supplied', async () => {
      const runtime = new FakeRuntime();
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
      });
      await tool.invoke({ a: 1 });
      expect(runtime.calls[0]!.request.args).toEqual({ a: 1 });
    });

    it('throws TypeError when transformArgs returns a non-plain-object', async () => {
      const runtime = new FakeRuntime();
      const tool = wrapAsLangChainTool(runtime, {
        frameworkToolName: 't',
        gatewayTool: 'gw',
        transformArgs: () => 'not-an-object' as never,
      });
      await expect(tool.invoke({})).rejects.toThrow(TypeError);
    });
  });
});

import {
  createEunoFunctionToolMiddleware,
  createEunoAgentRunMiddleware,
  MAFFunctionInvocationContext,
  MAFAgentRunContext,
} from '../src/maf';
import { CapabilityDenialError, ToolBinding } from '../src/types';
import { FakeRuntime } from './fake-runtime';

const makeFnContext = (
  name: string,
  args: Record<string, unknown> = {}
): MAFFunctionInvocationContext => ({
  function: { name },
  arguments: args,
  metadata: {},
});

describe('MAF function-tool middleware', () => {
  it('routes a governed call through the gateway and short-circuits next()', async () => {
    const runtime = new FakeRuntime();
    runtime.setNextResponse({ success: true, data: { v: 7 }, statusCode: 200 });
    const bindings: ToolBinding[] = [
      { frameworkToolName: 'lookup', gatewayTool: 'crm.read', gatewayResource: 'api://crm' },
    ];
    const events: any[] = [];
    const mw = createEunoFunctionToolMiddleware(runtime, bindings, {
      onAuditEvent: (e) => events.push(e),
    });

    const ctx = makeFnContext('lookup', { id: 1 });
    let nextCalled = false;
    await mw(ctx, async () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(ctx.result).toEqual({ v: 7 });
    expect(runtime.calls[0]!.request).toEqual({
      tool: 'crm.read',
      args: { id: 1 },
      resource: 'api://crm',
    });
    expect(events.map((e) => e.phase)).toEqual(['tool-start', 'tool-end']);
    expect(ctx.metadata!.eunoCorrelationId).toBeTruthy();
    expect(events[0].correlationId).toBe(ctx.metadata!.eunoCorrelationId);
  });

  it('passes through unknown tools by default', async () => {
    const runtime = new FakeRuntime();
    const mw = createEunoFunctionToolMiddleware(runtime, []);
    const ctx = makeFnContext('not_governed');
    let nextCalled = false;
    await mw(ctx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(runtime.calls).toHaveLength(0);
  });

  it('denies unknown tools when policy="deny"', async () => {
    const runtime = new FakeRuntime();
    const events: any[] = [];
    const mw = createEunoFunctionToolMiddleware(runtime, [], {
      unknownToolPolicy: 'deny',
      onAuditEvent: (e) => events.push(e),
    });
    const ctx = makeFnContext('not_governed');
    await expect(mw(ctx, async () => undefined)).rejects.toBeInstanceOf(CapabilityDenialError);
    expect(events).toHaveLength(1);
    expect(events[0].phase).toBe('tool-error');
    expect(events[0].statusCode).toBe(403);
  });

  it('propagates gateway denials and emits a tool-error event', async () => {
    const runtime = new FakeRuntime();
    runtime.setNextResponse({
      success: false,
      error: 'expired',
      errorCode: 'EXPIRED_TOKEN',
      statusCode: 401,
    });
    const events: any[] = [];
    const mw = createEunoFunctionToolMiddleware(
      runtime,
      [{ frameworkToolName: 't', gatewayTool: 'gw' }],
      { onAuditEvent: (e) => events.push(e) }
    );
    const ctx = makeFnContext('t');
    await expect(mw(ctx, async () => undefined)).rejects.toBeInstanceOf(CapabilityDenialError);
    expect(events.map((e) => e.phase)).toEqual(['tool-start', 'tool-error']);
    expect(events[1].errorCode).toBe('EXPIRED_TOKEN');
    expect(events[1].statusCode).toBe(401);
  });

  it('rejects misconfigured runtimes', () => {
    expect(() => createEunoFunctionToolMiddleware({} as never, [])).toThrow(TypeError);
  });
});

describe('MAF agent-run middleware', () => {
  it('refuses to start a run when the runtime is terminated', async () => {
    const runtime = new FakeRuntime();
    runtime.setTerminated(true);
    const events: any[] = [];
    const mw = createEunoAgentRunMiddleware(runtime, { onAuditEvent: (e) => events.push(e) });
    const ctx: MAFAgentRunContext = {};
    await expect(mw(ctx, async () => undefined)).rejects.toBeInstanceOf(CapabilityDenialError);
    expect(events).toHaveLength(1);
    expect(events[0].phase).toBe('run-start');
    expect(events[0].statusCode).toBe(403);
  });

  it('tags the run context with a correlation ID and emits start/end events', async () => {
    const runtime = new FakeRuntime();
    const events: any[] = [];
    const mw = createEunoAgentRunMiddleware(runtime, { onAuditEvent: (e) => events.push(e) });
    const ctx: MAFAgentRunContext = {};
    let nextCalled = false;
    await mw(ctx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(ctx.metadata!.eunoCorrelationId).toBeTruthy();
    expect(events.map((e) => e.phase)).toEqual(['run-start', 'run-end']);
    expect(events[0].correlationId).toBe(events[1].correlationId);
  });

  it('still emits run-end when next() throws', async () => {
    const runtime = new FakeRuntime();
    const events: any[] = [];
    const mw = createEunoAgentRunMiddleware(runtime, { onAuditEvent: (e) => events.push(e) });
    await expect(
      mw({}, async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    expect(events.map((e) => e.phase)).toEqual(['run-start', 'run-end']);
  });
});

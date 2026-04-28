import { wrapAsCrewAITool, wrapAsCrewAITools, EunoCrewAITaskLifecycle } from '../src/crewai';
import { CapabilityDenialError, ToolBinding } from '../src/types';
import { FakeRuntime } from './fake-runtime';

describe('CrewAI tool wrapper', () => {
  it('routes func() and run() through the gateway', async () => {
    const runtime = new FakeRuntime();
    runtime.setNextResponse({ success: true, data: { ok: true }, statusCode: 200 });
    const binding: ToolBinding = {
      frameworkToolName: 'crm_lookup',
      gatewayTool: 'crm.read',
      gatewayResource: 'api://crm',
    };
    const tool = wrapAsCrewAITool(runtime, binding);

    expect(tool.name).toBe('crm_lookup');
    const r1 = await tool.func({ id: 1 });
    const r2 = await tool.run({ id: 2 });
    expect(r1).toEqual({ ok: true });
    expect(r2).toEqual({ ok: true });
    expect(runtime.calls.map((c) => c.request.args)).toEqual([{ id: 1 }, { id: 2 }]);
  });

  it('preserves CapabilityDenialError on failure', async () => {
    const runtime = new FakeRuntime();
    runtime.setNextResponse({
      success: false,
      error: 'no scope',
      errorCode: 'INSUFFICIENT_SCOPE',
      statusCode: 403,
    });
    const tool = wrapAsCrewAITool(runtime, { frameworkToolName: 't', gatewayTool: 'gw' });
    let caught: unknown;
    try {
      await tool.func({});
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CapabilityDenialError);
    expect((caught as CapabilityDenialError).errorCode).toBe('INSUFFICIENT_SCOPE');
  });

  it('rejects misconfigured runtimes / bindings', () => {
    const runtime = new FakeRuntime();
    expect(() => wrapAsCrewAITool({} as never, { frameworkToolName: 't', gatewayTool: 'g' })).toThrow(
      TypeError
    );
    expect(() => wrapAsCrewAITool(runtime, { frameworkToolName: '', gatewayTool: 'g' })).toThrow(
      TypeError
    );
    expect(() => wrapAsCrewAITool(runtime, { frameworkToolName: 't', gatewayTool: '' })).toThrow(
      TypeError
    );
  });

  it('wrapAsCrewAITools bulk-wraps', () => {
    const runtime = new FakeRuntime();
    const tools = wrapAsCrewAITools(runtime, [
      { frameworkToolName: 'a', gatewayTool: 'ga' },
      { frameworkToolName: 'b', gatewayTool: 'gb' },
    ]);
    expect(tools.map((t) => t.name)).toEqual(['a', 'b']);
  });
});

describe('EunoCrewAITaskLifecycle', () => {
  it('emits task-start / task-end with the same correlationId', () => {
    const events: any[] = [];
    const lifecycle = new EunoCrewAITaskLifecycle(new FakeRuntime(), (e) => events.push(e));
    const corr = lifecycle.beforeKickoff({ id: 'task-1', description: 'do thing' });
    lifecycle.afterKickoff({ id: 'task-1', description: 'do thing' }, { ok: true });
    expect(events.map((e) => e.phase)).toEqual(['task-start', 'task-end']);
    expect(events[0].correlationId).toBe(corr);
    expect(events[1].correlationId).toBe(corr);
  });

  it('refuses to start a task when runtime is terminated', () => {
    const runtime = new FakeRuntime();
    runtime.setTerminated(true);
    const events: any[] = [];
    const lifecycle = new EunoCrewAITaskLifecycle(runtime, (e) => events.push(e));
    expect(() => lifecycle.beforeKickoff({ id: 'task-1' })).toThrow(CapabilityDenialError);
    expect(events).toHaveLength(1);
    expect(events[0].phase).toBe('task-error');
    expect(events[0].statusCode).toBe(403);
  });

  it('emits task-error with structured fields when error is supplied', () => {
    const events: any[] = [];
    const lifecycle = new EunoCrewAITaskLifecycle(new FakeRuntime(), (e) => events.push(e));
    lifecycle.beforeKickoff({ id: 'task-2' });
    const denial = new CapabilityDenialError({
      message: 'denied',
      statusCode: 401,
      errorCode: 'EXPIRED_TOKEN',
      tool: 'gw',
    });
    lifecycle.afterKickoff({ id: 'task-2' }, undefined, denial);
    expect(events.map((e) => e.phase)).toEqual(['task-start', 'task-error']);
    expect(events[1].errorCode).toBe('EXPIRED_TOKEN');
    expect(events[1].statusCode).toBe(401);
    expect(events[1].errorMessage).toBe('denied');
  });

  it('falls back to description-based key when id is missing', () => {
    const events: any[] = [];
    const lifecycle = new EunoCrewAITaskLifecycle(new FakeRuntime(), (e) => events.push(e));
    lifecycle.beforeKickoff({ description: 'inline' });
    lifecycle.afterKickoff({ description: 'inline' });
    expect(events[0].correlationId).toBe(events[1].correlationId);
  });

  it('rejects misconfigured runtimes', () => {
    expect(() => new EunoCrewAITaskLifecycle({} as never)).toThrow(TypeError);
  });
});

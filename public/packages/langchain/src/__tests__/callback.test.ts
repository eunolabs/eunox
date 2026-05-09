/**
 * Tests for EunoLangChainCallbackHandler.
 */

import { EunoLangChainCallbackHandler } from '../callback';
import { CapabilityDenialError } from '../types';
import type { EunoCallbackEvent } from '../callback';

// ---------------------------------------------------------------------------
// EunoLangChainCallbackHandler
// ---------------------------------------------------------------------------

describe('EunoLangChainCallbackHandler', () => {
  describe('constructor', () => {
    it('creates an instance when given a valid sink', () => {
      const handler = new EunoLangChainCallbackHandler(() => {});
      expect(handler).toBeInstanceOf(EunoLangChainCallbackHandler);
    });

    it('exposes name === "EunoLangChainCallbackHandler"', () => {
      const handler = new EunoLangChainCallbackHandler(() => {});
      expect(handler.name).toBe('EunoLangChainCallbackHandler');
    });

    it('throws TypeError when sink is undefined', () => {
      expect(() => new EunoLangChainCallbackHandler(undefined as never)).toThrow(TypeError);
    });

    it('throws TypeError when sink is null', () => {
      expect(() => new EunoLangChainCallbackHandler(null as never)).toThrow(TypeError);
    });

    it('throws TypeError when sink is not a function', () => {
      expect(() => new EunoLangChainCallbackHandler('not-a-fn' as never)).toThrow(TypeError);
    });

    it('throws TypeError when sink is a plain object', () => {
      expect(() => new EunoLangChainCallbackHandler({} as never)).toThrow(TypeError);
    });
  });

  describe('handleToolStart', () => {
    it('emits a tool-start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'query_db' }, '{"sql":"SELECT 1"}', 'run-1');
      expect(events).toHaveLength(1);
      expect(events[0]!.phase).toBe('tool-start');
    });

    it('emits the correct toolName', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'my_tool' }, '', 'run-1');
      expect(events[0]!.toolName).toBe('my_tool');
    });

    it('emits the correct runId', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'my_tool' }, '', 'run-42');
      expect(events[0]!.runId).toBe('run-42');
    });

    it('emits parentRunId when provided', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'my_tool' }, '', 'run-1', 'parent-run-9');
      expect(events[0]!.parentRunId).toBe('parent-run-9');
    });

    it('parentRunId is undefined when not provided', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'my_tool' }, '', 'run-1');
      expect(events[0]!.parentRunId).toBeUndefined();
    });

    it('emits a correlationId that is a UUID v4', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      expect(events[0]!.correlationId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('emits a ts (ISO timestamp)', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      expect(events[0]!.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('uses <unknown> as toolName when tool.name is missing', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart(null as never, '', 'run-1');
      expect(events[0]!.toolName).toBe('<unknown>');
    });
  });

  describe('handleToolEnd', () => {
    it('emits a tool-end event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'query_db' }, '', 'run-1');
      handler.handleToolEnd('result', 'run-1');
      expect(events[1]!.phase).toBe('tool-end');
    });

    it('carries the same correlationId as the start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolEnd('', 'run-1');
      expect(events[0]!.correlationId).toBe(events[1]!.correlationId);
    });

    it('carries the same toolName as the start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'my_tool' }, '', 'run-1');
      handler.handleToolEnd('', 'run-1');
      expect(events[1]!.toolName).toBe('my_tool');
    });

    it('includes runId', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-77');
      handler.handleToolEnd('', 'run-77');
      expect(events[1]!.runId).toBe('run-77');
    });

    it('emits parentRunId on end when provided on start', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1', 'parent-run-3');
      handler.handleToolEnd('', 'run-1', 'parent-run-3');
      expect(events[1]!.parentRunId).toBe('parent-run-3');
    });

    it('emits <unknown> toolName when no matching start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolEnd('', 'unregistered-run');
      expect(events[0]!.toolName).toBe('<unknown>');
    });

    it('cleans up run state after handleToolEnd', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolEnd('', 'run-1');
      // Second end for same runId should use <unknown>
      handler.handleToolEnd('', 'run-1');
      expect(events[2]!.toolName).toBe('<unknown>');
    });
  });

  describe('handleToolError', () => {
    it('emits a tool-error event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('boom'), 'run-1');
      expect(events[1]!.phase).toBe('tool-error');
    });

    it('carries the same correlationId as the start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('boom'), 'run-1');
      expect(events[0]!.correlationId).toBe(events[1]!.correlationId);
    });

    it('carries the correct toolName from start', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'crm_lookup' }, '', 'run-3');
      handler.handleToolError(new Error('err'), 'run-3');
      expect(events[1]!.toolName).toBe('crm_lookup');
    });

    it('includes errorMessage from the error', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('something went wrong'), 'run-1');
      expect(events[1]!.errorMessage).toBe('something went wrong');
    });

    it('extracts errorCode from CapabilityDenialError', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(
        new CapabilityDenialError({
          message: 'denied',
          statusCode: 429,
          errorCode: 'MAX_CALLS_EXCEEDED',
          tool: 'query_db',
        }),
        'run-1',
      );
      expect(events[1]!.errorCode).toBe('MAX_CALLS_EXCEEDED');
    });

    it('extracts statusCode from CapabilityDenialError', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(
        new CapabilityDenialError({
          message: 'denied',
          statusCode: 429,
          errorCode: 'MAX_CALLS_EXCEEDED',
          tool: 'query_db',
        }),
        'run-1',
      );
      expect(events[1]!.statusCode).toBe(429);
    });

    it('extracts conditionType from CapabilityDenialError', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(
        new CapabilityDenialError({
          message: 'denied',
          statusCode: 403,
          errorCode: 'IP_RANGE_DENIED',
          tool: 'query_db',
          conditionType: 'ipRange',
        }),
        'run-1',
      );
      expect(events[1]!.conditionType).toBe('ipRange');
    });

    it('errorCode is undefined for non-denial errors', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('plain error'), 'run-1');
      expect(events[1]!.errorCode).toBeUndefined();
    });

    it('statusCode is undefined for non-denial errors', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('plain error'), 'run-1');
      expect(events[1]!.statusCode).toBeUndefined();
    });

    it('generates a fresh correlationId when no start event was registered', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolError(new Error('boom'), 'unregistered-run');
      expect(events[0]!.correlationId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('uses <unknown> toolName when no start event', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolError(new Error('err'), 'unregistered-run');
      expect(events[0]!.toolName).toBe('<unknown>');
    });

    it('cleans up run state after error', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolError(new Error('err'), 'run-1');
      // A second error for the same runId should not carry the cached state
      handler.handleToolError(new Error('err2'), 'run-1');
      expect(events[2]!.toolName).toBe('<unknown>');
    });

    it('includes parentRunId when provided on error', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1', 'parent-1');
      handler.handleToolError(new Error('err'), 'run-1', 'parent-1');
      expect(events[1]!.parentRunId).toBe('parent-1');
    });
  });

  describe('multiple concurrent runs', () => {
    it('tracks multiple runIds independently', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));

      handler.handleToolStart({ name: 'tool_a' }, '', 'run-1');
      handler.handleToolStart({ name: 'tool_b' }, '', 'run-2');
      handler.handleToolEnd('', 'run-1');
      handler.handleToolEnd('', 'run-2');

      const run1End = events.find((e) => e.phase === 'tool-end' && e.runId === 'run-1')!;
      const run2End = events.find((e) => e.phase === 'tool-end' && e.runId === 'run-2')!;
      expect(run1End.toolName).toBe('tool_a');
      expect(run2End.toolName).toBe('tool_b');
    });

    it('correlationIds are unique across different runs', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));

      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolStart({ name: 'tool' }, '', 'run-2');

      const corr1 = events[0]!.correlationId;
      const corr2 = events[1]!.correlationId;
      expect(corr1).not.toBe(corr2);
    });

    it('end events carry the correlation IDs of their respective start events', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));

      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolStart({ name: 'tool' }, '', 'run-2');
      handler.handleToolEnd('', 'run-2');
      handler.handleToolEnd('', 'run-1');

      const start1 = events.find((e) => e.runId === 'run-1' && e.phase === 'tool-start')!;
      const start2 = events.find((e) => e.runId === 'run-2' && e.phase === 'tool-start')!;
      const end1 = events.find((e) => e.runId === 'run-1' && e.phase === 'tool-end')!;
      const end2 = events.find((e) => e.runId === 'run-2' && e.phase === 'tool-end')!;

      expect(end1.correlationId).toBe(start1.correlationId);
      expect(end2.correlationId).toBe(start2.correlationId);
    });
  });

  describe('event timestamps', () => {
    it('ts is a valid ISO date string on all event types', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');
      handler.handleToolEnd('', 'run-1');
      handler.handleToolStart({ name: 'tool' }, '', 'run-2');
      handler.handleToolError(new Error('err'), 'run-2');

      for (const event of events) {
        expect(() => new Date(event.ts).toISOString()).not.toThrow();
      }
    });

    it('ts is recent (within the last minute)', () => {
      const events: EunoCallbackEvent[] = [];
      const handler = new EunoLangChainCallbackHandler((e) => events.push(e));
      handler.handleToolStart({ name: 'tool' }, '', 'run-1');

      const diff = Date.now() - new Date(events[0]!.ts).getTime();
      expect(diff).toBeGreaterThanOrEqual(0);
      expect(diff).toBeLessThan(60_000);
    });
  });
});

/**
 * Tests for the OpenTelemetry context-propagation primitives in
 * `packages/common/src/tracing.ts` (R-3 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 */

import { context, trace } from '@opentelemetry/api';
import Transport from 'winston-transport';
import {
  EUNO_ATTR,
  extractTraceContext,
  getActiveSpan,
  getCurrentTraceContext,
  getTracer,
  injectTraceContext,
  isValidSpanContext,
  setActiveSpanEunoAttributes,
  setEunoAttributes,
  tracingMiddleware,
  withSpan,
  _resetTracerCacheForTesting,
} from '../src/tracing';
import { createAuditLogger, _resetAuditChainStateForTesting } from '../src/logger';

describe('tracing module (R-3)', () => {
  beforeEach(() => {
    _resetTracerCacheForTesting();
  });

  // -------------------------------------------------------------------
  // W3C header propagation
  // -------------------------------------------------------------------

  describe('extractTraceContext / injectTraceContext', () => {
    const sampleTraceparent =
      '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';

    it('extracts a remote span context from a traceparent header', () => {
      const ctx = extractTraceContext({ traceparent: sampleTraceparent });
      const span = trace.getSpan(ctx);
      expect(span).toBeDefined();
      const sc = span!.spanContext();
      expect(sc.traceId).toBe('0af7651916cd43dd8448eb211c80319c');
      expect(sc.spanId).toBe('b7ad6b7169203331');
      expect(sc.traceFlags).toBe(1);
      expect(isValidSpanContext(sc)).toBe(true);
    });

    it('round-trips traceparent through inject', () => {
      const ctx = extractTraceContext({ traceparent: sampleTraceparent });
      const headers: Record<string, string> = {};
      injectTraceContext(headers, ctx);
      expect(headers.traceparent).toBe(sampleTraceparent);
    });

    it('handles array-valued headers (Node IncomingMessage shape)', () => {
      const ctx = extractTraceContext({
        traceparent: [sampleTraceparent],
      });
      const sc = trace.getSpan(ctx)!.spanContext();
      expect(sc.traceId).toBe('0af7651916cd43dd8448eb211c80319c');
    });

    it('is case-insensitive on the header key', () => {
      const ctx = extractTraceContext({ TraceParent: sampleTraceparent });
      const sc = trace.getSpan(ctx)!.spanContext();
      expect(sc.traceId).toBe('0af7651916cd43dd8448eb211c80319c');
    });

    it('returns the parent context unchanged when no traceparent is present', () => {
      const ctx = extractTraceContext({});
      expect(trace.getSpan(ctx)).toBeUndefined();
    });

    it('inject is a no-op when the active context has no valid span', () => {
      const headers: Record<string, string> = { existing: 'value' };
      injectTraceContext(headers);
      // No traceparent should be added because the global context has
      // no recording span (no SDK is registered in tests).
      expect(headers.traceparent).toBeUndefined();
      expect(headers.existing).toBe('value');
    });
  });

  // -------------------------------------------------------------------
  // Span helpers
  // -------------------------------------------------------------------

  describe('getCurrentTraceContext', () => {
    it('returns null with no active span', () => {
      expect(getCurrentTraceContext()).toBeNull();
    });

    it('returns the IDs from the propagated remote context', async () => {
      const ctx = extractTraceContext({
        traceparent:
          '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      });
      const remoteSpan = trace.getSpan(ctx)!;
      await context.with(trace.setSpan(context.active(), remoteSpan), async () => {
        const snap = getCurrentTraceContext();
        expect(snap).toEqual({
          trace_id: '0af7651916cd43dd8448eb211c80319c',
          span_id: 'b7ad6b7169203331',
          trace_flags: 1,
        });
      });
    });
  });

  describe('isValidSpanContext', () => {
    it('rejects undefined / zero IDs', () => {
      expect(isValidSpanContext(undefined)).toBe(false);
      expect(
        isValidSpanContext({
          traceId: '00000000000000000000000000000000',
          spanId: '0000000000000000',
          traceFlags: 0,
        }),
      ).toBe(false);
    });

    it('rejects malformed lengths', () => {
      expect(
        isValidSpanContext({
          traceId: 'short',
          spanId: 'b7ad6b7169203331',
          traceFlags: 0,
        }),
      ).toBe(false);
    });
  });

  describe('withSpan', () => {
    it('runs the body and returns its value (no SDK registered)', async () => {
      const tracer = getTracer('test-svc');
      const out = await withSpan(tracer, 'op', { [EUNO_ATTR.AGENT_ID]: 'a1' }, () => 42);
      expect(out).toBe(42);
    });

    it('re-throws and still ends the span on error', async () => {
      const tracer = getTracer('test-svc');
      await expect(
        withSpan(tracer, 'op', {}, async () => {
          throw new Error('boom');
        }),
      ).rejects.toThrow('boom');
    });
  });

  describe('setEunoAttributes / setActiveSpanEunoAttributes', () => {
    it('skips undefined attribute values', () => {
      const calls: Array<[string, unknown]> = [];
      const fakeSpan = {
        setAttribute: (k: string, v: unknown) => {
          calls.push([k, v]);
        },
      } as unknown as Parameters<typeof setEunoAttributes>[0];
      setEunoAttributes(fakeSpan, {
        [EUNO_ATTR.AGENT_ID]: 'a1',
        [EUNO_ATTR.JTI]: undefined,
        [EUNO_ATTR.OUTCOME]: 'allow',
      });
      expect(calls).toEqual([
        [EUNO_ATTR.AGENT_ID, 'a1'],
        [EUNO_ATTR.OUTCOME, 'allow'],
      ]);
    });

    it('setActiveSpanEunoAttributes is a no-op without an active span', () => {
      // Should not throw.
      setActiveSpanEunoAttributes({ [EUNO_ATTR.AGENT_ID]: 'a1' });
      expect(getActiveSpan()).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------
  // Express middleware
  // -------------------------------------------------------------------

  describe('tracingMiddleware', () => {
    function makeReq(headers: Record<string, string | string[]> = {}, overrides: Partial<{ method: string; path: string }> = {}) {
      return {
        method: overrides.method ?? 'GET',
        path: overrides.path ?? '/foo',
        headers,
      };
    }

    function makeRes() {
      const setHeaders: Record<string, string> = {};
      const listeners: Record<string, Array<() => void>> = {};
      return {
        statusCode: 200,
        setHeader: (k: string, v: string) => {
          setHeaders[k] = v;
        },
        on: (event: string, listener: () => void) => {
          (listeners[event] ||= []).push(listener);
        },
        _setHeaders: setHeaders,
        _listeners: listeners,
      };
    }

    it('extracts the inbound traceparent and activates a server span', (done) => {
      const mw = tracingMiddleware('test-svc');
      const req = makeReq({
        traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      });
      const res = makeRes();
      mw(req as never, res as never, () => {
        try {
          const snap = getCurrentTraceContext();
          // Same trace ID as the inbound header. Without a registered
          // SDK the started span is non-recording so the middleware
          // falls back to the wrapped remote context, meaning the
          // span_id matches the inbound value. With an SDK in place
          // the span_id would be a fresh child ID — both behaviours
          // are correct depending on whether tracing is exporting.
          expect(snap?.trace_id).toBe('0af7651916cd43dd8448eb211c80319c');
          expect(snap?.span_id).toMatch(/^[0-9a-f]{16}$/);
          // traceparent echoed back on the response.
          expect(res._setHeaders.traceparent).toMatch(
            /^00-0af7651916cd43dd8448eb211c80319c-[0-9a-f]{16}-/,
          );
          // Trigger finish; should not throw.
          res._listeners.finish?.forEach((fn) => fn());
          // Calling finish twice is idempotent.
          res._listeners.finish?.forEach((fn) => fn());
          done();
        } catch (err) {
          done(err);
        }
      });
    });

    it('still invokes next() when there is no inbound traceparent', (done) => {
      const mw = tracingMiddleware('test-svc');
      const req = makeReq();
      const res = makeRes();
      mw(req as never, res as never, () => {
        // Without an SDK and no inbound trace, the active span is the
        // non-recording one started by the middleware. It must still
        // invoke next without throwing.
        res._listeners.close?.forEach((fn) => fn());
        done();
      });
    });
  });

  // -------------------------------------------------------------------
  // Audit logger integration (R-3): the audit logger must stamp
  // trace_id/span_id from the active OTel span context onto every
  // record without callers having to thread the IDs through manually.
  // -------------------------------------------------------------------

  describe('audit logger trace-context enrichment', () => {
    /**
     * In-memory winston transport that captures every log entry so the
     * test can inspect the structured record after a `.info()` call.
     */
    class CaptureTransport extends Transport {
      public records: Array<Record<string, unknown>> = [];
      log(info: Record<string, unknown>, callback: () => void): void {
        this.records.push(info);
        callback();
      }
    }

    beforeEach(() => {
      _resetAuditChainStateForTesting();
    });

    it('stamps trace_id / span_id on every record when a span is active', async () => {
      const audit = createAuditLogger('audit-test');
      const capture = new CaptureTransport();
      audit.add(capture);

      const ctx = extractTraceContext({
        traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      });
      const remoteSpan = trace.getSpan(ctx)!;
      await context.with(trace.setSpan(context.active(), remoteSpan), async () => {
        audit.info('Action allowed', { agentId: 'a1', decision: 'allow' });
      });

      // Winston's transport pipeline is synchronous for the in-memory
      // test transport, but allow a tick for safety.
      await new Promise((resolve) => setImmediate(resolve));

      expect(capture.records).toHaveLength(1);
      const rec = capture.records[0]!;
      expect(rec.trace_id).toBe('0af7651916cd43dd8448eb211c80319c');
      expect(rec.span_id).toBe('b7ad6b7169203331');
      expect(rec.trace_flags).toBe(1);
      // The hash chain still wraps the record.
      expect(rec.auditChain).toMatchObject({
        seq: 1,
        prevHash: 'GENESIS',
      });
      expect(typeof (rec.auditChain as { hash: string }).hash).toBe('string');
    });

    it('omits trace fields when no span is active (no SDK / no request)', async () => {
      const audit = createAuditLogger('audit-test-no-span');
      const capture = new CaptureTransport();
      audit.add(capture);

      audit.info('Action allowed', { agentId: 'a2', decision: 'allow' });
      await new Promise((resolve) => setImmediate(resolve));

      const rec = capture.records[0]!;
      expect(rec.trace_id).toBeUndefined();
      expect(rec.span_id).toBeUndefined();
      expect(rec.trace_flags).toBeUndefined();
    });
  });
});

/**
 * Tests for types.ts — CapabilityDenialError and newCorrelationId.
 */

import { CapabilityDenialError, newCorrelationId } from '../types';

// ---------------------------------------------------------------------------
// CapabilityDenialError
// ---------------------------------------------------------------------------

describe('CapabilityDenialError', () => {
  describe('construction', () => {
    it('sets the Error name to CapabilityDenialError', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.name).toBe('CapabilityDenialError');
    });

    it('inherits from Error', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(CapabilityDenialError);
    });

    it('sets message correctly', () => {
      const err = new CapabilityDenialError({
        message: 'Max calls exceeded',
        statusCode: 429,
        errorCode: 'MAX_CALLS_EXCEEDED',
        tool: 'send_email',
      });
      expect(err.message).toBe('Max calls exceeded');
    });

    it('sets statusCode correctly', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 429,
        errorCode: 'MAX_CALLS_EXCEEDED',
        tool: 'query_db',
      });
      expect(err.statusCode).toBe(429);
    });

    it('sets errorCode correctly', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'IP_RANGE_DENIED',
        tool: 'query_db',
      });
      expect(err.errorCode).toBe('IP_RANGE_DENIED');
    });

    it('sets tool correctly', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'send_email',
      });
      expect(err.tool).toBe('send_email');
    });

    it('sets resource when provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
        resource: 'mcp-tool://query_db',
      });
      expect(err.resource).toBe('mcp-tool://query_db');
    });

    it('leaves resource undefined when not provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.resource).toBeUndefined();
    });

    it('sets correlationId when provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
        correlationId: 'abc-123',
      });
      expect(err.correlationId).toBe('abc-123');
    });

    it('leaves correlationId undefined when not provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.correlationId).toBeUndefined();
    });

    it('sets details when provided', () => {
      const details = { path: 'args.email', expected: 'email', got: 'not-an-email' };
      const err = new CapabilityDenialError({
        message: 'Argument validation failed',
        statusCode: 422,
        errorCode: 'ARGUMENT_VALIDATION_FAILED',
        tool: 'send_email',
        details,
      });
      expect(err.details).toEqual(details);
    });

    it('leaves details undefined when not provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.details).toBeUndefined();
    });

    it('sets conditionType when provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 429,
        errorCode: 'MAX_CALLS_EXCEEDED',
        tool: 'query_db',
        conditionType: 'maxCalls',
      });
      expect(err.conditionType).toBe('maxCalls');
    });

    it('leaves conditionType undefined when not provided', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.conditionType).toBeUndefined();
    });

    it('all fields set together', () => {
      const details = { path: 'args.sql', expected: 'SELECT …', got: 'DROP TABLE' };
      const err = new CapabilityDenialError({
        message: 'SQL operation not allowed',
        statusCode: 403,
        errorCode: 'OPERATION_NOT_ALLOWED',
        tool: 'query_db',
        resource: 'mcp-tool://query_db',
        correlationId: 'corr-456',
        details,
        conditionType: 'allowedOperations',
      });
      expect(err.message).toBe('SQL operation not allowed');
      expect(err.statusCode).toBe(403);
      expect(err.errorCode).toBe('OPERATION_NOT_ALLOWED');
      expect(err.tool).toBe('query_db');
      expect(err.resource).toBe('mcp-tool://query_db');
      expect(err.correlationId).toBe('corr-456');
      expect(err.details).toEqual(details);
      expect(err.conditionType).toBe('allowedOperations');
    });

    it('stack trace is populated', () => {
      const err = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err.stack).toBeDefined();
      expect(typeof err.stack).toBe('string');
    });

    it('can be caught as an Error', () => {
      const thrown = () => {
        throw new CapabilityDenialError({
          message: 'denied',
          statusCode: 403,
          errorCode: 'CAPABILITY_DENIED',
          tool: 'query_db',
        });
      };
      expect(thrown).toThrow(Error);
      expect(thrown).toThrow(CapabilityDenialError);
    });

    it('instanceof check survives cross-realm comparison pattern', () => {
      const err: unknown = new CapabilityDenialError({
        message: 'denied',
        statusCode: 403,
        errorCode: 'CAPABILITY_DENIED',
        tool: 'query_db',
      });
      expect(err instanceof CapabilityDenialError).toBe(true);
    });
  });

  describe('status code semantics', () => {
    it('supports 429 for rate-limit denials', () => {
      const err = new CapabilityDenialError({
        message: 'Rate limit exceeded',
        statusCode: 429,
        errorCode: 'MAX_CALLS_EXCEEDED',
        tool: 'query_db',
      });
      expect(err.statusCode).toBe(429);
    });

    it('supports 422 for argument schema failures', () => {
      const err = new CapabilityDenialError({
        message: 'Argument validation failed',
        statusCode: 422,
        errorCode: 'ARGUMENT_VALIDATION_FAILED',
        tool: 'send_email',
      });
      expect(err.statusCode).toBe(422);
    });

    it('supports 503 for kill-switch denials', () => {
      const err = new CapabilityDenialError({
        message: 'Runtime terminated',
        statusCode: 503,
        errorCode: 'KILL_SWITCH',
        tool: 'query_db',
      });
      expect(err.statusCode).toBe(503);
    });
  });
});

// ---------------------------------------------------------------------------
// newCorrelationId
// ---------------------------------------------------------------------------

describe('newCorrelationId', () => {
  it('returns a string', () => {
    const id = newCorrelationId();
    expect(typeof id).toBe('string');
  });

  it('returns a non-empty string', () => {
    const id = newCorrelationId();
    expect(id.length).toBeGreaterThan(0);
  });

  it('returns a UUID v4 shaped string (8-4-4-4-12 segments)', () => {
    const id = newCorrelationId();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it('returns unique values on successive calls', () => {
    const ids = new Set(Array.from({ length: 100 }, () => newCorrelationId()));
    expect(ids.size).toBe(100);
  });

  it('is callable multiple times without error', () => {
    expect(() => {
      for (let i = 0; i < 20; i++) {
        newCorrelationId();
      }
    }).not.toThrow();
  });
});

/**
 * Unit tests for {@link applyRemoteObligations}.
 *
 * Verifies that the remote-obligations path (used by RemoteEnforcerPDP)
 * correctly strips dotted-path fields from JSON text content and
 * structuredContent, and that annotate obligations are pass-through
 * (do not modify the upstream result).
 */

import { applyRemoteObligations } from '../transport/obligations';
import type { ToolCallResult } from '../transport/obligations';
import type { Obligation } from '@euno/common-core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeJsonResult(obj: unknown): ToolCallResult {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }] };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('applyRemoteObligations – no-op cases', () => {
  it('returns the original object when obligations array is empty', () => {
    const result = makeJsonResult({ key: 'value' });
    expect(applyRemoteObligations(result, [])).toBe(result);
  });

  it('returns the original object when only annotate obligations are present', () => {
    const obligations: Obligation[] = [
      { type: 'annotate', key: 'classification', value: 'internal' },
    ];
    const result = makeJsonResult({ key: 'value' });
    expect(applyRemoteObligations(result, obligations)).toBe(result);
  });

  it('returns the original object when no fields match the redact path', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['nonExistentField'] },
    ];
    const result = makeJsonResult({ key: 'value' });
    expect(applyRemoteObligations(result, obligations)).toBe(result);
  });
});

describe('applyRemoteObligations – redactFields obligation', () => {
  it('redacts a top-level field from JSON text content', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['password'] },
    ];
    const result = makeJsonResult({ username: 'alice', password: 'secret' });

    const out = applyRemoteObligations(result, obligations);

    const parsed = JSON.parse(out.content[0]!.text!);
    expect(parsed.username).toBe('alice');
    expect(Object.prototype.hasOwnProperty.call(parsed, 'password')).toBe(false);
  });

  it('redacts multiple fields listed in one obligation', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['password', 'token'] },
    ];
    const result = makeJsonResult({ user: 'alice', password: 'secret', token: 'abc123', id: 1 });

    const out = applyRemoteObligations(result, obligations);

    const item = out.content[0]!;
    const parsed = JSON.parse(item.text!);
    expect(parsed.user).toBe('alice');
    expect(parsed.id).toBe(1);
    expect(Object.prototype.hasOwnProperty.call(parsed, 'password')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(parsed, 'token')).toBe(false);
  });

  it('merges paths from multiple redactFields obligations', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['password'] },
      { type: 'redactFields', paths: ['secret'] },
    ];
    const result = makeJsonResult({ user: 'alice', password: 'p', secret: 's' });

    const out = applyRemoteObligations(result, obligations);

    const item = out.content[0]!;
    const parsed = JSON.parse(item.text!);
    expect(parsed.user).toBe('alice');
    expect(Object.prototype.hasOwnProperty.call(parsed, 'password')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(parsed, 'secret')).toBe(false);
  });

  it('leaves non-JSON text content unchanged', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['secret'] },
    ];
    const result: ToolCallResult = {
      content: [{ type: 'text', text: 'plain text, not JSON' }],
    };

    const out = applyRemoteObligations(result, obligations);

    expect(out.content[0]?.text).toBe('plain text, not JSON');
  });

  it('applies redaction to structuredContent when present', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['secret'] },
    ];
    const result: ToolCallResult = {
      content: [],
      structuredContent: { user: 'alice', secret: 'top-secret' },
    };

    const out = applyRemoteObligations(result, obligations);

    expect((out.structuredContent as Record<string, unknown>).user).toBe('alice');
    expect(Object.prototype.hasOwnProperty.call(out.structuredContent, 'secret')).toBe(false);
  });

  it('returns original result when structuredContent is not present in the object', () => {
    // No structuredContent key on the result at all
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['nonExistent'] },
    ];
    const result: ToolCallResult = {
      content: [{ type: 'text', text: JSON.stringify({ a: 1 }) }],
    };
    // No field matches → same object returned
    expect(applyRemoteObligations(result, obligations)).toBe(result);
  });
});

describe('applyRemoteObligations – combined obligations', () => {
  it('applies redactFields and ignores annotate in the same list', () => {
    const obligations: Obligation[] = [
      { type: 'annotate', key: 'audit', value: 'sensitive' },
      { type: 'redactFields', paths: ['password'] },
    ];
    const result = makeJsonResult({ user: 'alice', password: 'secret' });

    const out = applyRemoteObligations(result, obligations);

    const parsed = JSON.parse(out.content[0]!.text!);
    expect(parsed.user).toBe('alice');
    expect(Object.prototype.hasOwnProperty.call(parsed, 'password')).toBe(false);
  });
});

describe('applyRemoteObligations – identity / reference semantics', () => {
  it('returns the original result reference when nothing changes', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['fieldThatDoesNotExist'] },
    ];
    const result = makeJsonResult({ user: 'alice' });
    expect(applyRemoteObligations(result, obligations)).toBe(result);
  });

  it('returns a new result object (not the same reference) when a field is redacted', () => {
    const obligations: Obligation[] = [
      { type: 'redactFields', paths: ['password'] },
    ];
    const result = makeJsonResult({ user: 'alice', password: 'secret' });
    expect(applyRemoteObligations(result, obligations)).not.toBe(result);
  });
});

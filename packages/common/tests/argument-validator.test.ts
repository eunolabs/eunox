/**
 * Tests for the allowlist-based argument validator that powers first-class
 * argument-level enforcement in the tool gateway.
 */

import { validateArguments, CapabilityError, ArgumentSchema } from '../src';

describe('validateArguments', () => {
  it('is a no-op when no schema is supplied', () => {
    expect(() => validateArguments({ foo: 'bar' }, undefined)).not.toThrow();
    expect(() => validateArguments(null, null)).not.toThrow();
  });

  describe('object allowlist semantics', () => {
    const schema: ArgumentSchema = {
      type: 'object',
      properties: {
        customerId: { type: 'string', pattern: '[a-zA-Z0-9-]+', maxLength: 64 },
        fields: { type: 'array', items: { type: 'string' }, maxItems: 10 },
      },
      required: ['customerId'],
    };

    it('accepts conforming objects', () => {
      expect(() =>
        validateArguments({ customerId: 'abc-123', fields: ['name', 'email'] }, schema)
      ).not.toThrow();
    });

    it('rejects unknown properties by default', () => {
      expect(() =>
        validateArguments({ customerId: 'abc-123', body: { hidden: true } }, schema)
      ).toThrow(CapabilityError);
      expect(() =>
        validateArguments({ customerId: 'abc-123', body: { hidden: true } }, schema)
      ).toThrow(/disallowed property "body"/);
    });

    it('rejects missing required properties', () => {
      expect(() => validateArguments({ fields: ['name'] }, schema)).toThrow(
        /missing required property "customerId"/
      );
    });

    it('permits unknown properties when additionalProperties is true', () => {
      const permissive: ArgumentSchema = { ...schema, additionalProperties: true };
      expect(() =>
        validateArguments({ customerId: 'abc-123', extra: 'ok' }, permissive)
      ).not.toThrow();
    });
  });

  describe('string constraints', () => {
    it('enforces minLength / maxLength', () => {
      expect(() => validateArguments('a', { type: 'string', minLength: 2 })).toThrow(
        CapabilityError
      );
      expect(() => validateArguments('aaaa', { type: 'string', maxLength: 3 })).toThrow(
        CapabilityError
      );
    });

    it('anchors pattern to the whole value', () => {
      const schema: ArgumentSchema = { type: 'string', pattern: '[a-z]+' };
      expect(() => validateArguments('abc', schema)).not.toThrow();
      // A bare alphabetic pattern must not match a value with extras.
      expect(() => validateArguments('abc; rm -rf /', schema)).toThrow(CapabilityError);
    });

    it('rejects null bytes in strings', () => {
      expect(() => validateArguments('foo\0bar', { type: 'string' })).toThrow(
        /null byte/
      );
    });
  });

  describe('numeric constraints', () => {
    it('enforces minimum / maximum', () => {
      expect(() => validateArguments(5, { type: 'number', minimum: 10 })).toThrow(
        CapabilityError
      );
      expect(() => validateArguments(15, { type: 'number', maximum: 10 })).toThrow(
        CapabilityError
      );
    });

    it('distinguishes integer from number', () => {
      expect(() => validateArguments(1.5, { type: 'integer' })).toThrow(CapabilityError);
      expect(() => validateArguments(2, { type: 'integer' })).not.toThrow();
    });

    it('rejects non-finite numbers under type=number', () => {
      expect(() => validateArguments(NaN, { type: 'number' })).toThrow(CapabilityError);
      expect(() => validateArguments(Infinity, { type: 'number' })).toThrow(
        CapabilityError
      );
    });
  });

  describe('array constraints', () => {
    it('validates each item against items schema', () => {
      const schema: ArgumentSchema = {
        type: 'array',
        items: { type: 'string', maxLength: 3 },
      };
      expect(() => validateArguments(['ok', 'no'], schema)).not.toThrow();
      expect(() => validateArguments(['ok', 'toolong'], schema)).toThrow(
        /args\[1\] must be at most 3/
      );
    });

    it('enforces maxItems', () => {
      expect(() =>
        validateArguments([1, 2, 3, 4], { type: 'array', maxItems: 3 })
      ).toThrow(CapabilityError);
    });
  });

  describe('enum constraints', () => {
    it('accepts only listed values', () => {
      const schema: ArgumentSchema = { enum: ['read', 'write'] };
      expect(() => validateArguments('read', schema)).not.toThrow();
      expect(() => validateArguments('admin', schema)).toThrow(CapabilityError);
    });

    it('supports object enum values via deep equality', () => {
      const schema: ArgumentSchema = { enum: [{ scope: 'self' }, { scope: 'team' }] };
      expect(() => validateArguments({ scope: 'team' }, schema)).not.toThrow();
      expect(() => validateArguments({ scope: 'org' }, schema)).toThrow(CapabilityError);
    });
  });

  it('produces a path in error messages for nested failures', () => {
    const schema: ArgumentSchema = {
      type: 'object',
      properties: {
        body: {
          type: 'object',
          properties: {
            email: { type: 'string', pattern: '[^@]+@[^@]+' },
          },
          required: ['email'],
        },
      },
      required: ['body'],
    };

    expect(() =>
      validateArguments({ body: { email: 'not-an-email' } }, schema)
    ).toThrow(/args\.body\.email/);
  });

  it('rejects schema-declared types it does not understand', () => {
    expect(() =>
      validateArguments('x', { type: 'bogus' as unknown as 'string' })
    ).toThrow(/unsupported type/);
  });

  describe('ReDoS guard on caller-supplied patterns', () => {
    // `argumentSchema` may originate from untrusted clients via
    // /attenuate, so pathological regexes must not be able to lock up
    // the gateway. The validator rejects known catastrophic-backtracking
    // shapes and overly long patterns before compiling.
    it('rejects nested-quantifier patterns', () => {
      expect(() =>
        validateArguments('aaaaaaaaaaaaaaaaaaaa!', {
          type: 'string',
          pattern: '(a+)+',
        })
      ).toThrow(/unsafe/);
    });

    it('rejects (a*)* style patterns', () => {
      expect(() =>
        validateArguments('aaaaa', {
          type: 'string',
          pattern: '(a*)*',
        })
      ).toThrow(/unsafe/);
    });

    it('rejects quantified alternation of identical branches', () => {
      expect(() =>
        validateArguments('aaaa', {
          type: 'string',
          pattern: '(a|a)*',
        })
      ).toThrow(/unsafe/);
    });

    it('rejects overly long patterns', () => {
      const longPattern = 'a'.repeat(1024);
      expect(() =>
        validateArguments('a', { type: 'string', pattern: longPattern })
      ).toThrow(/maximum length/);
    });

    it('still accepts ordinary patterns', () => {
      expect(() =>
        validateArguments('abc-123', {
          type: 'string',
          pattern: '[a-zA-Z0-9-]+',
        })
      ).not.toThrow();
    });
  });

  describe('deepEqual key-presence in enum matching', () => {
    // A property present with value `undefined` must not be treated as
    // equal to a missing property — important for object-valued enums
    // used as enforcement primitives.
    it('distinguishes missing key from key with undefined value', () => {
      const schema: ArgumentSchema = { enum: [{ scope: 'self' }] };
      // Missing `scope` is not equal to `{ scope: 'self' }`.
      expect(() => validateArguments({}, schema)).toThrow(CapabilityError);
      // Extra key is also not equal.
      expect(() =>
        validateArguments({ scope: 'self', extra: 1 }, schema)
      ).toThrow(CapabilityError);
    });
  });
});

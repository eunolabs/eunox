/**
 * Allowlist-based argument validator for capability tokens.
 *
 * This module powers the *first-class* argument-level enforcement performed
 * by the tool gateway. Capabilities can declare an {@link ArgumentSchema}
 * describing the exact shape of arguments / request bodies they authorize.
 * The enforcement engine calls {@link validateArguments} after the
 * (action, resource) check; any non-conforming call is rejected and audited.
 *
 * Design notes:
 *  - The validator is **allowlist-based**. For object schemas,
 *    `additionalProperties` defaults to `false`: unknown keys are rejected.
 *  - String validation supports `pattern`, `minLength`, `maxLength`, and
 *    `enum`. There is intentionally **no built-in denylist of "dangerous"
 *    keywords** — those are an anti-pattern that creates false confidence
 *    while missing real attacks. Callers express what they *do* allow.
 *  - This is one layer of defense. Backends MUST still use parameterized
 *    queries, safe APIs, and per-tenant isolation. The schema constrains
 *    what an agent can *send*, not what the backend will *do* with it.
 */

import { ArgumentSchema } from './types';
import { CapabilityError, ErrorCode } from './utils';

/**
 * Sentinel returned alongside an error message by individual checks.
 * `null` means "valid"; a string is the human-readable failure reason.
 */
type ValidationResult = string | null;

const PRIMITIVE_TYPES = new Set([
  'object',
  'string',
  'number',
  'integer',
  'boolean',
  'array',
  'null',
]);

/**
 * Validate `value` against the supplied {@link ArgumentSchema}.
 * Throws a {@link CapabilityError} (HTTP 400, INVALID_REQUEST) on failure.
 *
 * If `schema` is undefined or null, this is a no-op — capabilities without
 * an `argumentSchema` impose no argument-level constraints (the (action,
 * resource) check is the sole gate, matching the previous behaviour).
 *
 * @param value  The arguments / body to validate. May be any JSON-compatible
 *               value (object, primitive, array, null).
 * @param schema The schema declared by the matched capability constraint.
 * @param path   Internal: dotted path used to produce readable error
 *               messages (e.g. `args.body.email`). Callers should leave
 *               this at its default.
 */
export function validateArguments(
  value: unknown,
  schema: ArgumentSchema | undefined | null,
  path: string = 'args'
): void {
  if (!schema) {
    return;
  }

  const reason = checkAgainstSchema(value, schema, path);
  if (reason !== null) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Argument validation failed: ${reason}`,
      400
    );
  }
}

function checkAgainstSchema(
  value: unknown,
  schema: ArgumentSchema,
  path: string
): ValidationResult {
  // 1. enum (exact-match allowlist). Checked first because enum is the
  //    strictest possible constraint.
  if (schema.enum !== undefined) {
    const matched = schema.enum.some((allowed) => deepEqual(allowed, value));
    if (!matched) {
      return `${path} must be one of the allowed values`;
    }
  }

  // 2. type
  if (schema.type !== undefined) {
    const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    for (const t of allowedTypes) {
      if (!PRIMITIVE_TYPES.has(t)) {
        return `${path} schema declares unsupported type "${t}"`;
      }
    }
    if (!allowedTypes.some((t) => matchesType(value, t))) {
      return `${path} must be of type ${allowedTypes.join('|')}`;
    }
  }

  // 3. type-specific checks
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      return `${path} must be at least ${schema.minLength} characters`;
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      return `${path} must be at most ${schema.maxLength} characters`;
    }
    if (schema.pattern !== undefined) {
      // Anchor the pattern so callers' regex expresses a *whole-value*
      // allowlist and cannot accidentally match a substring.
      let re: RegExp;
      try {
        re = new RegExp(`^(?:${schema.pattern})$`);
      } catch {
        return `${path} schema has an invalid pattern`;
      }
      if (!re.test(value)) {
        return `${path} does not match the allowed pattern`;
      }
    }
    // Reject embedded null bytes universally — they are never legitimate in
    // tool arguments and frequently used for parser-confusion attacks.
    if (value.includes('\0')) {
      return `${path} contains a null byte`;
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return `${path} must be >= ${schema.minimum}`;
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return `${path} must be <= ${schema.maximum}`;
    }
  }

  if (Array.isArray(value)) {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return `${path} must contain at most ${schema.maxItems} items`;
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      return `${path} must contain at least ${schema.minItems} items`;
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        const reason = checkAgainstSchema(value[i], schema.items, `${path}[${i}]`);
        if (reason !== null) {
          return reason;
        }
      }
    }
  }

  if (isPlainObject(value)) {
    // Only enforce object-shape constraints when the schema actually
    // declares them. A schema like `{ enum: [...] }` (no `type`, no
    // `properties`) is a value-equality constraint, not a shape
    // constraint, and should not impose `additionalProperties: false`
    // on every property of the matched value.
    const declaresObjectShape =
      schema.properties !== undefined ||
      schema.required !== undefined ||
      schema.additionalProperties !== undefined ||
      includesType(schema.type, 'object');

    if (declaresObjectShape) {
      const properties = schema.properties ?? {};
      const required = schema.required ?? [];
      // Default to strict allowlist semantics. This is the whole point of
      // declaring an argumentSchema on a capability.
      const additionalProperties = schema.additionalProperties ?? false;

      for (const requiredKey of required) {
        if (!Object.prototype.hasOwnProperty.call(value, requiredKey)) {
          return `${path} is missing required property "${requiredKey}"`;
        }
      }

      for (const key of Object.keys(value)) {
        const propSchema = properties[key];
        if (propSchema === undefined) {
          if (!additionalProperties) {
            return `${path} contains disallowed property "${key}"`;
          }
          continue;
        }
        const reason = checkAgainstSchema(
          (value as Record<string, unknown>)[key],
          propSchema,
          `${path}.${key}`
        );
        if (reason !== null) {
          return reason;
        }
      }
    }
  }

  return null;
}

function includesType(
  declared: ArgumentSchema['type'] | undefined,
  needle: string
): boolean {
  if (declared === undefined) return false;
  if (Array.isArray(declared)) return declared.includes(needle as never);
  return declared === needle;
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case 'object':
      return isPlainObject(value);
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'array':
      return Array.isArray(value);
    case 'null':
      return value === null;
    default:
      return false;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value)
  );
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every((k) => deepEqual(a[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

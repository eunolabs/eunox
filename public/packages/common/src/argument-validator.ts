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

// ---------------------------------------------------------------------------
// Structured validation result
// ---------------------------------------------------------------------------

/**
 * Structured failure descriptor returned by {@link checkAgainstSchema} when
 * validation fails.  `null` means the value is valid.
 *
 * The three data fields – {@link path}, {@link expected}, {@link got} – are
 * intentionally machine-readable so consumers such as the MCP proxy can
 * forward them to clients as structured JSON without parsing the message
 * string.
 */
type ValidationResult = {
  /**
   * Human-readable message describing the failure.  Always includes `path`
   * so the text is still useful when the structured fields are not read.
   */
  reason: string;
  /**
   * Dotted JSON path to the value that failed validation
   * (e.g. `"args"`, `"args.body.email"`, `"args.tags[0]"`).
   */
  path: string;
  /**
   * Human-readable description of the constraint that was violated
   * (e.g. `"type:string"`, `">= 5 characters"`, `"one of [\"a\",\"b\"]"`).
   */
  expected: string;
  /**
   * The actual value (or a descriptor of it) that caused the failure.
   * For type mismatches this is the type name string; for value-level checks
   * it is the offending value itself.
   */
  got: unknown;
} | null;

// ---------------------------------------------------------------------------
// ArgumentValidationError
// ---------------------------------------------------------------------------

/**
 * Thrown by {@link validateArguments} when the supplied arguments do not
 * conform to the declared {@link ArgumentSchema}.
 *
 * Extends {@link CapabilityError} so existing catch-sites that check
 * `instanceof CapabilityError` continue to work unchanged, while new
 * consumers can distinguish this error and read the structured fields
 * ({@link path}, {@link expected}, {@link got}) to produce machine-readable
 * error responses.
 *
 * The `message` property keeps the same human-readable format as before
 * (`"Argument validation failed: <reason>"`), preserving backwards
 * compatibility for callers that only inspect `err.message`.
 *
 * @example
 * ```ts
 * try {
 *   validateArguments(args, schema);
 * } catch (err) {
 *   if (err instanceof ArgumentValidationError) {
 *     // structured fields available
 *     console.log(err.path, err.expected, err.got);
 *   }
 *   // err.message is always human-readable
 *   console.error(err.message);
 * }
 * ```
 */
export class ArgumentValidationError extends CapabilityError {
  /** Dotted JSON path to the value that failed validation. */
  public readonly path: string;
  /** Human-readable description of the constraint that was violated. */
  public readonly expected: string;
  /** The actual value (or type descriptor) that caused the failure. */
  public readonly got: unknown;

  constructor(path: string, expected: string, got: unknown, reason: string) {
    super(
      ErrorCode.INVALID_REQUEST,
      `Argument validation failed: ${reason}`,
      400,
    );
    this.name = 'ArgumentValidationError';
    this.path = path;
    this.expected = expected;
    this.got = got;
  }
}

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
 * Maximum permitted source length for a caller-supplied `pattern`. This is
 * a coarse but effective ReDoS guard for `argumentSchema` values that
 * may originate from untrusted clients via /attenuate.
 */
const MAX_PATTERN_LENGTH = 512;

/**
 * Validate `value` against the supplied {@link ArgumentSchema}.
 *
 * Throws an {@link ArgumentValidationError} (which is also a
 * {@link CapabilityError} with HTTP 400) on failure.
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

  const failure = checkAgainstSchema(value, schema, path, schema.strict ?? false);
  if (failure !== null) {
    throw new ArgumentValidationError(
      failure.path,
      failure.expected,
      failure.got,
      failure.reason,
    );
  }
}

function checkAgainstSchema(
  value: unknown,
  schema: ArgumentSchema,
  path: string,
  strict: boolean
): ValidationResult {
  // Inherit strict flag from the schema if it explicitly sets it, otherwise use the parent's
  const effectiveStrict = schema.strict ?? strict;
  // 1. enum (exact-match allowlist). Checked first because enum is the
  //    strictest possible constraint.
  if (schema.enum !== undefined) {
    const matched = schema.enum.some((allowed) => deepEqual(allowed, value));
    if (!matched) {
      const expectedList = schema.enum.map((v) => JSON.stringify(v)).join(', ');
      return fail(path, `one of [${expectedList}]`, safeGot(value), `${path} must be one of the allowed values`);
    }
  }

  // 2. type
  if (schema.type !== undefined) {
    const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    for (const t of allowedTypes) {
      if (!PRIMITIVE_TYPES.has(t)) {
        return fail(path, 'supported type (object|string|number|integer|boolean|array|null)', t, `${path} schema declares unsupported type "${t}"`);
      }
    }
    if (!allowedTypes.some((t) => matchesType(value, t))) {
      return fail(path, `type:${allowedTypes.join('|')}`, typeDescriptorOf(value), `${path} must be of type ${allowedTypes.join('|')}`);
    }
  }

  // 3. type-specific checks
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      return fail(path, `string with length >= ${schema.minLength}`, value.length, `${path} must be at least ${schema.minLength} characters`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      return fail(path, `string with length <= ${schema.maxLength}`, value.length, `${path} must be at most ${schema.maxLength} characters`);
    }
    if (schema.pattern !== undefined) {
      // Anchor the pattern so callers' regex expresses a *whole-value*
      // allowlist and cannot accidentally match a substring.
      //
      // `argumentSchema` can be supplied by clients via /attenuate (and
      // via requested capabilities), so the pattern source is an
      // attacker-controllable surface. We mitigate ReDoS in two ways:
      //   1) reject overly long patterns outright;
      //   2) reject patterns whose structure indicates known catastrophic
      //      backtracking (nested quantifiers, e.g. `(a+)+`, `(a*)*`,
      //      `(a|a)*`). This is a heuristic, not a proof of safety, but
      //      it stops the textbook ReDoS shapes from being smuggled in.
      // For belt-and-braces, callers can additionally bound `maxLength`
      // on the same string field to cap the input the regex sees.
      if (schema.pattern.length > MAX_PATTERN_LENGTH) {
        return fail(path, `pattern with length <= ${MAX_PATTERN_LENGTH}`, schema.pattern.length, `${path} schema pattern exceeds maximum length of ${MAX_PATTERN_LENGTH}`);
      }
      if (hasCatastrophicBacktrackingShape(schema.pattern)) {
        return fail(path, 'safe regex pattern (no nested quantifiers)', schema.pattern, `${path} schema pattern is rejected as potentially unsafe (nested quantifiers)`);
      }
      let re: RegExp;
      try {
        re = new RegExp(`^(?:${schema.pattern})$`);
      } catch {
        return fail(path, 'valid regex pattern', schema.pattern, `${path} schema has an invalid pattern`);
      }
      if (!re.test(value)) {
        return fail(path, `string matching /${schema.pattern}/`, safeGot(value), `${path} does not match the allowed pattern`);
      }
    }
    // Reject embedded null bytes universally — they are never legitimate in
    // tool arguments and frequently used for parser-confusion attacks.
    if (value.includes('\0')) {
      return fail(path, 'string without null bytes', safeGot(value), `${path} contains a null byte`);
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return fail(path, `number >= ${schema.minimum}`, value, `${path} must be >= ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return fail(path, `number <= ${schema.maximum}`, value, `${path} must be <= ${schema.maximum}`);
    }
  }

  if (Array.isArray(value)) {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return fail(path, `array with at most ${schema.maxItems} items`, value.length, `${path} must contain at most ${schema.maxItems} items`);
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      return fail(path, `array with at least ${schema.minItems} items`, value.length, `${path} must contain at least ${schema.minItems} items`);
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        const nested = checkAgainstSchema(value[i], schema.items, `${path}[${i}]`, effectiveStrict);
        if (nested !== null) {
          return nested;
        }
      }
    }
  }

  if (isPlainObject(value)) {
    // Enforce object-shape constraints when:
    //  - the schema explicitly declares them (properties/required/additionalProperties/type:object), OR
    //  - strict mode is active (treat every plain-object value as if it declares its shape)
    const declaresObjectShape =
      effectiveStrict ||
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
          return fail(
            `${path}.${requiredKey}`,
            'present',
            'absent',
            `${path}.${requiredKey} is missing (required)`,
          );
        }
      }

      for (const key of Object.keys(value)) {
        const propSchema = properties[key];
        if (propSchema === undefined) {
          if (!additionalProperties) {
            return fail(`${path}.${key}`, 'absent', 'present', `${path} contains disallowed property "${key}"`);
          }
          continue;
        }
        const nested = checkAgainstSchema(
          (value as Record<string, unknown>)[key],
          propSchema,
          `${path}.${key}`,
          effectiveStrict
        );
        if (nested !== null) {
          return nested;
        }
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a non-null {@link ValidationResult} — a shorthand to avoid repeating
 * the full object shape at every failure site in {@link checkAgainstSchema}.
 */
function fail(path: string, expected: string, got: unknown, reason: string): ValidationResult {
  return { path, expected, got, reason };
}

/**
 * Maximum number of characters to include verbatim from a string value in the
 * `got` field.  Strings longer than this are truncated and suffixed with `…`
 * to prevent large tool arguments from being written to the audit log.
 */
const GOT_STRING_MAX_LEN = 120;

/**
 * Produce a safe, bounded representation of `value` for the `got` field.
 *
 * - Primitives (number, boolean, null) are returned as-is — they are always
 *   compact.
 * - Strings are truncated to {@link GOT_STRING_MAX_LEN} characters to prevent
 *   large or sensitive argument values from being forwarded to clients or
 *   persisted in the audit log.
 * - Arrays are represented by their length descriptor (e.g. `"array(4)"`)
 *   rather than being serialised in full.
 * - Objects are represented by their key count descriptor (e.g. `"object{3}"`).
 *
 * This is intentionally lossy — the purpose of `got` is to give a developer a
 * quick hint for debugging, not to reproduce the full input.
 */
function safeGot(value: unknown): unknown {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    return value.length <= GOT_STRING_MAX_LEN
      ? value
      : `${value.slice(0, GOT_STRING_MAX_LEN)}…`;
  }
  if (Array.isArray(value)) {
    return `array(${value.length})`;
  }
  if (typeof value === 'object') {
    return `object{${Object.keys(value as object).length}}`;
  }
  return typeof value;
}

/**
 * Return a compact, human-readable type descriptor for `value`.
 *
 * Used in the `got` field of type-mismatch failures so MCP clients see
 * a concise label rather than the raw value (which could be an arbitrarily
 * large object).
 */
function typeDescriptorOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
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
    // Verify each key from `a` exists on `b` as an own property before
    // recursing — otherwise a missing key on one side would be treated
    // as equal to `undefined` on the other, which is unsafe for an
    // enforcement primitive.
    return aKeys.every(
      (k) =>
        Object.prototype.hasOwnProperty.call(b, k) &&
        deepEqual(a[k], (b as Record<string, unknown>)[k])
    );
  }
  return false;
}

/**
 * Heuristically reject regex shapes that are known to trigger catastrophic
 * backtracking. This is intentionally conservative — it covers the
 * textbook ReDoS shapes (`(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`, and
 * alternation of identical branches under a quantifier such as
 * `(a|a)*`) and *does not* claim to be a complete safe-regex check.
 * Production deployments that need stronger guarantees should evaluate
 * untrusted patterns with a linear-time engine such as RE2.
 */
function hasCatastrophicBacktrackingShape(pattern: string): boolean {
  // Nested quantifier on a parenthesised group, e.g. (a+)+, (a*)*, (a+)*.
  if (/\([^)]*[+*][^)]*\)\s*[+*?]/.test(pattern)) {
    return true;
  }
  // Quantified alternation of identical single-token branches, e.g. (a|a)*.
  if (/\(\s*([^|()]{1,8})\s*\|\s*\1\s*\)\s*[+*]/.test(pattern)) {
    return true;
  }
  return false;
}

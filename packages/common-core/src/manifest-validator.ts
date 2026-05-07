/**
 * Runtime validation of {@link AgentCapabilityManifest} using Zod.
 *
 * This module is the single source of truth for manifest validation, shared
 * by the `euno-mcp` local policy loader, the `euno validate` CLI (wired via
 * `@euno/common`), and the production issuer at mint time.  Sharing the schema
 * means that a manifest which passes `euno-mcp validate` will also be
 * accepted by the issuer and vice-versa.
 *
 * Design notes
 * ------------
 * - All objects use `.strict()` so that unknown keys are rejected at parse
 *   time.  This catches typos in condition type names early (e.g. `maxcalls`
 *   instead of `maxCalls`) before they silently produce a token that never
 *   enforces the intended constraint.
 * - The CapabilityCondition union covers every built-in type.  Unknown type
 *   discriminators produce a structured error that names the offending JSON
 *   path.  The caller (e.g. FilePolicySource in @euno/mcp) may add a second
 *   pass to further restrict which of the known types are supported in a
 *   given execution context (e.g. rejecting deferred Stage-2 types).
 * - Semantic checks (e.g. `notAfter >= notBefore`) are co-located with the
 *   structural checks so they are never silently skipped.
 */

import { z } from 'zod';
import type {
  AgentCapabilityManifest,
  CapabilityConstraint,
  CapabilityCondition,
  ArgumentSchema,
} from './types';

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/**
 * Thrown by {@link validateManifest} when the supplied value does not
 * conform to the {@link AgentCapabilityManifest} schema.
 *
 * `path` is the dotted JSON path to the first offending field
 * (e.g. `"requiredCapabilities[0].conditions[1].type"`).
 * `message` is a human-readable description suitable for display in a CLI
 * or API error body.
 */
export class ManifestValidationError extends Error {
  /** Dotted JSON path to the offending field (empty string for top-level). */
  readonly path: string;

  constructor(message: string, path = '') {
    // Do NOT prefix `message` with `path` here.  The callers of this
    // constructor either:
    //  (a) pass a `message` from `formatZodError()` that already embeds the
    //      path in each issue string — prefixing again would double up the
    //      path (e.g. "foo[0]: foo[0]: ..."), or
    //  (b) build a message that already includes the path as prose.
    // `path` is exposed as a separate field for programmatic consumers that
    // want to highlight or jump to the offending location.
    super(message);
    this.name = 'ManifestValidationError';
    this.path = path;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Require a non-empty string array. */
const nonEmptyStringArray = z.array(z.string().min(1)).min(1);

/**
 * Validate a full ISO 8601 datetime string.
 *
 * Two-step check (matches condition-registry.ts parseIsoTimestamp):
 *  1. Require a literal 'T' — rejects calendar-only strings ('2026-01-01')
 *     which some JS engines silently treat as UTC midnight but others treat
 *     as local midnight, introducing ambiguity.
 *  2. `Date.parse` must return a finite value — this catches all malformed
 *     strings (e.g. 'TXYZ') that contain 'T' but aren't valid datetimes.
 */
const iso8601DateTime = z
  .string()
  .refine((v) => /T/.test(v) && Number.isFinite(Date.parse(v)), {
    message: 'must be a full ISO 8601 datetime (e.g. 2026-01-01T00:00:00Z)',
  });

// ---------------------------------------------------------------------------
// ArgumentSchema (recursive)
// ---------------------------------------------------------------------------

const argSchemaType = z
  .union([
    z.enum(['object', 'string', 'number', 'integer', 'boolean', 'array', 'null']),
    z.array(
      z.enum(['object', 'string', 'number', 'integer', 'boolean', 'array', 'null']),
    ),
  ])
  .optional();

/**
 * Recursive Zod schema for {@link ArgumentSchema}.
 *
 * Uses `z.lazy` to handle the self-referential `properties` and `items`
 * fields.  Unknown keys are rejected (`.strict()`) so capability authors
 * cannot accidentally embed arbitrary data that would be silently ignored
 * by the argument-validator.
 */
export const ArgumentSchemaZ: z.ZodType<ArgumentSchema> = z.lazy(() =>
  z
    .object({
      type: argSchemaType,
      properties: z.record(ArgumentSchemaZ).optional(),
      required: z.array(z.string()).optional(),
      additionalProperties: z.boolean().optional(),
      enum: z.array(z.unknown()).readonly().optional(),
      pattern: z.string().optional(),
      minLength: z.number().int().nonnegative().optional(),
      maxLength: z.number().int().nonnegative().optional(),
      minimum: z.number().optional(),
      maximum: z.number().optional(),
      items: ArgumentSchemaZ.optional(),
      maxItems: z.number().int().nonnegative().optional(),
      minItems: z.number().int().nonnegative().optional(),
      description: z.string().optional(),
      strict: z.boolean().optional(),
    })
    .strict(),
);

// ---------------------------------------------------------------------------
// CapabilityCondition variants
// ---------------------------------------------------------------------------

// NOTE: z.discriminatedUnion() requires its members to be plain ZodObject
// schemas (not ZodEffects from .superRefine()). Semantic cross-field checks
// (e.g. notAfter >= notBefore) are applied via a superRefine on the outer
// CapabilityConditionZ so the discriminated union can parse cleanly first.

const TimeWindowConditionZ = z
  .object({
    type: z.literal('timeWindow'),
    notBefore: iso8601DateTime.optional(),
    notAfter: iso8601DateTime.optional(),
  })
  .strict();

const IpRangeConditionZ = z
  .object({
    type: z.literal('ipRange'),
    cidrs: nonEmptyStringArray,
  })
  .strict();

const AllowedOperationsConditionZ = z
  .object({
    type: z.literal('allowedOperations'),
    operations: nonEmptyStringArray,
  })
  .strict();

const AllowedExtensionsConditionZ = z
  .object({
    type: z.literal('allowedExtensions'),
    extensions: nonEmptyStringArray,
  })
  .strict();

const AllowedTablesConditionZ = z
  .object({
    type: z.literal('allowedTables'),
    tables: nonEmptyStringArray,
    columns: z.record(nonEmptyStringArray).optional(),
  })
  .strict();

const MaxCallsConditionZ = z
  .object({
    type: z.literal('maxCalls'),
    count: z.number().int().min(1, 'maxCalls.count must be >= 1'),
    windowSeconds: z
      .number()
      .int()
      .min(1, 'maxCalls.windowSeconds must be >= 1'),
  })
  .strict();

const RecipientDomainConditionZ = z
  .object({
    type: z.literal('recipientDomain'),
    domains: nonEmptyStringArray,
  })
  .strict();

const RedactFieldsConditionZ = z
  .object({
    type: z.literal('redactFields'),
    fields: nonEmptyStringArray,
  })
  .strict();

const PolicyConditionZ = z
  .object({
    type: z.literal('policy'),
    backend: z.string().min(1, 'policy.backend must be a non-empty string'),
    config: z.unknown().optional(),
    input: z.unknown().optional(),
  })
  .strict();

const CustomConditionZ = z
  .object({
    type: z.literal('custom'),
    name: z.string().min(1, "custom condition requires a non-empty 'name'"),
    config: z.unknown(),
  })
  .strict();

/**
 * Discriminated-union Zod schema covering every built-in
 * {@link CapabilityCondition} type, plus semantic cross-field checks.
 *
 * Unknown `type` discriminators produce a structured error naming the path.
 * The union intentionally includes the deferred Stage-2 types
 * (ipRange, recipientDomain, redactFields, policy, custom) so that this
 * general-purpose validator can be used by the production issuer.
 * Callers that want to enforce a stricter subset (e.g. the euno-mcp Stage-1
 * loader) should run a second pass after validation.
 */
export const CapabilityConditionZ: z.ZodType<CapabilityCondition> =
  z
    .discriminatedUnion('type', [
      TimeWindowConditionZ,
      IpRangeConditionZ,
      AllowedOperationsConditionZ,
      AllowedExtensionsConditionZ,
      AllowedTablesConditionZ,
      MaxCallsConditionZ,
      RecipientDomainConditionZ,
      RedactFieldsConditionZ,
      PolicyConditionZ,
      CustomConditionZ,
    ])
    .superRefine((c, ctx) => {
      if (c.type === 'timeWindow') {
        if (c.notBefore === undefined && c.notAfter === undefined) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "timeWindow requires at least one of 'notBefore' or 'notAfter'",
          });
          return;
        }
        if (c.notBefore !== undefined && c.notAfter !== undefined) {
          const nb = Date.parse(c.notBefore);
          const na = Date.parse(c.notAfter);
          if (Number.isFinite(nb) && Number.isFinite(na) && nb > na) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: 'timeWindow.notAfter must be on or after timeWindow.notBefore',
              path: ['notAfter'],
            });
          }
        }
      }
    }) as unknown as z.ZodType<CapabilityCondition>;

// ---------------------------------------------------------------------------
// CapabilityConstraint
// ---------------------------------------------------------------------------

export const CapabilityConstraintZ: z.ZodType<CapabilityConstraint> = z
  .object({
    resource: z.string().min(1, 'resource must be a non-empty string'),
    actions: z
      .array(z.string().min(1, 'each action must be a non-empty string'))
      .min(1, 'actions must be a non-empty array'),
    argumentSchema: ArgumentSchemaZ.optional(),
    conditions: z.array(CapabilityConditionZ).optional(),
  })
  .strict() as unknown as z.ZodType<CapabilityConstraint>;

// ---------------------------------------------------------------------------
// AgentCapabilityManifest
// ---------------------------------------------------------------------------

export const AgentCapabilityManifestZ: z.ZodType<AgentCapabilityManifest> = z
  .object({
    agentId: z.string().min(1, 'agentId must be a non-empty string'),
    name: z.string().min(1, 'name must be a non-empty string'),
    version: z.string().min(1, 'version must be a non-empty string'),
    requiredCapabilities: z
      .array(CapabilityConstraintZ)
      .min(1, 'requiredCapabilities must be a non-empty array'),
    optionalCapabilities: z.array(CapabilityConstraintZ).optional(),
    metadata: z
      .object({
        description: z.string().optional(),
        owner: z.string().optional(),
        tags: z.array(z.string()).optional(),
        runtime: z.string().optional(),
      })
      .strict()
      .optional(),
  })
  .strict() as unknown as z.ZodType<AgentCapabilityManifest>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Convert a Zod issue path array to a dotted/bracket JSON path string. */
function buildPath(parts: (string | number)[]): string {
  return parts.reduce<string>((acc, part) => {
    if (typeof part === 'number') return `${acc}[${part}]`;
    if (acc === '') return part;
    return `${acc}.${part}`;
  }, '');
}

/**
 * Format a Zod error into a human-readable string that includes the JSON
 * path and the validation message, matching the `✗ Validation failed:` UX
 * produced by the `euno validate` CLI.
 */
function formatZodError(err: z.ZodError): string {
  const issues = err.errors;
  if (issues.length === 0) return 'unknown validation error';

  return issues
    .map((issue) => {
      const path = issue.path.length > 0 ? buildPath(issue.path) : '';
      return path ? `${path}: ${issue.message}` : issue.message;
    })
    .join('; ');
}

/**
 * Validate `raw` against the {@link AgentCapabilityManifest} schema.
 *
 * Returns the typed manifest on success.  Throws {@link ManifestValidationError}
 * on structural or semantic failure.  `err.message` contains every offending
 * path+message joined by `; `; `err.path` points to the first issue for
 * programmatic consumers.
 *
 * Shared entry point used by:
 *  - `euno validate <file>` in `@euno/cli` (via `@euno/common` re-export)
 *  - `euno-mcp validate <file>` in `@euno/mcp` (Task 9)
 *  - `FilePolicySource.load()` in `@euno/mcp` (Task 7)
 *  - The capability issuer at mint time (production path)
 */
export function validateManifest(raw: unknown): AgentCapabilityManifest {
  const result = AgentCapabilityManifestZ.safeParse(raw);
  if (!result.success) {
    const msg = formatZodError(result.error);
    // Extract the first path for the ManifestValidationError constructor
    const firstIssue = result.error.errors[0];
    const path = firstIssue?.path ? buildPath(firstIssue.path) : '';
    throw new ManifestValidationError(msg, path);
  }
  return result.data;
}

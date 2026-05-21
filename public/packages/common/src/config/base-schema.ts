import { z } from 'zod';

// ---------------------------------------------------------------------------
// Field-level helpers.
// ---------------------------------------------------------------------------
//
// Env vars are always strings in `process.env`.  Treat the *empty
// string* the same as "unset" so that defaults apply uniformly whether
// the operator left the variable absent from `.env` or wrote
// `FOO=` explicitly.  Zod's `z.optional()` does not coerce empty
// strings, so wrap everything that goes into a schema with
// `optionalString` first.

export const optionalString = z
  .string()
  .transform((value) => (value === '' ? undefined : value))
  .optional();

/**
 * Coerce a string env var into a boolean using the `'true'` / `'false'`
 * convention used throughout the existing codebase.  Anything else is
 * a hard validation error so misconfig is loud, not silent.
 *
 * Overloaded so that callers who pass a `default` get a non-nullable
 * `boolean` in the inferred output type — eliminating the `!` /
 * `?? false` workarounds that downstream wiring would otherwise need.
 */
export function envBoolean(opts: { default: boolean; description: string }): z.ZodType<boolean, z.ZodTypeDef, unknown>;
export function envBoolean(opts: { description: string }): z.ZodType<boolean | undefined, z.ZodTypeDef, unknown>;
export function envBoolean(opts: { default?: boolean; description: string }): z.ZodType<boolean | undefined, z.ZodTypeDef, unknown> {
  return optionalString
    .pipe(
      z
        .union([z.literal('true'), z.literal('false'), z.undefined()])
        .transform((v) => (v === undefined ? opts.default : v === 'true')),
    )
    .describe(opts.description);
}

/**
 * Coerce a string env var into a positive integer, with a default and
 * a meaningful error message.  Used for ports, TTLs, intervals, etc.
 *
 * Overloaded so that callers who pass a `default` get a non-nullable
 * `number` in the inferred output type.
 */
export function envPositiveInt(opts: {
  default: number;
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number, z.ZodTypeDef, unknown>;
export function envPositiveInt(opts: {
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number | undefined, z.ZodTypeDef, unknown>;
export function envPositiveInt(opts: {
  default?: number;
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number | undefined, z.ZodTypeDef, unknown> {
  const min = opts.min ?? 1;
  const max = opts.max ?? Number.MAX_SAFE_INTEGER;
  return optionalString
    .pipe(
      z
        .string()
        .optional()
        .transform((v, ctx) => {
          if (v === undefined) return opts.default;
          // Reject partially-numeric strings like "10abc" outright. Without
          // this guard `Number.parseInt('10abc', 10)` silently returns 10
          // and a misconfig slips through — defeating the "loud failure"
          // goal of R-5. A leading '+' is allowed for symmetry with the
          // shell convention; '-' falls through to the range check.
          if (!/^[+-]?\d+$/.test(v)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be an integer (got "${v}")`,
            });
            return z.NEVER;
          }
          const parsed = Number.parseInt(v, 10);
          if (!Number.isFinite(parsed)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be an integer (got "${v}")`,
            });
            return z.NEVER;
          }
          if (parsed < min || parsed > max) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be between ${min} and ${max} (got ${parsed})`,
            });
            return z.NEVER;
          }
          return parsed;
        }),
    )
    .describe(opts.description);
}

/**
 * Specialisation of {@link envPositiveInt} for TCP port numbers (1–65535).
 * Validates that the value is a valid port number and provides a consistent
 * error message across all service schemas.
 */
export function envPort(opts: { default: number; description: string }): z.ZodType<number, z.ZodTypeDef, unknown> {
  return envPositiveInt({ ...opts, min: 1, max: 65535 }) as z.ZodType<number, z.ZodTypeDef, unknown>;
}

/**
 * Treat an env var as a comma-separated list of trimmed, non-empty
 * strings.  Returns `undefined` when unset so callers can distinguish
 * "no value" from "empty list".
 */
export function envCsv(opts: { description: string }) {
  return optionalString
    .pipe(
      z
        .string()
        .optional()
        .transform((v) => {
          if (v === undefined) return undefined;
          const parts = v
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
          return parts;
        }),
    )
    .describe(opts.description);
}

export function envEnum<T extends [string, ...string[]], D extends T[number]>(opts: {
  values: T;
  default: D;
  description: string;
}): z.ZodType<T[number], z.ZodTypeDef, unknown>;
export function envEnum<T extends [string, ...string[]]>(opts: {
  values: T;
  description: string;
}): z.ZodType<T[number] | undefined, z.ZodTypeDef, unknown>;
export function envEnum<T extends [string, ...string[]]>(opts: {
  values: T;
  default?: T[number];
  description: string;
}): z.ZodType<T[number] | undefined, z.ZodTypeDef, unknown> {
  return optionalString
    .pipe(
      z
        .enum(opts.values)
        .optional()
        .transform((v) => v ?? opts.default),
    )
    .describe(opts.description);
}

export const NODE_ENV = envEnum({
  values: ['development', 'staging', 'production'] as const,
  default: 'development',
  description:
    'Deployment environment. Used by logging and CORS to pick safe defaults.',
});

// ---------------------------------------------------------------------------
// Deployment-tier opt-in.
// ---------------------------------------------------------------------------
//
// Captures the operator's stated availability target so the cross-field
// rules below can demand the matching infrastructure (Redis, region tag,
// …). Without an explicit tier the schema applies the safest defaults
// (single-replica), preserving existing dev / single-pod deployments.
// See `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md` § "Redis availability
// tiers" for the full matrix.
export const EUNO_DEPLOYMENT_TIER = envEnum({
  values: [
    'single-replica',
    'multi-replica',
    'multi-region-active-active',
  ] as const,
  default: 'single-replica',
  description:
    'Deployment availability tier. Drives cross-field validation: ' +
    '`single-replica` (default) — Redis optional, in-memory fallback acceptable for dev / single-pod; ' +
    '`multi-replica` — REDIS_URL is REQUIRED so revocation, kill-switch, maxCalls, DPoP-replay (gateway) ' +
    'and the per-subject issuance rate limiter (issuer) share state across pods; ' +
    '`multi-region-active-active` — all of the above plus a region tag (ISSUER_REGION / GATEWAY_REGION) ' +
    'is REQUIRED on every replica so audit trails can be reconstructed after a regional failover. ' +
    'See docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md and docs/MULTI_REGION_ISSUER.md.',
});

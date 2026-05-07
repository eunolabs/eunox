/**
 * Condition registry: shared validation + enforcement for the typed
 * conditions carried inside a {@link CapabilityConstraint}.
 *
 * Background
 * ----------
 * Earlier versions of this codebase carried `conditions` as an opaque
 * `Record<string, unknown>` that was signed into capability tokens but
 * silently dropped at enforcement time — a fail-open posture for a
 * security-critical field. This module replaces that with a single
 * registry consulted by both the issuer (at mint time) and the gateway
 * (at request time):
 *
 *   - the issuer calls {@link validateCondition} on every condition of
 *     every capability before signing, rejecting the mint request with
 *     a structured error if any condition is malformed or unknown;
 *   - the gateway calls {@link enforceConditions} after the basic
 *     (action, resource) match passes, requiring every condition to
 *     resolve to `allow` and denying with a structured reason
 *     otherwise.
 *
 * Unknown / unrecognized condition types are treated as a hard denial
 * in both phases (deny-by-default) so that vendor extensions or future
 * condition types cannot silently round-trip into an unconstrained
 * token. Registering a custom handler via {@link registerCustomCondition}
 * is the explicit, auditable way to add new condition types.
 */

import {
  CapabilityCondition,
  TimeWindowCondition,
  IpRangeCondition,
  AllowedOperationsCondition,
  AllowedExtensionsCondition,
  AllowedTablesCondition,
  MaxCallsCondition,
  RecipientDomainCondition,
  RedactFieldsCondition,
  PolicyCondition,
  CustomCondition,
} from './types';

/**
 * Per-request context passed to {@link enforceCondition}. Fields are
 * optional because not every condition needs every piece of context —
 * however, when a condition *does* need a piece of context that the
 * caller did not supply, the handler returns `deny` rather than
 * silently skipping the check (deny-by-default on missing context).
 */
export interface ConditionContext {
  /** Wall-clock time of the request (defaults to `Date.now()`). */
  now?: Date;
  /** Source IP of the request, if known. */
  sourceIp?: string;
  /**
   * The operation the agent is asking the backend to perform within
   * the targeted resource (e.g. SQL verb, S3 sub-action). Used by
   * {@link AllowedOperationsCondition}.
   */
  operation?: string;
  /** File path the request targets, used by `allowedExtensions`. */
  filePath?: string;
  /**
   * Database tables the request targets, used by `allowedTables`.
   * Each entry may optionally carry the columns being read/written.
   */
  tables?: Array<{ table: string; columns?: string[] }>;
  /**
   * Recipients (e.g. email addresses) the request targets, used by
   * `recipientDomain`.
   */
  recipients?: string[];
  /**
   * Stable identifier the {@link CallCounterStore} keys on. Typically
   * `${capabilityId}:${conditionIndex}` so attenuated child tokens get
   * an independent counter from their parent.
   */
  counterKey?: string;
  /** Counter store used by {@link MaxCallsCondition}. */
  counterStore?: CallCounterStore;
  /**
   * The `sub` claim of the capability token currently being enforced.
   * Forwarded to {@link CallCounterStore.incrementAndGet} so that
   * shard-aware store implementations can route local-path agents to the
   * in-memory counter and mis-routed agents to the Redis fallback.
   * Optional: stores that do not need it simply ignore it.
   */
  agentSub?: string;
  /**
   * Map of registered custom-condition handlers keyed by the
   * `CustomCondition.name` they implement.
   */
  customHandlers?: Map<string, CustomConditionHandler>;
  /**
   * Per-context override of the global policy-backend registry (R-4
   * step 2 / F-10). Used by tests to inject a deterministic backend
   * without mutating the process-wide registry. When omitted the
   * handler falls back to the registry populated by
   * {@link registerPolicyBackend}.
   */
  policyBackends?: Map<string, PolicyBackend>;
}

/** Outcome of evaluating a single condition. */
export type ConditionResult =
  | { allow: true }
  | { allow: false; reason: string };

/**
 * A condition handler implements the validate/enforce/redact lobes of
 * the typed-condition contract (R-4 step 1):
 *
 *  - `validate` runs at issuance time and MUST throw a
 *    {@link ConditionValidationError} on bad data.
 *  - `enforce` runs at request time and returns a
 *    {@link ConditionResult}.
 *  - `redact` (optional) runs on the response path and returns a new
 *    body with the obligation applied. Handlers without this lobe
 *    impose no response-time obligation; the gateway leaves the body
 *    untouched.
 */
export interface ConditionHandler<C extends CapabilityCondition = CapabilityCondition> {
  validate(condition: C): void;
  enforce(condition: C, ctx: ConditionContext): ConditionResult | Promise<ConditionResult>;
  /**
   * Optional response post-processor. Receives the parsed response
   * body (typically JSON-shaped) and MUST return a new value with the
   * obligation applied. MUST NOT mutate `body`. Returning `body`
   * unchanged is a valid no-op.
   */
  redact?(condition: C, body: unknown): unknown;
}

/** Custom condition handlers don't see the discriminator-only `type`/`name`. */
export interface CustomConditionHandler {
  validate(config: unknown): void;
  enforce(config: unknown, ctx: ConditionContext): ConditionResult | Promise<ConditionResult>;
  /** Optional response post-processor — see {@link ConditionHandler.redact}. */
  redact?(config: unknown, body: unknown): unknown;
}

/**
 * Pluggable backend behind a `'policy'`-typed condition (R-4 step 2 /
 * F-10). Backends register the same `{ validate, enforce, redact? }`
 * shape as built-in handlers but receive the deserialised
 * `PolicyCondition.config` and `PolicyCondition.input` rather than the
 * full discriminated condition. This lets OPA / Cedar / future engines
 * plug into the gateway without touching the gateway middleware.
 */
export interface PolicyBackend {
  validate(config: unknown): void;
  enforce(
    config: unknown,
    input: unknown,
    ctx: ConditionContext,
  ): ConditionResult | Promise<ConditionResult>;
  /** Optional response post-processor — see {@link ConditionHandler.redact}. */
  redact?(config: unknown, input: unknown, body: unknown): unknown;
}

/** Storage for {@link MaxCallsCondition} counters. */
export interface CallCounterStore {
  /**
   * Increment the counter identified by `key` by 1 and return the
   * post-increment value. The counter MUST expire `windowSeconds`
   * after first creation (sliding-window semantics within
   * `windowSeconds` granularity).
   *
   * @param key - Stable counter key (`${capabilityId}:${conditionIndex}`).
   * @param windowSeconds - Tumbling window length in seconds.
   * @param agentSub - Optional `sub` claim of the capability token.
   *   Shard-aware implementations use this to decide whether to serve the
   *   request from the fast local in-memory path (owned agent) or fall back
   *   to the shared Redis backend (mis-routed agent). Stores that do not
   *   implement sharding ignore this parameter.
   */
  incrementAndGet(key: string, windowSeconds: number, agentSub?: string): Promise<number>;
}

/** Thrown by `validate*` helpers — surfaced by the issuer as `INVALID_REQUEST`. */
export class ConditionValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConditionValidationError';
  }
}

// ---------------------------------------------------------------------------
// Registry plumbing
// ---------------------------------------------------------------------------

const customHandlers = new Map<string, CustomConditionHandler>();
const policyBackends = new Map<string, PolicyBackend>();

/**
 * Register (or replace) a handler for the named custom condition. New
 * `CustomCondition` payloads carrying that `name` are then validated
 * and enforced via the supplied handler. Without an explicit
 * registration, a `custom` condition is denied at both issuance and
 * enforcement.
 */
export function registerCustomCondition(
  name: string,
  handler: CustomConditionHandler,
): void {
  if (!name || typeof name !== 'string') {
    throw new Error('registerCustomCondition: name must be a non-empty string');
  }
  customHandlers.set(name, handler);
}

/** Test helper — clears every registered custom handler. */
export function _resetCustomConditionRegistry(): void {
  customHandlers.clear();
}

/** Shallow snapshot of the current custom handler map. */
export function getCustomConditionHandlers(): Map<string, CustomConditionHandler> {
  return new Map(customHandlers);
}

/**
 * Register (or replace) a backend for the `'policy'` condition type
 * (R-4 step 2 / F-10). Without an explicit registration, a `policy`
 * condition naming this backend is denied at both issuance and
 * enforcement.
 */
export function registerPolicyBackend(name: string, backend: PolicyBackend): void {
  if (!name || typeof name !== 'string') {
    throw new Error('registerPolicyBackend: name must be a non-empty string');
  }
  policyBackends.set(name, backend);
}

/** Test helper — clears every registered policy backend. */
export function _resetPolicyBackendRegistry(): void {
  policyBackends.clear();
}

/** Shallow snapshot of the current policy backend map. */
export function getPolicyBackends(): Map<string, PolicyBackend> {
  return new Map(policyBackends);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate a single condition. Throws {@link ConditionValidationError}
 * on a structural problem. Issuers call this for every condition of
 * every capability before signing.
 */
export function validateCondition(condition: unknown): asserts condition is CapabilityCondition {
  if (typeof condition !== 'object' || condition === null) {
    throw new ConditionValidationError('condition must be an object');
  }
  const c = condition as { type?: unknown };
  if (typeof c.type !== 'string' || c.type.length === 0) {
    throw new ConditionValidationError("condition is missing a 'type' discriminator");
  }
  const handler = (BUILTIN_HANDLERS as Record<string, ConditionHandler<any>>)[c.type];
  if (handler) {
    handler.validate(condition as CapabilityCondition);
    return;
  }
  if (c.type === 'custom') {
    validateCustomCondition(condition as CustomCondition);
    return;
  }
  // Note: 'policy' is handled by BUILTIN_HANDLERS above (policyHandler).
  throw new ConditionValidationError(`unrecognized condition type '${c.type}'`);
}

/** Validate every condition on a capability. */
export function validateConditions(conditions: readonly CapabilityCondition[] | undefined): void {
  if (!conditions) return;
  if (!Array.isArray(conditions)) {
    throw new ConditionValidationError('conditions must be an array');
  }
  for (let i = 0; i < conditions.length; i++) {
    try {
      validateCondition(conditions[i]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new ConditionValidationError(`conditions[${i}]: ${msg}`);
    }
  }
}

function validateCustomCondition(c: CustomCondition): void {
  if (typeof c.name !== 'string' || c.name.length === 0) {
    throw new ConditionValidationError("custom condition is missing 'name'");
  }
  const handler = customHandlers.get(c.name);
  if (!handler) {
    throw new ConditionValidationError(
      `custom condition '${c.name}' has no registered handler`,
    );
  }
  handler.validate(c.config);
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/**
 * Enforce a single condition against the provided request context.
 * Unknown types resolve to `deny` (deny-by-default).
 */
export async function enforceCondition(
  condition: CapabilityCondition,
  ctx: ConditionContext,
): Promise<ConditionResult> {
  const handler = (BUILTIN_HANDLERS as Record<string, ConditionHandler<any>>)[condition.type];
  if (handler) {
    return handler.enforce(condition, ctx);
  }
  if (condition.type === 'custom') {
    const cc = condition as CustomCondition;
    const map = ctx.customHandlers ?? customHandlers;
    const ch = map.get(cc.name);
    if (!ch) {
      return { allow: false, reason: `unrecognized custom condition '${cc.name}'` };
    }
    return ch.enforce(cc.config, ctx);
  }
  // Note: 'policy' is dispatched via BUILTIN_HANDLERS above (policyHandler),
  // which honours `ctx.policyBackends`.
  return {
    allow: false,
    reason: `unrecognized condition type '${(condition as { type: string }).type}'`,
  };
}

/**
 * Enforce every condition. Returns the first denial encountered, or
 * `{ allow: true }` if every condition allowed (or the list is empty).
 *
 * Conditions are evaluated in two-tier order regardless of their
 * declaration order in the token:
 *
 *  1. **Cheap / stateless** — `timeWindow`, `ipRange`,
 *     `allowedOperations`, `allowedExtensions`, `allowedTables`,
 *     `recipientDomain`, `redactFields`, `allowedValues` — no I/O,
 *     fail-fast before any Redis round-trip.
 *  2. **Stateful / expensive** — `maxCalls` (Redis `INCR`), `policy`
 *     (remote OPA/Cedar call), `custom` (unknown cost).
 *
 * This ordering ensures that an IP-denied or time-window-expired
 * request never increments a `maxCalls` counter, keeping rate-limit
 * budgets accurate for legitimate callers and saving Redis round-trips
 * on blocked requests.
 *
 * The original declaration index is preserved for `maxCalls`
 * `counterKey` scoping so counter keys remain stable across
 * re-deployments even when this function reorders the evaluation.
 *
 * Conditions are still evaluated sequentially (not in parallel) so
 * side-effecting handlers see a well-defined ordering within each tier.
 */
export async function enforceConditions(
  conditions: readonly CapabilityCondition[] | undefined,
  ctx: ConditionContext,
): Promise<ConditionResult> {
  if (!conditions || conditions.length === 0) {
    return { allow: true };
  }

  // Assign each condition a stable (priority, originalIndex) tuple.
  // Conditions in the same priority bucket retain their declaration order
  // (stable sort) so relative ordering within a tier is predictable.
  const indexed = conditions.map((cond, i) => ({
    cond,
    originalIndex: i,
    priority: CONDITION_ENFORCEMENT_PRIORITY[cond.type] ?? CONDITION_PRIORITY_CUSTOM,
  }));
  indexed.sort((a, b) => a.priority - b.priority || a.originalIndex - b.originalIndex);

  for (const { cond, originalIndex } of indexed) {
    if (!cond) continue;
    // Use the *original* declaration index for maxCalls counter scoping
    // so that counter Redis keys remain stable even when the evaluation
    // order changes (e.g. after adding a new timeWindow condition before
    // maxCalls in the token). Changing the index would silently reset the
    // counter window for every deployed token on re-deployment.
    const scopedCtx: ConditionContext =
      cond.type === 'maxCalls' && ctx.counterKey
        ? { ...ctx, counterKey: `${ctx.counterKey}:${originalIndex}` }
        : ctx;
    const result = await enforceCondition(cond, scopedCtx);
    if (!result.allow) {
      return result;
    }
  }
  return { allow: true };
}

// ---------------------------------------------------------------------------
// Condition enforcement priority
// ---------------------------------------------------------------------------
//
// Lower number = evaluated first.
// Stateless conditions run before stateful (Redis) ones so a blocked
// request never increments a maxCalls counter or triggers a remote
// policy call.

/** Evaluation priority for known built-in condition types. */
const CONDITION_ENFORCEMENT_PRIORITY: Record<string, number> = {
  timeWindow: 0,          // pure clock comparison
  ipRange: 1,             // CIDR match, no I/O
  allowedOperations: 2,   // string comparison
  allowedExtensions: 2,   // string comparison
  allowedTables: 2,       // string comparison
  recipientDomain: 2,     // string comparison
  allowedValues: 2,       // string comparison
  redactFields: 3,        // response-only obligation; always allows on request path
  policy: 4,              // remote OPA/Cedar call
  maxCalls: 5,            // Redis INCR — stateful, must run last among builtins
};
const CONDITION_PRIORITY_CUSTOM = 6; // custom handlers: cost unknown, after builtins

// ---------------------------------------------------------------------------
// Built-in handlers
// ---------------------------------------------------------------------------

function expectStringArray(field: string, value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new ConditionValidationError(`${field} must be a non-empty array of strings`);
  }
  for (const v of value) {
    if (typeof v !== 'string' || v.length === 0) {
      throw new ConditionValidationError(`${field} entries must be non-empty strings`);
    }
  }
  return value as string[];
}

function parseIsoTimestamp(field: string, value: string): number {
  // `Date.parse` accepts a wide range of inputs; require an explicit `T`
  // so we reject calendar-only ("2026-01-01") and ambiguous formats
  // that otherwise interpret as UTC midnight in some runtimes and local
  // midnight in others.
  if (!/T/.test(value)) {
    throw new ConditionValidationError(
      `${field} must be a full ISO 8601 datetime (e.g. 2026-01-01T00:00:00Z)`,
    );
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new ConditionValidationError(`${field} is not a valid ISO 8601 datetime`);
  }
  return ms;
}

const timeWindowHandler: ConditionHandler<TimeWindowCondition> = {
  validate(c) {
    if (c.notBefore === undefined && c.notAfter === undefined) {
      throw new ConditionValidationError(
        "timeWindow requires at least one of 'notBefore' or 'notAfter'",
      );
    }
    let nb: number | undefined;
    let na: number | undefined;
    if (c.notBefore !== undefined) {
      if (typeof c.notBefore !== 'string') {
        throw new ConditionValidationError('timeWindow.notBefore must be a string');
      }
      nb = parseIsoTimestamp('timeWindow.notBefore', c.notBefore);
    }
    if (c.notAfter !== undefined) {
      if (typeof c.notAfter !== 'string') {
        throw new ConditionValidationError('timeWindow.notAfter must be a string');
      }
      na = parseIsoTimestamp('timeWindow.notAfter', c.notAfter);
    }
    if (nb !== undefined && na !== undefined && nb > na) {
      throw new ConditionValidationError(
        'timeWindow.notAfter must be on or after timeWindow.notBefore',
      );
    }
  },
  enforce(c, ctx) {
    const now = (ctx.now ?? new Date()).getTime();
    if (c.notBefore !== undefined) {
      const nb = Date.parse(c.notBefore);
      if (Number.isFinite(nb) && now < nb) {
        return { allow: false, reason: `timeWindow not yet active (notBefore=${c.notBefore})` };
      }
    }
    if (c.notAfter !== undefined) {
      const na = Date.parse(c.notAfter);
      if (Number.isFinite(na) && now > na) {
        return { allow: false, reason: `timeWindow expired (notAfter=${c.notAfter})` };
      }
    }
    return { allow: true };
  },
};

const ipRangeHandler: ConditionHandler<IpRangeCondition> = {
  validate(c) {
    const cidrs = expectStringArray('ipRange.cidrs', c.cidrs);
    for (const cidr of cidrs) {
      if (!isValidCidr(cidr)) {
        throw new ConditionValidationError(`ipRange.cidrs contains invalid CIDR '${cidr}'`);
      }
    }
  },
  enforce(c, ctx) {
    if (!ctx.sourceIp) {
      return { allow: false, reason: 'ipRange requires sourceIp in request context' };
    }
    for (const cidr of c.cidrs) {
      if (ipMatchesCidr(ctx.sourceIp, cidr)) {
        return { allow: true };
      }
    }
    return { allow: false, reason: `sourceIp ${ctx.sourceIp} not in any allowed CIDR` };
  },
};

const allowedOperationsHandler: ConditionHandler<AllowedOperationsCondition> = {
  validate(c) {
    expectStringArray('allowedOperations.operations', c.operations);
  },
  enforce(c, ctx) {
    if (!ctx.operation) {
      return { allow: false, reason: 'allowedOperations requires operation in request context' };
    }
    const op = ctx.operation.toLowerCase();
    for (const allowed of c.operations) {
      if (allowed.toLowerCase() === op) {
        return { allow: true };
      }
    }
    return {
      allow: false,
      reason: `operation '${ctx.operation}' is not in the allowed list`,
    };
  },
};

const allowedExtensionsHandler: ConditionHandler<AllowedExtensionsCondition> = {
  validate(c) {
    expectStringArray('allowedExtensions.extensions', c.extensions);
  },
  enforce(c, ctx) {
    if (!ctx.filePath) {
      return { allow: false, reason: 'allowedExtensions requires filePath in request context' };
    }
    const path = ctx.filePath.toLowerCase();
    for (const ext of c.extensions) {
      const norm = ext.startsWith('.') ? ext.toLowerCase() : '.' + ext.toLowerCase();
      if (path.endsWith(norm)) {
        return { allow: true };
      }
    }
    return {
      allow: false,
      reason: `file extension of '${ctx.filePath}' is not in the allowed list`,
    };
  },
};

const allowedTablesHandler: ConditionHandler<AllowedTablesCondition> = {
  validate(c) {
    expectStringArray('allowedTables.tables', c.tables);
    if (c.columns !== undefined) {
      if (typeof c.columns !== 'object' || c.columns === null || Array.isArray(c.columns)) {
        throw new ConditionValidationError('allowedTables.columns must be an object');
      }
      for (const [tbl, cols] of Object.entries(c.columns)) {
        expectStringArray(`allowedTables.columns['${tbl}']`, cols);
      }
    }
  },
  enforce(c, ctx) {
    if (!ctx.tables || ctx.tables.length === 0) {
      return { allow: false, reason: 'allowedTables requires tables in request context' };
    }
    const allowedTables = new Set(c.tables.map((t) => t.toLowerCase()));
    // Build a case-insensitive view of the columns map so that an
    // issuer-side casing of e.g. `{"Customers": [...]}` still applies
    // to a request that names the table as `customers`. Without this
    // normalization the column allowlist would be silently skipped on
    // any case mismatch — a fail-open path on a security-critical
    // narrowing condition.
    const columnsLower: Record<string, string[]> | undefined = c.columns
      ? Object.fromEntries(
          Object.entries(c.columns).map(([k, v]) => [k.toLowerCase(), v]),
        )
      : undefined;
    for (const entry of ctx.tables) {
      const tableLower = entry.table.toLowerCase();
      if (!allowedTables.has(tableLower)) {
        return {
          allow: false,
          reason: `table '${entry.table}' is not in the allowed list`,
        };
      }
      const colSpec = columnsLower?.[tableLower];
      if (colSpec && entry.columns) {
        if (colSpec.includes('*')) continue;
        const allowedCols = new Set(colSpec.map((col) => col.toLowerCase()));
        for (const col of entry.columns) {
          if (!allowedCols.has(col.toLowerCase())) {
            return {
              allow: false,
              reason: `column '${col}' on table '${entry.table}' is not allowed`,
            };
          }
        }
      }
    }
    return { allow: true };
  },
};

const maxCallsHandler: ConditionHandler<MaxCallsCondition> = {
  validate(c) {
    if (typeof c.count !== 'number' || !Number.isInteger(c.count) || c.count < 1) {
      throw new ConditionValidationError('maxCalls.count must be a positive integer');
    }
    if (
      typeof c.windowSeconds !== 'number' ||
      !Number.isInteger(c.windowSeconds) ||
      c.windowSeconds < 1
    ) {
      throw new ConditionValidationError('maxCalls.windowSeconds must be a positive integer');
    }
  },
  async enforce(c, ctx) {
    if (!ctx.counterStore || !ctx.counterKey) {
      return {
        allow: false,
        reason: 'maxCalls requires counterStore and counterKey in request context',
      };
    }
    const current = await ctx.counterStore.incrementAndGet(ctx.counterKey, c.windowSeconds, ctx.agentSub);
    if (current > c.count) {
      return {
        allow: false,
        reason: `maxCalls exceeded (${current} > ${c.count} in ${c.windowSeconds}s)`,
      };
    }
    return { allow: true };
  },
};

const recipientDomainHandler: ConditionHandler<RecipientDomainCondition> = {
  validate(c) {
    const domains = expectStringArray('recipientDomain.domains', c.domains);
    for (const d of domains) {
      // Reject `@` so callers don't accidentally write a full address.
      if (d.includes('@')) {
        throw new ConditionValidationError(
          `recipientDomain.domains entry '${d}' must be a bare domain, not an address`,
        );
      }
    }
  },
  enforce(c, ctx) {
    if (!ctx.recipients || ctx.recipients.length === 0) {
      return { allow: false, reason: 'recipientDomain requires recipients in request context' };
    }
    const allowed = new Set(c.domains.map((d) => d.toLowerCase()));
    for (const recipient of ctx.recipients) {
      const at = recipient.lastIndexOf('@');
      // Require a non-empty local part *and* a non-empty domain part.
      // `at < 1` catches both no-`@` (`-1`) and empty-local (`0`); a
      // trailing `@` (domain empty) is caught by the slice length.
      if (at < 1 || at === recipient.length - 1) {
        return { allow: false, reason: `recipient '${recipient}' is not a valid address` };
      }
      const domain = recipient.slice(at + 1).toLowerCase();
      if (!allowed.has(domain)) {
        return {
          allow: false,
          reason: `recipient domain '${domain}' is not in the allowed list`,
        };
      }
    }
    return { allow: true };
  },
};

const redactFieldsHandler: ConditionHandler<RedactFieldsCondition> = {
  validate(c) {
    expectStringArray('redactFields.fields', c.fields);
  },
  // The authorization decision is unconditional: this obligation never
  // denies a request — it only mutates the response. The actual field
  // stripping happens via {@link redact} below, invoked by the gateway
  // on the response path (R-4 step 1, closes I-3 / supports F-3).
  enforce() {
    return { allow: true };
  },
  redact(c, body) {
    let out = body;
    for (const path of c.fields) {
      out = deleteDottedPath(out, path);
    }
    return out;
  },
};

const policyHandler: ConditionHandler<PolicyCondition> = {
  validate(c) {
    if (typeof c.backend !== 'string' || c.backend.length === 0) {
      throw new ConditionValidationError("policy.backend must be a non-empty string");
    }
    const backend = policyBackends.get(c.backend);
    if (!backend) {
      throw new ConditionValidationError(
        `policy backend '${c.backend}' has no registered handler`,
      );
    }
    backend.validate(c.config);
  },
  async enforce(c, ctx) {
    const map = ctx.policyBackends ?? policyBackends;
    const backend = map.get(c.backend);
    if (!backend) {
      return { allow: false, reason: `unrecognized policy backend '${c.backend}'` };
    }
    return backend.enforce(c.config, c.input, ctx);
  },
  // Note: redactConditions handles `'policy'` directly so it can honour
  // `ctx.policyBackends` overrides (which the lobe signature can't see).
  // No `redact` lobe is exposed here to avoid a global-only path that
  // silently disagrees with the per-context one.
};

/** Built-in handler table keyed by `type`. */
export const BUILTIN_HANDLERS: {
  timeWindow: ConditionHandler<TimeWindowCondition>;
  ipRange: ConditionHandler<IpRangeCondition>;
  allowedOperations: ConditionHandler<AllowedOperationsCondition>;
  allowedExtensions: ConditionHandler<AllowedExtensionsCondition>;
  allowedTables: ConditionHandler<AllowedTablesCondition>;
  maxCalls: ConditionHandler<MaxCallsCondition>;
  recipientDomain: ConditionHandler<RecipientDomainCondition>;
  redactFields: ConditionHandler<RedactFieldsCondition>;
  policy: ConditionHandler<PolicyCondition>;
} = {
  timeWindow: timeWindowHandler,
  ipRange: ipRangeHandler,
  allowedOperations: allowedOperationsHandler,
  allowedExtensions: allowedExtensionsHandler,
  allowedTables: allowedTablesHandler,
  maxCalls: maxCallsHandler,
  recipientDomain: recipientDomainHandler,
  redactFields: redactFieldsHandler,
  policy: policyHandler,
};

// ---------------------------------------------------------------------------
// Response-time obligations (redaction)
// ---------------------------------------------------------------------------

/**
 * Per-call overrides for the redaction pipeline. Mirrors the
 * equivalent fields on {@link ConditionContext} so a request whose
 * authorization decision used a per-context custom-handler /
 * policy-backend map can apply the matching response-time obligations
 * with the *same* maps. Without this, enforcement and redaction would
 * silently disagree (e.g. enforcement uses a stub backend, redaction
 * falls back to the global one — or finds none and no-ops).
 */
export interface RedactContext {
  customHandlers?: Map<string, CustomConditionHandler>;
  policyBackends?: Map<string, PolicyBackend>;
}

/**
 * Apply every condition's `redact` lobe to `body` in declaration order
 * and return the resulting value. Conditions whose handler does not
 * declare a `redact` lobe are no-ops; the function is therefore safe
 * to call unconditionally on the response path.
 *
 * The implementation never mutates `body` — each `redact` call
 * structurally clones any object it touches before deleting the
 * targeted path. Callers that still want belt-and-braces isolation
 * should JSON-roundtrip the result themselves.
 *
 * Used by `EnforcementEngine.validateAction` to build the
 * `applyResponseRedactions` lobe of its result, which the tool gateway
 * then runs against the proxied response body (R-4 step 1, closes
 * I-3 / supports F-3). Pass the same `customHandlers` / `policyBackends`
 * maps used at enforcement time so both lanes consult the same
 * implementations.
 */
export function redactConditions(
  conditions: readonly CapabilityCondition[] | undefined,
  body: unknown,
  ctx: RedactContext = {},
): unknown {
  if (!conditions || conditions.length === 0) return body;
  let out = body;
  for (const cond of conditions) {
    if (!cond) continue;
    if (cond.type === 'custom') {
      const cc = cond as CustomCondition;
      const map = ctx.customHandlers ?? customHandlers;
      const ch = map.get(cc.name);
      if (ch?.redact) {
        out = ch.redact(cc.config, out);
      }
      continue;
    }
    if (cond.type === 'policy') {
      const pc = cond as PolicyCondition;
      const map = ctx.policyBackends ?? policyBackends;
      const backend = map.get(pc.backend);
      if (backend?.redact) {
        out = backend.redact(pc.config, pc.input, out);
      }
      continue;
    }
    const handler =
      (BUILTIN_HANDLERS as Record<string, ConditionHandler<any>>)[cond.type];
    if (handler?.redact) {
      out = handler.redact(cond, out);
    }
    // Unknown / unredact-capable types: leave body unchanged. We
    // intentionally do NOT deny here — the request was already
    // authorized by `enforceConditions`; redaction is a separate,
    // additive obligation lane.
  }
  return out;
}

/**
 * Return true when at least one condition in `conditions` resolves to
 * a handler / backend that declares a `redact` lobe under the supplied
 * context. Lets callers skip the redaction post-processor entirely
 * when no obligation actually wants to mutate the response (the common
 * case for capabilities whose only conditions are `timeWindow`,
 * `ipRange`, etc.).
 */
export function hasRedactObligation(
  conditions: readonly CapabilityCondition[] | undefined,
  ctx: RedactContext = {},
): boolean {
  if (!conditions || conditions.length === 0) return false;
  for (const cond of conditions) {
    if (!cond) continue;
    if (cond.type === 'custom') {
      const map = ctx.customHandlers ?? customHandlers;
      const ch = map.get((cond as CustomCondition).name);
      if (ch?.redact) return true;
      continue;
    }
    if (cond.type === 'policy') {
      const map = ctx.policyBackends ?? policyBackends;
      const backend = map.get((cond as PolicyCondition).backend);
      if (backend?.redact) return true;
      continue;
    }
    const handler =
      (BUILTIN_HANDLERS as Record<string, ConditionHandler<any>>)[cond.type];
    if (handler?.redact) return true;
  }
  return false;
}

/**
 * Return a structural clone of `obj` with the dotted `path` removed.
 * Arrays encountered on the way are descended into element-wise so
 * `users.ssn` against `{ users: [{ssn: ...}, {ssn: ...}] }` strips
 * `ssn` from both elements. Missing path segments are tolerated as
 * no-ops; the input is returned unchanged in that case (no clone).
 */
function deleteDottedPath(obj: unknown, path: string): unknown {
  const parts = path.split('.').filter((p) => p.length > 0);
  if (parts.length === 0) return obj;
  return cloneAndDelete(obj, parts);
}

function cloneAndDelete(node: unknown, parts: string[]): unknown {
  if (Array.isArray(node)) {
    let mutated = false;
    const out: unknown[] = node.map((el) => {
      const next = cloneAndDelete(el, parts);
      if (next !== el) mutated = true;
      return next;
    });
    return mutated ? out : node;
  }
  if (node === null || typeof node !== 'object') return node;
  const obj = node as Record<string, unknown>;
  const head = parts[0]!;
  if (!Object.prototype.hasOwnProperty.call(obj, head)) return node;
  const out: Record<string, unknown> = { ...obj };
  if (parts.length === 1) {
    delete out[head];
    return out;
  }
  const rest = parts.slice(1);
  const child = obj[head];
  const newChild = cloneAndDelete(child, rest);
  if (newChild === child) return node;
  out[head] = newChild;
  return out;
}

// ---------------------------------------------------------------------------
// CIDR helpers
// ---------------------------------------------------------------------------

/**
 * Validate a CIDR string. Supports IPv4 (`a.b.c.d/n`, n in 0..32) and
 * unbracketed IPv6 (`addr/n`, n in 0..128). The IPv6 path accepts the
 * `::` zero-compression and one optional embedded IPv4 suffix.
 */
export function isValidCidr(cidr: string): boolean {
  const slash = cidr.indexOf('/');
  if (slash < 0) return false;
  const addr = cidr.slice(0, slash);
  const prefix = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0) return false;
  if (addr.includes('.') && !addr.includes(':')) {
    return prefix <= 32 && parseIPv4(addr) !== null;
  }
  return prefix <= 128 && parseIPv6(addr) !== null;
}

/**
 * Return true if `ip` lies inside `cidr`. Mismatched address families
 * (IPv4 vs IPv6) return false rather than throwing — the handler will
 * report a generic deny reason in that case.
 */
export function ipMatchesCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/');
  if (slash < 0) return false;
  const addrStr = cidr.slice(0, slash);
  const prefix = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0) return false;

  const cidrIsV4 = addrStr.includes('.') && !addrStr.includes(':');
  const ipIsV4 = ip.includes('.') && !ip.includes(':');
  if (cidrIsV4 !== ipIsV4) return false;

  if (cidrIsV4) {
    if (prefix > 32) return false;
    const a = parseIPv4(ip);
    const b = parseIPv4(addrStr);
    if (a === null || b === null) return false;
    if (prefix === 0) return true;
    const mask = prefix === 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1)) >>> 0;
    return (a & mask) === (b & mask);
  }

  if (prefix > 128) return false;
  const a = parseIPv6(ip);
  const b = parseIPv6(addrStr);
  if (a === null || b === null) return false;
  let bitsLeft = prefix;
  for (let i = 0; i < 8; i++) {
    if (bitsLeft <= 0) return true;
    const groupBits = bitsLeft >= 16 ? 16 : bitsLeft;
    const shift = 16 - groupBits;
    if ((a[i]! >>> shift) !== (b[i]! >>> shift)) return false;
    bitsLeft -= groupBits;
  }
  return true;
}

function parseIPv4(s: string): number | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    // Reject leading zeros (e.g. `010`) which some host-resolver
    // implementations interpret as octal — accepting them would let
    // two textually-distinct CIDRs evaluate to different ranges
    // depending on the runtime that parses them. The single literal
    // `0` is allowed.
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    out = (out * 256 + n) >>> 0;
  }
  return out;
}

function parseIPv6(s: string): number[] | null {
  // Allow embedded IPv4 in the last 32 bits.
  let trailingV4: number | null = null;
  let work = s;
  const lastColon = work.lastIndexOf(':');
  if (lastColon >= 0 && work.slice(lastColon + 1).includes('.')) {
    const v4 = parseIPv4(work.slice(lastColon + 1));
    if (v4 === null) return null;
    trailingV4 = v4;
    work = work.slice(0, lastColon + 1) + '0:0';
  }

  const doubleColon = work.indexOf('::');
  let head: string[] = [];
  let tail: string[] = [];
  if (doubleColon < 0) {
    head = work.split(':');
  } else {
    if (work.indexOf('::', doubleColon + 1) >= 0) return null;
    const h = work.slice(0, doubleColon);
    const t = work.slice(doubleColon + 2);
    head = h === '' ? [] : h.split(':');
    tail = t === '' ? [] : t.split(':');
  }
  const total = head.length + tail.length;
  if (total > 8) return null;
  if (doubleColon < 0 && total !== 8) return null;
  const fillCount = 8 - total;
  const groups: number[] = [];
  for (const g of head) groups.push(parseHextet(g));
  for (let i = 0; i < fillCount; i++) groups.push(0);
  for (const g of tail) groups.push(parseHextet(g));
  if (groups.some((g) => g < 0)) return null;
  if (trailingV4 !== null) {
    groups[6] = (trailingV4 >>> 16) & 0xffff;
    groups[7] = trailingV4 & 0xffff;
  }
  return groups;
}

function parseHextet(s: string): number {
  if (!/^[0-9a-fA-F]{1,4}$/.test(s)) return -1;
  return parseInt(s, 16);
}

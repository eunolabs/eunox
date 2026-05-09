/**
 * PolicyDecisionPoint (PDP) — the single enforcement seam for @euno/mcp.
 *
 * Every `tools/call` request passes through the PDP before being forwarded to
 * the upstream MCP server.  The interface is intentionally narrow so that:
 *
 *   - Stage 1 ships {@link AlwaysAllowPDP} (no policy, transparent passthrough).
 *   - {@link ConditionEnforcerPDP} wires the real condition-registry backed
 *     enforcement using the in-memory CallCounterStore and KillSwitchManager
 *     from @euno/common-core.
 *   - Stage 3 replaces the policy source with a JWT loader — without touching
 *     this interface or the transport layer.
 *
 * ### Manifest-to-tool mapping convention
 *
 * An {@link AgentCapabilityManifest} constraint is matched against an MCP
 * `tools/call` request as follows:
 *
 *   - `resource`: the MCP tool name (e.g. `query_db`), OR a
 *     `mcp-tool://<toolName>` URI.  The PDP tries the raw tool name first
 *     (exact match and scheme-less wildcard patterns) then tries the
 *     `mcp-tool://` normalized form (scheme-qualified patterns such as
 *     `mcp-tool://*` or `mcp-tool://**`).
 *   - `actions`: must include `"call"` (the only MCP tool action).
 *   - Wildcards follow {@link matchesResource} semantics: only a trailing
 *     `/*` (single segment) or `/**` (any segments) are supported.
 *     Bare `*` is not a valid pattern.  Scheme parity is enforced when
 *     either side declares a `://` scheme, so `api://*` never matches
 *     `mcp-tool://echo`.
 *
 * Example manifest entries:
 * ```yaml
 * requiredCapabilities:
 *   # exact match (recommended for plain tool names)
 *   - resource: "query_db"
 *     actions: [call]
 *
 *   # scheme-qualified exact match
 *   - resource: "mcp-tool://query_db"
 *     actions: [call]
 *
 *   # any single tool name (no sub-paths)
 *   - resource: "mcp-tool://*"
 *     actions: [call]
 *
 *   # any tool name including hierarchical names
 *   - resource: "mcp-tool://**"
 *     actions: [call]
 * ```
 *
 * If no constraint matches the tool name → the call is allowed (the manifest
 * only restricts explicitly listed tools).
 *
 * @module
 */

import type { CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import {
  InMemoryCallCounterStore,
  DefaultKillSwitchManager,
  enforceCondition,
  validateArguments,
  ArgumentValidationError,
  findMatchingCapability,
  getCustomConditionHandlers,
  type CallCounterStore,
  type KillSwitchManager,
  type AgentCapabilityManifest,
  type CapabilityConstraint,
  type CapabilityCondition,
  type ConditionContext,
} from '@euno/common-core';
import type { LocalPolicySource } from './policy/source';

/**
 * Context supplied to every PDP decision call.
 */
export interface PdpContext {
  /**
   * Unique identifier for the current MCP session.  For stdio the session is
   * the lifetime of the proxy process; for HTTP it is one
   * `initialize` → `shutdown` cycle (see Task 5).
   */
  readonly sessionId: string;

  /**
   * The source IP address of the MCP client making the request.
   *
   * For HTTP transport this is the IP captured from the incoming HTTP
   * request (see {@link HttpProxy}).  For stdio transport this is always
   * `undefined` — there is no network peer in stdio mode, so manifests that
   * include an `ipRange` condition and are used over stdio will be denied
   * with the reason "ipRange requires sourceIp in request context".
   *
   * The value is already stripped of the `::ffff:` IPv4-mapped prefix so
   * handlers always receive a bare IPv4 or IPv6 address.
   */
  readonly sourceIp?: string;
}

/**
 * Decision returned by the PDP for a single `tools/call` invocation.
 */
export interface PdpDecision {
  /** Whether the call is permitted. */
  readonly allow: boolean;
  /**
   * Human-readable explanation — included in the MCP error response when
   * `allow` is `false`.
   */
  readonly reason?: string;
  /**
   * Machine-readable denial code (e.g. `CAPABILITY_DENIED`, `KILL_SWITCH`,
   * `MAX_CALLS_EXCEEDED`).  Only set when `allow` is `false`.
   */
  readonly denialCode?: string;
  /**
   * The `CapabilityCondition.type` that triggered the denial (e.g. `'maxCalls'`,
   * `'timeWindow'`, `'argumentSchema'`, `'kill'`).
   *
   * Populated by {@link ConditionEnforcerPDP} for telemetry and audit enrichment.
   * Only set when `allow` is `false`.
   */
  readonly conditionType?: string;
  /**
   * Structured details about the denial cause.  Currently populated only for
   * `argumentSchema` denials and contains the machine-readable fields from
   * {@link ArgumentValidationError}:
   *
   * ```json
   * {
   *   "path": "args.body.email",
   *   "expected": "string matching /^[^@]+@[^@]+$/",
   *   "got": "not-an-email"
   * }
   * ```
   *
   * MCP transports serialise this into the `details` field of the
   * `CapabilityDenied` result object so clients can react programmatically
   * without parsing the human-readable `reason` string.
   *
   * Only set when `allow` is `false` and structured information is available.
   */
  readonly details?: Record<string, unknown>;
  /**
   * The conditions from the matched {@link CapabilityConstraint} when
   * `allow` is `true` and a constraint was found.  Populated by
   * {@link ConditionEnforcerPDP} so the transport layer can apply
   * response-path obligations (e.g. `redactFields`) without re-running
   * the capability match.
   *
   * `undefined` when `allow` is `false`, when no constraint matched the
   * tool name, or when the matched constraint carries no conditions.
   */
  readonly matchedConditions?: readonly CapabilityCondition[];
}

/**
 * The PolicyDecisionPoint interface.
 *
 * Implementations must be safe to call concurrently for different requests in
 * the same session.
 */
export interface PolicyDecisionPoint {
  /**
   * Evaluate a `tools/call` request against the active policy.
   *
   * @param request - The incoming `tools/call` request from the MCP client.
   * @param ctx     - Session context (session id, etc.).
   * @returns A decision — synchronous or asynchronous.
   */
  decide(
    request: CallToolRequest,
    ctx: PdpContext,
  ): PdpDecision | Promise<PdpDecision>;
}

/**
 * Transparent PDP that always permits calls.
 *
 * Used during Stage 1 before a real condition-registry enforcer is wired.
 * Replacing this with {@link ConditionEnforcerPDP} is a one-line swap in
 * the proxy factory.
 */
export class AlwaysAllowPDP implements PolicyDecisionPoint {
  decide(_request: CallToolRequest, _ctx: PdpContext): PdpDecision {
    return { allow: true };
  }
}

// ---------------------------------------------------------------------------
// MCP action constant
// ---------------------------------------------------------------------------

/**
 * The single MCP tool-call action.  Every `tools/call` maps to this action so
 * capability constraints use `actions: [call]` to permit tool invocations.
 */
const MCP_TOOL_CALL_ACTION = 'call';

// ---------------------------------------------------------------------------
// Argument-context extraction helpers
// ---------------------------------------------------------------------------

/**
 * Attempt to extract a SQL operation verb from the arguments of a tool call.
 *
 * Looks for common argument keys (`sql`, `query`, `statement`) and extracts
 * the first word (verb) so `allowedOperations` conditions can be enforced.
 * Returns `undefined` when no recognisable SQL argument is found.
 *
 * ## Security limitation — first-word extraction, not SQL parsing
 *
 * This function extracts the **first whitespace-delimited token** from the
 * SQL string and uppercases it.  This approach is fast, dependency-free, and
 * effective against naive prompt injections, but it can be bypassed by
 * adversaries who control the query string:
 *
 * | Bypass vector | Example | Why it works |
 * |---|---|---|
 * | Semicolon-chained statements | `SELECT 1; DROP TABLE users` | First word is `SELECT` — second statement executes if the DB driver allows multi-statement queries |
 * | Block comments before verb | SQL starting with `slash-star ... star-slash DROP TABLE` | First token is the block-comment opener (e.g. `/*`) — this token is NOT in the allowlist, so the call is **denied** (fail-closed). Legitimate comment-prefixed SELECT queries are also blocked. |
 * | Inline comment injection | `SELECT * FROM users -- ; DROP TABLE users` | First word is `SELECT` but comment smuggles a second intent |
 * | Quoted identifiers | `"SELECT" something` | Verb-match may succeed depending on driver quoting |
 *
 * ### Recommended defense-in-depth
 *
 * `allowedOperations` is a **first line of defense**, not a complete SQL firewall.
 * To close the gaps above, combine it with:
 *
 * 1. **Parameterized queries in the upstream server** — the MCP server should
 *    never interpolate agent-supplied strings directly into SQL.
 * 2. **Read-only / restricted database credentials** — the DB user used by the
 *    upstream server should only have `SELECT` privilege if you only allow SELECT.
 * 3. **Disable multi-statement execution** in the database driver (e.g.
 *    `multipleStatements: false` in mysql2; default-off in psycopg2).
 * 4. **`argumentSchema` pattern constraint** — add a `pattern` on the `query`
 *    argument that anchors the verb at the start and rejects strings containing
 *    `;` or `/*`, e.g.:
 *    ```yaml
 *    argumentSchema:
 *      type: object
 *      properties:
 *        query:
 *          type: string
 *          pattern: '^SELECT\s.*'
 *          maxLength: 4096
 *    ```
 *    This is still regex-based and not a full SQL parser, but it eliminates the
 *    most common bypass shapes and provides a second independent gate.
 *
 * See `docs/prompt-injection-demo.md` for a full walkthrough of the
 * prompt-injection attack vector and defense layers.
 */
function extractSqlOperation(args: Record<string, unknown>): string | undefined {
  const candidates = ['sql', 'query', 'statement'];
  for (const key of candidates) {
    const val = args[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      const verb = val.trim().split(/\s+/)[0]?.toUpperCase();
      if (verb) {
        return verb;
      }
    }
  }
  return undefined;
}

/**
 * Attempt to extract a file path from the tool call arguments.
 *
 * Looks for common argument keys (`filePath`, `path`, `file`, `filename`).
 * Returns `undefined` when no recognisable path argument is found.
 */
function extractFilePath(args: Record<string, unknown>): string | undefined {
  const candidates = ['filePath', 'path', 'file', 'filename'];
  for (const key of candidates) {
    const val = args[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return val.trim();
    }
  }
  return undefined;
}

/**
 * Attempt to extract a list of recipient addresses from the tool call arguments.
 *
 * Recognises the common shapes tool authors use for message-routing arguments:
 *   - `to`         — a single address string or an array of address strings
 *   - `recipients` — a single address string or an array of address strings
 *   - `cc`         — a single address string or an array of address strings
 *   - `bcc`        — a single address string or an array of address strings
 *
 * All four fields are combined when present so that a `recipientDomain`
 * condition is enforced against every delivery target, not only the `to` list.
 *
 * Non-string values and empty/whitespace-only strings are silently ignored.
 * Returns `undefined` when no non-empty recipient strings are found across
 * all recognised fields (whether the fields are absent, empty strings,
 * arrays of non-strings, or any combination thereof).
 */
function extractRecipients(args: Record<string, unknown>): string[] | undefined {
  const recipients: string[] = [];

  const addField = (value: unknown): void => {
    if (typeof value === 'string' && value.trim().length > 0) {
      recipients.push(value.trim());
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.trim().length > 0) {
          recipients.push(item.trim());
        }
      }
    }
  };

  addField(args['to']);
  addField(args['recipients']);
  addField(args['cc']);
  addField(args['bcc']);

  return recipients.length > 0 ? recipients : undefined;
}

/**
 * Attempt to extract a list of table references from the tool call arguments.
 *
 * Looks for `table` (string) or `tables` (string | string[]) arguments.
 * Returns `undefined` when no recognisable table argument is found.
 */
function extractTables(
  args: Record<string, unknown>,
): Array<{ table: string; columns?: string[] }> | undefined {
  // Single table name
  if (typeof args['table'] === 'string' && args['table'].trim().length > 0) {
    return [{ table: args['table'].trim() }];
  }
  // Array of table names or table objects
  if (Array.isArray(args['tables'])) {
    const result: Array<{ table: string; columns?: string[] }> = [];
    for (const entry of args['tables']) {
      if (typeof entry === 'string' && entry.trim().length > 0) {
        result.push({ table: entry.trim() });
      } else if (
        entry !== null &&
        typeof entry === 'object' &&
        typeof (entry as { table?: unknown }).table === 'string'
      ) {
        const e = entry as { table: string; columns?: unknown };
        const row: { table: string; columns?: string[] } = { table: e.table };
        if (Array.isArray(e.columns) && e.columns.every((c) => typeof c === 'string')) {
          row.columns = e.columns as string[];
        }
        result.push(row);
      }
    }
    if (result.length > 0) return result;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Denial-code mapping
// ---------------------------------------------------------------------------

/**
 * Map a condition `type` string to a machine-readable denial code suitable
 * for the `PdpDecision.denialCode` field.
 */
function conditionTypeToDenialCode(conditionType: string): string {
  const MAP: Record<string, string> = {
    maxCalls: 'MAX_CALLS_EXCEEDED',
    timeWindow: 'TIME_WINDOW_DENIED',
    allowedOperations: 'OPERATION_NOT_ALLOWED',
    allowedExtensions: 'EXTENSION_NOT_ALLOWED',
    allowedTables: 'TABLE_NOT_ALLOWED',
    allowedValues: 'VALUE_NOT_ALLOWED',
    ipRange: 'IP_RANGE_DENIED',
    recipientDomain: 'RECIPIENT_DOMAIN_DENIED',
    policy: 'POLICY_BACKEND_DENIED',
  };
  return MAP[conditionType] ?? 'CONDITION_NOT_SATISFIED';
}

// ---------------------------------------------------------------------------
// Condition enforcement (two-tier ordered loop)
// ---------------------------------------------------------------------------

/**
 * Evaluation priority for known condition types — lower = earlier.
 * Mirrors the ordering in `enforceConditions` from @euno/common-core.
 */
const CONDITION_PRIORITY: Record<string, number> = {
  timeWindow: 0,
  ipRange: 1,
  allowedOperations: 2,
  allowedExtensions: 2,
  allowedTables: 2,
  recipientDomain: 2,
  allowedValues: 2,
  redactFields: 3,
  policy: 4,
  maxCalls: 5,
};
const CONDITION_PRIORITY_CUSTOM = 6;

/**
 * Enforce conditions in two-tier order (cheap/stateless before stateful).
 *
 * Returns either `{ allow: true }` or `{ allow: false, conditionType, reason }`.
 * The `conditionType` is taken directly from the condition's `type` field so
 * the denial code is always accurate — no reason-string parsing required.
 */
async function enforceConditionsWithType(
  conditions: readonly CapabilityCondition[],
  ctx: ConditionContext,
): Promise<{ allow: true } | { allow: false; conditionType: string; reason: string }> {
  // Stable two-tier sort preserving declaration order within each tier.
  const indexed = conditions.map((cond, i) => ({
    cond,
    originalIndex: i,
    priority: CONDITION_PRIORITY[cond.type] ?? CONDITION_PRIORITY_CUSTOM,
  }));
  indexed.sort((a, b) => a.priority - b.priority || a.originalIndex - b.originalIndex);

  for (const { cond, originalIndex } of indexed) {
    if (!cond) continue;
    // Scope the counter key by the original index so stable redeployments don't
    // silently reset maxCalls windows when reordering conditions.
    const scopedCtx: ConditionContext =
      cond.type === 'maxCalls' && ctx.counterKey
        ? { ...ctx, counterKey: `${ctx.counterKey}:${originalIndex}` }
        : ctx;
    // Note: counter keys are scoped by the condition's *original declaration
    // index* (not the sorted evaluation index), so counter windows remain
    // stable across re-deployments that add new stateless conditions before an
    // existing maxCalls entry. However, if two maxCalls conditions are
    // themselves reordered relative to each other their originalIndex values
    // change, which resets those counters. Policy authors should treat
    // maxCalls condition ordering as stable.

    const result = await enforceCondition(cond, scopedCtx);
    if (!result.allow) {
      return { allow: false, conditionType: cond.type, reason: result.reason };
    }
  }
  return { allow: true };
}

// ---------------------------------------------------------------------------
// ConditionEnforcerPDP
// ---------------------------------------------------------------------------

/**
 * Options for {@link ConditionEnforcerPDP}.
 */
export interface ConditionEnforcerPDPOptions {
  /**
   * The policy source to load the {@link AgentCapabilityManifest} from.
   * The manifest is loaded lazily on the first `decide()` call and refreshed
   * whenever the source's `watch()` notifies of a change.
   */
  policySource: LocalPolicySource;

  /**
   * Counter store used by `maxCalls` conditions.
   *
   * @default new InMemoryCallCounterStore()
   */
  counterStore?: CallCounterStore;

  /**
   * Kill-switch manager.  Call {@link ConditionEnforcerPDP.killSession} /
   * {@link ConditionEnforcerPDP.killAll} to activate.
   *
   * @default new DefaultKillSwitchManager()
   */
  killSwitchManager?: KillSwitchManager;
}

/**
 * Production PDP that enforces the loaded manifest via the shared
 * condition-registry from `@euno/common-core`.
 *
 * ## Manifest-to-tool mapping
 *
 * Each `CapabilityConstraint` in the manifest is matched against an MCP
 * `tools/call` by:
 *
 *   1. Checking that `actions` includes `"call"`.
 *   2. Comparing `resource` to the tool name, trying two forms:
 *      - the raw tool name (for exact-match and scheme-less patterns); then
 *      - the `mcp-tool://<toolName>` normalized form (for scheme-qualified
 *        patterns such as `mcp-tool://*` or `mcp-tool://**`).
 *
 * If no constraint matches the tool name the call is **allowed** (the manifest
 * only restricts explicitly named tools).
 *
 * ## Condition enforcement
 *
 * Conditions are evaluated in two-tier order (cheap stateless checks first,
 * stateful `maxCalls` last) via {@link enforceConditions}.  Unknown condition
 * types are denied at enforcement time as an additional defence-in-depth
 * measure (the {@link FilePolicySource} already rejects them at load time).
 *
 * ## Counter key format
 *
 * `<sessionId>|<toolName>|<resource>` — mirrors the
 * `IssuanceRateLimitSubject` shape used by the production gateway so a
 * Stage-3 counter-store swap-in is mechanical.
 *
 * ## Kill switch
 *
 * Call {@link killSession} with a session ID or `killAll()` to immediately
 * block all subsequent `tools/call` requests in that session / all sessions.
 * The block is in-memory only (not persisted across restarts).
 */
export class ConditionEnforcerPDP implements PolicyDecisionPoint {
  private readonly _policySource: LocalPolicySource;
  private readonly _counterStore: CallCounterStore;
  private readonly _killSwitch: KillSwitchManager;

  /** Cached manifest — refreshed via watch() on file change. */
  private _manifest: AgentCapabilityManifest | undefined;
  /**
   * Monotonically increasing generation counter.  Bumped by the watch()
   * callback.  Used to detect the race where a watch event fires while an
   * initial `load()` is in flight: the load's `.then()` only writes
   * `_manifest` when the generation it captured at call-site still matches
   * the current value, preventing a stale load from overwriting a newer
   * hot-reloaded manifest.
   */
  private _manifestGeneration = 0;
  /** Pending initial load promise — ensures we only load once concurrently. */
  private _loadPromise: Promise<AgentCapabilityManifest> | undefined;
  /** Unsubscribe handle for the file watcher. */
  private _unwatch?: () => void;

  constructor(opts: ConditionEnforcerPDPOptions) {
    this._policySource = opts.policySource;
    this._counterStore = opts.counterStore ?? new InMemoryCallCounterStore();
    this._killSwitch = opts.killSwitchManager ?? new DefaultKillSwitchManager();

    // Start watching for policy file changes so hot-reload works out-of-the-box.
    if (this._policySource.watch) {
      this._unwatch = this._policySource.watch(
        (updated) => {
          // Bump the generation before writing _manifest so any concurrent
          // in-flight _loadPromise will see the mismatch and skip its write.
          this._manifestGeneration++;
          this._manifest = updated;
          // Discard the pending load so the next decide() doesn't await a
          // stale promise from before the policy changed.
          this._loadPromise = undefined;
        },
        (err) => {
          process.stderr.write(
            `[euno-mcp] Policy reload error: ${err.stack ?? err.message}\n`,
          );
        },
      );
    }
  }

  /**
   * Immediately kill the given session.  All subsequent `tools/call` requests
   * from this session will be denied with `KILL_SWITCH`.
   */
  killSession(sessionId: string): void {
    this._killSwitch.killSession(sessionId);
  }

  /**
   * Activate the global kill switch — denies every `tools/call` regardless of
   * session.
   */
  killAll(): void {
    this._killSwitch.activateGlobalKill();
  }

  /**
   * Deactivate the global kill switch.  Per-session kills remain active.
   */
  reviveAll(): void {
    this._killSwitch.deactivateGlobalKill();
  }

  /**
   * Stop the file watcher (if any) started in the constructor.  Call when
   * shutting down the proxy to prevent resource leaks.
   */
  dispose(): void {
    this._unwatch?.();
  }

  /** @inheritdoc */
  async decide(request: CallToolRequest, ctx: PdpContext): Promise<PdpDecision> {
    // ── 1. Kill switch ────────────────────────────────────────────────────
    if (this._killSwitch.shouldBlock(ctx.sessionId)) {
      return {
        allow: false,
        reason: 'Session has been terminated by a kill-switch command',
        denialCode: 'KILL_SWITCH',
        conditionType: 'kill',
      };
    }

    // ── 2. Load manifest (lazy, cached) ───────────────────────────────────
    const manifest = await this._loadManifest();

    // ── 3. Find matching constraint ───────────────────────────────────────
    const toolName = request.params.name;
    const allConstraints: CapabilityConstraint[] = [
      ...manifest.requiredCapabilities,
      ...(manifest.optionalCapabilities ?? []),
    ];

    // Try the raw tool name first (supports exact match and scheme-less
    // patterns such as `resource: "query_db"`).  If nothing matches, retry
    // with the `mcp-tool://<toolName>` normalized form so that scheme-
    // qualified patterns (`resource: "mcp-tool://*"`) also work against
    // plain MCP tool names as they appear in real `tools/call` requests.
    let matched =
      findMatchingCapability<CapabilityConstraint>(MCP_TOOL_CALL_ACTION, toolName, allConstraints) ??
      findMatchingCapability<CapabilityConstraint>(
        MCP_TOOL_CALL_ACTION,
        `mcp-tool://${toolName}`,
        allConstraints,
      );

    if (!matched) {
      // No constraint for this tool → allow (manifest only restricts listed tools).
      return { allow: true };
    }

    // ── 4. Argument schema validation ─────────────────────────────────────
    // `request.params.arguments` is typed `Record<string, unknown> | undefined`
    // by the MCP SDK — coerce undefined to an empty object to simplify
    // downstream helpers that always receive a Record.
    const rawArgs: Record<string, unknown> = request.params.arguments ?? {};
    if (matched.argumentSchema) {
      try {
        validateArguments(rawArgs, matched.argumentSchema);
      } catch (err) {
        const reason =
          err instanceof Error ? err.message : 'Argument validation failed';
        const details: Record<string, unknown> | undefined =
          err instanceof ArgumentValidationError
            ? { path: err.path, expected: err.expected, got: err.got }
            : undefined;
        return {
          allow: false,
          reason,
          denialCode: 'ARGUMENT_VALIDATION_FAILED',
          conditionType: 'argumentSchema',
          details,
        };
      }
    }

    // ── 5. Condition enforcement ──────────────────────────────────────────
    if (matched.conditions && matched.conditions.length > 0) {
      // Counter key mirrors IssuanceRateLimitSubject: <sessionId>|<toolName>|<resource>
      const counterKey = `${ctx.sessionId}|${toolName}|${matched.resource}`;

      const conditionCtx: ConditionContext = {
        now: new Date(),
        counterStore: this._counterStore,
        counterKey,
        // Context fields extracted from tool arguments for stateless conditions
        operation: extractSqlOperation(rawArgs),
        filePath: extractFilePath(rawArgs),
        tables: extractTables(rawArgs),
        // Network-level context (populated by the HTTP transport; undefined for stdio)
        sourceIp: ctx.sourceIp,
        recipients: extractRecipients(rawArgs),
        customHandlers: getCustomConditionHandlers(),
      };

      const result = await enforceConditionsWithType(matched.conditions, conditionCtx);
      if (!result.allow) {
        return {
          allow: false,
          reason: result.reason,
          denialCode: conditionTypeToDenialCode(result.conditionType),
          conditionType: result.conditionType,
        };
      }
    }

    // Expose the matched constraint's conditions so the transport layer can
    // apply response-path obligations (e.g. redactFields) without re-matching.
    return {
      allow: true,
      matchedConditions:
        matched.conditions && matched.conditions.length > 0
          ? matched.conditions
          : undefined,
    };
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  /** Load the manifest, using the in-memory cache when available. */
  private async _loadManifest(): Promise<AgentCapabilityManifest> {
    if (this._manifest) {
      return this._manifest;
    }
    if (!this._loadPromise) {
      // Snapshot the generation so the .then() callback can detect if a
      // watch() update raced ahead while the load was in flight.
      const loadGeneration = this._manifestGeneration;
      this._loadPromise = this._policySource
        .load()
        .then((m) => {
          // Only cache when no watch() event has arrived since we started
          // loading.  If the generation moved, _manifest was already set by
          // the watch callback — keep that newer value.
          if (this._manifestGeneration === loadGeneration) {
            this._manifest = m;
          }
          this._loadPromise = undefined;
          // Return whichever manifest is authoritative (could be the watch-
          // loaded one if the generation advanced).
          return this._manifest ?? m;
        })
        .catch((err) => {
          this._loadPromise = undefined;
          throw err;
        });
    }
    return this._loadPromise;
  }
}

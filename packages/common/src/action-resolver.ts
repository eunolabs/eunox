/**
 * ActionResolver — pluggable HTTP/tool → action mapping plus
 * data-driven Conditional-Access tiering.
 *
 * Implements R-7 from `docs/IMPROVEMENTS_AND_REFACTORING.md` (addresses
 * I-4 and I-5):
 *
 *   * I-4: the tool-gateway used to derive a capability action from a
 *     fixed `{ GET: 'read', POST: 'write', ... }` table inlined into
 *     `routes/proxy.ts`. Backends that use POST for read-style RPC
 *     (GraphQL, search, SDKs that disable GET-with-body) were
 *     consequently over-authorised as `write`.
 *   * I-5: the capability-issuer used to coerce arbitrary action
 *     strings to a {@link CaActionTier} via substring matching
 *     (`a.includes('write')`, `a.includes('delete')`, …). Custom
 *     verbs like `forward_delete_request` would land in the wrong CA
 *     tier as a side effect.
 *
 * This module replaces both call sites with a single, pluggable
 * {@link ActionResolver} interface plus a {@link DefaultActionResolver}
 * implementation that:
 *
 *   * preserves the legacy behaviour for the HTTP method table and
 *     the in-process tool registry, and
 *   * exposes an explicit, declarative per-action → tier table (no
 *     substring matching), with operator-overridable defaults loaded
 *     from a JSON config file via {@link loadActionResolverFromFile}.
 *
 * Keeping the resolver in `@euno/common` lets the issuer and the
 * gateway share a single configuration source so a deployment-specific
 * verb (e.g. `db:select`) is mapped consistently at mint time and at
 * enforcement time.
 */

import * as fs from 'fs';
import * as path from 'path';

import type { Action, CaActionTier } from './types';
import { canonicalSha256 } from './utils';

// Re-export so consumers can import the pair from one place.
export type { Action, CaActionTier };

/**
 * The full set of CA tiers the issuer enforces, in escalating
 * privilege order. Centralised here so `DefaultActionResolver` and
 * file-loaded resolvers can validate operator-supplied tier strings
 * against a single list.
 */
export const CA_ACTION_TIERS = ['read', 'write', 'delete', 'admin'] as const satisfies readonly CaActionTier[];

/**
 * Inputs to {@link ActionResolver.fromHttpRequest}. Modelled as a
 * small struct (rather than the raw express `Request`) so the
 * resolver can be unit-tested without an HTTP runtime and so the
 * interface stays usable by non-Express transports (e.g. fastify,
 * gRPC-gateway shims).
 */
export interface ActionResolverHttpInput {
  /** Uppercase HTTP method, e.g. `GET`, `POST`. */
  method: string;
  /**
   * The post-mount path the gateway saw for the request. The default
   * resolver does not introspect the path; a deployment-specific
   * resolver may use it to discriminate (e.g. by resource prefix).
   */
  path: string;
  /**
   * The parsed JSON request body when available. Optional because the
   * gateway invokes the resolver before any body parsing for some
   * routes; the default resolver does not consult it.
   */
  body?: unknown;
  /** Lower-cased header bag. The default resolver does not consult it. */
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * Inputs to {@link ActionResolver.fromToolInvocation}. The tool
 * gateway derives the action server-side from the named tool (never
 * from a client-supplied action) — see `routes/tools.ts`.
 */
export interface ActionResolverToolInput {
  /** Server-recognised tool name, e.g. `read_file`, `http_post`. */
  tool: string;
  /** Parsed argument bag, when present. The default resolver does not consult it. */
  args?: unknown;
}

/**
 * Resolver contract used by both the gateway (HTTP/tool → action) and
 * the issuer (action → CA tier). Implementations must be pure with
 * respect to their inputs so callers can cache them across requests.
 */
export interface ActionResolver {
  /** Derive the capability action for an inbound HTTP request. */
  fromHttpRequest(input: ActionResolverHttpInput): Action;
  /** Derive the capability action for an inbound `/api/v1/tools/invoke` call. */
  fromToolInvocation(input: ActionResolverToolInput): Action;
  /**
   * Map an action to its Conditional-Access tier. Used by the
   * capability-issuer to enforce CA at issuance time. Implementations
   * MUST return a tier from {@link CA_ACTION_TIERS}.
   */
  toCaTier(action: Action): CaActionTier;
}

/**
 * Declarative, immutable configuration for {@link DefaultActionResolver}.
 * Operators supply this either programmatically or via a JSON file
 * loaded with {@link loadActionResolverFromFile}.
 */
export interface ActionResolverConfig {
  /**
   * HTTP method → action. Methods are matched case-insensitively. When
   * the inbound method is missing from the map the resolver falls back
   * to {@link defaultHttpAction}.
   */
  httpMethodActions?: Record<string, Action>;
  /**
   * Action returned when the HTTP method is not in
   * {@link httpMethodActions}. Defaults to `'read'` (the safest
   * generic verb for an unrecognised method).
   */
  defaultHttpAction?: Action;
  /**
   * Tool name → action. Tools are matched case-sensitively (tool
   * names are server-controlled identifiers). When the tool is
   * missing from the map the resolver returns {@link defaultToolAction}.
   */
  toolActions?: Record<string, Action>;
  /**
   * Action returned when a tool name is not in {@link toolActions}.
   * Defaults to `'execute'`, the most restrictive of the legacy
   * actions, so an unknown tool fails closed at the CA tier.
   */
  defaultToolAction?: Action;
  /**
   * Action → CA tier. Each entry is an exact, case-insensitive match
   * (e.g. `"db:select": "read"`). Unknown actions fall back to
   * {@link defaultTier}. Replaces the previous substring-matching
   * heuristic.
   */
  actionTiers?: Record<string, CaActionTier>;
  /**
   * CA tier returned for an action absent from {@link actionTiers}.
   * Defaults to `'read'`, matching the previous behaviour for
   * un-categorised actions. Set to `'admin'` for fail-closed CA
   * enforcement against unknown verbs.
   */
  defaultTier?: CaActionTier;
}

/**
 * Built-in HTTP method → action map. Matches the table previously
 * inlined in `tool-gateway/src/routes/proxy.ts`.
 */
export const DEFAULT_HTTP_METHOD_ACTIONS: Readonly<Record<string, Action>> = Object.freeze({
  GET: 'read',
  HEAD: 'read',
  OPTIONS: 'read',
  POST: 'write',
  PUT: 'write',
  PATCH: 'write',
  DELETE: 'delete',
});

/**
 * Built-in tool name → action map. Lifted from the previous
 * `TOOL_ACTION_REGISTRY` in `tool-gateway/src/routes/tools.ts` so
 * gateway and issuer can share a single source of truth.
 */
export const DEFAULT_TOOL_ACTIONS: Readonly<Record<string, Action>> = Object.freeze({
  // File operations
  read_file: 'read',
  get_file: 'read',
  list_files: 'read',
  list_directory: 'read',
  write_file: 'write',
  create_file: 'write',
  update_file: 'write',
  append_file: 'write',
  delete_file: 'delete',
  remove_file: 'delete',
  // HTTP/API operations
  http_get: 'read',
  http_post: 'write',
  http_put: 'write',
  http_delete: 'delete',
  // Code execution
  run_code: 'execute',
  execute_command: 'execute',
  run_shell: 'execute',
});

/**
 * Built-in action → CA tier table. Replaces the previous
 * substring-matching heuristic in `actionToCaTier` with an explicit,
 * exhaustive listing of every action that participates in the default
 * role mapping plus a curated set of resource-specific verbs that
 * production deployments commonly use. Operators can extend or
 * override this table via {@link loadActionResolverFromFile}.
 */
export const DEFAULT_ACTION_CA_TIERS: Readonly<Record<string, CaActionTier>> = Object.freeze({
  // Generic legacy verbs ----------------------------------------------------
  read: 'read',
  write: 'write',
  execute: 'write',
  delete: 'delete',
  admin: 'admin',
  // Common resource-specific verbs ------------------------------------------
  // Database
  'db:select': 'read',
  'db:insert': 'write',
  'db:update': 'write',
  'db:upsert': 'write',
  'db:delete': 'delete',
  'db:truncate': 'delete',
  'db:drop': 'delete',
  'db:grant': 'admin',
  'db:revoke': 'admin',
  // Object storage
  's3:getObject': 'read',
  's3:listBucket': 'read',
  's3:putObject': 'write',
  's3:copyObject': 'write',
  's3:deleteObject': 'delete',
  's3:putBucketPolicy': 'admin',
  // Pub/sub
  'kafka:consume': 'read',
  'kafka:publish': 'write',
  'pubsub:publish': 'write',
  'pubsub:subscribe': 'read',
});

/**
 * Default resolver. Reproduces the legacy gateway/issuer behaviour
 * exactly when constructed with no arguments. Operator-supplied
 * `config` entries are *merged* with the built-in maps (operator
 * entries win), so a deployment-specific verb only needs to declare
 * the rows that differ.
 */
export class DefaultActionResolver implements ActionResolver {
  private readonly httpMethodActions: Record<string, Action>;
  private readonly defaultHttpAction: Action;
  private readonly toolActions: Record<string, Action>;
  private readonly defaultToolAction: Action;
  private readonly actionTiers: Record<string, CaActionTier>;
  private readonly defaultTier: CaActionTier;

  constructor(config: ActionResolverConfig = {}) {
    // HTTP method keys are normalised to upper-case at construction
    // time so lookups can use the inbound method verbatim without
    // re-uppercasing per request.
    this.httpMethodActions = uppercaseKeys({
      ...DEFAULT_HTTP_METHOD_ACTIONS,
      ...(config.httpMethodActions ?? {}),
    });
    this.defaultHttpAction = config.defaultHttpAction ?? 'read';

    this.toolActions = {
      ...DEFAULT_TOOL_ACTIONS,
      ...(config.toolActions ?? {}),
    };
    this.defaultToolAction = config.defaultToolAction ?? 'execute';

    this.actionTiers = lowercaseKeys({
      ...DEFAULT_ACTION_CA_TIERS,
      ...(config.actionTiers ?? {}),
    });
    this.defaultTier = config.defaultTier ?? 'read';
  }

  fromHttpRequest(input: ActionResolverHttpInput): Action {
    const method = (input.method ?? '').toUpperCase();
    return this.httpMethodActions[method] ?? this.defaultHttpAction;
  }

  fromToolInvocation(input: ActionResolverToolInput): Action {
    return this.toolActions[input.tool] ?? this.defaultToolAction;
  }

  toCaTier(action: Action): CaActionTier {
    return this.actionTiers[action.toLowerCase()] ?? this.defaultTier;
  }
}

/**
 * Singleton built-in resolver shared by call sites that have not been
 * configured with an explicit operator-supplied resolver.
 */
export const BUILTIN_ACTION_RESOLVER: ActionResolver = new DefaultActionResolver();

/**
 * Validate an arbitrary parsed JSON value into an
 * {@link ActionResolverConfig}. Exposed separately so deployments
 * that fetch resolver configuration from a config service (Consul,
 * App Config, etc.) can reuse the same validation as the file
 * loader.
 */
export function validateActionResolverConfig(value: unknown): ActionResolverConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error("action resolver config: must be a JSON object");
  }
  const obj = value as Record<string, unknown>;
  const out: ActionResolverConfig = {};

  if (obj.httpMethodActions !== undefined) {
    out.httpMethodActions = validateActionMap(obj.httpMethodActions, 'httpMethodActions');
  }
  if (obj.defaultHttpAction !== undefined) {
    out.defaultHttpAction = validateActionString(obj.defaultHttpAction, 'defaultHttpAction');
  }
  if (obj.toolActions !== undefined) {
    out.toolActions = validateActionMap(obj.toolActions, 'toolActions');
  }
  if (obj.defaultToolAction !== undefined) {
    out.defaultToolAction = validateActionString(obj.defaultToolAction, 'defaultToolAction');
  }
  if (obj.actionTiers !== undefined) {
    out.actionTiers = validateActionTierMap(obj.actionTiers, 'actionTiers');
  }
  if (obj.defaultTier !== undefined) {
    out.defaultTier = validateCaTier(obj.defaultTier, 'defaultTier');
  }
  return out;
}

/**
 * Load a {@link DefaultActionResolver} from a JSON file on disk.
 * Throws if the file is missing, unparseable, or fails schema
 * validation so misconfigured deployments fail fast at startup
 * rather than serving with the wrong action mappings.
 */
export function loadActionResolverFromFile(filePath: string): DefaultActionResolver {
  const resolved = path.resolve(filePath);
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(
      `Failed to read action resolver config '${resolved}': ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Action resolver config '${resolved}' is not valid JSON: ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  return new DefaultActionResolver(validateActionResolverConfig(parsed));
}

/**
 * Compute a stable, canonical SHA-256 hex digest of an
 * {@link ActionResolverConfig} (or `null` when no
 * operator-supplied file is configured).
 *
 * **Scope**: only the operator-supplied overrides are digested — the
 * built-in {@link DEFAULT_HTTP_METHOD_ACTIONS}, {@link DEFAULT_TOOL_ACTIONS}
 * and {@link DEFAULT_ACTION_CA_TIERS} constants are the same in every
 * deployment and do not need to be part of the fingerprint.  Two services
 * using the *same* operator-supplied file therefore produce the same hash
 * regardless of the runtime or the Node.js version, while any difference in
 * the operator config (including a missing file on one side) is immediately
 * visible.
 *
 * **`null` and `{}` are treated as semantically equivalent** — both mean
 * "no operator overrides; use built-in defaults only".  A service with no
 * `ACTION_RESOLVER_FILE` configured will therefore produce the same hash as
 * a service configured with an empty `{}` file, and the two are treated as
 * in agreement by the parity check.
 *
 * **Algorithm**: {@link canonicalSha256} (sorted-key JSON → SHA-256 hex) so
 * the digest is deterministic across JS runtimes and matches any out-of-band
 * operator tool that implements the same algorithm.
 *
 * The sentinel value `null` represents "no operator file configured; use
 * built-in defaults only".  Callers that load an operator file MUST pass the
 * validated {@link ActionResolverConfig} object (which may be `{}` for an
 * empty file).
 */
export function computeActionResolverHash(config: ActionResolverConfig | null): string {
  // null and {} are semantically equivalent ("no operator overrides") so we
  // coalesce null to {} before hashing, ensuring both sides of the parity
  // check agree even when one service has no ACTION_RESOLVER_FILE configured
  // and the other has an explicitly empty one.
  return canonicalSha256(config ?? {});
}

/**
 * Result of {@link loadActionResolverFromFileWithHash}: both the ready-to-use
 * resolver and the canonical digest of the operator config it was built from.
 */
export interface ActionResolverWithHash {
  resolver: DefaultActionResolver;
  /**
   * Canonical SHA-256 hex digest of the operator-supplied
   * {@link ActionResolverConfig}.  Produced by
   * {@link computeActionResolverHash} and suitable for cross-service
   * comparison (issuer vs gateway) and for embedding in the issuer's
   * `/.well-known/capability-issuer` discovery document.
   */
  hash: string;
}

/**
 * Load a {@link DefaultActionResolver} from a JSON file on disk and return
 * both the resolver and the canonical {@link computeActionResolverHash}
 * of the validated config.  Identical to {@link loadActionResolverFromFile}
 * except that callers receive the hash without a second file read.
 */
export function loadActionResolverFromFileWithHash(filePath: string): ActionResolverWithHash {
  const resolved = path.resolve(filePath);
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(
      `Failed to read action resolver config '${resolved}': ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Action resolver config '${resolved}' is not valid JSON: ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  const config = validateActionResolverConfig(parsed);
  return {
    resolver: new DefaultActionResolver(config),
    hash: computeActionResolverHash(config),
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function validateActionString(value: unknown, contextPath: string): Action {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`action resolver config: '${contextPath}' must be a non-empty string`);
  }
  return value;
}

function validateActionMap(value: unknown, contextPath: string): Record<string, Action> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(
      `action resolver config: '${contextPath}' must be an object mapping keys to action strings`,
    );
  }
  const out: Record<string, Action> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = validateActionString(v, `${contextPath}.${k}`);
  }
  return out;
}

function validateActionTierMap(
  value: unknown,
  contextPath: string,
): Record<string, CaActionTier> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(
      `action resolver config: '${contextPath}' must be an object mapping action strings to CA tiers`,
    );
  }
  const out: Record<string, CaActionTier> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = validateCaTier(v, `${contextPath}.${k}`);
  }
  return out;
}

function validateCaTier(value: unknown, contextPath: string): CaActionTier {
  if (typeof value !== 'string' || !(CA_ACTION_TIERS as readonly string[]).includes(value)) {
    throw new Error(
      `action resolver config: '${contextPath}' must be one of ${CA_ACTION_TIERS.join(', ')} ` +
        `(got '${String(value)}')`,
    );
  }
  return value as CaActionTier;
}

function uppercaseKeys<T>(obj: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(obj)) out[k.toUpperCase()] = v;
  return out;
}

function lowercaseKeys<T>(obj: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}

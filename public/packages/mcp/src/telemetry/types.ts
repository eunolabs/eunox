/**
 * Shared types for the @euno/mcp telemetry module.
 *
 * These types are imported by both the transport layer (to declare the hook
 * interface on proxy options) and the telemetry module itself (to build and
 * emit events).  Keeping them in a single file avoids circular dependencies.
 *
 * @module
 */

// ---------------------------------------------------------------------------
// Telemetry event
// ---------------------------------------------------------------------------

/** Broad OS family — coarser than `process.platform` to avoid fingerprinting. */
export type OsFamily = 'linux' | 'darwin' | 'win32' | 'other';

/**
 * One telemetry event per CLI invocation.
 *
 * All fields are either non-sensitive scalars or pre-sanitized strings.
 * No tool names, argument values, file paths, SQL fragments, or any payload
 * content is ever included.
 */
export interface TelemetryEvent {
  /** Anonymous per-install UUID, generated once and persisted to ~/.euno/telemetry. */
  readonly installId: string;
  /** Package version (e.g. "1.0.0"). */
  readonly version: string;
  /** Broad OS family. */
  readonly osFamily: OsFamily;
  /** Major Node.js version number (e.g. 20). */
  readonly nodeMajor: number;
  /** CLI subcommand that was invoked. */
  readonly subcommand: 'proxy' | 'validate' | 'kill' | 'validate-token' | 'stats';
  /**
   * Number of MCP sessions started in this invocation.
   * For stdio proxy: always 1 (one process = one session).
   * For HTTP proxy: number of initialize→shutdown cycles.
   */
  readonly sessionsStarted: number;
  /**
   * Number of those sessions that had at least one enforcement event
   * (allow or deny decision by the PDP).
   */
  readonly sessionsWithEnforcement: number;
  /**
   * Total denial counts per condition type across all sessions.
   * Keys are CapabilityCondition.type values (e.g. "maxCalls", "timeWindow")
   * or special types "argumentSchema" and "kill".
   */
  readonly denialsByConditionType: Readonly<Record<string, number>>;
  /**
   * Sanitized name of the upstream MCP server.
   * Set to a well-known OSS server name when the command matches a recognized
   * package; "custom" otherwise.  Never includes file paths or arguments.
   */
  readonly upstreamServerName: string;
  /** Unix epoch milliseconds when the event was emitted. */
  readonly timestamp: number;
}

/**
 * Ordered tuple of all {@link TelemetryEvent} field names.
 *
 * Used by tests to verify that TELEMETRY.md documents every field and to
 * catch additions or removals via snapshot.
 */
export const TELEMETRY_EVENT_KEYS: ReadonlyArray<keyof TelemetryEvent> = [
  'installId',
  'version',
  'osFamily',
  'nodeMajor',
  'subcommand',
  'sessionsStarted',
  'sessionsWithEnforcement',
  'denialsByConditionType',
  'upstreamServerName',
  'timestamp',
] as const;

// ---------------------------------------------------------------------------
// Telemetry hooks (minimal interface added to transport options)
// ---------------------------------------------------------------------------

/**
 * Lifecycle callbacks that transport layers call to feed per-session metrics
 * to the telemetry collector.
 *
 * All methods are optional — callers use optional-chaining (`hook?.method?.()`)
 * so a partial implementation is safe.
 */
export interface TelemetryHooks {
  /**
   * Called once when a new MCP session starts (after the proxy server is
   * connected to the host transport).
   */
  onSessionStart?(): void;
  /**
   * Called for each `tools/call` enforcement decision.
   *
   * @param allowed       Whether the call was permitted.
   * @param conditionType The condition type that caused the denial (e.g.
   *   `"maxCalls"`, `"timeWindow"`, `"kill"`).  Only present when
   *   `allowed` is `false`.
   */
  onDecision?(allowed: boolean, conditionType?: string): void;
  /**
   * Called once when the session ends (upstream process exited or client
   * disconnected).
   */
  onSessionEnd?(): void;
  /**
   * Optional factory for creating independent per-session hook instances.
   *
   * The HTTP proxy supports multiple concurrent sessions.  When this method is
   * present it is called once per session (in `_createSession`) to get a fresh
   * hook set whose `hadEnforcement` flag is isolated from all other sessions.
   * The stdio proxy always has exactly one session, so it can use the hooks
   * object directly without calling this factory.
   */
  createSessionHooks?(): TelemetryHooks;
}

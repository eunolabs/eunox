/**
 * Gateway hosted-mode telemetry — Task 16 (Telemetry continuity)
 * ---------------------------------------------------------------------------
 * Emits server-side, per-tenant enforcement analytics to the same telemetry
 * backend used by `@euno/mcp` in local mode so Stage 1–2 dashboards remain
 * valid without schema changes.
 *
 * The emitted JSON matches the `TelemetryEvent` schema from `@euno/mcp`
 * (same field names, same types). The sole addition is
 * `subcommand: 'hosted-enforce'` which identifies gateway-originated rows.
 * Dashboard queries can filter or group on that field to separate client-side
 * from server-side events.
 *
 * Privacy model
 * -------------
 * - `installId` = `'tenant:' + tenantId` — identifies the tenant, not any
 *   individual user or session. No user IDs, session IDs, tool names, or
 *   argument values are emitted.
 * - `denialsByConditionType` keys are condition type names (e.g. `"maxCalls"`,
 *   `"timeWindow"`). No tool names or request content.
 * - `peakConcurrentSessions` is a privacy-preserving team-size signal: the
 *   max number of distinct MCP session IDs observed simultaneously within a
 *   60-second window during the reporting interval.
 *
 * Opt-out
 * -------
 * `EUNO_TELEMETRY=0` — disables server-side telemetry entirely. All hooks
 * become no-ops. Default: enabled (the gateway operator controls this env var;
 * there is no interactive prompt).
 *
 * Configuration
 * -------------
 * | Env var                           | Default                                     |
 * | --------------------------------- | ------------------------------------------- |
 * | `EUNO_TELEMETRY`                  | (unset = enabled; `0` = disabled)           |
 * | `EUNO_TELEMETRY_URL`              | `https://telemetry.euno.dev/v1/events`      |
 * | `GATEWAY_TELEMETRY_FLUSH_MS`      | `300000` (5 minutes)                        |
 *
 * @module
 */

import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default telemetry endpoint — matches the local-mode client. */
const DEFAULT_TELEMETRY_ENDPOINT = 'https://telemetry.euno.dev/v1/events';

/** Default reporting window in milliseconds (5 minutes). */
const DEFAULT_FLUSH_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Seconds within which two enforce requests on different sessions are
 * considered "concurrent" for the `peakConcurrentSessions` computation.
 * 60 s mirrors the typical MCP session handshake timeout.
 */
const CONCURRENCY_WINDOW_MS = 60_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * JSON shape emitted per tenant per reporting window.
 *
 * Field names are identical to `TelemetryEvent` in `@euno/mcp` so the same
 * telemetry-backend schema and dashboards work without modification. The
 * gateway does not import `@euno/mcp` (that would invert the dependency
 * direction), so this is an independent structural type kept in sync
 * manually — any schema change to `TelemetryEvent` MUST be reflected here.
 */
export interface GatewayTelemetryEvent {
  /** `'tenant:' + tenantId` — identifies the tenant; never a user or session. */
  readonly installId: string;
  /** Installed gateway package version. */
  readonly version: string;
  /** Broad OS family of the gateway host. */
  readonly osFamily: 'linux' | 'darwin' | 'win32' | 'other';
  /** Major Node.js version on the gateway host. */
  readonly nodeMajor: number;
  /**
   * Always `'hosted-enforce'` for gateway-originated events.
   * Matches the new value added to `TelemetryEvent.subcommand` in `@euno/mcp`.
   */
  readonly subcommand: 'hosted-enforce';
  /** Unique MCP session IDs seen during this reporting window for this tenant. */
  readonly sessionsStarted: number;
  /** Sessions that had at least one enforcement decision (allow or deny). */
  readonly sessionsWithEnforcement: number;
  /** Per-condition-type denial counts. Keys match `CapabilityCondition.type`. */
  readonly denialsByConditionType: Readonly<Record<string, number>>;
  /**
   * Maximum number of sessions simultaneously active during the window.
   * "Simultaneous" = two sessions whose most recent requests fell within
   * `CONCURRENCY_WINDOW_MS` (60 s) of each other. Privacy-preserving
   * team-size signal; no user IDs or IP addresses are included.
   */
  readonly peakConcurrentSessions: number;
  /** Always `'gateway'` — the server has no client-facing upstream command. */
  readonly upstreamServerName: 'gateway';
  /** Unix epoch milliseconds at flush time. */
  readonly timestamp: number;
}

/**
 * Minimal hook interface passed to the enforce route.
 *
 * Kept narrow so the route does not need to import the full collector class.
 */
export interface GatewayTelemetryHooks {
  /**
   * Record one enforcement decision from the `/api/v1/enforce` route.
   *
   * @param tenantId       Tenant identifier from the JWT's `authorizedBy.tenantId`
   *                       claim. Use `'unknown'` when the token is malformed.
   * @param sessionId      MCP session ID from the enforce request body.
   * @param allowed        Whether the gateway allowed the action.
   * @param conditionType  Condition type that caused a denial (e.g. `'maxCalls'`).
   *                       Only meaningful when `allowed` is `false`.
   */
  recordDecision(
    tenantId: string,
    sessionId: string,
    allowed: boolean,
    conditionType?: string,
  ): void;
}

// ---------------------------------------------------------------------------
// Internal per-tenant state
// ---------------------------------------------------------------------------

interface PerTenantState {
  /** All session IDs seen in the current window. */
  sessionIds: Set<string>;
  /** Denial counts keyed by condition type. */
  denialsByConditionType: Record<string, number>;
  /**
   * Recent (sessionId, timestampMs) pairs used to compute peak concurrency.
   * Entries older than `CONCURRENCY_WINDOW_MS` from the most recent entry
   * are pruned on each update.
   */
  recentActivity: Array<{ sessionId: string; timestampMs: number }>;
  /** Running peak: max count of sessions within any 60-s window observed so far. */
  peakConcurrent: number;
}

// ---------------------------------------------------------------------------
// GatewayTelemetryCollector
// ---------------------------------------------------------------------------

/**
 * Per-tenant telemetry collector for the hosted gateway.
 *
 * One instance is shared across all enforce requests. Callers obtain the
 * {@link GatewayTelemetryHooks} interface via {@link hooks} and pass it to
 * the enforce route factory so the route can record decisions without
 * depending on the collector directly.
 *
 * Call {@link start} once at gateway startup to begin the periodic flush.
 * Call {@link stop} on shutdown to clear the flush timer and emit a final
 * event for any pending tenant stats.
 */
export class GatewayTelemetryCollector implements GatewayTelemetryHooks {
  private readonly _tenantState = new Map<string, PerTenantState>();
  private _flushTimer: ReturnType<typeof setInterval> | null = null;
  private readonly _endpointUrl: string;
  private readonly _version: string;
  private readonly _osFamily: GatewayTelemetryEvent['osFamily'];
  private readonly _nodeMajor: number;
  private readonly _disabled: boolean;

  constructor(options: {
    endpointUrl?: string;
    version?: string;
    disabled?: boolean;
  } = {}) {
    this._disabled = options.disabled ?? false;
    this._endpointUrl = options.endpointUrl ?? DEFAULT_TELEMETRY_ENDPOINT;
    this._version = options.version ?? _getVersion();
    this._osFamily = _getOsFamily();
    this._nodeMajor = _getNodeMajor();
  }

  // ── GatewayTelemetryHooks ─────────────────────────────────────────────────

  /** Record one enforcement decision for a given tenant and session. */
  recordDecision(
    tenantId: string,
    sessionId: string,
    allowed: boolean,
    conditionType?: string,
  ): void {
    if (this._disabled) return;

    const state = this._getOrCreateState(tenantId);
    const nowMs = Date.now();

    // Track unique sessions.
    state.sessionIds.add(sessionId);

    // Track denials by condition type.
    if (!allowed) {
      const key = conditionType ?? 'unknown';
      state.denialsByConditionType[key] = (state.denialsByConditionType[key] ?? 0) + 1;
    }

    // Update concurrency window.
    state.recentActivity.push({ sessionId, timestampMs: nowMs });
    this._updatePeakConcurrent(state, nowMs);
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Start the periodic flush timer.
   *
   * @param intervalMs Flush interval in milliseconds. Defaults to
   *   {@link DEFAULT_FLUSH_INTERVAL_MS} (5 minutes).
   */
  start(intervalMs: number = DEFAULT_FLUSH_INTERVAL_MS): void {
    if (this._disabled) return;
    if (this._flushTimer !== null) return; // already started

    this._flushTimer = setInterval(() => {
      void this.flush();
    }, intervalMs);
    // Prevent the timer from keeping the Node process alive on its own.
    if (typeof this._flushTimer.unref === 'function') {
      this._flushTimer.unref();
    }
  }

  /**
   * Stop the flush timer and flush any pending tenant stats.
   *
   * Safe to call multiple times; subsequent calls are no-ops.
   */
  async stop(): Promise<void> {
    if (this._flushTimer !== null) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    // Flush remaining data even on shutdown — best effort.
    await this.flush();
  }

  /**
   * Build and emit one {@link GatewayTelemetryEvent} per active tenant, then
   * reset per-tenant state.
   *
   * Errors are silently discarded so a telemetry failure never propagates
   * to the enforcement path.
   */
  async flush(): Promise<void> {
    if (this._disabled) return;

    const activeTenants = Array.from(this._tenantState.keys());
    for (const tenantId of activeTenants) {
      const state = this._tenantState.get(tenantId);
      if (!state || state.sessionIds.size === 0) continue;

      const event: GatewayTelemetryEvent = {
        installId: `tenant:${tenantId}`,
        version: this._version,
        osFamily: this._osFamily,
        nodeMajor: this._nodeMajor,
        subcommand: 'hosted-enforce',
        sessionsStarted: state.sessionIds.size,
        sessionsWithEnforcement: state.sessionIds.size,
        denialsByConditionType: { ...state.denialsByConditionType },
        peakConcurrentSessions: state.peakConcurrent,
        upstreamServerName: 'gateway',
        timestamp: Date.now(),
      };

      // Reset state for the next window.
      this._tenantState.delete(tenantId);

      // Emit without awaiting — fire-and-forget so errors never block shutdown.
      this._emit(event).catch(() => { /* silent */ });
    }
  }

  /**
   * Expose the collector as a {@link GatewayTelemetryHooks} without revealing
   * the full class interface. Pass the returned reference to
   * {@link createEnforceRouter}.
   */
  get hooks(): GatewayTelemetryHooks {
    return this;
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private _getOrCreateState(tenantId: string): PerTenantState {
    let state = this._tenantState.get(tenantId);
    if (!state) {
      state = {
        sessionIds: new Set(),
        denialsByConditionType: {},
        recentActivity: [],
        peakConcurrent: 0,
      };
      this._tenantState.set(tenantId, state);
    }
    return state;
  }

  /**
   * Prune activity entries older than `CONCURRENCY_WINDOW_MS` from the most
   * recent entry, then update the running peak with the number of distinct
   * session IDs remaining in the window.
   */
  private _updatePeakConcurrent(state: PerTenantState, nowMs: number): void {
    const cutoff = nowMs - CONCURRENCY_WINDOW_MS;
    // Keep only entries within the window.
    state.recentActivity = state.recentActivity.filter((e) => e.timestampMs >= cutoff);
    // Distinct sessions within the window.
    const activeSessionIds = new Set(state.recentActivity.map((e) => e.sessionId));
    const concurrent = activeSessionIds.size;
    if (concurrent > state.peakConcurrent) {
      state.peakConcurrent = concurrent;
    }
  }

  private async _emit(event: GatewayTelemetryEvent): Promise<void> {
    try {
      const fetchFn =
        typeof globalThis.fetch === 'function'
          ? (globalThis.fetch as typeof fetch)
          : null;
      if (!fetchFn) return; // Node < 18 without polyfill — silently skip.

      await fetchFn(this._endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      // Telemetry errors are intentionally swallowed — they must never
      // affect the enforcement hot path or gateway startup/shutdown.
      // Matching the local-mode client: HttpTelemetryEmitter also discards
      // errors silently to preserve the same guarantee for operators who
      // route telemetry through an unreliable or off-by-default endpoint.
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build a {@link GatewayTelemetryCollector} from environment variables and
 * start its flush timer.
 *
 * Returns `null` when `EUNO_TELEMETRY=0` so callers can short-circuit without
 * creating an object.
 */
export function createGatewayTelemetryFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): GatewayTelemetryCollector | null {
  if (env['EUNO_TELEMETRY'] === '0') {
    return null;
  }

  const endpointUrl =
    env['EUNO_TELEMETRY_URL'] ?? DEFAULT_TELEMETRY_ENDPOINT;

  const flushIntervalMs = (() => {
    const raw = env['GATEWAY_TELEMETRY_FLUSH_MS'];
    if (raw === undefined) return DEFAULT_FLUSH_INTERVAL_MS;
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_FLUSH_INTERVAL_MS;
  })();

  const collector = new GatewayTelemetryCollector({ endpointUrl });
  collector.start(flushIntervalMs);
  return collector;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the tenant ID from a raw JWT token string without verifying the
 * signature. Used exclusively for telemetry routing — never for authorization.
 *
 * Returns `'unknown'` when the token is malformed or does not carry the
 * `authorizedBy.tenantId` claim.
 */
export function extractTenantIdFromToken(token: string): string {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return 'unknown';
    const raw = Buffer.from(parts[1] as string, 'base64url').toString('utf8');
    const payload = JSON.parse(raw) as Record<string, unknown>;
    const authorizedBy = payload['authorizedBy'] as Record<string, unknown> | undefined;
    const tenantId = authorizedBy?.['tenantId'];
    return typeof tenantId === 'string' && tenantId.length > 0 ? tenantId : 'unknown';
  } catch {
    return 'unknown';
  }
}

// ---------------------------------------------------------------------------
// Runtime helpers (intentionally not imported from @euno/common to keep the
// module self-contained and dependency-free)
// ---------------------------------------------------------------------------

function _getVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require('../../package.json') as { version: string };
    return pkg.version;
  } catch {
    return 'unknown';
  }
}

function _getOsFamily(): GatewayTelemetryEvent['osFamily'] {
  const p = os.platform();
  if (p === 'linux') return 'linux';
  if (p === 'darwin') return 'darwin';
  if (p === 'win32') return 'win32';
  return 'other';
}

function _getNodeMajor(): number {
  const match = /^(\d+)/.exec(process.versions.node);
  return match ? parseInt(match[1] as string, 10) : 0;
}

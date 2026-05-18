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
 * Opt-in
 * ------
 * `EUNO_TELEMETRY=1` — explicitly enables server-side telemetry (opt-in).
 * Telemetry is **disabled by default** (DI-4). Self-hosters must set
 * `EUNO_TELEMETRY=1` to activate the outbound connection.
 *
 * Configuration
 * -------------
 * | Env var                           | Default                                     |
 * | --------------------------------- | ------------------------------------------- |
 * | `EUNO_TELEMETRY`                  | (unset = disabled; `1` = enabled)           |
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
  /**
   * Total successful capability-token issuances in this reporting window.
   * Aggregated at the tenant level; unique user count is available in
   * {@link distinctIssuingUsers} for support / forensics (not billing).
   */
  readonly issuanceEvents: number;
  /**
   * Total successful capability-token renewals in this reporting window.
   * Aggregated at the tenant level; unique user count is available in
   * {@link distinctRenewingUsers} for support / forensics (not billing).
   */
  readonly renewalEvents: number;
  /**
   * Number of distinct user identities that issued at least one capability
   * token during this window. Support / forensics dimension — not used for
   * billing (billing uses {@link issuanceEvents}).
   */
  readonly distinctIssuingUsers: number;
  /**
   * Number of distinct user identities that renewed at least one capability
   * token during this window. Support / forensics dimension — not used for
   * billing (billing uses {@link renewalEvents}).
   */
  readonly distinctRenewingUsers: number;
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

  /**
   * Record a successful capability-token issuance from the issuer.
   *
   * @param tenantId  Tenant identifier extracted from the issued JWT.
   * @param userId    User identifier resolved from the upstream IdP token
   *                  (e.g. `email` or `sub` claim). Used for per-user forensic
   *                  dimension only; billing aggregates at the tenant level.
   */
  recordIssuance(tenantId: string, userId: string): void;

  /**
   * Record a successful capability-token renewal from the issuer.
   *
   * @param tenantId  Tenant identifier extracted from the renewed JWT.
   * @param userId    User identifier from the `authorizedBy.userId` claim of
   *                  the presented token. Used for per-user forensic dimension
   *                  only; billing aggregates at the tenant level.
   */
  recordRenewal(tenantId: string, userId: string): void;
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
   * Maps sessionId → timestamp of most recent request within the concurrency
   * window. Bounded by the number of *distinct active sessions* (not by
   * request volume), so the per-request update is O(1) amortised.
   * Entries older than `CONCURRENCY_WINDOW_MS` from the current time are
   * pruned lazily on each update.
   */
  sessionLastSeen: Map<string, number>;
  /** Running peak: max count of sessions within any 60-s window observed so far. */
  peakConcurrent: number;
  /** Total successful issuances in the current window (billing aggregate). */
  issuanceEvents: number;
  /** Total successful renewals in the current window (billing aggregate). */
  renewalEvents: number;
  /** Distinct user IDs that issued at least one token (forensics dimension). */
  issuingUsers: Set<string>;
  /** Distinct user IDs that renewed at least one token (forensics dimension). */
  renewingUsers: Set<string>;
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

    // Update concurrency window (O(active sessions), not O(requests)).
    this._updatePeakConcurrent(state, sessionId, nowMs);
  }

  /**
   * Record a successful capability-token issuance.
   *
   * Aggregated at the tenant level for billing; `userId` feeds the
   * forensics-only {@link GatewayTelemetryEvent.distinctIssuingUsers} count.
   */
  recordIssuance(tenantId: string, userId: string): void {
    if (this._disabled) return;
    const state = this._getOrCreateState(tenantId);
    state.issuanceEvents += 1;
    state.issuingUsers.add(userId);
  }

  /**
   * Record a successful capability-token renewal.
   *
   * Aggregated at the tenant level for billing; `userId` feeds the
   * forensics-only {@link GatewayTelemetryEvent.distinctRenewingUsers} count.
   */
  recordRenewal(tenantId: string, userId: string): void {
    if (this._disabled) return;
    const state = this._getOrCreateState(tenantId);
    state.renewalEvents += 1;
    state.renewingUsers.add(userId);
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
   * Errors from `_emit()` are silently discarded so a telemetry failure never
   * propagates to the enforcement path. The emit is awaited (not
   * fire-and-forget) so that when `stop()` calls `flush()` during graceful
   * shutdown the network request actually has a chance to complete before the
   * process exits.
   */
  async flush(): Promise<void> {
    if (this._disabled) return;

    const activeTenants = Array.from(this._tenantState.keys());
    for (const tenantId of activeTenants) {
      const state = this._tenantState.get(tenantId);
      if (!state || !this._hasActivity(state)) continue;

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
        issuanceEvents: state.issuanceEvents,
        renewalEvents: state.renewalEvents,
        distinctIssuingUsers: state.issuingUsers.size,
        distinctRenewingUsers: state.renewingUsers.size,
        timestamp: Date.now(),
      };

      // Reset state for the next window BEFORE emitting so that new decisions
      // arriving during the await are accumulated in a fresh window rather than
      // being re-read or double-counted.
      this._tenantState.delete(tenantId);

      // Await the emit so that stop() → flush() during graceful shutdown
      // gives the request a chance to complete. Errors are silently discarded
      // inside _emit() and must never reach callers.
      await this._emit(event);
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
        sessionLastSeen: new Map(),
        peakConcurrent: 0,
        issuanceEvents: 0,
        renewalEvents: 0,
        issuingUsers: new Set(),
        renewingUsers: new Set(),
      };
      this._tenantState.set(tenantId, state);
    }
    return state;
  }

  /**
   * Returns `true` when a tenant has had at least one session, issuance, or
   * renewal event in the current window and should therefore emit a telemetry
   * event on flush.
   */
  private _hasActivity(state: PerTenantState): boolean {
    return state.sessionIds.size > 0 || state.issuanceEvents > 0 || state.renewalEvents > 0;
  }

  /**
   * Update the per-session `lastSeen` timestamp and prune sessions whose
   * most-recent activity is older than `CONCURRENCY_WINDOW_MS`.  Work is
   * O(active sessions), not O(total requests), because we update one map
   * entry per call and only iterate for pruning.
   */
  private _updatePeakConcurrent(state: PerTenantState, sessionId: string, nowMs: number): void {
    // Update this session's last-seen timestamp (upsert — O(1)).
    state.sessionLastSeen.set(sessionId, nowMs);

    // Prune sessions that have gone stale (last seen > CONCURRENCY_WINDOW_MS ago).
    const cutoff = nowMs - CONCURRENCY_WINDOW_MS;
    for (const [sid, lastSeen] of state.sessionLastSeen) {
      if (lastSeen < cutoff) {
        state.sessionLastSeen.delete(sid);
      }
    }

    // Active sessions = those still in the map after pruning.
    const concurrent = state.sessionLastSeen.size;
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
 * Returns `null` unless `EUNO_TELEMETRY=1` is explicitly set (opt-in).
 * The previous behaviour (unset = enabled, `0` = disabled) was an
 * unexpected outbound connection for self-hosters; the new default is
 * disabled so operators must consciously opt in (DI-4).
 */
export function createGatewayTelemetryFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): GatewayTelemetryCollector | null {
  if (env['EUNO_TELEMETRY'] !== '1') {
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
    const pkg = require('../package.json') as { version: string };
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

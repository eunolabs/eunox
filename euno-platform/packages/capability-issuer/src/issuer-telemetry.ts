/**
 * Issuer-side telemetry collector — Stage 4, Task 10 (Telemetry continuity)
 * ---------------------------------------------------------------------------
 * Emits per-tenant issuance and renewal analytics to the same telemetry
 * backend used by the `GatewayTelemetryCollector` in the tool-gateway, so
 * Stage-3 dashboards remain valid without schema changes.
 *
 * The emitted JSON matches the `GatewayTelemetryEvent` schema (same field
 * names, same types, same `subcommand: 'hosted-enforce'` value). No new event
 * names are introduced (Task 10 constraint). The issuance-specific data is
 * carried in the new `issuanceEvents`, `renewalEvents`, `distinctIssuingUsers`,
 * and `distinctRenewingUsers` fields that were added to `GatewayTelemetryEvent`
 * as part of this task.
 *
 * Privacy model
 * -------------
 * - `installId` = `'tenant:' + tenantId` — identifies the tenant, not any
 *   individual user or session.
 * - `distinctIssuingUsers` / `distinctRenewingUsers` are cardinality counts —
 *   no actual user identifiers are emitted. The identifiers are stored only
 *   in-process for the duration of the 5-minute window, then discarded.
 *
 * Opt-in
 * ------
 * `EUNO_TELEMETRY=1` — explicitly enables issuer-side telemetry (opt-in,
 * matches the gateway's DI-4 default). Telemetry is **disabled by default**.
 *
 * Configuration
 * -------------
 * | Env var                           | Default                                     |
 * | --------------------------------- | ------------------------------------------- |
 * | `EUNO_TELEMETRY`                  | (unset = disabled; `1` = enabled)           |
 * | `EUNO_TELEMETRY_URL`              | `https://telemetry.euno.dev/v1/events`      |
 * | `ISSUER_TELEMETRY_FLUSH_MS`       | `300000` (5 minutes)                        |
 *
 * @module
 */

import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default telemetry endpoint — matches the gateway's local-mode client. */
const DEFAULT_TELEMETRY_ENDPOINT = 'https://telemetry.euno.dev/v1/events';

/** Default reporting window in milliseconds (5 minutes). */
const DEFAULT_FLUSH_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Hard cap on the number of distinct user IDs tracked per tenant per flush
 * window for the `issuingUsers` / `renewingUsers` cardinality sets.
 *
 * Beyond this limit new user IDs are no longer added to the set (preventing
 * unbounded memory growth for high-cardinality tenants or from malicious
 * input), while the aggregate `issuanceEvents` / `renewalEvents` counters
 * continue to increment normally. The emitted `distinctIssuingUsers` /
 * `distinctRenewingUsers` values will be capped at this limit, which is
 * documented as an approximate count for forensics use only.
 */
const MAX_DISTINCT_USERS_PER_TENANT = 10_000;

// ---------------------------------------------------------------------------
// Types (structural copy of GatewayTelemetryEvent — kept in sync manually)
// ---------------------------------------------------------------------------

/**
 * JSON shape emitted per tenant per reporting window.
 *
 * Field names are identical to `GatewayTelemetryEvent` so the same
 * telemetry-backend schema and dashboards work without modification.
 * The issuer does not import from `tool-gateway` (that would invert the
 * dependency direction), so this is an independent structural type kept in
 * sync manually with `GatewayTelemetryEvent`.
 *
 * **Any schema change to `GatewayTelemetryEvent` MUST be reflected here.**
 */
interface IssuerTelemetryEvent {
  readonly installId: string;
  readonly version: string;
  readonly osFamily: 'linux' | 'darwin' | 'win32' | 'other';
  readonly nodeMajor: number;
  readonly subcommand: 'hosted-enforce';
  readonly sessionsStarted: number;
  readonly sessionsWithEnforcement: number;
  readonly denialsByConditionType: Readonly<Record<string, number>>;
  readonly peakConcurrentSessions: number;
  readonly upstreamServerName: 'gateway';
  readonly issuanceEvents: number;
  readonly renewalEvents: number;
  readonly distinctIssuingUsers: number;
  readonly distinctRenewingUsers: number;
  /**
   * Set to `true` when `distinctIssuingUsers` has hit the
   * `MAX_DISTINCT_USERS_PER_TENANT` cap and therefore represents an
   * approximate lower-bound rather than the exact cardinality.
   * Dashboards should flag saturation when this field is present and `true`.
   * (CI-1 fix)
   */
  readonly distinctIssuingUsersCapped?: boolean;
  /**
   * Set to `true` when `distinctRenewingUsers` has hit the
   * `MAX_DISTINCT_USERS_PER_TENANT` cap.
   * (CI-1 fix)
   */
  readonly distinctRenewingUsersCapped?: boolean;
  readonly timestamp: number;
}

// ---------------------------------------------------------------------------
// Internal per-tenant state
// ---------------------------------------------------------------------------

interface PerTenantState {
  /** Total successful issuances in the current window. */
  issuanceEvents: number;
  /** Total successful renewals in the current window. */
  renewalEvents: number;
  /** Distinct user IDs that issued at least one token (forensics). */
  issuingUsers: Set<string>;
  /** Distinct user IDs that renewed at least one token (forensics). */
  renewingUsers: Set<string>;
}

// ---------------------------------------------------------------------------
// IssuerTelemetryCollector
// ---------------------------------------------------------------------------

/**
 * Per-tenant telemetry collector for the capability issuer.
 *
 * Records issuance and renewal events per tenant and flushes them on the
 * same 5-minute interval as the `GatewayTelemetryCollector`. One instance
 * is shared across all issue/renew request handlers.
 *
 * Call {@link start} once at issuer startup to begin the periodic flush.
 * Call {@link stop} on shutdown to clear the flush timer and emit a final
 * event for any pending tenant stats.
 */
export class IssuerTelemetryCollector {
  private readonly _tenantState = new Map<string, PerTenantState>();
  private _flushTimer: ReturnType<typeof setInterval> | null = null;
  private readonly _endpointUrl: string;
  private readonly _version: string;
  private readonly _osFamily: IssuerTelemetryEvent['osFamily'];
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

  // ── Recording ─────────────────────────────────────────────────────────────

  /**
   * Record a successful capability-token issuance.
   *
   * Billing aggregates at the tenant level (`issuanceEvents`). The `userId`
   * is used only to maintain a cardinality count of distinct issuing users
   * for support / forensic purposes (`distinctIssuingUsers` in the emitted
   * event). No user identifier is included in the telemetry payload.
   *
   * The distinct-user set is capped at {@link MAX_DISTINCT_USERS_PER_TENANT}
   * to prevent unbounded memory growth; aggregate counts are unaffected.
   */
  recordIssuance(tenantId: string, userId: string): void {
    if (this._disabled) return;
    const state = this._getOrCreateState(tenantId);
    state.issuanceEvents += 1;
    if (state.issuingUsers.size < MAX_DISTINCT_USERS_PER_TENANT) {
      state.issuingUsers.add(userId);
    }
  }

  /**
   * Record a successful capability-token renewal.
   *
   * Billing aggregates at the tenant level (`renewalEvents`). The `userId`
   * is used only to maintain a cardinality count of distinct renewing users
   * for support / forensic purposes (`distinctRenewingUsers` in the emitted
   * event). No user identifier is included in the telemetry payload.
   *
   * The distinct-user set is capped at {@link MAX_DISTINCT_USERS_PER_TENANT}
   * to prevent unbounded memory growth; aggregate counts are unaffected.
   */
  recordRenewal(tenantId: string, userId: string): void {
    if (this._disabled) return;
    const state = this._getOrCreateState(tenantId);
    state.renewalEvents += 1;
    if (state.renewingUsers.size < MAX_DISTINCT_USERS_PER_TENANT) {
      state.renewingUsers.add(userId);
    }
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
    if (this._flushTimer !== null) return;

    this._flushTimer = setInterval(() => {
      void this.flush();
    }, intervalMs);
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
    await this.flush();
  }

  /**
   * Build and emit one event per active tenant, then reset per-tenant state.
   *
   * Errors from `_emit()` are silently discarded so a telemetry failure never
   * propagates to the issuance hot path.
   */
  async flush(): Promise<void> {
    if (this._disabled) return;

    const activeTenants = Array.from(this._tenantState.keys());
    for (const tenantId of activeTenants) {
      const state = this._tenantState.get(tenantId);
      if (!state || (state.issuanceEvents === 0 && state.renewalEvents === 0)) continue;

      const event: IssuerTelemetryEvent = {
        installId: `tenant:${tenantId}`,
        version: this._version,
        osFamily: this._osFamily,
        nodeMajor: this._nodeMajor,
        subcommand: 'hosted-enforce',
        // The issuer does not track session-level enforcement; these fields
        // are zero to preserve the shared schema without introducing new event
        // names (Task 10 constraint).
        sessionsStarted: 0,
        sessionsWithEnforcement: 0,
        denialsByConditionType: {},
        peakConcurrentSessions: 0,
        upstreamServerName: 'gateway',
        issuanceEvents: state.issuanceEvents,
        renewalEvents: state.renewalEvents,
        distinctIssuingUsers: state.issuingUsers.size,
        distinctRenewingUsers: state.renewingUsers.size,
        ...(state.issuingUsers.size >= MAX_DISTINCT_USERS_PER_TENANT
          ? { distinctIssuingUsersCapped: true }
          : {}),
        ...(state.renewingUsers.size >= MAX_DISTINCT_USERS_PER_TENANT
          ? { distinctRenewingUsersCapped: true }
          : {}),
        timestamp: Date.now(),
      };

      // Reset state BEFORE emitting so concurrent issuances during the await
      // go into the next window rather than being double-counted.
      this._tenantState.delete(tenantId);

      await this._emit(event);
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private _getOrCreateState(tenantId: string): PerTenantState {
    let state = this._tenantState.get(tenantId);
    if (!state) {
      state = {
        issuanceEvents: 0,
        renewalEvents: 0,
        issuingUsers: new Set(),
        renewingUsers: new Set(),
      };
      this._tenantState.set(tenantId, state);
    }
    return state;
  }

  private async _emit(event: IssuerTelemetryEvent): Promise<void> {
    try {
      const fetchFn =
        typeof globalThis.fetch === 'function'
          ? (globalThis.fetch as typeof fetch)
          : null;
      if (!fetchFn) return;

      await fetchFn(this._endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      // Telemetry errors are intentionally swallowed — they must never affect
      // the issuance hot path.
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build an {@link IssuerTelemetryCollector} from environment variables and
 * start its flush timer.
 *
 * Returns `null` unless `EUNO_TELEMETRY=1` is explicitly set (opt-in,
 * matching the gateway's DI-4 default).
 */
export function createIssuerTelemetryFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): IssuerTelemetryCollector | null {
  if (env['EUNO_TELEMETRY'] !== '1') {
    return null;
  }

  const endpointUrl = env['EUNO_TELEMETRY_URL'] ?? DEFAULT_TELEMETRY_ENDPOINT;

  const flushIntervalMs = (() => {
    const raw = env['ISSUER_TELEMETRY_FLUSH_MS'];
    if (raw === undefined) return DEFAULT_FLUSH_INTERVAL_MS;
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_FLUSH_INTERVAL_MS;
  })();

  const collector = new IssuerTelemetryCollector({ endpointUrl });
  collector.start(flushIntervalMs);
  return collector;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract tenantId and userId from a raw JWT string without verifying the
 * signature. Used exclusively for telemetry routing — never for authorization.
 *
 * Returns `{ tenantId: 'unknown', userId: 'unknown' }` when the token is
 * malformed or does not carry the required claims.
 */
export function extractTelemetryClaimsFromToken(token: string): {
  tenantId: string;
  userId: string;
} {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { tenantId: 'unknown', userId: 'unknown' };
    const raw = Buffer.from(parts[1] as string, 'base64url').toString('utf8');
    const payload = JSON.parse(raw) as Record<string, unknown>;
    const authorizedBy = payload['authorizedBy'] as Record<string, unknown> | undefined;
    const tenantId =
      typeof authorizedBy?.['tenantId'] === 'string' && authorizedBy['tenantId']
        ? authorizedBy['tenantId']
        : 'unknown';
    const userId =
      typeof authorizedBy?.['userId'] === 'string' && authorizedBy['userId']
        ? authorizedBy['userId']
        : 'unknown';
    return { tenantId, userId };
  } catch {
    return { tenantId: 'unknown', userId: 'unknown' };
  }
}

// ---------------------------------------------------------------------------
// Runtime helpers
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

function _getOsFamily(): IssuerTelemetryEvent['osFamily'] {
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

/**
 * Telemetry metrics collector for @euno/mcp.
 *
 * `TelemetryCollector` accumulates per-session metrics across the lifetime of
 * a single CLI invocation and emits one {@link TelemetryEvent} when
 * {@link TelemetryCollector.flush} is called.
 *
 * ### Usage
 *
 * ```ts
 * const collector = await createTelemetry({ subcommand: 'proxy', upstreamCommand: 'npx', upstreamArgs });
 *
 * // Pass the session hooks to the proxy (stdio — one session per process)
 * const proxy = new StdioProxy({ ..., telemetryHooks: collector.sessionHooks() });
 * await proxy.start();
 *
 * // Flush at process exit
 * await collector.flush();
 * ```
 *
 * For the HTTP proxy, which supports multiple concurrent sessions, the proxy
 * calls {@link TelemetryHooks.createSessionHooks} (exposed on the return value
 * of `sessionHooks()`) to get a fresh, isolated hook set per session.
 *
 * @module
 */

import type { TelemetryEvent, TelemetryHooks } from './types';
import type { TelemetryEmitter } from './emitter';

// ---------------------------------------------------------------------------
// Base event fields (set at construction time, static across all sessions)
// ---------------------------------------------------------------------------

/** Fields of {@link TelemetryEvent} that are determined at invocation start. */
export type TelemetryEventBase = Omit<
  TelemetryEvent,
  'sessionsStarted' | 'sessionsWithEnforcement' | 'denialsByConditionType' | 'timestamp'
>;

// ---------------------------------------------------------------------------
// TelemetryCollector
// ---------------------------------------------------------------------------

/**
 * Accumulates session metrics and emits a {@link TelemetryEvent} on
 * {@link flush}.
 *
 * Use {@link sessionHooks} to obtain per-session {@link TelemetryHooks}
 * instances to pass to proxy options.  Each call to `sessionHooks()` creates
 * an independent closure — this is how concurrent HTTP sessions are safely
 * isolated from one another.
 */
export class TelemetryCollector {
  private _sessionsStarted = 0;
  private _sessionsWithEnforcement = 0;
  private readonly _denialsByConditionType: Record<string, number> = {};

  constructor(
    private readonly _emitter: TelemetryEmitter,
    private readonly _base: TelemetryEventBase,
  ) {}

  // ── Session hook factory ──────────────────────────────────────────────────

  /**
   * Returns a fresh {@link TelemetryHooks} closure for a single MCP session.
   *
   * Every call creates an independent `hadEnforcement` flag, so concurrent
   * HTTP sessions are correctly isolated from each other.  The returned object
   * also exposes {@link TelemetryHooks.createSessionHooks} so the HTTP proxy
   * can call it per-session without knowing about the collector directly.
   *
   * Enforcement semantics: `sessionsWithEnforcement` is incremented when the
   * session had **any** `tools/call` request (allow or deny), consistent with
   * the documented meaning "at least one enforcement event".  Only denials
   * accumulate `denialsByConditionType`.
   */
  sessionHooks(): TelemetryHooks {
    let hadEnforcement = false;

    return {
      onSessionStart: () => {
        this._sessionsStarted++;
      },

      onDecision: (allowed: boolean, conditionType?: string) => {
        // Any tools/call that reaches the PDP counts as an enforcement event.
        hadEnforcement = true;
        if (!allowed) {
          const key = conditionType ?? 'unknown';
          this._denialsByConditionType[key] =
            (this._denialsByConditionType[key] ?? 0) + 1;
        }
      },

      onSessionEnd: () => {
        if (hadEnforcement) {
          this._sessionsWithEnforcement++;
        }
      },

      // Allow the HTTP proxy to create a fresh, isolated hook set per session.
      createSessionHooks: () => this.sessionHooks(),
    };
  }

  // ── Flush ─────────────────────────────────────────────────────────────────

  /**
   * Build the {@link TelemetryEvent} from accumulated state and pass it to the
   * configured emitter.
   *
   * Safe to call multiple times; each call emits an independent snapshot of the
   * current counters.  MUST NOT throw.
   */
  async flush(): Promise<void> {
    try {
      const event: TelemetryEvent = {
        ...this._base,
        sessionsStarted: this._sessionsStarted,
        sessionsWithEnforcement: this._sessionsWithEnforcement,
        denialsByConditionType: { ...this._denialsByConditionType },
        timestamp: Date.now(),
      };
      await this._emitter.emit(event);
    } catch {
      // Telemetry flush must never propagate to the caller.
    }
  }
}

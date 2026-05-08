/**
 * Telemetry emitter implementations for @euno/mcp.
 *
 * Three emitters are provided:
 *
 * | Emitter                  | When used                                     |
 * | ------------------------ | --------------------------------------------- |
 * | {@link NoopTelemetryEmitter}       | Telemetry disabled (EUNO_TELEMETRY=0) or user opted out. |
 * | {@link LocalFileTelemetryEmitter}  | EUNO_TELEMETRY_LOCAL=1 — writes JSONL to ~/.euno/telemetry.jsonl, sends nothing. |
 * | {@link HttpTelemetryEmitter}       | Default when telemetry is enabled — POSTs to the configured endpoint. |
 *
 * All emitters implement {@link TelemetryEmitter}.  Errors are always silently
 * swallowed so telemetry never affects the user-facing enforcement path.
 *
 * @module
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { TelemetryEvent } from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default HTTPS endpoint to POST telemetry events to.
 *
 * Override with `EUNO_TELEMETRY_URL` to point at a custom collector or for
 * local development/testing.
 */
export const DEFAULT_TELEMETRY_ENDPOINT = 'https://telemetry.euno.dev/v1/events';

/** Default path for the local-mode JSONL output. */
export const DEFAULT_LOCAL_TELEMETRY_PATH = path.join(
  os.homedir(),
  '.euno',
  'telemetry.jsonl',
);

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/** Common contract for all telemetry emitters. */
export interface TelemetryEmitter {
  /** Emit one event. MUST NOT throw. */
  emit(event: TelemetryEvent): Promise<void>;
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

/** Silently discards every event. Used when the user has opted out. */
export class NoopTelemetryEmitter implements TelemetryEmitter {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async emit(_event: TelemetryEvent): Promise<void> { /* intentional no-op */ }
}

/**
 * Appends events to a local JSONL file (`~/.euno/telemetry.jsonl` by default)
 * and sends nothing to any network endpoint.
 *
 * Activated by `EUNO_TELEMETRY_LOCAL=1`.  This lets security-conscious users
 * inspect exactly what would be sent without any outbound traffic.
 */
export class LocalFileTelemetryEmitter implements TelemetryEmitter {
  constructor(
    private readonly localPath: string = DEFAULT_LOCAL_TELEMETRY_PATH,
  ) {}

  async emit(event: TelemetryEvent): Promise<void> {
    try {
      await fs.promises.mkdir(path.dirname(this.localPath), { recursive: true });
      await fs.promises.appendFile(
        this.localPath,
        JSON.stringify(event) + '\n',
        'utf8',
      );
    } catch {
      // Silent: telemetry must never propagate errors to the caller.
    }
  }
}

/**
 * POSTs events to {@link DEFAULT_TELEMETRY_ENDPOINT} (or a custom URL set via
 * `EUNO_TELEMETRY_URL`) using the global `fetch` API available in Node 18+.
 *
 * Network errors and non-2xx responses are silently discarded.
 */
export class HttpTelemetryEmitter implements TelemetryEmitter {
  constructor(
    private readonly endpointUrl: string = DEFAULT_TELEMETRY_ENDPOINT,
  ) {}

  async emit(event: TelemetryEvent): Promise<void> {
    try {
      const fetchFn =
        typeof globalThis.fetch === 'function'
          ? (globalThis.fetch as typeof fetch)
          : null;
      if (!fetchFn) return; // Node < 18 without polyfill — silently skip.

      await fetchFn(this.endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        // 5-second hard deadline so a slow endpoint never blocks process exit.
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      // Silent: network errors must never affect the user.
    }
  }
}

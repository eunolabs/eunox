/**
 * Telemetry consent and install-ID management for @euno/mcp.
 *
 * ### State file: `~/.euno/telemetry`
 *
 * A JSON file that persists three values:
 *   - `installId`   — anonymous UUID created on first run, never regenerated.
 *   - `enabled`     — whether the user opted in.
 *   - `promptedAt`  — ISO-8601 timestamp of when the consent prompt was shown.
 *
 * ### Env-var overrides (checked before the file)
 *
 * | Variable               | Effect                                         |
 * | ---------------------- | ---------------------------------------------- |
 * | `EUNO_TELEMETRY=0`     | Telemetry disabled entirely; file not written. |
 * | `EUNO_TELEMETRY=1`     | Telemetry enabled; prompt is skipped.          |
 * | `EUNO_TELEMETRY_LOCAL` | Handled by the emitter, not here.             |
 *
 * @module
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/** Default path for the telemetry consent/state file. */
export const DEFAULT_TELEMETRY_STATE_PATH = path.join(os.homedir(), '.euno', 'telemetry');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Contents of the `~/.euno/telemetry` state file.
 */
export interface TelemetryState {
  /** Anonymous UUID created on first run. */
  readonly installId: string;
  /** Whether the user has opted in to telemetry. */
  readonly enabled: boolean;
  /** ISO-8601 timestamp of when the consent decision was recorded. */
  readonly promptedAt: string;
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/**
 * Read and parse the telemetry state file.
 *
 * Returns `null` when the file does not exist or cannot be parsed (e.g. first
 * run or corrupted file).  Never throws.
 */
export async function loadTelemetryState(
  statePath: string = DEFAULT_TELEMETRY_STATE_PATH,
): Promise<TelemetryState | null> {
  try {
    const raw = await fs.promises.readFile(statePath, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    // Accept partial/older files by providing safe defaults for missing fields.
    const installId =
      typeof parsed['installId'] === 'string' && parsed['installId'].length > 0
        ? parsed['installId']
        : crypto.randomUUID();
    const enabled = typeof parsed['enabled'] === 'boolean' ? parsed['enabled'] : false;
    const promptedAt =
      typeof parsed['promptedAt'] === 'string'
        ? parsed['promptedAt']
        : new Date().toISOString();
    return { installId, enabled, promptedAt };
  } catch {
    return null;
  }
}

/**
 * Write the telemetry state to disk.
 *
 * Creates the parent directory (`~/.euno/`) if it does not exist.
 * Propagates I/O errors — callers should handle them (typically by logging to
 * stderr and continuing, since a failed write just means "no consent
 * persistence").
 */
export async function saveTelemetryState(
  state: TelemetryState,
  statePath: string = DEFAULT_TELEMETRY_STATE_PATH,
): Promise<void> {
  await fs.promises.mkdir(path.dirname(statePath), { recursive: true });
  await fs.promises.writeFile(statePath, JSON.stringify(state, null, 2) + '\n', 'utf8');
}

// ---------------------------------------------------------------------------
// First-run consent prompt
// ---------------------------------------------------------------------------

/**
 * Show a consent prompt on stderr and read the user's answer from stdin.
 *
 * Returns:
 *   - `true`  — user explicitly opted in (typed "y" or "Y").
 *   - `false` — user explicitly opted out.
 *   - `null`  — could not prompt (non-TTY stdin/stderr, or timeout).
 *
 * The prompt is shown on **stderr** because stdout may carry the MCP protocol
 * stream.  Stdin is read via `readline` but only when both stdin and stderr are
 * interactive TTYs; in non-interactive environments (Claude Desktop, CI) the
 * function returns `null` immediately.
 *
 * A 30-second timeout is applied so that non-interactive invocations where the
 * TTY check is unreliable do not hang the process.
 */
export function promptForConsent(): Promise<boolean | null> {
  // Only prompt when both input and output are interactive.
  if (!process.stderr.isTTY || !process.stdin.isTTY) {
    return Promise.resolve(null);
  }

  return new Promise<boolean | null>((resolve) => {
    const PROMPT =
      '\n[euno-mcp] Help improve euno-mcp with anonymous usage counts.\n' +
      '  What\'s collected: version, OS, Node.js major, session counts,\n' +
      '  and denial-type counts (e.g. "maxCalls: 2").  No tool names,\n' +
      '  argument values, file paths, or any payload content — ever.\n' +
      '  Full schema: https://github.com/edgeobs/euno/blob/main/public/packages/mcp/TELEMETRY.md\n' +
      '  Disable any time: EUNO_TELEMETRY=0\n' +
      'Enable anonymous telemetry? [y/N] ';

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    let settled = false;
    // Declared before settle() so it is in scope for clearTimeout().
    let timer: ReturnType<typeof setTimeout>;

    const settle = (value: boolean | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      resolve(value);
    };

    rl.question(PROMPT, (answer) => {
      settle(answer.trim().toLowerCase() === 'y');
    });

    // Time-box the prompt so non-interactive/piped invocations don't hang.
    timer = setTimeout(() => {
      process.stderr.write('\n[euno-mcp] Consent prompt timed out — defaulting to off.\n');
      settle(null);
    }, 30_000);
    // Prevent the timer from keeping the process alive.
    timer.unref();
  });
}

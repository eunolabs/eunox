/**
 * @euno/mcp telemetry module — public API and factory.
 *
 * ### Quick start
 *
 * ```ts
 * // In a CLI action handler, before starting the proxy:
 * const telemetry = await createTelemetry({
 *   subcommand: 'proxy',
 *   upstreamCommand: upstreamCommand,
 *   upstreamArgs: upstreamArgs,
 * });
 *
 * const proxy = new StdioProxy({
 *   ...
 *   telemetryHooks: telemetry.sessionHooks(),
 * });
 * await proxy.start();
 *
 * // Flush the collected metrics (e.g. via process.on('beforeExit', ...))
 * await telemetry.flush();
 * ```
 *
 * ### Env variables
 *
 * | Variable              | Effect                                                 |
 * | --------------------- | ------------------------------------------------------ |
 * | `EUNO_TELEMETRY=0`    | Disable entirely — no prompt, no file, no network.     |
 * | `EUNO_TELEMETRY=1`    | Enable without prompting (useful in CI that opts in).  |
 * | `EUNO_TELEMETRY_LOCAL=1` | Write to `~/.euno/telemetry.jsonl`, send nothing.   |
 * | `EUNO_TELEMETRY_URL`  | Override the default HTTPS endpoint.                   |
 *
 * @module
 */

import * as crypto from 'node:crypto';
import * as os from 'node:os';

import type { TelemetryEvent } from './types';
import {
  loadTelemetryState,
  saveTelemetryState,
  promptForConsent,
  DEFAULT_TELEMETRY_STATE_PATH,
} from './consent';
import {
  NoopTelemetryEmitter,
  LocalFileTelemetryEmitter,
  HttpTelemetryEmitter,
  DEFAULT_TELEMETRY_ENDPOINT,
} from './emitter';
import { TelemetryCollector } from './collector';
import type { TelemetryEventBase } from './collector';

// Re-export everything callers may need.
export type { TelemetryEvent, TelemetryHooks, OsFamily } from './types';
export { TELEMETRY_EVENT_KEYS } from './types';
export type { TelemetryState } from './consent';
export {
  DEFAULT_TELEMETRY_STATE_PATH,
  loadTelemetryState,
  saveTelemetryState,
  promptForConsent,
} from './consent';
export type { TelemetryEmitter } from './emitter';
export {
  DEFAULT_TELEMETRY_ENDPOINT,
  DEFAULT_LOCAL_TELEMETRY_PATH,
  NoopTelemetryEmitter,
  LocalFileTelemetryEmitter,
  HttpTelemetryEmitter,
} from './emitter';
export type { TelemetryEventBase } from './collector';
export { TelemetryCollector } from './collector';

// ---------------------------------------------------------------------------
// Known OSS upstream server allow-list
// ---------------------------------------------------------------------------

/**
 * Set of upstream server package names that are reported verbatim in the
 * telemetry event.  Any command that does not match this list is reported as
 * `"custom"` to avoid leaking arbitrary paths or package names.
 */
const KNOWN_OSS_SERVERS: ReadonlySet<string> = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-gdrive',
  '@modelcontextprotocol/server-git',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-sentry',
  '@modelcontextprotocol/server-time',
  '@modelcontextprotocol/server-sqlite',
]);

/**
 * Extract a sanitized upstream server name from the command and args.
 *
 * Checks the command and each argument against the {@link KNOWN_OSS_SERVERS}
 * allow-list, stripping version suffixes (`@x.y.z` or `@latest`) before
 * matching.  Returns `"custom"` when nothing matches.
 */
export function sanitizeUpstreamServerName(
  command: string,
  args: string[],
): string {
  for (const candidate of [command, ...args]) {
    // Strip version suffix: `@modelcontextprotocol/server-fs@1.2.3` → base name
    const bare = candidate
      .replace(/@[\d.]+$/, '')    // e.g. @1.2.3
      .replace(/@latest$/, '');   // e.g. @latest
    if (KNOWN_OSS_SERVERS.has(bare)) {
      return bare;
    }
    if (KNOWN_OSS_SERVERS.has(candidate)) {
      return candidate;
    }
  }
  return 'custom';
}

// ---------------------------------------------------------------------------
// OS/runtime helpers
// ---------------------------------------------------------------------------

function getOsFamily(): TelemetryEvent['osFamily'] {
  const p = os.platform();
  if (p === 'linux') return 'linux';
  if (p === 'darwin') return 'darwin';
  if (p === 'win32') return 'win32';
  return 'other';
}

function getNodeMajor(): number {
  const match = /^(\d+)/.exec(process.versions.node);
  return match ? parseInt(match[1] as string, 10) : 0;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Options for {@link createTelemetry}. */
export interface CreateTelemetryOptions {
  /** CLI subcommand being executed. */
  subcommand: TelemetryEvent['subcommand'];
  /**
   * The upstream MCP server command (used for sanitized server-name
   * detection).  Pass `undefined` when there is no upstream (e.g. `validate`
   * or `kill`).
   */
  upstreamCommand?: string;
  /** Arguments passed to the upstream command. */
  upstreamArgs?: string[];
  /**
   * Path to the telemetry state file.
   * Defaults to {@link DEFAULT_TELEMETRY_STATE_PATH} (`~/.euno/telemetry`).
   * Override in tests to avoid touching the real home directory.
   */
  statePath?: string;
}

/**
 * Build a ready-to-use {@link TelemetryCollector} for the current CLI
 * invocation.
 *
 * Handles the full lifecycle:
 *   1. Check `EUNO_TELEMETRY=0` → return no-op collector.
 *   2. Check `EUNO_TELEMETRY_LOCAL=1` → use local-file emitter.
 *   3. Load or create the consent state from `~/.euno/telemetry`.
 *   4. Prompt for consent when it has not been recorded and stdin is a TTY.
 *   5. Return a collector wired to the appropriate emitter.
 *
 * This function MUST NOT throw — any internal error falls back to a no-op
 * collector so telemetry never interrupts the main proxy/validate/kill flow.
 */
export async function createTelemetry(
  opts: CreateTelemetryOptions,
): Promise<TelemetryCollector> {
  try {
    return await _createTelemetryInternal(opts);
  } catch {
    // Internal error — fall back to a no-op collector.
    return _makeNoopCollector(opts);
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function _makeNoopCollector(opts: CreateTelemetryOptions): TelemetryCollector {
  const base: TelemetryEventBase = {
    installId: 'disabled',
    version: _getVersion(),
    osFamily: getOsFamily(),
    nodeMajor: getNodeMajor(),
    subcommand: opts.subcommand,
    upstreamServerName: sanitizeUpstreamServerName(
      opts.upstreamCommand ?? '',
      opts.upstreamArgs ?? [],
    ),
  };
  return new TelemetryCollector(new NoopTelemetryEmitter(), base);
}

function _getVersion(): string {
  // Import package.json lazily to avoid issues if the module is bundled.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require('../../package.json') as { version: string };
    return pkg.version;
  } catch {
    return 'unknown';
  }
}

async function _createTelemetryInternal(
  opts: CreateTelemetryOptions,
): Promise<TelemetryCollector> {
  // ── 1. Hard disable via env var ───────────────────────────────────────
  if (process.env['EUNO_TELEMETRY'] === '0') {
    return _makeNoopCollector(opts);
  }

  // ── 2. Determine emitter mode ─────────────────────────────────────────
  const isLocalMode = process.env['EUNO_TELEMETRY_LOCAL'] === '1';
  const endpointUrl =
    process.env['EUNO_TELEMETRY_URL'] ?? DEFAULT_TELEMETRY_ENDPOINT;
  const statePath = opts.statePath ?? DEFAULT_TELEMETRY_STATE_PATH;

  // ── 3. Load or prompt for consent ─────────────────────────────────────
  let state = await loadTelemetryState(statePath);
  let isEnabled: boolean;

  if (process.env['EUNO_TELEMETRY'] === '1') {
    // Explicit opt-in via env var — skip the prompt.
    isEnabled = true;
    if (state === null) {
      state = {
        installId: crypto.randomUUID(),
        enabled: true,
        promptedAt: new Date().toISOString(),
      };
      // Best-effort save; ignore I/O errors.
      await saveTelemetryState(state, statePath).catch(() => undefined);
    }
  } else if (state === null) {
    // First run — prompt if we can.
    const answer = await promptForConsent();
    isEnabled = answer === true;

    if (answer !== null) {
      // User gave an explicit answer (y or n) — persist it so we never ask again.
      state = {
        installId: crypto.randomUUID(),
        enabled: isEnabled,
        promptedAt: new Date().toISOString(),
      };
      await saveTelemetryState(state, statePath).catch(() => undefined);
    } else {
      // Non-TTY / timeout: treat as opted-out for this invocation but do NOT
      // persist the decision so the next interactive run can still prompt.
      state = {
        installId: crypto.randomUUID(),
        enabled: false,
        promptedAt: new Date().toISOString(),
      };
      // Intentionally NOT saving to disk here.
    }
  } else {
    // Respect the persisted consent choice.
    isEnabled = state.enabled;
  }

  // ── 4. Build collector ─────────────────────────────────────────────────
  const base: TelemetryEventBase = {
    installId: state.installId,
    version: _getVersion(),
    osFamily: getOsFamily(),
    nodeMajor: getNodeMajor(),
    subcommand: opts.subcommand,
    upstreamServerName: sanitizeUpstreamServerName(
      opts.upstreamCommand ?? '',
      opts.upstreamArgs ?? [],
    ),
  };

  if (!isEnabled) {
    return new TelemetryCollector(new NoopTelemetryEmitter(), base);
  }

  const emitter = isLocalMode
    ? new LocalFileTelemetryEmitter()
    : new HttpTelemetryEmitter(endpointUrl);

  return new TelemetryCollector(emitter, base);
}

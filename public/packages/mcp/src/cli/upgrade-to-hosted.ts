/**
 * `euno-mcp upgrade-to-hosted` — interactive migration command.
 * ---------------------------------------------------------------------------
 * Guides the user through migrating from local in-process enforcement to the
 * hosted Euno gateway in three steps:
 *
 *   Step 1 — Validate the API key against the gateway.
 *   Step 2 — Upload the local policy file to the hosted policy store.
 *   Step 3 — Patch known config files to switch to remote-enforcer mode.
 *
 * The command is designed to be idempotent: running it multiple times
 * produces the same end state.  Config files are backed up before every
 * patch so the operator can always roll back with `cp <file>.bak.<ts> <file>`.
 *
 * **Manual path** — see `docs/upgrade-to-hosted.md` if you prefer to perform
 * these steps yourself rather than running this command.
 *
 * @module
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Command } from 'commander';
import { validateManifest, type AgentCapabilityManifest } from '@euno/common-core';

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Convert an unknown thrown value to a human-readable message string. */
export function formatError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Return a copy of an args array with the value of `--enforcer-api-key`
 * replaced by `"***"` so the key is never printed to terminals, CI logs,
 * or shell history.
 */
export function redactArgs(args: string[]): string[] {
  return args.map((arg, i) => (args[i - 1] === '--enforcer-api-key' ? '***' : arg));
}

// ---------------------------------------------------------------------------
// Injectable fetch interface (for unit-test isolation)
// ---------------------------------------------------------------------------

/**
 * Minimal fetch-compatible interface used by {@link MinterClient} to
 * communicate with the minter/gateway.  Defaults to the global `fetch`.
 * Inject a mock in unit tests to avoid real network I/O.
 */
export type UpgradeFetcher = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

const defaultFetcher: UpgradeFetcher = async (url, init) => {
  const res = await fetch(url, init);
  return {
    ok: res.ok,
    status: res.status,
    json: () => res.json() as Promise<unknown>,
    text: () => res.text(),
  };
};

// ---------------------------------------------------------------------------
// Minter client
// ---------------------------------------------------------------------------

/**
 * Responses from {@link MinterClient.ping}.
 */
export interface PingResult {
  tenantId: string;
  policyId: string;
  scopes: string[];
}

/**
 * Thin HTTP client for the api-key-minter service used by the upgrade command.
 * All methods time out after {@link timeoutMs} milliseconds.
 */
export class MinterClient {
  private readonly _baseUrl: string;
  private readonly _fetcher: UpgradeFetcher;
  private readonly _timeoutMs: number;

  constructor(opts: {
    baseUrl: string;
    fetcher?: UpgradeFetcher;
    timeoutMs?: number;
  }) {
    this._baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this._fetcher = opts.fetcher ?? defaultFetcher;
    this._timeoutMs = opts.timeoutMs ?? 10_000;
  }

  /**
   * `GET /health` — verify that the minter service is reachable.
   *
   * Throws if the service is unreachable or returns a non-200 status.
   */
  async health(): Promise<void> {
    const url = `${this._baseUrl}/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    try {
      const res = await this._fetcher(url, {
        method: 'GET',
        headers: {},
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} from ${url}`);
      }
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * `GET /api/v1/ping` — validate a Bearer API key and return its metadata.
   *
   * Throws with a descriptive message on invalid key (401), unreachable
   * service, or malformed response.
   */
  async ping(apiKey: string): Promise<PingResult> {
    const url = `${this._baseUrl}/api/v1/ping`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    let res: Awaited<ReturnType<UpgradeFetcher>>;
    try {
      res = await this._fetcher(url, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${apiKey}` },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 401) {
      throw new Error('API key is not valid — please check your --api-key value');
    }
    if (!res.ok) {
      throw new Error(`API key validation failed with HTTP ${res.status}`);
    }

    const body = await res.json();
    if (
      typeof body !== 'object' ||
      body === null ||
      typeof (body as Record<string, unknown>)['tenantId'] !== 'string' ||
      typeof (body as Record<string, unknown>)['policyId'] !== 'string'
    ) {
      throw new Error('Unexpected response shape from /api/v1/ping');
    }

    const b = body as Record<string, unknown>;
    return {
      tenantId: b['tenantId'] as string,
      policyId: b['policyId'] as string,
      scopes: Array.isArray(b['scopes']) ? (b['scopes'] as string[]) : [],
    };
  }

  /**
   * `POST /admin/v1/policies` — upload an `AgentCapabilityManifest` to the
   * hosted policy store and propagate the capabilities to all matching API keys.
   *
   * Requires the admin API key (`X-Admin-Key`).
   *
   * @returns The number of API keys whose capabilities were updated.
   */
  async uploadPolicy(opts: {
    adminKey: string;
    policyId: string;
    manifest: AgentCapabilityManifest;
  }): Promise<{ updatedKeys: number; capabilityCount: number }> {
    const url = `${this._baseUrl}/admin/v1/policies`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    let res: Awaited<ReturnType<UpgradeFetcher>>;
    try {
      res = await this._fetcher(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': opts.adminKey,
        },
        body: JSON.stringify({ policyId: opts.policyId, manifest: opts.manifest }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 401) {
      throw new Error('Admin key rejected — please check your --admin-key value');
    }
    if (!res.ok) {
      let detail = '';
      try {
        const b = (await res.json()) as Record<string, unknown>;
        const err = b['error'] as Record<string, unknown> | undefined;
        if (err?.['message']) detail = `: ${String(err['message'])}`;
      } catch {
        /* ignore parse failure */
      }
      throw new Error(`Policy upload failed with HTTP ${res.status}${detail}`);
    }

    const body = (await res.json()) as Record<string, unknown>;
    return {
      updatedKeys: typeof body['updatedKeys'] === 'number' ? body['updatedKeys'] : 0,
      capabilityCount:
        typeof body['capabilityCount'] === 'number' ? body['capabilityCount'] : 0,
    };
  }
}

// ---------------------------------------------------------------------------
// Policy file loading
// ---------------------------------------------------------------------------

/**
 * Load and validate an `AgentCapabilityManifest` from a YAML or JSON file.
 *
 * Extension determines the parser:
 *  - `.json`  → `JSON.parse`
 *  - otherwise → `js-yaml` (accepts YAML and JSON)
 *
 * @throws If the file cannot be read or fails manifest validation.
 */
export function loadManifestFromFile(filePath: string): AgentCapabilityManifest {
  const resolved = path.resolve(filePath);
  let content: string;
  try {
    content = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(
      `Cannot read policy file '${filePath}': ${formatError(err)}`,
    );
  }

  let raw: unknown;
  const ext = path.extname(resolved).toLowerCase();
  if (ext === '.json') {
    try {
      raw = JSON.parse(content);
    } catch (err) {
      throw new Error(
        `Cannot parse JSON policy file '${filePath}': ${formatError(err)}`,
      );
    }
  } else {
    try {
      raw = yaml.load(content);
    } catch (err) {
      throw new Error(
        `Cannot parse YAML policy file '${filePath}': ${formatError(err)}`,
      );
    }
  }

  return validateManifest(raw);
}

// ---------------------------------------------------------------------------
// Config file discovery
// ---------------------------------------------------------------------------

/**
 * The set of MCP client config files that `upgrade-to-hosted` can patch.
 */
export interface ConfigFileInfo {
  /** Human-readable label for display. */
  label: string;
  /** Absolute path to the config file. */
  filePath: string;
}

/**
 * Return the platform-specific default path to the Claude Desktop config file.
 */
export function claudeDesktopConfigPath(): string {
  switch (process.platform) {
    case 'darwin':
      return path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    case 'win32':
      return path.join(
        process.env['APPDATA'] ?? path.join(os.homedir(), 'AppData', 'Roaming'),
        'Claude',
        'claude_desktop_config.json',
      );
    default: // Linux and others
      return path.join(
        process.env['XDG_CONFIG_HOME'] ?? path.join(os.homedir(), '.config'),
        'Claude',
        'claude_desktop_config.json',
      );
  }
}

/**
 * Discover config files that exist on disk and are eligible for patching.
 *
 * Candidates:
 *  1. Claude Desktop `claude_desktop_config.json` (platform-specific location)
 *  2. An explicit `--config` path if supplied
 *
 * Returns only entries whose files actually exist.
 */
export function discoverConfigFiles(explicitPaths: string[] = []): ConfigFileInfo[] {
  const candidates: ConfigFileInfo[] = [
    {
      label: 'Claude Desktop (claude_desktop_config.json)',
      filePath: claudeDesktopConfigPath(),
    },
  ];

  for (const p of explicitPaths) {
    candidates.push({
      label: path.basename(p),
      filePath: path.resolve(p),
    });
  }

  return candidates.filter((c) => {
    try {
      return fs.existsSync(c.filePath);
    } catch {
      return false;
    }
  });
}

// ---------------------------------------------------------------------------
// Backup utility
// ---------------------------------------------------------------------------

/**
 * Copy `filePath` to `<filePath>.bak.<YYYYMMDDHHmmss>`.
 *
 * @returns The path of the backup file.
 */
export function backupFile(filePath: string): string {
  const now = new Date();
  const ts = [
    String(now.getFullYear()),
    String(now.getMonth() + 1).padStart(2, '0'),
    String(now.getDate()).padStart(2, '0'),
    String(now.getHours()).padStart(2, '0'),
    String(now.getMinutes()).padStart(2, '0'),
    String(now.getSeconds()).padStart(2, '0'),
  ].join('');
  const backupPath = `${filePath}.bak.${ts}`;
  fs.copyFileSync(filePath, backupPath);
  return backupPath;
}

// ---------------------------------------------------------------------------
// claude_desktop_config.json patching
// ---------------------------------------------------------------------------

/**
 * Shape of a single MCP server entry in `claude_desktop_config.json`.
 */
export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  [key: string]: unknown;
}

/**
 * Shape of the top-level `claude_desktop_config.json` structure
 * (only the parts this module cares about).
 */
export interface ClaudeDesktopConfig {
  mcpServers?: Record<string, McpServerEntry>;
  [key: string]: unknown;
}

/**
 * Describes a change that will be applied to a single MCP server entry.
 * Returned by {@link computeConfigPatch} so callers can show a dry-run diff.
 */
export interface EntryPatch {
  /** Name of the MCP server entry in `mcpServers`. */
  serverName: string;
  /** The args array before patching. */
  before: string[];
  /** The args array after patching. */
  after: string[];
}

/**
 * Compute the patches needed to upgrade every `euno-mcp proxy` entry in the
 * given Claude Desktop config.
 *
 * An entry is a target when:
 *  1. `command` basename (ignoring `.cmd`/`.bat`/`.exe` suffixes) is `"euno-mcp"`
 *  2. The args contain a `"proxy"` subcommand (skipping flag-value pairs)
 *  3. The entry does NOT already have BOTH `--enforcer-url` AND `--enforcer-api-key`
 *
 * The patch:
 *  - Removes `--policy <path>` from `args` (if present).
 *  - Injects `--enforcer-url <url>` and `--enforcer-api-key <key>` immediately
 *    before the `--` separator (or at the end of the pre-`--` args).
 */
export function computeConfigPatch(
  config: ClaudeDesktopConfig,
  enforcerUrl: string,
  apiKey: string,
): EntryPatch[] {
  const patches: EntryPatch[] = [];
  const servers = config.mcpServers ?? {};

  for (const [name, entry] of Object.entries(servers)) {
    if (!isEunoMcpEntry(entry)) continue;
    const args = entry.args ?? [];
    if (!hasProxySubcommand(args)) continue;
    // Only skip when BOTH enforcer flags are already present — allow re-running
    // to rotate/update the API key or add a missing flag.
    if (args.includes('--enforcer-url') && args.includes('--enforcer-api-key')) continue;

    const patched = patchArgs(args, enforcerUrl, apiKey);
    if (JSON.stringify(patched) !== JSON.stringify(args)) {
      patches.push({ serverName: name, before: args, after: patched });
    }
  }

  return patches;
}

function isEunoMcpEntry(entry: McpServerEntry): boolean {
  const cmd = entry.command ?? '';
  // Extract the basename using both Unix ('/') and Windows ('\') separators
  // so this works cross-platform and on configs copied between OSes.
  const base = cmd.split(/[\\/]/).pop() ?? cmd;
  const normalized = base.replace(/\.(cmd|bat|exe)$/i, '');
  return normalized === 'euno-mcp';
}

function hasProxySubcommand(args: string[]): boolean {
  // Scan for a "proxy" positional argument while correctly skipping
  // flag-value pairs (e.g. `--log-level debug`) so that flag values
  // named "proxy" are not mistaken for the subcommand.
  //
  // Rules:
  //   - `--` ends the euno-mcp argument list; stop scanning.
  //   - `--flag=value` style: the flag is self-contained, advance by 1.
  //   - `--flag value`  style: skip both the flag and the next token.
  //   - `-x` (short flag)    : treat as boolean, advance by 1.
  //   - any other token      : positional → check for "proxy".
  let i = 0;
  while (i < args.length) {
    const arg = args[i]!;
    if (arg === '--') return false; // upstream command starts; no subcommand here
    if (arg.startsWith('--')) {
      if (arg.includes('=')) {
        i += 1; // --flag=value — fully self-contained
      } else {
        // --flag value pair: next token is the value iff it doesn't look like a flag
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          i += 2;
        } else {
          i += 1;
        }
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      i += 1; // short flag (-v, -q, …) — treat as boolean
    } else {
      return arg === 'proxy'; // positional argument — must be subcommand
    }
  }
  return false;
}

/**
 * Rewrite the args array for one MCP server entry.
 *
 * 1. Remove `--policy <path>` (two consecutive tokens).
 * 2. Insert `--enforcer-url <url>` and `--enforcer-api-key <key>` just before
 *    `--` (the separator between euno-mcp flags and the upstream command), or
 *    at the end if no `--` is present.
 */
export function patchArgs(
  args: string[],
  enforcerUrl: string,
  apiKey: string,
): string[] {
  // Step 1: remove --policy <path>
  // A token is treated as the policy value if it does not look like a named
  // flag (does not start with '--') and is not the bare '-' sentinel.
  // Single-hyphen paths (e.g. '-/relative/path') are uncommon but valid; the
  // check intentionally accepts them so real-world policy file paths are never
  // silently dropped.
  const withoutPolicy: string[] = [];
  let i = 0;
  while (i < args.length) {
    const next = args[i + 1];
    const nextIsFlag = next === undefined || next === '-' || next.startsWith('--');
    if (args[i] === '--policy' && !nextIsFlag) {
      i += 2; // skip --policy and its value
    } else {
      withoutPolicy.push(args[i]!);
      i++;
    }
  }

  // Step 2: find the '--' separator
  const sepIdx = withoutPolicy.indexOf('--');
  const insertAt = sepIdx === -1 ? withoutPolicy.length : sepIdx;

  const result = [
    ...withoutPolicy.slice(0, insertAt),
    '--enforcer-url',
    enforcerUrl,
    '--enforcer-api-key',
    apiKey,
    ...withoutPolicy.slice(insertAt),
  ];

  return result;
}

/**
 * Apply a set of {@link EntryPatch}es to a config object in-place.
 *
 * Assumes the patches were computed with {@link computeConfigPatch} from the
 * same config object, so the entry references are still valid.
 */
export function applyConfigPatches(
  config: ClaudeDesktopConfig,
  patches: EntryPatch[],
): void {
  for (const patch of patches) {
    const entry = config.mcpServers?.[patch.serverName];
    if (entry) {
      entry.args = patch.after;
    }
  }
}

// ---------------------------------------------------------------------------
// File read / write helpers
// ---------------------------------------------------------------------------

/**
 * Read and JSON-parse a config file.
 *
 * @throws If the file cannot be read or is not valid JSON.
 */
export function readJsonConfigFile(filePath: string): ClaudeDesktopConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(
      `Cannot read config file '${filePath}': ${formatError(err)}`,
    );
  }
  try {
    return JSON.parse(content) as ClaudeDesktopConfig;
  } catch (err) {
    throw new Error(
      `Cannot parse config file '${filePath}' as JSON: ` +
        `${formatError(err)}`,
    );
  }
}

/**
 * Write a config object back to disk as pretty-printed JSON.
 *
 * @throws On write failures.
 */
export function writeJsonConfigFile(filePath: string, config: unknown): void {
  try {
    fs.writeFileSync(filePath, JSON.stringify(config, null, 2) + '\n', 'utf8');
  } catch (err) {
    throw new Error(
      `Cannot write config file '${filePath}': ${formatError(err)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Step result types
// ---------------------------------------------------------------------------

/** Outcome of a single step in the upgrade flow. */
export type StepStatus = 'ok' | 'skipped' | 'error';

export interface StepResult {
  status: StepStatus;
  message: string;
}

// ---------------------------------------------------------------------------
// High-level upgrade orchestration
// ---------------------------------------------------------------------------

/**
 * Options accepted by {@link runUpgrade}.
 */
export interface UpgradeOptions {
  /**
   * Base URL of the Euno gateway / minter service.
   * e.g. `"https://gateway.euno.example"`.
   */
  gatewayUrl: string;

  /**
   * User-facing enforcement API key (`sk-...`).
   * Used for step 1 (validation) and embedded in the patched config files.
   */
  apiKey: string;

  /**
   * Admin API key for policy upload (step 2).
   * If omitted, step 2 is skipped.
   */
  adminKey?: string;

  /**
   * Path to the local policy file to upload.
   * If omitted, step 2 is skipped.
   */
  policyFile?: string;

  /**
   * Additional config file paths to patch (beyond the auto-discovered ones).
   */
  configFiles?: string[];

  /**
   * When `true`, compute and display the changes but do not write anything to disk.
   */
  dryRun?: boolean;

  /** Injectable fetch implementation. Defaults to the global `fetch`. */
  fetcher?: UpgradeFetcher;

  /** Write a line to stdout (overridable for testing). */
  out?: (line: string) => void;
  /** Write a line to stderr (overridable for testing). */
  err?: (line: string) => void;
}

/**
 * Run the upgrade-to-hosted flow end-to-end.
 *
 * @returns Exit code: `0` for full success (or dry-run), `1` on any error.
 */
export async function runUpgrade(opts: UpgradeOptions): Promise<number> {
  const out = opts.out ?? ((line) => process.stdout.write(line + '\n'));
  const err = opts.err ?? ((line) => process.stderr.write(line + '\n'));
  const dryRun = opts.dryRun ?? false;

  const client = new MinterClient({
    baseUrl: opts.gatewayUrl,
    fetcher: opts.fetcher,
  });

  // ── Header ──────────────────────────────────────────────────────────────
  out('');
  out('euno-mcp upgrade-to-hosted');
  out('─'.repeat(50));
  if (dryRun) {
    out('DRY RUN — no files will be modified');
    out('─'.repeat(50));
  }
  out('');

  // ── Step 1: Validate API key ─────────────────────────────────────────────
  out('Step 1 — Validate API key');
  let pingResult: PingResult | undefined;
  try {
    out(`  Checking connectivity: ${opts.gatewayUrl}/health …`);
    await client.health();
    out(`  Validating API key …`);
    pingResult = await client.ping(opts.apiKey);
    out(`  ✓ API key is valid`);
    out(`    tenant : ${pingResult.tenantId}`);
    out(`    policy : ${pingResult.policyId}`);
    out(`    scopes : ${pingResult.scopes.join(', ')}`);
  } catch (e) {
    err(`  ✗ API key validation failed: ${formatError(e)}`);
    err('');
    err('  Make sure --gateway-url and --api-key are correct.');
    err('  See docs/upgrade-to-hosted.md for the manual upgrade path.');
    return 1;
  }
  out('');

  // ── Step 2: Upload policy ────────────────────────────────────────────────
  out('Step 2 — Upload policy to hosted store');
  if (!opts.policyFile || !opts.adminKey) {
    const reason = !opts.policyFile ? '--policy not provided' : '--admin-key not provided';
    out(`  ↷ Skipped (${reason})`);
    out('    Your policy capabilities are already stored on the gateway under');
    out(`    policyId "${pingResult.policyId}".  To update them, re-run with`);
    out('    --policy <file> and --admin-key <key>.');
  } else {
    let manifest: AgentCapabilityManifest;
    try {
      out(`  Loading policy file: ${opts.policyFile} …`);
      manifest = loadManifestFromFile(opts.policyFile);
      out(
        `  ✓ Policy loaded (${manifest.requiredCapabilities.length} required` +
          (manifest.optionalCapabilities?.length
            ? `, ${manifest.optionalCapabilities.length} optional`
            : '') +
          ' capabilities)',
      );
    } catch (e) {
      err(`  ✗ Failed to load policy file: ${formatError(e)}`);
      return 1;
    }

    try {
      if (dryRun) {
        out('  (dry-run) Would call POST /admin/v1/policies — skipping actual upload');
      } else {
        out(`  Uploading capabilities to policyId "${pingResult.policyId}" …`);
        const uploadResult = await client.uploadPolicy({
          adminKey: opts.adminKey,
          policyId: pingResult.policyId,
          manifest,
        });
        out(`  ✓ Policy uploaded successfully`);
        out(`    capabilities : ${uploadResult.capabilityCount}`);
        out(`    keys updated : ${uploadResult.updatedKeys}`);
      }
    } catch (e) {
      err(`  ✗ Policy upload failed: ${formatError(e)}`);
      return 1;
    }
  }
  out('');

  // ── Step 3: Patch config files ───────────────────────────────────────────
  out('Step 3 — Patch config files');
  const discovered = discoverConfigFiles(opts.configFiles ?? []);
  if (discovered.length === 0) {
    out('  ↷ No config files found to patch');
    out('    To configure manually, see docs/upgrade-to-hosted.md');
  } else {
    let anyPatched = false;
    let patchFailed = false;
    for (const info of discovered) {
      out(`  Processing: ${info.label}`);
      out(`    Path: ${info.filePath}`);

      let config: ClaudeDesktopConfig;
      try {
        config = readJsonConfigFile(info.filePath);
      } catch (e) {
        err(
          `    ✗ Could not read/parse file: ${formatError(e)}`,
        );
        patchFailed = true;
        continue;
      }

      const patches = computeConfigPatch(config, opts.gatewayUrl, opts.apiKey);
      if (patches.length === 0) {
        out('    ↷ No euno-mcp proxy entries found (or already upgraded)');
        continue;
      }

      out(`    Found ${patches.length} entry/entries to upgrade:`);
      for (const p of patches) {
        out(`      [${p.serverName}]`);
        // Redact --enforcer-api-key value so it does not appear in terminal
        // history, CI logs, or shell transcripts.
        out(`        before: ${JSON.stringify(redactArgs(p.before))}`);
        out(`        after : ${JSON.stringify(redactArgs(p.after))}`);
      }

      if (dryRun) {
        out('    (dry-run) Would write changes — skipping');
        continue;
      }

      let backupPath: string;
      try {
        backupPath = backupFile(info.filePath);
        out(`    ✓ Backup created: ${path.basename(backupPath)}`);
      } catch (e) {
        err(
          `    ✗ Could not create backup: ${formatError(e)}`,
        );
        patchFailed = true;
        continue;
      }

      try {
        applyConfigPatches(config, patches);
        writeJsonConfigFile(info.filePath, config);
        out(`    ✓ Config file updated`);
        anyPatched = true;
      } catch (e) {
        err(
          `    ✗ Could not write patched config: ${formatError(e)}`,
        );
        err(`    Restore from backup: cp "${backupPath}" "${info.filePath}"`);
        patchFailed = true;
        continue;
      }
    }

    if (anyPatched && !dryRun) {
      out('');
      out('  Restart Claude Desktop (or whichever MCP client you use) to');
      out('  apply the configuration changes.');
    }

    if (patchFailed) {
      err('');
      err('  One or more config files could not be patched (see errors above).');
      err('  The upgrade is incomplete. Re-run after resolving the issues.');
      return 1;
    }
  }
  out('');

  // ── Summary ──────────────────────────────────────────────────────────────
  out('─'.repeat(50));
  if (dryRun) {
    out('Dry run complete — no files were modified.');
    out('Re-run without --dry-run to apply the changes.');
  } else {
    out('Upgrade complete.');
    out('');
    out('Your euno-mcp proxy is now configured to use the hosted gateway.');
    out(`Gateway : ${opts.gatewayUrl}`);
    out(`Tenant  : ${pingResult.tenantId}`);
    out(`Policy  : ${pingResult.policyId}`);
    out('');
    out('For the manual upgrade steps, see: docs/upgrade-to-hosted.md');
  }
  out('');

  return 0;
}

// ---------------------------------------------------------------------------
// Commander command builder
// ---------------------------------------------------------------------------

/**
 * Build the `upgrade-to-hosted` sub-command for the `euno-mcp` CLI.
 */
export function buildUpgradeToHostedCommand(): Command {
  return new Command('upgrade-to-hosted')
    .description(
      'Migrate from local in-process enforcement to the hosted Euno gateway.\n' +
        '  Validates your API key, uploads your local policy, and patches\n' +
        '  your Claude Desktop / mcp.json config to use --enforcer-url.',
    )
    .requiredOption(
      '--gateway-url <url>',
      'Base URL of the Euno gateway / minter service (e.g. https://gateway.euno.example)',
    )
    .requiredOption(
      '--api-key <key>',
      'Your enforcement API key (sk-…)',
    )
    .option(
      '--admin-key <key>',
      'Admin API key for policy upload (required for --policy)',
    )
    .option(
      '--policy <file>',
      'Path to your local YAML/JSON policy file to upload to the hosted store',
    )
    .option(
      '--config <file>',
      'Additional config file to patch (may be repeated)',
      (val: string, prev: string[]) => [...prev, val],
      [] as string[],
    )
    .option(
      '--dry-run',
      'Print what would change without writing any files',
      false,
    )
    .addHelpText(
      'after',
      `
Examples:
  # Validate your API key and patch Claude Desktop config
  euno-mcp upgrade-to-hosted \\
    --gateway-url https://gateway.euno.example \\
    --api-key sk-x7Kp9mRq.bL3n...

  # Also upload a local policy file to the hosted store
  euno-mcp upgrade-to-hosted \\
    --gateway-url https://gateway.euno.example \\
    --api-key sk-x7Kp9mRq.bL3n... \\
    --admin-key <admin-key> \\
    --policy ./euno.policy.yaml

  # Preview changes without modifying anything
  euno-mcp upgrade-to-hosted \\
    --gateway-url https://gateway.euno.example \\
    --api-key sk-x7Kp9mRq.bL3n... \\
    --policy ./euno.policy.yaml --admin-key <admin-key> \\
    --dry-run

Manual path: docs/upgrade-to-hosted.md
`,
    )
    .action(async (options) => {
      const exitCode = await runUpgrade({
        gatewayUrl: options.gatewayUrl as string,
        apiKey: options.apiKey as string,
        adminKey: options.adminKey as string | undefined,
        policyFile: options.policy as string | undefined,
        configFiles: options.config as string[],
        dryRun: options.dryRun as boolean,
      });
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });
}

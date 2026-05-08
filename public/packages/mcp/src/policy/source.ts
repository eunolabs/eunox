/**
 * LocalPolicySource — the local-file policy seam for @euno/mcp.
 *
 * Stage 1 ships {@link FilePolicySource}, which loads a capability manifest
 * from a YAML or JSON file.  Stage 3 replaces this with a JWT loader
 * (signed capability token → AgentCapabilityManifest) without changing the
 * consumer interface ({@link LocalPolicySource}).
 *
 * Supported condition types
 * -------------------------
 * Per docs/mvp.md §"What ships / Stage 1–2":
 *
 *   Stage 1: maxCalls | timeWindow | allowedOperations | allowedExtensions | allowedTables
 *   Stage 2: ipRange (requires HTTP transport; sourceIp is populated by the HTTP layer)
 *
 * Stage-2 lifted condition types (also supported)
 * ------------------------------------------------
 * Per stage2executionplan.md Task 3:
 *
 *   recipientDomain
 *
 *   Recipients are extracted from the tool call arguments (to, recipients,
 *   cc, bcc fields) and matched against the allowed-domains list.
 *
 * The following condition types are structurally valid in the production
 * gateway but are DEFERRED to a later Stage and therefore REJECTED by this
 * loader with an explicit error message:
 *
 *   redactFields | policy | custom
 *
 * Rejecting them (rather than silently accepting) ensures that users get
 * immediate, actionable feedback instead of deploying a manifest whose
 * constraints will not be enforced.
 *
 * @module
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import {
  validateManifest,
  ManifestValidationError,
} from '@euno/common-core';
import type { AgentCapabilityManifest, CapabilityCondition } from '@euno/common-core';

// ---------------------------------------------------------------------------
// Stage-1 condition gate
// ---------------------------------------------------------------------------

/**
 * Condition types that are recognised by the production gateway but are
 * deferred to a later Stage in the euno-mcp local-proxy context.
 *
 * A manifest that contains any of these types in any capability's
 * `conditions` array is rejected at load time with an error message that
 * names the offending JSON path.
 *
 * Stage-2 progress: both `ipRange` (Task 2) and `recipientDomain` (Task 3)
 * have been lifted from this set and are now fully enforced.
 */
const DEFERRED_CONDITION_TYPES: ReadonlySet<string> = new Set([
  'redactFields',
  'policy',
  'custom',
]);

/**
 * Walk every condition in a loaded manifest and throw if any deferred
 * Stage-2 condition type is found.
 *
 * Separate from the structural validation in `validateManifest` so that
 * the production issuer can accept all condition types while the Stage-1
 * local loader enforces a stricter subset.
 */
function rejectDeferredConditions(manifest: AgentCapabilityManifest): void {
  const requiredLen = manifest.requiredCapabilities.length;
  const allConstraints = [
    ...manifest.requiredCapabilities,
    ...(manifest.optionalCapabilities ?? []),
  ];

  for (let ci = 0; ci < allConstraints.length; ci++) {
    const constraint = allConstraints[ci]!;
    const capArray = ci < requiredLen ? 'requiredCapabilities' : 'optionalCapabilities';
    const capIdx = ci < requiredLen ? ci : ci - requiredLen;

    const conditions = constraint.conditions;
    if (!conditions) continue;

    for (let di = 0; di < conditions.length; di++) {
      const condition = conditions[di]! as CapabilityCondition & { type: string };
      if (DEFERRED_CONDITION_TYPES.has(condition.type)) {
        const jsonPath = `${capArray}[${capIdx}].conditions[${di}].type`;
        throw new ManifestValidationError(
          `${jsonPath}: condition type '${condition.type}' is not supported in this Stage — ` +
            `it is deferred to a later Stage. Remove this condition or upgrade to a ` +
            `gateway that supports it.`,
          jsonPath,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// LocalPolicySource interface
// ---------------------------------------------------------------------------

/**
 * The policy-source seam for the euno-mcp proxy.
 *
 * Stage 1 ships {@link FilePolicySource}; Stage 3 will provide a JWT-loader
 * implementation that resolves a signed capability token into a manifest.
 * The consumer (the PDP wired up in Phase B / Task 8) sees only this
 * interface, so the swap is transparent.
 */
export interface LocalPolicySource {
  /**
   * Load (or reload) the {@link AgentCapabilityManifest} from the
   * underlying source.  For a file-backed source this reads and parses the
   * file on every call; callers should cache the result if they want stable
   * semantics across hot-reload events.
   *
   * @throws {@link ManifestValidationError} if the manifest is structurally
   *   or semantically invalid.
   * @throws `Error` (with `code: 'ENOENT'` or similar) if the underlying
   *   file cannot be read.
   */
  load(): Promise<AgentCapabilityManifest>;

  /**
   * Register a callback that is invoked whenever the underlying source
   * changes.  The callback receives the newly-loaded manifest (already
   * validated; if the reloaded file is invalid the callback is not called
   * and the error is forwarded to `onError` if supplied).
   *
   * Returns an unsubscribe function.  Calling it removes the listener and
   * stops any underlying file watch.
   *
   * Implementations are free to debounce rapid-fire change events.
   *
   * @param onChange - Invoked with the new manifest on every valid change.
   * @param onError  - Optional; invoked when a reload fails validation.
   *   Defaults to logging to stderr.
   */
  watch?(
    onChange: (manifest: AgentCapabilityManifest) => void,
    onError?: (err: Error) => void,
  ): () => void;
}

// ---------------------------------------------------------------------------
// FilePolicySource
// ---------------------------------------------------------------------------

/** Options for {@link FilePolicySource}. */
export interface FilePolicySourceOptions {
  /**
   * Path to the YAML (`.yaml` / `.yml`) or JSON (`.json`) manifest file.
   * Relative paths are resolved against `process.cwd()`.
   */
  filePath: string;

  /**
   * Debounce delay in milliseconds applied to file-watch change events.
   * Prevents rapid re-loads triggered by editors that write files in
   * multiple steps (e.g. write-rename or atomic-replace patterns).
   *
   * @default 200
   */
  watchDebounceMs?: number;
}

/**
 * A {@link LocalPolicySource} that loads an {@link AgentCapabilityManifest}
 * from a local YAML or JSON file.
 *
 * File format is determined by the file extension:
 *  - `.yaml` / `.yml` → parsed with js-yaml
 *  - `.json`          → parsed with `JSON.parse`
 *  - anything else    → parsed with js-yaml (YAML is a superset of JSON,
 *                       so valid JSON files without the `.json` extension
 *                       are also accepted)
 *
 * Validation pipeline (fail-fast on first error)
 * -----------------------------------------------
 * 1. File-system read (ENOENT → clear OS error)
 * 2. YAML / JSON parse (syntax error → parse error)
 * 3. Structural schema validation via {@link validateManifest} from
 *    `@euno/common-core` (unknown fields, wrong types, etc.)
 * 4. Stage gate — rejects deferred condition types
 *    (redactFields, policy, custom) with an explicit error message.
 *    Both `ipRange` (Task 2) and `recipientDomain` (Task 3) are now accepted.
 */
export class FilePolicySource implements LocalPolicySource {
  private readonly resolvedPath: string;
  private readonly watchDebounceMs: number;

  constructor(options: FilePolicySourceOptions) {
    this.resolvedPath = path.resolve(options.filePath);
    this.watchDebounceMs = options.watchDebounceMs ?? 200;
  }

  /** @inheritdoc */
  async load(): Promise<AgentCapabilityManifest> {
    const content = await fs.promises.readFile(this.resolvedPath, 'utf8');
    const raw = this._parse(content, this.resolvedPath);
    const manifest = validateManifest(raw);
    rejectDeferredConditions(manifest);
    return manifest;
  }

  /**
   * Parse file content into a raw JavaScript value.
   *
   * YAML is a strict superset of JSON, so js-yaml can parse both.
   * However, `JSON.parse` produces better error messages for JSON files
   * (line/column numbers vs. js-yaml's generic "bad indentation" messages),
   * so we dispatch on the extension.
   */
  private _parse(content: string, filePath: string): unknown {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.json') {
      try {
        return JSON.parse(content) as unknown;
      } catch (err) {
        throw new Error(
          `Failed to parse JSON manifest at '${filePath}': ${String(err)}`,
        );
      }
    }
    // .yaml, .yml, or unknown extension → try YAML
    try {
      return yaml.load(content);
    } catch (err) {
      throw new Error(
        `Failed to parse YAML manifest at '${filePath}': ${String(err)}`,
      );
    }
  }

  /** @inheritdoc */
  watch(
    onChange: (manifest: AgentCapabilityManifest) => void,
    onError?: (err: Error) => void,
  ): () => void {
    const handleError = onError ?? ((err: Error) => {
      process.stderr.write(
        `[euno-mcp] FilePolicySource watch error for '${this.resolvedPath}': ${err.message}\n`,
      );
    });

    let debounceTimer: ReturnType<typeof setTimeout> | undefined;

    const reload = (): void => {
      this.load().then(onChange).catch(handleError);
    };

    const watcher = fs.watch(this.resolvedPath, (_event) => {
      if (debounceTimer !== undefined) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(reload, this.watchDebounceMs);
    });

    // Surface unexpected watcher errors (e.g. permissions change, disk
    // errors) rather than swallowing them.
    watcher.on('error', handleError);

    return () => {
      if (debounceTimer !== undefined) clearTimeout(debounceTimer);
      watcher.close();
    };
  }
}

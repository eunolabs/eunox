/**
 * PDP mode selection helpers (MH-R2).
 *
 * This module is extracted from `cli.ts` so it can be unit-tested without
 * triggering `program.parse(process.argv)` at import time.
 *
 * See `cli.ts` for the integration: it imports `buildPdp` and
 * `EnforcementMode` from here and calls `buildPdp(enforcementMode)` inside
 * the `proxy` command's action handler.
 */

import { FilePolicySource } from '../policy/source';
import {
  loadCustomConditionModules,
  validateCustomConditionRegistrations,
} from '../policy/custom-handlers';
import { loadPolicyBackends } from '../policy/backends';
import { ConditionEnforcerPDP, AlwaysAllowPDP, PolicyDecisionPoint } from '../pdp';
import { RemoteEnforcerPDP } from '../enforcer/remote';

// ---------------------------------------------------------------------------
// Discriminated union
// ---------------------------------------------------------------------------

/**
 * Discriminated union representing the two mutually-exclusive PDP modes.
 *
 * Adding a third enforcement mode requires:
 *  1. Adding a new member here.
 *  2. Adding a matching arm in {@link buildPdp}.
 *
 * The boolean `isRemoteMode` flag that previously threaded through the
 * `proxy` action has been replaced by this union so the mode boundary is
 * explicit at construction time and additional modes do not require
 * rewriting a cascading `if/else` block.
 */
export type EnforcementMode =
  | {
      mode: 'remote';
      /** Gateway URL (validated non-empty by the CLI option parser). */
      url: string;
      /** API key sent as a Bearer token on every enforce request. */
      apiKey: string;
      /** Per-request timeout in milliseconds. */
      timeoutMs?: number;
      /** CLI flags that are silently ignored in remote mode (used for warnings). */
      ignoredCustomConditionModules: string[];
      ignoredPolicyBackendPaths: string[];
    }
  | {
      mode: 'local';
      /** Path to the YAML/JSON policy file, if any. */
      policyPath?: string;
      /** Paths to custom-condition handler modules to load before serving. */
      customConditionModules: string[];
      /** Paths to policy backend modules to load before serving. */
      policyBackendPaths: string[];
    };

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Return type of {@link buildPdp}. */
export interface BuildPdpResult {
  pdp: PolicyDecisionPoint;
  /**
   * The local `ConditionEnforcerPDP` instance, when one was created.
   * Present only in `'local'` mode when a policy file was provided.
   * Callers use this to wire the kill-switch controller and to call
   * `dispose()` on shutdown.
   */
  conditionPdp?: ConditionEnforcerPDP;
}

/**
 * Build the PDP (Policy Decision Point) from the resolved enforcement mode.
 *
 * In `'remote'` mode all enforcement is delegated to the hosted gateway;
 * local infrastructure (FilePolicySource, custom-condition modules, policy
 * backends) is intentionally skipped and a warning is emitted for any
 * conflicting flags the operator supplied.
 *
 * In `'local'` mode the function loads custom-condition modules, parses and
 * validates the policy file (if provided), and loads policy backend modules.
 * Any fatal error during loading is written to stderr and causes the process
 * to exit with code 1.
 *
 * @returns The constructed PDP and the optional `ConditionEnforcerPDP`
 *          instance for lifecycle management (kill-switch wiring, dispose).
 */
export async function buildPdp(mode: EnforcementMode): Promise<BuildPdpResult> {
  if (mode.mode === 'remote') {
    if (mode.ignoredCustomConditionModules.length > 0) {
      process.stderr.write(
        `[euno-mcp] WARNING: --custom-condition is ignored in remote-enforcer mode ` +
          `(--enforcer-url). Custom conditions are registered on the gateway.\n`,
      );
    }
    if (mode.ignoredPolicyBackendPaths.length > 0) {
      process.stderr.write(
        `[euno-mcp] WARNING: --policy-backend is ignored in remote-enforcer mode ` +
          `(--enforcer-url). Policy backends are registered on the gateway.\n`,
      );
    }
    const pdp = new RemoteEnforcerPDP({
      url: mode.url,
      apiKey: mode.apiKey,
      timeoutMs: mode.timeoutMs,
    });
    process.stderr.write(
      `[euno-mcp] Remote-enforcer mode: enforcement delegated to ${mode.url}\n`,
    );
    return { pdp };
  }

  // ── local mode ────────────────────────────────────────────────────────────
  const { policyPath, customConditionModules, policyBackendPaths } = mode;

  if (customConditionModules.length > 0) {
    try {
      await loadCustomConditionModules(customConditionModules);
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exit(1);
    }
  }

  let conditionPdp: ConditionEnforcerPDP | undefined;
  let pdp: PolicyDecisionPoint;

  if (policyPath) {
    const policySource = new FilePolicySource({ filePath: policyPath });
    try {
      const manifest = await policySource.load();
      validateCustomConditionRegistrations(manifest);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const hint = /custom condition '[^']*' has no registered handler/.test(message)
        ? ' Hint: load the handler with --custom-condition <module>.'
        : '';
      process.stderr.write(`[euno-mcp] Policy validation failed: ${message}${hint}\n`);
      process.exit(1);
    }
    conditionPdp = new ConditionEnforcerPDP({ policySource });
    pdp = conditionPdp;
  } else {
    pdp = new AlwaysAllowPDP();
  }

  if (policyBackendPaths.length > 0) {
    try {
      await loadPolicyBackends(policyBackendPaths);
    } catch {
      // loadPolicyBackends already wrote a human-readable message to stderr.
      process.exit(1);
    }
  }

  return { pdp, conditionPdp };
}

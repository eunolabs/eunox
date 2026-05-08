/**
 * Policy-backend module loader for @euno/mcp.
 *
 * Operators can plug external policy engines (OPA, Cedar, custom rules) into
 * the euno-mcp proxy by registering them as policy backends.  Each backend
 * module must export a default function that receives the registry API and
 * calls {@link registerPolicyBackend} once for each backend it provides.
 *
 * ## Module contract
 *
 * ```ts
 * // my-policy-backend.ts (or .js)
 * import type { PolicyBackend } from '@euno/common-core';
 *
 * const myBackend: PolicyBackend = {
 *   validate(config) { /* validate backend-specific config *\/ },
 *   async enforce(config, input, ctx) {
 *     const allowed = await callMyEngine(config, input, ctx);
 *     return { allow: allowed, reason: allowed ? undefined : 'denied by policy engine' };
 *   },
 * };
 *
 * export default function register(api: { registerPolicyBackend: Function }) {
 *   api.registerPolicyBackend('my-engine', myBackend);
 * }
 * ```
 *
 * See {@link docs/policy-backends.md} for the full contract and a worked OPA example.
 *
 * ## Path resolution
 *
 * Module paths follow the same rules as Node.js `import()`:
 *  - Absolute paths (`/abs/path/to/module.js`) are used directly.
 *  - Relative paths (`./relative/module.js`) are resolved against
 *    `process.cwd()` (the working directory where `euno-mcp` is invoked).
 *  - Bare specifiers (`my-module`) are resolved from `node_modules`.
 *
 * Both CommonJS and ESM modules are supported.
 *
 * @module
 */

import * as path from 'path';
import {
  registerPolicyBackend,
  type PolicyBackend,
} from '@euno/common-core';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * The type of the default export required from every policy-backend module.
 *
 * The function receives the registry API object and should call
 * {@link registerPolicyBackend} once for each backend it provides.  An async
 * function is acceptable — the loader `await`s the return value.
 */
export type PolicyBackendRegistrar = (api: {
  registerPolicyBackend: (name: string, backend: PolicyBackend) => void;
}) => void | Promise<void>;

/**
 * Load policy-backend modules from the supplied paths, calling each module's
 * default export with the `{ registerPolicyBackend }` API.
 *
 * This function is called once at proxy startup — before any requests are
 * served — so an error in any module causes the process to exit with a clear
 * message rather than starting with a partially-wired backend set.
 *
 * @param modulePaths - Ordered list of module paths to load.  May be empty
 *   (in which case this function is a no-op).
 * @throws Re-throws any module load or registration error after writing a
 *   human-readable message to `process.stderr`.
 */
export async function loadPolicyBackends(modulePaths: readonly string[]): Promise<void> {
  for (const modulePath of modulePaths) {
    // Resolve paths that begin with './' or '../' relative to cwd so the
    // caller can pass raw CLI arguments without knowing this file's location.
    // Absolute paths and bare specifiers (e.g. 'my-npm-package') are passed
    // through unchanged — Node.js handles them via its normal resolution
    // algorithm (node_modules lookup, package.json exports, etc.).
    const isRelative =
      modulePath.startsWith('./') || modulePath.startsWith('../');
    const resolvedPath = isRelative
      ? path.resolve(process.cwd(), modulePath)
      : modulePath;

    let mod: { default?: unknown };
    try {
      mod = (await import(resolvedPath)) as { default?: unknown };
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] Failed to load policy backend module '${modulePath}': ${String(err)}\n`,
      );
      throw err;
    }

    const defaultExport = mod.default;
    if (typeof defaultExport !== 'function') {
      const message =
        `Policy backend module '${modulePath}' must export a default function ` +
        `(api: { registerPolicyBackend }) => void, ` +
        `but its default export is ${defaultExport === null ? 'null' : typeof defaultExport}. ` +
        `See docs/policy-backends.md for the module contract.`;
      process.stderr.write(`[euno-mcp] ${message}\n`);
      throw new Error(message);
    }

    // Wrap registerPolicyBackend to capture each registered name for the log
    // line.  The outer registry is the shared @euno/common-core singleton so
    // the Stage-3 gateway sees the same registrations unchanged.
    const registeredNames: string[] = [];
    const wrappedRegister = (name: string, backend: PolicyBackend): void => {
      registerPolicyBackend(name, backend);
      registeredNames.push(name);
    };

    try {
      await (defaultExport as PolicyBackendRegistrar)({ registerPolicyBackend: wrappedRegister });
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] Error registering policy backends from '${modulePath}': ${String(err)}\n`,
      );
      throw err;
    }

    for (const name of registeredNames) {
      process.stderr.write(`[euno-mcp] registered policy backend: ${name}\n`);
    }
  }
}

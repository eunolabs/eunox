/**
 * `loadConfig` — typed, fail-fast configuration loader.
 *
 * Replaces the pattern of inlining `process.env.FOO || 'default'`
 * across each service entry-point.  See R-5 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`: misconfig must produce a
 * single, structured "what's wrong" report rather than partial
 * defaults that get caught later, deeper in the stack.
 */

import { ZodError } from 'zod';
import {
  EUNO_CONFIG_SCHEMAS,
  EunoServiceName,
  EunoConfigFor,
} from './schema';

/**
 * One concrete validation failure, in a shape that's friendly to both
 * humans (formatted error) and operator tooling (structured field).
 */
export interface ConfigError {
  /** Env-var name (top-level field), or `''` for cross-field errors. */
  field: string;
  /** Operator-facing failure description. */
  message: string;
}

/**
 * Discriminated-union result returned by {@link loadConfig}.  Callers
 * either get the typed config or the *complete* list of problems —
 * never a partially-populated config.
 */
export type LoadConfigResult<S extends EunoServiceName> =
  | { ok: true; config: EunoConfigFor<S> }
  | { ok: false; errors: ConfigError[] };

/**
 * Validate a process-environment-shaped record against the schema for
 * the named service.  This function is pure: it does not read
 * `process.env` itself, does not log, and does not exit — it returns
 * the result so callers can decide how to surface failures.  See
 * {@link loadConfigOrExit} for the boot-time convenience wrapper.
 */
export function loadConfig<S extends EunoServiceName>(
  env: NodeJS.ProcessEnv,
  service: S,
): LoadConfigResult<S> {
  const schema = EUNO_CONFIG_SCHEMAS[service];
  const result = schema.safeParse(env);
  if (result.success) {
    return { ok: true, config: result.data as EunoConfigFor<S> };
  }
  return { ok: false, errors: zodErrorToConfigErrors(result.error) };
}

function zodErrorToConfigErrors(err: ZodError): ConfigError[] {
  return err.issues.map((issue) => {
    // For top-level field errors the path is `[FIELD_NAME]`.  For
    // cross-field errors raised in `superRefine` we use the same
    // pattern so the operator sees which env var to fix; only fall back
    // to '' for genuinely structural issues with no path.
    const field = issue.path.length > 0 ? String(issue.path[0]) : '';
    return { field, message: issue.message };
  });
}

/**
 * Format a list of {@link ConfigError}s as a single human-readable
 * block suitable for logging or printing to stderr at boot.
 */
export function formatConfigErrors(
  service: string,
  errors: ConfigError[],
): string {
  const header = `Invalid ${service} configuration — ${errors.length} problem${
    errors.length === 1 ? '' : 's'
  }:`;
  const bullets = errors.map((e) =>
    e.field ? `  • ${e.field}: ${e.message}` : `  • ${e.message}`,
  );
  return [header, ...bullets].join('\n');
}

/**
 * Boot-time convenience: validate the environment and either return
 * the typed config or print the structured error report to stderr and
 * call `process.exit(1)`.  Use from each service's `index.ts`:
 *
 * ```ts
 * const config = loadConfigOrExit(process.env, 'issuer');
 * ```
 */
export function loadConfigOrExit<S extends EunoServiceName>(
  env: NodeJS.ProcessEnv,
  service: S,
): EunoConfigFor<S> {
  const result = loadConfig(env, service);
  if (result.ok) {
    return result.config;
  }
  // Use stderr directly rather than the structured logger: at this
  // point the logger may not yet be initialised, and the operator
  // benefits from a single, easy-to-read block.
  // eslint-disable-next-line no-console
  console.error(formatConfigErrors(service, result.errors));
  process.exit(1);
}

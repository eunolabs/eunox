/**
 * Test fixture: echo-deny policy backend.
 *
 * Always denies.  Used in unit and integration tests for the policy-backend
 * module loader (stage2executionplan.md Task 5).
 *
 * Usage in tests:
 * ```ts
 * import type { PolicyBackendRegistrar } from '../../src/policy/backends';
 * import registerEchoDeny from './policy-backends/echo-deny';
 * ```
 *
 * Or via the loader:
 * ```ts
 * await loadPolicyBackends([require.resolve('./policy-backends/echo-deny')]);
 * ```
 */

import type { PolicyBackend } from '@euno/common-core';

/** The registered backend name — used in test policy manifests. */
export const ECHO_DENY_BACKEND_NAME = 'echo-deny';

const echoDenyBackend: PolicyBackend = {
  validate(_config: unknown): void {
    // This fixture backend accepts any config (or none).
  },
  enforce(
    _config: unknown,
    _input: unknown,
  ): { allow: false; reason: string } {
    return { allow: false, reason: 'echo-deny: always denied by test backend' };
  },
};

/**
 * Default export — the module registrar function expected by
 * {@link loadPolicyBackends}.
 */
export default function register(api: {
  registerPolicyBackend: (name: string, backend: PolicyBackend) => void;
}): void {
  api.registerPolicyBackend(ECHO_DENY_BACKEND_NAME, echoDenyBackend);
}

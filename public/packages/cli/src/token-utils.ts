/**
 * Shared helpers for persisting capability-token JWTs to the local file system.
 *
 * Extracted from `src/index.ts` so the token-persistence code path can be
 * exercised directly in integration tests (see
 * `euno-platform/packages/integration-tests/tests/cli-issuer.test.ts`)
 * without re-implementing or patching the same `writeFileSync` + `chmodSync`
 * sequence.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Returns the default directory in which `saveCapabilityToken` stores tokens:
 * `~/.euno/tokens`.
 */
export function defaultTokenDir(): string {
  return path.join(os.homedir(), '.euno', 'tokens');
}

/**
 * Write a capability-token JWT to `<tokenDir>/<agentId>.jwt` with strict
 * Unix permissions (0600) so the private token is not world-readable.
 *
 * The parent directory is created with mode 0700 when absent.
 *
 * @param tokenDir  Directory to store the token in.  Callers usually pass
 *                  {@link defaultTokenDir} or an isolated temp directory in
 *                  tests.
 * @param agentId   Agent identifier; used as the filename stem.
 * @param token     The raw JWT string to persist.
 * @returns         The absolute path of the written file.
 */
export function saveCapabilityToken(
  tokenDir: string,
  agentId: string,
  token: string,
): string {
  if (!fs.existsSync(tokenDir)) {
    fs.mkdirSync(tokenDir, { recursive: true, mode: 0o700 });
  }
  const tokenPath = path.join(tokenDir, `${agentId}.jwt`);
  fs.writeFileSync(tokenPath, token);
  fs.chmodSync(tokenPath, 0o600);
  return tokenPath;
}

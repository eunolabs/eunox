/**
 * HMAC key management for the local audit log.
 *
 * The 32-byte symmetric key is persisted to a file in `~/.euno/` so audit
 * records written by different process invocations are all verifiable with
 * the same key. The file is created with mode 0600 (owner read/write only)
 * so other users on the same machine cannot read it.
 *
 * ### Key lifecycle
 *
 * | Condition                              | Behaviour                                     |
 * | -------------------------------------- | --------------------------------------------- |
 * | File does not exist                    | Create dir, generate key, write 0600          |
 * | File exists, readable, correct length  | Load and use it                               |
 * | File exists, readable, too permissive  | Load it, emit a stderr warning (POSIX only)   |
 * | File exists but is NOT readable        | Fail-fast (throw HmacKeyError)                |
 * | Concurrent creation (race)             | One writer wins; loser loads the winner's key |
 *
 * ### Why HMAC, not a private key?
 *
 * Stage 1 is fully local — there is no external verifier. A 32-byte random
 * symmetric key is sufficient to detect in-process tampering and accidental
 * corruption. Stage 3 will swap this for an asymmetric signing key (RSA-PSS
 * or ECDSA) once a remote verifier / KMS is introduced; the `LocalHmacSigner`
 * is designed to be a drop-in for `CryptoSigner`.
 *
 * @module
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** Default directory for Euno local state files. */
export const EUNO_STATE_DIR = path.join(os.homedir(), '.euno');

/** Default path for the HMAC signing key. */
export const DEFAULT_KEY_PATH = path.join(EUNO_STATE_DIR, 'key');

/** Size of the HMAC key in bytes. */
const KEY_BYTES = 32;

/** File mode for the key file: owner read/write only. */
const KEY_FILE_MODE = 0o600;

/**
 * Error thrown when the key file exists but cannot be read (e.g. wrong
 * permissions, corrupted, locked by another process).
 *
 * This is a fail-fast condition: continuing with a missing key would silently
 * produce unverifiable audit records, which defeats the tamper-evidence
 * guarantee.
 */
export class HmacKeyError extends Error {
  constructor(
    public readonly keyPath: string,
    cause: unknown,
  ) {
    const causeMsg = cause instanceof Error ? cause.message : String(cause);
    super(`Failed to read HMAC key at ${keyPath}: ${causeMsg}. ` +
      `If the file is unreadable due to permissions, run: chmod 600 ${keyPath}`);
    this.name = 'HmacKeyError';
  }
}

/**
 * Load the HMAC key from `keyPath`, creating it if it does not exist.
 *
 * On first call (file absent):
 *   1. Ensures the parent directory exists (`mkdir -p`).
 *   2. Generates `KEY_BYTES` random bytes via `crypto.randomBytes`.
 *   3. Writes the raw bytes to `keyPath` with mode 0600.
 *
 * On subsequent calls (file present):
 *   - Returns the raw bytes exactly as written.
 *   - On POSIX, warns (to stderr) when the key file's permissions are too
 *     permissive (group- or world-readable/writable) but still returns the
 *     key — operators can remediate with `chmod 600`.
 *
 * If the file exists but cannot be read, throws {@link HmacKeyError}
 * (fail-fast; do not silently fall back to a new key).
 *
 * Concurrent creation (two processes both hitting ENOENT simultaneously) is
 * handled with atomic link-based no-clobber semantics: whichever process
 * loses the race loads the winner's key rather than overwriting it.
 *
 * @param keyPath  Path to the key file. Defaults to {@link DEFAULT_KEY_PATH}.
 */
export async function loadOrCreateHmacKey(
  keyPath: string = DEFAULT_KEY_PATH,
): Promise<Buffer> {
  // Try to read the existing key first.
  try {
    const [data, stat] = await Promise.all([
      fs.promises.readFile(keyPath),
      fs.promises.stat(keyPath),
    ]);
    if (data.length !== KEY_BYTES) {
      throw new HmacKeyError(
        keyPath,
        `key file has unexpected length ${data.length} (expected ${KEY_BYTES})`,
      );
    }
    // Warn when the key is world- or group-readable/writable (POSIX only).
    if (process.platform !== 'win32') {
      const loose = stat.mode & 0o077;
      if (loose !== 0) {
        process.stderr.write(
          `[euno-mcp] Warning: HMAC key file ${keyPath} has permissions ` +
            `${(stat.mode & 0o777).toString(8)} — other users may be able to ` +
            `read or write it. Run: chmod 600 ${keyPath}\n`,
        );
      }
    }
    return data;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      // File does not exist — create it.
      return createHmacKey(keyPath);
    }
    if (err instanceof HmacKeyError) {
      throw err;
    }
    // File exists but is unreadable or otherwise broken — fail fast.
    throw new HmacKeyError(keyPath, err);
  }
}

/**
 * Generate a new key and write it atomically to `keyPath` using a
 * write-then-link pattern that is race-safe across concurrent processes.
 *
 * Steps:
 *   1. Write a fresh key to a temp file (`keyPath.tmp.<pid>.<random>`) using
 *      the exclusive-create (`wx`) flag so two concurrent invocations always
 *      produce different temp files.
 *   2. Hard-link the temp file to `keyPath` (atomic no-clobber on POSIX and
 *      Windows NTFS).  If `keyPath` already exists (another process won the
 *      race), the link fails with EEXIST and we load that process's key
 *      instead — guaranteeing that all concurrent callers converge on the
 *      same key.
 *   3. Clean up the temp file unconditionally.
 */
async function createHmacKey(keyPath: string): Promise<Buffer> {
  const dir = path.dirname(keyPath);
  // Ensure the parent directory exists with permissive mode; the key file
  // itself is the sensitive asset, not the directory.
  await fs.promises.mkdir(dir, { recursive: true });

  const key = crypto.randomBytes(KEY_BYTES);
  // Add 4 random bytes so concurrent processes write to distinct temp paths.
  const tmpPath = `${keyPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;

  try {
    // Write temp file with exclusive-create flag (fails if it somehow exists).
    await fs.promises.writeFile(tmpPath, key, { mode: KEY_FILE_MODE, flag: 'wx' });

    try {
      // Atomic no-clobber: link fails with EEXIST if keyPath already exists.
      await fs.promises.link(tmpPath, keyPath);
      // We own the key file — best-effort chmod in case umask was too loose.
      try {
        await fs.promises.chmod(keyPath, KEY_FILE_MODE);
      } catch {
        process.stderr.write(
          `[euno-mcp] Warning: could not chmod ${keyPath} to 0600. ` +
            `Ensure the file is only readable by the current user.\n`,
        );
      }
      return key;
    } catch (linkErr) {
      if ((linkErr as NodeJS.ErrnoException).code === 'EEXIST') {
        // Another process won the race — load the key they created.
        const existing = await fs.promises.readFile(keyPath);
        if (existing.length !== KEY_BYTES) {
          throw new HmacKeyError(
            keyPath,
            `key file has unexpected length ${existing.length} (expected ${KEY_BYTES})`,
          );
        }
        return existing;
      }
      throw new HmacKeyError(keyPath, linkErr);
    }
  } finally {
    // Always clean up the temp file regardless of success or failure.
    try { await fs.promises.unlink(tmpPath); } catch { /* ignore */ }
  }
}

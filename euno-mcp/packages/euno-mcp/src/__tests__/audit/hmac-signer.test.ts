/**
 * Tests for LocalHmacSigner and loadOrCreateHmacKey.
 *
 * Coverage:
 *   - HMAC sign/verify round-trip
 *   - CryptoSigner-compatible signDigest/verifyDigest
 *   - Key creation (including file mode 0600 on POSIX)
 *   - Fail-fast when key file is unreadable
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LocalHmacSigner, LOCAL_HMAC_KEY_ID, LOCAL_HMAC_ALGORITHM } from '../../audit/hmac-signer';
import { loadOrCreateHmacKey, HmacKeyError } from '../../audit/hmac-key';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'euno-hmac-test-'));
}

function randomKey(): Buffer {
  return crypto.randomBytes(32);
}

// ---------------------------------------------------------------------------
// LocalHmacSigner
// ---------------------------------------------------------------------------

describe('LocalHmacSigner', () => {
  const key = randomKey();
  const signer = new LocalHmacSigner(key);

  describe('identity', () => {
    it('exposes the expected keyId', () => {
      expect(signer.keyId).toBe(LOCAL_HMAC_KEY_ID);
    });

    it('exposes the expected algorithm', () => {
      expect(signer.algorithm).toBe(LOCAL_HMAC_ALGORITHM);
    });

    it('getKeyId() resolves to keyId (async)', async () => {
      await expect(signer.getKeyId()).resolves.toBe(LOCAL_HMAC_KEY_ID);
    });

    it('getAlgorithm() returns algorithm (sync)', () => {
      expect(signer.getAlgorithm()).toBe(LOCAL_HMAC_ALGORITHM);
    });
  });

  describe('sign / verify round-trip', () => {
    it('verifies a tag it produced', () => {
      const payload = '{"class_uid":6003,"decision":"allow"}';
      const tag = signer.sign(payload);
      expect(signer.verify(payload, tag)).toBe(true);
    });

    it('rejects a tampered payload', () => {
      const tag = signer.sign('{"class_uid":6003,"decision":"allow"}');
      expect(signer.verify('{"class_uid":6003,"decision":"deny"}', tag)).toBe(false);
    });

    it('rejects a truncated tag', () => {
      const tag = signer.sign('hello');
      expect(signer.verify('hello', tag.slice(0, -4))).toBe(false);
    });

    it('rejects an empty tag', () => {
      expect(signer.verify('hello', '')).toBe(false);
    });

    it('produces different tags for different payloads', () => {
      const t1 = signer.sign('payload-a');
      const t2 = signer.sign('payload-b');
      expect(t1).not.toBe(t2);
    });

    it('produces consistent tags for the same payload', () => {
      const payload = 'deterministic-payload';
      expect(signer.sign(payload)).toBe(signer.sign(payload));
    });
  });

  describe('signDigest / verifyDigest (CryptoSigner compat)', () => {
    it('produces a verifiable digest signature', async () => {
      const digest = crypto.createHash('sha256').update('test').digest();
      const sig = await signer.signDigest(digest);
      const ok = await signer.verifyDigest(digest, sig, LOCAL_HMAC_KEY_ID, LOCAL_HMAC_ALGORITHM);
      expect(ok).toBe(true);
    });

    it('rejects wrong keyId', async () => {
      const digest = crypto.createHash('sha256').update('test').digest();
      const sig = await signer.signDigest(digest);
      const ok = await signer.verifyDigest(digest, sig, 'wrong-key-id', LOCAL_HMAC_ALGORITHM);
      expect(ok).toBe(false);
    });

    it('rejects wrong algorithm', async () => {
      const digest = crypto.createHash('sha256').update('test').digest();
      const sig = await signer.signDigest(digest);
      const ok = await signer.verifyDigest(digest, sig, LOCAL_HMAC_KEY_ID, 'rsa-pss');
      expect(ok).toBe(false);
    });

    it('rejects a tampered signature', async () => {
      const digest = crypto.createHash('sha256').update('test').digest();
      const sig = await signer.signDigest(digest);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      sig[0]! ^= 0xff; // flip bits
      const ok = await signer.verifyDigest(digest, sig, LOCAL_HMAC_KEY_ID, LOCAL_HMAC_ALGORITHM);
      expect(ok).toBe(false);
    });
  });

  describe('construction guards', () => {
    it('throws when key is too short', () => {
      expect(() => new LocalHmacSigner(Buffer.alloc(8))).toThrow(RangeError);
    });

    it('accepts a custom keyId', () => {
      const s = new LocalHmacSigner(randomKey(), 'my-custom-key-v2');
      expect(s.keyId).toBe('my-custom-key-v2');
    });
  });

  describe('key isolation', () => {
    it('two signers with different keys produce different tags', () => {
      const s1 = new LocalHmacSigner(randomKey());
      const s2 = new LocalHmacSigner(randomKey());
      const payload = 'shared payload';
      expect(s1.sign(payload)).not.toBe(s2.sign(payload));
    });

    it('a tag from signer-1 does not verify under signer-2', () => {
      const s1 = new LocalHmacSigner(randomKey());
      const s2 = new LocalHmacSigner(randomKey());
      const tag = s1.sign('hello');
      expect(s2.verify('hello', tag)).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// loadOrCreateHmacKey
// ---------------------------------------------------------------------------

describe('loadOrCreateHmacKey', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('creates a 32-byte key file when none exists', async () => {
    const keyPath = path.join(dir, 'key');
    const key = await loadOrCreateHmacKey(keyPath);
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it('creates the parent directory if it does not exist', async () => {
    const nested = path.join(dir, 'a', 'b', 'c');
    const keyPath = path.join(nested, 'key');
    await loadOrCreateHmacKey(keyPath);
    expect(fs.existsSync(keyPath)).toBe(true);
  });

  it('returns the same key on subsequent calls', async () => {
    const keyPath = path.join(dir, 'key');
    const k1 = await loadOrCreateHmacKey(keyPath);
    const k2 = await loadOrCreateHmacKey(keyPath);
    expect(k1.equals(k2)).toBe(true);
  });

  it('throws HmacKeyError if the key file is unreadable', async () => {
    // Only meaningful on POSIX systems where file permissions are enforced.
    if (process.platform === 'win32') return;
    // Also skip if running as root (root ignores file permissions).
    if (process.getuid && process.getuid() === 0) return;

    const keyPath = path.join(dir, 'key');
    await loadOrCreateHmacKey(keyPath);
    // Remove read permission.
    fs.chmodSync(keyPath, 0o200);

    await expect(loadOrCreateHmacKey(keyPath)).rejects.toThrow(HmacKeyError);
  });

  it('sets the key file mode to 0600 on POSIX', async () => {
    if (process.platform === 'win32') return;
    // Also skip if running as root.
    if (process.getuid && process.getuid() === 0) return;

    const keyPath = path.join(dir, 'key');
    await loadOrCreateHmacKey(keyPath);

    const stat = fs.statSync(keyPath);
    // Extract the permission bits (lower 9 bits).
    const mode = stat.mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('throws HmacKeyError for a key file with wrong length', async () => {
    const keyPath = path.join(dir, 'key');
    fs.writeFileSync(keyPath, Buffer.alloc(16)); // wrong length
    await expect(loadOrCreateHmacKey(keyPath)).rejects.toThrow(HmacKeyError);
  });

  it('emits a stderr warning when the key file is world-readable (POSIX)', async () => {
    if (process.platform === 'win32') return;
    if (process.getuid && process.getuid() === 0) return;

    const keyPath = path.join(dir, 'key');
    // Write a valid 32-byte key with loose permissions.
    fs.writeFileSync(keyPath, crypto.randomBytes(32), { mode: 0o644 });

    const written: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = (chunk: unknown) => {
      if (typeof chunk === 'string') written.push(chunk);
      return origWrite(chunk as Parameters<typeof origWrite>[0]);
    };

    try {
      await loadOrCreateHmacKey(keyPath);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stderr as any).write = origWrite;
    }

    const allOutput = written.join('');
    expect(allOutput).toMatch(/Warning.*644|0600/);
  });

  it('handles a concurrent creation race: both callers get the same key', async () => {
    const keyPath = path.join(dir, 'race-key');
    // Fire two concurrent createHmacKey calls (via loadOrCreateHmacKey).
    const [k1, k2] = await Promise.all([
      loadOrCreateHmacKey(keyPath),
      loadOrCreateHmacKey(keyPath),
    ]);
    // Both should return a valid 32-byte key.
    expect(k1).toBeInstanceOf(Buffer);
    expect(k1.length).toBe(32);
    expect(k2.length).toBe(32);
    // Only one key file should exist on disk.
    expect(fs.existsSync(keyPath)).toBe(true);
    const onDisk = fs.readFileSync(keyPath);
    // Both in-memory keys must match the on-disk key.
    expect(k1.equals(onDisk) || k2.equals(onDisk)).toBe(true);
  });
});

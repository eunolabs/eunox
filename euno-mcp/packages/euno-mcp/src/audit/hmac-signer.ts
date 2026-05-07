/**
 * Local HMAC-SHA-256 signer for @euno/mcp audit records.
 *
 * The signer computes `HMAC-SHA-256(key, SHA-256(canonical_json))` over the
 * canonical JSON representation of each record's unsigned body. The output is
 * standard base64-encoded (not base64url) and is included in the record as an
 * `enrichments` entry so downstream verifiers can check it without
 * Euno-specific parsers.
 *
 * The double-hash step — SHA-256 then HMAC-SHA-256 — allows the same signing
 * primitive to be used as a `CryptoSigner` (which pre-hashes payloads before
 * calling `signDigest`) without any interface change.
 *
 * ### Stage 3 interoperability
 *
 * `LocalHmacSigner` follows the same interface contract as the production
 * `CryptoSigner` from `@euno/common-core/src/evidence.ts`: it exposes
 * `signDigest`, `getKeyId`, and `getAlgorithm`. Stage 3 will swap this class
 * for an RSA-PSS or ECDSA signer backed by a KMS without touching the audit
 * sink.
 *
 * @module
 */

import * as crypto from 'crypto';

/**
 * Key ID embedded in every signed record.  The `v1` suffix allows future
 * key-rotation schemes to issue new key IDs without changing the format.
 */
export const LOCAL_HMAC_KEY_ID = 'local-hmac-v1' as const;

/** OCSF-compatible algorithm name. */
export const LOCAL_HMAC_ALGORITHM = 'hmac-sha256' as const;

/**
 * Local HMAC-SHA-256 signing primitive.
 *
 * The key is a 32-byte `Buffer` sourced from
 * {@link loadOrCreateHmacKey} (typically `~/.euno/key`).
 *
 * The signer is **stateless** between calls and **thread-safe**: each
 * invocation creates a fresh `crypto.createHmac` context.
 */
export class LocalHmacSigner {
  private readonly _key: Buffer;
  private readonly _keyId: string;

  /**
   * @param key    32-byte HMAC key.
   * @param keyId  Key identifier embedded in signed records. Defaults to
   *               {@link LOCAL_HMAC_KEY_ID}.
   */
  constructor(key: Buffer, keyId: string = LOCAL_HMAC_KEY_ID) {
    if (key.length < 16) {
      throw new RangeError(
        `HMAC key must be at least 16 bytes; got ${key.length}`,
      );
    }
    this._key = key;
    this._keyId = keyId;
  }

  /** Key identifier embedded in signed records. */
  get keyId(): string {
    return this._keyId;
  }

  /** Algorithm identifier for OCSF enrichments. */
  get algorithm(): string {
    return LOCAL_HMAC_ALGORITHM;
  }

  // ── CryptoSigner-compatible interface ───────────────────────────────────

  /** Async key-id accessor (matches `CryptoSigner.getKeyId`). */
  async getKeyId(): Promise<string> {
    return this._keyId;
  }

  /** Algorithm name (matches `CryptoSigner.getAlgorithm`). */
  getAlgorithm(): string {
    return LOCAL_HMAC_ALGORITHM;
  }

  /**
   * Compute `HMAC-SHA-256(key, digest)` and return the raw MAC bytes.
   *
   * Matches the `CryptoSigner.signDigest` signature: callers pre-hash the
   * payload and pass in the digest `Buffer`.
   */
  async signDigest(digest: Buffer): Promise<Buffer> {
    return crypto
      .createHmac('sha256', this._key)
      .update(digest)
      .digest();
  }

  /**
   * Verify a MAC previously produced by {@link signDigest}.
   *
   * Uses `crypto.timingSafeEqual` to prevent timing attacks.  Returns `false`
   * (never throws) when the signature is invalid or parameters do not match.
   *
   * Matches the optional `CryptoSigner.verifyDigest` signature so this signer
   * can be used as a drop-in wherever `CryptoSigner` is expected.
   */
  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    keyId: string,
    algorithm: string,
  ): Promise<boolean> {
    if (keyId !== this._keyId || algorithm !== LOCAL_HMAC_ALGORITHM) {
      return false;
    }
    try {
      const expected = await this.signDigest(digest);
      if (expected.length !== signature.length) return false;
      return crypto.timingSafeEqual(expected, signature);
    } catch {
      return false;
    }
  }

  // ── Higher-level helpers used by the audit sink ─────────────────────────

  /**
   * Compute `HMAC-SHA-256(key, SHA-256(canonicalJson))` over a canonical JSON
   * string and return the base64url-encoded MAC.
   *
   * The double-hash step (`SHA-256` then `HMAC-SHA-256`) lets the same key
   * work as both a `CryptoSigner` (which passes pre-hashed digests) and a
   * direct payload signer.  The result is fully deterministic and suitable for
   * embedding in OCSF `enrichments`.
   */
  sign(canonicalJson: string): string {
    const digest = crypto
      .createHash('sha256')
      .update(canonicalJson, 'utf8')
      .digest();
    return crypto
      .createHmac('sha256', this._key)
      .update(digest)
      .digest('base64');
  }

  /**
   * Verify a MAC previously produced by {@link sign}.
   *
   * Uses `crypto.timingSafeEqual` to prevent timing attacks.  Returns `false`
   * on any mismatch or error; never throws.
   */
  verify(canonicalJson: string, tag: string): boolean {
    try {
      const expected = Buffer.from(this.sign(canonicalJson), 'base64');
      const actual = Buffer.from(tag, 'base64');
      if (expected.length !== actual.length) return false;
      return crypto.timingSafeEqual(expected, actual);
    } catch {
      return false;
    }
  }
}

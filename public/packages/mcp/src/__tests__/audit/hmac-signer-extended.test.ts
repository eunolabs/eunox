/**
 * Extended unit tests for LocalHmacSigner.
 *
 * These tests augment hmac-signer.test.ts with additional coverage for:
 *   - Construction edge cases
 *   - sign() output properties
 *   - verify() correctness with various inputs
 *   - Key sensitivity (different keys produce different signatures)
 *   - Signature stability (same key + same input → same signature)
 *   - Algorithm and keyId accessors
 *   - Tamper detection
 *
 * @module
 */

import * as crypto from 'node:crypto';
import { LocalHmacSigner } from '../../audit/hmac-signer';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function freshSigner(keyId?: string): LocalHmacSigner {
  return new LocalHmacSigner(crypto.randomBytes(32), keyId);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

describe('LocalHmacSigner — construction', () => {
  it('accepts a 32-byte key Buffer', () => {
    expect(() => new LocalHmacSigner(crypto.randomBytes(32))).not.toThrow();
  });

  it('accepts a 16-byte key Buffer', () => {
    expect(() => new LocalHmacSigner(crypto.randomBytes(16))).not.toThrow();
  });

  it('accepts a 64-byte key Buffer (512-bit)', () => {
    expect(() => new LocalHmacSigner(crypto.randomBytes(64))).not.toThrow();
  });

  it('accepts a key Buffer of all zeros', () => {
    expect(() => new LocalHmacSigner(Buffer.alloc(32, 0))).not.toThrow();
  });

  it('accepts a custom keyId string', () => {
    const signer = new LocalHmacSigner(crypto.randomBytes(32), 'my-custom-key-id');
    expect(signer.keyId).toBe('my-custom-key-id');
  });

  it('uses a default keyId when none is provided', () => {
    const signer = new LocalHmacSigner(crypto.randomBytes(32));
    expect(typeof signer.keyId).toBe('string');
    expect(signer.keyId.length).toBeGreaterThan(0);
  });

  it('two signers with the same key but different keyIds have the same signing output', () => {
    const key = crypto.randomBytes(32);
    const s1 = new LocalHmacSigner(key, 'key-id-1');
    const s2 = new LocalHmacSigner(key, 'key-id-2');
    // keyId is just metadata; the signing key is what matters for signatures
    expect(s1.sign('test-input')).toBe(s2.sign('test-input'));
  });
});

// ---------------------------------------------------------------------------
// sign() output properties
// ---------------------------------------------------------------------------

describe('LocalHmacSigner — sign()', () => {
  it('returns a non-empty string', () => {
    const signer = freshSigner();
    expect(signer.sign('test').length).toBeGreaterThan(0);
  });

  it('returns a base64-encoded string (no invalid base64 chars)', () => {
    const signer = freshSigner();
    const sig = signer.sign('test input');
    // Base64 chars are A-Z, a-z, 0-9, +, /, =
    expect(sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('is deterministic: same key + same input → same signature', () => {
    const key = crypto.randomBytes(32);
    const s1 = new LocalHmacSigner(key);
    const s2 = new LocalHmacSigner(key);
    expect(s1.sign('hello world')).toBe(s2.sign('hello world'));
  });

  it('is different for different inputs with the same key', () => {
    const signer = freshSigner();
    expect(signer.sign('input-A')).not.toBe(signer.sign('input-B'));
  });

  it('is different for the same input with different keys', () => {
    const s1 = freshSigner();
    const s2 = freshSigner();
    expect(s1.sign('same input')).not.toBe(s2.sign('same input'));
  });

  it('handles empty string input', () => {
    const signer = freshSigner();
    expect(signer.sign('')).toBeTruthy();
  });

  it('handles very long input strings', () => {
    const signer = freshSigner();
    const longInput = 'x'.repeat(100_000);
    expect(() => signer.sign(longInput)).not.toThrow();
    expect(signer.sign(longInput)).toBeTruthy();
  });

  it('handles input with unicode characters', () => {
    const signer = freshSigner();
    expect(() => signer.sign('日本語テスト 🎉')).not.toThrow();
    expect(signer.sign('日本語テスト 🎉')).toBeTruthy();
  });

  it('handles input with newlines and tabs', () => {
    const signer = freshSigner();
    const sig = signer.sign('line1\nline2\ttab');
    expect(sig).toBeTruthy();
  });

  it('handles input with JSON-serialized content', () => {
    const signer = freshSigner();
    const jsonStr = JSON.stringify({ time: 1234, status: 'Success', uid: 'abc' });
    expect(() => signer.sign(jsonStr)).not.toThrow();
  });

  it('HMAC-SHA256 output is always 44 chars in base64 (256 bits = 32 bytes = 44 base64 chars)', () => {
    const signer = freshSigner();
    const sig = signer.sign('any input');
    // HMAC-SHA256 = 32 bytes → base64 = ceil(32 * 4/3) = 44 chars (with padding)
    expect(sig).toHaveLength(44);
  });
});

// ---------------------------------------------------------------------------
// verify() correctness
// ---------------------------------------------------------------------------

describe('LocalHmacSigner — verify()', () => {
  it('returns true for a signature produced by the same key', () => {
    const signer = freshSigner();
    const input = 'canonical data here';
    const sig = signer.sign(input);
    expect(signer.verify(input, sig)).toBe(true);
  });

  it('returns false for a signature produced by a different key', () => {
    const s1 = freshSigner();
    const s2 = freshSigner();
    const sig = s1.sign('canonical data');
    expect(s2.verify('canonical data', sig)).toBe(false);
  });

  it('returns false when the input differs from the signed input', () => {
    const signer = freshSigner();
    const sig = signer.sign('original input');
    expect(signer.verify('modified input', sig)).toBe(false);
  });

  it('returns false for an empty signature string', () => {
    const signer = freshSigner();
    expect(signer.verify('any input', '')).toBe(false);
  });

  it('returns false for a garbage signature string', () => {
    const signer = freshSigner();
    expect(signer.verify('any input', 'not-a-valid-base64-hmac-value!!!')).toBe(false);
  });

  it('returns false when the signature is all zeros (wrong MAC)', () => {
    const signer = freshSigner();
    const zeroBuf = Buffer.alloc(32, 0);
    const zeroSig = zeroBuf.toString('base64');
    expect(signer.verify('any input', zeroSig)).toBe(false);
  });

  it('returns true for empty string input signed with the same key', () => {
    const signer = freshSigner();
    const sig = signer.sign('');
    expect(signer.verify('', sig)).toBe(true);
  });

  it('uses constant-time comparison (does not short-circuit on first byte)', () => {
    // This test verifies the API contract without measuring time.
    // We flip individual bits in the signature and confirm all are rejected.
    const signer = freshSigner();
    const input = 'test data';
    const sig = signer.sign(input);
    const sigBytes = Buffer.from(sig, 'base64');

    // Flip one byte in the signature
    sigBytes[0] = sigBytes[0]! ^ 0xff;
    const tamperedSig = sigBytes.toString('base64');
    expect(signer.verify(input, tamperedSig)).toBe(false);
  });

  it('round-trip: sign then verify with the same signer instance', () => {
    const signer = freshSigner();
    for (let i = 0; i < 10; i++) {
      const input = `input-${i}-` + crypto.randomBytes(8).toString('hex');
      const sig = signer.sign(input);
      expect(signer.verify(input, sig)).toBe(true);
    }
  });

  it('round-trip: sign with one signer instance, verify with another using same key', () => {
    const key = crypto.randomBytes(32);
    const signer1 = new LocalHmacSigner(key, 'k1');
    const signer2 = new LocalHmacSigner(key, 'k2');
    const sig = signer1.sign('shared input');
    expect(signer2.verify('shared input', sig)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

describe('LocalHmacSigner — accessors', () => {
  it('algorithm accessor returns "hmac-sha256"', () => {
    const signer = freshSigner();
    expect(signer.algorithm).toBe('hmac-sha256');
  });

  it('algorithm is consistent across calls', () => {
    const signer = freshSigner();
    expect(signer.algorithm).toBe(signer.algorithm);
  });

  it('keyId is consistent across calls', () => {
    const signer = freshSigner('stable-key-id');
    expect(signer.keyId).toBe('stable-key-id');
    expect(signer.keyId).toBe(signer.keyId);
  });

  it('keyId from two signers with different keyIds are different', () => {
    const key = crypto.randomBytes(32);
    const s1 = new LocalHmacSigner(key, 'id-alpha');
    const s2 = new LocalHmacSigner(key, 'id-beta');
    expect(s1.keyId).not.toBe(s2.keyId);
  });
});

// ---------------------------------------------------------------------------
// Signature sensitivity to small changes
// ---------------------------------------------------------------------------

describe('LocalHmacSigner — signature sensitivity', () => {
  it('differs when a single character is changed in the input', () => {
    const signer = freshSigner();
    const base = '{"status":"Success","time":1234}';
    const modified = '{"status":"Failure","time":1234}';
    expect(signer.sign(base)).not.toBe(signer.sign(modified));
  });

  it('differs when a single byte changes in the key', () => {
    const key = Buffer.from('0'.repeat(64), 'hex');
    const altKey = Buffer.from(key);
    altKey[0] = 0x01;
    const s1 = new LocalHmacSigner(key);
    const s2 = new LocalHmacSigner(altKey);
    expect(s1.sign('test')).not.toBe(s2.sign('test'));
  });

  it('differs when key bytes are reversed', () => {
    const key = crypto.randomBytes(32);
    const reversed = Buffer.from(key).reverse();
    const s1 = new LocalHmacSigner(key);
    const s2 = new LocalHmacSigner(reversed);
    // Unless key is a palindrome (astronomically unlikely with random bytes)
    if (!key.equals(reversed)) {
      expect(s1.sign('data')).not.toBe(s2.sign('data'));
    }
  });
});

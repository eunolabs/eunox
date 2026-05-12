/**
 * MeteredTokenSigner — unit tests
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. `getAlgorithm` is `undefined` when the inner signer does not implement it.
 *   2. `getAlgorithm` is a callable function when the inner signer implements it,
 *      and calling it returns the inner signer's reported algorithm string.
 *   3. The `.bind(inner)` delegation is correct: an inner signer whose
 *      `getAlgorithm` reads `this.algorithm` (i.e. relies on `this`) still
 *      receives the correct `this` context when called through the wrapper.
 *   4. `sign` delegates to the inner signer and returns its result.
 *   5. `sign` wraps KMS errors in `KmsSigningError` and records Prometheus metrics.
 *   6. `getPublicKey` and `getKeyId` delegate to the inner signer.
 */

import { MeteredTokenSigner } from '../src/metered-token-signer';
import { LocalTokenSigner } from '../src/local-token-signer';
import { KmsSigningError } from '../src/kms-signing-error';
import { minterMetrics } from '../src/metrics';
import type { TokenSigner, CapabilityTokenPayload } from '@euno/common';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Minimal payload cast for sign() delegation tests. */
const DUMMY_PAYLOAD = {
  sub: 'agent-1',
  iss: 'did:web:test',
  aud: 'gateway',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 300,
  jti: 'jti-test',
  schemaVersion: '1.0',
  capabilities: [],
} as unknown as CapabilityTokenPayload;

/** Build a minimal `TokenSigner` stub with no `getAlgorithm` method. */
function makeMinimalSigner(): TokenSigner {
  return {
    async sign() {
      return 'signed-jwt';
    },
    async getPublicKey() {
      return 'public-key-pem';
    },
    async getKeyId() {
      return 'key-id-1';
    },
    // intentionally omits getAlgorithm
  };
}

// Reset Prometheus registry before each test to avoid counter carry-over.
beforeEach(async () => {
  await minterMetrics.registry.resetMetrics();
});

// ── Test 1: getAlgorithm forwarding ───────────────────────────────────────────

describe('MeteredTokenSigner.getAlgorithm forwarding', () => {
  it('is undefined when the inner signer does not implement getAlgorithm', () => {
    const inner = makeMinimalSigner();
    const wrapped = new MeteredTokenSigner(inner, 'test-provider');

    expect(wrapped.getAlgorithm).toBeUndefined();
  });

  it('is a callable function when the inner signer implements getAlgorithm', async () => {
    const inner = await LocalTokenSigner.generate('ES256');
    const wrapped = new MeteredTokenSigner(inner, 'test-provider');

    expect(typeof wrapped.getAlgorithm).toBe('function');
    expect(wrapped.getAlgorithm!()).toBe('ES256');
  });

  it('returns the same algorithm string as the inner signer', async () => {
    const rs256Inner = await LocalTokenSigner.generate('RS256');
    const es256Inner = await LocalTokenSigner.generate('ES256');

    expect(new MeteredTokenSigner(rs256Inner, 'p').getAlgorithm!()).toBe('RS256');
    expect(new MeteredTokenSigner(es256Inner, 'p').getAlgorithm!()).toBe('ES256');
  });

  it('preserves `this` binding — inner method that relies on `this` still resolves correctly', () => {
    // Construct an inner signer whose getAlgorithm reads `this.algorithm` to
    // verify that .bind(inner) is applied (not just a bare function reference).
    class ThisReliantSigner implements TokenSigner {
      private readonly algorithm = 'PS256';

      async sign() {
        return 'jwt';
      }
      async getPublicKey() {
        return 'pk';
      }
      async getKeyId() {
        return 'kid';
      }
      getAlgorithm(): string {
        // Explicitly uses `this` — will return 'undefined' or throw if `this`
        // is not the inner instance.
        return this.algorithm;
      }
    }

    const inner = new ThisReliantSigner();
    const wrapped = new MeteredTokenSigner(inner, 'test-provider');

    // Call the wrapped function without an explicit receiver (no manual `.call(inner)`).
    // If binding is correct, `this.algorithm` inside `getAlgorithm` is 'PS256'.
    const getAlg = wrapped.getAlgorithm!;
    expect(getAlg()).toBe('PS256');
  });
});

// ── Test 2: sign delegation ───────────────────────────────────────────────────

describe('MeteredTokenSigner.sign', () => {
  it('delegates to the inner signer and returns its JWT', async () => {
    const inner = await LocalTokenSigner.generate('RS256');
    const wrapped = new MeteredTokenSigner(inner, 'local');

    const token = await wrapped.sign(DUMMY_PAYLOAD);
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3); // header.payload.signature
  });

  it('wraps inner signer errors in KmsSigningError', async () => {
    const inner = makeMinimalSigner();
    (inner as unknown as { sign: jest.Mock }).sign = jest.fn().mockRejectedValue(new Error('KMS unavailable'));

    const wrapped = new MeteredTokenSigner(inner, 'aws-kms');

    await expect(wrapped.sign(DUMMY_PAYLOAD)).rejects.toBeInstanceOf(KmsSigningError);
  });

  it('increments kmsErrorTotal on sign failure', async () => {
    const inner = makeMinimalSigner();
    (inner as unknown as { sign: jest.Mock }).sign = jest.fn().mockRejectedValue(new Error('connection refused'));

    const wrapped = new MeteredTokenSigner(inner, 'aws-kms');

    await expect(wrapped.sign(DUMMY_PAYLOAD)).rejects.toBeInstanceOf(KmsSigningError);

    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_kms_error_total.*aws-kms/);
  });
});

// ── Test 3: key info delegation ───────────────────────────────────────────────

describe('MeteredTokenSigner key info delegation', () => {
  it('getPublicKey delegates to inner signer', async () => {
    const inner = await LocalTokenSigner.generate('RS256');
    const wrapped = new MeteredTokenSigner(inner, 'local');

    expect(await wrapped.getPublicKey()).toBe(await inner.getPublicKey());
  });

  it('getKeyId delegates to inner signer', async () => {
    const inner = await LocalTokenSigner.generate('RS256');
    const wrapped = new MeteredTokenSigner(inner, 'local');

    expect(await wrapped.getKeyId()).toBe(await inner.getKeyId());
  });
});

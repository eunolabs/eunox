/**
 * MeteredTokenSigner
 * ────────────────────────────────────────────────────────────────────────────
 * A {@link TokenSigner} decorator that wraps any underlying signer and records
 * per-operation Prometheus metrics:
 *
 * - `euno_minter_kms_sign_latency_seconds{provider}` — latency of the HSM
 *   sign call (success and failure paths both recorded so the histogram is
 *   unbiased; a KMS timeout still has a measurable latency value).
 * - `euno_minter_kms_error_total{provider, error_class}` — incremented on
 *   every sign failure, with a coarse error-class label derived from the
 *   error message.
 *
 * On failure, the original error is wrapped in a {@link KmsSigningError} so
 * that the mint route can record `result='kms_error'` on `mintTotal` without
 * needing to know which provider is configured.
 *
 * ## Usage (bootstrap)
 *
 * ```typescript
 * const rawSigner = createKmsTokenSignerFromEnv(process.env);
 * const signer = rawSigner
 *   ? new MeteredTokenSigner(rawSigner, process.env['MINTER_KMS_PROVIDER'] ?? 'unknown')
 *   : fallbackLocalSigner;
 * ```
 */

import type { TokenSigner, CapabilityTokenPayload, IssuanceContext } from '@euno/common';
import { kmsSignLatencySeconds, kmsErrorTotal } from './metrics';
import { KmsSigningError } from './kms-signing-error';

// ── Error classification ───────────────────────────────────────────────────

/**
 * Map a caught error to a coarse error-class label for `kmsErrorTotal`.
 *
 * The classification is intentionally coarse (4 values: `auth_error`,
 * `timeout`, `unavailable`, `sign_failed`) to avoid unbounded label
 * cardinality in Prometheus.  Fine-grained diagnostics are available in the
 * minter logs and in the provider's own audit trail.
 */
function classifyKmsError(err: unknown): string {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    if (
      msg.includes('unauthorized') ||
      msg.includes('forbidden') ||
      msg.includes('access denied') ||
      msg.includes('permission denied') ||
      msg.includes('credentials') ||
      msg.includes('authentication')
    ) {
      return 'auth_error';
    }
    if (msg.includes('timeout') || msg.includes('timed out') || msg.includes('deadline')) {
      return 'timeout';
    }
    if (
      msg.includes('unavailable') ||
      msg.includes('unreachable') ||
      msg.includes('econnrefused') ||
      msg.includes('econnreset') ||
      msg.includes('network') ||
      msg.includes('connection')
    ) {
      return 'unavailable';
    }
  }
  return 'sign_failed';
}

// ── MeteredTokenSigner ─────────────────────────────────────────────────────

export class MeteredTokenSigner implements TokenSigner {
  private readonly inner: TokenSigner;
  private readonly provider: string;

  /**
   * Forwarded from the inner signer when it provides `getAlgorithm`.
   *
   * `TokenSigner.getAlgorithm` is optional (`?`): when declared it must return
   * `string`.  We satisfy that contract by assigning this property only when
   * the inner signer actually provides the method, leaving it `undefined`
   * otherwise — which is a valid implementation of the optional interface
   * member.
   */
  readonly getAlgorithm?: () => string;

  /**
   * @param inner    - The underlying signer to delegate to.
   * @param provider - Human-readable provider label for Prometheus metrics
   *                   (e.g. `'azure-keyvault'`, `'aws-kms'`, `'gcp-cloudkms'`,
   *                   `'local'`).  This MUST be a bounded, low-cardinality
   *                   value — never include tenant IDs or key ARNs.
   */
  constructor(inner: TokenSigner, provider: string) {
    this.inner = inner;
    this.provider = provider;
    if (typeof inner.getAlgorithm === 'function') {
      // Bind to the inner instance so `this` resolves correctly inside the delegate.
      this.getAlgorithm = inner.getAlgorithm.bind(inner);
    }
  }

  async sign(payload: CapabilityTokenPayload, context?: IssuanceContext): Promise<string> {
    const endTimer = kmsSignLatencySeconds.startTimer({ provider: this.provider });
    try {
      const token = await this.inner.sign(payload, context);
      endTimer();
      return token;
    } catch (err) {
      // Record latency even on error so the histogram is unbiased.
      endTimer();
      const errorClass = classifyKmsError(err);
      kmsErrorTotal.inc({ provider: this.provider, error_class: errorClass });
      throw new KmsSigningError(
        err instanceof Error ? err.message : 'KMS signing failed',
        this.provider,
        errorClass,
        err,
      );
    }
  }

  getPublicKey(): Promise<string> {
    return this.inner.getPublicKey();
  }

  getKeyId(): Promise<string> {
    return this.inner.getKeyId();
  }

}

/**
 * KmsSigningError
 * ────────────────────────────────────────────────────────────────────────────
 * Thrown by {@link MeteredTokenSigner} when the underlying KMS/HSM sign call
 * fails.  Carrying `provider` and `errorClass` on the error allows the mint
 * route to record an accurate `result='kms_error'` label on `mintTotal`
 * without the route needing to know which provider is configured.
 */
export class KmsSigningError extends Error {
  /** The KMS provider that failed (e.g. `'azure-keyvault'`, `'aws-kms'`). */
  readonly provider: string;
  /**
   * Coarse error class label used for `euno_minter_kms_error_total`.
   *
   * | Value | Meaning |
   * |---|---|
   * | `'sign_failed'`  | HSM rejected or failed the sign call (generic) |
   * | `'auth_error'`   | Workload identity rejected (IAM / token expiry) |
   * | `'timeout'`      | KMS call timed out |
   * | `'unavailable'`  | KMS endpoint unreachable (network / provider outage) |
   */
  readonly errorClass: string;

  constructor(
    message: string,
    provider: string,
    errorClass: string,
    cause?: unknown,
  ) {
    super(message);
    this.name = 'KmsSigningError';
    this.provider = provider;
    this.errorClass = errorClass;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

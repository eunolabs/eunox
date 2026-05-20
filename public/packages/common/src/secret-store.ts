/**
 * SecretStore — pluggable secrets abstraction layer.
 *
 * Defines a minimal interface for retrieving named secrets so that
 * business code (config loaders, bootstrap wiring) never reads directly
 * from `process.env` for sensitive values in cloud deployments.
 *
 * The contract is intentionally small:
 *   - `getSecret(name)` — returns the secret value, or `undefined` when
 *     the secret does not exist in this store.
 *   - `getSecretOrThrow(name)` — convenience wrapper that throws when the
 *     secret is absent.
 *
 * Built-in implementations (in `@euno/common-infra`):
 *   - `EnvSecretStore`                — reads `process.env` (default)
 *   - `AzureKeyVaultSecretStore`      — reads from Azure Key Vault secrets
 *   - `AwsSecretsManagerSecretStore`  — reads from AWS Secrets Manager
 *   - `GcpSecretManagerSecretStore`   — reads from GCP Secret Manager
 *
 * Selection is driven by the `SECRET_STORE_PROVIDER` environment variable.
 * When unset, `EnvSecretStore` is used automatically.
 *
 * @example
 * ```ts
 * import { createSecretStore } from '@euno/common-infra';
 *
 * const store = createSecretStore(process.env);
 * const hmacSecret = await store.getSecretOrThrow('AUDIT_LEDGER_HMAC_SECRET');
 * ```
 */

/**
 * Minimal interface for reading named secrets.
 *
 * Implementations may cache values internally and should handle retries
 * / back-off for transient cloud-API errors. They MUST NOT cache `undefined`
 * permanently — a secret that does not yet exist may be created later.
 */
export interface SecretStore {
  /**
   * Retrieve a secret by name.
   *
   * @param name - The secret name as understood by this implementation.
   *   For `EnvSecretStore` this is the environment variable name.
   *   For cloud implementations this is the secret's resource name or ARN
   *   (typically obtained from an `<PROVIDER>_SECRET_*` env var).
   * @returns The secret value as a string, or `undefined` when the secret
   *   is not present in this store.
   */
  getSecret(name: string): Promise<string | undefined>;

  /**
   * Convenience wrapper: retrieve a secret or throw if absent.
   *
   * @param name - Same semantics as {@link getSecret}.
   * @throws `SecretNotFoundError` when the secret cannot be found.
   */
  getSecretOrThrow(name: string): Promise<string>;
}

/**
 * Thrown by {@link SecretStore.getSecretOrThrow} when the requested secret
 * is not present in the store.
 */
export class SecretNotFoundError extends Error {
  constructor(
    public readonly secretName: string,
    public readonly provider: string,
  ) {
    super(
      `SecretStore (${provider}): secret "${secretName}" not found. ` +
        'Ensure the secret is provisioned and the runtime has permission to read it.',
    );
    this.name = 'SecretNotFoundError';
  }
}

/**
 * Supported secret-store provider identifiers.
 * Used as the value of the `SECRET_STORE_PROVIDER` environment variable.
 */
export const SECRET_STORE_PROVIDERS = [
  'env',
  'azure-keyvault',
  'aws-secrets-manager',
  'gcp-secret-manager',
] as const;

/** Type alias for the provider identifier union. */
export type SecretStoreProvider = (typeof SECRET_STORE_PROVIDERS)[number];

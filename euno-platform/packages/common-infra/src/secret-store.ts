/**
 * Built-in SecretStore implementations — pluggable secrets abstraction layer.
 * ─────────────────────────────────────────────────────────────────────────────
 * Implements the {@link SecretStore} interface from `@euno/common-core` for
 * four providers:
 *
 *   • `env`                  — {@link EnvSecretStore}               (default)
 *   • `azure-keyvault`       — {@link AzureKeyVaultSecretStore}
 *   • `aws-secrets-manager`  — {@link AwsSecretsManagerSecretStore}
 *   • `gcp-secret-manager`   — {@link GcpSecretManagerSecretStore}
 *
 * ### Selection
 *
 * Use the {@link createSecretStore} factory to select the implementation
 * automatically from the `SECRET_STORE_PROVIDER` environment variable.
 * When unset (or set to `"env"`) the factory returns an `EnvSecretStore`
 * that reads plain environment variables — no cloud credentials required.
 *
 * ### Cloud SDK dependencies
 *
 * Cloud SDKs are **not** hard dependencies of `@euno/common-infra`.  They
 * are `require()`d dynamically at construction time.  Install only the SDK
 * you actually use in your deployment image; a clear error is thrown if the
 * required package is absent.
 *
 * | Provider              | Required package                        |
 * |-----------------------|-----------------------------------------|
 * | `azure-keyvault`      | `@azure/keyvault-secrets`, `@azure/identity` |
 * | `aws-secrets-manager` | `@aws-sdk/client-secrets-manager`       |
 * | `gcp-secret-manager`  | `@google-cloud/secret-manager`          |
 *
 * ### Usage
 *
 * ```typescript
 * import { createSecretStore } from '@euno/common-infra';
 *
 * // Reads SECRET_STORE_PROVIDER from the environment.
 * const store = createSecretStore(process.env);
 *
 * // Returns undefined when absent, throws SecretNotFoundError when required.
 * const hmacSecret = await store.getSecretOrThrow('AUDIT_LEDGER_HMAC_SECRET');
 * ```
 *
 * ### Name-mapping convention for cloud providers
 *
 * Cloud implementations resolve the secret name via a two-step lookup:
 *
 *   1. If an env var named `<PROVIDER>_SECRET_<NAME>` is present, its value
 *      is used as the cloud-side resource reference (ARN, resource ID, etc.).
 *   2. Otherwise the name itself is used as the resource reference.
 *
 * This allows operators to decouple the logical name used in code from the
 * physical secret path in the cloud provider.
 */

import { SecretStore, SecretNotFoundError, SecretStoreProvider } from '@euno/common-core';

// ── EnvSecretStore ────────────────────────────────────────────────────────────

/**
 * Default {@link SecretStore} implementation that reads values from a
 * `process.env`-shaped object.
 *
 * This implementation is always available without installing any additional
 * packages. It is used automatically when `SECRET_STORE_PROVIDER` is unset
 * or set to `"env"`.
 */
export class EnvSecretStore implements SecretStore {
  private readonly env: Record<string, string | undefined>;

  /**
   * @param env - The environment record to read from.  Defaults to
   *   `process.env` when omitted.  Pass a custom object in tests.
   */
  constructor(env: Record<string, string | undefined> = process.env) {
    this.env = env;
  }

  async getSecret(name: string): Promise<string | undefined> {
    const value = this.env[name];
    return value === '' ? undefined : value;
  }

  async getSecretOrThrow(name: string): Promise<string> {
    const value = await this.getSecret(name);
    if (value === undefined) {
      throw new SecretNotFoundError(name, 'env');
    }
    return value;
  }
}

// ── AzureKeyVaultSecretStore ──────────────────────────────────────────────────

/**
 * Configuration for {@link AzureKeyVaultSecretStore}.
 */
export interface AzureKeyVaultSecretStoreConfig {
  /** Azure Key Vault base URL. Example: `https://my-vault.vault.azure.net/` */
  vaultUrl: string;
  /**
   * Credential strategy. Defaults to `'default'` (DefaultAzureCredential —
   * workload identity, managed identity, standard AZURE_* env vars tried
   * in order). Use `'managed-identity'` or `'client-secret'` when the
   * DefaultAzureCredential chain does not apply.
   */
  credentialType?: 'default' | 'managed-identity' | 'client-secret';
  /** Azure service principal client ID. Required when `credentialType === 'client-secret'`. */
  clientId?: string;
  /** Azure service principal client secret. Required when `credentialType === 'client-secret'`. */
  clientSecret?: string;
  /** Azure tenant ID. Required when `credentialType === 'client-secret'`. */
  tenantId?: string;
}

/**
 * {@link SecretStore} backed by Azure Key Vault secrets.
 *
 * Each `getSecret(name)` call invokes `SecretClient.getSecret(secretName)`
 * where `secretName` is resolved from the env var `AZURE_KEYVAULT_SECRET_<NAME>`
 * when present, falling back to `name` itself.
 *
 * Authentication uses `@azure/identity` (installed separately):
 *   - `'default'` — `DefaultAzureCredential`
 *   - `'managed-identity'` — `ManagedIdentityCredential`
 *   - `'client-secret'` — `ClientSecretCredential`
 *
 * @requires `@azure/keyvault-secrets`, `@azure/identity`
 */
export class AzureKeyVaultSecretStore implements SecretStore {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly client: any;
  private readonly env: Record<string, string | undefined>;
  private readonly cache = new Map<string, string>();

  constructor(
    config: AzureKeyVaultSecretStoreConfig,
    env: Record<string, string | undefined> = process.env,
  ) {
    const credType = config.credentialType ?? 'default';
    if (credType === 'client-secret') {
      if (!config.tenantId || !config.clientId || !config.clientSecret) {
        throw new Error(
          'AzureKeyVaultSecretStore: credentialType=client-secret requires tenantId, clientId, and clientSecret.',
        );
      }
    }

    this.env = env;

    let SecretClientCtor: new (vaultUrl: string, credential: unknown) => unknown;
    let AzureIdentityModule: {
      DefaultAzureCredential: new () => unknown;
      ManagedIdentityCredential: new (clientId?: string) => unknown;
      ClientSecretCredential: new (tenantId: string, clientId: string, clientSecret: string) => unknown;
    };

    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      const mod = require('@azure/keyvault-secrets');
      SecretClientCtor = mod.SecretClient;
    } catch {
      throw new Error(
        'AzureKeyVaultSecretStore: the @azure/keyvault-secrets package is not installed. ' +
          'Add it to your deployment image: npm install @azure/keyvault-secrets',
      );
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      AzureIdentityModule = require('@azure/identity');
    } catch {
      throw new Error(
        'AzureKeyVaultSecretStore: the @azure/identity package is not installed. ' +
          'Add it to your deployment image: npm install @azure/identity',
      );
    }

    let credential: unknown;
    if (credType === 'managed-identity') {
      credential = new AzureIdentityModule.ManagedIdentityCredential(config.clientId);
    } else if (credType === 'client-secret') {
      credential = new AzureIdentityModule.ClientSecretCredential(
        config.tenantId!,
        config.clientId!,
        config.clientSecret!,
      );
    } else {
      credential = new AzureIdentityModule.DefaultAzureCredential();
    }

    this.client = new SecretClientCtor(config.vaultUrl, credential);
  }

  /** Resolve the Key Vault secret name from an env-var override or use the name as-is. */
  private resolveSecretName(name: string): string {
    const envKey = `AZURE_KEYVAULT_SECRET_${name}`;
    return this.env[envKey] ?? name;
  }

  async getSecret(name: string): Promise<string | undefined> {
    const secretName = this.resolveSecretName(name);
    if (this.cache.has(secretName)) {
      return this.cache.get(secretName);
    }
    try {
      const result = await this.client.getSecret(secretName);
      const value: string | undefined = result?.value ?? undefined;
      if (value !== undefined) {
        this.cache.set(secretName, value);
      }
      return value;
    } catch (err: unknown) {
      // Azure SDK throws with statusCode 404 when the secret does not exist.
      const e = err as { statusCode?: number; code?: string };
      if (e.statusCode === 404 || e.code === 'SecretNotFound') {
        return undefined;
      }
      throw err;
    }
  }

  async getSecretOrThrow(name: string): Promise<string> {
    const value = await this.getSecret(name);
    if (value === undefined) {
      throw new SecretNotFoundError(name, 'azure-keyvault');
    }
    return value;
  }
}

// ── AwsSecretsManagerSecretStore ──────────────────────────────────────────────

/**
 * Configuration for {@link AwsSecretsManagerSecretStore}.
 */
export interface AwsSecretsManagerSecretStoreConfig {
  /** AWS region. Defaults to the SDK default (`AWS_REGION` / `AWS_DEFAULT_REGION` env vars). */
  region?: string;
  /** Optional explicit AWS access key ID (overrides credential chain). */
  accessKeyId?: string;
  /** Optional explicit AWS secret access key (overrides credential chain). */
  secretAccessKey?: string;
  /** Optional AWS STS session token (for temporary credentials). */
  sessionToken?: string;
}

/**
 * {@link SecretStore} backed by AWS Secrets Manager.
 *
 * Each `getSecret(name)` call invokes `GetSecretValueCommand` where the
 * `SecretId` is resolved from `AWS_SECRETS_ARN_<NAME>` when present,
 * falling back to `name` itself.
 *
 * Authentication uses the standard AWS credential provider chain —
 * IAM role, IRSA, EC2 instance profile, `AWS_ACCESS_KEY_ID` /
 * `AWS_SECRET_ACCESS_KEY` env vars, or a shared credentials file.
 * Explicit credentials can be supplied via `accessKeyId`, `secretAccessKey`,
 * and `sessionToken` to override the chain.
 *
 * @requires `@aws-sdk/client-secrets-manager`
 */
export class AwsSecretsManagerSecretStore implements SecretStore {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly client: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly GetSecretValueCommand: any;
  private readonly env: Record<string, string | undefined>;
  private readonly cache = new Map<string, string>();

  constructor(
    config: AwsSecretsManagerSecretStoreConfig = {},
    env: Record<string, string | undefined> = process.env,
  ) {
    this.env = env;

    let SecretsManagerClientCtor: new (opts: unknown) => unknown;
    let GetSecretValueCommand: new (opts: unknown) => unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      const mod = require('@aws-sdk/client-secrets-manager');
      SecretsManagerClientCtor = mod.SecretsManagerClient;
      GetSecretValueCommand = mod.GetSecretValueCommand;
    } catch {
      throw new Error(
        'AwsSecretsManagerSecretStore: the @aws-sdk/client-secrets-manager package is not installed. ' +
          'Add it to your deployment image: npm install @aws-sdk/client-secrets-manager',
      );
    }

    const clientConfig: {
      region?: string;
      credentials?: { accessKeyId: string; secretAccessKey: string; sessionToken?: string };
    } = {};
    if (config.region) {
      clientConfig.region = config.region;
    }
    if (config.accessKeyId && config.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        ...(config.sessionToken ? { sessionToken: config.sessionToken } : {}),
      };
    }

    this.client = new SecretsManagerClientCtor(clientConfig);
    this.GetSecretValueCommand = GetSecretValueCommand;
  }

  /** Resolve the Secrets Manager secret ID from an env-var override or use the name as-is. */
  private resolveSecretId(name: string): string {
    const envKey = `AWS_SECRETS_ARN_${name}`;
    return this.env[envKey] ?? name;
  }

  async getSecret(name: string): Promise<string | undefined> {
    const secretId = this.resolveSecretId(name);
    if (this.cache.has(secretId)) {
      return this.cache.get(secretId);
    }
    try {
      const response = await this.client.send(new this.GetSecretValueCommand({ SecretId: secretId }));
      const value: string | undefined =
        response?.SecretString ?? undefined;
      if (value !== undefined) {
        this.cache.set(secretId, value);
      }
      return value;
    } catch (err: unknown) {
      // AWS SDK throws with `name === 'ResourceNotFoundException'` when absent.
      const e = err as { name?: string; $metadata?: { httpStatusCode?: number } };
      if (
        e.name === 'ResourceNotFoundException' ||
        e.$metadata?.httpStatusCode === 404
      ) {
        return undefined;
      }
      throw err;
    }
  }

  async getSecretOrThrow(name: string): Promise<string> {
    const value = await this.getSecret(name);
    if (value === undefined) {
      throw new SecretNotFoundError(name, 'aws-secrets-manager');
    }
    return value;
  }
}

// ── GcpSecretManagerSecretStore ───────────────────────────────────────────────

/**
 * Configuration for {@link GcpSecretManagerSecretStore}.
 */
export interface GcpSecretManagerSecretStoreConfig {
  /** GCP project ID. Required when `GCP_PROJECT_ID` is not set in the environment. */
  projectId?: string;
  /**
   * Optional path to a GCP service account key file. When set, this
   * overrides Application Default Credentials for this client only.
   * Falls back to Workload Identity / `GOOGLE_APPLICATION_CREDENTIALS`
   * when unset.
   */
  keyFilePath?: string;
}

/**
 * {@link SecretStore} backed by GCP Secret Manager.
 *
 * Each `getSecret(name)` call accesses the latest version of the secret
 * whose resource ID is resolved from `GCP_SECRET_<NAME>` when present,
 * falling back to `name` itself. The full resource name is assembled as:
 * `projects/<projectId>/secrets/<secretId>/versions/latest`.
 *
 * Authentication uses Application Default Credentials (ADC) — Workload
 * Identity, `GOOGLE_APPLICATION_CREDENTIALS`, or `gcloud auth
 * application-default login` in development.
 *
 * @requires `@google-cloud/secret-manager`
 */
export class GcpSecretManagerSecretStore implements SecretStore {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly client: any;
  private readonly projectId: string;
  private readonly env: Record<string, string | undefined>;
  private readonly cache = new Map<string, string>();

  constructor(
    config: GcpSecretManagerSecretStoreConfig = {},
    env: Record<string, string | undefined> = process.env,
  ) {
    this.env = env;

    const projectId = config.projectId ?? env['GCP_PROJECT_ID'];
    if (!projectId) {
      throw new Error(
        'GcpSecretManagerSecretStore: projectId is required. ' +
          'Set it in the config or via the GCP_PROJECT_ID environment variable.',
      );
    }
    this.projectId = projectId;

    let SecretManagerServiceClientCtor: new (opts?: unknown) => unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      const mod = require('@google-cloud/secret-manager');
      SecretManagerServiceClientCtor = mod.SecretManagerServiceClient;
    } catch {
      throw new Error(
        'GcpSecretManagerSecretStore: the @google-cloud/secret-manager package is not installed. ' +
          'Add it to your deployment image: npm install @google-cloud/secret-manager',
      );
    }

    const clientOpts: { keyFilename?: string } = {};
    if (config.keyFilePath) {
      clientOpts.keyFilename = config.keyFilePath;
    }
    this.client = new SecretManagerServiceClientCtor(clientOpts);
  }

  /** Resolve the GCP secret ID from an env-var override or use the name as-is. */
  private resolveSecretId(name: string): string {
    const envKey = `GCP_SECRET_${name}`;
    return this.env[envKey] ?? name;
  }

  async getSecret(name: string): Promise<string | undefined> {
    const secretId = this.resolveSecretId(name);
    const resourceName = `projects/${this.projectId}/secrets/${secretId}/versions/latest`;
    if (this.cache.has(resourceName)) {
      return this.cache.get(resourceName);
    }
    try {
      const [version] = await this.client.accessSecretVersion({ name: resourceName });
      const payload = version?.payload?.data;
      if (!payload) {
        return undefined;
      }
      const value =
        typeof payload === 'string'
          ? payload
          : Buffer.isBuffer(payload)
            ? payload.toString('utf8')
            : Buffer.from(payload as Uint8Array).toString('utf8');
      this.cache.set(resourceName, value);
      return value;
    } catch (err: unknown) {
      // GCP SDK throws with `code === 5` (NOT_FOUND) or the message includes
      // "NOT_FOUND" when the secret does not exist.
      const e = err as { code?: number; message?: string };
      if (e.code === 5 || e.message?.includes('NOT_FOUND')) {
        return undefined;
      }
      throw err;
    }
  }

  async getSecretOrThrow(name: string): Promise<string> {
    const value = await this.getSecret(name);
    if (value === undefined) {
      throw new SecretNotFoundError(name, 'gcp-secret-manager');
    }
    return value;
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a {@link SecretStore} from the `SECRET_STORE_PROVIDER` environment
 * variable and any provider-specific configuration variables.
 *
 * | `SECRET_STORE_PROVIDER` | Implementation                      | Required env vars                                    |
 * |-------------------------|-------------------------------------|------------------------------------------------------|
 * | unset / `"env"`         | `EnvSecretStore`                    | none                                                 |
 * | `"azure-keyvault"`      | `AzureKeyVaultSecretStore`          | `SECRET_STORE_AZURE_VAULT_URL` (+ optional cred vars) |
 * | `"aws-secrets-manager"` | `AwsSecretsManagerSecretStore`      | optional `SECRET_STORE_AWS_REGION`                   |
 * | `"gcp-secret-manager"`  | `GcpSecretManagerSecretStore`       | `GCP_PROJECT_ID` (or `SECRET_STORE_GCP_PROJECT_ID`)  |
 *
 * Throws when `SECRET_STORE_PROVIDER` is set to an unrecognised value or
 * when required provider-specific variables are missing.
 *
 * @param env - Environment record to read provider config from. Defaults to
 *   `process.env` when omitted.
 */
export function createSecretStore(
  env: Record<string, string | undefined> = process.env,
): SecretStore {
  const provider = (env['SECRET_STORE_PROVIDER'] ?? 'env') as SecretStoreProvider;

  switch (provider) {
    case 'env':
      return new EnvSecretStore(env);

    case 'azure-keyvault': {
      const vaultUrl = env['SECRET_STORE_AZURE_VAULT_URL'];
      if (!vaultUrl) {
        throw new Error(
          'createSecretStore (azure-keyvault): SECRET_STORE_AZURE_VAULT_URL is required.',
        );
      }
      const credentialType = (
        env['SECRET_STORE_AZURE_CREDENTIAL_TYPE'] ?? 'default'
      ) as AzureKeyVaultSecretStoreConfig['credentialType'];
      return new AzureKeyVaultSecretStore(
        {
          vaultUrl,
          credentialType,
          clientId: env['SECRET_STORE_AZURE_CLIENT_ID'],
          clientSecret: env['SECRET_STORE_AZURE_CLIENT_SECRET'],
          tenantId: env['SECRET_STORE_AZURE_TENANT_ID'],
        },
        env,
      );
    }

    case 'aws-secrets-manager': {
      return new AwsSecretsManagerSecretStore(
        {
          region: env['SECRET_STORE_AWS_REGION'] ?? env['AWS_REGION'] ?? env['AWS_DEFAULT_REGION'],
          accessKeyId: env['SECRET_STORE_AWS_ACCESS_KEY_ID'],
          secretAccessKey: env['SECRET_STORE_AWS_SECRET_ACCESS_KEY'],
          sessionToken: env['SECRET_STORE_AWS_SESSION_TOKEN'],
        },
        env,
      );
    }

    case 'gcp-secret-manager': {
      return new GcpSecretManagerSecretStore(
        {
          projectId: env['SECRET_STORE_GCP_PROJECT_ID'] ?? env['GCP_PROJECT_ID'],
          keyFilePath: env['SECRET_STORE_GCP_KEY_FILE_PATH'],
        },
        env,
      );
    }

    default: {
      // Exhaustiveness check — the type system narrows `provider` to `never`
      // here, but we still need a runtime guard for unknown values passed at
      // runtime.
      const _exhaustive: never = provider;
      throw new Error(
        `createSecretStore: unknown SECRET_STORE_PROVIDER "${_exhaustive}". ` +
          'Supported values: env, azure-keyvault, aws-secrets-manager, gcp-secret-manager.',
      );
    }
  }
}

// Re-export the interface and error type so callers only need to import from
// `@euno/common-infra` when they want a concrete implementation.
export { SecretStore, SecretNotFoundError, SecretStoreProvider } from '@euno/common-core';

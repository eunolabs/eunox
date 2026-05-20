/**
 * Secrets abstraction layer — `SecretStore` interface
 * ────────────────────────────────────────────────────────────────────────────
 * Defines a minimal `SecretStore` contract that lets services fetch sensitive
 * values (e.g. `AUDIT_LEDGER_HMAC_SECRET`, `GATEWAY_ADMIN_API_KEY`) from a
 * cloud-native secret manager instead of — or in addition to — environment
 * variables.
 *
 * ## Built-in implementations
 *
 * | Provider key           | Implementation                   | SDK required                         |
 * |------------------------|----------------------------------|--------------------------------------|
 * | `env` (default)        | `EnvSecretStore`                 | none — reads `process.env`           |
 * | `azure-keyvault`       | `AzureKeyVaultSecretStore`       | `@azure/keyvault-secrets` + `@azure/identity` |
 * | `aws-secretsmanager`   | `AwsSecretsManagerSecretStore`   | `@aws-sdk/client-secrets-manager`    |
 * | `gcp-secretmanager`    | `GcpSecretManagerSecretStore`    | `@google-cloud/secret-manager`       |
 *
 * ## Selection logic
 *
 * ```
 * SECRET_STORE_PROVIDER=aws-secretsmanager   → AwsSecretsManagerSecretStore
 * SECRET_STORE_PROVIDER=azure-keyvault       → AzureKeyVaultSecretStore
 * SECRET_STORE_PROVIDER=gcp-secretmanager    → GcpSecretManagerSecretStore
 * SECRET_STORE_PROVIDER=env (or unset)       → EnvSecretStore  (default)
 * ```
 *
 * Call `createSecretStoreFromEnv(process.env)` at service startup to obtain
 * the right implementation automatically.
 *
 * ## Cloud SDK dependencies
 *
 * The cloud provider SDKs are **not** hard dependencies of `@euno/common-core`.
 * They are dynamically `require()`d lazily on the first `getSecret()` call
 * (inside `buildClient()`), not at construction time.  Callers are responsible
 * for installing whichever SDK their deployment uses.  A clear `Error` is
 * thrown if the SDK is absent when the first secret fetch is attempted.
 *
 * ## Usage
 *
 * ```typescript
 * import { createSecretStoreFromEnv } from '@euno/common-core';
 *
 * const store = createSecretStoreFromEnv(process.env);
 * const hmacSecret = await store.getSecret('AUDIT_LEDGER_HMAC_SECRET');
 * // Non-env stores return undefined for missing secrets; fall back explicitly:
 * // const hmacSecret = await store.getSecret('AUDIT_LEDGER_HMAC_SECRET') ?? process.env['AUDIT_LEDGER_HMAC_SECRET'];
 * ```
 */

// ── Interface ─────────────────────────────────────────────────────────────────

/**
 * Minimal interface for retrieving secret values by name.
 *
 * Implementations MUST be safe to call concurrently and SHOULD cache
 * fetched values in memory to avoid redundant network round-trips on
 * every call.  Caching semantics (TTL, cache invalidation) are
 * implementation-defined.
 */
export interface SecretStore {
  /**
   * Fetch a secret by name.
   *
   * Returns the plaintext string value if the secret exists, or
   * `undefined` if no secret with that name is present in the store.
   *
   * Implementations MUST NOT throw for a missing secret (use `undefined`);
   * they MAY throw for transient I/O or authentication errors.
   */
  getSecret(name: string): Promise<string | undefined>;
}

// ── Provider type ─────────────────────────────────────────────────────────────

/** The set of built-in `SecretStore` provider identifiers. */
export type SecretStoreProvider =
  | 'env'
  | 'azure-keyvault'
  | 'aws-secretsmanager'
  | 'gcp-secretmanager';

// ── EnvSecretStore ────────────────────────────────────────────────────────────

/**
 * Default `SecretStore` implementation that resolves secret names directly
 * from `process.env` (or any `NodeJS.ProcessEnv`-shaped map).
 *
 * This implementation is appropriate for local development, CI, and
 * deployments that inject secrets as Kubernetes environment variables or
 * Docker secrets mounted as env vars.
 */
export class EnvSecretStore implements SecretStore {
  private readonly env: NodeJS.ProcessEnv;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.env = env;
  }

  async getSecret(name: string): Promise<string | undefined> {
    const value = this.env[name];
    return value === '' ? undefined : value;
  }
}

// ── AzureKeyVaultSecretStore ──────────────────────────────────────────────────

/**
 * Configuration for {@link AzureKeyVaultSecretStore}.
 *
 * Authentication mirrors the pattern used by the KMS signers:
 *   - `credentialType: 'default'` (recommended) — `DefaultAzureCredential`
 *   - `credentialType: 'managed-identity'` — `ManagedIdentityCredential`
 *   - `credentialType: 'client-secret'` — `ClientSecretCredential`
 *
 * The `@azure/keyvault-secrets` and `@azure/identity` packages MUST be
 * installed in the deployment image.
 */
export interface AzureKeyVaultSecretStoreConfig {
  /** Key Vault base URL. Example: `https://my-vault.vault.azure.net/` */
  vaultUrl: string;
  /** Credential strategy. Defaults to `'default'` (`DefaultAzureCredential`). */
  credentialType?: 'default' | 'managed-identity' | 'client-secret';
  /** Required when `credentialType === 'managed-identity'` (user-assigned identity). */
  clientId?: string;
  /** Required when `credentialType === 'client-secret'`. */
  clientSecret?: string;
  /** Required when `credentialType === 'client-secret'`. */
  tenantId?: string;
}

/**
 * `SecretStore` backed by Azure Key Vault Secrets.
 *
 * Each `getSecret(name)` call invokes `SecretClient.getSecret(name)` and
 * returns the latest enabled secret version's plaintext value.
 *
 * Results are cached in memory for the lifetime of this instance to
 * avoid redundant round-trips when a secret is accessed multiple times
 * during a single process run.
 */
export class AzureKeyVaultSecretStore implements SecretStore {
  private readonly config: AzureKeyVaultSecretStoreConfig;
  // Lazily initialized on the first call to getSecret().
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client?: any;
  private readonly cache = new Map<string, string>();

  constructor(config: AzureKeyVaultSecretStoreConfig) {
    if (!config.vaultUrl) {
      throw new Error('AzureKeyVaultSecretStore: vaultUrl is required.');
    }
    if (config.credentialType === 'client-secret') {
      if (!config.tenantId || !config.clientId || !config.clientSecret) {
        throw new Error(
          'AzureKeyVaultSecretStore: tenantId, clientId, and clientSecret are required ' +
            'when credentialType is "client-secret".',
        );
      }
    }
    this.config = config;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private buildClient(): any {
    let identity: Record<string, unknown>;
    let secretsSdk: { SecretClient: new (url: string, credential: unknown) => unknown };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      identity = require('@azure/identity');
    } catch {
      throw new Error(
        'AzureKeyVaultSecretStore: the "@azure/identity" package is not installed. ' +
          'Add it to your deployment image: npm install @azure/identity',
      );
    }
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      secretsSdk = require('@azure/keyvault-secrets');
    } catch {
      throw new Error(
        'AzureKeyVaultSecretStore: the "@azure/keyvault-secrets" package is not installed. ' +
          'Add it to your deployment image: npm install @azure/keyvault-secrets',
      );
    }

    const { credentialType = 'default', clientId, clientSecret, tenantId } = this.config;

    let credential: unknown;
    if (credentialType === 'managed-identity') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const ManagedIdentityCredential = (identity as any).ManagedIdentityCredential;
      credential = clientId
        ? new ManagedIdentityCredential(clientId)
        : new ManagedIdentityCredential();
    } else if (credentialType === 'client-secret') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const ClientSecretCredential = (identity as any).ClientSecretCredential;
      credential = new ClientSecretCredential(tenantId!, clientId!, clientSecret!);
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const DefaultAzureCredential = (identity as any).DefaultAzureCredential;
      credential = new DefaultAzureCredential();
    }

    return new secretsSdk.SecretClient(this.config.vaultUrl, credential);
  }

  async getSecret(name: string): Promise<string | undefined> {
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;

    if (!this.client) {
      this.client = this.buildClient();
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result: any = await this.client.getSecret(name);
      const value: string | undefined = result?.value;
      if (value !== undefined && value !== '') {
        this.cache.set(name, value);
      }
      return value === '' ? undefined : value;
    } catch (err: unknown) {
      // Azure SDK throws a `RestError` with `statusCode === 404` when a
      // secret does not exist.  Treat 404 as "not found" (return undefined).
      if (
        typeof err === 'object' &&
        err !== null &&
        'statusCode' in err &&
        (err as Record<string, unknown>).statusCode === 404
      ) {
        return undefined;
      }
      throw err;
    }
  }
}

// ── AwsSecretsManagerSecretStore ──────────────────────────────────────────────

/**
 * Configuration for {@link AwsSecretsManagerSecretStore}.
 *
 * Authentication uses the standard AWS credential provider chain —
 * IAM role, IRSA, EC2 instance profile, `AWS_ACCESS_KEY_ID` /
 * `AWS_SECRET_ACCESS_KEY` env vars, or a shared credentials file.
 * Explicit credentials can be supplied to override the chain.
 *
 * The `@aws-sdk/client-secrets-manager` package MUST be installed in the
 * deployment image.
 */
export interface AwsSecretsManagerSecretStoreConfig {
  /** AWS region. Defaults to the SDK default (`AWS_REGION` / `AWS_DEFAULT_REGION`). */
  region?: string;
  /** Optional explicit AWS access key ID (overrides credential chain). */
  accessKeyId?: string;
  /** Optional explicit AWS secret access key (overrides credential chain). */
  secretAccessKey?: string;
  /** Optional AWS STS session token (for temporary credentials). */
  sessionToken?: string;
}

/**
 * `SecretStore` backed by AWS Secrets Manager.
 *
 * Each `getSecret(name)` call sends a `GetSecretValueCommand` with
 * `SecretId: name` and returns the `SecretString` field.
 *
 * Results are cached in memory for the lifetime of this instance.
 */
export class AwsSecretsManagerSecretStore implements SecretStore {
  private readonly config: AwsSecretsManagerSecretStoreConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client?: any;
  private readonly cache = new Map<string, string>();

  constructor(config: AwsSecretsManagerSecretStoreConfig = {}) {
    this.config = config;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private buildClient(): any {
    let sdk: {
      SecretsManagerClient: new (opts: Record<string, unknown>) => unknown;
      GetSecretValueCommand: new (input: Record<string, unknown>) => unknown;
    };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@aws-sdk/client-secrets-manager');
    } catch {
      throw new Error(
        'AwsSecretsManagerSecretStore: the "@aws-sdk/client-secrets-manager" package is ' +
          'not installed. Add it to your deployment image: ' +
          'npm install @aws-sdk/client-secrets-manager',
      );
    }

    const opts: Record<string, unknown> = {};
    if (this.config.region) opts['region'] = this.config.region;
    if (this.config.accessKeyId && this.config.secretAccessKey) {
      const credentials: Record<string, string> = {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
      };
      if (this.config.sessionToken) {
        credentials['sessionToken'] = this.config.sessionToken;
      }
      opts['credentials'] = credentials;
    }

    return new sdk.SecretsManagerClient(opts);
  }

  async getSecret(name: string): Promise<string | undefined> {
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;

    // Lazily build the SDK client so tests can mock `require()` before the
    // first call.
    if (!this.client) {
      this.client = this.buildClient();
    }

    // GetSecretValueCommand is resolved from the same `require()` call that
    // built the client — re-require to stay in the same module instance.
    let sdk: { GetSecretValueCommand: new (input: Record<string, unknown>) => unknown };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@aws-sdk/client-secrets-manager');
    } catch {
      throw new Error(
        'AwsSecretsManagerSecretStore: the "@aws-sdk/client-secrets-manager" package is not installed.',
      );
    }

    try {
      const command = new sdk.GetSecretValueCommand({ SecretId: name });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const response: any = await (this.client as any).send(command);
      const value: string | undefined = response?.SecretString;
      if (value !== undefined && value !== '') {
        this.cache.set(name, value);
      }
      return value === '' ? undefined : value;
    } catch (err: unknown) {
      // AWS SDK v3 throws an error with `name === 'ResourceNotFoundException'`
      // when the secret does not exist.  Treat as "not found".
      if (
        typeof err === 'object' &&
        err !== null &&
        'name' in err &&
        (err as Record<string, unknown>).name === 'ResourceNotFoundException'
      ) {
        return undefined;
      }
      throw err;
    }
  }
}

// ── GcpSecretManagerSecretStore ───────────────────────────────────────────────

/**
 * Configuration for {@link GcpSecretManagerSecretStore}.
 *
 * Authentication uses Application Default Credentials (ADC) — Workload
 * Identity Federation, `GOOGLE_APPLICATION_CREDENTIALS` key file, or
 * `gcloud auth application-default login` in development.  An explicit
 * key file path can be supplied via `keyFilePath`.
 *
 * The `@google-cloud/secret-manager` package MUST be installed in the
 * deployment image.
 */
export interface GcpSecretManagerSecretStoreConfig {
  /** GCP project ID. Example: `my-project-123`. */
  projectId: string;
  /**
   * Optional path to a GCP service account key file.  When set, this
   * overrides Application Default Credentials for this client only.
   */
  keyFilePath?: string;
}

/**
 * `SecretStore` backed by GCP Secret Manager.
 *
 * Each `getSecret(name)` call accesses the **latest enabled version** of
 * the secret named `name` in the configured project.  The resource path
 * used is:
 *
 *   `projects/<projectId>/secrets/<name>/versions/latest`
 *
 * Results are cached in memory for the lifetime of this instance.
 */
export class GcpSecretManagerSecretStore implements SecretStore {
  private readonly config: GcpSecretManagerSecretStoreConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client?: any;
  private readonly cache = new Map<string, string>();

  constructor(config: GcpSecretManagerSecretStoreConfig) {
    if (!config.projectId) {
      throw new Error('GcpSecretManagerSecretStore: projectId is required.');
    }
    this.config = config;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private buildClient(): any {
    let sdk: { SecretManagerServiceClient: new (opts?: Record<string, unknown>) => unknown };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@google-cloud/secret-manager');
    } catch {
      throw new Error(
        'GcpSecretManagerSecretStore: the "@google-cloud/secret-manager" package is not ' +
          'installed. Add it to your deployment image: ' +
          'npm install @google-cloud/secret-manager',
      );
    }

    const opts: Record<string, unknown> = {};
    if (this.config.keyFilePath) {
      opts['keyFilename'] = this.config.keyFilePath;
    }

    return new sdk.SecretManagerServiceClient(opts);
  }

  async getSecret(name: string): Promise<string | undefined> {
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;

    if (!this.client) {
      this.client = this.buildClient();
    }

    const resourceName =
      `projects/${this.config.projectId}/secrets/${name}/versions/latest`;

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const [version]: any[] = await (this.client as any).accessSecretVersion({
        name: resourceName,
      });
      const payloadData = version?.payload?.data;
      if (!payloadData) return undefined;

      const value =
        typeof payloadData === 'string'
          ? payloadData
          : Buffer.from(payloadData as Uint8Array).toString('utf8');

      if (value !== '') {
        this.cache.set(name, value);
      }
      return value === '' ? undefined : value;
    } catch (err: unknown) {
      // GCP SDK throws a gRPC error with `code === 5` (NOT_FOUND) when the
      // secret or its latest version does not exist.
      if (
        typeof err === 'object' &&
        err !== null &&
        'code' in err &&
        (err as Record<string, unknown>).code === 5
      ) {
        return undefined;
      }
      throw err;
    }
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Union type of all built-in `SecretStore` implementation configs.
 * Used as the `config` parameter of {@link createSecretStore}.
 */
export type SecretStoreConfig =
  | AzureKeyVaultSecretStoreConfig
  | AwsSecretsManagerSecretStoreConfig
  | GcpSecretManagerSecretStoreConfig
  | Record<string, never>;

/**
 * Create a `SecretStore` for the given provider key.
 *
 * @param provider - One of the built-in provider identifiers.
 * @param config   - Provider-specific configuration.  For `'env'`, pass `{}`
 *                   (or omit).
 *
 * @example
 * ```typescript
 * const store = createSecretStore('aws-secretsmanager', { region: 'us-east-1' });
 * const secret = await store.getSecret('MY_SECRET_NAME');
 * ```
 */
export function createSecretStore(
  provider: SecretStoreProvider,
  config?: SecretStoreConfig,
): SecretStore {
  switch (provider) {
    case 'env':
      return new EnvSecretStore();
    case 'azure-keyvault':
      return new AzureKeyVaultSecretStore(config as AzureKeyVaultSecretStoreConfig);
    case 'aws-secretsmanager':
      return new AwsSecretsManagerSecretStore(
        (config as AwsSecretsManagerSecretStoreConfig) ?? {},
      );
    case 'gcp-secretmanager':
      return new GcpSecretManagerSecretStore(config as GcpSecretManagerSecretStoreConfig);
    default: {
      // Exhaustiveness check — TypeScript will flag this if a new provider
      // is added to `SecretStoreProvider` without updating this switch.
      const _exhaustive: never = provider;
      throw new Error(`createSecretStore: unknown provider '${String(_exhaustive)}'.`);
    }
  }
}

/**
 * Create a `SecretStore` from environment variables.
 *
 * Reads `SECRET_STORE_PROVIDER` to determine which implementation to
 * use, then reads provider-specific config from the environment.  Falls
 * back to {@link EnvSecretStore} when `SECRET_STORE_PROVIDER` is unset.
 *
 * ### Provider-specific env vars
 *
 * | Provider              | Env vars read                                                                                                         |
 * |-----------------------|-----------------------------------------------------------------------------------------------------------------------|
 * | `env` (default)       | — none —                                                                                                              |
 * | `azure-keyvault`      | `SECRET_STORE_AZURE_VAULT_URL` (required), `AZURE_CREDENTIAL_TYPE`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
 * | `aws-secretsmanager`  | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`                                       |
 * | `gcp-secretmanager`   | `GCP_PROJECT_ID` (required), `GOOGLE_APPLICATION_CREDENTIALS` (ADC key file, consumed by SDK automatically)          |
 *
 * @param env - A `NodeJS.ProcessEnv`-shaped map.  Defaults to `process.env`.
 *
 * @example
 * ```typescript
 * // At service startup:
 * const store = createSecretStoreFromEnv(process.env);
 * const hmacSecret = await store.getSecret('AUDIT_LEDGER_HMAC_SECRET');
 * ```
 */
export function createSecretStoreFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): SecretStore {
  const rawProvider = env['SECRET_STORE_PROVIDER'];
  const provider = (rawProvider === '' ? undefined : rawProvider) as
    | SecretStoreProvider
    | undefined;

  switch (provider) {
    case undefined:
    case 'env':
      return new EnvSecretStore(env);

    case 'azure-keyvault': {
      const vaultUrl = env['SECRET_STORE_AZURE_VAULT_URL'];
      if (!vaultUrl) {
        throw new Error(
          'createSecretStoreFromEnv: SECRET_STORE_AZURE_VAULT_URL must be set ' +
            'when SECRET_STORE_PROVIDER=azure-keyvault.',
        );
      }
      const credentialType = env['AZURE_CREDENTIAL_TYPE'] as
        | 'default'
        | 'managed-identity'
        | 'client-secret'
        | undefined;
      return new AzureKeyVaultSecretStore({
        vaultUrl,
        credentialType: credentialType ?? 'default',
        clientId: env['AZURE_CLIENT_ID'],
        clientSecret: env['AZURE_CLIENT_SECRET'],
        tenantId: env['AZURE_TENANT_ID'],
      });
    }

    case 'aws-secretsmanager': {
      return new AwsSecretsManagerSecretStore({
        region: env['AWS_REGION'],
        accessKeyId: env['AWS_ACCESS_KEY_ID'],
        secretAccessKey: env['AWS_SECRET_ACCESS_KEY'],
        sessionToken: env['AWS_SESSION_TOKEN'],
      });
    }

    case 'gcp-secretmanager': {
      const projectId = env['GCP_PROJECT_ID'];
      if (!projectId) {
        throw new Error(
          'createSecretStoreFromEnv: GCP_PROJECT_ID must be set ' +
            'when SECRET_STORE_PROVIDER=gcp-secretmanager.',
        );
      }
      // GOOGLE_APPLICATION_CREDENTIALS is consumed automatically by the GCP
      // SDK as Application Default Credentials; we don't need to forward it.
      return new GcpSecretManagerSecretStore({ projectId });
    }

    default: {
      throw new Error(
        `createSecretStoreFromEnv: unrecognised SECRET_STORE_PROVIDER '${String(provider)}'. ` +
          'Valid values: env, azure-keyvault, aws-secretsmanager, gcp-secretmanager.',
      );
    }
  }
}

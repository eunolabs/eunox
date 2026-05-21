/**
 * Integration tests for the SecretStore factory (`createSecretStoreFromEnv`)
 * and cross-provider routing across all three cloud adapters.
 *
 * These tests validate the wiring logic of `createSecretStoreFromEnv` without
 * requiring live cloud services: they check that the factory creates the right
 * implementation class, populates provider-specific options correctly, and
 * rejects invalid configurations with useful error messages.
 *
 * Tests that actually call `getSecret()` against a live service are in the
 * provider-specific integration test files:
 *   - `aws-secrets-adapter.test.ts`  — AwsSecretsManagerSecretStore vs. LocalStack
 *   - `gcs-object-store.test.ts`     — GcsObjectStore vs. fake-gcs-server
 *   - `azure-blob-object-store.test.ts` — AzureBlobObjectStore vs. Azurite
 *
 * This file runs unconditionally (no emulator required).
 */

import {
  createSecretStoreFromEnv,
  EnvSecretStore,
  AzureKeyVaultSecretStore,
  AwsSecretsManagerSecretStore,
  GcpSecretManagerSecretStore,
} from '@euno/common-core';

// ── createSecretStoreFromEnv — provider routing ────────────────────────────────

describe('createSecretStoreFromEnv — provider routing', () => {
  it('defaults to EnvSecretStore when SECRET_STORE_PROVIDER is absent', () => {
    const store = createSecretStoreFromEnv({});
    expect(store).toBeInstanceOf(EnvSecretStore);
  });

  it('returns EnvSecretStore for SECRET_STORE_PROVIDER=env', () => {
    const store = createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'env' });
    expect(store).toBeInstanceOf(EnvSecretStore);
  });

  it('returns EnvSecretStore when SECRET_STORE_PROVIDER is empty string', () => {
    const store = createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: '' });
    expect(store).toBeInstanceOf(EnvSecretStore);
  });

  it('returns AzureKeyVaultSecretStore for azure-keyvault', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.example.com',
    });
    expect(store).toBeInstanceOf(AzureKeyVaultSecretStore);
  });

  it('throws when azure-keyvault is selected but vault URL is missing', () => {
    expect(() =>
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'azure-keyvault' }),
    ).toThrow('SECRET_STORE_AZURE_VAULT_URL must be set');
  });

  it('returns AwsSecretsManagerSecretStore for aws-secretsmanager', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'eu-west-1',
    });
    expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('returns GcpSecretManagerSecretStore for gcp-secretmanager', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'my-project',
    });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });

  it('throws when gcp-secretmanager is selected but project ID is missing', () => {
    expect(() =>
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'gcp-secretmanager' }),
    ).toThrow('SECRET_STORE_GCP_PROJECT_ID (or GCP_PROJECT_ID) must be set');
  });

  it('throws for an unrecognised SECRET_STORE_PROVIDER value', () => {
    expect(() =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'vault' } as any),
    ).toThrow("unrecognised SECRET_STORE_PROVIDER 'vault'");
  });
});

// ── AWS Secrets Manager — config population ────────────────────────────────────

describe('createSecretStoreFromEnv — AwsSecretsManagerSecretStore config', () => {
  function getConfig(store: AwsSecretsManagerSecretStore) {
    return (store as unknown as Record<string, unknown>)['config'] as {
      region?: string;
      arnsBySecretName: Record<string, string>;
      fallbackEnv: NodeJS.ProcessEnv;
    };
  }

  it('builds arnsBySecretName from every AWS_SECRETS_ARN_* env var', () => {
    const env: NodeJS.ProcessEnv = {
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-east-1',
      AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET:
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
      AWS_SECRETS_ARN_GATEWAY_ADMIN_API_KEY:
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/admin-key-xyz',
    };
    const store = createSecretStoreFromEnv(env) as AwsSecretsManagerSecretStore;
    const cfg = getConfig(store);

    expect(cfg.arnsBySecretName['AUDIT_LEDGER_HMAC_SECRET']).toBe(
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
    );
    expect(cfg.arnsBySecretName['GATEWAY_ADMIN_API_KEY']).toBe(
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/admin-key-xyz',
    );
  });

  it('sets fallbackEnv to the supplied env map', () => {
    const env: NodeJS.ProcessEnv = {
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      GATEWAY_ADMIN_API_KEY: 'direct-env-key',
    };
    const store = createSecretStoreFromEnv(env) as AwsSecretsManagerSecretStore;
    expect(getConfig(store).fallbackEnv).toBe(env);
  });

  it('uses SECRET_STORE_AWS_REGION in preference to AWS_REGION', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-east-1',
      SECRET_STORE_AWS_REGION: 'ap-southeast-2',
    }) as AwsSecretsManagerSecretStore;
    expect(getConfig(store).region).toBe('ap-southeast-2');
  });

  it('falls back to env-only lookup when no ARN is configured for the name', async () => {
    const env: NodeJS.ProcessEnv = {
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      MY_ENV_SECRET: 'from-env-only',
    };
    const store = createSecretStoreFromEnv(env);
    expect(await store.getSecret('MY_ENV_SECRET')).toBe('from-env-only');
  });
});

// ── GCP Secret Manager — config population ─────────────────────────────────────

describe('createSecretStoreFromEnv — GcpSecretManagerSecretStore config', () => {
  function getConfig(store: GcpSecretManagerSecretStore) {
    return (store as unknown as Record<string, unknown>)['config'] as {
      projectId: string;
      keyFilePath?: string;
    };
  }

  it('sets projectId from GCP_PROJECT_ID', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'my-project-123',
    }) as GcpSecretManagerSecretStore;
    expect(getConfig(store).projectId).toBe('my-project-123');
  });

  it('prefers SECRET_STORE_GCP_PROJECT_ID over GCP_PROJECT_ID', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'legacy-project',
      SECRET_STORE_GCP_PROJECT_ID: 'preferred-project',
    }) as GcpSecretManagerSecretStore;
    expect(getConfig(store).projectId).toBe('preferred-project');
  });

  it('sets keyFilePath from SECRET_STORE_GCP_KEY_FILE_PATH when provided', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'my-project',
      SECRET_STORE_GCP_KEY_FILE_PATH: '/path/to/key.json',
    }) as GcpSecretManagerSecretStore;
    expect(getConfig(store).keyFilePath).toBe('/path/to/key.json');
  });
});

// ── Azure Key Vault — config population ────────────────────────────────────────

describe('createSecretStoreFromEnv — AzureKeyVaultSecretStore config', () => {
  function getConfig(store: AzureKeyVaultSecretStore) {
    return (store as unknown as Record<string, unknown>)['config'] as {
      vaultUrl: string;
      credentialType?: string;
      clientId?: string;
      clientSecret?: string;
      tenantId?: string;
    };
  }

  it('sets vaultUrl from SECRET_STORE_AZURE_VAULT_URL', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://my-vault.vault.azure.net',
    }) as AzureKeyVaultSecretStore;
    expect(getConfig(store).vaultUrl).toBe('https://my-vault.vault.azure.net');
  });

  it('forwards client-secret credential fields', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.example.com',
      SECRET_STORE_AZURE_CREDENTIAL_TYPE: 'client-secret',
      SECRET_STORE_AZURE_TENANT_ID: 'my-tenant',
      SECRET_STORE_AZURE_CLIENT_ID: 'my-client-id',
      SECRET_STORE_AZURE_CLIENT_SECRET: 'my-client-secret',
    }) as AzureKeyVaultSecretStore;
    const cfg = getConfig(store);
    expect(cfg.credentialType).toBe('client-secret');
    expect(cfg.tenantId).toBe('my-tenant');
    expect(cfg.clientId).toBe('my-client-id');
    expect(cfg.clientSecret).toBe('my-client-secret');
  });
});

// ── All four providers: getSecret() fallback / basic smoke ─────────────────────

describe('createSecretStoreFromEnv — getSecret() smoke tests (no live service)', () => {
  it('EnvSecretStore returns a value from the supplied env map', async () => {
    const store = createSecretStoreFromEnv({ MY_KEY: 'hello-world' });
    expect(await store.getSecret('MY_KEY')).toBe('hello-world');
  });

  it('EnvSecretStore returns undefined for a missing key', async () => {
    const store = createSecretStoreFromEnv({});
    expect(await store.getSecret('NONEXISTENT')).toBeUndefined();
  });

  it('AwsSecretsManagerSecretStore falls back to env for keys without an ARN', async () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      PLAIN_ENV_KEY: 'plain-value',
    });
    expect(await store.getSecret('PLAIN_ENV_KEY')).toBe('plain-value');
  });
});

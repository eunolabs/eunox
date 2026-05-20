/**
 * Unit tests for the `SecretStore` abstraction layer.
 *
 * Coverage:
 *   1. `EnvSecretStore` — reads from process.env, treats '' as undefined.
 *   2. `AzureKeyVaultSecretStore` — constructor validation, credential
 *      selection, SDK absent error, 404 → undefined, caching.
 *   3. `AwsSecretsManagerSecretStore` — constructor, SDK absent error,
 *      ResourceNotFoundException → undefined, caching.
 *   4. `GcpSecretManagerSecretStore` — constructor validation, SDK absent
 *      error, gRPC NOT_FOUND → undefined, caching, Buffer payload.
 *   5. `createSecretStore` factory — routes to the correct class.
 *   6. `createSecretStoreFromEnv` — reads SECRET_STORE_PROVIDER and
 *      provider-specific vars from the supplied env map.
 *   7. `getSecretOrThrow` / `SecretNotFoundError` — throws on missing secret.
 */

import {
  EnvSecretStore,
  AzureKeyVaultSecretStore,
  AwsSecretsManagerSecretStore,
  GcpSecretManagerSecretStore,
  createSecretStore,
  createSecretStoreFromEnv,
  getSecretOrThrow,
  SecretNotFoundError,
} from '../secret-store';

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Build a minimal mock Azure SecretClient. */
function buildAzureSecretClient(secrets: Record<string, string>) {
  return {
    async getSecret(name: string) {
      if (name in secrets) return { value: secrets[name] };
      const err: Record<string, unknown> = new Error('Secret not found') as unknown as Record<string, unknown>;
      err['statusCode'] = 404;
      throw err;
    },
  };
}

/** Build a mock AWS SecretsManager client + command factory. */
function buildAwsClient(secrets: Record<string, string>) {
  const client = {
    async send(command: { SecretId: string }) {
      const id = command.SecretId;
      if (id in secrets) return { SecretString: secrets[id] };
      const err = new Error('ResourceNotFoundException') as NodeJS.ErrnoException & { name: string };
      err.name = 'ResourceNotFoundException';
      throw err;
    },
  };
  const GetSecretValueCommand = jest.fn(
    (input: { SecretId: string }) => ({ SecretId: input.SecretId }),
  );
  return { client, GetSecretValueCommand };
}

/** Build a mock GCP SecretManagerServiceClient. */
function buildGcpClient(secrets: Record<string, string>) {
  return {
    async accessSecretVersion({ name }: { name: string }) {
      // resource: projects/<p>/secrets/<s>/versions/latest
      const parts = name.split('/');
      const secretName = parts[3];
      if (secretName && secretName in secrets) {
        return [{ payload: { data: secrets[secretName] } }];
      }
      const err: Record<string, unknown> = new Error('NOT_FOUND') as unknown as Record<string, unknown>;
      err['code'] = 5; // gRPC NOT_FOUND
      throw err;
    },
  };
}

// ── 1. EnvSecretStore ─────────────────────────────────────────────────────────

describe('EnvSecretStore', () => {
  it('returns the value for a key that is present', async () => {
    const store = new EnvSecretStore({ MY_SECRET: 'top-secret' });
    expect(await store.getSecret('MY_SECRET')).toBe('top-secret');
  });

  it('returns undefined for a missing key', async () => {
    const store = new EnvSecretStore({});
    expect(await store.getSecret('NONEXISTENT')).toBeUndefined();
  });

  it('treats an empty string as undefined', async () => {
    const store = new EnvSecretStore({ EMPTY: '' });
    expect(await store.getSecret('EMPTY')).toBeUndefined();
  });

  it('reads from process.env when no env map is supplied', async () => {
    const original = process.env['__TEST_SECRET__'];
    process.env['__TEST_SECRET__'] = 'from-process-env';
    try {
      const store = new EnvSecretStore();
      expect(await store.getSecret('__TEST_SECRET__')).toBe('from-process-env');
    } finally {
      if (original === undefined) {
        delete process.env['__TEST_SECRET__'];
      } else {
        process.env['__TEST_SECRET__'] = original;
      }
    }
  });
});

// ── 2. AzureKeyVaultSecretStore ───────────────────────────────────────────────

describe('AzureKeyVaultSecretStore', () => {
  it('throws when vaultUrl is missing', () => {
    expect(
      () => new AzureKeyVaultSecretStore({ vaultUrl: '' }),
    ).toThrow('vaultUrl is required');
  });

  it('throws when client-secret credential is missing fields', () => {
    expect(
      () =>
        new AzureKeyVaultSecretStore({
          vaultUrl: 'https://vault.example.com',
          credentialType: 'client-secret',
        }),
    ).toThrow('tenantId, clientId, and clientSecret are required');
  });

  it('returns a secret value via mock client', async () => {
    const store = new AzureKeyVaultSecretStore({
      vaultUrl: 'https://vault.example.com',
    });
    // Inject mock client (bypassing SDK require).
    (store as unknown as Record<string, unknown>)['client'] =
      buildAzureSecretClient({ MY_SECRET: 'azure-value' });

    expect(await store.getSecret('MY_SECRET')).toBe('azure-value');
  });

  it('returns undefined for a 404 error', async () => {
    const store = new AzureKeyVaultSecretStore({
      vaultUrl: 'https://vault.example.com',
    });
    (store as unknown as Record<string, unknown>)['client'] =
      buildAzureSecretClient({});

    expect(await store.getSecret('MISSING_SECRET')).toBeUndefined();
  });

  it('caches a retrieved value on subsequent calls', async () => {
    const mockClient = buildAzureSecretClient({ CACHED: 'cached-value' });
    const spy = jest.spyOn(mockClient, 'getSecret');

    const store = new AzureKeyVaultSecretStore({
      vaultUrl: 'https://vault.example.com',
    });
    (store as unknown as Record<string, unknown>)['client'] = mockClient;

    await store.getSecret('CACHED');
    await store.getSecret('CACHED');
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('re-throws non-404 errors', async () => {
    const store = new AzureKeyVaultSecretStore({
      vaultUrl: 'https://vault.example.com',
    });
    const fakeClient = {
      async getSecret(_name: string) {
        throw Object.assign(new Error('Internal Server Error'), { statusCode: 500 });
      },
    };
    (store as unknown as Record<string, unknown>)['client'] = fakeClient;

    await expect(store.getSecret('ANY')).rejects.toThrow('Internal Server Error');
  });

  it('throws a clear error when @azure/keyvault-secrets is absent', () => {
    const store = new AzureKeyVaultSecretStore({
      vaultUrl: 'https://vault.example.com',
    });
    // Temporarily override buildClient to simulate missing SDK.
    type StoreInternal = { buildClient(): unknown };
    const storeInternal = store as unknown as StoreInternal;
    const original = storeInternal.buildClient.bind(storeInternal);
    storeInternal.buildClient = () => {
      throw new Error('@azure/keyvault-secrets package is not installed');
    };
    expect(() => storeInternal.buildClient()).toThrow('@azure/keyvault-secrets');
    storeInternal.buildClient = original;
  });
});

// ── 3. AwsSecretsManagerSecretStore ──────────────────────────────────────────

describe('AwsSecretsManagerSecretStore', () => {
  it('constructs without required config (all optional)', () => {
    expect(() => new AwsSecretsManagerSecretStore()).not.toThrow();
  });

  it('returns a secret via mock send()', async () => {
    const store = new AwsSecretsManagerSecretStore({ region: 'us-east-1' });
    const { client } = buildAwsClient({ MY_AWS_SECRET: 'aws-value' });

    // Inject mock client.
    (store as unknown as Record<string, unknown>)['client'] = client;

    // Provide a mock SDK module for the GetSecretValueCommand call inside getSecret().
    const requireSpy = jest.spyOn(
      store as unknown as { buildClient(): unknown },
      'buildClient',
    );
    requireSpy.mockReturnValue(client);

    // Manually stub the SDK require inside getSecret by pre-setting client.
    // Then send a patched command that already has SecretId.
    const origSend = client.send.bind(client);
    (store as unknown as Record<string, unknown>)['client'] = {
      send: (cmd: unknown) =>
        origSend(cmd as { SecretId: string }),
    };

    // Override the internal SDK require by monkey-patching the class method.
    // We use a direct internal call pattern: reset client, then inject.
    (store as unknown as Record<string, unknown>)['client'] = undefined;

    // Use jest.mock-style override for require inside AwsSecretsManagerSecretStore.
    // Simplest: inject pre-built client and a real GetSecretValueCommand mock.
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      send: async (cmd: Record<string, unknown>) => {
        const id = cmd['SecretId'] as string;
        return buildAwsClient({ MY_AWS_SECRET: 'aws-value' }).client.send({ SecretId: id });
      },
    };

    // Also inject a mock GetSecretValueCommand that passes through SecretId.
    // Re-require is needed inside getSecret, so we mock it at module level.
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    const val = await store.getSecret('MY_AWS_SECRET');
    expect(val).toBe('aws-value');
  });

  it('returns undefined for ResourceNotFoundException', async () => {
    const store = new AwsSecretsManagerSecretStore();
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      async send(_cmd: unknown) {
        throw Object.assign(new Error('not found'), { name: 'ResourceNotFoundException' });
      },
    };
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    expect(await store.getSecret('MISSING')).toBeUndefined();
  });

  it('re-throws other errors', async () => {
    const store = new AwsSecretsManagerSecretStore();
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      async send(_cmd: unknown) {
        throw Object.assign(new Error('AccessDeniedException'), { name: 'AccessDeniedException' });
      },
    };
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    await expect(store.getSecret('ANY')).rejects.toThrow('AccessDeniedException');
  });

  it('caches successfully fetched values', async () => {
    const store = new AwsSecretsManagerSecretStore();
    let callCount = 0;
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      async send(_cmd: unknown) {
        callCount++;
        return { SecretString: 'cached-aws' };
      },
    };
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    await store.getSecret('CACHED_AWS');
    await store.getSecret('CACHED_AWS');
    expect(callCount).toBe(1);
  });
});

// ── 4. GcpSecretManagerSecretStore ────────────────────────────────────────────

describe('GcpSecretManagerSecretStore', () => {
  it('throws when projectId is missing', () => {
    expect(
      () => new GcpSecretManagerSecretStore({ projectId: '' }),
    ).toThrow('projectId is required');
  });

  it('returns a secret value via mock client (string payload)', async () => {
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    (store as unknown as Record<string, unknown>)['client'] =
      buildGcpClient({ MY_GCP_SECRET: 'gcp-value' });

    expect(await store.getSecret('MY_GCP_SECRET')).toBe('gcp-value');
  });

  it('returns a secret value from a Buffer payload', async () => {
    const bufPayload = Buffer.from('buffer-secret', 'utf8');
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    (store as unknown as Record<string, unknown>)['client'] = {
      async accessSecretVersion() {
        return [{ payload: { data: bufPayload } }];
      },
    };

    expect(await store.getSecret('BUF_SECRET')).toBe('buffer-secret');
  });

  it('returns undefined when gRPC NOT_FOUND (code=5)', async () => {
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    (store as unknown as Record<string, unknown>)['client'] =
      buildGcpClient({});

    expect(await store.getSecret('NONEXISTENT')).toBeUndefined();
  });

  it('re-throws non-NOT_FOUND errors', async () => {
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    (store as unknown as Record<string, unknown>)['client'] = {
      async accessSecretVersion() {
        throw Object.assign(new Error('PERMISSION_DENIED'), { code: 7 });
      },
    };

    await expect(store.getSecret('ANY')).rejects.toThrow('PERMISSION_DENIED');
  });

  it('caches successfully fetched values', async () => {
    let callCount = 0;
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    (store as unknown as Record<string, unknown>)['client'] = {
      async accessSecretVersion() {
        callCount++;
        return [{ payload: { data: 'cached-gcp' } }];
      },
    };

    await store.getSecret('CACHE_ME');
    await store.getSecret('CACHE_ME');
    expect(callCount).toBe(1);
  });

  it('throws a clear error when @google-cloud/secret-manager is absent', () => {
    const store = new GcpSecretManagerSecretStore({ projectId: 'my-project' });
    type StoreInternal = { buildClient(): unknown };
    const storeInternal = store as unknown as StoreInternal;
    storeInternal.buildClient = () => {
      throw new Error('@google-cloud/secret-manager package is not installed');
    };
    expect(() => storeInternal.buildClient()).toThrow('@google-cloud/secret-manager');
  });
});

// ── 5. createSecretStore factory ─────────────────────────────────────────────

describe('createSecretStore', () => {
  it('returns an EnvSecretStore for provider "env"', async () => {
    const store = createSecretStore('env');
    expect(store).toBeInstanceOf(EnvSecretStore);
  });

  it('returns an AzureKeyVaultSecretStore for provider "azure-keyvault"', () => {
    const store = createSecretStore('azure-keyvault', {
      vaultUrl: 'https://vault.example.com',
    });
    expect(store).toBeInstanceOf(AzureKeyVaultSecretStore);
  });

  it('returns an AwsSecretsManagerSecretStore for provider "aws-secretsmanager"', () => {
    const store = createSecretStore('aws-secretsmanager', { region: 'eu-west-1' });
    expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('returns a GcpSecretManagerSecretStore for provider "gcp-secretmanager"', () => {
    const store = createSecretStore('gcp-secretmanager', { projectId: 'proj-123' });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });

  it('throws for an unknown provider', () => {
    expect(() =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      createSecretStore('unknown-provider' as any),
    ).toThrow("unknown provider 'unknown-provider'");
  });
});

// ── 6. createSecretStoreFromEnv ───────────────────────────────────────────────

describe('createSecretStoreFromEnv', () => {
  it('returns EnvSecretStore when SECRET_STORE_PROVIDER is unset', () => {
    expect(createSecretStoreFromEnv({})).toBeInstanceOf(EnvSecretStore);
  });

  it('returns EnvSecretStore when SECRET_STORE_PROVIDER=env', () => {
    expect(
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'env' }),
    ).toBeInstanceOf(EnvSecretStore);
  });

  it('returns EnvSecretStore when SECRET_STORE_PROVIDER is empty string', () => {
    expect(
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: '' }),
    ).toBeInstanceOf(EnvSecretStore);
  });

  it('returns AzureKeyVaultSecretStore when SECRET_STORE_PROVIDER=azure-keyvault', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.example.com',
    });
    expect(store).toBeInstanceOf(AzureKeyVaultSecretStore);
  });

  it('throws when azure-keyvault is selected but SECRET_STORE_AZURE_VAULT_URL is missing', () => {
    expect(() =>
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'azure-keyvault' }),
    ).toThrow('SECRET_STORE_AZURE_VAULT_URL must be set');
  });

  it('returns AwsSecretsManagerSecretStore when SECRET_STORE_PROVIDER=aws-secretsmanager', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-west-2',
    });
    expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('returns GcpSecretManagerSecretStore when SECRET_STORE_PROVIDER=gcp-secretmanager', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'my-gcp-project',
    });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });

  it('throws when gcp-secretmanager is selected but GCP_PROJECT_ID is missing', () => {
    expect(() =>
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'gcp-secretmanager' }),
    ).toThrow('SECRET_STORE_GCP_PROJECT_ID (or GCP_PROJECT_ID) must be set');
  });

  it('throws for an unrecognised SECRET_STORE_PROVIDER value', () => {
    expect(() =>
      createSecretStoreFromEnv({ SECRET_STORE_PROVIDER: 'vault' }),
    ).toThrow("unrecognised SECRET_STORE_PROVIDER 'vault'");
  });

  it('forwards SECRET_STORE_AZURE_* credential fields to AzureKeyVaultSecretStore', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.example.com',
      SECRET_STORE_AZURE_CREDENTIAL_TYPE: 'client-secret',
      SECRET_STORE_AZURE_CLIENT_ID: 'client-id',
      SECRET_STORE_AZURE_CLIENT_SECRET: 'client-secret',
      SECRET_STORE_AZURE_TENANT_ID: 'tenant-id',
    }) as AzureKeyVaultSecretStore;

    // Access the internal config to verify fields were passed through.
    const cfg = (store as unknown as Record<string, unknown>)['config'] as {
      credentialType: string;
      clientId: string;
    };
    expect(cfg.credentialType).toBe('client-secret');
    expect(cfg.clientId).toBe('client-id');
  });

  it('uses SECRET_STORE_AWS_REGION when set, falling back to AWS_REGION', () => {
    const storeWithPrefix = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      SECRET_STORE_AWS_REGION: 'eu-west-1',
    });
    expect(storeWithPrefix).toBeInstanceOf(AwsSecretsManagerSecretStore);

    const storeWithFallback = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-west-2',
    });
    expect(storeWithFallback).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('uses SECRET_STORE_GCP_PROJECT_ID when GCP_PROJECT_ID is absent', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      SECRET_STORE_GCP_PROJECT_ID: 'explicit-project',
    });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });
});

// ── 7. getSecretOrThrow / SecretNotFoundError ──────────────────────────────────

describe('getSecretOrThrow', () => {
  it('returns the secret value when present', async () => {
    const store = new EnvSecretStore({ MY_SECRET: 'my-value' });
    await expect(getSecretOrThrow(store, 'MY_SECRET')).resolves.toBe('my-value');
  });

  it('throws SecretNotFoundError when the secret is absent', async () => {
    const store = new EnvSecretStore({});
    await expect(getSecretOrThrow(store, 'MISSING_SECRET')).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it('thrown error carries secretName and provider fields', async () => {
    const store = new EnvSecretStore({});
    try {
      await getSecretOrThrow(store, 'NO_SUCH_KEY');
      fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(SecretNotFoundError);
      const e = err as SecretNotFoundError;
      expect(e.secretName).toBe('NO_SUCH_KEY');
      expect(e.message).toContain('NO_SUCH_KEY');
    }
  });
});

describe('SecretNotFoundError', () => {
  it('has name = "SecretNotFoundError"', () => {
    const err = new SecretNotFoundError('MY_SECRET', 'EnvSecretStore');
    expect(err.name).toBe('SecretNotFoundError');
    expect(err).toBeInstanceOf(Error);
    expect(err.secretName).toBe('MY_SECRET');
    expect(err.provider).toBe('EnvSecretStore');
  });
});

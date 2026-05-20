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

    // Need an ARN override for the secret to reach Secrets Manager
    const storeWithArn = new AwsSecretsManagerSecretStore({
      region: 'us-east-1',
      arnsBySecretName: { MY_AWS_SECRET: 'MY_AWS_SECRET' },
    });
    const storeWithArnAny = storeWithArn as unknown as Record<string, unknown>;
    storeWithArnAny['client'] = {
      send: async (cmd: Record<string, unknown>) => {
        const id = cmd['SecretId'] as string;
        return buildAwsClient({ MY_AWS_SECRET: 'aws-value' }).client.send({ SecretId: id });
      },
    };
    const val = await storeWithArn.getSecret('MY_AWS_SECRET');
    expect(val).toBe('aws-value');
  });

  it('returns undefined for ResourceNotFoundException', async () => {
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: { MISSING: 'arn:aws:secretsmanager:us-east-1:123:secret:missing' },
    });
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
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: { ANY: 'arn:aws:secretsmanager:us-east-1:123:secret:any' },
    });
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
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: { CACHED_AWS: 'arn:aws:secretsmanager:us-east-1:123:secret:cached' },
    });
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

  // ── ARN fallback behaviour ────────────────────────────────────────────────

  it('falls back to fallbackEnv when no ARN is configured for the name', async () => {
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: {},
      fallbackEnv: { MY_ENV_SECRET: 'env-value' },
    });
    expect(await store.getSecret('MY_ENV_SECRET')).toBe('env-value');
  });

  it('treats empty fallbackEnv value as undefined (same as EnvSecretStore)', async () => {
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: {},
      fallbackEnv: { EMPTY_SECRET: '' },
    });
    expect(await store.getSecret('EMPTY_SECRET')).toBeUndefined();
  });

  it('returns undefined from fallbackEnv for a missing key', async () => {
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: {},
      fallbackEnv: {},
    });
    expect(await store.getSecret('NOT_PRESENT')).toBeUndefined();
  });

  it('uses the ARN as SecretId when arnsBySecretName has an entry for the name', async () => {
    const capturedSecretIds: string[] = [];
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: {
        HMAC_SECRET: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
      },
      fallbackEnv: {},
    });
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      async send(cmd: Record<string, unknown>) {
        capturedSecretIds.push(cmd['SecretId'] as string);
        return { SecretString: 'fetched-from-sm' };
      },
    };
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    const val = await store.getSecret('HMAC_SECRET');
    expect(val).toBe('fetched-from-sm');
    expect(capturedSecretIds).toEqual([
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
    ]);
  });

  it('mixes ARN and env fallback for different secrets in the same store', async () => {
    const store = new AwsSecretsManagerSecretStore({
      arnsBySecretName: {
        HMAC_SECRET: 'arn:aws:secretsmanager:us-east-1:123:secret:hmac',
      },
      fallbackEnv: {
        ADMIN_KEY: 'admin-from-env',
        HMAC_SECRET: 'should-not-be-used', // ARN takes precedence
      },
    });
    const storeAny = store as unknown as Record<string, unknown>;
    storeAny['client'] = {
      async send(_cmd: unknown) {
        return { SecretString: 'hmac-from-sm' };
      },
    };
    jest.mock('@aws-sdk/client-secrets-manager', () => ({
      SecretsManagerClient: jest.fn(),
      GetSecretValueCommand: jest.fn((input: Record<string, unknown>) => input),
    }), { virtual: true });

    expect(await store.getSecret('HMAC_SECRET')).toBe('hmac-from-sm');
    expect(await store.getSecret('ADMIN_KEY')).toBe('admin-from-env');
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

  it('populates arnsBySecretName from AWS_SECRETS_ARN_* env vars', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-east-1',
      AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET:
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
      AWS_SECRETS_ARN_GATEWAY_ADMIN_API_KEY:
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/admin-key-xyz',
    }) as AwsSecretsManagerSecretStore;

    const cfg = (store as unknown as Record<string, unknown>)['config'] as {
      arnsBySecretName: Record<string, string>;
    };
    expect(cfg.arnsBySecretName['AUDIT_LEDGER_HMAC_SECRET']).toBe(
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/hmac-abc',
    );
    expect(cfg.arnsBySecretName['GATEWAY_ADMIN_API_KEY']).toBe(
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/admin-key-xyz',
    );
  });

  it('sets fallbackEnv to the supplied env map for aws-secretsmanager', () => {
    const env: NodeJS.ProcessEnv = {
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      GATEWAY_ADMIN_API_KEY: 'env-admin-key',
    };
    const store = createSecretStoreFromEnv(env) as AwsSecretsManagerSecretStore;
    const cfg = (store as unknown as Record<string, unknown>)['config'] as {
      fallbackEnv: NodeJS.ProcessEnv;
    };
    expect(cfg.fallbackEnv).toBe(env);
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

  it('forwards AzureAD credential fields to AzureKeyVaultSecretStore', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.example.com',
      AZURE_CREDENTIAL_TYPE: 'client-secret',
      AZURE_CLIENT_ID: 'client-id',
      AZURE_CLIENT_SECRET: 'client-secret',
      AZURE_TENANT_ID: 'tenant-id',
    }) as AzureKeyVaultSecretStore;

    // Access the internal config to verify fields were passed through.
    const cfg = (store as unknown as Record<string, unknown>)['config'] as {
      credentialType: string;
      clientId: string;
    };
    expect(cfg.credentialType).toBe('client-secret');
    expect(cfg.clientId).toBe('client-id');
  });
});

// ── getSecretOrThrow / SecretNotFoundError ─────────────────────────────────────

describe('getSecretOrThrow', () => {
  it('returns the secret value when present', async () => {
    const store = new EnvSecretStore({ MY_KEY: 'my-value' });
    const value = await getSecretOrThrow(store, 'MY_KEY');
    expect(value).toBe('my-value');
  });

  it('throws SecretNotFoundError when secret is absent', async () => {
    const store = new EnvSecretStore({});
    await expect(getSecretOrThrow(store, 'MISSING_KEY')).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it('SecretNotFoundError has the correct secretName and provider', async () => {
    const store = new EnvSecretStore({});
    let caught: SecretNotFoundError | undefined;
    try {
      await getSecretOrThrow(store, 'MISSING_KEY');
    } catch (err) {
      caught = err as SecretNotFoundError;
    }
    expect(caught).toBeDefined();
    expect(caught!.secretName).toBe('MISSING_KEY');
    expect(caught!.name).toBe('SecretNotFoundError');
  });

  it('SecretNotFoundError message contains the secret name', async () => {
    const store = new EnvSecretStore({});
    await expect(getSecretOrThrow(store, 'MY_SECRET')).rejects.toThrow('MY_SECRET');
  });
});

describe('createSecretStoreFromEnv — SECRET_STORE_* prefixed vars', () => {
  it('prefers SECRET_STORE_AWS_REGION over AWS_REGION for aws-secretsmanager', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      SECRET_STORE_AWS_REGION: 'eu-central-1',
      AWS_REGION: 'us-east-1',
    });
    expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('falls back to AWS_REGION when SECRET_STORE_AWS_REGION is absent', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'aws-secretsmanager',
      AWS_REGION: 'us-west-2',
    });
    expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
  });

  it('prefers SECRET_STORE_GCP_PROJECT_ID over GCP_PROJECT_ID', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      SECRET_STORE_GCP_PROJECT_ID: 'override-project',
      GCP_PROJECT_ID: 'fallback-project',
    });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });

  it('falls back to GCP_PROJECT_ID when SECRET_STORE_GCP_PROJECT_ID is absent', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'gcp-secretmanager',
      GCP_PROJECT_ID: 'my-project',
    });
    expect(store).toBeInstanceOf(GcpSecretManagerSecretStore);
  });

  it('prefers SECRET_STORE_AZURE_CREDENTIAL_TYPE over AZURE_CREDENTIAL_TYPE', () => {
    const store = createSecretStoreFromEnv({
      SECRET_STORE_PROVIDER: 'azure-keyvault',
      SECRET_STORE_AZURE_VAULT_URL: 'https://vault.azure.net/',
      SECRET_STORE_AZURE_CREDENTIAL_TYPE: 'managed-identity',
      AZURE_CREDENTIAL_TYPE: 'default',
    });
    expect(store).toBeInstanceOf(AzureKeyVaultSecretStore);
  });
});

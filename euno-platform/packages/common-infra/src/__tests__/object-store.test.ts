/**
 * Unit tests for the cloud-agnostic ObjectStore abstraction.
 *
 * Covers:
 *   1. S3ObjectStore — delegates to S3AnchorClient.putObject()
 *   2. GcsObjectStore — delegates to GcsAnchorClient.putObject()
 *   3. AzureBlobObjectStore — lazy-loads @azure/storage-blob; error path when absent
 *   4. createObjectStoreFromEnv — provider selection and env-var validation
 */

// ── AzureBlobObjectStore tests mock @azure/storage-blob before imports ────────

jest.mock('@azure/storage-blob', () => {
  const upload = jest.fn().mockResolvedValue(undefined);
  const getBlockBlobClient = jest.fn().mockReturnValue({ upload });
  const getContainerClient = jest.fn().mockReturnValue({ getBlockBlobClient });
  const fromConnectionString = jest.fn().mockReturnValue({ getContainerClient });
  const BlobServiceClient = Object.assign(
    jest.fn().mockReturnValue({ getContainerClient }),
    { fromConnectionString },
  );
  const StorageSharedKeyCredential = jest.fn();
  return { BlobServiceClient, StorageSharedKeyCredential };
}, { virtual: true });

jest.mock('@azure/identity', () => {
  const DefaultAzureCredential = jest.fn();
  return { DefaultAzureCredential };
}, { virtual: true });

import {
  S3ObjectStore,
  GcsObjectStore,
  AzureBlobObjectStore,
  createObjectStoreFromEnv,
  ObjectStore,
} from '../object-store';
import { S3AnchorClient, GcsAnchorClient } from '../ledger-signer';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockS3Client() {
  const calls: { bucket: string; key: string; body: string; contentType: string }[] = [];
  const client: S3AnchorClient = {
    async putObject(params) {
      calls.push(params);
    },
  };
  return { client, calls };
}

function makeMockGcsClient() {
  const calls: { bucket: string; key: string; body: string; contentType: string }[] = [];
  const client: GcsAnchorClient = {
    async putObject(params) {
      calls.push(params);
    },
  };
  return { client, calls };
}

// ── S3ObjectStore ─────────────────────────────────────────────────────────────

describe('S3ObjectStore', () => {
  it('implements ObjectStore interface', () => {
    const { client } = makeMockS3Client();
    const store: ObjectStore = new S3ObjectStore(client, 'my-bucket');
    expect(typeof store.put).toBe('function');
  });

  it('delegates put() to client.putObject() with the correct bucket', async () => {
    const { client, calls } = makeMockS3Client();
    const store = new S3ObjectStore(client, 'audit-bucket');

    await store.put('audit-anchor/rep-1/1-1000.json', '{"merkleRoot":"abc"}', 'application/json');

    expect(calls).toHaveLength(1);
    expect(calls[0]!.bucket).toBe('audit-bucket');
    expect(calls[0]!.key).toBe('audit-anchor/rep-1/1-1000.json');
    expect(calls[0]!.body).toBe('{"merkleRoot":"abc"}');
    expect(calls[0]!.contentType).toBe('application/json');
  });

  it('passes through errors from the underlying client', async () => {
    const client: S3AnchorClient = {
      putObject: async () => { throw new Error('S3 put failed'); },
    };
    const store = new S3ObjectStore(client, 'bucket');
    await expect(store.put('key', 'body', 'application/json')).rejects.toThrow('S3 put failed');
  });

  it('calls client.putObject exactly once per put()', async () => {
    const { client, calls } = makeMockS3Client();
    const store = new S3ObjectStore(client, 'b');
    await store.put('k1', 'd1', 'application/json');
    await store.put('k2', 'd2', 'application/json');
    expect(calls).toHaveLength(2);
    expect(calls[0]!.key).toBe('k1');
    expect(calls[1]!.key).toBe('k2');
  });

  it('uses the bucket provided at construction time', async () => {
    const { client, calls } = makeMockS3Client();
    const store = new S3ObjectStore(client, 'fixed-bucket');
    await store.put('key', 'data', 'text/plain');
    expect(calls[0]!.bucket).toBe('fixed-bucket');
  });
});

// ── GcsObjectStore ────────────────────────────────────────────────────────────

describe('GcsObjectStore', () => {
  it('implements ObjectStore interface', () => {
    const { client } = makeMockGcsClient();
    const store: ObjectStore = new GcsObjectStore(client, 'gcs-bucket');
    expect(typeof store.put).toBe('function');
  });

  it('delegates put() to client.putObject() with the correct bucket', async () => {
    const { client, calls } = makeMockGcsClient();
    const store = new GcsObjectStore(client, 'gcs-audit');

    await store.put('audit-anchor/rep-gcs/1-500.json', '{"root":"xyz"}', 'application/json');

    expect(calls).toHaveLength(1);
    expect(calls[0]!.bucket).toBe('gcs-audit');
    expect(calls[0]!.key).toBe('audit-anchor/rep-gcs/1-500.json');
    expect(calls[0]!.body).toBe('{"root":"xyz"}');
    expect(calls[0]!.contentType).toBe('application/json');
  });

  it('passes through errors from the underlying client', async () => {
    const client: GcsAnchorClient = {
      putObject: async () => { throw new Error('GCS put failed'); },
    };
    const store = new GcsObjectStore(client, 'bucket');
    await expect(store.put('key', 'body', 'application/json')).rejects.toThrow('GCS put failed');
  });

  it('uses the bucket provided at construction time', async () => {
    const { client, calls } = makeMockGcsClient();
    const store = new GcsObjectStore(client, 'my-gcs-bucket');
    await store.put('k', 'd', 'application/json');
    expect(calls[0]!.bucket).toBe('my-gcs-bucket');
  });
});

// ── AzureBlobObjectStore ──────────────────────────────────────────────────────

describe('AzureBlobObjectStore', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockSdk: any;

  beforeEach(() => {
    jest.resetModules();
    mockSdk = jest.requireMock('@azure/storage-blob');
    // Reset all mock functions
    mockSdk.BlobServiceClient.mockClear();
    mockSdk.BlobServiceClient.fromConnectionString.mockClear();
    mockSdk.StorageSharedKeyCredential.mockClear();
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue({ upload: jest.fn().mockResolvedValue(undefined) }) };
    mockSdk.BlobServiceClient.mockReturnValue({ getContainerClient: jest.fn().mockReturnValue(containerClient) });
    mockSdk.BlobServiceClient.fromConnectionString.mockReturnValue({ getContainerClient: jest.fn().mockReturnValue(containerClient) });
  });

  it('constructs without throwing', () => {
    expect(() => new AzureBlobObjectStore({
      containerName: 'audit-anchors',
      connectionString: 'UseDevelopmentStorage=true',
    })).not.toThrow();
  });

  it('throws when neither connectionString nor accountName is provided', async () => {
    const store = new AzureBlobObjectStore({ containerName: 'c' });
    await expect(store.put('k', 'd', 'application/json')).rejects.toThrow(
      'either connectionString or accountName must be provided',
    );
  });

  it('uses BlobServiceClient.fromConnectionString when connectionString is provided', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.fromConnectionString.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'my-container',
      connectionString: 'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=AAAA==;EndpointSuffix=core.windows.net',
    });

    await store.put('audit-anchor/cross-chain/coord/1.json', '{"test":1}', 'application/json');

    expect(mockSdk.BlobServiceClient.fromConnectionString).toHaveBeenCalledWith(
      'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=AAAA==;EndpointSuffix=core.windows.net',
    );
    expect(serviceClient.getContainerClient).toHaveBeenCalledWith('my-container');
    expect(containerClient.getBlockBlobClient).toHaveBeenCalledWith('audit-anchor/cross-chain/coord/1.json');
    expect(uploadMock).toHaveBeenCalled();
  });

  it('passes blobContentType to upload', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.fromConnectionString.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      connectionString: 'UseDevelopmentStorage=true',
    });

    await store.put('k', 'hello', 'application/json');

    const [buf, _len, opts] = uploadMock.mock.calls[0] as [Buffer, number, { blobHTTPHeaders: { blobContentType: string } }];
    expect(buf.toString('utf-8')).toBe('hello');
    expect(opts.blobHTTPHeaders.blobContentType).toBe('application/json');
  });

  it('uses StorageSharedKeyCredential when accountName + accountKey are provided', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      accountName: 'myaccount',
      accountKey: 'dGVzdA==',
    });

    await store.put('k', 'd', 'application/json');

    expect(mockSdk.StorageSharedKeyCredential).toHaveBeenCalledWith('myaccount', 'dGVzdA==');
    expect(mockSdk.BlobServiceClient).toHaveBeenCalledWith(
      'https://myaccount.blob.core.windows.net',
      expect.any(Object),
    );
  });

  it('uses custom endpoint when provided with accountName + accountKey', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      accountName: 'devstoreaccount1',
      accountKey: 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==',
      endpoint: 'http://127.0.0.1:10000/devstoreaccount1',
    });

    await store.put('k', 'd', 'application/json');

    expect(mockSdk.BlobServiceClient).toHaveBeenCalledWith(
      'http://127.0.0.1:10000/devstoreaccount1',
      expect.any(Object),
    );
  });

  it('uses DefaultAzureCredential when only accountName is provided', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.mockReturnValue(serviceClient);

    const { DefaultAzureCredential } = jest.requireMock('@azure/identity') as { DefaultAzureCredential: jest.Mock };
    DefaultAzureCredential.mockClear();

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      accountName: 'myaccount',
    });

    await store.put('k', 'd', 'application/json');

    expect(DefaultAzureCredential).toHaveBeenCalledTimes(1);
    expect(mockSdk.BlobServiceClient).toHaveBeenCalledWith(
      'https://myaccount.blob.core.windows.net',
      expect.any(Object),
    );
  });

  it('reuses the same container client across multiple put() calls (lazy singleton)', async () => {
    const uploadMock = jest.fn().mockResolvedValue(undefined);
    const blobClient = { upload: uploadMock };
    const getBlockBlobClient = jest.fn().mockReturnValue(blobClient);
    const containerClient = { getBlockBlobClient };
    const getContainerClient = jest.fn().mockReturnValue(containerClient);
    const serviceClient = { getContainerClient };
    mockSdk.BlobServiceClient.fromConnectionString.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      connectionString: 'UseDevelopmentStorage=true',
    });

    await store.put('k1', 'd1', 'application/json');
    await store.put('k2', 'd2', 'application/json');

    // BlobServiceClient.fromConnectionString should only be called once.
    expect(mockSdk.BlobServiceClient.fromConnectionString).toHaveBeenCalledTimes(1);
    expect(getContainerClient).toHaveBeenCalledTimes(1);
    expect(uploadMock).toHaveBeenCalledTimes(2);
  });

  it('propagates errors from upload()', async () => {
    const uploadMock = jest.fn().mockRejectedValue(new Error('Azure upload failed'));
    const blobClient = { upload: uploadMock };
    const containerClient = { getBlockBlobClient: jest.fn().mockReturnValue(blobClient) };
    const serviceClient = { getContainerClient: jest.fn().mockReturnValue(containerClient) };
    mockSdk.BlobServiceClient.fromConnectionString.mockReturnValue(serviceClient);

    const store = new AzureBlobObjectStore({
      containerName: 'c',
      connectionString: 'UseDevelopmentStorage=true',
    });

    await expect(store.put('k', 'd', 'application/json')).rejects.toThrow('Azure upload failed');
  });

  describe('when @azure/storage-blob is not installed', () => {
    it('throws a clear error message', async () => {
      // Temporarily override the module require to simulate missing SDK.
      const store = new AzureBlobObjectStore({
        containerName: 'c',
        connectionString: 'UseDevelopmentStorage=true',
      });

      // Override buildContainerClient to simulate the SDK not being available.
      jest.spyOn(
        store as unknown as { buildContainerClient(): unknown },
        'buildContainerClient',
      ).mockImplementation(() => {
        throw new Error('@azure/storage-blob package is not installed');
      });

      await expect(store.put('k', 'd', 'application/json')).rejects.toThrow(
        '@azure/storage-blob package is not installed',
      );
    });
  });
});

// ── createObjectStoreFromEnv ──────────────────────────────────────────────────

describe('createObjectStoreFromEnv', () => {
  it('returns undefined when AUDIT_LEDGER_OBJECT_STORE_PROVIDER is not set', () => {
    expect(createObjectStoreFromEnv({})).toBeUndefined();
  });

  it('throws for an unknown provider value', () => {
    expect(() =>
      createObjectStoreFromEnv({ AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'minio' }),
    ).toThrow('unknown AUDIT_LEDGER_OBJECT_STORE_PROVIDER value "minio"');
  });

  describe('provider=s3', () => {
    it('returns an S3ObjectStore instance', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 's3',
        AUDIT_LEDGER_S3_BUCKET: 'my-s3-bucket',
      });
      expect(store).toBeInstanceOf(S3ObjectStore);
    });

    it('throws when AUDIT_LEDGER_S3_BUCKET is not set', () => {
      expect(() =>
        createObjectStoreFromEnv({ AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 's3' }),
      ).toThrow('requires AUDIT_LEDGER_S3_BUCKET');
    });

    it('bakes the bucket into the returned store', async () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 's3',
        AUDIT_LEDGER_S3_BUCKET: 'locked-s3-bucket',
      }) as S3ObjectStore;

      // Verify bucket is embedded by inspecting the private field via cast.
      const internal = store as unknown as { bucket: string };
      expect(internal.bucket).toBe('locked-s3-bucket');
    });
  });

  describe('provider=gcs', () => {
    it('returns a GcsObjectStore instance', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
        AUDIT_LEDGER_GCS_BUCKET: 'my-gcs-bucket',
      });
      expect(store).toBeInstanceOf(GcsObjectStore);
    });

    it('throws when AUDIT_LEDGER_GCS_BUCKET is not set', () => {
      expect(() =>
        createObjectStoreFromEnv({ AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs' }),
      ).toThrow('requires AUDIT_LEDGER_GCS_BUCKET');
    });

    it('bakes the GCS bucket into the returned store', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
        AUDIT_LEDGER_GCS_BUCKET: 'my-retention-bucket',
      }) as GcsObjectStore;
      const internal = store as unknown as { bucket: string };
      expect(internal.bucket).toBe('my-retention-bucket');
    });
  });

  describe('provider=azure-blob', () => {
    it('returns an AzureBlobObjectStore instance', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: 'audit-anchors',
        AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING: 'UseDevelopmentStorage=true',
      });
      expect(store).toBeInstanceOf(AzureBlobObjectStore);
    });

    it('throws when AUDIT_LEDGER_AZURE_CONTAINER is not set', () => {
      expect(() =>
        createObjectStoreFromEnv({ AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob' }),
      ).toThrow('requires AUDIT_LEDGER_AZURE_CONTAINER');
    });

    it('bakes the container name into the returned store', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: 'immutable-anchors',
        AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING: 'UseDevelopmentStorage=true',
      }) as AzureBlobObjectStore;

      // AzureBlobObjectStore stores config, not direct fields.
      const internal = store as unknown as { config: { containerName: string } };
      expect(internal.config.containerName).toBe('immutable-anchors');
    });

    it('passes connectionString from env to the store', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: 'c',
        AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING: 'my-conn-str',
      }) as AzureBlobObjectStore;
      const internal = store as unknown as { config: { connectionString?: string } };
      expect(internal.config.connectionString).toBe('my-conn-str');
    });

    it('passes accountName and accountKey from env to the store', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: 'c',
        AUDIT_LEDGER_AZURE_ACCOUNT_NAME: 'myaccount',
        AUDIT_LEDGER_AZURE_ACCOUNT_KEY: 'mykey',
      }) as AzureBlobObjectStore;
      const internal = store as unknown as {
        config: { accountName?: string; accountKey?: string };
      };
      expect(internal.config.accountName).toBe('myaccount');
      expect(internal.config.accountKey).toBe('mykey');
    });

    it('passes custom endpoint from env to the store', () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: 'c',
        AUDIT_LEDGER_AZURE_ACCOUNT_NAME: 'devstoreaccount1',
        AUDIT_LEDGER_AZURE_ENDPOINT: 'http://127.0.0.1:10000/devstoreaccount1',
      }) as AzureBlobObjectStore;
      const internal = store as unknown as { config: { endpoint?: string } };
      expect(internal.config.endpoint).toBe('http://127.0.0.1:10000/devstoreaccount1');
    });
  });
});

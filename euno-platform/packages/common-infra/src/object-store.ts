/**
 * Cloud-agnostic object storage abstraction for audit-ledger anchoring.
 * ────────────────────────────────────────────────────────────────────────────
 * Defines the minimal {@link ObjectStore} interface used by
 * {@link CrossChainAnchor}, {@link PostgresLedgerBackend}, and
 * {@link PerReplicaPostgresLedgerBackend} to publish tamper-evident anchor
 * objects to external storage — without coupling the core ledger logic to
 * any particular cloud SDK.
 *
 * ## Built-in implementations
 *
 * | Class                  | Cloud       | Underlying SDK                      |
 * |------------------------|-------------|-------------------------------------|
 * | `S3ObjectStore`        | AWS         | `@aws-sdk/client-s3` (via adapter)  |
 * | `GcsObjectStore`       | GCP         | `@google-cloud/storage` (via adapter)|
 * | `AzureBlobObjectStore` | Azure       | `@azure/storage-blob` (lazily loaded)|
 *
 * ## Selection via environment variable
 *
 * `createObjectStoreFromEnv()` reads `AUDIT_LEDGER_OBJECT_STORE_PROVIDER`
 * (`'s3'` | `'gcs'` | `'azure-blob'`) and builds the appropriate
 * implementation from companion environment variables.
 *
 * When `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` is **not** set the factory
 * returns `undefined` — callers continue to use the legacy `s3?`/`gcs?`
 * options on the ledger backend/anchor constructors.
 */

import type { S3AnchorClient, GcsAnchorClient } from './ledger-signer';
import { AwsSdkS3AnchorClient } from './s3-anchor-client';

// ── ObjectStore interface ─────────────────────────────────────────────────────

/**
 * Minimal interface for writing a single object to cloud object storage.
 *
 * Implementations are bucket/container-specific: the bucket or container name
 * is provided at construction time (or read from environment variables), so
 * callers only supply the object `key`, the `data` payload, and an optional
 * `contentType`.
 *
 * The implementation SHOULD ensure the written object is immutable or
 * write-once when the underlying storage supports it (S3 Object Lock
 * COMPLIANCE mode, GCS `temporaryHold`, Azure Blob immutability policy).
 */
export interface ObjectStore {
  /**
   * Write `data` to the object at `key`.
   *
   * @param key         Full object key / blob name (e.g. `audit-anchor/rep-1/1-1000.json`).
   * @param data        Object body as a UTF-8 string.
   * @param contentType MIME type (e.g. `application/json`).
   */
  put(key: string, data: string, contentType: string): Promise<void>;
}

// ── S3ObjectStore ─────────────────────────────────────────────────────────────

/**
 * {@link ObjectStore} implementation backed by an {@link S3AnchorClient}.
 *
 * The bucket is fixed at construction time.  The underlying `S3AnchorClient`
 * implementation (typically {@link AwsSdkS3AnchorClient}) writes objects with
 * `ObjectLockMode: 'COMPLIANCE'` for tamper-evidence.
 */
export class S3ObjectStore implements ObjectStore {
  constructor(
    private readonly client: S3AnchorClient,
    private readonly bucket: string,
  ) {}

  put(key: string, data: string, contentType: string): Promise<void> {
    return this.client.putObject({ bucket: this.bucket, key, body: data, contentType });
  }
}

// ── GcsObjectStore ────────────────────────────────────────────────────────────

/**
 * {@link ObjectStore} implementation backed by a {@link GcsAnchorClient}.
 *
 * The bucket is fixed at construction time.  The underlying implementation
 * (typically `GcsAnchorClientImpl`) applies a `temporaryHold` to each
 * uploaded object for per-object tamper-evidence.
 */
export class GcsObjectStore implements ObjectStore {
  constructor(
    private readonly client: GcsAnchorClient,
    private readonly bucket: string,
  ) {}

  put(key: string, data: string, contentType: string): Promise<void> {
    return this.client.putObject({ bucket: this.bucket, key, body: data, contentType });
  }
}

// ── AzureBlobObjectStore ──────────────────────────────────────────────────────

/**
 * Configuration for {@link AzureBlobObjectStore}.
 *
 * Exactly one of `connectionString` or `accountName` must be provided.
 *
 * ## Authentication options
 *
 * 1. **Connection string** (`connectionString`) — suitable for development and
 *    Azurite local testing.  Not recommended for production.
 * 2. **Account name + key** (`accountName` + `accountKey`) — shared-key
 *    authentication.  Provides full access; consider using a SAS token for
 *    least-privilege scenarios.
 * 3. **Account name only** (`accountName` without `accountKey`) — uses
 *    `DefaultAzureCredential` from `@azure/identity` for workload-identity /
 *    managed-identity authentication.  Recommended for AKS deployments.
 *
 * ## Immutability
 *
 * Azure Blob Storage immutability is configured at the container or blob level
 * via an **immutability policy** or **legal hold**.  This client writes block
 * blobs without setting any hold — configure the storage container's
 * immutability policy externally so that written objects cannot be deleted or
 * overwritten until the retention period expires.  This is equivalent to S3
 * Object Lock COMPLIANCE mode applied at the container level.
 */
export interface AzureBlobObjectStoreConfig {
  /**
   * Azure Storage container name (equivalent to an S3 "bucket" or GCS "bucket").
   */
  containerName: string;
  /**
   * Azure Storage connection string.
   *
   * Use `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;` format
   * for standard accounts, or `UseDevelopmentStorage=true` for Azurite.
   *
   * When provided, takes precedence over `accountName` + `accountKey`.
   */
  connectionString?: string;
  /**
   * Azure Storage account name.
   *
   * When provided without `accountKey`, `DefaultAzureCredential` from
   * `@azure/identity` is used for authentication (recommended for workload
   * identity deployments on AKS).
   *
   * When provided with `accountKey`, shared-key authentication is used.
   */
  accountName?: string;
  /**
   * Azure Storage shared key (base64-encoded).
   *
   * Only used when `accountName` is also provided and `connectionString` is
   * absent.  When omitted, `DefaultAzureCredential` is used.
   */
  accountKey?: string;
  /**
   * Optional custom endpoint URL.
   *
   * Use `http://127.0.0.1:10000/devstoreaccount1` for Azurite local testing.
   * When omitted the standard `https://<accountName>.blob.core.windows.net`
   * endpoint is used.
   */
  endpoint?: string;
}

/**
 * {@link ObjectStore} implementation backed by Azure Blob Storage.
 *
 * Uses `@azure/storage-blob` loaded **lazily** on the first {@link put} call
 * so that deployments not using Azure do not need the SDK installed.  A clear
 * `Error` is thrown if the SDK is absent when the first PUT is attempted.
 *
 * ### Immutability
 *
 * Configure the storage container's immutability policy (time-based retention
 * or legal hold) through the Azure portal or Bicep/ARM templates.  This client
 * writes standard block blobs — the container-level policy enforces write-once
 * behaviour automatically.
 */
export class AzureBlobObjectStore implements ObjectStore {
  private readonly config: AzureBlobObjectStoreConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private containerClient?: any;

  constructor(config: AzureBlobObjectStoreConfig) {
    this.config = config;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private buildContainerClient(): any {
    let sdk: {
      BlobServiceClient: {
        fromConnectionString(connStr: string): unknown;
        new (url: string, credential: unknown): unknown;
      };
      StorageSharedKeyCredential: new (accountName: string, accountKey: string) => unknown;
    };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@azure/storage-blob');
    } catch {
      throw new Error(
        'AzureBlobObjectStore: the "@azure/storage-blob" package is not installed. ' +
          'Add it to your deployment image: npm install @azure/storage-blob',
      );
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let serviceClient: any;

    if (this.config.connectionString) {
      serviceClient = sdk.BlobServiceClient.fromConnectionString(this.config.connectionString);
    } else if (this.config.accountName && this.config.accountKey) {
      const credential = new sdk.StorageSharedKeyCredential(
        this.config.accountName,
        this.config.accountKey,
      );
      const url =
        this.config.endpoint ??
        `https://${this.config.accountName}.blob.core.windows.net`;
      serviceClient = new sdk.BlobServiceClient(url, credential);
    } else if (this.config.accountName) {
      // DefaultAzureCredential — requires @azure/identity to be installed.
      let identitySdk: { DefaultAzureCredential: new () => unknown };
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        identitySdk = require('@azure/identity');
      } catch {
        throw new Error(
          'AzureBlobObjectStore: the "@azure/identity" package is not installed. ' +
            'Add it to your deployment image: npm install @azure/identity ' +
            '(required when using managed-identity / workload-identity authentication)',
        );
      }
      const credential = new identitySdk.DefaultAzureCredential();
      const url =
        this.config.endpoint ??
        `https://${this.config.accountName}.blob.core.windows.net`;
      serviceClient = new sdk.BlobServiceClient(url, credential);
    } else {
      throw new Error(
        'AzureBlobObjectStore: either connectionString or accountName must be provided.',
      );
    }

    return serviceClient.getContainerClient(this.config.containerName);
  }

  async put(key: string, data: string, contentType: string): Promise<void> {
    if (!this.containerClient) {
      this.containerClient = this.buildContainerClient();
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const blobClient = (this.containerClient as any).getBlockBlobClient(key);
    const buffer = Buffer.from(data, 'utf-8');
    await blobClient.upload(buffer, buffer.length, {
      blobHTTPHeaders: { blobContentType: contentType },
    });
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create an {@link ObjectStore} from environment variables.
 *
 * Reads `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` to select the provider:
 *
 * | Value          | Implementation         | Required env vars                                    |
 * |----------------|------------------------|------------------------------------------------------|
 * | `s3`           | {@link S3ObjectStore}  | `AUDIT_LEDGER_S3_BUCKET` (+ standard AWS vars)       |
 * | `gcs`          | {@link GcsObjectStore} | `AUDIT_LEDGER_GCS_BUCKET` (+ GCP credential vars)    |
 * | `azure-blob`   | {@link AzureBlobObjectStore} | `AUDIT_LEDGER_AZURE_CONTAINER` + auth vars      |
 *
 * Returns `undefined` when `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` is not set,
 * so callers can fall back to the legacy `s3?`/`gcs?` options.
 *
 * @param env - Environment variable map.  Defaults to `process.env`.
 */
export function createObjectStoreFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ObjectStore | undefined {
  const provider = env['AUDIT_LEDGER_OBJECT_STORE_PROVIDER'];
  if (!provider) return undefined;

  if (provider === 's3') {
    const bucket = env['AUDIT_LEDGER_S3_BUCKET'];
    if (!bucket) {
      throw new Error(
        'createObjectStoreFromEnv: AUDIT_LEDGER_OBJECT_STORE_PROVIDER=s3 ' +
          'requires AUDIT_LEDGER_S3_BUCKET to be set.',
      );
    }
    const client = new AwsSdkS3AnchorClient({
      region: env['AWS_REGION'],
      endpoint: env['AUDIT_LEDGER_S3_ENDPOINT'],
      forcePathStyle:
        env['AUDIT_LEDGER_S3_FORCE_PATH_STYLE'] === 'true' ||
        env['AUDIT_LEDGER_S3_FORCE_PATH_STYLE'] === '1',
      accessKeyId: env['AWS_ACCESS_KEY_ID'],
      secretAccessKey: env['AWS_SECRET_ACCESS_KEY'],
      sessionToken: env['AWS_SESSION_TOKEN'],
    });
    return new S3ObjectStore(client, bucket);
  }

  if (provider === 'gcs') {
    const bucket = env['AUDIT_LEDGER_GCS_BUCKET'];
    if (!bucket) {
      throw new Error(
        'createObjectStoreFromEnv: AUDIT_LEDGER_OBJECT_STORE_PROVIDER=gcs ' +
          'requires AUDIT_LEDGER_GCS_BUCKET to be set.',
      );
    }
    // GcsAnchorClientImpl lives in ledger-signer.ts; load it lazily to avoid
    // importing the entire ledger-signer module here.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { GcsAnchorClientImpl } = require('./ledger-signer') as {
      GcsAnchorClientImpl: new (cfg?: {
        keyFilePath?: string;
        projectId?: string;
        skipTemporaryHold?: boolean;
      }) => GcsAnchorClient;
    };
    const gcsClient = new GcsAnchorClientImpl({
      keyFilePath: env['GOOGLE_APPLICATION_CREDENTIALS'],
      projectId: env['GCLOUD_PROJECT'] ?? env['GOOGLE_CLOUD_PROJECT'],
      skipTemporaryHold: env['AUDIT_LEDGER_GCS_SKIP_HOLD'] === 'true',
    });
    return new GcsObjectStore(gcsClient, bucket);
  }

  if (provider === 'azure-blob') {
    const containerName = env['AUDIT_LEDGER_AZURE_CONTAINER'];
    if (!containerName) {
      throw new Error(
        'createObjectStoreFromEnv: AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob ' +
          'requires AUDIT_LEDGER_AZURE_CONTAINER to be set.',
      );
    }
    return new AzureBlobObjectStore({
      containerName,
      connectionString: env['AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING'],
      accountName: env['AUDIT_LEDGER_AZURE_ACCOUNT_NAME'],
      accountKey: env['AUDIT_LEDGER_AZURE_ACCOUNT_KEY'],
      endpoint: env['AUDIT_LEDGER_AZURE_ENDPOINT'],
    });
  }

  throw new Error(
    `createObjectStoreFromEnv: unknown AUDIT_LEDGER_OBJECT_STORE_PROVIDER value "${provider}". ` +
      'Valid values: "s3", "gcs", "azure-blob".',
  );
}

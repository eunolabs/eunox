/**
 * Integration tests for AzureBlobObjectStore against Azurite.
 *
 * Guard: `AZURITE_CONNECTION_STRING` env var must be set to the Azurite
 * connection string.  A typical local value uses the well-known Azurite
 * development credentials (accountName=devstoreaccount1, key=Eby8...) that
 * are publicly documented at
 * https://learn.microsoft.com/azure/storage/common/storage-use-azurite — they
 * are not real credentials and are safe to use in local development and CI.
 *
 * How to run locally:
 *   docker run --rm -d -p 10000:10000 \
 *     mcr.microsoft.com/azure-storage/azurite:latest \
 *     azurite-blob --blobHost 0.0.0.0
 *   AZURITE_CONNECTION_STRING="DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;" \
 *     npx jest --testPathPattern=azure-blob-object-store
 *
 * CI: started automatically by .github/workflows/test-cloud-adapters.yml
 */

import { randomUUID } from 'crypto';
import { AzureBlobObjectStore, createObjectStoreFromEnv } from '@euno/common-infra';

// ── Guard ─────────────────────────────────────────────────────────────────────

const AZURITE_CONNECTION_STRING = process.env['AZURITE_CONNECTION_STRING'];
const describeWithAzurite = AZURITE_CONNECTION_STRING ? describe : describe.skip;

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Create an Azure Blob container in Azurite using the SDK.
 */
async function createTestContainer(containerName: string): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { BlobServiceClient } = require('@azure/storage-blob');
  const serviceClient = BlobServiceClient.fromConnectionString(AZURITE_CONNECTION_STRING!);
  const containerClient = serviceClient.getContainerClient(containerName);
  await containerClient.createIfNotExists();
}

/**
 * Download a blob from Azurite and return its content as a UTF-8 string.
 */
async function getBlobBody(containerName: string, blobName: string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { BlobServiceClient } = require('@azure/storage-blob');
  const serviceClient = BlobServiceClient.fromConnectionString(AZURITE_CONNECTION_STRING!);
  const containerClient = serviceClient.getContainerClient(containerName);
  const blobClient = containerClient.getBlockBlobClient(blobName);
  const response = await blobClient.downloadToBuffer();
  return response.toString('utf8');
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describeWithAzurite('AzureBlobObjectStore — Azurite integration', () => {
  describe('AzureBlobObjectStore.put()', () => {
    const container = `euno-anchor-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestContainer(container);
    }, 20_000);

    it('writes a blob that is readable from Azurite', async () => {
      const store = new AzureBlobObjectStore({
        containerName: container,
        connectionString: AZURITE_CONNECTION_STRING!,
      });

      const key = `test-anchor/${randomUUID()}.json`;
      const body = JSON.stringify({ merkleRoot: 'abc123', event: 'test' });

      await store.put(key, body, 'application/json');

      const downloaded = await getBlobBody(container, key);
      expect(downloaded).toBe(body);
    }, 15_000);

    it('writes multiple blobs to the same container without conflict', async () => {
      const store = new AzureBlobObjectStore({
        containerName: container,
        connectionString: AZURITE_CONNECTION_STRING!,
      });

      const entries = [
        { key: `multi/${randomUUID()}.json`, body: '{"a":1}' },
        { key: `multi/${randomUUID()}.json`, body: '{"b":2}' },
        { key: `multi/${randomUUID()}.json`, body: '{"c":3}' },
      ];

      await Promise.all(entries.map(e => store.put(e.key, e.body, 'application/json')));

      for (const e of entries) {
        expect(await getBlobBody(container, e.key)).toBe(e.body);
      }
    }, 20_000);
  });

  describe('createObjectStoreFromEnv() with AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob', () => {
    const container = `euno-factory-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestContainer(container);
    }, 20_000);

    it('creates an AzureBlobObjectStore and writes a blob via the factory', async () => {
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'azure-blob',
        AUDIT_LEDGER_AZURE_CONTAINER: container,
        AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING: AZURITE_CONNECTION_STRING!,
      });

      expect(store).toBeDefined();

      const key = `factory-test/${randomUUID()}.json`;
      await store!.put(key, '{"factory":true}', 'application/json');

      const downloaded = await getBlobBody(container, key);
      expect(downloaded).toBe('{"factory":true}');
    }, 15_000);

    it('returns undefined when AUDIT_LEDGER_OBJECT_STORE_PROVIDER is absent', () => {
      expect(createObjectStoreFromEnv({})).toBeUndefined();
    });
  });
});

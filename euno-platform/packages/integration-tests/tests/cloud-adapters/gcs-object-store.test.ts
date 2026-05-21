/**
 * Integration tests for GcsObjectStore / GcsAnchorClientImpl against
 * fake-gcs-server.
 *
 * Guard: `FAKE_GCS_ENDPOINT` env var must be set to the HTTP endpoint of a
 * running fake-gcs-server instance (e.g. `http://localhost:4443`).
 * When absent the entire suite is skipped.
 *
 * The GCP Storage SDK reads the `STORAGE_EMULATOR_HOST` environment variable
 * automatically and redirects all calls to the specified host.  This test
 * sets it to `FAKE_GCS_ENDPOINT` (stripping the `http://` prefix if present)
 * before any SDK objects are constructed.
 *
 * How to run locally:
 *   docker run --rm -d -p 4443:4443 \
 *     fsouza/fake-gcs-server:latest -scheme http -port 4443
 *   FAKE_GCS_ENDPOINT=http://localhost:4443 \
 *     npx jest --testPathPattern=gcs-object-store
 *
 * CI: started automatically by .github/workflows/test-cloud-adapters.yml
 */

import { randomUUID } from 'crypto';
import type { GcsAnchorClientConfig } from '@euno/common-infra';

// ── Guard ─────────────────────────────────────────────────────────────────────

const FAKE_GCS_ENDPOINT = process.env['FAKE_GCS_ENDPOINT'];
const describeWithFakeGcs = FAKE_GCS_ENDPOINT ? describe : describe.skip;

// ── Emulator host wiring ──────────────────────────────────────────────────────

// The @google-cloud/storage SDK reads STORAGE_EMULATOR_HOST before constructing
// the Storage client.  We set it here so it's available when the lazy require
// inside GcsAnchorClientImpl runs.
if (FAKE_GCS_ENDPOINT) {
  // The SDK expects a host[:port] value (no scheme) when using the env var form.
  // Strip the http:// or https:// prefix if present.
  process.env['STORAGE_EMULATOR_HOST'] = FAKE_GCS_ENDPOINT.replace(/^https?:\/\//, '');
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Create a GCS bucket via the fake-gcs-server REST API.
 *
 * Uses the `@google-cloud/storage` SDK configured to talk to the emulator.
 */
async function createTestBucket(bucketName: string): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Storage } = require('@google-cloud/storage');
  const storage = new Storage({
    projectId: 'test-project',
    apiEndpoint: FAKE_GCS_ENDPOINT,
  });
  await storage.createBucket(bucketName);
}

/**
 * Download an object from the fake-gcs-server and return its body as a UTF-8
 * string.
 */
async function getObjectBody(bucketName: string, key: string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Storage } = require('@google-cloud/storage');
  const storage = new Storage({
    projectId: 'test-project',
    apiEndpoint: FAKE_GCS_ENDPOINT,
  });
  const [contents] = await storage.bucket(bucketName).file(key).download();
  return contents.toString('utf8');
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describeWithFakeGcs('GcsObjectStore — fake-gcs-server integration', () => {
  describe('GcsAnchorClientImpl.putObject()', () => {
    const bucket = `euno-anchor-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('writes an object that is readable from fake-gcs-server', async () => {
      const { GcsAnchorClientImpl } = await import('@euno/common-infra');

      const cfg: GcsAnchorClientConfig = { skipTemporaryHold: true, projectId: 'test-project' };
      const client = new GcsAnchorClientImpl(cfg);
      const key = `test-anchor/${randomUUID()}.json`;
      const body = JSON.stringify({ merkleRoot: 'abc123', event: 'test' });

      await client.putObject({ bucket, key, body, contentType: 'application/json' });

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe(body);
    }, 15_000);
  });

  describe('GcsObjectStore.put()', () => {
    const bucket = `euno-store-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('delegates to GcsAnchorClientImpl and writes a readable object', async () => {
      const { GcsAnchorClientImpl, GcsObjectStore } = await import('@euno/common-infra');

      const cfg: GcsAnchorClientConfig = { skipTemporaryHold: true, projectId: 'test-project' };
      const anchorClient = new GcsAnchorClientImpl(cfg);
      const store = new GcsObjectStore(anchorClient, bucket);

      const key = `audit-anchor/rep-1/${randomUUID()}.json`;
      const body = '{"merkleRoot":"deadbeef","sequence":42}';

      await store.put(key, body, 'application/json');

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe(body);
    }, 15_000);
  });

  describe('createObjectStoreFromEnv() with AUDIT_LEDGER_OBJECT_STORE_PROVIDER=gcs', () => {
    const bucket = `euno-factory-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('creates a GcsObjectStore and writes an object via the factory', async () => {
      const { createObjectStoreFromEnv } = await import('@euno/common-infra');

      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
        AUDIT_LEDGER_GCS_BUCKET: bucket,
        AUDIT_LEDGER_GCS_SKIP_HOLD: 'true',
        GCLOUD_PROJECT: 'test-project',
      });

      expect(store).toBeDefined();

      const key = `factory-test/${randomUUID()}.json`;
      await store!.put(key, '{"factory":true}', 'application/json');

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe('{"factory":true}');
    }, 20_000);

    it('returns undefined when AUDIT_LEDGER_OBJECT_STORE_PROVIDER is absent', async () => {
      const { createObjectStoreFromEnv } = await import('@euno/common-infra');
      expect(createObjectStoreFromEnv({})).toBeUndefined();
    });
  });
});

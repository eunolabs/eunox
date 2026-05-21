/**
 * Integration tests for S3ObjectStore / AwsSdkS3AnchorClient against LocalStack.
 *
 * Guard: `LOCALSTACK_ENDPOINT` env var must be set (e.g. `http://localhost:4566`).
 * When absent the entire suite is skipped so the standard `npm run test` in CI
 * continues to pass without requiring a running LocalStack instance.
 *
 * How to run locally:
 *   # Start LocalStack (S3 + Secrets Manager)
 *   docker run --rm -d -p 4566:4566 -e SERVICES=s3 localstack/localstack:latest
 *   # Run this suite
 *   LOCALSTACK_ENDPOINT=http://localhost:4566 npx jest --testPathPattern=aws-s3-object-store
 *
 * CI: started automatically by .github/workflows/test-cloud-adapters.yml
 */

import { randomUUID } from 'crypto';

// ── Guard — skip when LocalStack is unavailable ────────────────────────────────

const LOCALSTACK_ENDPOINT = process.env['LOCALSTACK_ENDPOINT'];
const describeWithLocalstack = LOCALSTACK_ENDPOINT ? describe : describe.skip;

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Shared AWS client config that points to LocalStack with static test credentials.
 * LocalStack accepts any non-empty key/secret and treats all requests as
 * authenticated.
 */
function localstackConfig() {
  return {
    region: 'us-east-1',
    endpoint: LOCALSTACK_ENDPOINT!,
    forcePathStyle: true,
    accessKeyId: 'test',
    secretAccessKey: 'test',
  };
}

/**
 * Creates an S3 bucket with Object Lock enabled and a 1-day COMPLIANCE
 * default retention so that `PutObject` with `ObjectLockMode: COMPLIANCE`
 * is accepted without needing an explicit retain-until date.
 */
async function createTestBucket(bucketName: string): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { S3Client, CreateBucketCommand, PutObjectLockConfigurationCommand } =
    require('@aws-sdk/client-s3');

  const cfg = localstackConfig();
  const s3 = new S3Client({
    region: cfg.region,
    endpoint: cfg.endpoint,
    forcePathStyle: cfg.forcePathStyle,
    credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
  });

  await s3.send(new CreateBucketCommand({
    Bucket: bucketName,
    ObjectLockEnabledForBucket: true,
  }));

  await s3.send(new PutObjectLockConfigurationCommand({
    Bucket: bucketName,
    ObjectLockConfiguration: {
      ObjectLockEnabled: 'Enabled',
      Rule: { DefaultRetention: { Mode: 'COMPLIANCE', Days: 1 } },
    },
  }));
}

/**
 * Downloads an object from LocalStack S3 and returns its body as a UTF-8
 * string for verification.
 */
async function getObjectBody(bucketName: string, key: string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');

  const cfg = localstackConfig();
  const s3 = new S3Client({
    region: cfg.region,
    endpoint: cfg.endpoint,
    forcePathStyle: cfg.forcePathStyle,
    credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const response: any = await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: key }));
  // The Body is a readable stream in Node.js; collect it.
  const chunks: Buffer[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for await (const chunk of response.Body as any) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describeWithLocalstack('S3ObjectStore — LocalStack integration', () => {
  // Each describe block uses an isolated bucket to prevent cross-test pollution.

  describe('AwsSdkS3AnchorClient.putObject()', () => {
    const bucket = `euno-anchor-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('writes an object that is readable from LocalStack', async () => {
      const { AwsSdkS3AnchorClient } = await import('@euno/common-infra');

      const client = new AwsSdkS3AnchorClient(localstackConfig());
      const key = `test-anchor/${randomUUID()}.json`;
      const body = JSON.stringify({ merkleRoot: 'abc123', event: 'test' });

      await client.putObject({ bucket, key, body, contentType: 'application/json' });

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe(body);
    }, 15_000);

    it('uses the correct Content-Type when writing the object', async () => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
      const { AwsSdkS3AnchorClient } = await import('@euno/common-infra');

      const client = new AwsSdkS3AnchorClient(localstackConfig());
      const key = `test-anchor/content-type-${randomUUID()}.json`;

      await client.putObject({
        bucket,
        key,
        body: '{"test":true}',
        contentType: 'application/json',
      });

      const cfg = localstackConfig();
      const s3 = new S3Client({
        region: cfg.region,
        endpoint: cfg.endpoint,
        forcePathStyle: cfg.forcePathStyle,
        credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resp: any = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      expect(resp.ContentType).toBe('application/json');
    }, 15_000);
  });

  describe('S3ObjectStore.put()', () => {
    const bucket = `euno-store-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('delegates to the underlying anchor client and writes a readable object', async () => {
      const { AwsSdkS3AnchorClient, S3ObjectStore } = await import('@euno/common-infra');

      const anchorClient = new AwsSdkS3AnchorClient(localstackConfig());
      const store = new S3ObjectStore(anchorClient, bucket);

      const key = `audit-anchor/rep-1/${randomUUID()}.json`;
      const body = '{"merkleRoot":"deadbeef","sequence":42}';

      await store.put(key, body, 'application/json');

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe(body);
    }, 15_000);
  });

  describe('createObjectStoreFromEnv() with AUDIT_LEDGER_OBJECT_STORE_PROVIDER=s3', () => {
    const bucket = `euno-factory-${randomUUID().slice(0, 8)}`;

    beforeAll(async () => {
      await createTestBucket(bucket);
    }, 20_000);

    it('creates an S3ObjectStore and writes an object via the factory', async () => {
      const { createObjectStoreFromEnv } = await import('@euno/common-infra');

      const cfg = localstackConfig();
      const store = createObjectStoreFromEnv({
        AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 's3',
        AUDIT_LEDGER_S3_BUCKET: bucket,
        AWS_REGION: cfg.region,
        AUDIT_LEDGER_S3_ENDPOINT: cfg.endpoint,
        AUDIT_LEDGER_S3_FORCE_PATH_STYLE: 'true',
        AWS_ACCESS_KEY_ID: cfg.accessKeyId,
        AWS_SECRET_ACCESS_KEY: cfg.secretAccessKey,
      });

      expect(store).toBeDefined();

      const key = `factory-test/${randomUUID()}.json`;
      await store!.put(key, '{"factory":true}', 'application/json');

      const downloaded = await getObjectBody(bucket, key);
      expect(downloaded).toBe('{"factory":true}');
    }, 15_000);

    it('returns undefined when AUDIT_LEDGER_OBJECT_STORE_PROVIDER is absent', async () => {
      const { createObjectStoreFromEnv } = await import('@euno/common-infra');
      expect(createObjectStoreFromEnv({})).toBeUndefined();
    });
  });
});

/**
 * Integration tests for AwsSecretsManagerSecretStore against LocalStack.
 *
 * Guard: `LOCALSTACK_ENDPOINT` env var must be set (e.g. `http://localhost:4566`).
 * When absent the entire suite is skipped.
 *
 * How to run locally:
 *   docker run --rm -d -p 4566:4566 \
 *     -e SERVICES=secretsmanager \
 *     localstack/localstack:latest
 *   LOCALSTACK_ENDPOINT=http://localhost:4566 \
 *     npx jest --testPathPattern=aws-secrets-adapter
 *
 * CI: started automatically by .github/workflows/test-cloud-adapters.yml
 */

import { randomUUID } from 'crypto';
import {
  AwsSecretsManagerSecretStore,
  createSecretStoreFromEnv,
} from '@euno/common-core';

// ── Guard ─────────────────────────────────────────────────────────────────────

const LOCALSTACK_ENDPOINT = process.env['LOCALSTACK_ENDPOINT'];
const describeWithLocalstack = LOCALSTACK_ENDPOINT ? describe : describe.skip;

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Static credentials accepted by LocalStack for any operation. */
const LOCALSTACK_CREDS = {
  region: 'us-east-1',
  accessKeyId: 'test',
  secretAccessKey: 'test',
};

/**
 * Create a Secrets Manager secret in LocalStack.
 * Returns the ARN of the created secret.
 */
async function createSecret(name: string, value: string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { SecretsManagerClient, CreateSecretCommand } = require('@aws-sdk/client-secrets-manager');
  const client = new SecretsManagerClient({
    region: LOCALSTACK_CREDS.region,
    endpoint: LOCALSTACK_ENDPOINT,
    credentials: LOCALSTACK_CREDS,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const resp: any = await client.send(
    new CreateSecretCommand({ Name: name, SecretString: value }),
  );
  return resp.ARN as string;
}

/** Build a LocalStack-pointing SecretsManagerClient and inject it into store. */
function injectLocalstackClient(store: AwsSecretsManagerSecretStore): void {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
  const customClient = new SecretsManagerClient({
    region: LOCALSTACK_CREDS.region,
    endpoint: LOCALSTACK_ENDPOINT,
    credentials: LOCALSTACK_CREDS,
  });
  (store as unknown as Record<string, unknown>)['client'] = customClient;
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describeWithLocalstack('AwsSecretsManagerSecretStore — LocalStack integration', () => {
  describe('getSecret() with ARN-based lookup', () => {
    it('returns the correct value for an existing secret', async () => {
      const secretName = `euno/test/${randomUUID()}`;
      const secretValue = `value-${randomUUID()}`;
      const arn = await createSecret(secretName, secretValue);

      const store = new AwsSecretsManagerSecretStore({
        region: LOCALSTACK_CREDS.region,
        accessKeyId: LOCALSTACK_CREDS.accessKeyId,
        secretAccessKey: LOCALSTACK_CREDS.secretAccessKey,
        arnsBySecretName: { MY_SECRET: arn },
      });
      injectLocalstackClient(store);

      const result = await store.getSecret('MY_SECRET');
      expect(result).toBe(secretValue);
    }, 15_000);

    it('returns undefined for a secret that does not exist', async () => {
      const store = new AwsSecretsManagerSecretStore({
        region: LOCALSTACK_CREDS.region,
        arnsBySecretName: {
          MISSING: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:euno/missing-xyz',
        },
      });
      injectLocalstackClient(store);

      const result = await store.getSecret('MISSING');
      expect(result).toBeUndefined();
    }, 15_000);

    it('uses the ARN as SecretId and fetches the correct value', async () => {
      const secretName = `euno/hmac/${randomUUID()}`;
      const hmacValue = `hmac-secret-${randomUUID()}`;
      const arn = await createSecret(secretName, hmacValue);

      const store = new AwsSecretsManagerSecretStore({
        region: LOCALSTACK_CREDS.region,
        arnsBySecretName: { AUDIT_LEDGER_HMAC_SECRET: arn },
      });
      injectLocalstackClient(store);

      expect(await store.getSecret('AUDIT_LEDGER_HMAC_SECRET')).toBe(hmacValue);
    }, 15_000);

    it('caches the fetched value and only calls Secrets Manager once', async () => {
      const secretName = `euno/cache/${randomUUID()}`;
      const value = `cached-${randomUUID()}`;
      const arn = await createSecret(secretName, value);

      const store = new AwsSecretsManagerSecretStore({
        region: LOCALSTACK_CREDS.region,
        arnsBySecretName: { CACHED_SECRET: arn },
      });

      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
      const customClient = new SecretsManagerClient({
        region: LOCALSTACK_CREDS.region,
        endpoint: LOCALSTACK_ENDPOINT,
        credentials: LOCALSTACK_CREDS,
      });
      let sendCallCount = 0;
      const originalSend = customClient.send.bind(customClient);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      customClient.send = async (cmd: any) => {
        sendCallCount++;
        return originalSend(cmd);
      };
      (store as unknown as Record<string, unknown>)['client'] = customClient;

      await store.getSecret('CACHED_SECRET');
      await store.getSecret('CACHED_SECRET'); // second call — should hit cache
      expect(sendCallCount).toBe(1);
    }, 15_000);
  });

  describe('getSecret() env fallback (no ARN configured)', () => {
    it('returns the value from the fallback env map when no ARN is configured', async () => {
      const store = new AwsSecretsManagerSecretStore({
        arnsBySecretName: {},
        fallbackEnv: { MY_ENV_SECRET: 'env-only-value' },
      });
      expect(await store.getSecret('MY_ENV_SECRET')).toBe('env-only-value');
    });

    it('returns undefined from the fallback env for a missing key', async () => {
      const store = new AwsSecretsManagerSecretStore({
        arnsBySecretName: {},
        fallbackEnv: {},
      });
      expect(await store.getSecret('NONEXISTENT')).toBeUndefined();
    });
  });

  describe('createSecretStoreFromEnv() wiring', () => {
    it('creates an AwsSecretsManagerSecretStore from env vars and fetches a secret', async () => {
      const secretName = `euno/factory/${randomUUID()}`;
      const secretValue = `factory-val-${randomUUID()}`;
      const arn = await createSecret(secretName, secretValue);

      const store = createSecretStoreFromEnv({
        SECRET_STORE_PROVIDER: 'aws-secretsmanager',
        AWS_REGION: LOCALSTACK_CREDS.region,
        AWS_ACCESS_KEY_ID: LOCALSTACK_CREDS.accessKeyId,
        AWS_SECRET_ACCESS_KEY: LOCALSTACK_CREDS.secretAccessKey,
        [`AWS_SECRETS_ARN_FACTORY_SECRET`]: arn,
      });

      expect(store).toBeInstanceOf(AwsSecretsManagerSecretStore);
      injectLocalstackClient(store as AwsSecretsManagerSecretStore);

      expect(await store.getSecret('FACTORY_SECRET')).toBe(secretValue);
    }, 20_000);
  });
});

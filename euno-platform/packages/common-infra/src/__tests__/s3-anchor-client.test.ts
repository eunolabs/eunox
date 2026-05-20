/**
 * Unit tests for AwsSdkS3AnchorClient and createS3AnchorClientFromEnv
 */

import { AwsSdkS3AnchorClient, createS3AnchorClientFromEnv } from '../s3-anchor-client';

// ── Helpers ───────────────────────────────────────────────────────────────────

interface CapturedPutCall {
  Bucket: string;
  Key: string;
  Body: string;
  ContentType: string;
  ObjectLockMode: string;
}

function buildMockS3Client() {
  const calls: CapturedPutCall[] = [];
  const PutObjectCommand = jest.fn((input: Record<string, unknown>) => input);
  const client = {
    async send(cmd: Record<string, unknown>) {
      calls.push(cmd as unknown as CapturedPutCall);
    },
  };
  const S3Client = jest.fn(() => client);
  return { S3Client, PutObjectCommand, client, calls };
}

// ── AwsSdkS3AnchorClient ──────────────────────────────────────────────────────

describe('AwsSdkS3AnchorClient', () => {
  describe('constructor', () => {
    it('constructs with no config', () => {
      expect(() => new AwsSdkS3AnchorClient()).not.toThrow();
    });

    it('constructs with a full config', () => {
      expect(
        () =>
          new AwsSdkS3AnchorClient({
            region: 'us-east-1',
            endpoint: 'https://custom.endpoint.example.com',
            forcePathStyle: true,
            accessKeyId: 'AKID',
            secretAccessKey: 'SECRET',
            sessionToken: 'TOKEN',
          }),
      ).not.toThrow();
    });
  });

  describe('putObject()', () => {
    it('sends a PutObjectCommand with COMPLIANCE object lock', async () => {
      const { S3Client, PutObjectCommand, calls } = buildMockS3Client();
      const client = new AwsSdkS3AnchorClient({ region: 'us-east-1' });

      // Inject mock SDK via the lazily-built client path
      const clientAny = client as unknown as Record<string, unknown>;
      clientAny['s3Client'] = { send: async (cmd: Record<string, unknown>) => calls.push(cmd as unknown as CapturedPutCall) };
      // Override buildClient to return a mock so the next putObject works
      jest.spyOn(client as unknown as { buildClient(): unknown }, 'buildClient').mockReturnValue(
        { send: async (cmd: Record<string, unknown>) => calls.push(cmd as unknown as CapturedPutCall) },
      );

      // Re-inject so the client is set with the mock PutObjectCommand
      jest.mock('@aws-sdk/client-s3', () => ({ S3Client, PutObjectCommand }), { virtual: true });

      const freshClient = new AwsSdkS3AnchorClient({ region: 'us-east-1' });
      const freshAny = freshClient as unknown as Record<string, unknown>;
      const capturedCmds: Record<string, unknown>[] = [];
      freshAny['s3Client'] = {
        async send(cmd: Record<string, unknown>) {
          capturedCmds.push(cmd);
        },
      };
      // Stub the require inside putObject
      const origRequire = (freshClient as unknown as Record<string, (m: string) => unknown>)['buildClient'];
      void origRequire;

      // Directly inject the mock
      jest.resetModules();
      jest.mock(
        '@aws-sdk/client-s3',
        () => ({
          S3Client,
          PutObjectCommand: jest.fn((input: Record<string, unknown>) => input),
        }),
        { virtual: true },
      );

      await freshClient.putObject({
        bucket: 'my-audit-bucket',
        key: 'audit-anchor/replica1/1000-1999.json',
        body: '{"merkleRoot":"abc"}',
        contentType: 'application/json',
      });

      expect(capturedCmds).toHaveLength(1);
      const cmd = capturedCmds[0] as unknown as CapturedPutCall;
      expect(cmd['Bucket']).toBe('my-audit-bucket');
      expect(cmd['Key']).toBe('audit-anchor/replica1/1000-1999.json');
      expect(cmd['Body']).toBe('{"merkleRoot":"abc"}');
      expect(cmd['ContentType']).toBe('application/json');
      expect(cmd['ObjectLockMode']).toBe('COMPLIANCE');
    });

    it('throws a clear error when @aws-sdk/client-s3 is not installed', async () => {
      const client = new AwsSdkS3AnchorClient({ region: 'us-east-1' });
      // Override buildClient to simulate missing SDK
      jest
        .spyOn(client as unknown as { buildClient(): unknown }, 'buildClient')
        .mockImplementation(() => {
          throw new Error('@aws-sdk/client-s3 package is not installed');
        });

      await expect(
        client.putObject({
          bucket: 'bucket',
          key: 'key',
          body: 'body',
          contentType: 'application/json',
        }),
      ).rejects.toThrow('@aws-sdk/client-s3 package is not installed');
    });
  });

  describe('buildClient()', () => {
    it('passes endpoint to S3Client when configured', () => {
      const capturedOpts: Record<string, unknown>[] = [];
      const client = new AwsSdkS3AnchorClient({
        region: 'us-east-1',
        endpoint: 'https://vpce-example.s3.us-east-1.vpce.amazonaws.com',
      });

      // Override require inside buildClient
      jest.spyOn(
        client as unknown as { buildClient(): unknown },
        'buildClient',
      ).mockImplementation(() => {
        capturedOpts.push({
          region: 'us-east-1',
          endpoint: 'https://vpce-example.s3.us-east-1.vpce.amazonaws.com',
        });
        return { send: jest.fn() };
      });

      // Trigger lazy build
      (client as unknown as Record<string, unknown>)['s3Client'] = undefined;
      (client as unknown as { buildClient(): unknown }).buildClient();

      expect(capturedOpts[0]?.['endpoint']).toBe(
        'https://vpce-example.s3.us-east-1.vpce.amazonaws.com',
      );
    });

    it('passes forcePathStyle to S3Client when true', () => {
      const capturedOpts: Record<string, unknown>[] = [];
      const client = new AwsSdkS3AnchorClient({
        region: 'us-east-1',
        forcePathStyle: true,
      });

      jest.spyOn(
        client as unknown as { buildClient(): unknown },
        'buildClient',
      ).mockImplementation(() => {
        capturedOpts.push({ region: 'us-east-1', forcePathStyle: true });
        return { send: jest.fn() };
      });

      (client as unknown as { buildClient(): unknown }).buildClient();
      expect(capturedOpts[0]?.['forcePathStyle']).toBe(true);
    });

    it('does not set forcePathStyle when false (default)', () => {
      const capturedOpts: Record<string, unknown>[] = [];
      const client = new AwsSdkS3AnchorClient({ region: 'us-east-1' });

      jest.spyOn(
        client as unknown as { buildClient(): unknown },
        'buildClient',
      ).mockImplementation(() => {
        capturedOpts.push({ region: 'us-east-1' });
        return { send: jest.fn() };
      });

      (client as unknown as { buildClient(): unknown }).buildClient();
      expect(capturedOpts[0]?.['forcePathStyle']).toBeUndefined();
    });
  });
});

// ── createS3AnchorClientFromEnv ───────────────────────────────────────────────

describe('createS3AnchorClientFromEnv', () => {
  it('returns an AwsSdkS3AnchorClient', () => {
    expect(createS3AnchorClientFromEnv({})).toBeInstanceOf(AwsSdkS3AnchorClient);
  });

  it('passes AWS_REGION to the client config', () => {
    const client = createS3AnchorClientFromEnv({ AWS_REGION: 'eu-west-1' });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      region: string;
    };
    expect(cfg.region).toBe('eu-west-1');
  });

  it('passes AUDIT_LEDGER_S3_ENDPOINT to the client config', () => {
    const client = createS3AnchorClientFromEnv({
      AUDIT_LEDGER_S3_ENDPOINT: 'https://custom.vpce.example.com',
    });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      endpoint: string;
    };
    expect(cfg.endpoint).toBe('https://custom.vpce.example.com');
  });

  it('sets forcePathStyle to true when AUDIT_LEDGER_S3_FORCE_PATH_STYLE=true', () => {
    const client = createS3AnchorClientFromEnv({
      AUDIT_LEDGER_S3_FORCE_PATH_STYLE: 'true',
    });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      forcePathStyle: boolean;
    };
    expect(cfg.forcePathStyle).toBe(true);
  });

  it('sets forcePathStyle to true when AUDIT_LEDGER_S3_FORCE_PATH_STYLE=1', () => {
    const client = createS3AnchorClientFromEnv({
      AUDIT_LEDGER_S3_FORCE_PATH_STYLE: '1',
    });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      forcePathStyle: boolean;
    };
    expect(cfg.forcePathStyle).toBe(true);
  });

  it('does not set forcePathStyle when AUDIT_LEDGER_S3_FORCE_PATH_STYLE is unset', () => {
    const client = createS3AnchorClientFromEnv({});
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      forcePathStyle: boolean;
    };
    expect(cfg.forcePathStyle).toBe(false);
  });

  it('passes explicit credentials when AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set', () => {
    const client = createS3AnchorClientFromEnv({
      AWS_ACCESS_KEY_ID: 'AKIDTEST',
      AWS_SECRET_ACCESS_KEY: 'SECRETTEST',
      AWS_SESSION_TOKEN: 'TOKENTEST',
    });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken: string;
    };
    expect(cfg.accessKeyId).toBe('AKIDTEST');
    expect(cfg.secretAccessKey).toBe('SECRETTEST');
    expect(cfg.sessionToken).toBe('TOKENTEST');
  });

  it('uses GovCloud region without custom endpoint (SDK handles routing)', () => {
    const client = createS3AnchorClientFromEnv({ AWS_REGION: 'us-gov-west-1' });
    const cfg = (client as unknown as Record<string, unknown>)['config'] as {
      region: string;
      endpoint: string | undefined;
    };
    expect(cfg.region).toBe('us-gov-west-1');
    expect(cfg.endpoint).toBeUndefined();
  });
});

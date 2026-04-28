/**
 * Unit tests for the per-cloud storage-grant minters and the
 * StorageGrantService dispatcher. Each provider's SDK is replaced with
 * a stub via the constructor's factory hooks (the dynamic-import path
 * is exercised separately by the integration tests in `issuer.test.ts`).
 *
 * Behaviors covered:
 *  - Action → permission mapping for all four legacy actions.
 *  - TTL capping at the operator and hard-ceiling maximums.
 *  - Wildcard vs. single-object branch selection per cloud.
 *  - Service-level: feature flag off → no-op; mint failure aborts; only
 *    canonical URIs trigger minting (non-canonical produces a warn-log
 *    skip, not a mint).
 */

import {
  StorageGrantService,
  AzureStorageGrantMinter,
  AwsStorageGrantMinter,
  GcpStorageGrantMinter,
  STORAGE_GRANT_HARD_MAX_TTL_SECONDS,
} from '../src/storage-grant';
import { CapabilityError, CapabilityConstraint } from '@euno/common';

const ctx = { agentId: 'agent-1', authorizedBy: 'user-1', capabilityTtlSeconds: 600 };

describe('StorageGrantService — disabled by default', () => {
  it('returns undefined when not enabled', async () => {
    const svc = new StorageGrantService();
    expect(svc.isEnabled()).toBe(false);
    expect(
      await svc.mintForCapabilities(
        [{ resource: 'storage://azure/sales/foo.csv', actions: ['read'] }],
        ctx,
      ),
    ).toBeUndefined();
  });

  it('isEnabled is false even when enabled=true if no minters registered', () => {
    const svc = new StorageGrantService({ enabled: true });
    expect(svc.isEnabled()).toBe(false);
  });
});

describe('AzureStorageGrantMinter', () => {
  const fakeClient = {
    accountName: 'salesdata',
    getUserDelegationKey: jest.fn(async () => ({ value: 'fake-key' })),
  };
  const signer = jest.fn(({ permissions, blobName, containerName, expiresOn }) => ({
    sasToken: `sig-${permissions}`,
    url: `https://${containerName}/${blobName ?? ''}?${expiresOn.toISOString()}`,
  }));

  beforeEach(() => {
    fakeClient.getUserDelegationKey.mockClear();
    signer.mockClear();
  });

  it('mints a single-object SAS with rwd permissions', async () => {
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => fakeClient,
      signer,
    });
    const grant = await minter.mint({
      resource: 'storage://azure/salesdata/reports/q1.csv',
      actions: ['read', 'write', 'delete'],
      ttlSeconds: 600,
      agentId: 'a',
      authorizedBy: 'u',
    });
    expect(grant.provider).toBe('azure-blob');
    expect(grant.actions).toEqual(['read', 'write', 'delete']);
    expect(signer).toHaveBeenCalledTimes(1);
    const arg = signer.mock.calls[0]![0] as { permissions: string; blobName?: string };
    // Letters sorted alphabetically.
    expect(arg.permissions).toBe('drw');
    expect(arg.blobName).toBe('q1.csv');
    expect(grant.azureSas?.sasToken).toBe('sig-drw');
  });

  it('mints a container-scoped SAS for a wildcard URI (no blobName)', async () => {
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => fakeClient,
      signer,
    });
    await minter.mint({
      resource: 'storage://azure/salesdata/reports/**',
      actions: ['read'],
      ttlSeconds: 60,
      agentId: 'a',
      authorizedBy: 'u',
    });
    const arg = signer.mock.calls[0]![0] as { blobName?: string; permissions: string };
    expect(arg.blobName).toBeUndefined();
    expect(arg.permissions).toBe('r');
  });

  it('rejects a resource the parser does not recognize', async () => {
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => fakeClient,
      signer,
    });
    await expect(
      minter.mint({
        resource: 'storage://aws/bucket/key',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
      }),
    ).rejects.toBeInstanceOf(CapabilityError);
  });

  it('rejects an Azure URI that lacks a container path', async () => {
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => fakeClient,
      signer,
    });
    await expect(
      minter.mint({
        resource: 'storage://azure/salesdata/**',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
      }),
    ).rejects.toBeInstanceOf(CapabilityError);
  });
});

describe('AwsStorageGrantMinter', () => {
  it('mints presigned URLs for a single-object capability — one per method', async () => {
    const presigner = jest.fn(async ({ method, bucket, key }) => `https://${bucket}/${key}#${method}`);
    const minter = new AwsStorageGrantMinter({ presigner });
    const grant = await minter.mint({
      resource: 'storage://aws/uploads/incoming/a.json',
      actions: ['read', 'write'],
      ttlSeconds: 300,
      agentId: 'a',
      authorizedBy: 'u',
    });
    expect(grant.s3Presigned).toEqual([
      { method: 'GET', url: 'https://uploads/incoming/a.json#GET' },
      { method: 'PUT', url: 'https://uploads/incoming/a.json#PUT' },
    ]);
    expect(grant.s3Session).toBeUndefined();
  });

  it('mints session credentials with a scope-down policy for a wildcard capability', async () => {
    const stsClient = {
      send: jest.fn(async ({ input }) => {
        // Assert the scope-down policy targets only the requested prefix.
        expect(typeof input.Policy).toBe('string');
        const policy = JSON.parse(input.Policy as string);
        expect(policy.Statement[0].Resource).toBe('arn:aws:s3:::uploads/incoming/*');
        expect(input.RoleArn).toBe('arn:aws:iam::123:role/euno-grant');
        return {
          Credentials: {
            AccessKeyId: 'AKID',
            SecretAccessKey: 'SK',
            SessionToken: 'STK',
            Expiration: new Date(Date.now() + 600_000),
          },
        };
      }),
    };
    const minter = new AwsStorageGrantMinter({
      region: 'us-east-1',
      assumeRoleArn: 'arn:aws:iam::123:role/euno-grant',
      stsClientFactory: () => stsClient,
    });
    const grant = await minter.mint({
      resource: 'storage://aws/uploads/incoming/**',
      actions: ['read', 'write'],
      ttlSeconds: 600,
      agentId: 'agent-1',
      authorizedBy: 'u',
    });
    expect(grant.s3Session).toMatchObject({
      accessKeyId: 'AKID',
      secretAccessKey: 'SK',
      sessionToken: 'STK',
      region: 'us-east-1',
      bucket: 'uploads',
      prefix: 'incoming',
    });
    expect(grant.s3Presigned).toBeUndefined();
  });

  it('refuses wildcard mint without assumeRoleArn and region', async () => {
    const minter = new AwsStorageGrantMinter({});
    await expect(
      minter.mint({
        resource: 'storage://aws/uploads/incoming/**',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
      }),
    ).rejects.toBeInstanceOf(CapabilityError);
  });
});

describe('GcpStorageGrantMinter', () => {
  it('mints signed URLs for a single-object capability — one per method', async () => {
    const file = {
      getSignedUrl: jest.fn(async ({ action }) => [`https://gcs/x?act=${action}`] as [string]),
    };
    const bucket = { file: jest.fn(() => file) };
    const client = { bucket: jest.fn(() => bucket) };
    const minter = new GcpStorageGrantMinter({ storageClientFactory: () => client });
    const grant = await minter.mint({
      resource: 'storage://gcp/euno-models/v3/checkpoint.pt',
      actions: ['read', 'write', 'delete'],
      ttlSeconds: 60,
      agentId: 'a',
      authorizedBy: 'u',
    });
    expect(grant.gcsSigned).toEqual([
      { method: 'GET', url: 'https://gcs/x?act=read' },
      { method: 'PUT', url: 'https://gcs/x?act=write' },
      { method: 'DELETE', url: 'https://gcs/x?act=delete' },
    ]);
    expect(client.bucket).toHaveBeenCalledWith('euno-models');
    expect(bucket.file).toHaveBeenCalledWith('v3/checkpoint.pt');
  });

  it('mints downscoped credentials for a wildcard capability', async () => {
    const minter = new GcpStorageGrantMinter({
      downscopedTokenSource: {
        mint: async ({ bucket, prefix }) => ({
          token: `tok:${bucket}:${prefix}`,
          expiresAt: new Date('2030-01-01T00:00:00Z'),
        }),
      },
    });
    const grant = await minter.mint({
      resource: 'storage://gcp/euno-models/v3/**',
      actions: ['read'],
      ttlSeconds: 60,
      agentId: 'a',
      authorizedBy: 'u',
    });
    expect(grant.gcsDownscoped).toMatchObject({
      accessToken: 'tok:euno-models:v3',
      bucket: 'euno-models',
      prefix: 'v3',
    });
    expect(grant.expiresAt).toBe('2030-01-01T00:00:00.000Z');
  });
});

describe('StorageGrantService — dispatch and TTL capping', () => {
  function buildService(maxTtlSeconds = 900): StorageGrantService {
    return new StorageGrantService({
      enabled: true,
      maxTtlSeconds,
      minters: {
        'azure-blob': {
          provider: 'azure-blob',
          mint: async (input) => ({
            provider: 'azure-blob',
            resource: input.resource,
            actions: [...input.actions],
            expiresAt: new Date(Date.now() + input.ttlSeconds * 1000).toISOString(),
            azureSas: { url: 'https://x?', sasToken: 'sig' },
          }),
        },
      },
    });
  }

  it('dispatches only to canonical storage URIs', async () => {
    const svc = buildService();
    const caps: CapabilityConstraint[] = [
      { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
      { resource: 'api://crm/customers', actions: ['read'] },
      { resource: 'storage://*', actions: ['read'] }, // non-canonical
    ];
    const grants = await svc.mintForCapabilities(caps, ctx);
    expect(grants).toHaveLength(1);
    expect(grants?.[0]?.resource).toBe('storage://azure/sales/foo.csv');
  });

  it('returns undefined when no eligible storage capabilities are present', async () => {
    const svc = buildService();
    expect(
      await svc.mintForCapabilities([{ resource: 'api://crm/customers', actions: ['read'] }], ctx),
    ).toBeUndefined();
  });

  it('caps TTL at the operator-configured maximum', async () => {
    const minter = jest.fn(async (input) => ({
      provider: 'azure-blob' as const,
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: new Date(Date.now() + input.ttlSeconds * 1000).toISOString(),
      azureSas: { url: 'x', sasToken: 'y' },
    }));
    const svc = new StorageGrantService({
      enabled: true,
      maxTtlSeconds: 60,
      minters: { 'azure-blob': { provider: 'azure-blob', mint: minter } },
    });
    await svc.mintForCapabilities(
      [{ resource: 'storage://azure/sales/foo.csv', actions: ['read'] }],
      { ...ctx, capabilityTtlSeconds: 9999 },
    );
    expect(minter).toHaveBeenCalledWith(
      expect.objectContaining({ ttlSeconds: 60 }),
    );
  });

  it('caps configured TTL at the hard 1h ceiling', () => {
    const svc = new StorageGrantService({
      enabled: true,
      maxTtlSeconds: 99999,
      minters: { 'azure-blob': { provider: 'azure-blob', mint: jest.fn() } },
    });
    // Reach into the private field via JSON to avoid touching encapsulation
    // in production code; this is a pure assertion about config behavior.
    expect((svc as unknown as { maxTtlSeconds: number }).maxTtlSeconds).toBe(
      STORAGE_GRANT_HARD_MAX_TTL_SECONDS,
    );
  });

  it('aborts the entire issuance when a single mint fails', async () => {
    const svc = new StorageGrantService({
      enabled: true,
      minters: {
        'azure-blob': {
          provider: 'azure-blob',
          mint: async () => {
            throw new Error('cloud unavailable');
          },
        },
      },
    });
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'storage://azure/sales/foo.csv', actions: ['read'] }],
        ctx,
      ),
    ).rejects.toBeInstanceOf(CapabilityError);
  });

  it('throws when no minter is registered for a requested cloud', async () => {
    const svc = new StorageGrantService({
      enabled: true,
      minters: {
        'azure-blob': { provider: 'azure-blob', mint: jest.fn() },
      },
    });
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'storage://aws/bucket/key', actions: ['read'] }],
        ctx,
      ),
    ).rejects.toThrow(/No storage-grant minter registered/);
  });
});

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
import { buildRoleSessionName } from '../src/storage-grant/aws';
import { mapActionsToGcsRoles, escapeCelStringLiteral } from '../src/storage-grant/gcp';
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

  it('refuses a wildcard with a sub-prefix beyond the container', async () => {
    // A user-delegation SAS cannot scope to a sub-prefix; minting one
    // would silently grant the entire container. Fail closed.
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => fakeClient,
      signer,
    });
    await expect(
      minter.mint({
        resource: 'storage://azure/salesdata/reports/2026/**',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
      }),
    ).rejects.toThrow(/sub-prefix/);
    expect(signer).not.toHaveBeenCalled();
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
        // Only the IAM actions that map to the requested capability
        // actions appear — read+write maps to GetObject+PutObject only,
        // never DeleteObject.
        expect(policy.Statement[0].Action).toEqual(['s3:GetObject', 's3:PutObject']);
        // No `list` capability action → no ListBucket statement.
        expect(policy.Statement).toHaveLength(1);
        expect(input.RoleArn).toBe('arn:aws:iam::123:role/euno-grant');
        // RoleSessionName fits STS character + length constraints.
        expect(typeof input.RoleSessionName).toBe('string');
        expect((input.RoleSessionName as string).length).toBeLessThanOrEqual(64);
        expect(input.RoleSessionName as string).toMatch(/^[a-zA-Z0-9_=,.@-]+$/);
        return {
          Credentials: {
            AccessKeyId: 'AKID',
            SecretAccessKey: 'SK',
            SessionToken: 'STK',
            Expiration: new Date(Date.now() + 900_000),
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
      // 900s is the STS AssumeRole minimum session duration; anything
      // shorter is rejected by `mintSession` before STS is contacted.
      ttlSeconds: 900,
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

  it('refuses wildcard mint when ttl is below the STS 900s minimum', async () => {
    const stsClient = { send: jest.fn(async () => ({ Credentials: {} })) };
    const minter = new AwsStorageGrantMinter({
      region: 'us-east-1',
      assumeRoleArn: 'arn:aws:iam::123:role/euno-grant',
      stsClientFactory: () => stsClient,
    });
    await expect(
      minter.mint({
        resource: 'storage://aws/uploads/incoming/**',
        actions: ['read'],
        ttlSeconds: 600,
        agentId: 'a',
        authorizedBy: 'u',
      }),
    ).rejects.toThrow(/minimum session duration/);
    // STS must NOT have been called for a sub-minimum request.
    expect(stsClient.send).not.toHaveBeenCalled();
  });

  it('builds the scope-down policy from the requested actions only (read-only stays read-only)', async () => {
    const stsClient = {
      send: jest.fn(async ({ input }) => {
        const policy = JSON.parse(input.Policy as string);
        // Only s3:GetObject is allowed for a `read`-only capability —
        // PutObject and DeleteObject must not appear in the policy.
        expect(policy.Statement[0].Action).toEqual(['s3:GetObject']);
        return {
          Credentials: {
            AccessKeyId: 'A', SecretAccessKey: 'S', SessionToken: 'T',
            Expiration: new Date(Date.now() + 900_000),
          },
        };
      }),
    };
    const minter = new AwsStorageGrantMinter({
      region: 'us-east-1',
      assumeRoleArn: 'arn:aws:iam::123:role/euno-grant',
      stsClientFactory: () => stsClient,
    });
    await minter.mint({
      resource: 'storage://aws/uploads/incoming/**',
      actions: ['read'],
      ttlSeconds: 900,
      agentId: 'a',
      authorizedBy: 'u',
    });
    expect(stsClient.send).toHaveBeenCalledTimes(1);
  });

  it('includes ListBucket only when the capability includes the list action', async () => {
    const stsClient = {
      send: jest.fn(async ({ input }) => {
        const policy = JSON.parse(input.Policy as string);
        expect(policy.Statement).toHaveLength(2);
        expect(policy.Statement[1].Action).toBe('s3:ListBucket');
        expect(policy.Statement[1].Condition.StringLike['s3:prefix']).toEqual(['incoming/*']);
        return {
          Credentials: {
            AccessKeyId: 'A', SecretAccessKey: 'S', SessionToken: 'T',
            Expiration: new Date(Date.now() + 900_000),
          },
        };
      }),
    };
    const minter = new AwsStorageGrantMinter({
      region: 'us-east-1',
      assumeRoleArn: 'arn:aws:iam::123:role/euno-grant',
      stsClientFactory: () => stsClient,
    });
    await minter.mint({
      resource: 'storage://aws/uploads/incoming/**',
      actions: ['read', 'list'],
      ttlSeconds: 900,
      agentId: 'a',
      authorizedBy: 'u',
    });
  });

  it('sanitizes a DID-style agentId into a valid STS RoleSessionName', async () => {
    let captured = '';
    const stsClient = {
      send: jest.fn(async ({ input }) => {
        captured = input.RoleSessionName as string;
        return {
          Credentials: {
            AccessKeyId: 'A', SecretAccessKey: 'S', SessionToken: 'T',
            Expiration: new Date(Date.now() + 900_000),
          },
        };
      }),
    };
    const minter = new AwsStorageGrantMinter({
      region: 'us-east-1',
      assumeRoleArn: 'arn:aws:iam::123:role/euno-grant',
      stsClientFactory: () => stsClient,
    });
    await minter.mint({
      resource: 'storage://aws/uploads/incoming/**',
      actions: ['read'],
      ttlSeconds: 900,
      // DIDs contain `:` which STS does NOT permit in RoleSessionName.
      agentId: 'did:web:agent.example.com:special-very-long-identifier-' +
        'that-would-otherwise-overflow-the-64-char-limit-easily',
      authorizedBy: 'u',
    });
    // Sanitized: only allowed chars, length within the AWS-imposed cap.
    expect(captured).toMatch(/^[a-zA-Z0-9_=,.@-]+$/);
    expect(captured.length).toBeLessThanOrEqual(64);
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

  it('forwards capability actions to the downscoped-token source', async () => {
    let seenActions: string[] | undefined;
    const minter = new GcpStorageGrantMinter({
      downscopedTokenSource: {
        mint: async ({ actions }) => {
          seenActions = actions;
          return { token: 't', expiresAt: new Date(Date.now() + 60_000) };
        },
      },
    });
    await minter.mint({
      resource: 'storage://gcp/euno-models/v3/**',
      actions: ['read', 'write'],
      ttlSeconds: 60,
      agentId: 'a',
      authorizedBy: 'u',
    });
    // The minter must propagate actions so the CAB scope can match them.
    expect(seenActions).toEqual(['read', 'write']);
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

describe('aws helpers', () => {
  it('buildRoleSessionName sanitizes disallowed characters and respects the 64-char STS cap', () => {
    // DIDs include `:` and `/` which STS does not permit.
    const did = 'did:web:euno.example.com:agent-name';
    const name = buildRoleSessionName(did, 1_700_000_000_000);
    expect(name).toMatch(/^[a-zA-Z0-9_=,.@-]+$/);
    expect(name.length).toBeLessThanOrEqual(64);
    // Two calls with the same agent + ts produce the same name (stable).
    expect(buildRoleSessionName(did, 1_700_000_000_000)).toBe(name);
  });

  it('buildRoleSessionName hashes very long agent IDs to fit', () => {
    const longId = 'x'.repeat(500);
    const name = buildRoleSessionName(longId, 1_700_000_000_000);
    expect(name.length).toBeLessThanOrEqual(64);
    expect(name).toMatch(/^[a-zA-Z0-9_=,.@-]+$/);
  });

  it('buildRoleSessionName handles an empty agent ID without producing an STS-invalid name', () => {
    const name = buildRoleSessionName('', 1_700_000_000_000);
    // Must not be empty and must not contain the literal `--` produced
    // by an empty middle segment.
    expect(name.length).toBeGreaterThan(2);
    expect(name).toMatch(/^euno-[a-f0-9]{16}-\d+$/);
  });
});

describe('gcp helpers', () => {
  it('mapActionsToGcsRoles emits objectViewer for read-only and adds objectAdmin only for mutations', () => {
    expect(mapActionsToGcsRoles(['read'])).toEqual(['inRole:roles/storage.objectViewer']);
    expect(mapActionsToGcsRoles(['read', 'list'])).toEqual([
      'inRole:roles/storage.objectViewer',
    ]);
    expect(mapActionsToGcsRoles(['read', 'write'])).toEqual([
      'inRole:roles/storage.objectViewer',
      'inRole:roles/storage.objectAdmin',
    ]);
    expect(mapActionsToGcsRoles(['delete'])).toEqual(['inRole:roles/storage.objectAdmin']);
    // Unknown action contributes no role rather than silently broadening.
    expect(mapActionsToGcsRoles(['nonsense'])).toEqual([]);
  });

  it('escapeCelStringLiteral escapes backslashes and single quotes used in CEL string literals', () => {
    // Without escaping, a `'` would close the literal early and allow
    // the rest of the prefix to be treated as CEL — this is a CEL
    // injection vector via crafted GCS prefixes.
    expect(escapeCelStringLiteral("a'b")).toBe("a\\'b");
    expect(escapeCelStringLiteral('a\\b')).toBe('a\\\\b');
    // Newlines/tabs are escaped to keep the condition single-line.
    expect(escapeCelStringLiteral('a\nb')).toBe('a\\nb');
    // Plain content passes through unchanged.
    expect(escapeCelStringLiteral('plain/prefix-1')).toBe('plain/prefix-1');
  });
});

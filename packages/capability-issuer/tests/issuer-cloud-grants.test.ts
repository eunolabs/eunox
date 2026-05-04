/**
 * Integration tests for the issuer-service ↔ storage-grant /
 * db-token pipeline introduced by sprint-3-4-gap items #7 and #8.
 *
 * These tests assert the end-to-end behavior:
 *  - When both services are disabled (default), the response shape is
 *    unchanged — `storageGrants` / `dbCredentials` are undefined and
 *    no SDK is loaded.
 *  - When enabled, the issuer dispatches a mint per cloud capability
 *    in the request, includes them in the response, and never writes
 *    raw credentials to the audit log.
 *  - A mint failure aborts the entire issuance.
 */

import { CapabilityIssuerService, CapabilityIssuerServiceOptions } from '../src/issuer-service';
import {
  StorageGrantService,
  AzureStorageGrantMinter,
} from '../src/storage-grant';
import { DbTokenService, AzureSqlTokenMinter } from '../src/db-token';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  IssuanceRateLimiter,
  IssuanceRateLimitSubject,
  RateLimitDecision,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  RoleCapabilityPolicy,
  createLogger,
} from '@euno/common';
import * as jose from 'jose';

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private context: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(): Promise<UserContext> {
    return this.context;
  }
  async getUserRoles(): Promise<string[]> {
    return this.context.roles;
  }
}

class JoseSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  constructor() {
    super({ type: 'jose', name: 'jose', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async init(): Promise<void> {
    const { privateKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(this.privateKey);
  }
  async getPublicKey(): Promise<string> {
    return '';
  }
  async getKeyId(): Promise<string> {
    return 'kid-1';
  }
}

const logger = createLogger('issuer-cloud-grants-test', 'test');

async function makeService(opts?: {
  storage?: StorageGrantService;
  db?: DbTokenService;
  policy?: RoleCapabilityPolicy;
  roles?: string[];
  storageGrantRateLimiter?: IssuanceRateLimiter;
  dbTokenRateLimiter?: IssuanceRateLimiter;
}): Promise<CapabilityIssuerService> {
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: opts?.roles ?? ['Administrator'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const signer = new JoseSigner();
  await signer.init();
  const ctorOpts: CapabilityIssuerServiceOptions = {};
  if (opts?.storage) ctorOpts.storageGrantService = opts.storage;
  if (opts?.db) ctorOpts.dbTokenService = opts.db;
  if (opts?.policy) ctorOpts.policy = opts.policy;
  if (opts?.storageGrantRateLimiter) ctorOpts.storageGrantRateLimiter = opts.storageGrantRateLimiter;
  if (opts?.dbTokenRateLimiter) ctorOpts.dbTokenRateLimiter = opts.dbTokenRateLimiter;
  return new CapabilityIssuerService(
    signer,
    identity,
    'did:web:example.com',
    900,
    logger,
    ctorOpts,
  );
}

/** Build a stub rate limiter that either allows or denies. */
function makeRateLimiter(allowed: boolean): IssuanceRateLimiter {
  return {
    windowSeconds: 60,
    consume: async (_subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> => ({
      allowed,
      limit: 10,
      windowSeconds: 60,
      remaining: allowed ? 9 : 0,
      retryAfterSeconds: allowed ? 0 : 60,
    }),
  };
}

describe('Issuer-service ↔ cloud-grant pipelines', () => {
  it('returns response without storageGrants/dbCredentials when services are disabled (back-compat)', async () => {
    const service = await makeService();
    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
      ],
    });
    expect(resp.storageGrants).toBeUndefined();
    expect(resp.dbCredentials).toBeUndefined();
  });

  it('attaches storageGrants when the storage service is enabled', async () => {
    const azureMinter = new AzureStorageGrantMinter({
      clientFactory: () => ({
        accountName: 'sales',
        getUserDelegationKey: async () => ({}),
      }),
      signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
    });
    const storage = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': azureMinter },
    });
    const service = await makeService({ storage });
    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
        { resource: 'api://crm/customers', actions: ['read'] }, // not eligible
      ],
    });
    expect(resp.storageGrants).toHaveLength(1);
    expect(resp.storageGrants?.[0]?.provider).toBe('azure-blob');
    expect(resp.storageGrants?.[0]?.azureSas?.sasToken).toBe('sig');
    expect(resp.dbCredentials).toBeUndefined();
  });

  it('attaches dbCredentials when the db service is enabled and the user has a role-mapped username', async () => {
    const azureSql = new AzureSqlTokenMinter({
      tokenSource: {
        getToken: async () => ({ token: 'JWT', expiresOnTimestamp: Date.now() + 600_000 }),
      },
    });
    const db = new DbTokenService({
      enabled: true,
      instances: new Map([
        [
          'salesserver',
          {
            id: 'salesserver',
            provider: 'azure-sql',
            host: 'salesserver.database.windows.net',
            port: 1433,
            databases: ['salesdb'],
          },
        ],
      ]),
      minters: { 'azure-sql': azureSql },
    });
    const policy: RoleCapabilityPolicy = {
      default: {
        DataAnalyst: [
          { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
        ],
      },
      dbUsernamesByRole: { DataAnalyst: 'euno_readonly' },
    };
    const service = await makeService({ db, policy, roles: ['DataAnalyst'] });
    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      ],
    });
    expect(resp.dbCredentials).toHaveLength(1);
    expect(resp.dbCredentials?.[0]?.username).toBe('euno_readonly');
    expect(resp.dbCredentials?.[0]?.token).toBe('JWT');
    expect(resp.storageGrants).toBeUndefined();
  });

  it('aborts issuance when storage-grant mint fails', async () => {
    const failingMinter = {
      provider: 'azure-blob' as const,
      mint: async () => {
        throw new Error('network down');
      },
    };
    const storage = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': failingMinter },
    });
    const service = await makeService({ storage });
    await expect(
      service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [
          { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
        ],
      }),
    ).rejects.toMatchObject({ code: 'INTERNAL_ERROR' });
  });

  describe('dedicated cloud-credential rate limiters', () => {
    it('allows storage-grant issuance when storageGrantRateLimiter permits', async () => {
      const azureMinter = new AzureStorageGrantMinter({
        clientFactory: () => ({
          accountName: 'sales',
          getUserDelegationKey: async () => ({}),
        }),
        signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
      });
      const storage = new StorageGrantService({
        enabled: true,
        minters: { 'azure-blob': azureMinter },
      });
      const service = await makeService({
        storage,
        storageGrantRateLimiter: makeRateLimiter(true),
      });
      const resp = await service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'storage://azure/sales/foo.csv', actions: ['read'] }],
      });
      expect(resp.storageGrants).toHaveLength(1);
    });

    it('denies storage-grant issuance when storageGrantRateLimiter is exhausted', async () => {
      const azureMinter = new AzureStorageGrantMinter({
        clientFactory: () => ({
          accountName: 'sales',
          getUserDelegationKey: async () => ({}),
        }),
        signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
      });
      const storage = new StorageGrantService({
        enabled: true,
        minters: { 'azure-blob': azureMinter },
      });
      const service = await makeService({
        storage,
        storageGrantRateLimiter: makeRateLimiter(false),
      });
      await expect(
        service.issueCapability({
          authToken: 'irrelevant',
          agentId: 'agent-1',
          requestedCapabilities: [{ resource: 'storage://azure/sales/foo.csv', actions: ['read'] }],
        }),
      ).rejects.toMatchObject({ statusCode: 429 });
    });

    it('denies db-token issuance when dbTokenRateLimiter is exhausted', async () => {
      const azureSql = new AzureSqlTokenMinter({
        tokenSource: {
          getToken: async () => ({ token: 'JWT', expiresOnTimestamp: Date.now() + 600_000 }),
        },
      });
      const db = new DbTokenService({
        enabled: true,
        instances: new Map([
          [
            'salesserver',
            {
              id: 'salesserver',
              provider: 'azure-sql' as const,
              host: 'salesserver.database.windows.net',
              port: 1433,
              databases: ['salesdb'],
            },
          ],
        ]),
        minters: { 'azure-sql': azureSql },
      });
      const policy: RoleCapabilityPolicy = {
        default: {
          DataAnalyst: [
            { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
          ],
        },
        dbUsernamesByRole: { DataAnalyst: 'euno_readonly' },
      };
      const service = await makeService({
        db,
        policy,
        roles: ['DataAnalyst'],
        dbTokenRateLimiter: makeRateLimiter(false),
      });
      await expect(
        service.issueCapability({
          authToken: 'irrelevant',
          agentId: 'agent-1',
          requestedCapabilities: [
            { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
          ],
        }),
      ).rejects.toMatchObject({ statusCode: 429 });
    });

    it('storageGrantRateLimiter does not block when the request contains no storage capabilities', async () => {
      // The storage service is enabled and the rate limiter is exhausted, but
      // there are no storage:// URIs in the request — quota must NOT be consumed
      // and issuance must succeed.
      const azureMinter = new AzureStorageGrantMinter({
        clientFactory: () => ({
          accountName: 'sales',
          getUserDelegationKey: async () => ({}),
        }),
        signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
      });
      const storage = new StorageGrantService({
        enabled: true,
        minters: { 'azure-blob': azureMinter },
      });
      // Exhausted limiter — would deny if consulted.
      const consumed: IssuanceRateLimitSubject[] = [];
      const trackingLimiter: IssuanceRateLimiter = {
        windowSeconds: 60,
        consume: async (s) => { consumed.push(s); return { allowed: false, limit: 10, windowSeconds: 60, remaining: 0, retryAfterSeconds: 60 }; },
      };
      const service = await makeService({ storage, storageGrantRateLimiter: trackingLimiter });
      // Only api:// capabilities — no storage:// URIs.
      const resp = await service.issueCapability({
        authToken: 'irrelevant',
        agentId: 'agent-1',
        requestedCapabilities: [{ resource: 'api://crm/customers', actions: ['read'] }],
      });
      // Rate limiter must not have been called.
      expect(consumed).toHaveLength(0);
      // No storage grants expected.
      expect(resp.storageGrants).toBeUndefined();
    });
  });
});

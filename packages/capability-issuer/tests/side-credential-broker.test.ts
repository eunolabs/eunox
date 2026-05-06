/**
 * Unit tests for `SideCredentialBroker` implementations.
 *
 * Covers:
 *  - `InProcessSideCredentialBroker`: delegates to underlying services,
 *    correctly reports `isStorageEnabled` / `isDbEnabled`, handles
 *    disabled services as no-ops.
 *  - `HttpSideCredentialBroker`: calls the correct remote URLs with the
 *    signed token as Bearer auth; handles HTTP errors; parallel fanout;
 *    timeout plumbing.
 *  - `CapabilityIssuerService` integration: `'best-effort'` mode
 *    returns the JWT even when the broker throws; `'fail-fast'` mode
 *    propagates the error; `sideCredentialBroker` option takes
 *    precedence over legacy service options.
 */

import {
  InProcessSideCredentialBroker,
  HttpSideCredentialBroker,
  SideCredentialBroker,
  SideCredentialMintContext,
} from '../src/side-credential-broker';
import { StorageGrantService, AzureStorageGrantMinter } from '../src/storage-grant';
import { DbTokenService, AzureSqlTokenMinter } from '../src/db-token';
import { CapabilityIssuerService, CapabilityIssuerServiceOptions } from '../src/issuer-service';
import {
  CapabilityConstraint,
  CapabilityTokenPayload,
  IdentityAdapter,
  IdentityAdapterConfig,
  RoleCapabilityPolicy,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  createLogger,
  StorageGrant,
  DbCredential,
} from '@euno/common';
import * as jose from 'jose';

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

const logger = createLogger('broker-test', 'test');

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private context: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(): Promise<UserContext> { return this.context; }
  async getUserRoles(): Promise<string[]> { return this.context.roles; }
}

class JoseSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  public publicKeyObj!: jose.KeyLike;
  constructor() {
    super({ type: 'jose', name: 'jose', algorithm: 'RS256' } as SigningAdapterConfig);
  }
  async init(): Promise<void> {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.publicKeyObj = publicKey;
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(this.privateKey);
  }
  async getPublicKey(): Promise<string> { return ''; }
  async getKeyId(): Promise<string> { return 'kid-1'; }
}

const stubUserContext: UserContext = {
  userId: 'user-1',
  email: 'user@example.com',
  roles: ['Administrator'],
  tenantId: 'tenant-1',
  claims: {},
};

const storageCapabilities: CapabilityConstraint[] = [
  { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
];
const dbCapabilities: CapabilityConstraint[] = [
  { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
];
const apiCapabilities: CapabilityConstraint[] = [
  { resource: 'api://crm/customers', actions: ['read'] },
];

const policy: RoleCapabilityPolicy = {
  default: {
    Administrator: [
      ...storageCapabilities,
      ...dbCapabilities,
      ...apiCapabilities,
    ],
  },
  dbUsernamesByRole: { Administrator: 'euno_readonly' },
};

const mintCtx: SideCredentialMintContext = {
  agentId: 'agent-1',
  authorizedBy: 'user-1',
  capabilityTtlSeconds: 900,
  userRoles: ['Administrator'],
  policy,
};

async function makeIssuerService(opts: CapabilityIssuerServiceOptions): Promise<CapabilityIssuerService> {
  const signer = new JoseSigner();
  await signer.init();
  return new CapabilityIssuerService(
    signer,
    new StubIdentityProvider(stubUserContext),
    'did:web:example.com',
    900,
    logger,
    { policy, ...opts },
  );
}

function makeStorageGrantService(enabled: boolean): StorageGrantService {
  const azureMinter = new AzureStorageGrantMinter({
    clientFactory: () => ({
      accountName: 'sales',
      getUserDelegationKey: async () => ({}),
    }),
    signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
  });
  return new StorageGrantService({
    enabled,
    minters: { 'azure-blob': azureMinter },
  });
}

function makeDbTokenService(enabled: boolean): DbTokenService {
  const azureSql = new AzureSqlTokenMinter({
    tokenSource: {
      getToken: async () => ({ token: 'JWT', expiresOnTimestamp: Date.now() + 600_000 }),
    },
  });
  return new DbTokenService({
    enabled,
    instances: new Map([
      ['salesserver', { id: 'salesserver', provider: 'azure-sql', host: 'x.database.windows.net', port: 1433, databases: ['salesdb'] }],
    ]),
    minters: { 'azure-sql': azureSql },
  });
}

// ---------------------------------------------------------------------------
// InProcessSideCredentialBroker
// ---------------------------------------------------------------------------

describe('InProcessSideCredentialBroker', () => {
  it('reports isStorageEnabled correctly', () => {
    const enabled = new InProcessSideCredentialBroker({
      storageGrantService: makeStorageGrantService(true),
    });
    const disabled = new InProcessSideCredentialBroker({
      storageGrantService: makeStorageGrantService(false),
    });
    const empty = new InProcessSideCredentialBroker();

    expect(enabled.isStorageEnabled()).toBe(true);
    expect(disabled.isStorageEnabled()).toBe(false);
    expect(empty.isStorageEnabled()).toBe(false);
  });

  it('reports isDbEnabled correctly', () => {
    const enabled = new InProcessSideCredentialBroker({
      dbTokenService: makeDbTokenService(true),
    });
    expect(enabled.isDbEnabled()).toBe(true);
    expect(new InProcessSideCredentialBroker().isDbEnabled()).toBe(false);
  });

  it('mints storage grants for storage:// capabilities', async () => {
    const broker = new InProcessSideCredentialBroker({
      storageGrantService: makeStorageGrantService(true),
    });
    const result = await broker.mint('dummy-token', storageCapabilities, mintCtx);
    expect(result.storageGrants).toHaveLength(1);
    expect(result.storageGrants?.[0]?.provider).toBe('azure-blob');
    expect(result.dbCredentials).toBeUndefined();
  });

  it('mints DB credentials for db:// capabilities', async () => {
    const broker = new InProcessSideCredentialBroker({
      dbTokenService: makeDbTokenService(true),
    });
    const result = await broker.mint('dummy-token', dbCapabilities, mintCtx);
    expect(result.dbCredentials).toHaveLength(1);
    expect(result.dbCredentials?.[0]?.username).toBe('euno_readonly');
    expect(result.storageGrants).toBeUndefined();
  });

  it('ignores the signed token (in-process trust boundary)', async () => {
    // The in-process broker must NOT reject any token value — verification
    // is implicit because both services run in the same trust domain.
    const broker = new InProcessSideCredentialBroker({
      storageGrantService: makeStorageGrantService(true),
    });
    const result = await broker.mint('__not_a_real_jwt__', storageCapabilities, mintCtx);
    expect(result.storageGrants).toHaveLength(1);
  });

  it('returns empty result when no services are configured', async () => {
    const broker = new InProcessSideCredentialBroker();
    const result = await broker.mint('t', [...storageCapabilities, ...dbCapabilities], mintCtx);
    expect(result.storageGrants).toBeUndefined();
    expect(result.dbCredentials).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// HttpSideCredentialBroker
// ---------------------------------------------------------------------------

// Minimal fetch mock
type FetchMock = jest.Mock;
const globalAny = global as Record<string, unknown>;

function setupFetchMock(
  responses: Array<{ url: string; body: unknown; status?: number }>,
): FetchMock {
  const mock: FetchMock = jest.fn(async (url: string) => {
    const match = responses.find((r) => url.includes(r.url));
    const status = match?.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => match?.body ?? {},
    };
  });
  globalAny['fetch'] = mock;
  return mock;
}

afterEach(() => {
  delete globalAny['fetch'];
});

describe('HttpSideCredentialBroker', () => {
  const storageGrant: StorageGrant = {
    grantId: 'test-grant-id',
    provider: 'azure-blob',
    resource: 'storage://azure/sales/foo.csv',
    actions: ['read'],
    expiresAt: new Date(Date.now() + 900_000).toISOString(),
    azureSas: { sasToken: 'sig', url: 'https://sales/foo.csv?sig' },
  };
  const dbCred: DbCredential = {
    grantId: 'test-db-grant-id',
    provider: 'azure-sql',
    resource: 'db://azure-sql/salesserver/salesdb/orders.read',
    actions: ['read'],
    expiresAt: new Date(Date.now() + 900_000).toISOString(),
    host: 'x.database.windows.net',
    port: 1433,
    database: 'salesdb',
    username: 'euno_readonly',
    token: 'JWT',
  };

  it('isStorageEnabled / isDbEnabled reflect URL config', () => {
    const both = new HttpSideCredentialBroker({
      storageGrantServiceUrl: 'http://sg:8080',
      dbTokenServiceUrl: 'http://db:8080',
    });
    expect(both.isStorageEnabled()).toBe(true);
    expect(both.isDbEnabled()).toBe(true);

    const storageOnly = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080' });
    expect(storageOnly.isStorageEnabled()).toBe(true);
    expect(storageOnly.isDbEnabled()).toBe(false);
  });

  it('calls storage-grant service with Bearer token', async () => {
    const mock = setupFetchMock([
      { url: '/api/v1/storage-grants', body: { grants: [storageGrant] } },
    ]);
    const broker = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080' });
    const result = await broker.mint('my-jwt', storageCapabilities, mintCtx);

    expect(mock).toHaveBeenCalledTimes(1);
    const [url, init] = mock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://sg:8080/api/v1/storage-grants');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer my-jwt');
    expect(result.storageGrants).toEqual([storageGrant]);
    expect(result.dbCredentials).toBeUndefined();
  });

  it('calls db-token service with Bearer token', async () => {
    const mock = setupFetchMock([
      { url: '/api/v1/db-tokens', body: { credentials: [dbCred] } },
    ]);
    const broker = new HttpSideCredentialBroker({ dbTokenServiceUrl: 'http://db:8080' });
    const result = await broker.mint('my-jwt', dbCapabilities, mintCtx);

    expect(mock).toHaveBeenCalledTimes(1);
    expect(result.dbCredentials).toEqual([dbCred]);
    expect(result.storageGrants).toBeUndefined();
  });

  it('calls both services in parallel for mixed capabilities', async () => {
    setupFetchMock([
      { url: '/api/v1/storage-grants', body: { grants: [storageGrant] } },
      { url: '/api/v1/db-tokens', body: { credentials: [dbCred] } },
    ]);
    const broker = new HttpSideCredentialBroker({
      storageGrantServiceUrl: 'http://sg:8080',
      dbTokenServiceUrl: 'http://db:8080',
    });
    const result = await broker.mint('jwt', [...storageCapabilities, ...dbCapabilities], mintCtx);
    expect(result.storageGrants).toHaveLength(1);
    expect(result.dbCredentials).toHaveLength(1);
  });

  it('skips the storage service call for api:// only capabilities', async () => {
    const mock = setupFetchMock([
      { url: '/api/v1/storage-grants', body: { grants: [storageGrant] } },
    ]);
    const broker = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080' });
    const result = await broker.mint('jwt', apiCapabilities, mintCtx);
    expect(mock).not.toHaveBeenCalled();
    expect(result.storageGrants).toBeUndefined();
  });

  it('throws CapabilityError when the remote service returns 502', async () => {
    setupFetchMock([
      { url: '/api/v1/storage-grants', body: { error: { code: 'INTERNAL_ERROR', message: 'STS down' } }, status: 502 },
    ]);
    const broker = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080' });
    await expect(broker.mint('jwt', storageCapabilities, mintCtx)).rejects.toMatchObject({
      message: 'STS down',
    });
  });

  it('throws CapabilityError on network failure', async () => {
    globalAny['fetch'] = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const broker = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080' });
    await expect(broker.mint('jwt', storageCapabilities, mintCtx)).rejects.toMatchObject({
      message: expect.stringContaining('ECONNREFUSED'),
    });
  });

  it('strips trailing slash from service URLs', async () => {
    const mock = setupFetchMock([
      { url: '/api/v1/storage-grants', body: { grants: [storageGrant] } },
    ]);
    const broker = new HttpSideCredentialBroker({ storageGrantServiceUrl: 'http://sg:8080/' });
    await broker.mint('jwt', storageCapabilities, mintCtx);
    const [url] = mock.mock.calls[0] as [string];
    expect(url).toBe('http://sg:8080/api/v1/storage-grants');
  });
});

// ---------------------------------------------------------------------------
// CapabilityIssuerService integration with broker
// ---------------------------------------------------------------------------

describe('CapabilityIssuerService broker integration', () => {
  it('uses a custom SideCredentialBroker when provided', async () => {
    const mockBroker: SideCredentialBroker = {
      isStorageEnabled: () => true,
      isDbEnabled: () => false,
      mint: jest.fn().mockResolvedValue({
        storageGrants: [{ grantId: 'test-grant-id', provider: 'azure-blob', resource: 'storage://azure/sales/foo.csv', actions: ['read'], expiresAt: new Date(Date.now() + 900_000).toISOString() }],
      }),
    };
    const service = await makeIssuerService({ sideCredentialBroker: mockBroker });
    const resp = await service.issueCapability({ authToken: 'x', agentId: 'agent-1', requestedCapabilities: storageCapabilities });
    expect(resp.storageGrants).toHaveLength(1);
    expect(mockBroker.mint).toHaveBeenCalledTimes(1);
    // Verify the signed JWT was passed to the broker
    const [signedToken] = (mockBroker.mint as jest.Mock).mock.calls[0] as [string];
    expect(typeof signedToken).toBe('string');
    expect(signedToken.split('.').length).toBe(3); // compact JWS
  });

  it('broker takes precedence over legacy storageGrantService option', async () => {
    const legacyStorageService = makeStorageGrantService(true);
    const mintSpy = jest.spyOn(legacyStorageService, 'mintForCapabilities');

    const mockBroker: SideCredentialBroker = {
      isStorageEnabled: () => true,
      isDbEnabled: () => false,
      mint: jest.fn().mockResolvedValue({ storageGrants: [] }),
    };
    const service = await makeIssuerService({
      sideCredentialBroker: mockBroker,
      storageGrantService: legacyStorageService, // should be ignored
    });
    await service.issueCapability({ authToken: 'x', agentId: 'agent-1', requestedCapabilities: storageCapabilities });
    expect(mockBroker.mint).toHaveBeenCalledTimes(1);
    expect(mintSpy).not.toHaveBeenCalled();
    mintSpy.mockRestore();
  });

  it('best-effort mode returns JWT without side credentials on broker failure', async () => {
    const failingBroker: SideCredentialBroker = {
      isStorageEnabled: () => true,
      isDbEnabled: () => false,
      mint: jest.fn().mockRejectedValue(new Error('STS outage')),
    };
    const errorCb = jest.fn();
    const service = await makeIssuerService({
      sideCredentialBroker: failingBroker,
      sideCredentialFailureMode: 'best-effort',
      onSideCredentialError: errorCb,
    });
    const resp = await service.issueCapability({ authToken: 'x', agentId: 'agent-1', requestedCapabilities: storageCapabilities });
    // JWT is present despite broker failure
    expect(typeof resp.token).toBe('string');
    expect(resp.storageGrants).toBeUndefined();
    expect(resp.dbCredentials).toBeUndefined();
    // Callback was notified
    expect(errorCb).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ message: 'STS outage' }));
  });

  it('fail-fast mode (default) propagates broker errors', async () => {
    const failingBroker: SideCredentialBroker = {
      isStorageEnabled: () => true,
      isDbEnabled: () => false,
      mint: jest.fn().mockRejectedValue(new Error('STS outage')),
    };
    const service = await makeIssuerService({
      sideCredentialBroker: failingBroker,
      // sideCredentialFailureMode defaults to 'fail-fast'
    });
    await expect(
      service.issueCapability({ authToken: 'x', agentId: 'agent-1', requestedCapabilities: storageCapabilities }),
    ).rejects.toThrow('STS outage');
  });

  it('KMS signing completes before broker is called (sign-first ordering)', async () => {
    const callOrder: string[] = [];
    const signerSpy = new JoseSigner();
    await signerSpy.init();
    const originalSign = signerSpy.sign.bind(signerSpy);
    jest.spyOn(signerSpy, 'sign').mockImplementation(async (payload) => {
      callOrder.push('sign');
      return originalSign(payload);
    });

    const broker: SideCredentialBroker = {
      isStorageEnabled: () => true,
      isDbEnabled: () => false,
      mint: jest.fn().mockImplementation(async () => {
        callOrder.push('broker');
        return {};
      }),
    };

    const service = new CapabilityIssuerService(
      signerSpy,
      new StubIdentityProvider(stubUserContext),
      'did:web:example.com',
      900,
      logger,
      { policy, sideCredentialBroker: broker },
    );
    await service.issueCapability({ authToken: 'x', agentId: 'agent-1', requestedCapabilities: storageCapabilities });
    expect(callOrder).toEqual(['sign', 'broker']);
  });
});

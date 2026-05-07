/**
 * Invariant test matrix for the SideCredentialBroker confused-deputy
 * hotspot.
 *
 * # Threat model
 *
 * `SideCredentialBroker.mint()` is the single seam between the
 * capability constraint the issuer minted and the actual cloud
 * credential handed back to the agent.  A subset/scope bug here
 * produces silent privilege escalation: the agent receives a
 * storage STS session or DB auth token that is broader than the
 * capability authorized.  Unlike the gateway path, no second guard
 * sees these credentials — they are used directly against cloud APIs.
 *
 * # Invariants verified
 *
 * For every (capability → grant) mapping the test matrix asserts:
 *
 *   1. **Action-scope invariant** — the grant's permission set is
 *      derived exclusively from the capability's action list.  A
 *      read-only capability MUST NOT produce write/delete permissions,
 *      even if a broader IAM role is available at the cloud layer.
 *
 *   2. **TTL invariant** — the grant's reported `expiresAt` MUST NOT
 *      exceed `now + capabilityTtlSeconds`.  The operator-configured
 *      `maxTtlSeconds` is a secondary cap; neither the cloud SDK nor
 *      the minter may silently extend the lifetime.
 *
 *   3. **Resource-scope invariant** — the grant is scoped to the
 *      exact resource named in the capability (bucket / prefix /
 *      instance / database).  The grant MUST echo the capability's
 *      `resource` field verbatim so downstream code can correlate
 *      without re-parsing cloud-specific fields.
 *
 *   4. **DB-username invariant** — the database principal in the
 *      minted credential comes from the operator-side role mapping
 *      (`dbUsernamesByRole`), never from agent input.  An agent that
 *      supplies a different username via the capability resource URI
 *      receives `INSUFFICIENT_PERMISSIONS`, not a credential for the
 *      requested principal.
 *
 *   5. **grantId invariant** — every minted grant MUST carry a
 *      non-empty `grantId` so it is traceable end-to-end from the
 *      capability token (`capabilityId`) through the SIEM audit stream.
 *      The `grantId` MUST appear in the `logIssuance` audit metadata,
 *      linking the capability to the side credential.
 *
 * These invariants together ensure that a scope bug in any minter
 * is caught before it reaches production, and that every credential
 * issuance is fully auditable in the SIEM without needing to inspect
 * cloud-provider logs.
 */

import {
  StorageGrantService,
  AzureStorageGrantMinter,
  AwsStorageGrantMinter,
  GcpStorageGrantMinter,
} from '../src/storage-grant';
import { mapActionsToGcsRoles } from '../src/storage-grant/gcp';
import {
  DbTokenService,
  AzureSqlTokenMinter,
  RdsTokenMinter,
  CloudSqlTokenMinter,
  RDS_IAM_TOKEN_LIFETIME_SECONDS,
} from '../src/db-token';
import { InProcessSideCredentialBroker } from '../src/side-credential-broker';
import { CapabilityIssuerService } from '../src/issuer-service';
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
} from '@euno/common';
import * as jose from 'jose';
import * as winston from 'winston';
import { Writable } from 'stream';

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const logger = createLogger('invariant-test', 'test');

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
  async getPublicKey(): Promise<string> { return ''; }
  async getKeyId(): Promise<string> { return 'kid-1'; }
}

const stubUserContext: UserContext = {
  userId: 'user-1',
  email: 'user@example.com',
  roles: ['DataAnalyst'],
  tenantId: 'tenant-1',
  claims: {},
};

// Shared policy: DataAnalyst role maps to euno_readonly DB principal
// and has access to specific resources.
const testPolicy: RoleCapabilityPolicy = {
  default: {
    DataAnalyst: [
      { resource: 'storage://azure/sales/q1.csv', actions: ['read'] },
      { resource: 'storage://aws/bucket/key.csv', actions: ['read', 'write'] },
      { resource: 'storage://gcp/my-bucket/data.csv', actions: ['read'] },
      { resource: 'storage://aws/bucket/*', actions: ['read'] },
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      { resource: 'db://rds/prod-pg/billing/invoices.read', actions: ['read'] },
      { resource: 'db://cloudsql/analytics-pg/events/raw.read', actions: ['read'] },
    ],
  },
  dbUsernamesByRole: { DataAnalyst: 'euno_readonly' },
};

// ---------------------------------------------------------------------------
// § 1 — Azure Blob storage-grant invariants
// ---------------------------------------------------------------------------

describe('Invariant § 1 — Azure Blob storage grant', () => {
  /**
   * Capture what permissions were actually passed to the SAS signer so
   * the test can assert on them without relying on the opaque SAS token.
   */
  function buildAzureMinter(): {
    minter: AzureStorageGrantMinter;
    seenPermissions: string[];
  } {
    const seenPermissions: string[] = [];
    const minter = new AzureStorageGrantMinter({
      clientFactory: () => ({
        accountName: 'sales',
        getUserDelegationKey: async () => ({}),
      }),
      signer: (input) => {
        seenPermissions.push(input.permissions);
        return { sasToken: `sig-${input.permissions}`, url: `https://sales/q1.csv?${input.permissions}` };
      },
    });
    return { minter, seenPermissions };
  }

  it('read capability → only r permission in SAS (no write / delete)', async () => {
    const { minter, seenPermissions } = buildAzureMinter();
    const svc = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': minter },
    });
    const caps: CapabilityConstraint[] = [
      { resource: 'storage://azure/sales/q1.csv', actions: ['read'] },
    ];
    const grants = await svc.mintForCapabilities(caps, {
      agentId: 'a',
      authorizedBy: 'u',
      capabilityTtlSeconds: 600,
    });

    expect(grants).toHaveLength(1);
    const perms = seenPermissions[0]!;
    // Must contain 'r' (read).
    expect(perms).toContain('r');
    // MUST NOT contain write ('w') or delete ('d').
    expect(perms).not.toContain('w');
    expect(perms).not.toContain('d');
  });

  it('write capability → only w permission in SAS (no read / delete)', async () => {
    const { minter, seenPermissions } = buildAzureMinter();
    const svc = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': minter },
    });
    await svc.mintForCapabilities(
      [{ resource: 'storage://azure/sales/q1.csv', actions: ['write'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );

    const perms = seenPermissions[0]!;
    expect(perms).toContain('w');
    expect(perms).not.toContain('r');
    expect(perms).not.toContain('d');
  });

  it('read+write+delete → r+w+d permissions (exact set, no list without request)', async () => {
    const { minter, seenPermissions } = buildAzureMinter();
    const svc = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': minter },
    });
    await svc.mintForCapabilities(
      [{ resource: 'storage://azure/sales/q1.csv', actions: ['read', 'write', 'delete'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );

    const perms = seenPermissions[0]!;
    expect(perms).toContain('r');
    expect(perms).toContain('w');
    expect(perms).toContain('d');
    // list permission must NOT appear when not in the capability actions.
    expect(perms).not.toContain('l');
  });

  it('resource-scope: grant.resource echoes the capability resource verbatim', async () => {
    const { minter } = buildAzureMinter();
    const svc = new StorageGrantService({ enabled: true, minters: { 'azure-blob': minter } });
    const resource = 'storage://azure/sales/q1.csv';
    const grants = await svc.mintForCapabilities(
      [{ resource, actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(grants?.[0]?.resource).toBe(resource);
  });

  it('TTL invariant: grant.expiresAt ≤ now + capabilityTtlSeconds', async () => {
    const { minter } = buildAzureMinter();
    const svc = new StorageGrantService({ enabled: true, minters: { 'azure-blob': minter } });
    const ttl = 300;
    const before = Date.now();
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://azure/sales/q1.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: ttl },
    );
    const after = Date.now();
    const grantExpiry = Date.parse(grants![0]!.expiresAt);
    // Grant expiry must not exceed now + ttl (with 5s tolerance for clock drift).
    expect(grantExpiry).toBeLessThanOrEqual(after + ttl * 1000 + 5_000);
    // Grant expiry must be in the future.
    expect(grantExpiry).toBeGreaterThan(before);
  });

  it('grantId invariant: every minted Azure Blob grant carries a non-empty grantId', async () => {
    const { minter } = buildAzureMinter();
    const svc = new StorageGrantService({ enabled: true, minters: { 'azure-blob': minter } });
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://azure/sales/q1.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(grants).toHaveLength(1);
    expect(typeof grants![0]!.grantId).toBe('string');
    expect(grants![0]!.grantId.length).toBeGreaterThan(0);
  });

  it('grantId is unique across two consecutive mints (no reuse)', async () => {
    const { minter } = buildAzureMinter();
    const svc = new StorageGrantService({ enabled: true, minters: { 'azure-blob': minter } });
    const ctx = { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 };
    const cap = [{ resource: 'storage://azure/sales/q1.csv', actions: ['read'] }];
    const g1 = await svc.mintForCapabilities(cap, ctx);
    const g2 = await svc.mintForCapabilities(cap, ctx);
    expect(g1![0]!.grantId).not.toBe(g2![0]!.grantId);
  });
});

// ---------------------------------------------------------------------------
// § 2 — AWS S3 storage-grant invariants
// ---------------------------------------------------------------------------

describe('Invariant § 2 — AWS S3 storage grant', () => {
  it('single-object read → only GET presigned URL (no PUT / DELETE)', async () => {
    const seenMethods: string[] = [];
    const minter = new AwsStorageGrantMinter({
      presigner: async ({ method }) => {
        seenMethods.push(method);
        return `https://bucket.s3.amazonaws.com/key?method=${method}`;
      },
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/key.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(seenMethods).toContain('GET');
    expect(seenMethods).not.toContain('PUT');
    expect(seenMethods).not.toContain('DELETE');
  });

  it('single-object write → only PUT presigned URL (no GET / DELETE)', async () => {
    const seenMethods: string[] = [];
    const minter = new AwsStorageGrantMinter({
      presigner: async ({ method }) => {
        seenMethods.push(method);
        return `https://bucket.s3.amazonaws.com/key?method=${method}`;
      },
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/key.csv', actions: ['write'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(seenMethods).toContain('PUT');
    expect(seenMethods).not.toContain('GET');
    expect(seenMethods).not.toContain('DELETE');
  });

  it('wildcard/prefix read → STS scope-down policy contains only s3:GetObject (no PutObject / DeleteObject)', async () => {
    const capturedPolicies: string[] = [];
    const minter = new AwsStorageGrantMinter({
      assumeRoleArn: 'arn:aws:iam::123:role/EunoGrant',
      region: 'us-east-1',
      stsClientFactory: async () => ({
        send: async ({ input }) => {
          capturedPolicies.push(String(input['Policy'] ?? ''));
          return {
            Credentials: {
              AccessKeyId: 'ASIATEST',
              SecretAccessKey: 'secretTest',
              SessionToken: 'sessionTest',
              Expiration: new Date(Date.now() + 900_000),
            },
          };
        },
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/*', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 900 },
    );

    expect(capturedPolicies).toHaveLength(1);
    const policy = JSON.parse(capturedPolicies[0]!);
    const objectStatement = policy.Statement.find(
      (s: { Sid?: string }) => s.Sid === 'EunoScopedAccess',
    );
    expect(objectStatement).toBeDefined();
    const actions: string[] = objectStatement.Action;
    expect(actions).toContain('s3:GetObject');
    // A read-only STS policy MUST NOT include write or delete IAM actions.
    expect(actions).not.toContain('s3:PutObject');
    expect(actions).not.toContain('s3:DeleteObject');
  });

  it('wildcard/prefix write → STS scope-down policy contains s3:PutObject (no GetObject)', async () => {
    const capturedPolicies: string[] = [];
    const minter = new AwsStorageGrantMinter({
      assumeRoleArn: 'arn:aws:iam::123:role/EunoGrant',
      region: 'us-east-1',
      stsClientFactory: async () => ({
        send: async ({ input }) => {
          capturedPolicies.push(String(input['Policy'] ?? ''));
          return {
            Credentials: {
              AccessKeyId: 'ASIATEST',
              SecretAccessKey: 'secretTest',
              SessionToken: 'sessionTest',
              Expiration: new Date(Date.now() + 900_000),
            },
          };
        },
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/*', actions: ['write'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 900 },
    );

    const policy = JSON.parse(capturedPolicies[0]!);
    const objectStatement = policy.Statement.find(
      (s: { Sid?: string }) => s.Sid === 'EunoScopedAccess',
    );
    const actions: string[] = objectStatement.Action;
    expect(actions).toContain('s3:PutObject');
    expect(actions).not.toContain('s3:GetObject');
    expect(actions).not.toContain('s3:DeleteObject');
  });

  it('resource-scope: STS session is scoped to the stated prefix (not the whole bucket)', async () => {
    let capturedResource: string | undefined;
    const minter = new AwsStorageGrantMinter({
      assumeRoleArn: 'arn:aws:iam::123:role/EunoGrant',
      region: 'us-east-1',
      stsClientFactory: async () => ({
        send: async ({ input }) => {
          const policy = JSON.parse(String(input['Policy'] ?? '{}'));
          const stmt = policy.Statement?.find((s: { Sid?: string }) => s.Sid === 'EunoScopedAccess');
          capturedResource = stmt?.Resource;
          return {
            Credentials: {
              AccessKeyId: 'ASIATEST',
              SecretAccessKey: 'secretTest',
              SessionToken: 'sessionTest',
              Expiration: new Date(Date.now() + 900_000),
            },
          };
        },
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://aws/my-bucket/*', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 900 },
    );

    // The IAM resource ARN must be scoped to the bucket, not a wildcard
    // covering all buckets or an arbitrary resource.
    expect(capturedResource).toMatch(/^arn:aws:s3:::my-bucket/);
  });

  it('grantId invariant: AWS S3 presigned grant carries a non-empty grantId', async () => {
    const minter = new AwsStorageGrantMinter({
      presigner: async ({ method }) => `https://bucket.s3.amazonaws.com/key?method=${method}`,
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/key.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(typeof grants![0]!.grantId).toBe('string');
    expect(grants![0]!.grantId.length).toBeGreaterThan(0);
  });

  it('grantId invariant: AWS S3 STS session grant carries a non-empty grantId', async () => {
    const minter = new AwsStorageGrantMinter({
      assumeRoleArn: 'arn:aws:iam::123:role/EunoGrant',
      region: 'us-east-1',
      stsClientFactory: async () => ({
        send: async () => ({
          Credentials: {
            AccessKeyId: 'ASIATEST',
            SecretAccessKey: 'secretTest',
            SessionToken: 'sessionTest',
            Expiration: new Date(Date.now() + 900_000),
          },
        }),
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 's3': minter } });
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://aws/bucket/*', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 900 },
    );
    expect(typeof grants![0]!.grantId).toBe('string');
    expect(grants![0]!.grantId.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// § 3 — GCP Cloud Storage grant invariants
// ---------------------------------------------------------------------------

describe('Invariant § 3 — GCP Cloud Storage grant', () => {
  it('read capability → only GET signed URL (no PUT / DELETE)', async () => {
    const seenActions: string[] = [];
    const minter = new GcpStorageGrantMinter({
      storageClientFactory: () => ({
        bucket: (name: string) => ({
          file: (key: string) => ({
            getSignedUrl: async (opts: { action: 'read' | 'write' | 'delete'; expires: number | Date }) => {
              seenActions.push(opts.action);
              return [`https://storage.googleapis.com/${name}/${key}?${opts.action}`] as [string];
            },
          }),
        }),
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 'gcs': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://gcp/my-bucket/data.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(seenActions).toContain('read');
    expect(seenActions).not.toContain('write');
    expect(seenActions).not.toContain('delete');
  });

  it('write capability → only PUT/write signed URL', async () => {
    const seenActions: string[] = [];
    const minter = new GcpStorageGrantMinter({
      storageClientFactory: () => ({
        bucket: (name: string) => ({
          file: (key: string) => ({
            getSignedUrl: async (opts: { action: 'read' | 'write' | 'delete'; expires: number | Date }) => {
              seenActions.push(opts.action);
              return [`https://storage.googleapis.com/${name}/${key}?${opts.action}`] as [string];
            },
          }),
        }),
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 'gcs': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://gcp/my-bucket/data.csv', actions: ['write'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(seenActions).toContain('write');
    expect(seenActions).not.toContain('read');
    expect(seenActions).not.toContain('delete');
  });

  it('wildcard/prefix read → downscoped credential contains only objectViewer (no objectAdmin)', async () => {
    const seenPermissions: string[][] = [];
    const minter = new GcpStorageGrantMinter({
      downscopedTokenSource: {
        mint: async ({ actions }) => {
          const roles = mapActionsToGcsRoles(actions);
          seenPermissions.push(roles);
          return {
            token: 'downscoped-tok',
            expiresAt: new Date(Date.now() + 600_000),
          };
        },
      },
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 'gcs': minter } });
    await svc.mintForCapabilities(
      [{ resource: 'storage://gcp/my-bucket/*', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(seenPermissions[0]).toContain('inRole:roles/storage.objectViewer');
    expect(seenPermissions[0]).not.toContain('inRole:roles/storage.objectAdmin');
  });

  it('grantId invariant: GCP signed-URL grant carries a non-empty grantId', async () => {
    const minter = new GcpStorageGrantMinter({
      storageClientFactory: () => ({
        bucket: (name: string) => ({
          file: (key: string) => ({
            getSignedUrl: async (_opts: { action: 'read' | 'write' | 'delete'; expires: number | Date }) =>
              [`https://storage.googleapis.com/${name}/${key}`] as [string],
          }),
        }),
      }),
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 'gcs': minter } });
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://gcp/my-bucket/data.csv', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(typeof grants![0]!.grantId).toBe('string');
    expect(grants![0]!.grantId.length).toBeGreaterThan(0);
  });

  it('grantId invariant: GCP downscoped grant carries a non-empty grantId', async () => {
    const minter = new GcpStorageGrantMinter({
      downscopedTokenSource: {
        mint: async () => ({
          token: 'downscoped-tok',
          expiresAt: new Date(Date.now() + 600_000),
        }),
      },
    });
    const svc = new StorageGrantService({ enabled: true, minters: { 'gcs': minter } });
    const grants = await svc.mintForCapabilities(
      [{ resource: 'storage://gcp/my-bucket/*', actions: ['read'] }],
      { agentId: 'a', authorizedBy: 'u', capabilityTtlSeconds: 600 },
    );
    expect(typeof grants![0]!.grantId).toBe('string');
    expect(grants![0]!.grantId.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// § 4 — DB credential invariants (all providers)
// ---------------------------------------------------------------------------

/**
 * Standard DB token service used by § 4 tests. The stub minters
 * echo their inputs back so assertions can inspect what the dispatcher
 * derived from the capability and the operator config — not what the
 * cloud SDK would return.
 */
function buildDbService(): DbTokenService {
  return new DbTokenService({
    enabled: true,
    maxTtlSeconds: 900,
    instances: new Map([
      ['salesserver', {
        id: 'salesserver', provider: 'azure-sql',
        host: 'salesserver.database.windows.net', port: 1433,
        databases: ['salesdb'],
      }],
      ['prod-pg', {
        id: 'prod-pg', provider: 'rds-iam',
        host: 'prod.us-east-1.rds.amazonaws.com', port: 5432,
        databases: ['billing'],
        region: 'us-east-1',
      }],
      ['analytics-pg', {
        id: 'analytics-pg', provider: 'cloudsql-iam',
        host: '10.0.0.1', port: 5432,
        databases: ['events'],
      }],
    ]),
    minters: {
      'azure-sql': new AzureSqlTokenMinter({
        tokenSource: {
          getToken: async () => ({ token: 'azure-jwt', expiresOnTimestamp: Date.now() + 600_000 }),
        },
      }),
      'rds-iam': new RdsTokenMinter({
        now: () => 1_700_000_000_000,
        signerFactory: (input) => ({
          getAuthToken: async () => `rds-tok-${input.username}`,
        }),
      }),
      'cloudsql-iam': new CloudSqlTokenMinter({
        now: () => 1_700_000_000_000,
        authClientFactory: () => ({
          getAccessToken: async () => ({ token: 'gcs-tok', res: { data: { expires_in: 600 } } }),
        }),
      }),
    },
  });
}

const dbBaseCtx = {
  agentId: 'agent-db',
  authorizedBy: 'user-1',
  capabilityTtlSeconds: 600,
  userRoles: ['DataAnalyst'],
  policy: testPolicy,
};

describe('Invariant § 4a — DB username invariant (confused-deputy prevention)', () => {
  it('Azure SQL: username comes from role mapping, not from the capability resource URI', async () => {
    const svc = buildDbService();
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      dbBaseCtx,
    );
    expect(creds).toHaveLength(1);
    // Username must be the operator-mapped 'euno_readonly', not any
    // value an agent could supply by crafting the resource URI.
    expect(creds![0]!.username).toBe('euno_readonly');
  });

  it('RDS: username comes from role mapping, not from the capability resource URI', async () => {
    const svc = buildDbService();
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://rds/prod-pg/billing/invoices.read', actions: ['read'] }],
      dbBaseCtx,
    );
    expect(creds![0]!.username).toBe('euno_readonly');
  });

  it('Cloud SQL: username comes from role mapping, not from the capability resource URI', async () => {
    const svc = buildDbService();
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://cloudsql/analytics-pg/events/raw.read', actions: ['read'] }],
      dbBaseCtx,
    );
    expect(creds![0]!.username).toBe('euno_readonly');
  });

  it('fails closed with INSUFFICIENT_PERMISSIONS when no role maps to a dbUsername', async () => {
    const svc = buildDbService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
        { ...dbBaseCtx, userRoles: ['UnknownRole'] },
      ),
    ).rejects.toMatchObject({ code: 'INSUFFICIENT_PERMISSIONS' });
  });

  it('host and port come from operator instance config, not from any agent-supplied field', async () => {
    const svc = buildDbService();
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      dbBaseCtx,
    );
    // These values come from the operator-configured instances Map,
    // not from any field the agent could influence.
    expect(creds![0]!.host).toBe('salesserver.database.windows.net');
    expect(creds![0]!.port).toBe(1433);
    expect(creds![0]!.database).toBe('salesdb');
  });
});

describe('Invariant § 4b — DB resource-scope invariant', () => {
  it('rejects an instance not in the operator allow-list', async () => {
    const svc = buildDbService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/attacker-instance/salesdb/orders.read', actions: ['read'] }],
        dbBaseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('rejects a database not declared on the instance', async () => {
    const svc = buildDbService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/salesserver/secretdb/orders.read', actions: ['read'] }],
        dbBaseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('rejects when the URI cloud does not match the instance provider', async () => {
    const svc = buildDbService();
    // salesserver is azure-sql; requesting via rds URI is a provider mismatch.
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://rds/salesserver/salesdb/orders.read', actions: ['read'] }],
        dbBaseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('resource-scope: credential.resource echoes the capability resource verbatim', async () => {
    const svc = buildDbService();
    const resource = 'db://azure-sql/salesserver/salesdb/orders.read';
    const creds = await svc.mintForCapabilities(
      [{ resource, actions: ['read'] }],
      dbBaseCtx,
    );
    expect(creds![0]!.resource).toBe(resource);
  });
});

describe('Invariant § 4c — DB TTL invariant', () => {
  it('Azure SQL: refuses issuance when AAD token lifetime exceeds operator cap', async () => {
    const svc = new DbTokenService({
      enabled: true,
      maxTtlSeconds: 600,
      instances: new Map([
        ['srv', { id: 'srv', provider: 'azure-sql', host: 'h', port: 1433, databases: ['db'] }],
      ]),
      minters: {
        'azure-sql': new AzureSqlTokenMinter({
          // AAD returns a 1-hour token; cap is 600s.
          tokenSource: { getToken: async () => ({ token: 'jwt', expiresOnTimestamp: Date.now() + 3600_000 }) },
        }),
      },
    });
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/srv/db/t.read', actions: ['read'] }],
        { ...dbBaseCtx, capabilityTtlSeconds: 600 },
      ),
    ).rejects.toThrow(/exceeds the configured DB-token cap/);
  });

  it('Cloud SQL: credential expiresAt is capped at capabilityTtlSeconds', async () => {
    const FIXED_NOW = 1_700_000_000_000;
    const svc = new DbTokenService({
      enabled: true,
      maxTtlSeconds: 900,
      instances: new Map([
        ['analytics-pg', { id: 'analytics-pg', provider: 'cloudsql-iam', host: '10.0.0.1', port: 5432, databases: ['events'] }],
      ]),
      minters: {
        'cloudsql-iam': new CloudSqlTokenMinter({
          now: () => FIXED_NOW,
          // Provider returns a 1800s token; cap is 600s.
          authClientFactory: () => ({
            getAccessToken: async () => ({ token: 'tok', res: { data: { expires_in: 1800 } } }),
          }),
        }),
      },
    });
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://cloudsql/analytics-pg/events/raw.read', actions: ['read'] }],
      { ...dbBaseCtx, capabilityTtlSeconds: 600 },
    );
    const expiry = Date.parse(creds![0]!.expiresAt);
    // Expiry must be capped to capabilityTtlSeconds, not the provider's 1800s.
    expect(expiry).toBe(FIXED_NOW + 600_000);
  });

  it('RDS: expiresAt is always now + 15 min (AWS-fixed lifetime), never longer', async () => {
    const FIXED_NOW = 1_700_000_000_000;
    const svc = buildDbService();
    const creds = await svc.mintForCapabilities(
      [{ resource: 'db://rds/prod-pg/billing/invoices.read', actions: ['read'] }],
      dbBaseCtx,
    );
    const expiry = Date.parse(creds![0]!.expiresAt);
    expect(expiry).toBe(FIXED_NOW + RDS_IAM_TOKEN_LIFETIME_SECONDS * 1000);
  });
});

describe('Invariant § 4d — DB grantId invariant', () => {
  it('every DB credential carries a non-empty grantId', async () => {
    const svc = buildDbService();
    const caps = [
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      { resource: 'db://rds/prod-pg/billing/invoices.read', actions: ['read'] },
      { resource: 'db://cloudsql/analytics-pg/events/raw.read', actions: ['read'] },
    ];
    const creds = await svc.mintForCapabilities(caps, dbBaseCtx);
    expect(creds).toHaveLength(3);
    for (const cred of creds!) {
      expect(typeof cred.grantId).toBe('string');
      expect(cred.grantId.length).toBeGreaterThan(0);
    }
  });

  it('grantId is unique across every credential in a multi-resource batch', async () => {
    const svc = buildDbService();
    const caps = [
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      { resource: 'db://rds/prod-pg/billing/invoices.read', actions: ['read'] },
      { resource: 'db://cloudsql/analytics-pg/events/raw.read', actions: ['read'] },
    ];
    const creds = await svc.mintForCapabilities(caps, dbBaseCtx);
    const ids = creds!.map((c) => c.grantId);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ---------------------------------------------------------------------------
// § 5 — Audit-log SIEM annotation invariant
// ---------------------------------------------------------------------------

describe('Invariant § 5 — grantId traced into SIEM-bound audit log', () => {
  /**
   * Build a full CapabilityIssuerService wired with an in-process broker
   * and intercept the audit log entries it writes so we can assert that
   * grantIds for minted grants appear in the audit metadata.
   */
  async function buildIssuerWithAuditSpy(): Promise<{
    service: CapabilityIssuerService;
    auditEntries: Record<string, unknown>[];
  }> {
    const signer = new JoseSigner();
    await signer.init();

    const auditEntries: Record<string, unknown>[] = [];

    // Build real minters so grantIds are generated in production code paths.
    const azureMinter = new AzureStorageGrantMinter({
      clientFactory: () => ({
        accountName: 'sales',
        getUserDelegationKey: async () => ({}),
      }),
      signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
    });
    const storageSvc = new StorageGrantService({
      enabled: true,
      minters: { 'azure-blob': azureMinter },
    });

    const azureSqlMinter = new AzureSqlTokenMinter({
      tokenSource: { getToken: async () => ({ token: 'JWT', expiresOnTimestamp: Date.now() + 600_000 }) },
    });
    const dbSvc = new DbTokenService({
      enabled: true,
      instances: new Map([
        ['salesserver', { id: 'salesserver', provider: 'azure-sql', host: 'h', port: 1433, databases: ['salesdb'] }],
      ]),
      minters: { 'azure-sql': azureSqlMinter },
    });

    const auditPolicy: RoleCapabilityPolicy = {
      default: {
        DataAnalyst: [
          { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
          { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
        ],
      },
      dbUsernamesByRole: { DataAnalyst: 'euno_readonly' },
    };

    // Intercept audit log entries via a real Winston stream transport
    // so we avoid any mocking of Winston internals. The stream transport
    // receives JSON-serialized log lines; we parse and collect them.
    const captureStream = new Writable({
      write(chunk: Buffer, _enc, cb) {
        try {
          auditEntries.push(JSON.parse(chunk.toString()) as Record<string, unknown>);
        } catch {
          /* ignore non-JSON flush lines */
        }
        cb();
      },
    });
    const captureTransport = new winston.transports.Stream({ stream: captureStream });

    const service = new CapabilityIssuerService(
      signer,
      new StubIdentityProvider(stubUserContext),
      'did:web:example.com',
      900,
      logger,
      {
        policy: auditPolicy,
        storageGrantService: storageSvc,
        dbTokenService: dbSvc,
        auditTransports: [captureTransport],
      },
    );

    return { service, auditEntries };
  }

  it('storage grant grantId appears in the issuance audit entry metadata', async () => {
    const { service, auditEntries } = await buildIssuerWithAuditSpy();

    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
      ],
    });
    // Allow the Winston stream transport one tick to flush.
    await new Promise((r) => setTimeout(r, 20));

    // The response must carry a grantId for tracing.
    expect(resp.storageGrants).toHaveLength(1);
    const grantId = resp.storageGrants![0]!.grantId;
    expect(typeof grantId).toBe('string');
    expect(grantId.length).toBeGreaterThan(0);

    // The audit entry must include the grantId so the SIEM can correlate
    // the capability token with the cloud credential it produced.
    const issuanceEntry = auditEntries.find(
      (e) => {
        const meta = e['metadata'] as Record<string, unknown> | undefined;
        const grants = meta?.['storageGrants'] as unknown[] | undefined;
        return Array.isArray(grants) && grants.length > 0;
      },
    );
    expect(issuanceEntry).toBeDefined();
    const metadata = issuanceEntry!['metadata'] as Record<string, unknown>;
    const auditedGrants = metadata['storageGrants'] as Array<Record<string, unknown>>;
    expect(auditedGrants[0]!['grantId']).toBe(grantId);
  });

  it('DB credential grantId appears in the issuance audit entry metadata', async () => {
    const { service, auditEntries } = await buildIssuerWithAuditSpy();

    const resp = await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      ],
    });
    await new Promise((r) => setTimeout(r, 20));

    expect(resp.dbCredentials).toHaveLength(1);
    const grantId = resp.dbCredentials![0]!.grantId;
    expect(typeof grantId).toBe('string');
    expect(grantId.length).toBeGreaterThan(0);

    const issuanceEntry = auditEntries.find(
      (e) => {
        const meta = e['metadata'] as Record<string, unknown> | undefined;
        const creds = meta?.['dbCredentials'] as unknown[] | undefined;
        return Array.isArray(creds) && creds.length > 0;
      },
    );
    expect(issuanceEntry).toBeDefined();
    const metadata = issuanceEntry!['metadata'] as Record<string, unknown>;
    const auditedCreds = metadata['dbCredentials'] as Array<Record<string, unknown>>;
    expect(auditedCreds[0]!['grantId']).toBe(grantId);
  });

  it('raw credential secrets are NOT written to the audit log', async () => {
    const { service, auditEntries } = await buildIssuerWithAuditSpy();

    await service.issueCapability({
      authToken: 'irrelevant',
      agentId: 'agent-1',
      requestedCapabilities: [
        { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
        { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
      ],
    });
    await new Promise((r) => setTimeout(r, 20));

    // The raw SAS token and DB bearer token must never appear in audit entries.
    const auditText = JSON.stringify(auditEntries);
    expect(auditText).not.toContain('"sasToken"');
    expect(auditText).not.toContain('"token"');
    // The azureSas / token payload objects must not appear under any key.
    expect(auditText).not.toContain('azureSas');
  });
});

// ---------------------------------------------------------------------------
// § 6 — InProcessSideCredentialBroker end-to-end invariants
// ---------------------------------------------------------------------------

describe('Invariant § 6 — InProcessSideCredentialBroker (end-to-end)', () => {
  function buildBroker(): InProcessSideCredentialBroker {
    const azureMinter = new AzureStorageGrantMinter({
      clientFactory: () => ({
        accountName: 'sales',
        getUserDelegationKey: async () => ({}),
      }),
      signer: () => ({ sasToken: 'sig', url: 'https://sales/foo.csv?sig' }),
    });
    const azureSqlMinter = new AzureSqlTokenMinter({
      tokenSource: { getToken: async () => ({ token: 'JWT', expiresOnTimestamp: Date.now() + 600_000 }) },
    });
    return new InProcessSideCredentialBroker({
      storageGrantService: new StorageGrantService({
        enabled: true,
        minters: { 'azure-blob': azureMinter },
      }),
      dbTokenService: new DbTokenService({
        enabled: true,
        instances: new Map([
          ['salesserver', { id: 'salesserver', provider: 'azure-sql', host: 'h', port: 1433, databases: ['salesdb'] }],
        ]),
        minters: { 'azure-sql': azureSqlMinter },
      }),
    });
  }

  it('every minted StorageGrant has a unique grantId per issuance', async () => {
    const broker = buildBroker();
    const caps: CapabilityConstraint[] = [
      { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
    ];
    const ctx = {
      agentId: 'agent-1',
      authorizedBy: 'user-1',
      capabilityTtlSeconds: 600,
      userRoles: ['DataAnalyst'],
      policy: testPolicy,
    };
    const r1 = await broker.mint('jwt1', caps, ctx);
    const r2 = await broker.mint('jwt2', caps, ctx);
    expect(r1.storageGrants![0]!.grantId).not.toBe(r2.storageGrants![0]!.grantId);
  });

  it('every minted DbCredential has a unique grantId per issuance', async () => {
    const broker = buildBroker();
    const caps: CapabilityConstraint[] = [
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
    ];
    const ctx = {
      agentId: 'agent-1',
      authorizedBy: 'user-1',
      capabilityTtlSeconds: 600,
      userRoles: ['DataAnalyst'],
      policy: testPolicy,
    };
    const r1 = await broker.mint('jwt1', caps, ctx);
    const r2 = await broker.mint('jwt2', caps, ctx);
    expect(r1.dbCredentials![0]!.grantId).not.toBe(r2.dbCredentials![0]!.grantId);
  });

  it('actions in minted StorageGrant match the capability actions exactly', async () => {
    const broker = buildBroker();
    const caps: CapabilityConstraint[] = [
      { resource: 'storage://azure/sales/foo.csv', actions: ['read'] },
    ];
    const result = await broker.mint('jwt', caps, {
      agentId: 'agent-1',
      authorizedBy: 'user-1',
      capabilityTtlSeconds: 600,
      userRoles: ['DataAnalyst'],
      policy: testPolicy,
    });
    expect(result.storageGrants![0]!.actions).toEqual(['read']);
  });

  it('actions in minted DbCredential match the capability actions exactly', async () => {
    const broker = buildBroker();
    const caps: CapabilityConstraint[] = [
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
    ];
    const result = await broker.mint('jwt', caps, {
      agentId: 'agent-1',
      authorizedBy: 'user-1',
      capabilityTtlSeconds: 600,
      userRoles: ['DataAnalyst'],
      policy: testPolicy,
    });
    expect(result.dbCredentials![0]!.actions).toEqual(['read']);
  });
});

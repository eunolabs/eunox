/**
 * Unit tests for the per-cloud DB-token minters and the
 * DbTokenService dispatcher.
 *
 * Behaviors covered:
 *  - URI parser: canonical form, traversal rejection, wildcard rejection.
 *  - Per-cloud minters: token / connection-hint plumbing, expiry sourced
 *    from the SDK (Azure SQL) or computed from the AWS-fixed lifetime
 *    (RDS), `dbUsername` always sourced from issuer-side resolution
 *    rather than agent input.
 *  - Service-level: feature flag off → no-op; instance allow-list
 *    enforced; URI cloud must match instance provider; database must be
 *    declared on the instance; agent without a role-mapped dbUsername
 *    receives INSUFFICIENT_PERMISSIONS.
 */

import {
  DbTokenService,
  AzureSqlTokenMinter,
  RdsTokenMinter,
  CloudSqlTokenMinter,
  parseDbUri,
  validateInstancesDocument,
  RDS_IAM_TOKEN_LIFETIME_SECONDS,
} from '../src/db-token';
import { CapabilityError, CapabilityConstraint, RoleCapabilityPolicy } from '@euno/common';

const policy: RoleCapabilityPolicy = {
  default: {},
  dbUsernamesByRole: { 'data-analyst': 'euno_readonly', 'admin': 'euno_admin' },
};

describe('parseDbUri', () => {
  it('parses an Azure SQL URI', () => {
    expect(parseDbUri('db://azure-sql/salesserver/salesdb/orders.read')).toEqual({
      raw: 'db://azure-sql/salesserver/salesdb/orders.read',
      cloud: 'azure-sql',
      instance: 'salesserver',
      database: 'salesdb',
      objectAndAction: 'orders.read',
    });
  });

  it('parses RDS and Cloud SQL URIs', () => {
    expect(parseDbUri('db://rds/prod-postgres/billing/invoices.read')?.cloud).toBe('rds-iam');
    expect(parseDbUri('db://cloudsql/analytics-pg/events/raw_events.read')?.cloud).toBe('cloudsql-iam');
  });

  it('rejects non-db URIs and missing segments', () => {
    expect(parseDbUri('storage://azure/x/y')).toBeNull();
    expect(parseDbUri('db://azure-sql/srv')).toBeNull();
    expect(parseDbUri('db://azure-sql/srv/db')).toBeNull();
  });

  it('rejects wildcards and traversals', () => {
    expect(parseDbUri('db://azure-sql/srv/db/*.read')).toBeNull();
    expect(parseDbUri('db://azure-sql/srv/db/../etc.read')).toBeNull();
  });

  it('rejects unknown clouds', () => {
    expect(parseDbUri('db://snowflake/srv/db/t.read')).toBeNull();
  });
});

describe('validateInstancesDocument', () => {
  it('accepts a well-formed document and rejects duplicates', () => {
    const map = validateInstancesDocument({
      instances: [
        {
          id: 'salesserver',
          provider: 'azure-sql',
          host: 'salesserver.database.windows.net',
          port: 1433,
          databases: ['salesdb', 'archivedb'],
        },
        {
          id: 'prod-postgres',
          provider: 'rds-iam',
          host: 'prod.cluster.us-east-1.rds.amazonaws.com',
          port: 5432,
          databases: ['billing'],
          region: 'us-east-1',
        },
      ],
    });
    expect(map.size).toBe(2);
    expect(map.get('salesserver')?.provider).toBe('azure-sql');
    expect(map.get('prod-postgres')?.region).toBe('us-east-1');
  });

  it('rejects rds-iam without a region', () => {
    expect(() =>
      validateInstancesDocument({
        instances: [
          { id: 'p', provider: 'rds-iam', host: 'h', port: 5432, databases: ['d'] },
        ],
      }),
    ).toThrow(/region/);
  });

  it('rejects duplicates', () => {
    expect(() =>
      validateInstancesDocument({
        instances: [
          { id: 'a', provider: 'azure-sql', host: 'h', port: 1433, databases: ['d'] },
          { id: 'a', provider: 'azure-sql', host: 'h', port: 1433, databases: ['d'] },
        ],
      }),
    ).toThrow(/duplicate/);
  });
});

describe('AzureSqlTokenMinter', () => {
  it('returns a DbCredential with SDK-reported expiry when within the cap', async () => {
    const expires = Date.now() + 5 * 60_000; // 5 minutes from now → within 10-minute cap
    const minter = new AzureSqlTokenMinter({
      tokenSource: { getToken: async () => ({ token: 'JWT', expiresOnTimestamp: expires }) },
    });
    const cred = await minter.mint({
      resource: 'db://azure-sql/salesserver/salesdb/orders.read',
      actions: ['read'],
      ttlSeconds: 600,
      agentId: 'a',
      authorizedBy: 'u',
      dbUsername: 'agent-app@tenant.onmicrosoft.com',
      instance: {
        id: 'salesserver',
        provider: 'azure-sql',
        host: 'salesserver.database.windows.net',
        port: 1433,
        databases: ['salesdb'],
      },
      database: 'salesdb',
    });
    expect(cred.token).toBe('JWT');
    expect(cred.expiresAt).toBe(new Date(expires).toISOString());
    expect(cred.username).toBe('agent-app@tenant.onmicrosoft.com');
    expect(cred.host).toBe('salesserver.database.windows.net');
    expect(cred.port).toBe(1433);
    expect(cred.database).toBe('salesdb');
  });

  it('fails closed when the AAD-reported token expiry exceeds the operator cap', async () => {
    // AAD might issue a 60-minute token; the operator cap is 10 minutes.
    const expires = Date.now() + 60 * 60_000;
    const minter = new AzureSqlTokenMinter({
      tokenSource: { getToken: async () => ({ token: 'JWT', expiresOnTimestamp: expires }) },
    });
    await expect(
      minter.mint({
        resource: 'db://azure-sql/salesserver/salesdb/orders.read',
        actions: ['read'],
        ttlSeconds: 600,
        agentId: 'a',
        authorizedBy: 'u',
        dbUsername: 'agent-app@tenant.onmicrosoft.com',
        instance: {
          id: 'salesserver',
          provider: 'azure-sql',
          host: 'salesserver.database.windows.net',
          port: 1433,
          databases: ['salesdb'],
        },
        database: 'salesdb',
      }),
    ).rejects.toThrow(/exceeds the configured DB-token cap/);
  });
});

describe('RdsTokenMinter', () => {
  it('passes hostname/port/username from operator config and computes a 15-minute expiry', async () => {
    const seen: { hostname: string; port: number; username: string; region: string }[] = [];
    const minter = new RdsTokenMinter({
      now: () => 1_700_000_000_000,
      signerFactory: (input) => {
        seen.push(input);
        return { getAuthToken: async () => `tok-${input.username}` };
      },
    });
    const cred = await minter.mint({
      resource: 'db://rds/prod-postgres/billing/invoices.read',
      actions: ['read'],
      ttlSeconds: 600,
      agentId: 'a',
      authorizedBy: 'u',
      dbUsername: 'euno_readonly',
      instance: {
        id: 'prod-postgres',
        provider: 'rds-iam',
        host: 'prod.cluster.us-east-1.rds.amazonaws.com',
        port: 5432,
        databases: ['billing'],
        region: 'us-east-1',
      },
      database: 'billing',
    });
    expect(seen).toEqual([
      {
        hostname: 'prod.cluster.us-east-1.rds.amazonaws.com',
        port: 5432,
        username: 'euno_readonly',
        region: 'us-east-1',
      },
    ]);
    expect(cred.token).toBe('tok-euno_readonly');
    // Expiry is now + RDS lifetime — never recomputed from request input.
    const expectedMs = 1_700_000_000_000 + RDS_IAM_TOKEN_LIFETIME_SECONDS * 1000;
    expect(cred.expiresAt).toBe(new Date(expectedMs).toISOString());
  });

  it('rejects an instance missing region', async () => {
    const minter = new RdsTokenMinter({
      signerFactory: () => ({ getAuthToken: async () => 'tok' }),
    });
    await expect(
      minter.mint({
        resource: 'db://rds/p/b/i.read',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
        dbUsername: 'u',
        instance: { id: 'p', provider: 'rds-iam', host: 'h', port: 5432, databases: ['b'] },
        database: 'b',
      }),
    ).rejects.toBeInstanceOf(CapabilityError);
  });

  it('assumes the configured role via STS and passes credentials to the signer', async () => {
    // When assumeRoleArn is set, the minter should call STS.AssumeRole first,
    // then pass the resulting credentials to the signer factory.
    const seenCredentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string }[] = [];
    const minter = new RdsTokenMinter({
      assumeRoleArn: 'arn:aws:iam::123456789012:role/EunoDbTokenRole',
      stsClientFactory: async () => ({
        send: async () => ({
          Credentials: {
            AccessKeyId: 'ASIATEST',
            SecretAccessKey: 'secretTest',
            SessionToken: 'sessionTest',
          },
        }),
      }),
      signerFactory: (input) => {
        if (input.credentials) {
          seenCredentials.push(input.credentials);
        }
        return { getAuthToken: async () => 'sts-scoped-tok' };
      },
      now: () => 1_700_000_000_000,
    });
    const cred = await minter.mint({
      resource: 'db://rds/prod-postgres/billing/invoices.read',
      actions: ['read'],
      ttlSeconds: 600,
      agentId: 'agent-1',
      authorizedBy: 'user-1',
      dbUsername: 'euno_readonly',
      instance: {
        id: 'prod-postgres',
        provider: 'rds-iam',
        host: 'prod.cluster.us-east-1.rds.amazonaws.com',
        port: 5432,
        databases: ['billing'],
        region: 'us-east-1',
      },
      database: 'billing',
    });
    // The signer must have received the STS credentials.
    expect(seenCredentials).toHaveLength(1);
    expect(seenCredentials[0]?.accessKeyId).toBe('ASIATEST');
    expect(seenCredentials[0]?.sessionToken).toBe('sessionTest');
    expect(cred.token).toBe('sts-scoped-tok');
  });

  it('uses opts.now for the STS session-name timestamp so it is deterministic in tests', async () => {
    const capturedInputs: Record<string, unknown>[] = [];
    const FIXED_MS = 1_700_000_000_000;
    const minter = new RdsTokenMinter({
      assumeRoleArn: 'arn:aws:iam::123456789012:role/EunoDbTokenRole',
      stsClientFactory: async () => ({
        send: async (cmd: { input: Record<string, unknown> }) => {
          capturedInputs.push(cmd.input);
          return {
            Credentials: {
              AccessKeyId: 'ASIATEST2',
              SecretAccessKey: 'secret2',
              SessionToken: 'session2',
            },
          };
        },
      }),
      signerFactory: () => ({ getAuthToken: async () => 'tok' }),
      now: () => FIXED_MS,
    });
    await minter.mint({
      resource: 'db://rds/p/b/i.read',
      actions: ['read'],
      ttlSeconds: 60,
      agentId: 'agent-clock-test',
      authorizedBy: 'u',
      dbUsername: 'euno_readonly',
      instance: { id: 'p', provider: 'rds-iam', host: 'h', port: 5432, databases: ['b'], region: 'us-east-1' },
      database: 'b',
    });
    expect(capturedInputs).toHaveLength(1);
    // Session name must contain the fixed timestamp — not the real wall clock.
    expect(String(capturedInputs[0]?.RoleSessionName)).toContain(String(FIXED_MS));
  });

  it('fails closed when STS.AssumeRole returns no credentials', async () => {
    const minter = new RdsTokenMinter({
      assumeRoleArn: 'arn:aws:iam::123456789012:role/EunoDbTokenRole',
      stsClientFactory: async () => ({
        send: async () => ({ Credentials: undefined }),
      }),
      signerFactory: () => ({ getAuthToken: async () => 'tok' }),
    });
    await expect(
      minter.mint({
        resource: 'db://rds/p/b/i.read',
        actions: ['read'],
        ttlSeconds: 60,
        agentId: 'a',
        authorizedBy: 'u',
        dbUsername: 'u',
        instance: { id: 'p', provider: 'rds-iam', host: 'h', port: 5432, databases: ['b'], region: 'us-east-1' },
        database: 'b',
      }),
    ).rejects.toMatchObject({ code: 'INTERNAL_ERROR' });
  });
});

describe('CloudSqlTokenMinter', () => {
  it('mints an OAuth token with the role-mapped username', async () => {
    const minter = new CloudSqlTokenMinter({
      now: () => 1_700_000_000_000,
      authClientFactory: () => ({
        // Provider says expires_in=400 (< the 600s cap) → use provider lifetime.
        getAccessToken: async () => ({ token: 'oauth-tok', res: { data: { expires_in: 400 } } }),
      }),
    });
    const cred = await minter.mint({
      resource: 'db://cloudsql/analytics-pg/events/raw_events.read',
      actions: ['read'],
      ttlSeconds: 600,
      agentId: 'a',
      authorizedBy: 'u',
      dbUsername: 'analyst-sa@proj.iam',
      instance: {
        id: 'analytics-pg',
        provider: 'cloudsql-iam',
        host: '10.0.0.1',
        port: 5432,
        databases: ['events'],
      },
      database: 'events',
    });
    expect(cred.token).toBe('oauth-tok');
    expect(cred.username).toBe('analyst-sa@proj.iam');
    expect(cred.expiresAt).toBe(new Date(1_700_000_000_000 + 400_000).toISOString());
  });

  it('caps the credential expiry to the operator-configured ttl', async () => {
    // Provider returns a 1800-second OAuth token; capability ttl is 600s.
    // The credential's reported expiry must reflect the 600s cap, not
    // the longer provider lifetime — DB_TOKEN_MAX_TTL_SECONDS would be
    // ineffective otherwise.
    const minter = new CloudSqlTokenMinter({
      now: () => 1_700_000_000_000,
      authClientFactory: () => ({
        getAccessToken: async () => ({ token: 'oauth-tok', res: { data: { expires_in: 1800 } } }),
      }),
    });
    const cred = await minter.mint({
      resource: 'db://cloudsql/analytics-pg/events/raw_events.read',
      actions: ['read'],
      ttlSeconds: 600,
      agentId: 'a',
      authorizedBy: 'u',
      dbUsername: 'analyst-sa@proj.iam',
      instance: {
        id: 'analytics-pg',
        provider: 'cloudsql-iam',
        host: '10.0.0.1',
        port: 5432,
        databases: ['events'],
      },
      database: 'events',
    });
    expect(cred.expiresAt).toBe(new Date(1_700_000_000_000 + 600_000).toISOString());
  });
});

describe('DbTokenService — dispatch & validation', () => {
  function buildService(): DbTokenService {
    return new DbTokenService({
      enabled: true,
      maxTtlSeconds: 900,
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
      minters: {
        'azure-sql': {
          provider: 'azure-sql',
          mint: async (input) => ({
            provider: 'azure-sql',
            resource: input.resource,
            actions: [...input.actions],
            expiresAt: '2030-01-01T00:00:00.000Z',
            host: input.instance.host,
            port: input.instance.port,
            database: input.database,
            username: input.dbUsername,
            token: 'JWT',
          }),
        },
      },
    });
  }

  const baseCtx = {
    agentId: 'a',
    authorizedBy: 'u',
    capabilityTtlSeconds: 600,
    userRoles: ['data-analyst'],
    policy,
  };

  it('returns undefined when service disabled', async () => {
    const svc = new DbTokenService();
    expect(
      await svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
        baseCtx,
      ),
    ).toBeUndefined();
  });

  it('mints a credential whose username comes from the user role mapping, not the request', async () => {
    const svc = buildService();
    const caps: CapabilityConstraint[] = [
      { resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] },
    ];
    const creds = await svc.mintForCapabilities(caps, baseCtx);
    expect(creds).toHaveLength(1);
    expect(creds?.[0]?.username).toBe('euno_readonly');
  });

  it('refuses issuance when no role grants a dbUsername (privilege-escalation guard)', async () => {
    const svc = buildService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
        { ...baseCtx, userRoles: ['unrelated-role'] },
      ),
    ).rejects.toMatchObject({ code: 'INSUFFICIENT_PERMISSIONS' });
  });

  it('rejects an instance not in the operator allow-list', async () => {
    const svc = buildService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/attacker-srv/salesdb/orders.read', actions: ['read'] }],
        baseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('rejects when URI cloud does not match the instance provider', async () => {
    const svc = buildService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://rds/salesserver/salesdb/orders.read', actions: ['read'] }],
        baseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('rejects when database is not declared on the instance', async () => {
    const svc = buildService();
    await expect(
      svc.mintForCapabilities(
        [{ resource: 'db://azure-sql/salesserver/secretdb/orders.read', actions: ['read'] }],
        baseCtx,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('returns undefined when no eligible db capabilities are present', async () => {
    const svc = buildService();
    expect(
      await svc.mintForCapabilities(
        [{ resource: 'api://crm/customers', actions: ['read'] }],
        baseCtx,
      ),
    ).toBeUndefined();
  });
});

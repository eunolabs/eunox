/**
 * AWS RDS / Aurora IAM-database-auth token minter.
 *
 * Uses `@aws-sdk/rds-signer` `Signer.getAuthToken({ hostname, port,
 * username, region })`. Tokens have a 15-minute hard lifetime per AWS;
 * `expiresAt` is computed as `now + 15min` since `getAuthToken` does
 * not return an expiry. Per design § 6 the test asserts that
 * hostname/port/username are wired from operator config — never from
 * agent input.
 *
 * When `assumeRoleArn` is provided the minter first calls
 * STS `AssumeRole` to obtain short-lived credentials scoped to that
 * dedicated role, then constructs the RDS signer with those credentials.
 * This keeps the DB-token IAM surface isolated from the JWT-signing
 * KMS key role and the storage-grant STS role, limiting the blast
 * radius of a compromise in this code path.
 */

import { CapabilityError, ErrorCode, DbCredential } from '@euno/common';
import { DbTokenMinter, DbTokenMintInput } from './types';

export interface RdsSignerLike {
  getAuthToken(): Promise<string>;
}

export interface RdsTokenMinterOptions {
  /**
   * IAM role ARN to assume before generating the RDS auth token.
   * When set, the minter calls STS `AssumeRole` to obtain a
   * least-privilege credential set, then passes those credentials to
   * the RDS Signer. This isolates the DB-token issuance path from the
   * issuer's ambient IAM credentials (which may include broader KMS
   * grants used for JWT signing).
   */
  assumeRoleArn?: string;
  /** Factory for the signer (mainly for tests). */
  signerFactory?: (input: {
    hostname: string;
    port: number;
    username: string;
    region: string;
    credentials?: {
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken?: string;
    };
  }) => RdsSignerLike;
  /**
   * Optional STS client factory used when `assumeRoleArn` is set.
   * Injected in tests to avoid AWS SDK calls.
   */
  stsClientFactory?: () => Promise<{
    send(cmd: { input: Record<string, unknown> }): Promise<{
      Credentials?: {
        AccessKeyId?: string;
        SecretAccessKey?: string;
        SessionToken?: string;
      };
    }>;
  }>;
  /** Override the wall clock (mainly for tests). */
  now?: () => number;
}

/** RDS IAM auth token lifetime in seconds (AWS-fixed at 15 minutes). */
export const RDS_IAM_TOKEN_LIFETIME_SECONDS = 900;

export class RdsTokenMinter implements DbTokenMinter {
  public readonly provider = 'rds-iam' as const;
  private readonly opts: RdsTokenMinterOptions;
  constructor(opts: RdsTokenMinterOptions = {}) {
    this.opts = opts;
  }
  async mint(input: DbTokenMintInput): Promise<DbCredential> {
    if (!input.instance.region) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `RDS instance '${input.instance.id}' is missing 'region' in operator config`,
        500,
      );
    }

    // When an isolated role ARN is configured, assume it first so the
    // RDS auth token is generated under the minimal least-privilege
    // role rather than the issuer's ambient credentials.
    let assumedCredentials:
      | { accessKeyId: string; secretAccessKey: string; sessionToken?: string }
      | undefined;
    if (this.opts.assumeRoleArn) {
      assumedCredentials = await this.assumeRole(
        this.opts.assumeRoleArn,
        input.instance.region,
        input.agentId,
      );
    }

    const factory = this.opts.signerFactory ?? (await loadDefaultSignerFactory());
    const signer = factory({
      hostname: input.instance.host,
      port: input.instance.port,
      username: input.dbUsername,
      region: input.instance.region,
      ...(assumedCredentials ? { credentials: assumedCredentials } : {}),
    });
    const token = await signer.getAuthToken();
    if (!token) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'RDS Signer.getAuthToken returned an empty token',
        502,
      );
    }
    const now = this.opts.now ? this.opts.now() : Date.now();
    return {
      provider: 'rds-iam',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: new Date(now + RDS_IAM_TOKEN_LIFETIME_SECONDS * 1000).toISOString(),
      host: input.instance.host,
      port: input.instance.port,
      database: input.database,
      username: input.dbUsername,
      token,
    };
  }

  /**
   * Assume the operator-configured role via STS and return the
   * temporary credentials. The role session name encodes the agent ID
   * so CloudTrail entries are attributable.
   */
  private async assumeRole(
    roleArn: string,
    region: string,
    agentId: string,
  ): Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken?: string }> {
    const sts = this.opts.stsClientFactory
      ? await this.opts.stsClientFactory()
      : await loadDefaultStsClient(region);

    // Build a session name that is CloudTrail-friendly and within the
    // 64-char STS limit (same sanitisation as the storage-grant minter).
    const sanitized = String(agentId ?? '').replace(/[^a-zA-Z0-9_=,.@-]/g, '_');
    const ts = String(this.opts.now ? this.opts.now() : Date.now());
    const prefix = 'euno-db-';
    const headroom = 64 - prefix.length - 1 - ts.length;
    const agentPart = sanitized.slice(0, Math.max(4, headroom));
    const sessionName = `${prefix}${agentPart}-${ts}`.slice(0, 64);

    const result = await sts.send({
      input: {
        RoleArn: roleArn,
        RoleSessionName: sessionName,
        // STS minimum is 900 s; the RDS auth token itself is only valid for
        // 15 min so there is no benefit in a longer session.
        DurationSeconds: RDS_IAM_TOKEN_LIFETIME_SECONDS,
      },
    });
    const creds = result.Credentials;
    if (!creds || !creds.AccessKeyId || !creds.SecretAccessKey) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'STS AssumeRole for RDS token issuance returned no credentials',
        502,
      );
    }
    return {
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.SessionToken,
    };
  }
}

async function loadDefaultSignerFactory(): Promise<NonNullable<RdsTokenMinterOptions['signerFactory']>> {
  const sdk: any = await dynamicImport('@aws-sdk/rds-signer');
  return (input) => {
    const opts: Record<string, unknown> = {
      hostname: input.hostname,
      port: input.port,
      username: input.username,
      region: input.region,
    };
    if (input.credentials) {
      opts.credentials = input.credentials;
    }
    return new sdk.Signer(opts) as RdsSignerLike;
  };
}

async function loadDefaultStsClient(region: string): Promise<{
  send(cmd: { input: Record<string, unknown> }): Promise<{
    Credentials?: {
      AccessKeyId?: string;
      SecretAccessKey?: string;
      SessionToken?: string;
    };
  }>;
}> {
  const sdk: any = await dynamicImport('@aws-sdk/client-sts');
  const client = new sdk.STSClient({ region });
  return {
    send: async ({ input }) => {
      const cmd = new sdk.AssumeRoleCommand(input);
      return await client.send(cmd);
    },
  };
}

async function dynamicImport(name: string): Promise<any> {
  try {
    return await import(name);
  } catch {
    throw new CapabilityError(
      ErrorCode.INTERNAL_ERROR,
      `Required SDK '${name}' is not installed; install it or disable DB tokens for this provider`,
      500,
    );
  }
}

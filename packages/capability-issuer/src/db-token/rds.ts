/**
 * AWS RDS / Aurora IAM-database-auth token minter.
 *
 * Uses `@aws-sdk/rds-signer` `Signer.getAuthToken({ hostname, port,
 * username, region })`. Tokens have a 15-minute hard lifetime per AWS;
 * `expiresAt` is computed as `now + 15min` since `getAuthToken` does
 * not return an expiry. Per design § 6 the test asserts that
 * hostname/port/username are wired from operator config — never from
 * agent input.
 */

import { CapabilityError, ErrorCode, DbCredential } from '@euno/common';
import { DbTokenMinter, DbTokenMintInput } from './types';

export interface RdsSignerLike {
  getAuthToken(): Promise<string>;
}

export interface RdsTokenMinterOptions {
  /** Factory for the signer (mainly for tests). */
  signerFactory?: (input: {
    hostname: string;
    port: number;
    username: string;
    region: string;
  }) => RdsSignerLike;
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
    const factory = this.opts.signerFactory ?? (await loadDefaultSignerFactory());
    const signer = factory({
      hostname: input.instance.host,
      port: input.instance.port,
      username: input.dbUsername,
      region: input.instance.region,
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
}

async function loadDefaultSignerFactory(): Promise<NonNullable<RdsTokenMinterOptions['signerFactory']>> {
  const sdk: any = await dynamicImport('@aws-sdk/rds-signer');
  return (input) => new sdk.Signer(input) as RdsSignerLike;
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

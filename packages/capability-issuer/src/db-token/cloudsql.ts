/**
 * Cloud SQL IAM-database-auth token minter.
 *
 * Uses `google-auth-library`'s `GoogleAuth` with the
 * `https://www.googleapis.com/auth/sqlservice.admin` scope to obtain
 * the OAuth2 access token Cloud SQL accepts as the connection
 * password. The same token works for the Cloud SQL Auth Proxy and for
 * direct `psql` connections (see design § Open questions).
 *
 * The agent's role-mapped `dbUsername` becomes the Postgres / MySQL
 * user — never anything taken from agent input.
 */

import { CapabilityError, ErrorCode, DbCredential } from '@euno/common';
import { DbTokenMinter, DbTokenMintInput } from './types';

export interface CloudSqlAuthClientLike {
  getAccessToken(): Promise<{ token?: string; res?: { data?: { expires_in?: number } } } | string | null>;
}

export interface CloudSqlTokenMinterOptions {
  authClientFactory?: () => Promise<CloudSqlAuthClientLike> | CloudSqlAuthClientLike;
  now?: () => number;
}

/** Default lifetime when the API does not echo `expires_in` (Cloud SQL caps tokens at 1h). */
export const CLOUD_SQL_DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

export class CloudSqlTokenMinter implements DbTokenMinter {
  public readonly provider = 'cloudsql-iam' as const;
  private readonly opts: CloudSqlTokenMinterOptions;
  constructor(opts: CloudSqlTokenMinterOptions = {}) {
    this.opts = opts;
  }
  async mint(input: DbTokenMintInput): Promise<DbCredential> {
    const client = this.opts.authClientFactory
      ? await this.opts.authClientFactory()
      : await loadDefaultClient();
    const tokenResp = await client.getAccessToken();
    let token: string | undefined;
    let expiresInSec: number | undefined;
    if (typeof tokenResp === 'string') {
      token = tokenResp;
    } else if (tokenResp && typeof tokenResp === 'object') {
      token = tokenResp.token;
      expiresInSec = tokenResp.res?.data?.expires_in;
    }
    if (!token) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Cloud SQL token source returned no token',
        502,
      );
    }
    const now = this.opts.now ? this.opts.now() : Date.now();
    const providerLifetime = expiresInSec ?? CLOUD_SQL_DEFAULT_TOKEN_LIFETIME_SECONDS;
    // Cap to the operator-configured `input.ttlSeconds` so
    // `DB_TOKEN_MAX_TTL_SECONDS` is actually enforced. We can't
    // actually shorten the OAuth token's lifetime at Google's end, but
    // the credential we hand out is annotated with the capped
    // `expiresAt` so downstream gateways/agents reject reuse beyond it.
    const lifetime = Math.min(providerLifetime, input.ttlSeconds);
    return {
      provider: 'cloudsql-iam',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: new Date(now + lifetime * 1000).toISOString(),
      host: input.instance.host,
      port: input.instance.port,
      database: input.database,
      username: input.dbUsername,
      token,
    };
  }
}

async function loadDefaultClient(): Promise<CloudSqlAuthClientLike> {
  const sdk: any = await dynamicImport('google-auth-library');
  const auth = new sdk.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/sqlservice.admin'],
  });
  const client = await auth.getClient();
  return client as CloudSqlAuthClientLike;
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

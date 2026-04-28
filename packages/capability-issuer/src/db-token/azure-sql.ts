/**
 * Azure SQL Database short-lived access token minter.
 *
 * Uses `DefaultAzureCredential.getToken('https://database.windows.net/.default')`
 * to obtain an AAD bearer token. The token's lifetime is reported by
 * the SDK and trusted as-is (never recomputed locally) per design § 6.
 *
 * `@azure/identity` is loaded via dynamic `import()` so deployments
 * without Azure SQL never pay the load cost. Tests inject a
 * `tokenSource` to bypass the dynamic import.
 */

import { CapabilityError, ErrorCode, DbCredential } from '@euno/common';
import { DbTokenMinter, DbTokenMintInput } from './types';

export interface AzureSqlTokenSource {
  getToken(scope: string): Promise<{ token: string; expiresOnTimestamp: number }>;
}

export interface AzureSqlTokenMinterOptions {
  tokenSource?: AzureSqlTokenSource;
}

export class AzureSqlTokenMinter implements DbTokenMinter {
  public readonly provider = 'azure-sql' as const;
  private readonly opts: AzureSqlTokenMinterOptions;
  constructor(opts: AzureSqlTokenMinterOptions = {}) {
    this.opts = opts;
  }
  async mint(input: DbTokenMintInput): Promise<DbCredential> {
    const source = this.opts.tokenSource ?? (await loadDefaultSource());
    const tok = await source.getToken('https://database.windows.net/.default');
    if (!tok || !tok.token) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Azure SQL token source returned no token',
        502,
      );
    }
    return {
      provider: 'azure-sql',
      resource: input.resource,
      actions: [...input.actions],
      // Trust the SDK's expiry — never recompute as `now + ttl`.
      expiresAt: new Date(tok.expiresOnTimestamp).toISOString(),
      host: input.instance.host,
      port: input.instance.port,
      database: input.database,
      username: input.dbUsername,
      token: tok.token,
    };
  }
}

async function loadDefaultSource(): Promise<AzureSqlTokenSource> {
  const sdk: any = await dynamicImport('@azure/identity');
  const cred = new sdk.DefaultAzureCredential();
  return {
    getToken: async (scope: string) => {
      const t = await cred.getToken(scope);
      if (!t) throw new Error('DefaultAzureCredential returned null token');
      return { token: t.token, expiresOnTimestamp: t.expiresOnTimestamp };
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

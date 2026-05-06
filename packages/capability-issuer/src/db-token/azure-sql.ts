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

import { CapabilityError, ErrorCode, DbCredential, generateId } from '@euno/common';
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
    // The Azure SQL AAD token lifetime is set by AAD (typically 1 hour)
    // and cannot be shortened at request time. We can't *narrow* the
    // bearer token, but we MUST refuse to hand out a credential that
    // outlives the operator-configured `DB_TOKEN_MAX_TTL_SECONDS` cap
    // (or the per-issuance `input.ttlSeconds`). Fail closed when the
    // SDK-reported expiry exceeds the cap so deployments don't silently
    // emit longer-lived DB tokens than configured.
    const now = Date.now();
    const maxAllowedExpiry = now + input.ttlSeconds * 1000;
    if (tok.expiresOnTimestamp > maxAllowedExpiry + AZURE_SQL_EXPIRY_SLACK_MS) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Azure SQL AAD token lifetime exceeds the configured DB-token cap ` +
          `(token expires at ${new Date(tok.expiresOnTimestamp).toISOString()}, ` +
          `cap is ${new Date(maxAllowedExpiry).toISOString()}). ` +
          `Lower DB_TOKEN_MAX_TTL_SECONDS only when AAD can issue a token of that lifetime, ` +
          `or refuse the request.`,
        500,
      );
    }
    return {
      grantId: generateId(),
      provider: 'azure-sql',
      resource: input.resource,
      actions: [...input.actions],
      // Trust the SDK's expiry — never recompute as `now + ttl` —
      // because the bearer token itself is bound to the AAD-reported
      // exp claim and the database server validates that.
      expiresAt: new Date(tok.expiresOnTimestamp).toISOString(),
      host: input.instance.host,
      port: input.instance.port,
      database: input.database,
      username: input.dbUsername,
      token: tok.token,
    };
  }
}

/**
 * Tolerance applied when comparing the AAD-reported token expiry to the
 * operator-configured cap. AAD expiries land on second boundaries while
 * `Date.now()` is millisecond-resolution and small clock differences are
 * not security-relevant; treating ≤5 s of overshoot as "within cap"
 * avoids spurious failures on a normal AAD response.
 */
const AZURE_SQL_EXPIRY_SLACK_MS = 5_000;

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

/**
 * Per-tenant IdP configuration registry.
 *
 * Allows different tenants to authenticate via different identity providers
 * (Azure AD vs. AWS Cognito vs. GCP Cloud Identity) without restarting the
 * issuer. The registry is loaded from a JSON file at startup and reloaded
 * automatically on SIGHUP.
 *
 * ### File format
 *
 * ```json
 * {
 *   "tenants": {
 *     "tenant-abc": {
 *       "provider": "azure-ad",
 *       "azureAD": {
 *         "tenantId": "11111111-...",
 *         "clientId": "22222222-...",
 *         "clientSecret": "..."
 *       }
 *     },
 *     "tenant-xyz": {
 *       "provider": "aws-cognito",
 *       "awsCognito": {
 *         "region": "us-east-1",
 *         "userPoolId": "us-east-1_AbCdEfGhI",
 *         "clientId": "...",
 *         "clientSecret": "..."
 *       }
 *     }
 *   }
 * }
 * ```
 *
 * If the file is absent, or a tenantId is not found in the file, the registry
 * falls back to the global {@link IdentityAdapter} configured via
 * `IDENTITY_PROVIDER` / `AZURE_AD_TENANT_ID` / `AWS_COGNITO_*` etc.
 */

import fs from 'fs';
import {
  IdentityAdapter,
  AzureADConfig,
  AWSCognitoConfig,
  GCPIdentityConfig,
} from '@euno/common';
import { AzureADIdentityProvider } from './azure-identity-provider';
import { AWSCognitoIdentityProvider } from './aws-cognito-identity-provider';
import { GCPIdentityProvider } from './gcp-identity-provider';

// ---------------------------------------------------------------------------
// Serialised per-tenant config format
// ---------------------------------------------------------------------------

export interface TenantAzureAdEntry {
  provider: 'azure-ad';
  azureAD: AzureADConfig;
}

export interface TenantCognitoEntry {
  provider: 'aws-cognito';
  awsCognito: AWSCognitoConfig;
}

export interface TenantGcpEntry {
  provider: 'gcp-identity';
  gcpIdentity: GCPIdentityConfig;
}

export type TenantIdpEntry = TenantAzureAdEntry | TenantCognitoEntry | TenantGcpEntry;

export interface TenantIdpConfigFile {
  tenants: Record<string, TenantIdpEntry>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Registry of per-tenant identity adapters.
 *
 * Instantiating it is cheap: adapters are constructed lazily on first use and
 * cached for the lifetime of the registry instance (or until the next reload).
 */
export class TenantIdpRegistry {
  /** Raw per-tenant entries loaded from the config file. */
  private tenantEntries: Record<string, TenantIdpEntry> = {};
  /** Lazy-initialised adapter cache; cleared on reload. */
  private adapterCache = new Map<string, IdentityAdapter>();
  /** SIGHUP handler reference, stored so tests can remove it. */
  private readonly sigHupHandler: () => void;

  constructor(
    private readonly configFilePath: string | undefined,
    private readonly logger: { info: (msg: string, meta?: object) => void; warn: (msg: string, meta?: object) => void; error: (msg: string, meta?: object) => void },
  ) {
    this.sigHupHandler = () => {
      logger.info('SIGHUP received — reloading per-tenant IdP config');
      this.reload();
    };
    process.on('SIGHUP', this.sigHupHandler);
    if (configFilePath) {
      this.reload();
    }
  }

  /**
   * Remove the SIGHUP handler. Call during graceful shutdown or in tests that
   * instantiate the registry directly.
   */
  destroy(): void {
    process.removeListener('SIGHUP', this.sigHupHandler);
  }

  /**
   * Returns the number of tenant entries currently loaded.
   */
  get size(): number {
    return Object.keys(this.tenantEntries).length;
  }

  /**
   * Reload tenant entries from the configured file path.
   * On parse error the previous entries are preserved and the error is logged.
   */
  reload(): void {
    if (!this.configFilePath) return;
    try {
      const raw = fs.readFileSync(this.configFilePath, 'utf-8');
      const parsed: unknown = JSON.parse(raw);
      const config = this.validate(parsed);
      this.tenantEntries = config.tenants;
      // Invalidate the adapter cache so updated configs are picked up.
      this.adapterCache.clear();
      this.logger.info('Per-tenant IdP config loaded', {
        path: this.configFilePath,
        tenants: Object.keys(this.tenantEntries).length,
      });
    } catch (err) {
      this.logger.error('Failed to load per-tenant IdP config — keeping previous config', {
        path: this.configFilePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Returns a per-tenant {@link IdentityAdapter} for `tenantId`, or
   * `undefined` if no tenant-specific config exists (caller should fall back
   * to the global adapter).
   */
  getAdapter(tenantId: string): IdentityAdapter | undefined {
    const cached = this.adapterCache.get(tenantId);
    if (cached) return cached;

    const entry = this.tenantEntries[tenantId];
    if (!entry) return undefined;

    const adapter = this.buildAdapter(tenantId, entry);
    this.adapterCache.set(tenantId, adapter);
    return adapter;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private validate(raw: unknown): TenantIdpConfigFile {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('Per-tenant IdP config must be a JSON object');
    }
    const obj = raw as Record<string, unknown>;
    if (!obj['tenants'] || typeof obj['tenants'] !== 'object' || Array.isArray(obj['tenants'])) {
      throw new Error('Per-tenant IdP config must have a "tenants" object field');
    }
    const tenants = obj['tenants'] as Record<string, unknown>;
    for (const [tenantId, entry] of Object.entries(tenants)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new Error(`Tenant "${tenantId}": entry must be an object`);
      }
      const e = entry as Record<string, unknown>;
      if (!['azure-ad', 'aws-cognito', 'gcp-identity'].includes(e['provider'] as string)) {
        throw new Error(
          `Tenant "${tenantId}": provider must be one of azure-ad, aws-cognito, gcp-identity`,
        );
      }
    }
    return { tenants: tenants as Record<string, TenantIdpEntry> };
  }

  private buildAdapter(tenantId: string, entry: TenantIdpEntry): IdentityAdapter {
    switch (entry.provider) {
      case 'azure-ad':
        return new AzureADIdentityProvider({
          type: 'azure-ad',
          name: `azure-ad[${tenantId}]`,
          azureAD: entry.azureAD,
        });
      case 'aws-cognito':
        return new AWSCognitoIdentityProvider({
          type: 'aws-cognito',
          name: `aws-cognito[${tenantId}]`,
          awsCognito: entry.awsCognito,
        });
      case 'gcp-identity':
        return new GCPIdentityProvider({
          type: 'gcp-identity',
          name: `gcp-identity[${tenantId}]`,
          gcpIdentity: entry.gcpIdentity,
        });
      default:
        // Should be unreachable: validateConfig rejects unknown providers.
        throw new Error(
          `Tenant "${tenantId}": unsupported provider "${(entry as TenantIdpEntry).provider}"`,
        );
    }
  }
}

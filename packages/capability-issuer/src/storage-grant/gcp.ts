/**
 * GCP Cloud Storage grant minter.
 *
 * Two issuance paths per
 * `docs/sprint-3-4-gaps/07-storage-grants.md` § 3 / GCP-specific:
 *  - **Single-object** → `bucket.file(name).getSignedUrl(...)` per
 *    permitted method.
 *  - **Wildcard / prefix** → Credential Access Boundaries via the
 *    `google-auth-library` `DownscopedClient`, bounding a service-account
 *    token to the prefix.
 *
 * SDKs are loaded via dynamic `import()` so an Azure- or AWS-only
 * deployment can omit them. Tests inject a `clientFactory` to bypass
 * the dynamic import entirely.
 */

import { CapabilityError, ErrorCode, StorageGrant } from '@euno/common';
import { ParsedStorageUri } from './types';
import {
  StorageGrantMinter,
  StorageGrantMintInput,
  STORAGE_ACTION_MAP,
} from './types';
import { parseStorageUri } from './parse-uri';

/** Minimal subset of `@google-cloud/storage` we depend on. */
export interface GcsBucketLike {
  file(name: string): {
    getSignedUrl(opts: { action: 'read' | 'write' | 'delete'; expires: number | Date }): Promise<[string]>;
  };
}
export interface GcsClientLike {
  bucket(name: string): GcsBucketLike;
}

/** Minimal subset of `google-auth-library`'s downscoped client. */
export interface GcsDownscopedTokenSource {
  /** Returns the OAuth2 access token + expiry. */
  mint(input: {
    bucket: string;
    prefix: string;
    ttlSeconds: number;
  }): Promise<{ token: string; expiresAt: Date; availabilityCondition?: string }>;
}

export interface GcpStorageGrantMinterOptions {
  /** Override the storage client (mainly for tests). */
  storageClientFactory?: () => Promise<GcsClientLike> | GcsClientLike;
  /** Override the downscoped-token source (mainly for tests). */
  downscopedTokenSource?: GcsDownscopedTokenSource;
}

export class GcpStorageGrantMinter implements StorageGrantMinter {
  public readonly provider = 'gcs' as const;
  private readonly opts: GcpStorageGrantMinterOptions;

  constructor(opts: GcpStorageGrantMinterOptions = {}) {
    this.opts = opts;
  }

  async mint(input: StorageGrantMintInput): Promise<StorageGrant> {
    const parsed = parseStorageUri(input.resource);
    if (!parsed || parsed.cloud !== 'gcs') {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `GCP storage-grant minter cannot handle resource: ${input.resource}`,
        400,
      );
    }
    const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();

    if (parsed.isWildcard) {
      return this.mintDownscoped(parsed, input, expiresAt);
    }
    return this.mintSigned(parsed, input);
  }

  private async mintSigned(
    parsed: ParsedStorageUri,
    input: StorageGrantMintInput,
  ): Promise<StorageGrant> {
    const methods = mapActionsToGcsMethods(input.actions);
    if (methods.length === 0) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `No GCS methods map to actions: ${input.actions.join(',')}`,
        400,
      );
    }
    const client = this.opts.storageClientFactory
      ? await this.opts.storageClientFactory()
      : await loadGcsClient();
    const bucket = client.bucket(parsed.bucket);
    const file = bucket.file(parsed.keyOrPrefix);
    const expires = Date.now() + input.ttlSeconds * 1000;
    const signed: { method: 'GET' | 'PUT' | 'DELETE'; url: string }[] = [];
    for (const m of methods) {
      const action = m === 'GET' ? 'read' : m === 'PUT' ? 'write' : 'delete';
      const [url] = await file.getSignedUrl({ action, expires });
      signed.push({ method: m, url });
    }
    return {
      provider: 'gcs',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: new Date(expires).toISOString(),
      gcsSigned: signed,
    };
  }

  private async mintDownscoped(
    parsed: ParsedStorageUri,
    input: StorageGrantMintInput,
    fallbackExpiresAt: string,
  ): Promise<StorageGrant> {
    const source = this.opts.downscopedTokenSource ?? (await loadDefaultDownscopedSource());
    const minted = await source.mint({
      bucket: parsed.bucket,
      prefix: parsed.keyOrPrefix,
      ttlSeconds: input.ttlSeconds,
    });
    const grant: StorageGrant = {
      provider: 'gcs',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: minted.expiresAt ? minted.expiresAt.toISOString() : fallbackExpiresAt,
      gcsDownscoped: {
        accessToken: minted.token,
        bucket: parsed.bucket,
        ...(parsed.keyOrPrefix ? { prefix: parsed.keyOrPrefix } : {}),
        ...(minted.availabilityCondition
          ? { availabilityCondition: minted.availabilityCondition }
          : {}),
      },
    };
    return grant;
  }
}

function mapActionsToGcsMethods(actions: string[]): ('GET' | 'PUT' | 'DELETE')[] {
  const map = STORAGE_ACTION_MAP['gcs'];
  const methods: ('GET' | 'PUT' | 'DELETE')[] = [];
  for (const a of actions) {
    const op = map[a];
    if (op === 'GetObject' && !methods.includes('GET')) methods.push('GET');
    if (op === 'PutObject' && !methods.includes('PUT')) methods.push('PUT');
    if (op === 'DeleteObject' && !methods.includes('DELETE')) methods.push('DELETE');
  }
  return methods;
}

async function loadGcsClient(): Promise<GcsClientLike> {
  const sdk: any = await dynamicImport('@google-cloud/storage');
  return new sdk.Storage() as GcsClientLike;
}

async function loadDefaultDownscopedSource(): Promise<GcsDownscopedTokenSource> {
  const auth: any = await dynamicImport('google-auth-library');
  return {
    mint: async ({ bucket, prefix, ttlSeconds }) => {
      const client = new auth.GoogleAuth({
        scopes: ['https://www.googleapis.com/auth/devstorage.read_write'],
      }).getClient();
      const source = await client;
      const tokenResp = await source.getAccessToken();
      // Single source of truth for the CEL expression so the policy and
      // the response stay in lockstep.
      const availabilityCondition = prefix
        ? `resource.name.startsWith('projects/_/buckets/${bucket}/objects/${prefix}/')`
        : undefined;
      // Build a Credential Access Boundary policy and mint a downscoped token.
      const cab = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availablePermissions: [
                'inRole:roles/storage.objectViewer',
                'inRole:roles/storage.objectCreator',
              ],
              availableResource: `//storage.googleapis.com/projects/_/buckets/${bucket}`,
              availabilityCondition: availabilityCondition
                ? { title: 'PrefixScope', expression: availabilityCondition }
                : undefined,
            },
          ],
        },
      };
      const downscopedClient = new auth.DownscopedClient(source, cab);
      const downTok = await downscopedClient.getAccessToken();
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      return {
        token: downTok.token ?? tokenResp.token ?? '',
        expiresAt,
        availabilityCondition,
      };
    },
  };
}

async function dynamicImport(name: string): Promise<any> {
  try {
    return await import(name);
  } catch {
    throw new CapabilityError(
      ErrorCode.INTERNAL_ERROR,
      `Required SDK '${name}' is not installed; install it or disable storage grants for this provider`,
      500,
    );
  }
}

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
    /** Capability actions — drives `availablePermissions` in the CAB. */
    actions: string[];
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
      actions: input.actions,
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
    mint: async ({ bucket, prefix, ttlSeconds, actions }) => {
      const client = new auth.GoogleAuth({
        scopes: ['https://www.googleapis.com/auth/devstorage.read_write'],
      }).getClient();
      const sourceClient = await client;
      // Single source of truth for the CEL expression so the policy and
      // the response stay in lockstep. The prefix is escaped because it
      // can legally contain `'` or `\` — unescaped interpolation would
      // either break the expression or, worse, allow a crafted resource
      // URI to broaden the access boundary via CEL injection.
      const availabilityCondition = prefix
        ? `resource.name.startsWith('projects/_/buckets/${bucket}/objects/${escapeCelStringLiteral(prefix)}/')`
        : undefined;
      // Derive `availablePermissions` from the capability's actions so a
      // read-only capability cannot mint a token authorized to write.
      // Falling back to the legacy "viewer + creator" pair would silently
      // broaden the grant beyond what the capability allowed.
      const availablePermissions = mapActionsToGcsRoles(actions);
      if (availablePermissions.length === 0) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `No GCS roles map to capability actions: ${actions.join(',')}`,
          400,
        );
      }
      // Build a Credential Access Boundary policy and mint a downscoped token.
      const cab = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availablePermissions,
              availableResource: `//storage.googleapis.com/projects/_/buckets/${bucket}`,
              availabilityCondition: availabilityCondition
                ? { title: 'PrefixScope', expression: availabilityCondition }
                : undefined,
            },
          ],
        },
      };
      const downscopedClient = new auth.DownscopedClient(sourceClient, cab);
      const downTok = await downscopedClient.getAccessToken();
      // Never fall back to the source (un-downscoped) token — that would
      // hand out a credential broader than the capability authorized.
      const token = typeof downTok?.token === 'string' ? downTok.token : '';
      if (!token) {
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          'GCS DownscopedClient returned no token; refusing to fall back to source credentials',
          502,
        );
      }
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      return {
        token,
        expiresAt,
        availabilityCondition,
      };
    },
  };
}

/**
 * Map capability actions to GCS IAM roles for use in a Credential
 * Access Boundary's `availablePermissions` list. Read maps to
 * objectViewer; write/delete map to objectAdmin (the smallest standard
 * role that includes object create/delete; objectCreator alone cannot
 * delete). list is included in objectViewer so it does not add a role.
 *
 * Exported for unit testing — production callers reach this via
 * {@link loadDefaultDownscopedSource} only.
 */
export function mapActionsToGcsRoles(actions: string[]): string[] {
  const roles: string[] = [];
  const has = (a: string) => actions.includes(a);
  if (has('read') || has('list')) {
    roles.push('inRole:roles/storage.objectViewer');
  }
  if (has('write') || has('delete')) {
    // objectAdmin = create + delete + list + read on objects in the bucket.
    // The CAB's availabilityCondition still scopes this to the prefix.
    roles.push('inRole:roles/storage.objectAdmin');
  }
  return roles;
}

/**
 * Escape a string for safe embedding inside a single-quoted CEL string
 * literal. CEL string literals follow the same escape rules as Python:
 * `\` and `'` MUST be escaped; `\n`, `\r`, `\t` are escaped to keep the
 * one-line condition readable. Anything else passes through unchanged.
 *
 * Exported for unit testing.
 */
export function escapeCelStringLiteral(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
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

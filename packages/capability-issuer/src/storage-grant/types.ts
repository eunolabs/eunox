/**
 * Shared types for the storage-grant minter pipeline. See
 * `docs/sprint-3-4-gaps/07-storage-grants.md` for the design.
 */

import { Action, ResourceId, StorageGrant, StorageProvider } from '@euno/common';

/**
 * Canonical-form storage URI as parsed by {@link parseStorageUri}.
 * `storage://{cloud}/{account-or-bucket}/{key-or-prefix}`. The
 * `keyOrPrefix` is `''` when the URI targets the bucket root.
 */
export interface ParsedStorageUri {
  raw: ResourceId;
  cloud: StorageProvider;
  /** Storage account (Azure) or bucket name (S3 / GCS). */
  bucket: string;
  /**
   * Object key (single-object grant) or prefix (multi-object grant).
   * Empty string when the URI targets the bucket root with no prefix.
   */
  keyOrPrefix: string;
  /** True when the URI ends in `/*` or `/**` (multi-object). */
  isWildcard: boolean;
  /** Wildcard kind, when `isWildcard` is true. */
  wildcardKind?: 'single-segment' | 'recursive';
}

/** Input passed to every {@link StorageGrantMinter}. */
export interface StorageGrantMintInput {
  resource: ResourceId;
  actions: Action[];
  ttlSeconds: number;
  /** Requesting agent identifier — used for audit + key naming. */
  agentId: string;
  /** Subject of the user authentication token that authorized issuance. */
  authorizedBy: string;
}

/**
 * Provider-specific minter contract. Each cloud provider implementation
 * (Azure / AWS / GCP) exposes one of these. The factory in `index.ts`
 * dispatches to the correct minter based on the parsed URI's `cloud`.
 */
export interface StorageGrantMinter {
  /** Cloud this minter handles. */
  readonly provider: StorageProvider;
  mint(input: StorageGrantMintInput): Promise<StorageGrant>;
}

/** Maps euno generic actions to provider-specific permission letters. */
export const STORAGE_ACTION_MAP = {
  'azure-blob': { read: 'r', write: 'w', delete: 'd', list: 'l' } as Record<string, string>,
  s3: {
    read: 'GetObject',
    write: 'PutObject',
    delete: 'DeleteObject',
    list: 'ListBucket',
  } as Record<string, string>,
  gcs: {
    read: 'GetObject',
    write: 'PutObject',
    delete: 'DeleteObject',
    list: 'ListBucket',
  } as Record<string, string>,
} as const;

/** Hard ceiling on storage-grant TTL (1 hour) regardless of operator config. */
export const STORAGE_GRANT_HARD_MAX_TTL_SECONDS = 3600;
/** Default operator cap when `STORAGE_GRANT_MAX_TTL_SECONDS` is unset (15 min). */
export const STORAGE_GRANT_DEFAULT_MAX_TTL_SECONDS = 900;

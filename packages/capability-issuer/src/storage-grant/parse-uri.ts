/**
 * Storage-grant URI parser. Recognizes the canonical
 * `storage://{cloud}/{bucket}/{key-or-prefix}` form documented in
 * `docs/sprint-3-4-gaps/07-storage-grants.md` § 1.
 *
 * Returns `null` for any URI that is not a `storage://...` resource or
 * does not match the canonical form. The issuer treats `null` as
 * "no grant required for this capability" rather than as an error so
 * non-storage capabilities and legacy free-form `storage://` patterns
 * continue to work for capability validation alone.
 */

import { ResourceId, StorageProvider } from '@euno/common';
import { ParsedStorageUri } from './types';

const VALID_CLOUDS: ReadonlySet<StorageProvider> = new Set(['azure-blob', 's3', 'gcs']);

/**
 * Mapping of the user-facing cloud token in the URI (`azure` / `aws` /
 * `gcp`) to the {@link StorageProvider} value used internally. The
 * URI form keeps the short token because the design doc's examples use
 * it (`storage://azure/...`) and operators reading the URI shouldn't
 * have to know our internal provider names.
 */
const URI_CLOUD_TO_PROVIDER: Record<string, StorageProvider> = {
  azure: 'azure-blob',
  aws: 's3',
  gcp: 'gcs',
};

/**
 * Parse a `storage://...` URI into a {@link ParsedStorageUri}, or return
 * `null` if the URI is not eligible for grant minting.
 */
export function parseStorageUri(resource: ResourceId): ParsedStorageUri | null {
  if (typeof resource !== 'string' || !resource.startsWith('storage://')) {
    return null;
  }
  // Reject anything containing `..` so a non-canonical form can't slip
  // through and reach the cloud SDK with a traversal payload. The
  // capability validator already rejects this for new resources, but
  // guard at the parser too in case a legacy resource sneaks in.
  if (resource.includes('..')) {
    return null;
  }
  const rest = resource.slice('storage://'.length);
  const parts = rest.split('/');
  if (parts.length < 2) {
    return null;
  }
  const cloudToken = parts[0];
  const bucket = parts[1];
  if (!cloudToken || !bucket) {
    return null;
  }
  const provider = URI_CLOUD_TO_PROVIDER[cloudToken];
  if (!provider || !VALID_CLOUDS.has(provider)) {
    return null;
  }
  const remainder = parts.slice(2);

  let isWildcard = false;
  let wildcardKind: ParsedStorageUri['wildcardKind'] = undefined;
  // Detect trailing /* or /** as the only legal wildcards (matches
  // `validateResourcePattern` semantics).
  if (remainder.length > 0) {
    const last = remainder[remainder.length - 1];
    if (last === '**') {
      isWildcard = true;
      wildcardKind = 'recursive';
      remainder.pop();
    } else if (last === '*') {
      isWildcard = true;
      wildcardKind = 'single-segment';
      remainder.pop();
    }
  }
  // Any embedded `*` after stripping the trailing wildcard is non-canonical.
  if (remainder.some((seg) => seg.includes('*'))) {
    return null;
  }

  const keyOrPrefix = remainder.join('/');
  const result: ParsedStorageUri = {
    raw: resource,
    cloud: provider,
    bucket,
    keyOrPrefix,
    isWildcard,
  };
  if (wildcardKind) {
    result.wildcardKind = wildcardKind;
  }
  return result;
}

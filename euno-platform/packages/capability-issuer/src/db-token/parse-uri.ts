/**
 * DB-resource URI parser. Recognizes the canonical
 * `db://{cloud}/{instance}/{database}/{schema-or-table}.{action}` form
 * documented in `docs/sprint-3-4-gaps/08-db-token-issuance.md` § 1.
 *
 * Returns `null` when the URI is not eligible for token minting (not a
 * `db://` resource, missing required segments, or unsupported cloud).
 * The issuer treats `null` as "no token required for this capability".
 */

import { ResourceId, DbProvider } from '@euno/common';
import { ParsedDbUri } from './types';

const URI_CLOUD_TO_PROVIDER: Record<string, DbProvider> = {
  'azure-sql': 'azure-sql',
  rds: 'rds-iam',
  'rds-iam': 'rds-iam',
  cloudsql: 'cloudsql-iam',
  'cloudsql-iam': 'cloudsql-iam',
};

export function parseDbUri(resource: ResourceId): ParsedDbUri | null {
  if (typeof resource !== 'string' || !resource.startsWith('db://')) {
    return null;
  }
  if (resource.includes('..') || resource.includes('*')) {
    // Wildcard DB capabilities are not supported for token minting — the
    // database engine cannot scope an IAM token to a wildcard set of
    // databases. Capability validation may still permit them.
    return null;
  }
  const rest = resource.slice('db://'.length);
  const parts = rest.split('/');
  if (parts.length < 4) return null;
  const cloud = URI_CLOUD_TO_PROVIDER[parts[0] ?? ''];
  if (!cloud) return null;
  const instance = parts[1];
  const database = parts[2];
  const objectAndAction = parts.slice(3).join('/');
  if (!instance || !database || !objectAndAction) return null;
  return { raw: resource, cloud, instance, database, objectAndAction };
}

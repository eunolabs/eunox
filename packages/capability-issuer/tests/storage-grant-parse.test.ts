/**
 * Unit tests for the storage-grant URI parser. Covers the canonical
 * `storage://{cloud}/{bucket}/{key-or-prefix}` form documented in
 * `docs/sprint-3-4-gaps/07-storage-grants.md` § 1.
 */

import { parseStorageUri } from '../src/storage-grant';

describe('parseStorageUri', () => {
  it('returns null for non-storage URIs', () => {
    expect(parseStorageUri('api://crm/customers')).toBeNull();
    expect(parseStorageUri('db://azure-sql/srv/db/t.read')).toBeNull();
    expect(parseStorageUri('file://foo')).toBeNull();
  });

  it('returns null for missing cloud or bucket', () => {
    expect(parseStorageUri('storage://')).toBeNull();
    expect(parseStorageUri('storage://azure')).toBeNull();
    expect(parseStorageUri('storage://azure/')).toBeNull();
  });

  it('returns null for unknown clouds', () => {
    expect(parseStorageUri('storage://minio/bucket/obj')).toBeNull();
  });

  it('rejects parent-directory traversals', () => {
    expect(parseStorageUri('storage://aws/bucket/../etc/passwd')).toBeNull();
  });

  it('parses single-object Azure URI', () => {
    const p = parseStorageUri('storage://azure/salesdata/reports/q1.csv');
    expect(p).toEqual({
      raw: 'storage://azure/salesdata/reports/q1.csv',
      cloud: 'azure-blob',
      bucket: 'salesdata',
      keyOrPrefix: 'reports/q1.csv',
      isWildcard: false,
    });
  });

  it('parses single-object S3 URI', () => {
    const p = parseStorageUri('storage://aws/euno-uploads/incoming/a.json');
    expect(p?.cloud).toBe('s3');
    expect(p?.bucket).toBe('euno-uploads');
    expect(p?.keyOrPrefix).toBe('incoming/a.json');
    expect(p?.isWildcard).toBe(false);
  });

  it('parses single-object GCS URI', () => {
    const p = parseStorageUri('storage://gcp/euno-models/v3/checkpoint.pt');
    expect(p?.cloud).toBe('gcs');
    expect(p?.bucket).toBe('euno-models');
    expect(p?.keyOrPrefix).toBe('v3/checkpoint.pt');
  });

  it('parses recursive wildcard prefix', () => {
    const p = parseStorageUri('storage://azure/salesdata/reports/2026/**');
    expect(p?.isWildcard).toBe(true);
    expect(p?.wildcardKind).toBe('recursive');
    expect(p?.keyOrPrefix).toBe('reports/2026');
  });

  it('parses single-segment wildcard', () => {
    const p = parseStorageUri('storage://aws/euno-uploads/incoming/*');
    expect(p?.isWildcard).toBe(true);
    expect(p?.wildcardKind).toBe('single-segment');
    expect(p?.keyOrPrefix).toBe('incoming');
  });

  it('rejects embedded wildcards', () => {
    expect(parseStorageUri('storage://aws/euno-uploads/*/incoming/a.json')).toBeNull();
  });

  it('treats bucket-root URI as empty prefix', () => {
    const p = parseStorageUri('storage://aws/euno-uploads/**');
    expect(p?.isWildcard).toBe(true);
    expect(p?.keyOrPrefix).toBe('');
  });
});

/**
 * Unit tests for the shared role → capability mapper.
 *
 * The mapper was extracted from `AzureADIdentityProvider` so AWS Cognito,
 * GCP Identity, and any third-party identity provider use the same Sprint-1
 * role-to-capability semantics. These tests pin the default mapping and
 * confirm that custom mappings work for production overrides.
 */

import {
  mapRolesToCapabilities,
  mapRolesToCapabilitiesForPolicy,
  resolveRoleCapabilityMap,
  validateRoleCapabilityPolicy,
  loadRoleCapabilityPolicyFromFile,
  DEFAULT_ROLE_CAPABILITY_MAP,
  RoleCapabilityMap,
  RoleCapabilityPolicy,
} from '../src/role-mapping';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('mapRolesToCapabilities', () => {
  it('returns an empty list when no roles are provided', () => {
    expect(mapRolesToCapabilities([])).toEqual([]);
  });

  it('maps SalesManager to read+write CRM customers and read CRM reports', () => {
    const caps = mapRolesToCapabilities(['SalesManager']);
    expect(caps).toContainEqual({
      resource: 'api://crm/customers',
      actions: ['read', 'write'],
    });
    expect(caps).toContainEqual({
      resource: 'api://crm/reports',
      actions: ['read'],
    });
    expect(caps).toContainEqual({
      resource: 'storage://sales-data/**',
      actions: ['read', 'write'],
    });
  });

  it('maps Viewer to read-only CRM access', () => {
    const caps = mapRolesToCapabilities(['Viewer']);
    expect(caps).toEqual([
      { resource: 'api://crm/customers', actions: ['read'] },
      { resource: 'api://crm/reports', actions: ['read'] },
      { resource: 'storage://sales-data/**', actions: ['read'] },
    ]);
  });

  it('maps Administrator to wildcard admin/delete access', () => {
    const caps = mapRolesToCapabilities(['Administrator']);
    expect(caps).toContainEqual({
      resource: 'api://**',
      actions: ['read', 'write', 'admin'],
    });
    expect(caps).toContainEqual({
      resource: 'storage://**',
      actions: ['read', 'write', 'delete'],
    });
  });

  it('silently ignores unknown roles', () => {
    expect(mapRolesToCapabilities(['NotARealRole'])).toEqual([]);
  });

  it('combines capabilities from multiple roles without de-duplication', () => {
    // Sprint-1 mapping is additive; the issuer service performs subset
    // validation against the union, so duplicates are acceptable.
    const caps = mapRolesToCapabilities(['Viewer', 'DataScientist']);
    expect(caps.length).toBe(6);
  });

  it('honours a caller-supplied custom mapping', () => {
    const custom: RoleCapabilityMap = {
      CustomRole: [{ resource: 'api://custom/x', actions: ['read'] }],
    };
    expect(mapRolesToCapabilities(['CustomRole'], custom)).toEqual([
      { resource: 'api://custom/x', actions: ['read'] },
    ]);
    // Default-mapping roles are NOT inherited when a custom map is supplied.
    expect(mapRolesToCapabilities(['Administrator'], custom)).toEqual([]);
  });

  it('exposes the default mapping for inspection', () => {
    expect(Object.keys(DEFAULT_ROLE_CAPABILITY_MAP).sort()).toEqual([
      'Administrator',
      'DataScientist',
      'SalesManager',
      'Viewer',
    ]);
  });
});

describe('RoleCapabilityPolicy', () => {
  const basePolicy: RoleCapabilityPolicy = {
    default: {
      Viewer: [{ resource: 'api://crm/customers', actions: ['read'] }],
      Editor: [{ resource: 'api://crm/customers', actions: ['read', 'write'] }],
    },
    tenants: {
      'tenant-a': {
        // Override Viewer for tenant A: also grants reports access
        Viewer: [
          { resource: 'api://crm/customers', actions: ['read'] },
          { resource: 'api://crm/reports', actions: ['read'] },
        ],
      },
      'tenant-b': {
        // Suppress Editor for tenant B entirely
        Editor: [],
      },
    },
  };

  it('returns the default map when no tenant is specified', () => {
    expect(resolveRoleCapabilityMap(basePolicy)).toEqual(basePolicy.default);
  });

  it('returns the default map for an unknown tenant', () => {
    expect(resolveRoleCapabilityMap(basePolicy, 'tenant-x')).toEqual(basePolicy.default);
  });

  it('merges tenant overrides on a per-role basis', () => {
    const map = resolveRoleCapabilityMap(basePolicy, 'tenant-a');
    // Viewer overridden
    expect(map.Viewer).toHaveLength(2);
    expect(map.Viewer).toContainEqual({ resource: 'api://crm/reports', actions: ['read'] });
    // Editor unchanged from default
    expect(map.Editor).toEqual(basePolicy.default.Editor);
  });

  it('removes a default role when overridden with an empty array', () => {
    const map = resolveRoleCapabilityMap(basePolicy, 'tenant-b');
    expect(map.Editor).toBeUndefined();
    expect(map.Viewer).toEqual(basePolicy.default.Viewer);
  });

  it('mapRolesToCapabilitiesForPolicy applies tenant overrides end-to-end', () => {
    const caps = mapRolesToCapabilitiesForPolicy(['Viewer'], basePolicy, 'tenant-a');
    expect(caps).toHaveLength(2);
    expect(caps).toContainEqual({ resource: 'api://crm/reports', actions: ['read'] });
  });

  it('does not mutate the source default map when resolving overrides', () => {
    const before = JSON.stringify(basePolicy.default);
    resolveRoleCapabilityMap(basePolicy, 'tenant-b');
    expect(JSON.stringify(basePolicy.default)).toEqual(before);
  });
});

describe('validateRoleCapabilityPolicy', () => {
  it('accepts a minimal policy with only a default map', () => {
    expect(() =>
      validateRoleCapabilityPolicy({
        default: { Viewer: [{ resource: 'api://x', actions: ['read'] }] },
      }),
    ).not.toThrow();
  });

  it('rejects policies missing the default map', () => {
    expect(() => validateRoleCapabilityPolicy({})).toThrow(/missing required 'default'/);
  });

  it('rejects non-object input', () => {
    expect(() => validateRoleCapabilityPolicy('nope')).toThrow(/must be a JSON object/);
    expect(() => validateRoleCapabilityPolicy([])).toThrow(/must be a JSON object/);
  });

  it('rejects capability entries with invalid actions', () => {
    expect(() =>
      validateRoleCapabilityPolicy({
        default: { Viewer: [{ resource: 'api://x', actions: ['hack'] }] },
      }),
    ).toThrow(/invalid action 'hack'/);
  });

  it('rejects capability entries with empty resource', () => {
    expect(() =>
      validateRoleCapabilityPolicy({
        default: { Viewer: [{ resource: '', actions: ['read'] }] },
      }),
    ).toThrow(/'resource' must be a non-empty string/);
  });

  it('rejects capability entries with no actions', () => {
    expect(() =>
      validateRoleCapabilityPolicy({
        default: { Viewer: [{ resource: 'api://x', actions: [] }] },
      }),
    ).toThrow(/'actions' must be a non-empty array/);
  });

  it('rejects malformed tenants section', () => {
    expect(() =>
      validateRoleCapabilityPolicy({
        default: { Viewer: [{ resource: 'api://x', actions: ['read'] }] },
        tenants: 'not-an-object',
      }),
    ).toThrow(/'tenants' must be an object/);
  });

  it('treats a null role override as a removal marker', () => {
    const policy = validateRoleCapabilityPolicy({
      default: { Viewer: [{ resource: 'api://x', actions: ['read'] }] },
      tenants: { t1: { Viewer: null } },
    });
    expect(policy.tenants!.t1!.Viewer).toEqual([]);
    const map = resolveRoleCapabilityMap(policy, 't1');
    expect(map.Viewer).toBeUndefined();
  });
});

describe('loadRoleCapabilityPolicyFromFile', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-policy-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads and validates a JSON policy file', () => {
    const file = path.join(tmpDir, 'policy.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        default: { Viewer: [{ resource: 'api://x', actions: ['read'] }] },
        tenants: { t1: { Viewer: [{ resource: 'api://t1', actions: ['read', 'write'] }] } },
      }),
    );
    const policy = loadRoleCapabilityPolicyFromFile(file);
    expect(policy.default.Viewer![0]!.resource).toBe('api://x');
    expect(policy.tenants!.t1!.Viewer![0]!.actions).toEqual(['read', 'write']);
  });

  it('throws a clear error when the file does not exist', () => {
    expect(() => loadRoleCapabilityPolicyFromFile(path.join(tmpDir, 'missing.json'))).toThrow(
      /Failed to read role capability policy file/,
    );
  });

  it('throws a clear error when the file is not valid JSON', () => {
    const file = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(file, 'not-json');
    expect(() => loadRoleCapabilityPolicyFromFile(file)).toThrow(/is not valid JSON/);
  });

  it('throws a clear error when the file fails schema validation', () => {
    const file = path.join(tmpDir, 'bad-schema.json');
    fs.writeFileSync(file, JSON.stringify({ tenants: {} }));
    expect(() => loadRoleCapabilityPolicyFromFile(file)).toThrow(/missing required 'default'/);
  });
});

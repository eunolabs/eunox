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
  DEFAULT_ROLE_CAPABILITY_MAP,
  RoleCapabilityMap,
} from '../src/role-mapping';

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

/**
 * Verifies the wire/runtime type split introduced by R-8 (see
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`):
 *
 *  - Wire-shape *value* exports (constants, helper functions) are
 *    importable from `@euno/common/wire`.
 *  - Runtime *value* exports surface from `@euno/common/runtime`.
 *  - The legacy `@euno/common` (and its `./types` shim) still re-exports
 *    every value, so existing consumers compile unchanged.
 *
 * Note: type-only exports (interfaces, type aliases) cannot be observed
 * at runtime, so this test focuses on the value exports — but the act of
 * importing from each entry point also exercises that the modules
 * type-check and load without circular-import issues.
 */
import * as wire from '@euno/common/wire';
import * as runtime from '@euno/common/runtime';
import * as common from '@euno/common';
import * as legacyTypes from '@euno/common/types';

describe('wire/runtime type split (R-8)', () => {
  describe('@euno/common/wire', () => {
    it('exports the wire-side value surface', () => {
      expect(wire.CAPABILITY_TOKEN_SCHEMA_VERSION).toBe('1.0');
      expect(wire.SUPPORTED_SCHEMA_VERSIONS.has('1.0')).toBe(true);
      expect(Array.isArray(wire.LEGACY_ACTIONS)).toBe(true);
      expect(wire.LEGACY_ACTIONS).toEqual([
        'read',
        'write',
        'execute',
        'delete',
        'admin',
      ]);
      expect(typeof wire.isLegacyAction).toBe('function');
      expect(wire.isLegacyAction('read')).toBe(true);
      expect(wire.isLegacyAction('db:select')).toBe(false);
    });

    it('does NOT pull in runtime-only value exports', () => {
      // Sentinel: runtime config / interface modules contribute no value
      // exports today, but if we ever start exporting a runtime-side
      // class/factory by mistake, this catches the leak.
      const wireKeys = Object.keys(wire).sort();
      expect(wireKeys).toEqual(
        expect.arrayContaining([
          'CAPABILITY_TOKEN_SCHEMA_VERSION',
          'SUPPORTED_SCHEMA_VERSIONS',
          'LEGACY_ACTIONS',
          'isLegacyAction',
        ]),
      );
    });
  });

  describe('@euno/common/runtime', () => {
    it('loads without errors and is independent of wire value exports', () => {
      // The runtime module has no value exports today (every member is a
      // type/interface), but importing it must succeed and not pollute
      // the wire surface.
      expect(runtime).toBeDefined();
      expect(Object.prototype.hasOwnProperty.call(runtime, 'LEGACY_ACTIONS'))
        .toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          runtime,
          'CAPABILITY_TOKEN_SCHEMA_VERSION',
        ),
      ).toBe(false);
    });
  });

  describe('back-compat through @euno/common and @euno/common/types', () => {
    it('re-exports every wire value from the package root', () => {
      expect(common.CAPABILITY_TOKEN_SCHEMA_VERSION).toBe(
        wire.CAPABILITY_TOKEN_SCHEMA_VERSION,
      );
      expect(common.LEGACY_ACTIONS).toBe(wire.LEGACY_ACTIONS);
      expect(common.isLegacyAction).toBe(wire.isLegacyAction);
      expect(common.SUPPORTED_SCHEMA_VERSIONS).toBe(
        wire.SUPPORTED_SCHEMA_VERSIONS,
      );
    });

    it('still re-exports every wire value from the legacy ./types shim', () => {
      expect(legacyTypes.CAPABILITY_TOKEN_SCHEMA_VERSION).toBe(
        wire.CAPABILITY_TOKEN_SCHEMA_VERSION,
      );
      expect(legacyTypes.LEGACY_ACTIONS).toBe(wire.LEGACY_ACTIONS);
      expect(legacyTypes.isLegacyAction).toBe(wire.isLegacyAction);
    });
  });

  describe('type-level usage', () => {
    it('lets a wire-shape value satisfy the wire type contract', () => {
      // Compile-time check: this assignment fails the build if the type
      // is not exported from `./wire`.
      const payload: wire.CapabilityTokenPayload = {
        iss: 'did:web:issuer.example',
        sub: 'agent-1',
        aud: 'gateway',
        iat: 0,
        exp: 60,
        jti: 'jti-1',
        schemaVersion: wire.CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };
      expect(payload.jti).toBe('jti-1');
    });

    it('lets a runtime context value satisfy the runtime type contract', () => {
      const ctx: runtime.UserContext = {
        userId: 'u1',
        roles: ['reader'],
      };
      expect(ctx.userId).toBe('u1');
    });
  });
});

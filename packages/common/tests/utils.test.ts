/**
 * Tests for common utility functions
 */

import {
  sha256,
  canonicalize,
  canonicalSha256,
  generateId,
  isExpired,
  isValidDID,
  isValidResourceId,
  isActionAllowed,
  matchesResource,
  parseBearerToken,
  sanitizeForLog,
  ErrorCode,
} from '../src/utils';

describe('Utility Functions', () => {
  describe('sha256', () => {
    it('should generate consistent hash for same input', () => {
      const data = { test: 'data' };
      const hash1 = sha256(data);
      const hash2 = sha256(data);
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different inputs', () => {
      const hash1 = sha256({ test: 'data1' });
      const hash2 = sha256({ test: 'data2' });
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
    });

    it('should generate valid UUID format', () => {
      const id = generateId();
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });
  });

  describe('isExpired', () => {
    it('should return true for past timestamps', () => {
      const pastTimestamp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      expect(isExpired(pastTimestamp)).toBe(true);
    });

    it('should return false for future timestamps', () => {
      const futureTimestamp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      expect(isExpired(futureTimestamp)).toBe(false);
    });
  });

  describe('isValidDID', () => {
    it('should validate correct DID formats', () => {
      expect(isValidDID('did:web:example.com')).toBe(true);
      expect(isValidDID('did:ion:abc123')).toBe(true);
      expect(isValidDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(true);
    });

    it('should accept DIDs with multiple colon-separated segments (per W3C DID Core)', () => {
      // did:web with path segments
      expect(isValidDID('did:web:example.com:user:alice')).toBe(true);
      // did:peer numeric algorithm with dots in the identifier
      expect(isValidDID('did:peer:2.Ez6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(true);
    });

    it('should accept DIDs with percent-encoded characters', () => {
      expect(isValidDID('did:web:example.com:path%20with%20space')).toBe(true);
    });

    it('should reject invalid DID formats', () => {
      expect(isValidDID('not-a-did')).toBe(false);
      expect(isValidDID('did::')).toBe(false);
      expect(isValidDID('did:method')).toBe(false);
      // method-name must be lowercase letters / digits only
      expect(isValidDID('did:Method:abc')).toBe(false);
      // trailing colon (no final 1*idchar segment)
      expect(isValidDID('did:web:example.com:')).toBe(false);
      // characters outside the idchar set
      expect(isValidDID('did:web:example com')).toBe(false);
    });
  });

  describe('isValidResourceId', () => {
    it('should validate resource identifiers with colons', () => {
      expect(isValidResourceId('api://service/endpoint')).toBe(true);
      expect(isValidResourceId('storage://bucket/file')).toBe(true);
    });

    it('should reject invalid resource identifiers', () => {
      expect(isValidResourceId('')).toBe(false);
      expect(isValidResourceId('no-colon')).toBe(false);
    });
  });

  describe('isActionAllowed', () => {
    const capabilities = [
      { resource: 'api://service/endpoint', actions: ['read', 'write'] },
      { resource: 'api://other/*', actions: ['read'] },
    ];

    it('should allow action when capability matches', () => {
      expect(isActionAllowed('read', 'api://service/endpoint', capabilities)).toBe(true);
      expect(isActionAllowed('write', 'api://service/endpoint', capabilities)).toBe(true);
    });

    it('should deny action when capability does not match', () => {
      expect(isActionAllowed('delete', 'api://service/endpoint', capabilities)).toBe(false);
      expect(isActionAllowed('read', 'api://unknown/endpoint', capabilities)).toBe(false);
    });

    it('should handle wildcard resources', () => {
      expect(isActionAllowed('read', 'api://other/anything', capabilities)).toBe(true);
      expect(isActionAllowed('write', 'api://other/anything', capabilities)).toBe(false);
    });
  });

  describe('matchesResource', () => {
    it('should match exact resource patterns', () => {
      expect(matchesResource('api://service/endpoint', 'api://service/endpoint')).toBe(true);
    });

    it('should match wildcard patterns', () => {
      expect(matchesResource('api://service/endpoint', 'api://service/*')).toBe(true);
      expect(matchesResource('api://service/nested/endpoint', 'api://service/**')).toBe(true);
    });

    it('should not match non-matching patterns', () => {
      expect(matchesResource('api://service/endpoint', 'api://other/*')).toBe(false);
    });

    // Single-segment wildcard `*` must NOT span path separators.
    // The earlier `startsWith(prefix)` implementation conflated `*`
    // and `**`; this pins the corrected segment-aware behavior.
    it('single-segment wildcard does not match deeper paths', () => {
      expect(matchesResource('api://service/a/b', 'api://service/*')).toBe(false);
      expect(matchesResource('api://service/a', 'api://service/*')).toBe(true);
    });

    it('recursive wildcard matches scheme-rooted resources at any depth', () => {
      expect(matchesResource('api://crm/customers', 'api://**')).toBe(true);
      expect(matchesResource('api://crm/customers/123', 'api://**')).toBe(true);
    });

    // The earlier implementation accepted `prefix/` as a legal expansion
    // of `prefix/*` (empty tail). Now `prefix/*` and `prefix/**` both
    // require at least one extra character.
    it('rejects empty-tail expansions', () => {
      expect(matchesResource('api://service/', 'api://service/*')).toBe(false);
      expect(matchesResource('api://service/', 'api://service/**')).toBe(false);
    });

    // The earlier `startsWith(prefix)` implementation would have
    // matched `api://service-old/...` against `api://service/*`
    // because the boundary was not on a path-segment edge. The fix
    // requires the trailing `/` to be present in the resource.
    it('rejects matches that do not respect path-segment boundaries', () => {
      expect(matchesResource('api://service-old/x', 'api://service/*')).toBe(false);
      expect(matchesResource('api://service-old/x/y', 'api://service/**')).toBe(false);
    });

    // Scheme-confusion guard: a `file://...` pattern must never
    // authorize a `db://...` resource (or vice versa).
    it('refuses to match across schemes', () => {
      expect(matchesResource('db://data/x', 'file://data/*')).toBe(false);
      expect(matchesResource('db://data/x/y', 'file://data/**')).toBe(false);
      expect(matchesResource('file://data/x', 'db://data/*')).toBe(false);
    });
  });

  describe('parseBearerToken', () => {
    it('should extract token from valid Bearer header', () => {
      const token = parseBearerToken('Bearer abc123');
      expect(token).toBe('abc123');
    });

    it('should return null for invalid formats', () => {
      expect(parseBearerToken('Basic abc123')).toBeNull();
      expect(parseBearerToken('Bearer')).toBeNull();
      expect(parseBearerToken('')).toBeNull();
      expect(parseBearerToken(undefined)).toBeNull();
    });
  });

  describe('sanitizeForLog', () => {
    it('should redact sensitive fields', () => {
      const data = {
        username: 'test',
        password: 'secret123',
        token: 'abc123',
        apiKey: 'xyz789',
      };

      const sanitized = sanitizeForLog(data);

      expect(sanitized.username).toBe('test');
      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.token).toBe('[REDACTED]');
      expect(sanitized.apiKey).toBe('[REDACTED]');
    });

    it('should handle nested objects', () => {
      const data = {
        user: {
          name: 'test',
          secret: 'hidden',
        },
      };

      const sanitized = sanitizeForLog(data);
      const user = sanitized.user as Record<string, unknown>;

      expect(user.name).toBe('test');
      expect(user.secret).toBe('[REDACTED]');
    });

    it('should redact additional security key names (jwt, bearer, cookie, session, etc.)', () => {
      const data = {
        jwt: 'header.payload.sig',
        bearer: 'tok',
        cookie: 'sid=abc',
        session: 'xyz',
        client_secret: 'shh',
        private_key: '-----BEGIN-----',
      };
      const sanitized = sanitizeForLog(data);
      expect(sanitized.jwt).toBe('[REDACTED]');
      expect(sanitized.bearer).toBe('[REDACTED]');
      expect(sanitized.cookie).toBe('[REDACTED]');
      expect(sanitized.session).toBe('[REDACTED]');
      expect(sanitized.client_secret).toBe('[REDACTED]');
      expect(sanitized.private_key).toBe('[REDACTED]');
    });

    it('should NOT redact unrelated keys that merely contain a sensitive substring', () => {
      // Substring-based redaction (the previous implementation) flagged these
      // as sensitive even though they are not. Exact-match redaction does not.
      const data = {
        customerToken: 'value-1', // contains "token" but is not a credential field
        passwordHint: 'something', // contains "password" but is a non-secret hint
        notAuthRelated: 42,
      };
      const sanitized = sanitizeForLog(data);
      expect(sanitized.customerToken).toBe('value-1');
      expect(sanitized.passwordHint).toBe('something');
      expect(sanitized.notAuthRelated).toBe(42);
    });

    it('should traverse arrays', () => {
      const data = {
        users: [
          { name: 'a', token: 't1' },
          { name: 'b', token: 't2' },
        ],
      };
      const sanitized = sanitizeForLog(data);
      const users = sanitized.users as Array<Record<string, unknown>>;
      expect(Array.isArray(users)).toBe(true);
      expect(users[0]!.name).toBe('a');
      expect(users[0]!.token).toBe('[REDACTED]');
      expect(users[1]!.token).toBe('[REDACTED]');
    });

    it('should bound recursion depth and array size to keep cost predictable', () => {
      // Build a deeply nested object well past the depth limit.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const deep: any = {};
      let cursor = deep;
      for (let i = 0; i < 50; i++) {
        cursor.next = {};
        cursor = cursor.next;
      }
      cursor.token = 'deep-secret';
      const sanitized = sanitizeForLog(deep);
      // Must complete without stack overflow / runaway and return an object.
      expect(typeof sanitized).toBe('object');

      // Large array gets truncated.
      const big = { items: new Array(500).fill('x') };
      const sanitizedBig = sanitizeForLog(big);
      const items = sanitizedBig.items as unknown[];
      expect(items.length).toBeLessThan(big.items.length);
    });
  });

  describe('canonicalize / canonicalSha256', () => {
    it('produces the same output regardless of key insertion order', () => {
      const a = { b: 1, a: 2, c: { y: 1, x: 2 } };
      const b = { c: { x: 2, y: 1 }, a: 2, b: 1 };
      expect(canonicalize(a)).toBe(canonicalize(b));
      expect(canonicalSha256(a)).toBe(canonicalSha256(b));
    });

    it('differs across structurally different inputs', () => {
      expect(canonicalSha256({ a: 1 })).not.toBe(canonicalSha256({ a: 2 }));
      expect(canonicalSha256([1, 2, 3])).not.toBe(canonicalSha256([3, 2, 1]));
    });

    it('handles BigInt, undefined and non-finite numbers without throwing', () => {
      expect(canonicalize({ x: BigInt(5), y: undefined, z: NaN, w: Infinity })).toBe(
        '{"w":null,"x":"5n","z":null}',
      );
    });

    it('throws on circular references rather than silently producing a partial digest', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const obj: any = { a: 1 };
      obj.self = obj;
      expect(() => canonicalize(obj)).toThrow(/circular/i);
    });

    it('matches the documented sha256 helper behaviour for primitive inputs', () => {
      // canonicalSha256 of a primitive equals sha256String of its JSON encoding.
      expect(canonicalSha256('hello')).toHaveLength(64);
      // canonicalSha256 is not the same as the legacy sha256 because the
      // legacy helper does not sort keys.
      const obj = { b: 1, a: 2 };
      expect(canonicalSha256(obj)).not.toBe(sha256({ b: 1, a: 2 }));
    });
  });

  describe('ErrorCode enum', () => {
    it('does not contain duplicate string values (no aliased members)', () => {
      const values = Object.values(ErrorCode).filter((v) => typeof v === 'string') as string[];
      const unique = new Set(values);
      expect(values.length).toBe(unique.size);
    });

    it('exposes EXPIRED_TOKEN as the canonical expiry code', () => {
      expect(ErrorCode.EXPIRED_TOKEN).toBe('EXPIRED_TOKEN');
      // The deprecated alias was removed.
      expect((ErrorCode as Record<string, unknown>).TOKEN_EXPIRED).toBeUndefined();
    });
  });
});

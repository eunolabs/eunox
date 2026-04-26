/**
 * Tests for common utility functions
 */

import {
  sha256,
  generateId,
  isExpired,
  isValidDID,
  isValidResourceId,
  isActionAllowed,
  matchesResource,
  parseBearerToken,
  sanitizeForLog,
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

    it('should reject invalid DID formats', () => {
      expect(isValidDID('not-a-did')).toBe(false);
      expect(isValidDID('did::')).toBe(false);
      expect(isValidDID('did:method')).toBe(false);
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
  });
});

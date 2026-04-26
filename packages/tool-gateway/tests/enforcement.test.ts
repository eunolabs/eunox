/**
 * Tests for Enforcement Engine
 */

import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import {
  CapabilityTokenPayload,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
} from '@euno/common';
import * as jose from 'jose';

describe('EnforcementEngine', () => {
  let engine: EnforcementEngine;
  let verifier: JWTTokenVerifier;
  let privateKey: jose.KeyLike;
  let publicKey: string;
  const logger = createLogger('test');

  beforeAll(async () => {
    const { publicKey: pubKey, privateKey: privKey } = await jose.generateKeyPair('RS256');
    privateKey = privKey;
    publicKey = await jose.exportSPKI(pubKey);

    verifier = new JWTTokenVerifier(publicKey);
    engine = new EnforcementEngine(verifier, logger);
  });

  async function createTestToken(
    capabilities: Array<{ resource: string; actions: string[] }>
  ): Promise<string> {
    const payload: CapabilityTokenPayload = {
      iss: 'did:web:test.com',
      sub: 'test-agent',
      aud: 'tool-gateway',
      iat: getCurrentTimestamp(),
      exp: getExpirationTimestamp(900),
      jti: `test-${Date.now()}`,
      capabilities,
    };

    return await new jose.SignJWT(payload as any)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
  }

  describe('validateAction', () => {
    it('should allow action when capability matches', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read', 'write'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(true);
      expect(result.matchedCapability).toBeDefined();
      expect(result.matchedCapability?.resource).toBe('api://service/endpoint');
    });

    it('should deny action when capability does not match', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Insufficient permissions');
    });

    it('should deny action for wrong resource', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://other/endpoint',
      });

      expect(result.allowed).toBe(false);
    });

    it('should handle wildcard resources', async () => {
      const token = await createTestToken([
        { resource: 'api://service/*', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/anything',
      });

      expect(result.allowed).toBe(true);
    });

    it('should reject tokens with wrong audience', async () => {
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'wrong-audience',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token',
        capabilities: [{ resource: 'api://test', actions: ['read'] }],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://test',
        })
      ).rejects.toThrow('audience');
    });

    it('should handle multiple capability constraints', async () => {
      const token = await createTestToken([
        { resource: 'api://service1/endpoint', actions: ['read'] },
        { resource: 'api://service2/endpoint', actions: ['write'] },
      ]);

      const result1 = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service1/endpoint',
      });
      expect(result1.allowed).toBe(true);

      const result2 = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service2/endpoint',
      });
      expect(result2.allowed).toBe(true);

      const result3 = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service1/endpoint',
      });
      expect(result3.allowed).toBe(false);
    });
  });
});

/**
 * Tests for Enforcement Engine
 */

import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  DefaultKillSwitchManager,
  AuditEvidence,
  SignedAuditEvidence,
  EvidenceSigner,
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
    engine = new EnforcementEngine({
      verifier,
      logger,
    });
  });

  async function createTestToken(
    capabilities: CapabilityConstraint[],
    extra?: Partial<CapabilityTokenPayload>
  ): Promise<string> {
    const payload: CapabilityTokenPayload = {
      iss: 'did:web:test.com',
      sub: 'test-agent',
      aud: 'tool-gateway',
      iat: getCurrentTimestamp(),
      exp: getExpirationTimestamp(900),
      jti: `test-${Date.now()}`,
      capabilities,
      ...extra,
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

  describe('kill-switch enforcement', () => {
    let killEngine: EnforcementEngine;
    let killSwitchManager: DefaultKillSwitchManager;

    beforeEach(() => {
      killSwitchManager = new DefaultKillSwitchManager(logger);
      killEngine = new EnforcementEngine({ verifier, logger, killSwitchManager });
    });

    it('should block all requests when global kill switch is active', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.activateGlobalKill();

      await expect(
        killEngine.validateAction({ token, action: 'read', resource: 'api://service/endpoint' })
      ).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('terminated') });
    });

    it('should block requests for a killed session', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('session-abc');

      await expect(
        killEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          context: { sessionId: 'session-abc' },
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('should block requests for a killed agent', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { sub: 'agent-xyz' }
      );

      killSwitchManager.killAgent('agent-xyz');

      await expect(
        killEngine.validateAction({ token, action: 'read', resource: 'api://service/endpoint' })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('should not block requests when kill switch targets a different session', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('other-session');

      const result = await killEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 'session-abc' },
      });

      expect(result.allowed).toBe(true);
    });

    it('should not block requests when sessionId is not a string', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('undefined');

      // numeric sessionId must not be coerced – guard should treat it as absent
      const result = await killEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 42 as unknown as string },
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe('cryptographic evidence generation', () => {
    it('should invoke evidenceSigner for an allowed action', async () => {
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const mockSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const auditEngine = new EnforcementEngine({
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: true,
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const result = await auditEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 'sess-1' },
      });

      expect(result.allowed).toBe(true);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'allow', sessionId: 'sess-1' })
      );
    });

    it('should invoke evidenceSigner for a denied action', async () => {
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: true,
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const result = await auditEngine.validateAction({
        token,
        action: 'write',   // not allowed
        resource: 'api://service/endpoint',
        context: { sessionId: 'sess-2' },
      });

      expect(result.allowed).toBe(false);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny', sessionId: 'sess-2' })
      );
    });

    it('should not invoke evidenceSigner when audit is disabled', async () => {
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: false,
      });

      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      await auditEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(signEvidence).not.toHaveBeenCalled();
    });
  });
});

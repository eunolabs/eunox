/**
 * Tests for Token Verifier
 */

import { JWTTokenVerifier } from '../src/verifier';
import { CapabilityTokenPayload, getCurrentTimestamp, getExpirationTimestamp } from '@euno/common';
import * as jose from 'jose';

describe('JWTTokenVerifier', () => {
  let verifier: JWTTokenVerifier;
  let privateKey: jose.KeyLike;
  let publicKey: string;

  beforeAll(async () => {
    // Generate a key pair for testing
    const { publicKey: pubKey, privateKey: privKey } = await jose.generateKeyPair('RS256');
    privateKey = privKey;
    publicKey = await jose.exportSPKI(pubKey);

    verifier = new JWTTokenVerifier(publicKey);
  });

  describe('verify', () => {
    it('should verify a valid token', async () => {
      // Create a test token
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        capabilities: [
          { resource: 'api://test/endpoint', actions: ['read'] },
        ],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      const decoded = await verifier.verify(token);

      expect(decoded.iss).toBe(payload.iss);
      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.jti).toBe(payload.jti);
    });

    it('should reject expired tokens', async () => {
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp() - 1000,
        exp: getCurrentTimestamp() - 100, // Expired
        jti: 'test-token-id',
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(verifier.verify(token)).rejects.toThrow('expired');
    });

    it('should reject invalid signatures', async () => {
      // Create a token with a different key
      const { privateKey: wrongKey } = await jose.generateKeyPair('RS256');

      const payload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        exp: getExpirationTimestamp(900),
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(wrongKey);

      await expect(verifier.verify(token)).rejects.toThrow();
    });

    it('should reject revoked tokens', async () => {
      const tokenId = 'revoked-token';
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: tokenId,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      // Revoke the token
      verifier.revokeToken(tokenId);

      await expect(verifier.verify(token)).rejects.toThrow('revoked');
    });
  });

  describe('isRevoked', () => {
    it('should return true for revoked tokens', async () => {
      verifier.revokeToken('revoked-id');
      expect(await verifier.isRevoked('revoked-id')).toBe(true);
    });

    it('should return false for non-revoked tokens', async () => {
      expect(await verifier.isRevoked('valid-id')).toBe(false);
    });
  });
});

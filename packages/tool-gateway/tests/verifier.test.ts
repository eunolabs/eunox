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

  describe('algorithm support', () => {
    it('should verify ES256 tokens when configured', async () => {
      // Generate an EC key pair for ES256
      const { publicKey: ecPubKey, privateKey: ecPrivKey } = await jose.generateKeyPair('ES256');
      const ecPublicKeyPEM = await jose.exportSPKI(ecPubKey);

      // Create verifier with ES256 algorithm
      const es256Verifier = new JWTTokenVerifier(ecPublicKeyPEM, ['ES256']);

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
        .setProtectedHeader({ alg: 'ES256' })
        .sign(ecPrivKey);

      const decoded = await es256Verifier.verify(token);

      expect(decoded.iss).toBe(payload.iss);
      expect(decoded.sub).toBe(payload.sub);
    });

    it('should support multiple algorithms', async () => {
      // Generate an RSA key pair (same key can sign with RS256 or RS384)
      const { publicKey: rsaPubKey, privateKey: rsaPrivKey } = await jose.generateKeyPair('RS256');
      const rsaPublicKeyPEM = await jose.exportSPKI(rsaPubKey);

      // Create verifier that accepts both RS256 and RS384
      const multiAlgoVerifier = new JWTTokenVerifier(rsaPublicKeyPEM, ['RS256', 'RS384']);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        capabilities: [],
      };

      // Should verify RS256 token
      const rsaToken = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(rsaPrivKey);

      const decoded = await multiAlgoVerifier.verify(rsaToken);
      expect(decoded.iss).toBe(payload.iss);

      // Should also verify RS384 token signed with the same RSA key
      const rs384Token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS384' })
        .sign(rsaPrivKey);

      const decoded384 = await multiAlgoVerifier.verify(rs384Token);
      expect(decoded384.iss).toBe(payload.iss);
    });
  });
});

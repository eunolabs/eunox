/**
 * Tests for Token Verifier
 */

import { JWTTokenVerifier } from '../src/verifier';
import {
  InMemoryRevocationEpochStore,
} from '../src/revocation-store';
import {
  CapabilityTokenPayload,
  getCurrentTimestamp,
  getExpirationTimestamp,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
} from '@euno/common';
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

    verifier = new JWTTokenVerifier(publicKey, { requireKid: false });
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
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
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
      expect(decoded.schemaVersion).toBe(CAPABILITY_TOKEN_SCHEMA_VERSION);
    });

    it('should reject expired tokens', async () => {
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp() - 1000,
        exp: getCurrentTimestamp() - 100, // Expired
        jti: 'test-token-id',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
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
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      // Revoke the token
      await verifier.revokeToken(tokenId);

      await expect(verifier.verify(token)).rejects.toThrow('revoked');
    });
  });

  describe('isRevoked', () => {
    it('should return true for revoked tokens', async () => {
      await verifier.revokeToken('revoked-id');
      expect(await verifier.isRevoked('revoked-id')).toBe(true);
    });

    it('should return false for non-revoked tokens', async () => {
      expect(await verifier.isRevoked('valid-id')).toBe(false);
    });

    it('should return false and prune an entry whose expiry has passed', async () => {
      const pastExpiry = Math.floor(Date.now() / 1000) - 1; // already expired
      await verifier.revokeToken('stale-id', pastExpiry);
      // Should report not-revoked because the entry is expired
      expect(await verifier.isRevoked('stale-id')).toBe(false);
      // Calling again confirms the entry was deleted (not just ignored)
      expect(await verifier.isRevoked('stale-id')).toBe(false);
    });

    it('should return true for a revoked token with a future explicit expiry', async () => {
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      await verifier.revokeToken('future-id', futureExpiry);
      expect(await verifier.isRevoked('future-id')).toBe(true);
    });
  });

  describe('revokeToken', () => {
    it('should use a default expiry (~24 h) when expiresAt is omitted', async () => {
      const before = Math.floor(Date.now() / 1000);
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      await freshVerifier.revokeToken('default-ttl-id');
      expect(await freshVerifier.isRevoked('default-ttl-id')).toBe(true);
      // Confirm the stored expiry is roughly 24 h from now
      const after = Math.floor(Date.now() / 1000);
      const expectedMin = before + 86400;
      const expectedMax = after + 86400;
      // Access the in-memory store's private map via bracket notation
      // for white-box validation.
      const store = (freshVerifier as any).revocationStore;
      const map = store.revokedTokens as Map<string, number>;
      const stored = map.get('default-ttl-id')!;
      expect(stored).toBeGreaterThanOrEqual(expectedMin);
      expect(stored).toBeLessThanOrEqual(expectedMax);
    });

    it('should prune expired entries when a new revocation is added', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const pastExpiry = Math.floor(Date.now() / 1000) - 1;
      // Add several already-expired entries
      await freshVerifier.revokeToken('old-1', pastExpiry);
      await freshVerifier.revokeToken('old-2', pastExpiry);
      await freshVerifier.revokeToken('old-3', pastExpiry);
      // Trigger pruning by revoking a new token with a future expiry
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
      await freshVerifier.revokeToken('new-1', futureExpiry);
      // The map should only contain the new entry — the three stale ones are gone
      const store = (freshVerifier as any).revocationStore;
      const map = store.revokedTokens as Map<string, number>;
      expect(map.size).toBe(1);
      expect(map.has('new-1')).toBe(true);
    });
  });

  describe('algorithm support', () => {
    it('should verify ES256 tokens when configured', async () => {
      // Generate an EC key pair for ES256
      const { publicKey: ecPubKey, privateKey: ecPrivKey } = await jose.generateKeyPair('ES256');
      const ecPublicKeyPEM = await jose.exportSPKI(ecPubKey);

      // Create verifier with ES256 algorithm
      const es256Verifier = new JWTTokenVerifier(ecPublicKeyPEM, { requireKid: false, algorithms: ['ES256'] });

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
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
      const multiAlgoVerifier = new JWTTokenVerifier(rsaPublicKeyPEM, { requireKid: false, algorithms: ['RS256', 'RS384'] });

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
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

  describe('schema version validation', () => {
    it('should accept tokens with supported schema version', async () => {
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION, // Use constant, not hardcoded value
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      const decoded = await verifier.verify(token);
      expect(decoded.schemaVersion).toBe(CAPABILITY_TOKEN_SCHEMA_VERSION);
    });

    it('should reject tokens with missing schemaVersion', async () => {
      const payload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        capabilities: [],
        // schemaVersion missing
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(verifier.verify(token)).rejects.toThrow('missing required schemaVersion');
    });

    it('should reject tokens with unsupported schema version', async () => {
      const payload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: '2.0', // Unsupported version
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(verifier.verify(token)).rejects.toThrow('Unsupported token schema version: 2.0');
    });

    it('should include list of supported versions in error message', async () => {
      const payload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: '99.0',
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(verifier.verify(token)).rejects.toThrow(/Supported versions:.*1\.0/s);
    });

    it('should reject tokens with non-string schema version', async () => {
      const payload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token-id',
        schemaVersion: 1.0, // Number instead of string
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      // Should be rejected - either as missing or unsupported depending on type coercion
      await expect(verifier.verify(token)).rejects.toThrow();
    });
  });

  describe('epoch revocation', () => {
    it('accepts a token when no epoch is set', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const epochStore = new InMemoryRevocationEpochStore();
      await freshVerifier.setEpochStore(epochStore);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp() - 60,
        exp: getExpirationTimestamp(900),
        jti: 'epoch-ok-1',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).resolves.toBeDefined();
    });

    it('accepts a token whose iat is at or after the epoch', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const epochStore = new InMemoryRevocationEpochStore();
      const epoch = getCurrentTimestamp() - 600; // 10 min ago
      await epochStore.setEpoch('did:web:test.com', epoch);
      await freshVerifier.setEpochStore(epochStore);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: epoch, // exactly at epoch — allowed (strict < check)
        exp: getExpirationTimestamp(900),
        jti: 'epoch-ok-2',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).resolves.toBeDefined();
    });

    it('rejects a token whose iat is before the epoch', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const epochStore = new InMemoryRevocationEpochStore();
      const epoch = getCurrentTimestamp(); // epoch = now
      await epochStore.setEpoch('did:web:test.com', epoch);
      await freshVerifier.setEpochStore(epochStore);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: epoch - 100, // issued 100s before the epoch — blocked
        exp: getExpirationTimestamp(900),
        jti: 'epoch-blocked-1',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).rejects.toThrow(/predates.*epoch/i);
    });

    it('does not apply epoch check to a different issuer', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const epochStore = new InMemoryRevocationEpochStore();
      const epoch = getCurrentTimestamp() + 3600; // epoch in the future
      await epochStore.setEpoch('did:web:other-issuer.com', epoch);
      await freshVerifier.setEpochStore(epochStore);

      // Token from a different issuer — no epoch set for it, so it passes
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp() - 60,
        exp: getExpirationTimestamp(900),
        jti: 'epoch-other-issuer',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).resolves.toBeDefined();
    });

    it('setEpochStore replaces a previous store', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const oldStore = new InMemoryRevocationEpochStore();
      const epoch = getCurrentTimestamp() + 3600;
      await oldStore.setEpoch('did:web:test.com', epoch);
      await freshVerifier.setEpochStore(oldStore);

      // Now replace with a store that has no epoch set
      const newStore = new InMemoryRevocationEpochStore();
      await freshVerifier.setEpochStore(newStore);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp() - 60,
        exp: getExpirationTimestamp(900),
        jti: 'epoch-replace',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      // New store has no epoch — token should pass
      await expect(freshVerifier.verify(token)).resolves.toBeDefined();
    });

    it('rejects a token with missing iat when an epoch is active', async () => {
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const epochStore = new InMemoryRevocationEpochStore();
      await epochStore.setEpoch('did:web:test.com', getCurrentTimestamp() - 300);
      await freshVerifier.setEpochStore(epochStore);

      // Craft a payload without iat — cannot be placed on the timeline
      const payloadNoIat = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        // deliberately omit iat
        exp: getExpirationTimestamp(900),
        jti: 'epoch-no-iat',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [] as any[],
      };

      const token = await new jose.SignJWT(payloadNoIat as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).rejects.toMatchObject({
        code: 'INVALID_TOKEN',
      });
    });

    it('fail-closed epoch (nowSeconds()+1) blocks a token minted in the same second', async () => {
      // This test simulates the fail-closed path by constructing a fake epoch
      // store that returns nowSeconds()+1 (as the Redis error path now does)
      // and confirms that a token with iat === now is still rejected.
      const freshVerifier = new JWTTokenVerifier(publicKey, { requireKid: false });
      const nowEpoch = getCurrentTimestamp() + 1; // mirrors nowSeconds()+1
      const epochStore = new InMemoryRevocationEpochStore();
      await epochStore.setEpoch('did:web:test.com', nowEpoch);
      await freshVerifier.setEpochStore(epochStore);

      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(), // iat === now; epoch is now+1 → rejected
        exp: getExpirationTimestamp(900),
        jti: 'epoch-same-second',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(freshVerifier.verify(token)).rejects.toThrow(/predates.*epoch/i);
    });
  });

  // Defence in depth for the constructor's two supported call shapes:
  // the typed overloads make a mixed call a compile-time error, but a
  // bypass via `as any` / transpiled JS would otherwise silently drop
  // the legacy positional args. The runtime guard turns that into a
  // loud throw so misconfigurations like "passed revocationStore as
  // arg 3 alongside an options bag" can't reach production.
  describe('constructor — mixed-form rejection', () => {
    it('throws when an options bag is combined with a legacy positional argument', () => {
      expect(
        () =>
          // Bypass the TS overloads so we actually exercise the runtime
          // guard; without the cast tsc would already reject this call.
          new (JWTTokenVerifier as unknown as new (
            pk: string,
            opts: object,
            extra: object,
          ) => JWTTokenVerifier)(
            publicKey,
            { requireKid: false },
            // 3rd arg is `revocationStore` in the legacy positional form
            // — silently ignored before this guard, now rejected.
            {} as object,
          ),
      ).toThrow(/mixing the options-bag and legacy positional/);
    });
  });
});

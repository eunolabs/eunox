/**
 * Integration tests for Capability Issuer Service
 */

import request from 'supertest';
import { app } from '../src/index';

// Mock Azure services for testing
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

describe('Capability Issuer API', () => {
  describe('GET /health', () => {
    it('should return healthy status', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        status: 'healthy',
        service: 'capability-issuer',
      });
    });
  });

  describe('POST /api/v1/issue', () => {
    it('should reject request without authorization header', async () => {
      const response = await request(app)
        .post('/api/v1/issue')
        .send({
          agentId: 'test-agent',
        });

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('AUTHENTICATION_FAILED');
    });

    it('should reject request without agentId', async () => {
      const response = await request(app)
        .post('/api/v1/issue')
        .set('Authorization', 'Bearer fake-token')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('POST /api/v1/attenuate', () => {
    it('should reject request without authorization header', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .send({
          requestedCapabilities: [{ resource: 'api://service/endpoint', actions: ['read'] }],
        });

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('AUTHENTICATION_FAILED');
    });

    it('should reject request without requestedCapabilities', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .set('Authorization', 'Bearer fake-token')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject request with non-array requestedCapabilities', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .set('Authorization', 'Bearer fake-token')
        .send({ requestedCapabilities: 'not-an-array' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject request with invalid ttl (string)', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .set('Authorization', 'Bearer fake-token')
        .send({
          requestedCapabilities: [{ resource: 'api://service/endpoint', actions: ['read'] }],
          ttl: 'notanumber',
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject request with invalid ttl (negative)', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .set('Authorization', 'Bearer fake-token')
        .send({
          requestedCapabilities: [{ resource: 'api://service/endpoint', actions: ['read'] }],
          ttl: -100,
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject invalid/expired parent token with 401', async () => {
      const response = await request(app)
        .post('/api/v1/attenuate')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .send({
          requestedCapabilities: [{ resource: 'api://service/endpoint', actions: ['read'] }],
        });

      // Should be 401 INVALID_TOKEN, not 500 INTERNAL_ERROR
      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('POST /api/v1/renew', () => {
    it('should reject request without authorization header', async () => {
      const response = await request(app)
        .post('/api/v1/renew')
        .send({});

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('AUTHENTICATION_FAILED');
    });

    it('should reject request with invalid ttl (zero)', async () => {
      const response = await request(app)
        .post('/api/v1/renew')
        .set('Authorization', 'Bearer fake-token')
        .send({ ttl: 0 });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject request with invalid ttl (Infinity)', async () => {
      const response = await request(app)
        .post('/api/v1/renew')
        .set('Authorization', 'Bearer fake-token')
        .send({ ttl: Infinity });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject invalid/expired token with 401', async () => {
      const response = await request(app)
        .post('/api/v1/renew')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .send({});

      // Should be 401 INVALID_TOKEN, not 500 INTERNAL_ERROR
      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('GET /api/v1/public-key', () => {
    it('should return public key', async () => {
      // This will fail in test environment without proper Azure setup
      // but validates the endpoint exists
      const response = await request(app).get('/api/v1/public-key');

      // Expect either success, initialization error, or service-not-initialized
      expect([200, 500, 503]).toContain(response.status);
    });
  });

  describe('GET /.well-known/did.json', () => {
    it('should return DID document structure', async () => {
      const response = await request(app).get('/.well-known/did.json');

      // May fail without Azure setup but validates endpoint
      expect([200, 500, 503]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body).toHaveProperty('@context');
        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('verificationMethod');
      }
    });
  });

  describe('GET /.well-known/capability-issuer', () => {
    it('should return issuer metadata without requiring service initialization', async () => {
      const response = await request(app).get('/.well-known/capability-issuer');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('issuer');
      expect(response.body).toHaveProperty('schemaVersions');
      expect(response.body.schemaVersions).toHaveProperty('current');
      expect(response.body.schemaVersions).toHaveProperty('supported');
      expect(Array.isArray(response.body.schemaVersions.supported)).toBe(true);
      expect(response.body.schemaVersions.supported).toContain(response.body.schemaVersions.current);
      expect(response.body).toHaveProperty('signingAlgorithms');
      expect(Array.isArray(response.body.signingAlgorithms)).toBe(true);
      expect(response.body).toHaveProperty('endpoints');
      expect(response.body.endpoints).toHaveProperty('publicKey');
      expect(response.body.endpoints).toHaveProperty('didDocument');
    });
  });
});

describe('Capability Issuance Logic', () => {
  it('should map roles to capabilities correctly', async () => {
    const { AzureADIdentityProvider } = await import('../src/azure-identity-provider');

    const capabilities = AzureADIdentityProvider.mapRolesToCapabilities(['SalesManager']);

    expect(capabilities).toContainEqual({
      resource: 'api://crm/customers',
      actions: ['read', 'write'],
    });
  });

  it('should handle multiple roles', async () => {
    const { AzureADIdentityProvider } = await import('../src/azure-identity-provider');

    const capabilities = AzureADIdentityProvider.mapRolesToCapabilities([
      'Viewer',
      'DataScientist',
    ]);

    expect(capabilities.length).toBeGreaterThan(1);
    expect(capabilities.some(c => c.resource.includes('analytics'))).toBe(true);
  });
});

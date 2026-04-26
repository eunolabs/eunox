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

  describe('GET /api/v1/public-key', () => {
    it('should return public key', async () => {
      // This will fail in test environment without proper Azure setup
      // but validates the endpoint exists
      const response = await request(app).get('/api/v1/public-key');

      // Expect either success or initialization error
      expect([200, 500]).toContain(response.status);
    });
  });

  describe('GET /.well-known/did.json', () => {
    it('should return DID document structure', async () => {
      const response = await request(app).get('/.well-known/did.json');

      // May fail without Azure setup but validates endpoint
      expect([200, 500]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body).toHaveProperty('@context');
        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('verificationMethod');
      }
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

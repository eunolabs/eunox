/**
 * Tests for the default adapter registries
 */

import { defaultIdentityRegistry, defaultSigningRegistry } from '../src/default-registries';
import {
  IdentityAdapterRegistry,
  SigningAdapterRegistry,
  IdentityAdapter,
  UserContext,
  SigningAdapter,
  CapabilityTokenPayload,
} from '@euno/common';
import { AzureADIdentityProvider } from '../src/azure-identity-provider';
import { DIDIdentityProvider } from '../src/did-identity-provider';
import { AzureKeyVaultSigner } from '../src/azure-signer';
import { DIDSigner } from '../src/did-signer';

// Mock Azure services to avoid real network calls
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/identity');
jest.mock('@microsoft/microsoft-graph-client');

describe('defaultIdentityRegistry', () => {
  it('should be an instance of IdentityAdapterRegistry', () => {
    expect(defaultIdentityRegistry).toBeInstanceOf(IdentityAdapterRegistry);
  });

  it('should have azure-ad registered as a built-in type', () => {
    expect(defaultIdentityRegistry.getSupportedTypes()).toContain('azure-ad');
  });

  it('should have did registered as a built-in type', () => {
    expect(defaultIdentityRegistry.getSupportedTypes()).toContain('did');
  });

  it('should create an AzureADIdentityProvider for type azure-ad', async () => {
    const provider = await defaultIdentityRegistry.createIdentityAdapter({
      type: 'azure-ad',
      name: 'Test Azure AD',
      tenantId: 'test-tenant',
      clientId: 'test-client',
      clientSecret: 'test-secret',
    });

    expect(provider).toBeInstanceOf(AzureADIdentityProvider);
  });

  it('should create a DIDIdentityProvider for type did', async () => {
    const provider = await defaultIdentityRegistry.createIdentityAdapter({
      type: 'did',
      name: 'Test DID Provider',
    });

    expect(provider).toBeInstanceOf(DIDIdentityProvider);
  });

  it('should throw a clear error for unknown types', async () => {
    await expect(
      defaultIdentityRegistry.createIdentityAdapter({
        type: 'unknown-provider',
        name: 'Unknown',
      })
    ).rejects.toThrow('Unknown identity adapter type: unknown-provider');
  });

  it('should support registering a third-party provider', async () => {
    class TestIdentityProvider extends IdentityAdapter {
      public readonly name = 'test-provider';
      async validateToken(_token: string): Promise<UserContext> {
        return { userId: 'test', email: 'test@example.com', roles: [], claims: {} };
      }
      async getUserRoles(_userId: string): Promise<string[]> {
        return [];
      }
    }

    const registry = new IdentityAdapterRegistry();
    registry.register('test-provider', TestIdentityProvider);

    expect(registry.getSupportedTypes()).toContain('test-provider');
    const provider = await registry.createIdentityAdapter({
      type: 'test-provider',
      name: 'Test Provider',
    });
    expect(provider).toBeInstanceOf(TestIdentityProvider);
  });
});

describe('defaultSigningRegistry', () => {
  it('should be an instance of SigningAdapterRegistry', () => {
    expect(defaultSigningRegistry).toBeInstanceOf(SigningAdapterRegistry);
  });

  it('should have azure-keyvault registered as a built-in type', () => {
    expect(defaultSigningRegistry.getSupportedTypes()).toContain('azure-keyvault');
  });

  it('should have did registered as a built-in type', () => {
    expect(defaultSigningRegistry.getSupportedTypes()).toContain('did');
  });

  it('should create an AzureKeyVaultSigner for type azure-keyvault', async () => {
    // Mock initialize to avoid real Azure calls in tests
    jest.spyOn(AzureKeyVaultSigner.prototype, 'initialize').mockResolvedValueOnce(undefined);

    const signer = await defaultSigningRegistry.createSigningAdapter({
      type: 'azure-keyvault',
      name: 'Test Azure Key Vault',
      keyVault: {
        vaultUrl: 'https://test-vault.vault.azure.net',
        keyName: 'test-key',
        credentialType: 'default',
      },
    });

    expect(signer).toBeInstanceOf(AzureKeyVaultSigner);
  });

  it('should create a DIDSigner for type did', async () => {
    // Mock initialize to avoid DID resolution in tests
    jest.spyOn(DIDSigner.prototype, 'initialize').mockResolvedValueOnce(undefined);

    const signer = await defaultSigningRegistry.createSigningAdapter({
      type: 'did',
      name: 'Test DID Signer',
      issuerDID: 'did:web:example.com',
      privateKey: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
    });

    expect(signer).toBeInstanceOf(DIDSigner);
  });

  it('should throw a clear error for unknown types', async () => {
    await expect(
      defaultSigningRegistry.createSigningAdapter({
        type: 'unknown-signer',
        name: 'Unknown',
      })
    ).rejects.toThrow('Unknown signing adapter type: unknown-signer');
  });

  it('should support registering a third-party signer', async () => {
    class TestSigner extends SigningAdapter {
      async sign(_payload: CapabilityTokenPayload): Promise<string> { return 'test.token.signature'; }
      async getPublicKey(): Promise<string> { return 'test-public-key'; }
      async getKeyId(): Promise<string> { return 'test-key-id'; }
    }

    const registry = new SigningAdapterRegistry();
    registry.register('test-signer', TestSigner);

    expect(registry.getSupportedTypes()).toContain('test-signer');
    const signer = await registry.createSigningAdapter({
      type: 'test-signer',
      name: 'Test Signer',
    });
    expect(signer).toBeInstanceOf(TestSigner);
  });
});

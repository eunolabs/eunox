# Adapter Pattern for Azure Services

## Overview

The Euno capability governance system now implements a clean adapter pattern for identity providers and signing services. This establishes extensible contracts that enable support for multiple implementations, including future Distributed ID (DID) integration.

## Architecture

### Core Components

1. **Base Adapter Classes** (`packages/common/src/adapters.ts`)
   - `IdentityAdapter`: Abstract base class for identity providers
   - `SigningAdapter`: Abstract base class for token signers
   - `IdentityAdapterRegistry`: Factory for creating identity adapters
   - `SigningAdapterRegistry`: Factory for creating signing adapters

2. **Azure Implementations**
   - `AzureADIdentityProvider`: Azure AD identity provider adapter
   - `AzureKeyVaultSigner`: Azure Key Vault signing adapter

3. **DID Stubs** (For Future Implementation)
   - `DIDIdentityProvider`: Placeholder for W3C DID/VC support
   - `DIDSigner`: Placeholder for DID-based signing

## Key Benefits

### 1. Clean Contracts
- Well-defined interfaces separate concerns
- Base classes provide common functionality
- Type-safe configuration objects

### 2. Extensibility
- Easy to add new identity providers (OAuth, SAML, Custom SSO)
- Easy to add new signing methods (HSM, local keys, other cloud providers)
- Future-proof for Distributed ID integration

### 3. Lifecycle Management
- `initialize()`: Setup resources (connections, caches, etc.)
- `dispose()`: Cleanup resources (close connections, clear caches)
- Consistent lifecycle across all adapters

## Usage

### Creating an Azure AD Identity Provider

```typescript
import { AzureADIdentityProvider, AzureADAdapterConfig } from '@euno/capability-issuer';

const config: AzureADAdapterConfig = {
  type: 'azure-ad',
  name: 'Azure AD Identity Provider',
  azureAD: {
    tenantId: process.env.AZURE_AD_TENANT_ID!,
    clientId: process.env.AZURE_AD_CLIENT_ID!,
    clientSecret: process.env.AZURE_AD_CLIENT_SECRET,
  },
};

const identityProvider = new AzureADIdentityProvider(config);
await identityProvider.initialize();

// Use the provider
const userContext = await identityProvider.validateToken(token);
const roles = await identityProvider.getUserRoles(userContext.userId);
```

### Creating an Azure Key Vault Signer

```typescript
import { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from '@euno/capability-issuer';

const config: AzureKeyVaultAdapterConfig = {
  type: 'azure-keyvault',
  name: 'Azure Key Vault Signer',
  keyVault: {
    vaultUrl: process.env.AZURE_KEYVAULT_URL!,
    keyName: 'capability-signing-key',
    credentialType: 'managed-identity',
  },
};

const signer = new AzureKeyVaultSigner(config);
await signer.initialize();

// Use the signer
const token = await signer.sign(payload);
const publicKey = await signer.getPublicKey();
```

### Using the Registry Pattern (Advanced)

```typescript
import {
  IdentityAdapterRegistry,
  SigningAdapterRegistry,
} from '@euno/common';
import { AzureADIdentityProvider } from './azure-ad-identity-provider';
import { DIDIdentityProvider } from './did-identity-provider';

// Create registries
const identityRegistry = new IdentityAdapterRegistry();
const signingRegistry = new SigningAdapterRegistry();

// Register adapters
identityRegistry.register('azure-ad', AzureADIdentityProvider);
identityRegistry.register('did', DIDIdentityProvider);

// Create adapters from configuration
const identityProvider = await identityRegistry.createIdentityAdapter({
  type: 'azure-ad',
  name: 'Production Identity Provider',
  azureAD: { /* config */ },
});
```

## Implementing Custom Adapters

### Custom Identity Provider

```typescript
import { IdentityAdapter, IdentityAdapterConfig, UserContext } from '@euno/common';

export interface CustomIdentityConfig extends IdentityAdapterConfig {
  type: 'custom';
  apiEndpoint: string;
  apiKey: string;
}

export class CustomIdentityProvider extends IdentityAdapter {
  public readonly name = 'custom';
  private config: CustomIdentityConfig;

  constructor(config: CustomIdentityConfig) {
    super(config);
    this.config = config;
  }

  async validateToken(token: string): Promise<UserContext> {
    // Your implementation here
    const response = await fetch(`${this.config.apiEndpoint}/validate`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    // Parse and return user context
  }

  async getUserRoles(userId: string): Promise<string[]> {
    // Your implementation here
  }

  async initialize(): Promise<void> {
    // Setup connections, caches, etc.
  }

  async dispose(): Promise<void> {
    // Cleanup resources
  }
}
```

### Custom Signer

```typescript
import { SigningAdapter, SigningAdapterConfig, CapabilityTokenPayload } from '@euno/common';

export interface CustomSignerConfig extends SigningAdapterConfig {
  type: 'custom-hsm';
  hsmEndpoint: string;
  keyId: string;
}

export class CustomHSMSigner extends SigningAdapter {
  private config: CustomSignerConfig;

  constructor(config: CustomSignerConfig) {
    super(config);
    this.config = config;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    // Your signing implementation here
  }

  async getPublicKey(): Promise<string> {
    // Return public key in PEM format
  }

  async getKeyId(): Promise<string> {
    return this.config.keyId;
  }
}
```

## Future: Distributed ID Support

The system includes placeholder implementations for W3C Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs):

### DID Identity Provider (Planned)

- Validate Verifiable Presentations containing agent credentials
- Resolve DIDs to DID Documents using universal DID resolver
- Support multiple DID methods (did:ion, did:web, did:key)
- Extract capabilities from Verifiable Credentials
- Enable cross-domain trust without centralized identity provider

### DID Signer (Planned)

- Sign tokens using keys from DID Documents
- Reference keys by DID URL (e.g., `did:ion:abc123#key-1`)
- Support multiple key types (RSA, EC, Ed25519)
- Enable verifiers to validate signatures using DID resolution

### Implementation Steps

1. **Install DID Libraries**
   ```bash
   npm install @decentralized-identity/did-resolver
   npm install @decentralized-identity/ion-tools
   ```

2. **Implement DID Resolution**
   - Configure universal DID resolver
   - Support did:ion, did:web, did:key methods
   - Cache DID Documents for performance

3. **Implement VC Verification**
   - Validate Verifiable Presentation signatures
   - Verify Verifiable Credential signatures
   - Check revocation status
   - Extract claims and roles

4. **Update Configuration**
   ```typescript
   const didIdentityConfig = {
     type: 'did',
     name: 'DID Identity Provider',
     didMethod: 'ion',
     resolverEndpoint: 'https://discover.did.msidentity.com/1.0/identifiers',
   };
   ```

## Migration Guide

### From Old Implementation to Adapter Pattern

**Before:**
```typescript
const identityProvider = new AzureADIdentityProvider(config.azureAD!);
const signer = new AzureKeyVaultSigner(config.keyVault!);
```

**After:**
```typescript
const identityProvider = new AzureADIdentityProvider({
  type: 'azure-ad',
  name: 'Azure AD Identity Provider',
  azureAD: config.azureAD!,
});

const signer = new AzureKeyVaultSigner({
  type: 'azure-keyvault',
  name: 'Azure Key Vault Signer',
  keyVault: config.keyVault!,
});
```

### Testing Your Adapter

```typescript
import { describe, it, expect } from '@jest/globals';

describe('CustomIdentityProvider', () => {
  it('should validate tokens correctly', async () => {
    const provider = new CustomIdentityProvider(config);
    await provider.initialize();

    const userContext = await provider.validateToken('valid-token');
    expect(userContext.userId).toBeDefined();
    expect(userContext.roles).toBeInstanceOf(Array);

    await provider.dispose();
  });
});
```

## References

- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
- [Zero-Trust Agents: Adding Identity and Access to Multi-Agent Workflows](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)

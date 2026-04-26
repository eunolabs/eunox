# Third-Party Provider Registration Guide

This guide explains how to create and register custom identity providers and token signers with the Euno capability governance system.

## Overview

The Euno system uses a pluggable adapter pattern that allows you to:
- Add custom identity providers (OAuth, SAML, custom SSO, etc.)
- Add custom token signers (HSM, local keys, cloud KMS, etc.)
- Dynamically load providers at runtime
- Register third-party providers without modifying core code

## Architecture

### Built-in Providers

The system includes these providers out of the box:

**Identity Providers:**
- `azure-ad` - Azure Active Directory / Microsoft Entra ID
- `did` - Decentralized Identifiers (placeholder for future implementation)

**Token Signers:**
- `azure-keyvault` - Azure Key Vault for cryptographic signing
- `did` - DID-based signing (placeholder for future implementation)

### Registry System

Two registries manage providers:
- `defaultIdentityRegistry` - Manages identity provider adapters
- `defaultSigningRegistry` - Manages token signing adapters

Both registries come pre-loaded with built-in providers and support dynamic registration.

## Creating a Custom Identity Provider

### Step 1: Define Your Configuration Interface

```typescript
import { IdentityAdapterConfig } from '@euno/common';

export interface OktaIdentityConfig extends IdentityAdapterConfig {
  type: 'okta';
  domain: string;
  clientId: string;
  clientSecret?: string;
  authorizationServerId?: string;
}
```

### Step 2: Implement the Provider Class

```typescript
import {
  IdentityAdapter,
  UserContext,
  CapabilityError,
  ErrorCode,
} from '@euno/common';
import { OktaJwtVerifier } from '@okta/jwt-verifier';

export class OktaIdentityProvider extends IdentityAdapter {
  public readonly name = 'okta';
  private oktaConfig: OktaIdentityConfig;
  private verifier?: OktaJwtVerifier;

  constructor(config: OktaIdentityConfig) {
    super(config);
    this.oktaConfig = config;
  }

  async initialize(): Promise<void> {
    // Initialize the Okta JWT verifier
    this.verifier = new OktaJwtVerifier({
      issuer: `https://${this.oktaConfig.domain}/oauth2/${this.oktaConfig.authorizationServerId || 'default'}`,
      clientId: this.oktaConfig.clientId,
    });
  }

  async validateToken(token: string): Promise<UserContext> {
    try {
      if (!this.verifier) {
        await this.initialize();
      }

      const jwt = await this.verifier!.verifyAccessToken(token, 'api://default');

      return {
        userId: jwt.claims.sub as string,
        email: jwt.claims.email as string,
        roles: (jwt.claims.groups as string[]) || [],
        claims: jwt.claims as Record<string, unknown>,
      };
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate Okta token: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401
      );
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    // Implement role fetching from Okta
    // This might involve calling Okta's User API
    throw new Error('Not implemented');
  }

  async dispose(): Promise<void> {
    // Cleanup resources if needed
    this.verifier = undefined;
  }
}
```

### Step 3: Register Your Provider

```typescript
import { defaultIdentityRegistry } from '@euno/capability-issuer';
import { OktaIdentityProvider } from './okta-identity-provider';

// Register the custom provider
defaultIdentityRegistry.register('okta', OktaIdentityProvider);

// Later, create instances from configuration
const provider = await defaultIdentityRegistry.createIdentityAdapter({
  type: 'okta',
  name: 'Okta Identity Provider',
  domain: 'dev-12345.okta.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

// Use the provider
const userContext = await provider.validateToken(token);
```

## Creating a Custom Token Signer

### Step 1: Define Your Configuration Interface

```typescript
import { SigningAdapterConfig } from '@euno/common';

export interface HSMSignerConfig extends SigningAdapterConfig {
  type: 'hsm';
  hsmEndpoint: string;
  keyId: string;
  pin?: string;
  slot?: number;
}
```

### Step 2: Implement the Signer Class

```typescript
import {
  SigningAdapter,
  CapabilityTokenPayload,
  SigningAlgorithm,
} from '@euno/common';

export class HSMSigner extends SigningAdapter {
  private hsmConfig: HSMSignerConfig;
  private session?: any; // HSM session handle

  constructor(config: HSMSignerConfig) {
    super(config);
    this.hsmConfig = config;
  }

  async initialize(): Promise<void> {
    // Initialize HSM connection
    // this.session = await connectToHSM({
    //   endpoint: this.hsmConfig.hsmEndpoint,
    //   pin: this.hsmConfig.pin,
    //   slot: this.hsmConfig.slot,
    // });
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    await this.initialize();

    // Create JWT header
    const header = {
      alg: this.algorithm,
      typ: 'JWT',
      kid: await this.getKeyId(),
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Sign with HSM
    // const signature = await this.session.sign({
    //   keyId: this.hsmConfig.keyId,
    //   data: Buffer.from(signingInput),
    //   algorithm: this.algorithm,
    // });

    const signature = Buffer.from('dummy-signature'); // Replace with actual HSM signing
    const encodedSignature = this.base64UrlEncode(signature);

    return `${signingInput}.${encodedSignature}`;
  }

  async getPublicKey(): Promise<string> {
    await this.initialize();
    // Retrieve public key from HSM
    // return await this.session.getPublicKey(this.hsmConfig.keyId);
    return 'dummy-public-key'; // Replace with actual public key retrieval
  }

  async getKeyId(): Promise<string> {
    return this.hsmConfig.keyId;
  }

  async dispose(): Promise<void> {
    // Close HSM session
    if (this.session) {
      // await this.session.close();
      this.session = undefined;
    }
  }

  private base64UrlEncode(input: string | Buffer): string {
    const buffer = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input;
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
```

### Step 3: Register Your Signer

```typescript
import { defaultSigningRegistry } from '@euno/capability-issuer';
import { HSMSigner } from './hsm-signer';

// Register the custom signer
defaultSigningRegistry.register('hsm', HSMSigner);

// Later, create instances from configuration
const signer = await defaultSigningRegistry.createSigningAdapter({
  type: 'hsm',
  name: 'Hardware Security Module Signer',
  algorithm: 'RS256',
  hsmEndpoint: 'https://hsm.example.com',
  keyId: 'signing-key-001',
  pin: process.env.HSM_PIN,
  slot: 0,
});

// Use the signer
const token = await signer.sign(payload);
```

## Dynamic Provider Loading

### Loading Providers from Configuration

You can load providers dynamically based on configuration:

```typescript
import {
  defaultIdentityRegistry,
  defaultSigningRegistry,
} from '@euno/capability-issuer';

interface ProviderConfig {
  identity: {
    type: string;
    [key: string]: any;
  };
  signing: {
    type: string;
    [key: string]: any;
  };
}

async function initializeProviders(config: ProviderConfig) {
  // Create identity provider from config
  const identityProvider = await defaultIdentityRegistry.createIdentityAdapter(
    config.identity
  );

  // Create signing provider from config
  const signingProvider = await defaultSigningRegistry.createSigningAdapter(
    config.signing
  );

  return { identityProvider, signingProvider };
}

// Usage
const providers = await initializeProviders({
  identity: {
    type: 'okta',
    name: 'Production Identity',
    domain: 'company.okta.com',
    clientId: process.env.OKTA_CLIENT_ID,
  },
  signing: {
    type: 'hsm',
    name: 'Production Signer',
    algorithm: 'RS256',
    hsmEndpoint: process.env.HSM_ENDPOINT,
    keyId: 'prod-key',
  },
});
```

### Loading Providers from External Packages

```typescript
// In your application startup code
import { defaultIdentityRegistry } from '@euno/capability-issuer';

// Import third-party provider from npm package
import { Auth0IdentityProvider } from '@acme/euno-auth0-provider';
import { AWSKMSSigner } from '@acme/euno-aws-kms-signer';

// Register third-party providers
defaultIdentityRegistry.register('auth0', Auth0IdentityProvider);
defaultSigningRegistry.register('aws-kms', AWSKMSSigner);

// Now you can use them
const identityProvider = await defaultIdentityRegistry.createIdentityAdapter({
  type: 'auth0',
  name: 'Auth0 Provider',
  domain: 'myapp.auth0.com',
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
});
```

## Best Practices

### 1. Error Handling

Always use `CapabilityError` for consistent error handling:

```typescript
import { CapabilityError, ErrorCode } from '@euno/common';

throw new CapabilityError(
  ErrorCode.AUTHENTICATION_FAILED,
  'Detailed error message',
  401 // HTTP status code
);
```

### 2. Lifecycle Management

Implement `initialize()` and `dispose()` for proper resource management:

```typescript
async initialize(): Promise<void> {
  // Setup connections, caches, clients
  this.client = await createClient(this.config);
}

async dispose(): Promise<void> {
  // Cleanup resources
  if (this.client) {
    await this.client.close();
    this.client = undefined;
  }
}
```

### 3. Configuration Validation

Validate configuration in the constructor:

```typescript
constructor(config: CustomConfig) {
  super(config);

  if (!config.requiredField) {
    throw new Error('requiredField is required in configuration');
  }

  this.customConfig = config;
}
```

### 4. Testing

Write comprehensive tests for your providers:

```typescript
describe('OktaIdentityProvider', () => {
  let provider: OktaIdentityProvider;

  beforeEach(async () => {
    provider = new OktaIdentityProvider({
      type: 'okta',
      name: 'Test Provider',
      domain: 'test.okta.com',
      clientId: 'test-client-id',
    });
    await provider.initialize();
  });

  afterEach(async () => {
    await provider.dispose();
  });

  it('should validate tokens correctly', async () => {
    const userContext = await provider.validateToken('valid-token');
    expect(userContext.userId).toBeDefined();
    expect(userContext.roles).toBeInstanceOf(Array);
  });

  it('should throw error for invalid tokens', async () => {
    await expect(
      provider.validateToken('invalid-token')
    ).rejects.toThrow('AUTHENTICATION_FAILED');
  });
});
```

## Publishing Third-Party Providers

### Package Structure

Create a separate npm package for your provider:

```
my-euno-provider/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts
│   └── my-provider.ts
├── tests/
│   └── my-provider.test.ts
└── README.md
```

### Package.json

```json
{
  "name": "@acme/euno-okta-provider",
  "version": "1.0.0",
  "description": "Okta identity provider for Euno",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "peerDependencies": {
    "@euno/common": "^1.0.0"
  },
  "dependencies": {
    "@okta/jwt-verifier": "^3.0.0"
  }
}
```

### Documentation

Include clear documentation in your package README:

```markdown
# Euno Okta Identity Provider

Custom identity provider for Okta integration with Euno.

## Installation

\`\`\`bash
npm install @acme/euno-okta-provider
\`\`\`

## Usage

\`\`\`typescript
import { defaultIdentityRegistry } from '@euno/capability-issuer';
import { OktaIdentityProvider } from '@acme/euno-okta-provider';

defaultIdentityRegistry.register('okta', OktaIdentityProvider);
\`\`\`

## Configuration

See [full documentation](./docs/configuration.md).
```

## Support and Contributions

For questions or issues with:
- **Core system**: Open an issue in the [Euno repository](https://github.com/edgeobs/euno)
- **Third-party providers**: Contact the provider maintainer

## Examples

See the [examples directory](./examples/) for complete working examples of:
- Custom OAuth2 provider
- Custom JWT signer with local keys
- AWS Cognito integration
- Google Cloud KMS signer

## Related Documentation

- [Adapter Pattern Guide](./ADAPTER_PATTERN.md) - Core adapter architecture
- [API Reference](./docs/api-reference.md) - Complete API documentation
- [Security Best Practices](./docs/security.md) - Security guidelines for providers

# Pluggable Adapters: Identity Providers and Token Signers

The euno capability governance system implements a clean adapter pattern for
identity providers and token signers. This establishes extensible contracts
that enable support for multiple implementations — Azure AD + Azure Key Vault,
AWS Cognito + AWS KMS, GCP Cloud Identity + GCP Cloud KMS, and W3C
Decentralized Identifiers (DIDs) — all behind the same `IdentityAdapter` /
`SigningAdapter` contracts.

---

## Architecture

### Core components (`public/packages/common/src/adapters.ts`)

- `IdentityAdapter` — abstract base class for identity providers
- `SigningAdapter` — abstract base class for token signers
- `IdentityAdapterRegistry` — factory for creating identity adapters
- `SigningAdapterRegistry` — factory for creating signing adapters

### Built-in implementations

**Identity providers**

| Key | Implementation | Location |
|-----|---------------|----------|
| `azure-ad` | Azure Active Directory / Microsoft Entra ID | `azure-identity-provider.ts` |
| `aws-cognito` | Amazon Cognito user pools / compatible OIDC issuers | `aws-cognito-identity-provider.ts` |
| `gcp-identity` | Google identity tokens / Workforce Identity Federation | `gcp-identity-provider.ts` |
| `did` | W3C DID Documents (`did:web`, `did:ion`, `did:key`) | `did-identity-provider.ts` |

**Token signers**

| Key | Implementation | Location |
|-----|---------------|----------|
| `azure-keyvault` | Azure Key Vault asymmetric key signing | `azure-signer.ts` |
| `aws-kms` | AWS KMS asymmetric key signing | `aws-kms-signer.ts` |
| `gcp-cloudkms` | Google Cloud KMS asymmetric key signing | `gcp-cloudkms-signer.ts` |
| `did` | DID-bound local/private-key signing; public key via `/.well-known/did.json` | `did-signer.ts` |

**Implementation references:** the built-in registry is in
`euno-platform/packages/capability-issuer/src/default-registries.ts`.

### Registry system

Two registries manage providers:
- `defaultIdentityRegistry` — manages identity provider adapters
- `defaultSigningRegistry` — manages token signing adapters

Both registries come pre-loaded with built-in providers and support dynamic
registration.

---

## Using built-in providers

### Azure AD identity provider

```typescript
import { AzureADIdentityProvider, AzureADAdapterConfig } from '@euno/capability-issuer/adapters';

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
const userContext = await identityProvider.validateToken(token);
```

### Azure Key Vault signer

```typescript
import { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from '@euno/capability-issuer/adapters';

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
const token = await signer.sign(payload);
```

### AWS KMS signer

```typescript
const awsSigner = await defaultSigningRegistry.createSigningAdapter({
  type: 'aws-kms',
  name: 'AWS KMS Production Signer',
  algorithm: 'RS256',
  awsKMS: {
    region: 'us-east-1',
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
```

### GCP Cloud KMS signer

```typescript
const gcpSigner = await defaultSigningRegistry.createSigningAdapter({
  type: 'gcp-cloudkms',
  name: 'GCP Cloud KMS Production Signer',
  algorithm: 'RS256',
  gcpKMS: {
    projectId: 'my-project-id',
    locationId: 'us-central1',
    keyRingId: 'my-key-ring',
    cryptoKeyId: 'my-crypto-key',
    cryptoKeyVersion: '1',         // optional; uses primary if omitted
    keyFilePath: '/path/to/sa.json', // optional; uses ADC if omitted
  },
});
```

### Registry pattern (advanced)

```typescript
import { IdentityAdapterRegistry, SigningAdapterRegistry } from '@euno/common';

const identityRegistry = new IdentityAdapterRegistry();
const signingRegistry  = new SigningAdapterRegistry();

identityRegistry.register('azure-ad', AzureADIdentityProvider);
identityRegistry.register('did', DIDIdentityProvider);

const identityProvider = await identityRegistry.createIdentityAdapter({
  type: 'azure-ad',
  name: 'Production Identity Provider',
  azureAD: { tenantId: '...', clientId: '...' },
});
```

---

## Creating custom adapters

### Custom identity provider

```typescript
import { IdentityAdapter, IdentityAdapterConfig, UserContext, CapabilityError, ErrorCode } from '@euno/common';

export interface OktaIdentityConfig extends IdentityAdapterConfig {
  type: 'okta';
  domain: string;
  clientId: string;
  clientSecret?: string;
  authorizationServerId?: string;
}

export class OktaIdentityProvider extends IdentityAdapter {
  public readonly name = 'okta';
  private oktaConfig: OktaIdentityConfig;
  private verifier?: OktaJwtVerifier;

  constructor(config: OktaIdentityConfig) {
    super(config);
    this.oktaConfig = config;
  }

  async initialize(): Promise<void> {
    this.verifier = new OktaJwtVerifier({
      issuer: `https://${this.oktaConfig.domain}/oauth2/${this.oktaConfig.authorizationServerId ?? 'default'}`,
      clientId: this.oktaConfig.clientId,
    });
  }

  async validateToken(token: string): Promise<UserContext> {
    if (!this.verifier) await this.initialize();
    try {
      const jwt = await this.verifier!.verifyAccessToken(token, 'api://default');
      return {
        userId: jwt.claims.sub as string,
        email: jwt.claims.email as string,
        roles: (jwt.claims.groups as string[]) ?? [],
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
    throw new Error('Not implemented');
  }

  async dispose(): Promise<void> {
    this.verifier = undefined;
  }
}
```

### Custom token signer (HSM example)

```typescript
import { SigningAdapter, SigningAdapterConfig, CapabilityTokenPayload } from '@euno/common';

export interface HSMSignerConfig extends SigningAdapterConfig {
  type: 'hsm';
  hsmEndpoint: string;
  keyId: string;
  pin?: string;
  slot?: number;
}

export class HSMSigner extends SigningAdapter {
  private hsmConfig: HSMSignerConfig;

  constructor(config: HSMSignerConfig) {
    super(config);
    this.hsmConfig = config;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    // Hash locally, sign with HSM — only the digest crosses the boundary.
    // ...your HSM signing implementation...
  }

  async getPublicKey(): Promise<string> {
    // Retrieve public key from HSM
  }

  async getKeyId(): Promise<string> {
    return this.hsmConfig.keyId;
  }

  async initialize(): Promise<void> { /* open HSM session */ }
  async dispose(): Promise<void>    { /* close HSM session */ }
}
```

### Registering and using a custom provider

```typescript
import { defaultIdentityRegistry, defaultSigningRegistry } from '@euno/capability-issuer/adapters';

defaultIdentityRegistry.register('okta', OktaIdentityProvider);
defaultSigningRegistry.register('hsm', HSMSigner);

const provider = await defaultIdentityRegistry.createIdentityAdapter({
  type: 'okta',
  name: 'Okta Identity Provider',
  domain: 'dev-12345.okta.com',
  clientId: process.env.OKTA_CLIENT_ID,
  clientSecret: process.env.OKTA_CLIENT_SECRET,
});
```

### Dynamic loading from configuration

```typescript
async function initializeProviders(config: { identity: any; signing: any }) {
  const identityProvider = await defaultIdentityRegistry.createIdentityAdapter(config.identity);
  const signingProvider  = await defaultSigningRegistry.createSigningAdapter(config.signing);
  return { identityProvider, signingProvider };
}
```

---

## Best practices

### Error handling

Always use `CapabilityError` for consistent error propagation:

```typescript
throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Descriptive message', 401);
```

### Lifecycle management

Implement `initialize()` and `dispose()` — the service container calls both:

```typescript
async initialize(): Promise<void> { this.client = await createClient(this.config); }
async dispose():    Promise<void> { await this.client?.close(); this.client = undefined; }
```

### Configuration validation

Fail fast in the constructor rather than at runtime:

```typescript
constructor(config: CustomConfig) {
  super(config);
  if (!config.requiredField) throw new Error('requiredField is required');
  this.customConfig = config;
}
```

---

## Publishing a third-party provider package

Create a separate npm package:

```
my-euno-provider/
├── package.json          # peerDependencies: { "@euno/common": "^0.1.0" }
├── tsconfig.json
├── src/
│   ├── index.ts
│   └── my-provider.ts
└── tests/
    └── my-provider.test.ts
```

Name it `@<scope>/euno-<provider-name>` and export the provider class from
`index.ts`. Consumers import it, call `defaultIdentityRegistry.register(...)`,
and configure it the same way as any built-in provider.

---

## References

- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)

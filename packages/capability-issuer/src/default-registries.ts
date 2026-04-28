/**
 * Default Adapter Registries
 *
 * Pre-populated registries with all built-in identity providers and token signers.
 * Importing this module has side effects: it registers the built-in providers.
 *
 * Use these registries for dynamic provider loading from configuration, or register
 * additional third-party providers at application startup:
 *
 * ```typescript
 * import { defaultIdentityRegistry, defaultSigningRegistry } from '@euno/capability-issuer/adapters';
 * import { OktaIdentityProvider } from './okta-provider';
 * import { AWSKMSSigner } from './aws-kms-signer';
 *
 * defaultIdentityRegistry.register('okta', OktaIdentityProvider);
 * defaultSigningRegistry.register('aws-kms', AWSKMSSigner);
 * ```
 */

import { IdentityAdapterRegistry, SigningAdapterRegistry } from '@euno/common';
import { AzureADIdentityProvider } from './azure-identity-provider';
import { AWSCognitoIdentityProvider } from './aws-cognito-identity-provider';
import { GCPIdentityProvider } from './gcp-identity-provider';
import { DIDIdentityProvider } from './did-identity-provider';
import { AzureKeyVaultSigner } from './azure-signer';
import { DIDSigner } from './did-signer';
import { AWSKMSSigner } from './aws-kms-signer';
import { GCPCloudKMSSigner } from './gcp-cloudkms-signer';

/**
 * Default identity provider registry with built-in providers pre-registered.
 *
 * Built-in types: `azure-ad`, `aws-cognito`, `gcp-identity`, `did`
 */
export const defaultIdentityRegistry = new IdentityAdapterRegistry();
defaultIdentityRegistry.register('azure-ad', AzureADIdentityProvider);
defaultIdentityRegistry.register('aws-cognito', AWSCognitoIdentityProvider);
defaultIdentityRegistry.register('gcp-identity', GCPIdentityProvider);
defaultIdentityRegistry.register('did', DIDIdentityProvider);

/**
 * Default signing provider registry with built-in signers pre-registered.
 *
 * Built-in types: `azure-keyvault`, `did`, `aws-kms`, `gcp-cloudkms`
 */
export const defaultSigningRegistry = new SigningAdapterRegistry();
defaultSigningRegistry.register('azure-keyvault', AzureKeyVaultSigner);
defaultSigningRegistry.register('did', DIDSigner);
defaultSigningRegistry.register('aws-kms', AWSKMSSigner);
defaultSigningRegistry.register('gcp-cloudkms', GCPCloudKMSSigner);

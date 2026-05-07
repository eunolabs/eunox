/**
 * Identity Provider Module
 *
 * This module provides the base infrastructure for pluggable identity providers
 * and a registry system for third-party provider registration.
 *
 * To use:
 * 1. Import concrete providers (AzureADIdentityProvider, DIDIdentityProvider, etc.)
 * 2. Create instances directly, or use the registry for dynamic provider loading
 * 3. Register custom third-party providers with the registry
 *
 * For a pre-populated registry with built-in providers, import from
 * `@euno/capability-issuer/adapters` instead:
 * ```typescript
 * import { defaultIdentityRegistry } from '@euno/capability-issuer/adapters';
 * import { MyCustomProvider } from './my-custom-provider';
 *
 * defaultIdentityRegistry.register('my-provider', MyCustomProvider);
 * ```
 */

// Re-export base classes and interfaces from common
export {
  IdentityAdapter,
  IdentityAdapterConfig,
  IdentityAdapterRegistry,
  IdentityAdapterFactory,
} from '@euno/common';

// Re-export built-in provider implementations
export { AzureADIdentityProvider, AzureADAdapterConfig } from './azure-identity-provider';
export { AWSCognitoIdentityProvider, AWSCognitoAdapterConfig } from './aws-cognito-identity-provider';
export { GCPIdentityProvider, GCPIdentityAdapterConfig } from './gcp-identity-provider';
export { DIDIdentityProvider, DIDIdentityAdapterConfig } from './did-identity-provider';

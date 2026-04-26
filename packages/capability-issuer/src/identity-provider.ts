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
export { DIDIdentityProvider, DIDIdentityAdapterConfig } from './did-identity-provider';

// Import for default registry setup
import { IdentityAdapterRegistry } from '@euno/common';
import { AzureADIdentityProvider } from './azure-identity-provider';
import { DIDIdentityProvider } from './did-identity-provider';

/**
 * Default identity provider registry with built-in providers pre-registered.
 *
 * Third-party providers can be registered using:
 * ```typescript
 * import { defaultIdentityRegistry } from '@euno/capability-issuer';
 * import { MyCustomProvider } from './my-custom-provider';
 *
 * defaultIdentityRegistry.register('my-provider', MyCustomProvider);
 *
 * // Later, create instances from config
 * const provider = await defaultIdentityRegistry.createIdentityAdapter({
 *   type: 'my-provider',
 *   name: 'My Provider',
 *   // ... custom config
 * });
 * ```
 */
export const defaultIdentityRegistry = new IdentityAdapterRegistry();

// Register built-in providers
defaultIdentityRegistry.register('azure-ad', AzureADIdentityProvider);
defaultIdentityRegistry.register('did', DIDIdentityProvider);

/**
 * Token Signer Module
 *
 * This module provides the base infrastructure for pluggable token signers
 * and a registry system for third-party signer registration.
 *
 * To use:
 * 1. Import concrete signers (AzureKeyVaultSigner, DIDSigner, etc.)
 * 2. Create instances directly, or use the registry for dynamic signer loading
 * 3. Register custom third-party signers with the registry
 */

// Re-export base classes and interfaces from common
export {
  SigningAdapter,
  SigningAdapterConfig,
  SigningAdapterRegistry,
  SigningAdapterFactory,
  SigningAlgorithm,
} from '@euno/common';

// Re-export built-in signer implementations
export { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from './azure-signer';
export { DIDSigner, DIDSigningAdapterConfig } from './did-signer';

// Import for default registry setup
import { SigningAdapterRegistry } from '@euno/common';
import { AzureKeyVaultSigner } from './azure-signer';
import { DIDSigner } from './did-signer';

/**
 * Default signing provider registry with built-in signers pre-registered.
 *
 * Third-party signers can be registered using:
 * ```typescript
 * import { defaultSigningRegistry } from '@euno/capability-issuer';
 * import { MyCustomSigner } from './my-custom-signer';
 *
 * defaultSigningRegistry.register('my-signer', MyCustomSigner);
 *
 * // Later, create instances from config
 * const signer = await defaultSigningRegistry.createSigningAdapter({
 *   type: 'my-signer',
 *   name: 'My Signer',
 *   // ... custom config
 * });
 * ```
 */
export const defaultSigningRegistry = new SigningAdapterRegistry();

// Register built-in signers
defaultSigningRegistry.register('azure-keyvault', AzureKeyVaultSigner);
defaultSigningRegistry.register('did', DIDSigner);

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
 *
 * For a pre-populated registry with built-in signers, import from
 * `@euno/capability-issuer/adapters` instead:
 * ```typescript
 * import { defaultSigningRegistry } from '@euno/capability-issuer/adapters';
 * import { MyCustomSigner } from './my-custom-signer';
 *
 * defaultSigningRegistry.register('my-signer', MyCustomSigner);
 * ```
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

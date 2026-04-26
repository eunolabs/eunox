/**
 * Adapter interfaces and base classes for extensible identity and signing implementations
 *
 * This module defines clean contracts that enable:
 * - Multiple identity provider implementations (Azure AD, Distributed ID, etc.)
 * - Multiple signing implementations (Azure Key Vault, local keys, HSM, etc.)
 * - Easy extensibility for future providers
 */

import {
  IdentityProvider,
  UserContext,
  TokenSigner,
  CapabilityTokenPayload,
} from './types';

/**
 * Base configuration for identity adapters
 */
export interface IdentityAdapterConfig {
  /** Adapter type identifier */
  type: string;
  /** Human-readable name */
  name: string;
  /** Additional configuration options */
  options?: Record<string, unknown>;
}

/**
 * Base configuration for signing adapters
 */
export interface SigningAdapterConfig {
  /** Adapter type identifier */
  type: string;
  /** Human-readable name */
  name: string;
  /** Additional configuration options */
  options?: Record<string, unknown>;
}

/**
 * Abstract base class for identity provider adapters
 * Provides common functionality and enforces interface implementation
 */
export abstract class IdentityAdapter implements IdentityProvider {
  public abstract readonly name: string;
  protected config: IdentityAdapterConfig;

  constructor(config: IdentityAdapterConfig) {
    this.config = config;
  }

  /**
   * Validate an authentication token and extract user context
   * Must be implemented by concrete adapters
   */
  abstract validateToken(token: string): Promise<UserContext>;

  /**
   * Get user roles and permissions
   * Must be implemented by concrete adapters
   */
  abstract getUserRoles(userId: string): Promise<string[]>;

  /**
   * Check if user has specific permission
   * Default implementation uses getUserRoles, but can be overridden for optimization
   */
  async hasPermission(userId: string, permission: string): Promise<boolean> {
    const roles = await this.getUserRoles(userId);
    return roles.includes(permission);
  }

  /**
   * Get adapter configuration
   */
  getConfig(): IdentityAdapterConfig {
    return { ...this.config };
  }

  /**
   * Lifecycle hook: initialize resources
   * Override if adapter needs initialization
   */
  async initialize(): Promise<void> {
    // Default: no-op
  }

  /**
   * Lifecycle hook: cleanup resources
   * Override if adapter needs cleanup
   */
  async dispose(): Promise<void> {
    // Default: no-op
  }
}

/**
 * Abstract base class for token signing adapters
 * Provides common functionality and enforces interface implementation
 */
export abstract class SigningAdapter implements TokenSigner {
  protected config: SigningAdapterConfig;

  constructor(config: SigningAdapterConfig) {
    this.config = config;
  }

  /**
   * Sign a capability token payload
   * Must be implemented by concrete adapters
   */
  abstract sign(payload: CapabilityTokenPayload): Promise<string>;

  /**
   * Get the public key for verification (in PEM format)
   * Must be implemented by concrete adapters
   */
  abstract getPublicKey(): Promise<string>;

  /**
   * Get the key ID used for signing
   * Must be implemented by concrete adapters
   */
  abstract getKeyId(): Promise<string>;

  /**
   * Get adapter configuration
   */
  getConfig(): SigningAdapterConfig {
    return { ...this.config };
  }

  /**
   * Lifecycle hook: initialize resources
   * Override if adapter needs initialization
   */
  async initialize(): Promise<void> {
    // Default: no-op
  }

  /**
   * Lifecycle hook: cleanup resources
   * Override if adapter needs cleanup
   */
  async dispose(): Promise<void> {
    // Default: no-op
  }
}

/**
 * Factory interface for creating identity adapters
 */
export interface IdentityAdapterFactory {
  /**
   * Create an identity adapter from configuration
   */
  createIdentityAdapter<T extends IdentityAdapterConfig>(config: T): Promise<IdentityAdapter>;

  /**
   * Get supported adapter types
   */
  getSupportedTypes(): string[];
}

/**
 * Factory interface for creating signing adapters
 */
export interface SigningAdapterFactory {
  /**
   * Create a signing adapter from configuration
   */
  createSigningAdapter<T extends SigningAdapterConfig>(config: T): Promise<SigningAdapter>;

  /**
   * Get supported adapter types
   */
  getSupportedTypes(): string[];
}

/**
 * Adapter registry for managing multiple identity providers
 */
export class IdentityAdapterRegistry implements IdentityAdapterFactory {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private adapters: Map<string, new (config: any) => IdentityAdapter> = new Map();

  /**
   * Register an identity adapter type.
   * Accepts adapter classes whose constructors require a narrower config type
   * (e.g. AzureADAdapterConfig) so concrete adapters type-check correctly.
   */
  register<T extends IdentityAdapterConfig>(
    type: string,
    adapterClass: new (config: T) => IdentityAdapter
  ): void {
    this.adapters.set(type, adapterClass);
  }

  /**
   * Create an identity adapter from configuration
   */
  async createIdentityAdapter<T extends IdentityAdapterConfig>(config: T): Promise<IdentityAdapter> {
    const AdapterClass = this.adapters.get(config.type);
    if (!AdapterClass) {
      throw new Error(`Unknown identity adapter type: ${config.type}`);
    }

    const adapter = new AdapterClass(config);
    await adapter.initialize();
    return adapter;
  }

  /**
   * Get supported adapter types
   */
  getSupportedTypes(): string[] {
    return Array.from(this.adapters.keys());
  }
}

/**
 * Adapter registry for managing multiple signing providers
 */
export class SigningAdapterRegistry implements SigningAdapterFactory {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private adapters: Map<string, new (config: any) => SigningAdapter> = new Map();

  /**
   * Register a signing adapter type.
   * Accepts adapter classes whose constructors require a narrower config type
   * (e.g. AzureKeyVaultAdapterConfig) so concrete adapters type-check correctly.
   */
  register<T extends SigningAdapterConfig>(
    type: string,
    adapterClass: new (config: T) => SigningAdapter
  ): void {
    this.adapters.set(type, adapterClass);
  }

  /**
   * Create a signing adapter from configuration
   */
  async createSigningAdapter<T extends SigningAdapterConfig>(config: T): Promise<SigningAdapter> {
    const AdapterClass = this.adapters.get(config.type);
    if (!AdapterClass) {
      throw new Error(`Unknown signing adapter type: ${config.type}`);
    }

    const adapter = new AdapterClass(config);
    await adapter.initialize();
    return adapter;
  }

  /**
   * Get supported adapter types
   */
  getSupportedTypes(): string[] {
    return Array.from(this.adapters.keys());
  }
}

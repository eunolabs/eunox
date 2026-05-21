/**
 * Typed `EunoConfig` Zod schemas — R-5.
 *
 * This file is now a re-export barrel; each service schema lives in its
 * own sub-file in this directory.  All public types and schemas remain
 * importable from this path for backward compatibility.
 */

export * from './base-schema';
export * from './issuer-schema';
export * from './gateway-schema';
export * from './db-token-service-schema';
export * from './storage-grant-service-schema';
export * from './agent-runtime-schema';
export * from './minter-schema';

import { IssuerConfigSchema } from './issuer-schema';
import { GatewayConfigSchema } from './gateway-schema';
import { DbTokenServiceConfigSchema } from './db-token-service-schema';
import { StorageGrantServiceConfigSchema } from './storage-grant-service-schema';
import { AgentRuntimeConfigSchema } from './agent-runtime-schema';
import { MinterConfigSchema } from './minter-schema';

import type { IssuerConfig } from './issuer-schema';
import type { GatewayConfig } from './gateway-schema';
import type { DbTokenServiceConfig } from './db-token-service-schema';
import type { StorageGrantServiceConfig } from './storage-grant-service-schema';
import type { AgentRuntimeConfig } from './agent-runtime-schema';
import type { MinterConfig } from './minter-schema';

// ---------------------------------------------------------------------------
// Service registry — drives the loader and the dump-template generator.
// ---------------------------------------------------------------------------

/**
 * Names of services that participate in the typed-config contract.
 * Adding a new service is a four-step change:
 *
 *   1. Define a `<Service>ConfigSchema` above.
 *   2. Add it to {@link EUNO_CONFIG_SCHEMAS} below.
 *   3. Wire `loadConfig(process.env, '<service>')` into the service
 *      boot path.
 *   4. Run `euno config dump-template --service <service> > .env.example`
 *      to materialise the template.
 */
export const EUNO_SERVICE_NAMES = [
  'issuer',
  'gateway',
  'db-token-service',
  'storage-grant-service',
  'agent-runtime',
  'minter',
] as const;
export type EunoServiceName = (typeof EUNO_SERVICE_NAMES)[number];

export const EUNO_CONFIG_SCHEMAS = {
  issuer: IssuerConfigSchema,
  gateway: GatewayConfigSchema,
  'db-token-service': DbTokenServiceConfigSchema,
  'storage-grant-service': StorageGrantServiceConfigSchema,
  'agent-runtime': AgentRuntimeConfigSchema,
  minter: MinterConfigSchema,
} as const;

export type EunoConfigFor<S extends EunoServiceName> = S extends 'issuer'
  ? IssuerConfig
  : S extends 'gateway'
    ? GatewayConfig
    : S extends 'db-token-service'
      ? DbTokenServiceConfig
      : S extends 'storage-grant-service'
        ? StorageGrantServiceConfig
        : S extends 'agent-runtime'
          ? AgentRuntimeConfig
          : S extends 'minter'
            ? MinterConfig
            : never;

/**
 * The shape of a `EunoConfig` for any of the registered services.
 */
export type EunoConfig =
  | IssuerConfig
  | GatewayConfig
  | DbTokenServiceConfig
  | StorageGrantServiceConfig
  | AgentRuntimeConfig
  | MinterConfig;

import { z } from 'zod';
import { optionalString, envBoolean, envPositiveInt, envPort, NODE_ENV } from './base-schema';

// ---------------------------------------------------------------------------
// Storage Grant Service schema — `storage-grant-service`
// ---------------------------------------------------------------------------

export const StorageGrantServiceConfigSchema = z
  .object({
    NODE_ENV,
    PORT: envPort({
      default: 8082,
      description: 'TCP port the storage-grant-service HTTP server binds to.',
    }),

    // JWT verification
    ISSUER_JWKS_URI: z
      .string()
      .min(1)
      .describe(
        'JWKS endpoint of the capability-issuer used to verify incoming capability tokens. ' +
        'Required. Example: http://capability-issuer:3001/.well-known/jwks.json',
      ),
    ISSUER_DID: z
      .string()
      .min(1)
      .describe(
        'Expected `iss` claim in incoming capability tokens. Required. ' +
        'Must match the ISSUER_DID set on the corresponding capability-issuer.',
      ),
    GATEWAY_AUDIENCE: optionalString.describe(
      'Expected `aud` claim in incoming capability tokens. Default "tool-gateway".',
    ),

    // Storage grant minting
    STORAGE_GRANTS_ENABLED: envBoolean({
      default: false,
      description:
        'Enable storage-grant minting. Must be "true" for the service to issue storage credentials. ' +
        'When false the service starts but all /grant requests return 503.',
    }),
    STORAGE_GRANT_MAX_TTL_SECONDS: envPositiveInt({
      default: 900,
      description: 'Cap on storage grant TTL in seconds. Default 900; hard ceiling 3600.',
      max: 3600,
    }),
    AWS_REGION: optionalString.describe(
      'AWS region for S3 storage-grant calls.',
    ),
    AWS_STORAGE_GRANT_ROLE_ARN: optionalString.describe(
      'IAM role ARN the service assumes to mint AWS storage grants. ' +
      'MUST be distinct from any JWT-signing key role to limit blast radius.',
    ),
    AWS_ACCESS_KEY_ID: optionalString.describe(
      'AWS access key. Optional; falls back to the default credential provider chain.',
    ),
    AWS_SECRET_ACCESS_KEY: optionalString.describe(
      'AWS secret access key. Optional; falls back to the default credential provider chain.',
    ),
    AWS_SESSION_TOKEN: optionalString.describe(
      'AWS session token, for temporary credentials. Optional.',
    ),
  });

export type StorageGrantServiceConfig = z.infer<typeof StorageGrantServiceConfigSchema>;

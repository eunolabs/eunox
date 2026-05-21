import { z } from 'zod';
import { optionalString, envBoolean, envPositiveInt, envPort, NODE_ENV } from './base-schema';

// ---------------------------------------------------------------------------
// DB Token Service schema — `db-token-service`
// ---------------------------------------------------------------------------

export const DbTokenServiceConfigSchema = z
  .object({
    NODE_ENV,
    PORT: envPort({
      default: 8083,
      description: 'TCP port the db-token-service HTTP server binds to.',
    }),

    // JWT verification — tokens presented to this service were minted by
    // the capability-issuer; we verify them with the issuer's public JWKS.
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
      'Expected `aud` claim in incoming capability tokens. Default "tool-gateway". ' +
      'Must match the GATEWAY_AUDIENCE set on the corresponding capability-issuer and gateway.',
    ),

    // DB token minting
    DB_TOKENS_ENABLED: envBoolean({
      default: false,
      description:
        'Enable DB-token minting. Must be "true" for the service to issue database credentials. ' +
        'When false the service starts but all /token requests return 503.',
    }),
    DB_INSTANCES_FILE: optionalString.describe(
      'Path to the operator-declared JSON allow-list of permitted DB instances. ' +
      'Required when DB_TOKENS_ENABLED=true.',
    ),
    DB_TOKEN_MAX_TTL_SECONDS: envPositiveInt({
      default: 900,
      description: 'Cap on DB token TTL in seconds. Default 900; hard ceiling 900.',
      max: 900,
    }),
    DB_USERNAME_POLICY_FILE: optionalString.describe(
      'Optional path to a JSON file mapping capability roles to DB usernames. ' +
      'When unset, the ambient IAM user / role name is used.',
    ),
    AWS_DB_TOKEN_ROLE_ARN: optionalString.describe(
      'IAM role ARN to assume before calling rds:GenerateDbAuthToken. ' +
      'When set, RDS token minting uses a dedicated minimal role distinct from the ambient IAM credentials.',
    ),
    AWS_REGION: optionalString.describe(
      'AWS region for RDS DB-token calls.',
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
  })
  .superRefine((cfg, ctx) => {
    if (cfg.DB_TOKENS_ENABLED && !cfg.DB_INSTANCES_FILE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['DB_INSTANCES_FILE'],
        message:
          'DB_INSTANCES_FILE is required when DB_TOKENS_ENABLED=true (operator-declared instance allow-list).',
      });
    }
  });

export type DbTokenServiceConfig = z.infer<typeof DbTokenServiceConfigSchema>;

import { z } from 'zod';
import { optionalString, envBoolean, envPositiveInt, envPort, envEnum, NODE_ENV } from './base-schema';

// ---------------------------------------------------------------------------
// Minter schema — `minter`
// ---------------------------------------------------------------------------

export const MinterConfigSchema = z
  .object({
    NODE_ENV,

    // HTTP server
    MINTER_PORT: envPort({
      default: 3004,
      description: 'TCP port the API-key minter HTTP server binds to.',
    }),

    // Token claims
    MINTER_ISSUER_DID: optionalString.describe(
      'DID used as the `iss` claim in minted capability tokens. ' +
      'Default "did:web:minter.euno.local".',
    ),
    MINTER_GATEWAY_AUDIENCE: optionalString.describe(
      'Expected `aud` claim in minted capability tokens. Default "tool-gateway".',
    ),
    MINTER_TOKEN_TTL_SECONDS: envPositiveInt({
      default: 300,
      description:
        'Lifetime of minted capability tokens in seconds. Default 300 (5 min). ' +
        'Reduce for high-security workloads, increase for chatty agents that ' +
        'cannot tolerate frequent re-minting.',
    }),

    // Admin authentication
    MINTER_ADMIN_API_KEY: optionalString.describe(
      'Shared secret required to call admin endpoints (/admin/keys, /admin/policies). ' +
      'MUST be set in production, MUST NOT equal "dev-admin-key", and MUST be at least ' +
      '32 characters. Defaults to "dev-admin-key" in development for convenience only.',
    ),
    MINTER_ADMIN_JWKS_URI: optionalString.describe(
      'JWKS endpoint for admin JWT verification. ' +
      'When set alongside MINTER_ADMIN_JWT_AUDIENCE, operator JWTs are accepted as ' +
      'the primary authentication path for admin routes. ' +
      'Example: https://accounts.example.com/.well-known/jwks.json',
    ),
    MINTER_ADMIN_JWT_AUDIENCE: optionalString.describe(
      'Expected `aud` claim in admin JWTs. Required alongside MINTER_ADMIN_JWKS_URI.',
    ),
    MINTER_ADMIN_JWT_ISSUER: optionalString.describe(
      'Expected `iss` claim in admin JWTs. ' +
      'When set, tokens whose issuer does not match are rejected. ' +
      'Omit to skip issuer validation (useful during migration between IdPs). ' +
      'Requires MINTER_ADMIN_JWKS_URI and MINTER_ADMIN_JWT_AUDIENCE to be set.',
    ),

    // Pepper / key derivation
    MINTER_PEPPER_HEX: optionalString
      .pipe(
        z
          .string()
          .optional()
          .refine(
            (v) => v === undefined || /^[0-9a-fA-F]{64}$/.test(v),
            (v) => ({
              message:
                `MINTER_PEPPER_HEX must be a 64-character hex string (32 bytes / 256-bit pepper); ` +
                `got ${v === undefined ? 'undefined' : `"${v}" (${v.length} chars)`}.`,
            }),
          ),
      )
      .describe(
        '256-bit API-key pepper as a 64-character hex string (case-insensitive). ' +
        'MUST be set in production. Defaults to a random ephemeral value in development ' +
        '(keys will not survive restarts).',
      ),
    MINTER_PEPPER_VERSION: optionalString.describe(
      'Symbolic version label for MINTER_PEPPER_HEX (e.g. "v1", "v2"). ' +
      'Used to support pepper rotation. Default "v1".',
    ),

    // Rate limiting
    MINTER_RATE_LIMIT_MAX: envPositiveInt({
      default: 100,
      description:
        'Maximum number of mint requests allowed per rate-limit window per IP. Default 100.',
    }),
    MINTER_RATE_LIMIT_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description: 'Duration of the rate-limit window in seconds. Default 60.',
    }),

    // Signing key
    MINTER_KMS_PROVIDER: envEnum({
      values: ['azure-keyvault', 'aws-kms', 'gcp-cloudkms'] as const,
      description:
        'Cloud KMS provider for HSM-backed signing. ' +
        'When set, MINTER_PRIVATE_KEY_PEM / MINTER_PUBLIC_KEY_PEM are ignored. ' +
        'One of: azure-keyvault, aws-kms, gcp-cloudkms.',
    }),
    MINTER_PRIVATE_KEY_PEM: optionalString.describe(
      'PEM-encoded private key for local software signing (self-host / CI). ' +
      'Required alongside MINTER_PUBLIC_KEY_PEM when MINTER_KMS_PROVIDER is unset. ' +
      'In production prefer MINTER_KMS_PROVIDER for HSM-backed non-exportable keys.',
    ),
    MINTER_PUBLIC_KEY_PEM: optionalString.describe(
      'PEM-encoded public key matching MINTER_PRIVATE_KEY_PEM. ' +
      'Required alongside MINTER_PRIVATE_KEY_PEM.',
    ),
    MINTER_SIGNING_ALGORITHM: optionalString.describe(
      'JWT signing algorithm (e.g. "RS256", "ES256"). ' +
      'Inferred from the key type when unset.',
    ),

    // Audit store
    MINTER_AUDIT_DB_URL: optionalString.describe(
      'PostgreSQL connection URL for the append-only mint audit store. ' +
      'MUST be set in production. Uses separate credentials from any other DB (threat model §6). ' +
      'Defaults to an in-memory store in development (audit trail lost on restart).',
    ),
    MINTER_AUDIT_SCHEMA_INIT: envBoolean({
      default: false,
      description:
        'Run DDL on the Postgres audit store table at startup. ' +
        'Set "true" only when the service account has DDL privileges. ' +
        'Prefer running migrations from a sidecar with a dedicated DDL role in production.',
    }),

    // API-key store
    MINTER_API_KEY_DB_URL: optionalString.describe(
      'PostgreSQL connection URL for the durable API-key store. ' +
      'MUST be set in production. Defaults to an in-memory store in development ' +
      '(all keys lost on restart).',
    ),
    MINTER_API_KEY_SCHEMA_INIT: envBoolean({
      default: false,
      description:
        'Run DDL on the Postgres API-key store table at startup. ' +
        'Set "true" only when the service account has DDL privileges.',
    }),

    // Postgres connection pool configuration
    MINTER_AUDIT_POOL_SIZE: envPositiveInt({
      default: 5,
      description:
        'Maximum number of connections in the Postgres audit store connection pool. ' +
        'Increase for high-throughput minting workloads. Default 5.',
    }),
    MINTER_API_KEY_POOL_SIZE: envPositiveInt({
      default: 5,
      description:
        'Maximum number of connections in the Postgres API-key store connection pool. ' +
        'Increase when many concurrent key lookups are expected. Default 5.',
    }),
    MINTER_PG_CONNECTION_TIMEOUT_MS: envPositiveInt({
      default: 5000,
      description:
        'Timeout in milliseconds for acquiring a connection from any Postgres pool. ' +
        'Requests that cannot obtain a connection within this window are rejected with an error. ' +
        'Default 5000 ms.',
    }),

    // Replica identity
    MINTER_REPLICA_ID: optionalString.describe(
      'Identifier for this minter replica. ' +
      'Used for anomaly-detection shard keys. Defaults to os.hostname().',
    ),

    // Redis — fleet-wide anomaly detection and ping rate limiting
    REDIS_URL: optionalString.describe(
      'Redis connection URL used as the default for fleet-wide stores ' +
      '(anomaly detector, ping rate limiter). ' +
      'Optional; falls back to in-memory per-replica stores. ' +
      'In production MUST point at an HA endpoint (Sentinel or Cluster).',
    ),
    ANOMALY_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the anomaly detector. ' +
      'Overrides REDIS_URL for this store.',
    ),
    MINTER_PING_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the ping rate limiter. ' +
      'Overrides REDIS_URL for this store.',
    ),
    MINTER_MINT_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the mint rate limiter (POST /api/v1/mint). ' +
      'Overrides REDIS_URL for this store. ' +
      'In production MUST point at an HA endpoint (Sentinel or Cluster).',
    ),
  })
  .superRefine((cfg, ctx) => {
    if (cfg.NODE_ENV !== 'production') return;

    // In production: MINTER_ADMIN_API_KEY must be a secure value.
    if (!cfg.MINTER_ADMIN_API_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_ADMIN_API_KEY'],
        message:
          'MINTER_ADMIN_API_KEY must be set when NODE_ENV=production. ' +
          'Use a securely-generated random string of at least 32 characters.',
      });
    } else if (cfg.MINTER_ADMIN_API_KEY === 'dev-admin-key') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_ADMIN_API_KEY'],
        message:
          'MINTER_ADMIN_API_KEY must not use the insecure default "dev-admin-key" in production.',
      });
    } else if (cfg.MINTER_ADMIN_API_KEY.length < 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_ADMIN_API_KEY'],
        message:
          'MINTER_ADMIN_API_KEY is too short for production use. ' +
          'Minimum length is 32 characters.',
      });
    }

    // In production: MINTER_PEPPER_HEX must be set.
    if (!cfg.MINTER_PEPPER_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_PEPPER_HEX'],
        message:
          'MINTER_PEPPER_HEX must be set when NODE_ENV=production. ' +
          'Generate a 64-character hex string: openssl rand -hex 32',
      });
    }

    // In production: a signing key must be configured.
    const hasKms = !!cfg.MINTER_KMS_PROVIDER;
    const hasPem = !!(cfg.MINTER_PRIVATE_KEY_PEM && cfg.MINTER_PUBLIC_KEY_PEM);
    if (!hasKms && !hasPem) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_KMS_PROVIDER'],
        message:
          'A signing key must be configured in production: ' +
          'set MINTER_KMS_PROVIDER (KMS/HSM) or both MINTER_PRIVATE_KEY_PEM and MINTER_PUBLIC_KEY_PEM ' +
          '(local software signing — less secure).',
      });
    }

    // In production: both PEM vars must be set together.
    if (!hasKms && cfg.MINTER_PRIVATE_KEY_PEM && !cfg.MINTER_PUBLIC_KEY_PEM) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_PUBLIC_KEY_PEM'],
        message: 'MINTER_PUBLIC_KEY_PEM must be set when MINTER_PRIVATE_KEY_PEM is provided.',
      });
    }
    if (!hasKms && !cfg.MINTER_PRIVATE_KEY_PEM && cfg.MINTER_PUBLIC_KEY_PEM) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_PRIVATE_KEY_PEM'],
        message: 'MINTER_PRIVATE_KEY_PEM must be set when MINTER_PUBLIC_KEY_PEM is provided.',
      });
    }

    // In production: Postgres-backed stores are required.
    if (!cfg.MINTER_AUDIT_DB_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_AUDIT_DB_URL'],
        message:
          'MINTER_AUDIT_DB_URL must be set when NODE_ENV=production. ' +
          'The in-memory audit store is not suitable for production.',
      });
    }
    if (!cfg.MINTER_API_KEY_DB_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['MINTER_API_KEY_DB_URL'],
        message:
          'MINTER_API_KEY_DB_URL must be set when NODE_ENV=production. ' +
          'The in-memory API-key store is not suitable for production.',
      });
    }
  });

export type MinterConfig = z.infer<typeof MinterConfigSchema>;

/**
 * Typed `EunoConfig` Zod schemas — R-5 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md` (addresses I-13 and I-24).
 *
 * Every environment variable consumed by the issuer or gateway is
 * declared here as a single source of truth. The schemas are used at
 * three distinct sites:
 *
 *   1. {@link ./loader.ts} — `loadConfig(env, service)` validates
 *      `process.env` at boot and produces a single, structured
 *      "what's wrong" report on misconfig (no partial defaults, no
 *      late `undefined`s leaking into business code).
 *   2. {@link ./dump-template.ts} — generates the `.env.example` file
 *      content for each service, replacing the per-service
 *      hand-curated `.env.example` and `.env.template` duplicates.
 *   3. The CLI: `euno config dump-template --service <name>` re-emits
 *      the templates so they stay in lock-step with the schema.
 *
 * Each field carries a `.describe(...)` doc string so the dump-template
 * generator can emit human-meaningful comments in the `.env.example`
 * output.  When you add a new env var, add it here — the template,
 * the loader, and the docs all update from the same edit.
 */

import { z } from 'zod';
import { BACKPRESSURE_POLICIES } from '../audit-pipeline';

// ---------------------------------------------------------------------------
// Field-level helpers.
// ---------------------------------------------------------------------------
//
// Env vars are always strings in `process.env`.  Treat the *empty
// string* the same as "unset" so that defaults apply uniformly whether
// the operator left the variable absent from `.env` or wrote
// `FOO=` explicitly.  Zod's `z.optional()` does not coerce empty
// strings, so wrap everything that goes into a schema with
// `optionalString` first.

const optionalString = z
  .string()
  .transform((value) => (value === '' ? undefined : value))
  .optional();

/**
 * Coerce a string env var into a boolean using the `'true'` / `'false'`
 * convention used throughout the existing codebase.  Anything else is
 * a hard validation error so misconfig is loud, not silent.
 *
 * Overloaded so that callers who pass a `default` get a non-nullable
 * `boolean` in the inferred output type — eliminating the `!` /
 * `?? false` workarounds that downstream wiring would otherwise need.
 */
function envBoolean(opts: { default: boolean; description: string }): z.ZodType<boolean, z.ZodTypeDef, unknown>;
function envBoolean(opts: { description: string }): z.ZodType<boolean | undefined, z.ZodTypeDef, unknown>;
function envBoolean(opts: { default?: boolean; description: string }): z.ZodType<boolean | undefined, z.ZodTypeDef, unknown> {
  return optionalString
    .pipe(
      z
        .union([z.literal('true'), z.literal('false'), z.undefined()])
        .transform((v) => (v === undefined ? opts.default : v === 'true')),
    )
    .describe(opts.description);
}

/**
 * Coerce a string env var into a positive integer, with a default and
 * a meaningful error message.  Used for ports, TTLs, intervals, etc.
 *
 * Overloaded so that callers who pass a `default` get a non-nullable
 * `number` in the inferred output type.
 */
function envPositiveInt(opts: {
  default: number;
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number, z.ZodTypeDef, unknown>;
function envPositiveInt(opts: {
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number | undefined, z.ZodTypeDef, unknown>;
function envPositiveInt(opts: {
  default?: number;
  description: string;
  min?: number;
  max?: number;
}): z.ZodType<number | undefined, z.ZodTypeDef, unknown> {
  const min = opts.min ?? 1;
  const max = opts.max ?? Number.MAX_SAFE_INTEGER;
  return optionalString
    .pipe(
      z
        .string()
        .optional()
        .transform((v, ctx) => {
          if (v === undefined) return opts.default;
          // Reject partially-numeric strings like "10abc" outright. Without
          // this guard `Number.parseInt('10abc', 10)` silently returns 10
          // and a misconfig slips through — defeating the "loud failure"
          // goal of R-5. A leading '+' is allowed for symmetry with the
          // shell convention; '-' falls through to the range check.
          if (!/^[+-]?\d+$/.test(v)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be an integer (got "${v}")`,
            });
            return z.NEVER;
          }
          const parsed = Number.parseInt(v, 10);
          if (!Number.isFinite(parsed)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be an integer (got "${v}")`,
            });
            return z.NEVER;
          }
          if (parsed < min || parsed > max) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `must be between ${min} and ${max} (got ${parsed})`,
            });
            return z.NEVER;
          }
          return parsed;
        }),
    )
    .describe(opts.description);
}

/**
 * Specialisation of {@link envPositiveInt} for TCP port numbers (1–65535).
 * Validates that the value is a valid port number and provides a consistent
 * error message across all service schemas.
 */
function envPort(opts: { default: number; description: string }): z.ZodType<number, z.ZodTypeDef, unknown> {
  return envPositiveInt({ ...opts, min: 1, max: 65535 }) as z.ZodType<number, z.ZodTypeDef, unknown>;
}

/**
 * Treat an env var as a comma-separated list of trimmed, non-empty
 * strings.  Returns `undefined` when unset so callers can distinguish
 * "no value" from "empty list".
 */
function envCsv(opts: { description: string }) {
  return optionalString
    .pipe(
      z
        .string()
        .optional()
        .transform((v) => {
          if (v === undefined) return undefined;
          const parts = v
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
          return parts;
        }),
    )
    .describe(opts.description);
}

function envEnum<T extends [string, ...string[]], D extends T[number]>(opts: {
  values: T;
  default: D;
  description: string;
}): z.ZodType<T[number], z.ZodTypeDef, unknown>;
function envEnum<T extends [string, ...string[]]>(opts: {
  values: T;
  description: string;
}): z.ZodType<T[number] | undefined, z.ZodTypeDef, unknown>;
function envEnum<T extends [string, ...string[]]>(opts: {
  values: T;
  default?: T[number];
  description: string;
}): z.ZodType<T[number] | undefined, z.ZodTypeDef, unknown> {
  return optionalString
    .pipe(
      z
        .enum(opts.values)
        .optional()
        .transform((v) => v ?? opts.default),
    )
    .describe(opts.description);
}

const NODE_ENV = envEnum({
  values: ['development', 'staging', 'production'] as const,
  default: 'development',
  description:
    'Deployment environment. Used by logging and CORS to pick safe defaults.',
});

// ---------------------------------------------------------------------------
// Deployment-tier opt-in.
// ---------------------------------------------------------------------------
//
// Captures the operator's stated availability target so the cross-field
// rules below can demand the matching infrastructure (Redis, region tag,
// …). Without an explicit tier the schema applies the safest defaults
// (single-replica), preserving existing dev / single-pod deployments.
// See `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md` § "Redis availability
// tiers" for the full matrix.
const EUNO_DEPLOYMENT_TIER = envEnum({
  values: [
    'single-replica',
    'multi-replica',
    'multi-region-active-active',
  ] as const,
  default: 'single-replica',
  description:
    'Deployment availability tier. Drives cross-field validation: ' +
    '`single-replica` (default) — Redis optional, in-memory fallback acceptable for dev / single-pod; ' +
    '`multi-replica` — REDIS_URL is REQUIRED so revocation, kill-switch, maxCalls, DPoP-replay (gateway) ' +
    'and the per-subject issuance rate limiter (issuer) share state across pods; ' +
    '`multi-region-active-active` — all of the above plus a region tag (ISSUER_REGION / GATEWAY_REGION) ' +
    'is REQUIRED on every replica so audit trails can be reconstructed after a regional failover. ' +
    'See docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md and docs/MULTI_REGION_ISSUER.md.',
});

// ---------------------------------------------------------------------------
// Issuer schema — `capability-issuer`
// ---------------------------------------------------------------------------

export const IssuerConfigSchema = z
  .object({
    NODE_ENV,
    EUNO_DEPLOYMENT_TIER,
    PORT: envPort({
      default: 3001,
      description: 'TCP port the issuer HTTP server binds to.',
    }),

    // Provider selection ----------------------------------------------------
    SIGNING_PROVIDER: envEnum({
      values: ['azure-keyvault', 'aws-kms', 'gcp-cloudkms'] as const,
      default: 'azure-keyvault',
      description:
        'Token signing provider. One of: azure-keyvault, aws-kms, gcp-cloudkms.',
    }),
    IDENTITY_PROVIDER: envEnum({
      values: ['azure-ad', 'aws-cognito', 'gcp-identity', 'did'] as const,
      default: 'azure-ad',
      description:
        'Identity provider used to authenticate /issue callers. One of: azure-ad, aws-cognito, gcp-identity, did.',
    }),

    // Azure Key Vault -------------------------------------------------------
    AZURE_KEYVAULT_URL: optionalString.describe(
      'Azure Key Vault URL (required when SIGNING_PROVIDER=azure-keyvault). Example: https://your-vault.vault.azure.net/',
    ),
    AZURE_KEYVAULT_KEY_NAME: optionalString.describe(
      'Azure Key Vault key name. Defaults to "capability-signing-key".',
    ),
    AZURE_KEYVAULT_KEY_VERSION: optionalString.describe(
      'Optional specific Key Vault key version. Defaults to latest.',
    ),
    AZURE_CREDENTIAL_TYPE: envEnum({
      values: ['default', 'managed-identity', 'client-secret'] as const,
      default: 'default',
      description:
        'Azure credential type used to authenticate to Key Vault and Graph. One of: default, managed-identity, client-secret.',
    }),
    AZURE_CLIENT_ID: optionalString.describe(
      'Azure service principal client ID (required when AZURE_CREDENTIAL_TYPE=client-secret).',
    ),
    AZURE_CLIENT_SECRET: optionalString.describe(
      'Azure service principal client secret (required when AZURE_CREDENTIAL_TYPE=client-secret).',
    ),
    AZURE_TENANT_ID: optionalString.describe(
      'Azure tenant ID (required when AZURE_CREDENTIAL_TYPE=client-secret).',
    ),

    // AWS KMS ---------------------------------------------------------------
    AWS_KMS_REGION: optionalString.describe(
      'AWS region of the KMS key. Defaults to us-east-1 when SIGNING_PROVIDER=aws-kms.',
    ),
    AWS_KMS_KEY_ID: optionalString.describe(
      'AWS KMS key ARN or ID (required when SIGNING_PROVIDER=aws-kms).',
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

    // GCP Cloud KMS ---------------------------------------------------------
    GCP_PROJECT_ID: optionalString.describe(
      'GCP project ID (required when SIGNING_PROVIDER=gcp-cloudkms).',
    ),
    GCP_LOCATION_ID: optionalString.describe(
      'GCP KMS location. Defaults to us-central1.',
    ),
    GCP_KEYRING_ID: optionalString.describe(
      'GCP KMS key ring ID (required when SIGNING_PROVIDER=gcp-cloudkms).',
    ),
    GCP_CRYPTOKEY_ID: optionalString.describe(
      'GCP KMS crypto key ID (required when SIGNING_PROVIDER=gcp-cloudkms).',
    ),
    GCP_CRYPTOKEY_VERSION: optionalString.describe(
      'Optional GCP KMS crypto key version. Defaults to the primary version.',
    ),
    GCP_KEY_FILE_PATH: optionalString.describe(
      'Optional path to a GCP service account key file. Falls back to ADC when unset.',
    ),

    // Azure AD --------------------------------------------------------------
    AZURE_AD_TENANT_ID: optionalString.describe(
      'Azure AD tenant ID (required when IDENTITY_PROVIDER=azure-ad).',
    ),
    AZURE_AD_CLIENT_ID: optionalString.describe(
      'Azure AD application client ID (required when IDENTITY_PROVIDER=azure-ad).',
    ),
    AZURE_AD_CLIENT_SECRET: optionalString.describe(
      'Azure AD client secret. Optional; required only when the issuer needs Microsoft Graph access.',
    ),
    AZURE_AD_AUTHORITY: optionalString.describe(
      'Azure AD authority URL. Example: https://login.microsoftonline.com/<tenant-id>',
    ),

    // AWS Cognito / IAM Identity Center -------------------------------------
    AWS_COGNITO_REGION: optionalString.describe(
      'Cognito / IAM Identity Center region (e.g. us-east-1).',
    ),
    AWS_COGNITO_USER_POOL_ID: optionalString.describe(
      'Cognito user pool ID. Provide this OR AWS_COGNITO_ISSUER plus AWS_COGNITO_CLIENT_ID.',
    ),
    AWS_COGNITO_CLIENT_ID: optionalString.describe(
      'Cognito / OIDC client ID (required when IDENTITY_PROVIDER=aws-cognito).',
    ),
    AWS_COGNITO_ISSUER: optionalString.describe(
      'OIDC issuer URL for IAM Identity Center or generic OIDC. Provide this OR AWS_COGNITO_USER_POOL_ID.',
    ),
    AWS_COGNITO_JWKS_URI: optionalString.describe(
      'Optional explicit JWKS URI. Derived from issuer when unset.',
    ),
    AWS_COGNITO_TOKEN_USE: envEnum({
      values: ['id', 'access'] as const,
      description:
        'Which Cognito token kind to validate. One of: id, access. Optional.',
    }),

    // GCP Identity ----------------------------------------------------------
    GCP_IDENTITY_AUDIENCE: optionalString.describe(
      'OAuth client ID / audience for GCP identity tokens (required when IDENTITY_PROVIDER=gcp-identity).',
    ),
    GCP_IDENTITY_ISSUER: optionalString.describe(
      'GCP identity token issuer. Defaults to https://accounts.google.com.',
    ),
    GCP_IDENTITY_JWKS_URI: optionalString.describe(
      'GCP identity token JWKS URI. Defaults to https://www.googleapis.com/oauth2/v3/certs.',
    ),
    GCP_IDENTITY_PROJECT_ID: optionalString.describe(
      'Optional GCP project ID for identity validation.',
    ),
    GCP_IDENTITY_ROLES_CLAIM: optionalString.describe(
      'Optional claim name carrying user roles. Defaults to "roles".',
    ),

    // DID identity ----------------------------------------------------------
    ION_RESOLVER_URL: optionalString.describe(
      'did:ion resolver URL. Defaults to the public Microsoft resolver. Override for self-hosted ION.',
    ),

    // Token issuance --------------------------------------------------------
    ISSUER_DID: optionalString.describe(
      'Issuer DID. Defaults to did:web:example.com if unset (development only — set explicitly in production).',
    ),
    DEFAULT_TOKEN_TTL: envPositiveInt({
      default: 900,
      description:
        'Default capability-token TTL in seconds (default 900 = 15 minutes).',
    }),
    REQUIRE_USER_CONSENT: envBoolean({
      default: false,
      description:
        'Require explicit user consent before issuing high-privilege tokens. Boolean: true | false.',
    }),
    ROLE_POLICY_FILE: optionalString.describe(
      'Optional path to a JSON file describing the externalised role policy. Falls back to the in-code default mapping.',
    ),

    // Role-policy admin API (Task 3 — Stage 4 production hardening) ----------
    //
    // These env vars activate the Postgres-backed role-policy store and the
    // admin API that lets operators hot-reload the mapping without restarting
    // the issuer.  All three are optional — when absent the issuer continues
    // to use the file-based (ROLE_POLICY_FILE) or in-code default mapping.
    ISSUER_ROLE_POLICY_DB_URL: optionalString.describe(
      'Postgres connection URL for the role_policies table (Task 3). ' +
      'When set, the issuer loads the initial role → capability policy from this database at startup ' +
      'and persists admin-API mutations there. Falls back to ROLE_POLICY_FILE or the in-code default ' +
      'when unset. Example: postgres://user:pass@host:5432/dbname',
    ),
    ISSUER_ADMIN_API_KEY: optionalString.describe(
      'Shared admin API key for the issuer role-policy admin routes. ' +
      'Accepted via X-Admin-Key header as an explicit temporary fallback when ' +
      'ISSUER_ADMIN_JWKS_URI + ISSUER_ADMIN_JWT_AUDIENCE are not configured. ' +
      'Must be ≥32 characters in production. ' +
      'Mirrors MINTER_ADMIN_API_KEY on the API-key minter.',
    ),
    ISSUER_ADMIN_JWKS_URI: optionalString.describe(
      'JWKS endpoint URL of the IdP that issues operator tokens for the issuer admin API. ' +
      'When set alongside ISSUER_ADMIN_JWT_AUDIENCE, operator Bearer JWTs are accepted as the ' +
      'primary authentication path on the role-policy admin routes. ' +
      'Mirrors MINTER_ADMIN_JWKS_URI on the API-key minter.',
    ),
    ISSUER_ADMIN_JWT_AUDIENCE: optionalString.describe(
      'Expected `aud` claim in operator JWTs for the issuer admin routes. ' +
      'Required when ISSUER_ADMIN_JWKS_URI is set. ' +
      'Mirrors MINTER_ADMIN_JWT_AUDIENCE on the API-key minter.',
    ),
    ISSUER_ADMIN_JWT_ISSUER: optionalString.describe(
      'Expected `iss` claim in operator JWTs for the issuer admin routes (optional; omit to skip issuer validation). ' +
      'Requires ISSUER_ADMIN_JWKS_URI and ISSUER_ADMIN_JWT_AUDIENCE to be set. ' +
      'Mirrors MINTER_ADMIN_JWT_ISSUER on the API-key minter.',
    ),

    ACTION_RESOLVER_FILE: optionalString.describe(
      'Optional path to a JSON file describing the ActionResolver (R-7) used to (a) derive capability actions from incoming HTTP / tool invocations and (b) map actions to Conditional-Access tiers. Recognised top-level keys: `httpMethodActions`, `defaultHttpAction`, `toolActions`, `defaultToolAction`, `actionTiers`, `defaultTier`. Operator entries are merged on top of the built-in defaults so the file only needs to declare deployment-specific verbs (e.g. `db:select`, `acknowledge_alert`). The same file should be configured on the capability-issuer AND the tool-gateway so mint-time CA tiering and enforcement-time action derivation share a single vocabulary.',
    ),
    ENABLE_DETAILED_LOGGING: envBoolean({
      default: false,
      description: 'Enable verbose request / decision logs. Boolean: true | false.',
    }),

    // Cloud storage grants (Sprint 3-4 gap #7) ------------------------------
    STORAGE_GRANTS_ENABLED: envBoolean({
      default: false,
      description:
        'Mint cloud-storage credentials alongside capability tokens. See docs/sprint-3-4-gaps/07-storage-grants.md.',
    }),
    STORAGE_GRANT_MAX_TTL_SECONDS: envPositiveInt({
      default: 900,
      description:
        'Cap on storage grant TTL in seconds. Default 900; hard ceiling 3600.',
      max: 3600,
    }),
    AWS_STORAGE_GRANT_ROLE_ARN: optionalString.describe(
      'IAM role ARN the issuer assumes to mint AWS storage grants. ' +
      'MUST be a role distinct from the JWT-signing KMS role so that a storage-grant ' +
      'code path cannot escalate to signing arbitrary JWTs.',
    ),
    AWS_REGION: optionalString.describe(
      'Default AWS region used by storage / DB token issuance.',
    ),
    // Per-(tenant, user, agent) rate limit for storage-grant minting.  Much
    // tighter than the main issuance limit because each grant issues an STS
    // session (long-lived AWS credentials) — a bug here can leak a broader
    // AWS session than a capability JWT alone.
    STORAGE_GRANT_RATE_LIMIT_ENABLED: envBoolean({
      default: true,
      description:
        'Enable a dedicated per-(tenant, user, agent) rate limit for storage-grant issuance. Default true. ' +
        'Applies in addition to the main ISSUANCE_RATE_LIMIT when STORAGE_GRANTS_ENABLED=true. ' +
        'Set lower than ISSUANCE_RATE_LIMIT_MAX because each storage grant mints an STS session.',
    }),
    STORAGE_GRANT_RATE_LIMIT_MAX: envPositiveInt({
      default: 10,
      description:
        'Maximum storage-grant issuances per STORAGE_GRANT_RATE_LIMIT_WINDOW_SECONDS for the same ' +
        '(tenantId, userId, agentId) tuple. Default 10 (tighter than main issuance limit).',
    }),
    STORAGE_GRANT_RATE_LIMIT_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Length (seconds) of the tumbling window used by the storage-grant rate limiter. Default 60.',
    }),
    STORAGE_GRANT_RATE_LIMIT_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for the storage-grant rate limiter. Default "sgrl:". ' +
      'Change only when multiple issuer clusters share a Redis instance and key namespacing is required.',
    ),

    // DB token issuance (Sprint 3-4 gap #8) ---------------------------------
    DB_TOKENS_ENABLED: envBoolean({
      default: false,
      description:
        'Mint short-lived database credentials alongside capability tokens. See docs/sprint-3-4-gaps/08-db-token-issuance.md.',
    }),
    DB_TOKEN_MAX_TTL_SECONDS: envPositiveInt({
      default: 900,
      description: 'Cap on DB token TTL in seconds. Default 900; hard ceiling 900.',
      max: 900,
    }),
    DB_INSTANCES_FILE: optionalString.describe(
      'REQUIRED when DB_TOKENS_ENABLED=true. Path to the operator-declared allow-list of permitted DB instances.',
    ),
    AWS_DB_TOKEN_ROLE_ARN: optionalString.describe(
      'IAM role ARN the issuer assumes before calling rds:GenerateDbAuthToken. ' +
      'When set, RDS token minting uses a dedicated minimal role distinct from both ' +
      'the JWT-signing KMS role and the storage-grant STS role, limiting the blast radius ' +
      'of a compromise in the DB-token code path. Optional; when unset the issuer\'s ' +
      'ambient IAM credentials are used (less isolated).',
    ),
    // Per-(tenant, user, agent) rate limit for DB-token minting.  Tighter than
    // the main issuance limit because a bug in DB-token issuance can expose a
    // 15-minute AWS RDS IAM auth token — a bigger blast radius than a short-lived
    // capability JWT.
    DB_TOKEN_RATE_LIMIT_ENABLED: envBoolean({
      default: true,
      description:
        'Enable a dedicated per-(tenant, user, agent) rate limit for DB-token issuance. Default true. ' +
        'Applies in addition to the main ISSUANCE_RATE_LIMIT when DB_TOKENS_ENABLED=true. ' +
        'Set lower than ISSUANCE_RATE_LIMIT_MAX because each DB token mints an IAM DB auth token.',
    }),
    DB_TOKEN_RATE_LIMIT_MAX: envPositiveInt({
      default: 10,
      description:
        'Maximum DB-token issuances per DB_TOKEN_RATE_LIMIT_WINDOW_SECONDS for the same ' +
        '(tenantId, userId, agentId) tuple. Default 10 (tighter than main issuance limit).',
    }),
    DB_TOKEN_RATE_LIMIT_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Length (seconds) of the tumbling window used by the DB-token rate limiter. Default 60.',
    }),
    DB_TOKEN_RATE_LIMIT_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for the DB-token rate limiter. Default "dbrl:". ' +
      'Change only when multiple issuer clusters share a Redis instance and key namespacing is required.',
    ),

    // CORS ------------------------------------------------------------------
    ALLOWED_ORIGINS: envCsv({
      description:
        'Comma-separated list of browser origins allowed to call the issuer. In production the issuer disables CORS entirely when this is unset.',
    }),

    // Per-(tenant, user, agent, jti, ip) issuance rate limit (F-1, addresses I-1) --
    // Multi-dimensional token-bucket replacing the former per-IP express-rate-limit.
    // Keyed on (tenantId, userId, agentId, jti, ip) so a compromised account /
    // agent / IP is bounded independently. Tenant-aware for F-7 multi-region.
    // See docs/MULTI_REGION_ISSUER.md.
    ISSUANCE_RATE_LIMIT_ENABLED: envBoolean({
      default: true,
      description:
        'Enable the per-(tenant, user, agent, jti, ip) issuance rate limit (F-1, addresses I-1). Default true. Disable only in development; in production this is the primary defence against a compromised user/agent flooding /api/v1/issue.',
    }),
    ISSUANCE_RATE_LIMIT_MAX: envPositiveInt({
      default: 60,
      description:
        'Maximum capability-issuance requests permitted per ISSUANCE_RATE_LIMIT_WINDOW_SECONDS for the same (tenantId, userId, agentId, jti, ip) tuple. Default 60.',
    }),
    ISSUANCE_RATE_LIMIT_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Length (seconds) of the tumbling window used by the issuance rate limiter. Default 60.',
    }),
    ISSUANCE_RATE_LIMIT_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for the issuance rate limiter. Default "issrl:". Prepended to the store key before the CallCounterStore backend adds its own prefix (default "capcall:").',
    ),
    ISSUANCE_RATE_LIMIT_FAIL_CLOSED: envBoolean({
      default: true,
      description:
        'When true (default), CallCounterStore errors during issuance rate-limit lookup deny the request (fail closed). Set to false only when transient Redis loss should not block issuance — note this re-opens the window an attacker could exploit.',
    }),

    // Distributed coordination (Redis) — required for multi-replica issuer ----
    // and for F-7 multi-region active/active deployments. When unset the
    // F-1 limiter falls back to in-memory state (single-replica only).
    REDIS_URL: optionalString.describe(
      'Optional shared Redis URL. When set, issuance rate-limit counters propagate across issuer replicas / regions (required for multi-replica or multi-region active/active deployments — F-7).',
    ),

    // Multi-region active/active (F-7) ---------------------------------------
    ISSUER_REGION: optionalString.describe(
      'Logical region tag for this issuer instance (e.g. "eastus2", "westeurope"). Surfaced on issued tokens (`region` claim), audit events, posture records, request span attributes (`euno.region`), and the /.well-known/capability-issuer metadata endpoint. Recommended in any multi-region deployment so audit trails can be reconstructed after a regional failover. See docs/MULTI_REGION_ISSUER.md.',
    ),

    // Gateway audience (cross-tenant defence) --------------------------------
    GATEWAY_AUDIENCE: optionalString.describe(
      'Audience string stamped into the `aud` JWT claim of every capability token minted by this issuer. ' +
      'Defaults to "tool-gateway". In multi-tenant deployments set this to a unique per-tenant value ' +
      '(e.g. "tool-gateway:acme-corp-prod") so a token minted for one tenant\'s gateway cannot be ' +
      'replayed at another tenant\'s gateway. MUST match the GATEWAY_AUDIENCE configured on the ' +
      'corresponding tool-gateway instance.',
    ),

    // OCSF audit transport (F-6) --------------------------------------------
    OCSF_TRANSPORT: optionalString.describe(
      'Optional OCSF (Open Cybersecurity Schema Framework) audit sink. One of: "stdout" (one JSON-line per event written to stderr so existing stdout pipelines are untouched), "file" (append to OCSF_FILE_PATH), "http" (POST each event to OCSF_HTTP_URL). When unset (default), OCSF emission is disabled and existing winston logging is unchanged. Every AuditLogEntry emitted by the issuer is mirrored as an OCSF v1.1 Authorization (3003) event so any SIEM that speaks OCSF can ingest without writing a Euno-specific parser.',
    ),
    OCSF_FILE_PATH: optionalString.describe(
      'Path the file OCSF transport appends events to. Required when OCSF_TRANSPORT=file. Rotation is delegated to the operating system (logrotate / journald).',
    ),
    OCSF_HTTP_URL: optionalString.describe(
      'Collector URL the http OCSF transport POSTs events to. Required when OCSF_TRANSPORT=http. Failures are logged and swallowed — operators who need guaranteed delivery should layer a queueing collector (Vector, Fluent Bit) in front of this transport.',
    ),
    OCSF_HTTP_HEADERS: optionalString.describe(
      'Optional JSON object of additional HTTP headers for the http OCSF transport (e.g. \'{"x-api-key":"..."}\'). Ignored if OCSF_TRANSPORT≠http.',
    ),

    // Multi-issuer trust hardening (cosignature + transparency log) ---------
    //
    // Mitigates the "single-issuer trust root" critical risk: an attacker
    // who pivots from a compromised issuer pod to KMS `signDigest`
    // permission still cannot mint usable tokens because (a) at least one
    // independent cosigner key is also required, and (b) every issuance
    // is recorded in an append-only transparency log the gateway
    // independently verifies. Both layers are off by default for back-
    // compat; production deployments should enable at least cosignature.
    COSIGNERS: optionalString.describe(
      'Optional JSON array of independent cosigner specs. Each element is ' +
      '`{"kid":"...","alg":"EdDSA|ES256|...","keyPem":"-----BEGIN PRIVATE KEY-----\\n..."}` ' +
      'or `{"kid":"...","keyPemFile":"/path/to/key.pem"}`. Each cosigner countersigns every ' +
      'issuance receipt with an independent key — the gateway then requires ' +
      'REQUIRE_COSIGNATURE_COUNT of these signatures to verify a token. The cosigner key ' +
      'MUST be held by a different principal than the primary issuer signing key (the whole ' +
      'point is independence): typical realisations are an offline policy authority key ' +
      '(sealed PEM mounted from a separate secret store), a second KMS in a different ' +
      'cloud account, or a remote co-signing micro-service. When unset, no cosignature ' +
      'is added (back-compat).',
    ),
    TRANSPARENCY_LOG_ENABLED: envBoolean({
      default: false,
      description:
        'When true, every issuance receipt is submitted to the in-process software ' +
        'transparency log and the resulting SCT is added to the token\'s `proofs.sct[]` claim. ' +
        'Provides an external, append-only witness independent of the issuer\'s primary ' +
        'signing key — auditors can reconcile the log against the issuer\'s audit trail to ' +
        'detect silent issuance fraud. Requires TRANSPARENCY_LOG_KEY_PEM (or _FILE), ' +
        'TRANSPARENCY_LOG_KEY_KID, and TRANSPARENCY_LOG_ID. NOTE: for the strongest defence ' +
        'run an out-of-process log with its own KMS key and load only its public JWKS into ' +
        'the gateway; the in-process log is intended for tests, dev, and intentionally co-' +
        'located deployments. Boolean: true | false. Default false.',
    }),
    TRANSPARENCY_LOG_ID: optionalString.describe(
      'Stable identifier of this issuer\'s transparency log (e.g. "euno-prod-log-1"). ' +
      'Required when TRANSPARENCY_LOG_ENABLED=true. Stamped on every SCT and used by the ' +
      'gateway to look up the log\'s trusted JWKS.',
    ),
    TRANSPARENCY_LOG_KEY_KID: optionalString.describe(
      'kid of the transparency log signing key. Required when TRANSPARENCY_LOG_ENABLED=true.',
    ),
    TRANSPARENCY_LOG_KEY_ALG: envEnum({
      values: ['EdDSA', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as const,
      description:
        'JWA algorithm of the transparency log signing key. When omitted, the alg is ' +
        'inferred from the key material (EdDSA for Ed25519/Ed448, ES{256,384,512} for ' +
        'P-{256,384,521}). Must be supplied for RSA keys.',
    }),
    TRANSPARENCY_LOG_KEY_PEM: optionalString.describe(
      'Inline PEM-encoded private key for the transparency log. Provide this OR TRANSPARENCY_LOG_KEY_FILE.',
    ),
    TRANSPARENCY_LOG_KEY_FILE: optionalString.describe(
      'Path to a PEM-encoded private key for the transparency log. Provide this OR TRANSPARENCY_LOG_KEY_PEM.',
    ),

    // Microservice decomposition (R-1) --------------------------------------
    // When these URLs are set the issuer delegates side-credential minting
    // to the dedicated remote services (HttpSideCredentialBroker).  Leave
    // unset to use the in-process backends (InProcessSideCredentialBroker,
    // backward-compatible default).
    STORAGE_GRANT_SERVICE_URL: optionalString.describe(
      'URL of the standalone storage-grant-service. When set, storage-grant minting is ' +
      'delegated to this remote service instead of the in-process StorageGrantService. ' +
      'Example: http://storage-grant-service:8082. See docs/microservice-decomposition.md.',
    ),
    DB_TOKEN_SERVICE_URL: optionalString.describe(
      'URL of the standalone db-token-service. When set, DB-token minting is delegated ' +
      'to this remote service instead of the in-process DbTokenService. ' +
      'Example: http://db-token-service:8083. See docs/microservice-decomposition.md.',
    ),
    SIDE_CREDENTIAL_FAILURE_MODE: envEnum({
      values: ['fail-fast', 'best-effort'] as const,
      default: 'fail-fast',
      description:
        'Controls how the issuer reacts when side-credential minting (storage-grant or DB-token) ' +
        'fails. "fail-fast" (default): the whole /issue request fails and the caller receives an ' +
        'error — ensures credentials are never returned without their associated side credentials. ' +
        '"best-effort": the side-credential error is logged and metered but the signed JWT is still ' +
        'returned — use only when partial credential delivery is explicitly acceptable (e.g. during ' +
        'STS maintenance windows).',
    }),

    // DID resolution --------------------------------------------------------
    // DID_WEB_ALLOW_HTTP_FOR_HOSTS is loaded once at the resolver call site
    // but placed here so misconfiguration is caught at boot and the value is
    // visible in dump-template output.
    DID_WEB_ALLOW_HTTP_FOR_HOSTS: optionalString.describe(
      'Comma-separated list of host[:port] entries for which the did:web resolver is ' +
      'permitted to use plain HTTP instead of HTTPS. Default empty (HTTPS-only, fail-closed). ' +
      'Intended exclusively for local docker-compose / CI harnesses that cannot terminate TLS. ' +
      'MUST NOT be set in production. Example: partner-sim.local:4001,localhost:4002',
    ),

    // Legacy region alias (F-7) ---------------------------------------------
    // EUNO_DEPLOYMENT_REGION was the original env var before ISSUER_REGION
    // was introduced as the canonical name.  Both are accepted; ISSUER_REGION
    // takes precedence when both are set.  New deployments should use
    // ISSUER_REGION; this alias is preserved for backward compatibility.
    EUNO_DEPLOYMENT_REGION: optionalString.describe(
      'Legacy alias for ISSUER_REGION. Provides the logical region tag for this issuer ' +
      'instance. ISSUER_REGION takes precedence when both are set. New deployments should ' +
      'use ISSUER_REGION instead.',
    ),

    // Posture emitter (sprint 3-4 gap item #9) ------------------------------
    // The posture emitter is disabled by default.  When POSTURE_EMITTER_ENABLED=true
    // the issuer streams AI-posture inventory records to the configured sink(s).
    // All fields are consumed by PostureEmitter.fromEnv() — declaring them here
    // ensures misconfiguration is caught at boot rather than silently ignored.
    POSTURE_EMITTER_ENABLED: envBoolean({
      default: false,
      description:
        'Enable the AI-posture inventory emitter. When true, the issuer streams posture ' +
        'records to the configured sink(s) on every issuance. Boolean: true | false.',
    }),
    POSTURE_EMITTER_PLUGINS: optionalString.describe(
      'Comma-separated list of posture-emitter plugin names to activate. Supported values: ' +
      '"stdout", "azure-security-center", "aws-security-hub", "gcp-security-command-center". ' +
      'Default "stdout" when POSTURE_EMITTER_ENABLED=true.',
    ),
    POSTURE_REFRESH_INTERVAL_MS: envPositiveInt({
      default: 300000,
      description:
        'How often (milliseconds) a long-running posture agent should re-emit a full inventory ' +
        'snapshot even when nothing has changed. Default 300000 (5 minutes).',
    }),
    POSTURE_DURABLE_QUEUE_PATH: optionalString.describe(
      'Filesystem path for the SQLite-backed durable posture queue ' +
      '(POSTURE_EMITTER_PLUGINS=durable). When unset, an in-memory queue is used ' +
      '(records are lost on restart). Set to a persistent path in production.',
    ),
    POSTURE_DURABLE_POLL_INTERVAL_MS: envPositiveInt({
      default: 5000,
      description:
        'How often (milliseconds) the durable-queue delivery worker polls for unsent records. ' +
        'Default 5000 (5 s).',
    }),
    POSTURE_DURABLE_MAX_ATTEMPTS: envPositiveInt({
      default: 5,
      description:
        'Maximum delivery attempts per posture record before it is moved to the dead-letter ' +
        'store. Default 5.',
    }),
    POSTURE_DURABLE_BATCH_SIZE: envPositiveInt({
      default: 50,
      description:
        'Number of posture records delivered per delivery-worker cycle. Default 50.',
    }),

    // Cloud-posture plugin credentials --------------------------------------
    // These are typically injected by the cloud runtime (IRSA / Workload
    // Identity / Managed Identity) rather than set by the operator, but
    // declaring them here makes the expected set of env vars explicit and
    // ensures they appear in the dump-template output so developers know
    // which vars the posture plugins consume.
    AZURE_SUBSCRIPTION_ID: optionalString.describe(
      'Azure subscription ID used by the azure-security-center posture plugin. ' +
      'Usually injected by Managed Identity or set as a Kubernetes secret.',
    ),
    AWS_ACCOUNT_ID: optionalString.describe(
      'AWS account ID used by the aws-security-hub posture plugin.',
    ),
    AWS_DEFAULT_REGION: optionalString.describe(
      'Fallback AWS region when AWS_REGION is not set. Used by the aws-security-hub posture ' +
      'plugin and other AWS SDK calls.',
    ),
    SECURITY_HUB_PRODUCT_ARN: optionalString.describe(
      'ARN of the AWS Security Hub custom product to publish posture findings to. ' +
      'Required when POSTURE_EMITTER_PLUGINS includes "aws-security-hub".',
    ),
    GCP_SCC_SOURCE_NAME: optionalString.describe(
      'Google Cloud Security Command Center source resource name to publish posture findings ' +
      'to. Required when POSTURE_EMITTER_PLUGINS includes "gcp-security-command-center".',
    ),

    // OIDC / IdP wiring (Task 2) -------------------------------------------
    // The three fields below support the hosted IdP code-exchange flow and
    // per-tenant IdP configuration.

    ISSUER_PUBLIC_URL: optionalString.describe(
      'Public base URL of this capability-issuer instance ' +
      '(e.g. "https://issuer.example.com"). ' +
      'Used to construct the `authorization_endpoint` and `token_endpoint` URLs ' +
      'in the GET /.well-known/openid-configuration discovery document. ' +
      'Required when the OIDC code-exchange endpoints (/api/v1/oidc/authorize and ' +
      '/api/v1/oidc/token) are exposed to external clients. ' +
      'When unset the discovery document omits the endpoint URLs.',
    ),

    ISSUER_TENANT_IDP_CONFIG_FILE: optionalString.describe(
      'Optional path to a JSON file that maps tenantId values to provider-specific ' +
      'IdP configuration overrides. When a request carries a tenantId that appears in ' +
      'this file the matching provider is used instead of the global IDENTITY_PROVIDER. ' +
      'Format: { "tenants": { "<tenantId>": { "provider": "azure-ad|aws-cognito|gcp-identity", ' +
      '"azureAD": {...} | "awsCognito": {...} | "gcpIdentity": {...} } } }. ' +
      'Reloaded automatically on SIGHUP without a restart.',
    ),

    OIDC_CODE_TTL_SECONDS: envPositiveInt({
      default: 600,
      description:
        'Time-to-live (seconds) for the in-memory authorization-code replay-prevention cache. ' +
        'An authorization code received by POST /api/v1/oidc/token is recorded for this many ' +
        'seconds; a second request with the same code within the TTL window is rejected ' +
        '(replay prevention). Default 600 (10 minutes). ' +
        'Should be set to at least the IdP\'s maximum authorization-code lifetime.',
    }),

    // Manifest template store (Task 6 — Stage 4) ----------------------------
    // Enables the Postgres-backed manifest template store and the
    // /api/v1/admin/templates admin API.  When ISSUER_DB_URL is unset the
    // admin API is disabled (404) and the hot-path template lookup is skipped.
    ISSUER_DB_URL: optionalString.describe(
      'Postgres connection string for the manifest template store. ' +
      'When set, the issuer persists manifest templates and their assignments in ' +
      'the configured database and exposes /api/v1/admin/templates. ' +
      'Example: postgres://issuer:secret@db:5432/issuer_db',
    ),
    ISSUER_DB_SCHEMA: z
      .string()
      .regex(
        /^[a-zA-Z_][a-zA-Z0-9_]*$/,
        'ISSUER_DB_SCHEMA must be a safe SQL identifier (letters, digits, underscores; must start with a letter or underscore)',
      )
      .max(63, 'ISSUER_DB_SCHEMA must be 63 characters or fewer (PostgreSQL identifier limit)')
      .optional()
      .describe(
        'Postgres schema name for the manifest template tables. Default: euno_issuer. ' +
        'Override when sharing a Postgres instance with other services. ' +
        'Must be a safe SQL identifier (letters, digits, underscores only).',
      ),
    ISSUER_DB_SCHEMA_INIT: envBoolean({
      default: false,
      description:
        'When true, run CREATE TABLE IF NOT EXISTS migrations at startup for the manifest ' +
        'template store. Safe to use in development and smoke tests; for production prefer ' +
        'running migrations with a dedicated role before deploying.',
    }),

  })
  // Cross-field validation: catch the pre-existing fail-closed cases at boot
  // rather than at first request, per the R-5 exit criterion.
  .superRefine((cfg, ctx) => {
    if (cfg.SIGNING_PROVIDER === 'azure-keyvault' && !cfg.AZURE_KEYVAULT_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AZURE_KEYVAULT_URL'],
        message:
          'AZURE_KEYVAULT_URL is required when SIGNING_PROVIDER=azure-keyvault.',
      });
    }
    if (cfg.SIGNING_PROVIDER === 'aws-kms' && !cfg.AWS_KMS_KEY_ID) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AWS_KMS_KEY_ID'],
        message: 'AWS_KMS_KEY_ID is required when SIGNING_PROVIDER=aws-kms.',
      });
    }
    if (cfg.SIGNING_PROVIDER === 'gcp-cloudkms') {
      const missing = (
        ['GCP_PROJECT_ID', 'GCP_KEYRING_ID', 'GCP_CRYPTOKEY_ID'] as const
      ).filter((k) => !cfg[k]);
      for (const k of missing) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [k],
          message: `${k} is required when SIGNING_PROVIDER=gcp-cloudkms.`,
        });
      }
    }
    if (
      cfg.AZURE_CREDENTIAL_TYPE === 'client-secret' &&
      (!cfg.AZURE_CLIENT_ID || !cfg.AZURE_CLIENT_SECRET || !cfg.AZURE_TENANT_ID)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AZURE_CREDENTIAL_TYPE'],
        message:
          'AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID are required when AZURE_CREDENTIAL_TYPE=client-secret.',
      });
    }
    if (
      cfg.IDENTITY_PROVIDER === 'aws-cognito' &&
      (!cfg.AWS_COGNITO_CLIENT_ID ||
        (!cfg.AWS_COGNITO_USER_POOL_ID && !cfg.AWS_COGNITO_ISSUER))
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AWS_COGNITO_CLIENT_ID'],
        message:
          'AWS_COGNITO_CLIENT_ID and either AWS_COGNITO_USER_POOL_ID or AWS_COGNITO_ISSUER are required when IDENTITY_PROVIDER=aws-cognito.',
      });
    }
    if (cfg.IDENTITY_PROVIDER === 'gcp-identity' && !cfg.GCP_IDENTITY_AUDIENCE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['GCP_IDENTITY_AUDIENCE'],
        message:
          'GCP_IDENTITY_AUDIENCE is required when IDENTITY_PROVIDER=gcp-identity.',
      });
    }
    if (cfg.DB_TOKENS_ENABLED && !cfg.DB_INSTANCES_FILE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['DB_INSTANCES_FILE'],
        message:
          'DB_INSTANCES_FILE is required when DB_TOKENS_ENABLED=true (operator-declared instance allow-list).',
      });
    }

    // Production-tier safety invariants (R-5 extension). The deployment
    // checklist's hard requirements are encoded here so a misconfigured
    // production rollout fails at boot rather than at first request.
    if (cfg.NODE_ENV === 'production' && cfg.EUNO_DEPLOYMENT_TIER !== 'single-replica' && !cfg.REDIS_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['REDIS_URL'],
        message:
          `REDIS_URL is required when NODE_ENV=production and EUNO_DEPLOYMENT_TIER=${cfg.EUNO_DEPLOYMENT_TIER}. ` +
          'Without it, the per-subject issuance rate limiter (F-1) falls back to per-pod ' +
          'in-memory counters and the effective budget is multiplied by the replica count. ' +
          'Set EUNO_DEPLOYMENT_TIER=single-replica only if you are deliberately running a ' +
          'single issuer pod and have accepted that operational consequence.',
      });
    }
    if (cfg.NODE_ENV === 'production' && cfg.EUNO_DEPLOYMENT_TIER === 'multi-region-active-active' && !cfg.ISSUER_REGION) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ISSUER_REGION'],
        message:
          'ISSUER_REGION is required when NODE_ENV=production and ' +
          'EUNO_DEPLOYMENT_TIER=multi-region-active-active. The region tag is surfaced on ' +
          'tokens, audit events, posture records, and trace spans so audit trails can be ' +
          'reconstructed after a regional failover. See docs/MULTI_REGION_ISSUER.md.',
      });
    }
    // ── Admin API key / JWT guards (Task 3) ─────────────────────────────────
    // When ISSUER_ADMIN_JWKS_URI is set, ISSUER_ADMIN_JWT_AUDIENCE is also
    // required — without the audience claim the JWT verifier would accept
    // tokens from any audience and silently fall back to the X-Admin-Key path.
    if (cfg.ISSUER_ADMIN_JWKS_URI && !cfg.ISSUER_ADMIN_JWT_AUDIENCE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ISSUER_ADMIN_JWT_AUDIENCE'],
        message:
          'ISSUER_ADMIN_JWT_AUDIENCE is required when ISSUER_ADMIN_JWKS_URI is set.',
      });
    }
    // ISSUER_ADMIN_JWT_ISSUER has no meaning without the JWKS URI.
    if (cfg.ISSUER_ADMIN_JWT_ISSUER && !cfg.ISSUER_ADMIN_JWKS_URI) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ISSUER_ADMIN_JWT_ISSUER'],
        message:
          'ISSUER_ADMIN_JWT_ISSUER requires ISSUER_ADMIN_JWKS_URI to be set.',
      });
    }
    // In production, when JWT auth is not configured, require a strong
    // ISSUER_ADMIN_API_KEY so the X-Admin-Key fallback cannot be guessed
    // (mirrors the MINTER_ADMIN_API_KEY guard in MinterConfigSchema).
    if (cfg.NODE_ENV === 'production' && !cfg.ISSUER_ADMIN_JWKS_URI) {
      if (!cfg.ISSUER_ADMIN_API_KEY) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ISSUER_ADMIN_API_KEY'],
          message:
            'ISSUER_ADMIN_API_KEY must be set when NODE_ENV=production and ' +
            'ISSUER_ADMIN_JWKS_URI is not configured. ' +
            'Use a securely-generated random string of at least 32 characters.',
        });
      } else if (cfg.ISSUER_ADMIN_API_KEY === 'dev-issuer-admin-key') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ISSUER_ADMIN_API_KEY'],
          message:
            'ISSUER_ADMIN_API_KEY must not use the insecure default "dev-issuer-admin-key" in production.',
        });
      } else if (cfg.ISSUER_ADMIN_API_KEY.length < 32) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ISSUER_ADMIN_API_KEY'],
          message:
            'ISSUER_ADMIN_API_KEY is too short for production use. ' +
            'Minimum length is 32 characters.',
        });
      }
    }

    // ── Transparency-log trust hardening ─────────────────────────────────────
    // Multi-issuer trust hardening: when the transparency log is enabled,
    // its identifier, kid, and a private key (inline OR file) MUST all be
    // present — otherwise the issuer would silently fall back to issuing
    // tokens without an SCT, defeating the whole point of enabling the log.
    if (cfg.TRANSPARENCY_LOG_ENABLED) {
      if (!cfg.TRANSPARENCY_LOG_ID) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['TRANSPARENCY_LOG_ID'],
          message: 'TRANSPARENCY_LOG_ID is required when TRANSPARENCY_LOG_ENABLED=true.',
        });
      }
      if (!cfg.TRANSPARENCY_LOG_KEY_KID) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['TRANSPARENCY_LOG_KEY_KID'],
          message: 'TRANSPARENCY_LOG_KEY_KID is required when TRANSPARENCY_LOG_ENABLED=true.',
        });
      }
      if (!cfg.TRANSPARENCY_LOG_KEY_PEM && !cfg.TRANSPARENCY_LOG_KEY_FILE) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['TRANSPARENCY_LOG_KEY_PEM'],
          message:
            'TRANSPARENCY_LOG_KEY_PEM or TRANSPARENCY_LOG_KEY_FILE is required when TRANSPARENCY_LOG_ENABLED=true.',
        });
      }
    }

    // ── DI-5: KMS key alias separation guard ─────────────────────────────────
    // Docs (docs/stage-4-design.md §6) mandate distinct key aliases for the
    // minter (`euno-minter-tenant-<tenantId>`) and the issuer
    // (`euno-issuer-tenant-<tenantId>`). In production, error when the
    // issuer is configured with a key name that matches the minter's
    // well-known alias convention or the shared generic default
    // ("capability-signing-key") used by both services when left unconfigured.
    //
    // Using the same signing key on both services voids the blast-radius
    // separation described in docs/stage-4-design.md §6.2: a compromise of
    // either service's workload identity would allow forging tokens for both.
    if (cfg.NODE_ENV === 'production') {
      const issuerKeyId = (() => {
        switch (cfg.SIGNING_PROVIDER) {
          case 'azure-keyvault':
            // Runtime fallback (index.ts) uses 'capability-signing-key'
            // when AZURE_KEYVAULT_KEY_NAME is absent; treat absence as that
            // default for the purpose of this guard.
            return cfg.AZURE_KEYVAULT_KEY_NAME ?? 'capability-signing-key';
          case 'aws-kms':
            return cfg.AWS_KMS_KEY_ID;
          case 'gcp-cloudkms':
            return cfg.GCP_CRYPTOKEY_ID;
          default:
            return undefined;
        }
      })();

      const fieldForProvider =
        cfg.SIGNING_PROVIDER === 'azure-keyvault'
          ? 'AZURE_KEYVAULT_KEY_NAME'
          : cfg.SIGNING_PROVIDER === 'aws-kms'
            ? 'AWS_KMS_KEY_ID'
            : 'GCP_CRYPTOKEY_ID';

      if (issuerKeyId) {
        const normalised = issuerKeyId.toLowerCase();
        const matchesSharedDefault = normalised === 'capability-signing-key';
        const matchesMinterConvention = normalised.startsWith('euno-minter');

        if (matchesSharedDefault || matchesMinterConvention) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [fieldForProvider],
            message:
              matchesMinterConvention
                ? `${fieldForProvider} value "${issuerKeyId}" matches the minter's key-alias convention ` +
                  '(prefix "euno-minter"). The issuer and the API-key minter must use separate KMS ' +
                  'key aliases to preserve blast-radius separation (docs/stage-4-design.md §6). ' +
                  'Use the issuer convention "euno-issuer-tenant-<tenantId>" instead.'
                : `${fieldForProvider} is the shared generic default "capability-signing-key". ` +
                  'In production, set an explicit issuer-specific key alias (e.g. ' +
                  '"euno-issuer-tenant-<tenantId>") so the issuer and the API-key minter ' +
                  'cannot accidentally share the same KMS key ' +
                  '(docs/stage-4-design.md §6, DI-5).',
          });
        }
      }
    }

  });

export type IssuerConfig = z.infer<typeof IssuerConfigSchema>;

// ---------------------------------------------------------------------------
// Gateway schema — `tool-gateway`
// ---------------------------------------------------------------------------

export const GatewayConfigSchema = z
  .object({
    NODE_ENV,
    EUNO_DEPLOYMENT_TIER,
    PORT: envPort({
      default: 3002,
      description: 'TCP port the gateway HTTP server binds to.',
    }),
    ADMIN_PORT: envPort({
      default: 3003,
      description:
        'TCP port the gateway admin HTTP server binds to. Admin routes (/admin/*) are served ' +
        'exclusively on this port so they are unreachable from the public-facing load-balancer. ' +
        'Must differ from PORT. Default 3003.',
    }),
    ADMIN_HOST: optionalString.describe(
      'Network interface the admin HTTP server binds to. The admin surface controls ' +
      'token revocation and kill-switch state and must not be reachable from the public ' +
      'load-balancer. In production the gateway refuses to start unless ADMIN_HOST is set ' +
      'to a non-wildcard address (anything other than "" / "0.0.0.0" / "::"), so a ' +
      'misconfigured ingress / route cannot expose /admin/* even by accident. Recommended ' +
      'values: "127.0.0.1" for sidecar-only access, or the pod\'s internal cluster IP. ' +
      'When unset (non-production only) the admin server binds to all interfaces (Express default).',
    ),

    // Issuer + backend wiring -----------------------------------------------
    ISSUER_JWKS_URL: optionalString.describe(
      'URL of the issuer JWKS endpoint. Defaults to http://localhost:3001/.well-known/jwks.json. Use this instead of ISSUER_PUBLIC_KEY_URL for R-6 JWKS key rotation.',
    ),
    ISSUER_PUBLIC_KEY_URL: optionalString.describe(
      '[Deprecated — use ISSUER_JWKS_URL] URL the gateway calls to fetch the issuer SPKI public key. Kept for one deprecation cycle; will be removed in a future release.',
    ),
    ISSUER_METADATA_URL: optionalString.describe(
      'URL of the issuer /.well-known/capability-issuer discovery document. ' +
      'When set (or derivable from ISSUER_JWKS_URL), the gateway fetches this ' +
      'endpoint at startup and compares its `actionResolverHash` against the ' +
      'locally computed hash of ACTION_RESOLVER_FILE. A mismatch means the issuer ' +
      'and gateway are using different action vocabularies (silent drift). ' +
      'Behaviour on mismatch is controlled by ACTION_RESOLVER_HASH_ENFORCEMENT. ' +
      'Automatically derived from ISSUER_JWKS_URL when that URL ends with ' +
      '/.well-known/jwks.json (e.g. https://issuer.example.com/.well-known/jwks.json ' +
      '→ https://issuer.example.com/.well-known/capability-issuer).',
    ),
    ACTION_RESOLVER_HASH_ENFORCEMENT: optionalString
      .pipe(
        z
          .union([z.literal('warn'), z.literal('error'), z.undefined()])
          .transform((v) => v ?? 'warn'),
      )
      .describe(
        'Policy applied when the gateway detects an actionResolverHash mismatch with the ' +
        'issuer\'s /.well-known/capability-issuer document. ' +
        '"warn" (default): log a warning and continue — suitable during migrations. ' +
        '"error": abort startup with a non-zero exit code — recommended for production to ' +
        'prevent a gateway from enforcing a different action vocabulary than the issuer minted with.',
      ),
    EUNO_JWKS_CACHE_TTL_SECONDS: envPositiveInt({
      default: 300,
      description:
        'JWKS cache TTL in seconds. The gateway re-fetches /.well-known/jwks.json after this interval. Default 300 (5 min). Reduce for faster key-rotation propagation.',
    }),
    EUNO_REQUIRE_KID: envBoolean({
      default: true,
      description:
        'Require a kid (key ID) in the JWT protected header. Default true (strict). Set to false only during the deprecation window when old tokens without kid are still in flight.',
    }),
    BACKEND_SERVICE_URL: optionalString.describe(
      'URL of the backend service the gateway proxies authorised requests to. Defaults to http://localhost:4000.',
    ),
    ACTION_RESOLVER_FILE: optionalString.describe(
      'Optional path to a JSON file describing the ActionResolver (R-7) used to derive a capability action from incoming HTTP requests on /proxy and from tool invocations on /api/v1/tools/invoke. Recognised top-level keys: `httpMethodActions`, `defaultHttpAction`, `toolActions`, `defaultToolAction`, `actionTiers`, `defaultTier`. Operator entries are merged on top of the built-in defaults so the file only needs to declare deployment-specific verbs (e.g. mapping `POST /graphql` queries to `read`). Should match the value configured on the capability-issuer so mint-time CA tiering and enforcement-time action derivation share a vocabulary.',
    ),

    // Admin API -------------------------------------------------------------
    ADMIN_API_KEY: optionalString.describe(
      'API key required to call /admin endpoints. MUST be set in production — the gateway refuses to start when NODE_ENV=production and this is unset. When unset in non-production environments the admin API is publicly reachable (not recommended).',
    ),
    ADMIN_TENANT_ID: optionalString.describe(
      'Tenant identifier that scopes this admin API instance. When set, all mutating admin ' +
      'operations (kill-switch, revocation) MUST include a matching `tenantId` field in the ' +
      'request body, and requests carrying a different tenantId are rejected with HTTP 403. ' +
      'This prevents a tenant admin credential from affecting resources belonging to another ' +
      'tenant on the same gateway. Global kill-switch operations additionally require ' +
      '`acknowledgesCrossTenantImpact: true` in the request body because they block all ' +
      'traffic on the gateway instance regardless of tenant. Unset means no tenant scoping ' +
      '(single-tenant / development deployments).',
    ),

    // Cryptographic audit ---------------------------------------------------
    ENABLE_CRYPTOGRAPHIC_AUDIT: envBoolean({
      default: false,
      description:
        'Sign every audit-trail entry with the configured evidence signer. When true, an evidence signer MUST be configured or the process exits. Legacy single-toggle for evidence signing; for finer-grained control use EVIDENCE_SIGNED_DECISIONS (I-8).',
    }),
    EVIDENCE_SIGNED_DECISIONS: envCsv({
      description:
        'Comma-separated list of validation decisions whose audit evidence is signed. Allowed values: allow, deny. When set, this overrides ENABLE_CRYPTOGRAPHIC_AUDIT (which becomes the legacy on/off shorthand). Use "deny" alone to record a tamper-evident trail of refusals without paying the per-allow signing cost (I-8). An evidence signer MUST be configured if this is non-empty.',
    }),
    EVIDENCE_SIGNING_KEY_PEM: optionalString.describe(
      'Inline PEM-encoded private key for evidence signing. Provide this OR EVIDENCE_SIGNING_KEY_FILE.',
    ),
    EVIDENCE_SIGNING_KEY_FILE: optionalString.describe(
      'Path to a PEM file containing the evidence signing private key. Provide this OR EVIDENCE_SIGNING_KEY_PEM.',
    ),
    EVIDENCE_SIGNING_PUBLIC_KEY_PEM: optionalString.describe(
      'Optional inline PEM public key. Derived from the private key when unset.',
    ),
    EVIDENCE_SIGNING_PUBLIC_KEY_FILE: optionalString.describe(
      'Optional path to a PEM file containing the evidence public key.',
    ),
    EVIDENCE_SIGNING_ALGORITHM: optionalString.describe(
      'Evidence signing algorithm. Defaults to RS256. Supported: RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.',
    ),
    EVIDENCE_SIGNING_KEY_ID: optionalString.describe(
      'Evidence signing key id. Defaults to "software-key".',
    ),

    // KMS-backed evidence signer (Task 5 — Stage 3) -------------------------
    //
    // When AUDIT_SIGNING_KMS_PROVIDER is set the gateway uses a cloud-KMS
    // backed EvidenceSigner instead of the software (PEM key) signer.
    // The two signers produce byte-identical canonical evidence records;
    // only the `signature` bytes, `keyId`, and `algorithm` fields differ.
    // Fail-closed: KMS unavailable → gateway refuses to sign and the
    // request is denied (AUDIT_PIPELINE_BACKPRESSURE=block for strict mode).
    AUDIT_SIGNING_KMS_PROVIDER: optionalString
      .pipe(
        z
          .union([
            z.literal('azure-keyvault'),
            z.literal('aws-kms'),
            z.literal('gcp-cloudkms'),
            z.undefined(),
          ])
          .optional(),
      )
      .describe(
        'Cloud KMS provider for audit evidence signing. One of: ' +
          '"azure-keyvault", "aws-kms", "gcp-cloudkms". ' +
          'When set, the KMS-backed EvidenceSigner is used instead of the software signer ' +
          '(EVIDENCE_SIGNING_KEY_PEM / EVIDENCE_SIGNING_KEY_FILE). ' +
          'The two signers produce byte-identical canonical evidence records; only the ' +
          'signature bytes, keyId, and algorithm fields differ. ' +
          'Required provider-specific variables are documented under AUDIT_SIGNING_AZURE_*, ' +
          'AUDIT_SIGNING_AWS_*, and AUDIT_SIGNING_GCP_*.',
      ),
    AUDIT_SIGNING_KEY_ID: optionalString.describe(
      'Logical key ID stamped on every signed audit-evidence record when using the KMS signer. ' +
        'A short, stable label (e.g. "audit-signing-key-v2") that operators can recognise in the ' +
        'audit log without needing the full key ARN. Derived from the provider key reference when omitted.',
    ),
    AUDIT_SIGNING_ALGORITHM: optionalString.describe(
      'JWS algorithm for the KMS-backed evidence signer. Defaults to RS256. ' +
        'Supported: RS256, PS256, ES256. The evidence signer always pre-hashes with SHA-256; ' +
        'only SHA-256-family algorithms are supported.',
    ),

    // Azure Key Vault provider -----------------------------------------------
    AUDIT_SIGNING_AZURE_KEYVAULT_URL: optionalString.describe(
      'Azure Key Vault base URL. Required when AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault. ' +
        'Example: https://my-vault.vault.azure.net/',
    ),
    AUDIT_SIGNING_AZURE_KEY_NAME: optionalString.describe(
      'Key name within the vault. Required when AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault. ' +
        'Example: audit-signing-key',
    ),
    AUDIT_SIGNING_AZURE_KEY_VERSION: optionalString.describe(
      'Optional specific key version. Defaults to the latest version when omitted. ' +
        'Pin a version only when auditability of the exact signing key matters more than ' +
        'seamless key rotation.',
    ),
    AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE: envEnum({
      values: ['default', 'managed-identity', 'client-secret'] as const,
      default: 'default',
      description:
        'Azure credential strategy for the audit signing Key Vault. ' +
        '"default" (recommended): DefaultAzureCredential — workload identity, managed identity, ' +
        'or standard AZURE_* env vars tried in order. ' +
        '"managed-identity": ManagedIdentityCredential (set AUDIT_SIGNING_AZURE_CLIENT_ID for user-assigned). ' +
        '"client-secret": ClientSecretCredential — requires AUDIT_SIGNING_AZURE_CLIENT_ID, ' +
        'AUDIT_SIGNING_AZURE_CLIENT_SECRET, and AUDIT_SIGNING_AZURE_TENANT_ID.',
    }),
    AUDIT_SIGNING_AZURE_CLIENT_ID: optionalString.describe(
      'Azure client ID. Required when AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret. ' +
        'Also accepted for managed-identity to select a specific user-assigned identity.',
    ),
    AUDIT_SIGNING_AZURE_CLIENT_SECRET: optionalString.describe(
      'Azure client secret. Required when AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret.',
    ),
    AUDIT_SIGNING_AZURE_TENANT_ID: optionalString.describe(
      'Azure tenant ID. Required when AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret.',
    ),

    // AWS KMS provider -------------------------------------------------------
    AUDIT_SIGNING_AWS_KMS_KEY_ID: optionalString.describe(
      'AWS KMS key ARN, key ID, or alias ARN. Required when AUDIT_SIGNING_KMS_PROVIDER=aws-kms. ' +
        'Example: arn:aws:kms:us-east-1:123456789012:key/mrk-… or alias/audit-signing-key.',
    ),
    AUDIT_SIGNING_AWS_KMS_REGION: optionalString.describe(
      'AWS region for the KMS key. Defaults to the SDK default (AWS_REGION / AWS_DEFAULT_REGION env vars). ' +
        'Set explicitly when the key region differs from the gateway region.',
    ),

    // GCP Cloud KMS provider -------------------------------------------------
    AUDIT_SIGNING_GCP_PROJECT_ID: optionalString.describe(
      'GCP project ID. Required when AUDIT_SIGNING_KMS_PROVIDER=gcp-cloudkms.',
    ),
    AUDIT_SIGNING_GCP_LOCATION_ID: optionalString.describe(
      'GCP KMS location (region or "global"). Defaults to "global". ' +
        'Example: us-central1',
    ),
    AUDIT_SIGNING_GCP_KEYRING_ID: optionalString.describe(
      'GCP KMS key ring ID. Required when AUDIT_SIGNING_KMS_PROVIDER=gcp-cloudkms.',
    ),
    AUDIT_SIGNING_GCP_CRYPTOKEY_ID: optionalString.describe(
      'GCP KMS crypto key ID. Required when AUDIT_SIGNING_KMS_PROVIDER=gcp-cloudkms.',
    ),
    AUDIT_SIGNING_GCP_CRYPTOKEY_VERSION: optionalString.describe(
      'GCP KMS crypto key version number. Defaults to version 1 when omitted. ' +
        'GCP Cloud KMS asymmetricSign requires an explicit CryptoKeyVersion resource name — ' +
        'there is no automatic primary-version resolution for asymmetric keys. ' +
        'Update this value (e.g. to "2") when rotating to a new key version.',
    ),
    AUDIT_SIGNING_GCP_KEY_FILE_PATH: optionalString.describe(
      'Optional path to a GCP service account key file. ' +
        'Falls back to Application Default Credentials (ADC) when unset — ' +
        'workload identity, GOOGLE_APPLICATION_CREDENTIALS, or gcloud ADC.',
    ),

    // Audit chain seed (per-service env var name pattern is documented; we
    // accept the gateway's well-known one explicitly).
    EUNO_AUDIT_CHAIN_SEED_TOOL_GATEWAY: optionalString.describe(
      `Seed the gateway audit chain with the previous run's terminal hash to maintain tamper-evidence continuity across restarts.`,
    ),

    // Async audit pipeline (R-9, addresses I-21) -----------------------------
    // The pipeline lifts `EvidenceSigner.signEvidence` off the request
    // critical path. All four knobs are optional; when unset the
    // pipeline still runs with sensible defaults whenever evidence
    // signing is enabled. Set AUDIT_PIPELINE_ENABLED=false to keep the
    // legacy synchronous signing path (e.g. for benchmarks comparing
    // before/after R-9).
    AUDIT_PIPELINE_ENABLED: envBoolean({
      default: true,
      description:
        'When true (default), the gateway routes audit evidence through the async batched pipeline (R-9): producers enqueue and return immediately while N background workers call the signer. Set false to revert to the legacy synchronous path that awaits signEvidence on every request — only useful for A/B comparison, the async path is the recommended configuration.',
    }),
    AUDIT_PIPELINE_MAX_SIZE: envPositiveInt({
      default: 1024,
      description:
        'Maximum number of unsigned audit-evidence records buffered in memory before the AUDIT_PIPELINE_BACKPRESSURE policy kicks in. Sized for a small gateway under burst; raise for high-throughput deployments. Memory cost is O(maxSize * average evidence size).',
    }),
    AUDIT_PIPELINE_WORKERS: envPositiveInt({
      default: 2,
      description:
        'Number of concurrent worker loops draining the audit pipeline. Each worker holds at most one in-flight signEvidence call, so this is also the maximum signer concurrency. Raise when the signer is high-latency (e.g. KMS) and the buffer keeps filling.',
    }),
    AUDIT_PIPELINE_MAX_BATCH: envPositiveInt({
      default: 16,
      description:
        'Maximum records a single worker pulls per wake-up. Larger values amortise event-loop wake-ups under heavy load; smaller values keep the per-record latency between enqueue and sign tighter.',
    }),
    AUDIT_PIPELINE_MAX_AGE_MS: envPositiveInt({
      description:
        'Optional maximum age (ms) a record may sit in the queue before it is dropped as `aged_out`. Defends against unbounded queue residency when the signer is slow or down. Unset disables age-based eviction (records wait indefinitely).',
    }),
    AUDIT_PIPELINE_BACKPRESSURE: optionalString.describe(
      'Backpressure policy when the pipeline is full. ' +
      '`drop_oldest_with_metric` (default) evicts the oldest queued record and increments a dropped counter; the producer never blocks and request-path p99 is preserved. ' +
      '`block` makes enqueue() await until a slot frees up — no evidence is dropped due to a full buffer, but during a signer stall requests will block until the signer recovers or a client/server timeout fires; records are still dropped once the AUDIT_PIPELINE_MAX_WAITERS cap is reached. ' +
      'Set to `block` only when your compliance posture requires audit completeness and you have a reliably low-latency signer and adequate capacity headroom. ' +
      'COMPLIANCE PROFILE: for regulated workloads that require a complete tamper-evident audit trail, set: ' +
      'AUDIT_PIPELINE_BACKPRESSURE=block, AUDIT_PIPELINE_MAX_WAITERS (bounded), EVIDENCE_SIGNED_DECISIONS=allow,deny, ' +
      'and OCSF_TRANSPORT=http with a durable SIEM collector. Pair with AUDIT_PIPELINE_MAX_AGE_MS to bound queue residency.',
    ),
    AUDIT_PIPELINE_MAX_WAITERS: envPositiveInt({
      description:
        'Hard cap on the number of producers that may park awaiting a free slot under the `block` backpressure policy. ' +
        'When this cap is reached, arriving records are dropped with reason=queue_full instead of growing the waiter list unboundedly. ' +
        'Defaults to AUDIT_PIPELINE_MAX_SIZE (i.e. the parked-waiter list cannot exceed the buffer). ' +
        'Tune downward to bound memory consumption and upstream latency when the signer is slower than the producer rate. ' +
        'Ignored under the `drop_oldest_with_metric` policy.',
    }),
    AUDIT_PIPELINE_DRAIN_TIMEOUT_MS: envPositiveInt({
      default: 5000,
      description:
        'Maximum time (ms) to wait for the pipeline to flush queued evidence on graceful shutdown (SIGTERM/SIGINT). Items still buffered when the deadline expires are counted as drops so the metric reflects the loss.',
    }),

    // Audit chain integrity (cross-replica Merkle anchoring) -----------------
    AUDIT_REPLICA_ID: optionalString.describe(
      'Replica/pod identifier stamped on every Merkle batch commitment. ' +
      'In Kubernetes, set to the Pod name via the downward API: $(POD_NAME). ' +
      'Defaults to the OS hostname when unset. ' +
      'Used by batch-commitment verifiers and SIEM queries to attribute a batch to a specific replica.',
    ),
    AUDIT_ANCHOR_URL: optionalString.describe(
      'Optional URL to POST each SignedBatchCommitment JSON to after every pipeline drain cycle. ' +
      'Accepts any endpoint that handles HTTP POST with Content-Type: application/json. ' +
      'Typical targets: an object-store pre-signed PUT URL (WORM bucket), a transparency-log ingestion endpoint, ' +
      'or a custom SIEM webhook. When unset, batch commitments are only emitted to the audit log (best-effort; no external anchor). ' +
      'Pair with AUDIT_PIPELINE_BACKPRESSURE=block and EVIDENCE_SIGNED_DECISIONS=allow,deny for regulated workloads.',
    ),

    // Pluggable ledger backend (closes the "compromised replica rewrites local chain" gap).
    // When AUDIT_LEDGER_BACKEND=postgres the gateway stores every signed evidence record
    // in an external PostgreSQL append-only table with per-row HMAC and optional S3
    // Object-Lock anchoring. Multiple replicas share the same table; a DB-level
    // advisory lock serialises writes, so no replica can fork or rewrite the chain
    // without the DB rejecting the conflicting seq/previousHash pair.
    // When AUDIT_LEDGER_BACKEND=acl the gateway writes to Azure Confidential Ledger,
    // a TEE-backed immutable store that guarantees entries cannot be deleted or modified.
    AUDIT_LEDGER_BACKEND: optionalString
      .pipe(
        z
          .union([
            z.literal('none'),
            z.literal('postgres'),
            z.literal('in-memory'),
            z.literal('acl'),
            z.literal('per-replica-postgres'),
            z.undefined(),
          ])
          .transform((v) => v ?? 'none'),
      )
      .describe(
        'Pluggable ledger backend for evidence signing. ' +
        '"none" (default) — in-process chain only (no replay protection against a compromised replica). ' +
        '"postgres" — append-only PostgreSQL table with per-row HMAC; uses pg_advisory_xact_lock ' +
        '  for cross-replica serialisation (single global write queue). ' +
        '"per-replica-postgres" — lock-free per-replica chains; each replica maintains its own ' +
        '  seq namespace; throughput scales linearly with replica count. ' +
        '  Use AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS to configure periodic cross-replica ' +
        '  Merkle commitments that bind all replica chains together. ' +
        '"in-memory" — ephemeral in-process ledger for testing. ' +
        '"acl" — Azure Confidential Ledger (TEE-backed). ' +
        'Requires AUDIT_LEDGER_PG_URL and AUDIT_LEDGER_HMAC_SECRET when set to "postgres" or ' +
        '"per-replica-postgres".',
      ),
    AUDIT_LEDGER_PG_URL: optionalString.describe(
      'PostgreSQL connection URL for the ledger backend. ' +
      'Required when AUDIT_LEDGER_BACKEND=postgres or AUDIT_LEDGER_BACKEND=per-replica-postgres. ' +
      'Format: postgresql://user:password@host:5432/dbname. ' +
      'The service account MUST have INSERT + SELECT on the ledger table; ' +
      'it does NOT need UPDATE or DELETE (those operations would indicate tampering).',
    ),
    AUDIT_LEDGER_HMAC_SECRET: optionalString.describe(
      'HMAC-SHA-256 secret for per-row ledger integrity. ' +
      'Required when AUDIT_LEDGER_BACKEND=postgres. ' +
      'Each row stores HMAC-SHA256(secret, seq:previousHash:recordHash:replicaId). ' +
      'Offline verification of row HMACs detects DB-level tampering without re-checking ' +
      'cryptographic signatures. Decoded as hex (64-char string preferred), base64, or raw UTF-8; ' +
      'must decode to at least 32 bytes (256 bits). Generate with: openssl rand -hex 32. ' +
      'To rotate: provision a new table name (AUDIT_LEDGER_TABLE) and start writing to it; ' +
      'never UPDATE existing rows — the append-only model is the tamper-evidence guarantee.',
    ),
    AUDIT_LEDGER_TABLE: optionalString.describe(
      'PostgreSQL table name for the ledger backend. Default "euno_audit_ledger". ' +
      'Override when multiple gateway clusters share one PostgreSQL instance.',
    ),
    AUDIT_LEDGER_RUN_MIGRATIONS: envBoolean({
      default: false,
      description:
        'When true, the gateway runs CREATE TABLE IF NOT EXISTS for the ledger table at startup. ' +
        'Suitable for development and single-replica deployments. ' +
        'In production prefer external schema management (Flyway, Liquibase, or a separate migration job) ' +
        'so the gateway service account does not need DDL privileges. Boolean: true | false. Default false.',
    }),
    AUDIT_LEDGER_S3_BUCKET: optionalString.describe(
      'S3 bucket for periodic Merkle-root anchoring. ' +
      'NOTE: the standard bootstrap does not inject an S3 client — setting this env var ' +
      'without a custom entrypoint that constructs PostgresLedgerBackend directly (with an ' +
      'S3AnchorClient) will cause a startup error. When properly wired, every ' +
      'AUDIT_LEDGER_ANCHOR_INTERVAL successful appends trigger a PUT of the Merkle root of ' +
      'those rows to S3. The bucket MUST have Object Lock enabled. ' +
      'When unset, no S3 anchoring is performed (HMAC + in-DB chain is the only protection).',
    ),
    AUDIT_LEDGER_S3_PREFIX: optionalString.describe(
      'S3 key prefix for ledger anchor objects. ' +
      'Default "audit-anchor/". Resulting key: {prefix}{replicaId}/{fromSeq}-{toSeq}.json.',
    ),
    AUDIT_LEDGER_ANCHOR_INTERVAL: envPositiveInt({
      default: 1000,
      min: 1,
      description:
        'Number of ledger rows between S3 Object-Lock anchor writes. Default 1000. ' +
        'Lower values provide more frequent external witnesses (smaller gap between a ' +
        'DB tamper event and S3 detection) at the cost of more S3 PUT requests. ' +
        'Only relevant when AUDIT_LEDGER_S3_BUCKET is set.',
    }),

    AUDIT_LEDGER_RETENTION_DAYS: envPositiveInt({
      min: 1,
      description:
        'Audit-log retention window in days. ' +
        'Surfaced in GET /admin/usage alongside live usage counters so billing operators ' +
        'can confirm the tenant\'s tier without consulting environment documentation. ' +
        'Cloud Free = 7; Cloud Team = 90; Cloud Enterprise = operator-configured. ' +
        'When unset (the default), the field is omitted from the /admin/usage response, ' +
        'which is the correct value for self-host deployments where retention is managed ' +
        'externally (e.g. by a Postgres backup policy).',
    }),

    // ACL-specific config (only used when AUDIT_LEDGER_BACKEND=acl).
    AUDIT_LEDGER_ACL_ENDPOINT: optionalString.describe(
      'Azure Confidential Ledger endpoint URL. ' +
      'Required when AUDIT_LEDGER_BACKEND=acl AND the ledger client is constructed ' +
      'inside the standard bootstrap (i.e. GatewayDependencies.ledgerAclClient is not ' +
      'provided by a custom entrypoint). Format: https://<name>.confidentialledger.azure.com. ' +
      'Authentication uses DefaultAzureCredential (workload identity, managed identity, ' +
      'or AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET environment variables). ' +
      'NOTE: the standard bootstrap dynamically requires @azure-rest/confidential-ledger and ' +
      '@azure/identity — add both to your deployment image when using this option.',
    ),

    // Per-replica backend config (only used when AUDIT_LEDGER_BACKEND=per-replica-postgres).
    ENABLE_CROSS_CHAIN_ANCHOR: envBoolean({
      default: false,
      description:
        'When true, the gateway automatically starts a CrossChainAnchor on startup when ' +
        'AUDIT_LEDGER_BACKEND=per-replica-postgres. The anchor periodically snapshots all ' +
        'known replica chain tips into a signed CrossChainCommitment that provides a ' +
        'tamper-evident external witness across all replicas. Default false. ' +
        'Commitments are stored in-memory and served via GET /api/v1/audit/chain-proof ' +
        '(admin-key authenticated). Set AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS to control ' +
        'commitment frequency.',
    }),
    AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS: envPositiveInt({
      default: 60000,
      min: 5000,
      description:
        'How often (ms) the CrossChainAnchor queries all replica tips and emits a ' +
        'SignedCrossChainCommitment. Active when ' +
        'AUDIT_LEDGER_BACKEND=per-replica-postgres and ENABLE_CROSS_CHAIN_ANCHOR=true ' +
        '(or when a custom crossChainAnchor is injected via InjectableBootstrapDeps). ' +
        'Default 60000 (1 minute). Minimum 5000 ms. ' +
        'Lower values provide more frequent cross-replica tamper-evidence checkpoints ' +
        'at the cost of additional Postgres queries. ' +
        'Set to a large value (e.g. 3600000) in high-write deployments to control costs.',
    }),


    POLICY_VERSION: optionalString.describe(
      'Version identifier for the active policy (string, default "0.1.0").',
    ),
    ARGUMENT_SCHEMA_REQUIRED: envBoolean({
      default: false,
      description:
        'When true, the gateway denies any matched capability that does not declare an `argumentSchema` (strict mode for I-7). The default (false) preserves existing behaviour: capabilities without an argument schema impose no argument-level constraint. Enable this once every capability your gateway accepts has been migrated to declare an explicit argument schema, to fail closed on schema-less tokens.',
    }),
    ENABLE_DETAILED_LOGGING: envBoolean({
      default: false,
      description: 'Enable verbose request / decision logs. Boolean: true | false.',
    }),

    // CORS ------------------------------------------------------------------
    ALLOWED_ORIGINS: envCsv({
      description:
        'Comma-separated list of browser origins allowed to call the gateway. In production the gateway disables CORS entirely when this is unset (fail-safe).',
    }),

    // Rate limiting ---------------------------------------------------------
    RATE_LIMIT_WINDOW_MS: envPositiveInt({
      default: 60000,
      description:
        'Rate-limit window in milliseconds. Default 60000 (60 s). See README for tuning guidance.',
    }),
    RATE_LIMIT_MAX_REQUESTS: envPositiveInt({
      default: 1000,
      description:
        'Max requests per IP per RATE_LIMIT_WINDOW_MS. Default 1000 (development); tighten in production.',
    }),

    // Per-(jti, action, resource) gateway quota (F-1b) -----------------------
    // Protects the enforcement hot-path from token-flooding. Fires on every
    // validateAction call after capability-match and argument validation, so
    // only well-formed requests consume quota.  Default disabled (back-compat);
    // enable in production with GATEWAY_QUOTA_ENABLED=true.
    GATEWAY_QUOTA_ENABLED: envBoolean({
      default: false,
      description:
        'Enable the per-(jti, action, resource) gateway quota engine (F-1b). Default false. ' +
        'When enabled, every validated tool invocation is counted against a per-token/action/resource ' +
        'budget so a single long-lived token cannot flood the enforcement engine. ' +
        'Wire CALL_COUNTER_REDIS_URL (or REDIS_URL) for distributed counting across replicas.',
    }),
    GATEWAY_QUOTA_MAX: envPositiveInt({
      default: 1000,
      description:
        'Maximum invocations per GATEWAY_QUOTA_WINDOW_SECONDS for the same ' +
        '(jti, action, resource) tuple. Default 1000. Lower for sensitive actions.',
    }),
    GATEWAY_QUOTA_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Length (seconds) of the tumbling window used by the gateway quota engine. Default 60.',
    }),
    GATEWAY_QUOTA_FAIL_CLOSED: envBoolean({
      default: false,
      description:
        'When false (default), a counter-store error allows the request through (fail-open). ' +
        'Set to true to deny when the store is unavailable — note this will deny all ' +
        'quota-eligible traffic during Redis outages.',
    }),

    // Gateway audience (cross-tenant defence) --------------------------------
    GATEWAY_AUDIENCE: optionalString.describe(
      'Expected `aud` claim for capability tokens this gateway will accept. Defaults to "tool-gateway". ' +
      'In multi-tenant deployments set this to a unique per-tenant value (e.g. "tool-gateway:acme-corp-prod") ' +
      'so a token minted for one tenant\'s gateway cannot be replayed at another tenant\'s gateway. ' +
      'MUST match the GATEWAY_AUDIENCE configured on the corresponding capability-issuer instance.',
    ),

    // Hosted/SaaS mode -------------------------------------------------------
    HOSTED_MODE: envBoolean({
      default: false,
      description:
        'Set to "true" when this gateway instance is operating in a hosted / multi-tenant SaaS ' +
        'deployment. When enabled, GATEWAY_AUDIENCE MUST be set to a unique per-tenant value ' +
        '(not the default "tool-gateway") to prevent cross-tenant token replay. ' +
        'The gateway will refuse to start with the default audience in this mode.',
    }),

    // Response redaction safety limit ----------------------------------------
    RESPONSE_REDACTION_MAX_BYTES: envPositiveInt({
      default: 1048576,
      description:
        'Maximum upstream response body size (bytes) that the gateway will buffer for redaction. ' +
        'Responses larger than this limit AND carrying a redaction obligation are refused with ' +
        'HTTP 502 (redaction_oversize) rather than passed through unredacted. Default 1 MiB (1048576). ' +
        'Raise only after confirming that large responses are expected and safe to buffer in memory.',
    }),

    // Cross-org partner trust -----------------------------------------------
    TRUSTED_PARTNER_DIDS: envCsv({
      description:
        'Comma-separated list of partner issuer DIDs whose capability tokens this gateway will accept. Empty / unset = local issuer only.',
    }),
    LOCAL_ISSUER_IDS: envCsv({
      description:
        'Comma-separated list of identifiers treated as the local issuer (in addition to ISSUER_JWKS_URL).',
    }),

    // Multi-issuer trust hardening (cosignature + transparency log) ---------
    //
    // Mitigates the "single-issuer trust root" critical risk: an attacker
    // who pivots from a compromised issuer pod to KMS `signDigest`
    // permission still cannot mint usable tokens that this gateway
    // accepts, because (a) we require N independent cosignatures from
    // separately-keyed authorities and (b) we require an SCT from a
    // trusted transparency log. Both are off by default for back-compat;
    // production gateways should enable at least cosignature.
    REQUIRE_COSIGNATURE_COUNT: envPositiveInt({
      default: 0,
      min: 0,
      description:
        'Minimum number of valid cosignatures the gateway requires on every capability ' +
        'token. 0 (default) disables cosignature enforcement. Set to N>0 to require N ' +
        'independent cosignatures from authorities listed in COSIGNER_JWKS_FILE. ' +
        'Strict-mode rejections raise HTTP 401. The corresponding capability-issuer ' +
        'instance MUST be configured with at least N cosigners (see COSIGNERS on the issuer).',
    }),
    COSIGNER_JWKS_FILE: optionalString.describe(
      'Path to a JWKS file (`{"keys":[...]}` JSON) containing the public keys of every ' +
      'cosigner this gateway trusts. Required when REQUIRE_COSIGNATURE_COUNT > 0. The ' +
      'file is read once at startup; rotate the file and restart the gateway to roll ' +
      'cosigner keys (cosigners are infrequent — file-based publishing is the lowest-' +
      'complexity path that still satisfies independence from the primary issuer JWKS).',
    ),
    COSIGNER_JWKS_INLINE: optionalString.describe(
      'Inline JSON literal of the cosigner JWKS, used as an alternative to ' +
      'COSIGNER_JWKS_FILE for environments (tests, k8s ConfigMaps) that prefer to inject ' +
      'JWKS via env vars rather than mounted files. Provide one of COSIGNER_JWKS_FILE / ' +
      'COSIGNER_JWKS_INLINE when REQUIRE_COSIGNATURE_COUNT > 0.',
    ),
    REQUIRE_TRANSPARENCY_LOG_PROOF: envBoolean({
      default: false,
      description:
        'When true, every capability token MUST carry at least one valid SCT (Signed ' +
        'Certificate Timestamp) from a transparency log listed in TRANSPARENCY_LOG_JWKS_FILE. ' +
        'Provides an independent witness of issuance — an attacker who suborns the issuer ' +
        'cannot retroactively erase log entries; auditors cross-check the log against the ' +
        'issuer\'s audit trail to detect silent fraud. Boolean: true | false. Default false.',
    }),
    TRANSPARENCY_LOG_JWKS_FILE: optionalString.describe(
      'Path to a JSON file mapping logId -> JWKS (`{"log-id":{"keys":[...]}, ...}`) of ' +
      'every transparency log this gateway trusts. Required when ' +
      'REQUIRE_TRANSPARENCY_LOG_PROOF=true. Each top-level key MUST equal the `logId` ' +
      'embedded in SCTs the corresponding log produces.',
    ),
    TRANSPARENCY_LOG_JWKS_INLINE: optionalString.describe(
      'Inline JSON literal mapping logId -> JWKS, alternative to TRANSPARENCY_LOG_JWKS_FILE ' +
      'for env-var-only injection.',
    ),
    PARTNER_DID_CACHE_TTL_SECONDS: envPositiveInt({
      default: 300,
      description:
        'TTL (seconds) for cached partner-DID document entries. After expiry the resolver re-fetches the ' +
        'DID document on the next use. Default 300 (5 min). Lower values propagate key rotations faster ' +
        'at the cost of more resolver traffic.',
    }),
    PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS: envPositiveInt({
      default: 30,
      min: 0,
      description:
        'TTL (seconds) for negative (failed-resolution) partner-DID cache entries. A short window here ' +
        'absorbs transient resolver outages without pinning a stale denial for as long as the positive TTL. ' +
        'Default 30 s. Set to 0 to disable negative caching (every failed resolution re-tries immediately, ' +
        'amplifying resolver traffic during outages).',
    }),
    PARTNER_DID_REQUIRE_PIN: envBoolean({
      default: false,
      description:
        'When true, all partner-DID proposals submitted via the registry admin API MUST include ' +
        'a pinnedDocSha256 value. Enforces pin discipline; proposals without a pin are rejected ' +
        'with HTTP 400. Does not retroactively affect env-var-seeded entries. Boolean: true | false.',
    }),
    PARTNER_DID_REGISTRY_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for partner-DID registry entries. Default "euno:gateway:partner-did". ' +
      'Override when multiple gateway clusters share one Redis instance.',
    ),
    PARTNER_DID_REGISTRY_REQUIRED: envBoolean({
      default: false,
      description:
        'Controls whether TRUSTED_PARTNER_DIDS (the legacy env-var bypass) is accepted. ' +
        'In production (NODE_ENV=production) the default flips to true — TRUSTED_PARTNER_DIDS is a ' +
        'startup error unless PARTNER_DID_REGISTRY_REQUIRED=false is explicitly set. ' +
        'Outside production the default remains false (warning only) unless this is set to true. ' +
        'Set to false in production only as a temporary migration measure; set to true everywhere ' +
        'once the registry is fully adopted and TRUSTED_PARTNER_DIDS has been removed.',
    }),
    PARTNER_DID_PIN_SECRET: optionalString.describe(
      'HMAC-SHA-256 secret used to sign and verify pin attestations on partner-DID registry entries. ' +
      'When set, the approval endpoint wraps pinnedDocSha256 in a signed attestation binding the hash ' +
      'to the approving operator and activation timestamp. The resolver then verifies this signature ' +
      'before trusting any pin — a tampered Redis store cannot forge a valid attestation without this ' +
      'secret. Min 32 bytes recommended; generate with: openssl rand -hex 32. ' +
      'When absent, attestations are not created and existing pins are verified hash-only (back-compat).',
    ),
    PARTNER_DID_AUTO_FETCH_PIN: envBoolean({
      default: false,
      description:
        'When true, the approval endpoint auto-fetches the partner DID document and computes the ' +
        'pinnedDocSha256 hash if the proposal did not include one. This ensures the pin was derived ' +
        'from the live document at the moment of approval — not from an operator-typed or proposer- ' +
        'supplied value. Requires network access to the partner DID endpoint at approval time. ' +
        'Boolean: true | false. Default false.',
    }),
    PARTNER_DID_CB_FAILURE_THRESHOLD: envPositiveInt({
      default: 3,
      min: 1,
      description:
        'Number of DID-document fetch failures within PARTNER_DID_CB_WINDOW_SECONDS that open the ' +
        'per-DID circuit breaker. Once open, getKey() calls for that DID fast-fail without any ' +
        'network round-trip until the cooldown (PARTNER_DID_CB_COOLDOWN_SECONDS) elapses. ' +
        'Default 3. Lower values trip the circuit faster at the cost of more false positives on ' +
        'transient glitches. Each trusted DID has its own independent breaker.',
    }),
    PARTNER_DID_CB_WINDOW_SECONDS: envPositiveInt({
      default: 30,
      min: 1,
      description:
        'Sliding window (seconds) for partner-DID circuit-breaker failure counting. Failures older ' +
        'than this window do not count toward the threshold. Default 30 s.',
    }),
    PARTNER_DID_CB_COOLDOWN_SECONDS: envPositiveInt({
      default: 60,
      min: 1,
      description:
        'Time (seconds) a per-DID circuit breaker stays open before allowing a single probe ' +
        'request. If the probe succeeds the circuit closes; if it fails the cooldown restarts. ' +
        'Default 60 s.',
    }),

    // Partner issuer discovery auto-bootstrap (Task 9 / § 4.7) ---------------
    PARTNER_ISSUER_DISCOVERY_URL: optionalString.describe(
      'Optional URL of a partner issuer\'s /.well-known/capability-issuer discovery document. ' +
      'When set, the gateway fetches this document at startup, extracts the partner\'s issuer DID ' +
      'from the top-level `issuer` field, and seeds that DID into the PartnerDidRegistry as an ' +
      'immediately-active entry (no two-eyes approval required — equivalent to TRUSTED_PARTNER_DIDS ' +
      'for a single partner that publishes a standard discovery document). ' +
      'The `endpoints.jwks` field is logged for diagnostics but not persisted; partner keys are ' +
      'resolved independently via DID-document resolution by the partner-issuer resolver. ' +
      'Production hardening: in production (NODE_ENV=production) this shortcut is blocked by ' +
      'default (same as TRUSTED_PARTNER_DIDS) because PARTNER_DID_REGISTRY_REQUIRED defaults to ' +
      'true. Set PARTNER_DID_REGISTRY_REQUIRED=false to explicitly opt out.',
    ),

    // Distributed coordination (Redis) --------------------------------------
    REDIS_URL: optionalString.describe(
      'Optional shared Redis URL. When set, revocation, kill-switch, and maxCalls counter state propagate across gateway replicas. Required for multi-instance deployments. ' +
      'Individual stores can override this with REVOCATION_REDIS_URL, KILL_SWITCH_REDIS_URL, or CALL_COUNTER_REDIS_URL to target dedicated Redis clusters.',
    ),

    // Per-store Redis URLs (override REDIS_URL for individual control surfaces)
    REVOCATION_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the revocation and epoch stores. Overrides REDIS_URL for these stores. ' +
      'Use to isolate revocation Redis from the kill-switch and call-counter Redis so an outage on one store does not cascade to the others.',
    ),
    KILL_SWITCH_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the kill-switch manager. Overrides REDIS_URL for this store. ' +
      'Allows the kill-switch to target a separate, highly-available Redis cluster or Sentinel setup.',
    ),
    CALL_COUNTER_REDIS_URL: optionalString.describe(
      'Optional dedicated Redis URL for the maxCalls call-counter store. Overrides REDIS_URL for this store. ' +
      'Allows the counter store to target a separate Redis cluster isolated from the revocation and kill-switch stores.',
    ),

    REVOCATION_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for revoked-token entries. Default "revoked:".',
    ),
    REVOCATION_FAIL_OPEN: envBoolean({
      default: false,
      description:
        'When Redis is unreachable, treat lookups as "not revoked" instead of "revoked". Use ONLY if availability matters more than revocation freshness. ' +
        'For a safer availability-preserving alternative, see REVOCATION_STALE_READABLE. Boolean: true | false.',
    }),
    REVOCATION_UNAVAILABLE_MODE: envEnum({
      values: ['fail-closed', '503', 'open'] as const,
      description:
        'How the revocation store should behave when Redis is unavailable and the stale cache cannot serve the request. ' +
        '"fail-closed" (default, back-compat — treat token as revoked → HTTP 401), ' +
        '"503" (throw RevocationUnavailableError → HTTP 503 Service Unavailable, accurate retry semantics for the agent runtime), ' +
        '"open" (treat token as not revoked → allow through, equivalent to REVOCATION_FAIL_OPEN=true). ' +
        'Ignored when REVOCATION_STALE_READABLE=true is also set (stale cache handles unavailability). ' +
        'Recommended for new deployments: "503".',
    }),
    REVOCATION_STALE_READABLE: envBoolean({
      default: false,
      description:
        'When true, the revocation and epoch stores maintain a local write-through cache. On Redis outage (circuit breaker open or connection error), ' +
        'the stores serve from this cache: confirmed-revoked tokens are still denied; tokens not seen locally are allowed through. ' +
        'This prevents a Redis blip from becoming a brownout at the cost of a brief window where cross-replica revocations are not propagated. ' +
        'Recommended over REVOCATION_FAIL_OPEN when you must prioritise availability — use in conjunction with REDIS_CIRCUIT_BREAKER_COOLDOWN_MS ' +
        'to control the outage window. Boolean: true | false.',
    }),
    REVOCATION_EPOCH_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for per-issuer revocation epoch entries. Default "epoch:". ' +
      'Each key stores the epoch (unix seconds) for one issuer; tokens with iat before the epoch are rejected.',
    ),
    REVOCATION_EPOCH_FAIL_OPEN: envBoolean({
      default: false,
      description:
        'When Redis is unreachable for epoch lookups, treat the check as "no epoch set" instead of failing closed. ' +
        'Use ONLY if availability matters more than the epoch-revocation guarantee. Boolean: true | false.',
    }),
    KILL_SWITCH_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for kill-switch entries. Default "killswitch:".',
    ),
    KILL_SWITCH_REFRESH_INTERVAL_MS: envPositiveInt({
      default: 30000,
      min: 0,
      description:
        'Safety-net refresh interval in ms for the kill-switch state. Pub/sub is the primary cross-replica propagation mechanism (sub-second); this timer covers the rare case of a dropped pub/sub message. Default 30000. Set to 0 to disable the periodic refresh entirely (pub/sub-only; only safe if Redis pub/sub delivery is reliable for your deployment).',
    }),
    KILL_SWITCH_FAIL_OPEN_ON_WRITE: envBoolean({
      default: false,
      description:
        'When true, kill-switch writes that fail against Redis still update the local cache. Default false. Boolean: true | false.',
    }),
    KILL_SWITCH_PUBSUB_ENABLED: envBoolean({
      default: true,
      description:
        'When true (default), the gateway opens a second Redis connection in subscribe mode and broadcasts kill-switch mutations on the "<KILL_SWITCH_KEY_PREFIX>events" channel for sub-second cross-replica propagation. Set to false to fall back to periodic-refresh-only propagation (slower; bounded by KILL_SWITCH_REFRESH_INTERVAL_MS). Boolean: true | false.',
    }),

    // Kill-switch Postgres persistence backend (secondary fallback) ----------
    // When configured, every Redis kill-switch write is dual-written to Postgres
    // (fire-and-forget after the Redis write succeeds) and Redis refresh failures
    // fall back to Postgres. This makes the kill-switch resilient to a complete
    // Redis outage — a safety control must not fate-share with a non-HA cache.
    KILL_SWITCH_POSTGRES_URL: optionalString.describe(
      'Optional Postgres connection string for the kill-switch persistence backend. ' +
      'When set, every kill-switch mutation is dual-written to Postgres immediately after the Redis write succeeds ' +
      '(fire-and-forget; write latency is not affected). Redis refresh failures fall back to Postgres so the ' +
      'local cache remains fresh even during a complete Redis outage. ' +
      'Strongly recommended for production deployments where the kill-switch is a safety-critical control. ' +
      'See KILL_SWITCH_PG_TABLE and KILL_SWITCH_PG_RUN_MIGRATIONS.',
    ),
    KILL_SWITCH_PG_TABLE: optionalString.describe(
      'Postgres table name for kill-switch entries. Default "euno_kill_switch_entries". ' +
      'The table is created automatically when KILL_SWITCH_PG_RUN_MIGRATIONS=true.',
    ),
    KILL_SWITCH_PG_RUN_MIGRATIONS: envBoolean({
      default: false,
      description:
        'When true, run CREATE TABLE IF NOT EXISTS for the kill-switch Postgres table at gateway startup. ' +
        'Safe to run repeatedly (idempotent). Requires the gateway DB role to have DDL privileges on the target schema. ' +
        'Default false — run migrations from a privileged role in your deployment pipeline instead. Boolean: true | false.',
    }),
    CALL_COUNTER_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for maxCalls counter entries. Default "capcall:".',
    ),
    CALL_COUNTER_FAIL_OPEN: envBoolean({
      default: false,
      description:
        'Controls circuit-breaker behaviour when Redis is unavailable for the call-counter store. ' +
        'false (default — fail-closed): a Redis error or circuit-open causes the gateway to return a deny ' +
        'for any request that carries a maxCalls condition, rather than risk under-counting calls. ' +
        'This is the correct default for the hosted gateway offering where cryptographic correctness ' +
        'takes precedence over availability. ' +
        'true (fail-open): falls back to an in-process per-replica counter instead of denying all ' +
        'maxCalls-conditioned requests. The effective cap during a Redis outage becomes maxCalls × replicaCount ' +
        '(counters are not shared across replicas). Recommended for self-hosted deployments where a Redis ' +
        'blip causing a service brownout is more disruptive than temporarily relaxed rate limits. ' +
        'Explicitly set this to "false" for the hosted offering and "true" for self-host if you prefer ' +
        'availability over strict cross-replica counting. Boolean: true | false.',
    }),

    // Redis circuit breaker (shared defaults; apply to revocation + call-counter stores)
    REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD: envPositiveInt({
      default: 5,
      description:
        'Number of Redis failures within REDIS_CIRCUIT_BREAKER_WINDOW_MS needed to trip the circuit breaker to "open". ' +
        'When the circuit is open, Redis calls for the affected store fail immediately (no TCP timeout) and the configured fallback is used. ' +
        'Default 5. Applies to the revocation and call-counter stores.',
    }),
    REDIS_CIRCUIT_BREAKER_WINDOW_MS: envPositiveInt({
      default: 10000,
      description:
        'Sliding window (ms) for Redis failure counting used by the circuit breaker. ' +
        'Failures older than this value do not count toward REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD. Default 10000.',
    }),
    REDIS_CIRCUIT_BREAKER_COOLDOWN_MS: envPositiveInt({
      default: 30000,
      description:
        'Time (ms) the circuit breaker stays in the "open" state before transitioning to "half-open" and allowing a single probe call. ' +
        'If the probe succeeds the circuit closes; if it fails the circuit reopens and the cooldown restarts. Default 30000.',
    }),

    // CR-3: Redis grace period — tolerate brief blips without denying traffic.
    // When set, the revocation and call-counter stores will not immediately
    // apply fail-closed / 503 semantics on a Redis outage.  Instead, for the
    // first REDIS_GRACE_PERIOD_MS milliseconds after the circuit trips open,
    // the stores use their local in-memory state:
    //   - Revocation store: tokens confirmed revoked locally are still denied;
    //     tokens not present in the local cache are allowed through.
    //   - Call-counter store: already falls back to the local in-memory counter.
    // After the grace window expires, the configured REVOCATION_UNAVAILABLE_MODE
    // (or fail-closed default) applies.
    //
    // Set to 0 or leave unset to disable the grace period (fail immediately on
    // circuit open — the pre-CR-3 default, preserved for back-compat).
    //
    // Recommended value for production: 5000 (5 seconds) — enough to absorb
    // a brief Redis network blip without causing a service brownout, while
    // still failing closed on sustained outages.
    REDIS_GRACE_PERIOD_MS: envPositiveInt({
      default: 0,
      min: 0,
      description:
        'Grace period (ms) after the Redis circuit breaker opens during which the revocation store ' +
        'uses its local write-through cache instead of applying fail-closed / 503 semantics. ' +
        'Tokens confirmed revoked locally are still denied; tokens not in the local cache are allowed through. ' +
        'Set to 0 (default) to disable and fail immediately on circuit open. ' +
        'Recommended production value: 5000 (5 s). See docs/DEPLOYMENT.md §"Redis HA for production".',
    }),

    // Horizontal sharding (H-1) — consistent-hash agents to replicas --------
    //
    // When GATEWAY_SHARD_COUNT > 1 the gateway data-plane is sharded: the
    // Envoy router (see k8s/envoy-shard-router.yaml) extracts the `sub` claim
    // from each Bearer JWT and directs all traffic for a given agent to the
    // same gateway pod.  That pod then serves the agent's `maxCalls` counter
    // from its local in-memory store — no Redis INCR on the hot path.
    // The revocation, kill-switch, and DPoP-replay stores still talk to Redis
    // for cross-shard safety; the benefit there is that each pod's in-memory
    // snapshot covers only its 1/N slice of the agent population.
    //
    // Set GATEWAY_SHARD_COUNT to the total number of gateway pods and
    // GATEWAY_SHARD_INDEX to this pod's zero-based ordinal.  When using a
    // StatefulSet (recommended) the ordinal is extracted from the pod name via
    // the downward API — see k8s/tool-gateway.yaml for the init-container
    // pattern that writes GATEWAY_SHARD_INDEX into the pod environment.
    GATEWAY_SHARD_COUNT: envPositiveInt({
      default: 1,
      min: 1,
      description:
        'Total number of gateway shards in the fleet. Default 1 (sharding disabled). ' +
        'Set to the replica count of your gateway StatefulSet when horizontal sharding is ' +
        'enabled (H-1). The Envoy shard router must be deployed alongside the gateway and ' +
        'configured with the same shard count so it routes agents consistently. Must match ' +
        'GATEWAY_SHARD_COUNT on every replica; a mismatch causes inconsistent routing and ' +
        'counter drift. See docs/HORIZONTAL_SHARDING.md.',
    }),
    GATEWAY_SHARD_INDEX: envPositiveInt({
      default: 0,
      min: 0,
      description:
        'Zero-based shard index for this gateway replica. Default 0. ' +
        'Must be in the range [0, GATEWAY_SHARD_COUNT - 1]. When running as a Kubernetes ' +
        'StatefulSet, inject this from the pod ordinal via an init container or a ' +
        '`GATEWAY_SHARD_INDEX=$(echo $POD_NAME | awk -F- \'{print $NF}\')` env stanza. ' +
        'See k8s/tool-gateway.yaml and docs/HORIZONTAL_SHARDING.md.',
    }),

    // Multi-region active/active (F-7) ---------------------------------------
    GATEWAY_REGION: optionalString.describe(
      'Logical region tag for this gateway instance (e.g. "eastus2", "westeurope"). Surfaced on audit events and request span attributes (`euno.region`). Symmetrical to ISSUER_REGION on the capability-issuer; recommended in any multi-region deployment so audit trails can be reconstructed after a regional failover. See docs/MULTI_REGION_ISSUER.md.',
    ),

    // DPoP / sender-constrained tokens (F-2, RFC 9449) -----------------------
    DPOP_REQUIRED: envBoolean({
      default: true,
      description:
        'When true (default), the gateway rejects any capability token without a `cnf.jkt` confirmation claim (i.e. requires sender-constrained tokens per RFC 9449 / F-2). Set to false only for backward-compatible deployments where issuers have not yet been rolled out with DPoP support; in that mode a leaked token remains usable as a plain bearer token until it expires or is revoked.',
    }),
    DPOP_CLOCK_SKEW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Maximum number of seconds the DPoP proof `iat` claim may be ahead of the gateway clock before the proof is rejected as future-dated. Default 60. Lower values demand tighter NTP sync; higher values widen the replay window slightly.',
    }),
    DPOP_MAX_AGE_SECONDS: envPositiveInt({
      default: 300,
      description:
        'Maximum age (in seconds) of an accepted DPoP proof. Anything older is refused as expired. Default 300 (5 minutes). The proof `jti` is remembered for this period to defeat replays.',
    }),

    // Reverse-proxy trust (security boundary for DPoP htu, client-IP, …) -----
    TRUST_PROXY: optionalString.describe(
      'Express `trust proxy` setting. Controls whether `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-For` are honoured when reconstructing the request URL — required for DPoP `htu` verification (F-2) when the gateway sits behind a TLS-terminating reverse proxy. Accepts: "true" (trust all proxies — UNSAFE if the gateway is also reachable directly by clients), "false"/unset (ignore X-Forwarded-* — safe default for direct deployment), an integer hop count ("1" = trust the immediate upstream proxy, recommended), or a comma-separated list of trusted CIDRs ("10.0.0.0/8,172.16.0.0/12"). MUST be configured when running behind a load balancer; without it, a direct caller can spoof X-Forwarded-* to make the DPoP proof verify against an attacker-chosen URL.',
    ),

    // Source-IP trust mode for POST /api/v1/enforce (CR-2) ------------------
    ENFORCE_SOURCE_IP_MODE: optionalString
      .pipe(
        z
          .union([z.literal('gateway'), z.literal('client'), z.undefined()])
          .transform((v) => v ?? 'gateway'),
      )
      .describe(
        'Controls which IP address is used as the authoritative sourceIp for ipRange policy conditions in POST /api/v1/enforce. ' +
          '"gateway" (default): the gateway derives the effective IP from the TCP connection / X-Forwarded-For headers (via Express req.ip, respecting TRUST_PROXY). ' +
          'The client-supplied context.sourceIp is ignored for enforcement but logged as a warning when it differs from the derived IP, making spoofing attempts observable. ' +
          '"client": legacy behaviour — the gateway trusts the sourceIp value sent in the request body. ' +
          'SECURITY: "client" mode allows any caller to pass an arbitrary IP to bypass ipRange conditions. ' +
          'Only use "client" if every caller is a trusted internal service that already enforces the trust boundary. ' +
          'DEPLOYMENT: when TRUST_PROXY is not configured and the gateway sits behind a reverse proxy, ' +
          '"gateway" mode will see the proxy\'s IP rather than the client\'s — configure TRUST_PROXY first.',
      ),

    // OCSF audit transport (F-6) --------------------------------------------
    OCSF_TRANSPORT: optionalString.describe(
      'Optional OCSF (Open Cybersecurity Schema Framework) audit sink. One of: "stdout" (one JSON-line per event written to stderr so existing stdout pipelines are untouched), "file" (append to OCSF_FILE_PATH), "http" (POST each event to OCSF_HTTP_URL). When unset (default), OCSF emission is disabled and existing winston logging is unchanged. Every AuditLogEntry and SignedAuditEvidence the gateway emits is mirrored as an OCSF v1.1 event (Authorization 3003 for issuance/revocation, API Activity 6003 for tool invocations) so any SIEM that speaks OCSF can ingest without writing a Euno-specific parser.',
    ),
    OCSF_FILE_PATH: optionalString.describe(
      'Path the file OCSF transport appends events to. Required when OCSF_TRANSPORT=file. Rotation is delegated to the operating system (logrotate / journald).',
    ),
    OCSF_HTTP_URL: optionalString.describe(
      'Collector URL the http OCSF transport POSTs events to. Required when OCSF_TRANSPORT=http. Failures are logged and swallowed — operators who need guaranteed delivery should layer a queueing collector (Vector, Fluent Bit) in front of this transport.',
    ),
    OCSF_HTTP_HEADERS: optionalString.describe(
      'Optional JSON object of additional HTTP headers for the http OCSF transport (e.g. \'{"x-api-key":"..."}\'). Ignored if OCSF_TRANSPORT≠http.',
    ),
  })
  .superRefine((cfg, ctx) => {
    // Hosted mode audience guard — must be checked in all environments.
    // A HOSTED_MODE deployment with the default audience "tool-gateway" would
    // allow cross-tenant token replay: a token minted for tenant A could be
    // used against tenant B's gateway. Operators must set a unique per-tenant
    // value (e.g. "tool-gateway:acme-corp-prod").
    if (cfg.HOSTED_MODE) {
      const audience = cfg.GATEWAY_AUDIENCE?.trim();
      if (!audience || audience === 'tool-gateway') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['GATEWAY_AUDIENCE'],
          message:
            'GATEWAY_AUDIENCE must be set to a unique per-tenant value when HOSTED_MODE=true. ' +
            `Got ${audience ? `"${audience}" (the insecure default)` : '<unset>'}. ` +
            'A non-unique audience allows a token minted for one tenant\'s gateway to be ' +
            'replayed at any other tenant\'s gateway. ' +
            'Set GATEWAY_AUDIENCE to a value like "tool-gateway:acme-corp-prod".',
        });
      }
    }

    // Admin API protection is a hard requirement in production: an
    // unprotected /admin/* surface controls revocation and kill-switch
    // state and must never be reachable without authentication.
    if (cfg.NODE_ENV === 'production' && !cfg.ADMIN_API_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_API_KEY'],
        message:
          'ADMIN_API_KEY must be set when NODE_ENV=production. ' +
          'The /admin endpoints control token revocation and kill-switch state ' +
          'and must not be publicly reachable.',
      });
    }

    const signedDecisions = cfg.EVIDENCE_SIGNED_DECISIONS;
    if (signedDecisions !== undefined) {
      const allowed = new Set(['allow', 'deny']);
      const bad = signedDecisions.filter((d) => !allowed.has(d));
      if (bad.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['EVIDENCE_SIGNED_DECISIONS'],
          message:
            `EVIDENCE_SIGNED_DECISIONS contains unsupported value(s): ${bad.join(', ')}. ` +
            `Allowed values are "allow" and "deny".`,
        });
      }
    }

    // Evidence signing is enabled when:
    //   - EVIDENCE_SIGNED_DECISIONS is defined (authoritative): only when
    //     it carries at least one decision; an explicitly-empty list
    //     disables signing even if the legacy boolean is true.
    //   - EVIDENCE_SIGNED_DECISIONS is undefined: fall back to the
    //     legacy ENABLE_CRYPTOGRAPHIC_AUDIT boolean.
    // This matches the per-decision semantics enforced by
    // EnforcementEngine and the documented override behaviour in the
    // PR / docs.
    const willSignSomething =
      signedDecisions !== undefined
        ? signedDecisions.length > 0
        : !!cfg.ENABLE_CRYPTOGRAPHIC_AUDIT;

    if (
      willSignSomething &&
      !cfg.EVIDENCE_SIGNING_KEY_PEM &&
      !cfg.EVIDENCE_SIGNING_KEY_FILE &&
      !cfg.AUDIT_SIGNING_KMS_PROVIDER
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['EVIDENCE_SIGNING_KEY_PEM'],
        message:
          'When evidence signing is enabled (ENABLE_CRYPTOGRAPHIC_AUDIT=true with EVIDENCE_SIGNED_DECISIONS unset, or EVIDENCE_SIGNED_DECISIONS non-empty), ' +
          'either EVIDENCE_SIGNING_KEY_PEM, EVIDENCE_SIGNING_KEY_FILE, or AUDIT_SIGNING_KMS_PROVIDER must be set.',
      });
    }

    // Validate KMS-provider-specific required fields at boot time so a
    // misconfigured deployment fails immediately rather than at first request.
    if (cfg.AUDIT_SIGNING_KMS_PROVIDER === 'azure-keyvault') {
      if (!cfg.AUDIT_SIGNING_AZURE_KEYVAULT_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUDIT_SIGNING_AZURE_KEYVAULT_URL'],
          message: 'AUDIT_SIGNING_AZURE_KEYVAULT_URL is required when AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault.',
        });
      }
      if (!cfg.AUDIT_SIGNING_AZURE_KEY_NAME) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUDIT_SIGNING_AZURE_KEY_NAME'],
          message: 'AUDIT_SIGNING_AZURE_KEY_NAME is required when AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault.',
        });
      }
      if (
        cfg.AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE === 'client-secret' &&
        (!cfg.AUDIT_SIGNING_AZURE_CLIENT_ID || !cfg.AUDIT_SIGNING_AZURE_CLIENT_SECRET || !cfg.AUDIT_SIGNING_AZURE_TENANT_ID)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE'],
          message:
            'AUDIT_SIGNING_AZURE_CLIENT_ID, AUDIT_SIGNING_AZURE_CLIENT_SECRET, and AUDIT_SIGNING_AZURE_TENANT_ID ' +
            'are required when AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret.',
        });
      }
    }

    if (cfg.AUDIT_SIGNING_KMS_PROVIDER === 'aws-kms') {
      if (!cfg.AUDIT_SIGNING_AWS_KMS_KEY_ID) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUDIT_SIGNING_AWS_KMS_KEY_ID'],
          message: 'AUDIT_SIGNING_AWS_KMS_KEY_ID is required when AUDIT_SIGNING_KMS_PROVIDER=aws-kms.',
        });
      }
    }

    if (cfg.AUDIT_SIGNING_KMS_PROVIDER === 'gcp-cloudkms') {
      const gcpRequired = ['AUDIT_SIGNING_GCP_PROJECT_ID', 'AUDIT_SIGNING_GCP_KEYRING_ID', 'AUDIT_SIGNING_GCP_CRYPTOKEY_ID'] as const;
      for (const field of gcpRequired) {
        if (!cfg[field]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [field],
            message: `${field} is required when AUDIT_SIGNING_KMS_PROVIDER=gcp-cloudkms.`,
          });
        }
      }
    }

    // R-9: validate the audit-pipeline backpressure policy at config
    // load time so a typo in the env var produces a single structured
    // failure instead of a runtime surprise on the first denied request.
    if (cfg.AUDIT_PIPELINE_BACKPRESSURE !== undefined) {
      if (!(BACKPRESSURE_POLICIES as readonly string[]).includes(cfg.AUDIT_PIPELINE_BACKPRESSURE)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUDIT_PIPELINE_BACKPRESSURE'],
          message:
            `AUDIT_PIPELINE_BACKPRESSURE must be one of: ${BACKPRESSURE_POLICIES.join(', ')} ` +
            `(got '${cfg.AUDIT_PIPELINE_BACKPRESSURE}').`,
        });
      }
    }

    // PORT and ADMIN_PORT must be different; an operator who mistakenly sets
    // them to the same value would get a cryptic OS-level EADDRINUSE crash at
    // runtime rather than a clear startup error.
    if (cfg.PORT === cfg.ADMIN_PORT) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_PORT'],
        message:
          `ADMIN_PORT and PORT cannot be the same value. ` +
          `Current values: ADMIN_PORT=${cfg.ADMIN_PORT}, PORT=${cfg.PORT}. ` +
          `Please set ADMIN_PORT to a different port (default: 3003).`,
      });
    }

    // ----------------------------------------------------------------------
    // Production-tier safety invariants (R-5 extension).
    // The deployment checklist's hard requirements are encoded here so a
    // misconfigured production rollout fails at boot rather than at first
    // request. Each rule maps 1:1 to an item in
    // `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md`.
    // ----------------------------------------------------------------------
    if (cfg.NODE_ENV === 'production') {
      // Multi-replica / multi-region deployments need REDIS_URL so
      // revocation, kill-switch, maxCalls counters and DPoP-replay state
      // propagate across pods (otherwise authorization decisions
      // split-brain and a token revoked on one replica is still accepted
      // by the others).
      if (cfg.EUNO_DEPLOYMENT_TIER !== 'single-replica' && !cfg.REDIS_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['REDIS_URL'],
          message:
            `REDIS_URL is required when NODE_ENV=production and ` +
            `EUNO_DEPLOYMENT_TIER=${cfg.EUNO_DEPLOYMENT_TIER}. ` +
            'Without it, revocation entries, kill-switch state, maxCalls counters and ' +
            'DPoP replay nonces fall back to per-pod in-memory stores, so a token revoked / ' +
            'killed on one replica is still accepted by the others (split-brain authorization). ' +
            'Set EUNO_DEPLOYMENT_TIER=single-replica only if you are deliberately running a ' +
            'single gateway pod and have accepted that operational consequence.',
        });
      }

      // Multi-region active/active also needs a region tag on every
      // replica so audit trails can be reconstructed across the fleet.
      if (cfg.EUNO_DEPLOYMENT_TIER === 'multi-region-active-active' && !cfg.GATEWAY_REGION) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['GATEWAY_REGION'],
          message:
            'GATEWAY_REGION is required when NODE_ENV=production and ' +
            'EUNO_DEPLOYMENT_TIER=multi-region-active-active. The region tag is stamped on ' +
            'audit events and trace spans so failovers can be reconstructed from the audit ' +
            'timeline. See docs/MULTI_REGION_ISSUER.md.',
        });
      }

      // DPoP enforcement is the F-2 defence against bearer-token theft.
      // After the documented DPoP migration the production default is
      // `true`; an operator can only get here by explicitly setting
      // `DPOP_REQUIRED=false`, which we treat as a hard error.
      if (cfg.DPOP_REQUIRED === false) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['DPOP_REQUIRED'],
          message:
            'DPOP_REQUIRED=false is not permitted when NODE_ENV=production. ' +
            'After the DPoP migration the gateway must reject any capability token without ' +
            'a `cnf.jkt` confirmation claim (RFC 9449 / F-2); otherwise a leaked token ' +
            'remains usable as a plain bearer until it expires or is revoked. Remove the ' +
            'override (DPOP_REQUIRED defaults to true) before promoting to production.',
        });
      }

      // R-6 JWKS rotation requires the gateway to read keys from the
      // issuer's JWKS endpoint, not the deprecated single-key endpoint.
      // Production must point at ISSUER_JWKS_URL — accepting only the
      // deprecated ISSUER_PUBLIC_KEY_URL silently freezes key material
      // at the value cached when the gateway booted.
      if (!cfg.ISSUER_JWKS_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ISSUER_JWKS_URL'],
          message:
            'ISSUER_JWKS_URL is required when NODE_ENV=production. ' +
            (cfg.ISSUER_PUBLIC_KEY_URL
              ? 'ISSUER_PUBLIC_KEY_URL is deprecated and must not be used as the sole key ' +
                'source in production — it freezes key material at the value cached on boot ' +
                'and breaks R-6 JWKS rotation. '
              : '') +
            'Set ISSUER_JWKS_URL to the issuer\'s JWKS endpoint, e.g. ' +
            'https://issuer.example.com/.well-known/jwks.json',
        });
      }

      // Evidence signing must be active so denials (and optionally
      // allows) carry a tamper-evident signature for SIEM ingestion.
      // Either the legacy single-toggle (ENABLE_CRYPTOGRAPHIC_AUDIT)
      // or the per-decision selector (EVIDENCE_SIGNED_DECISIONS) must
      // resolve to "we will sign at least one decision class".
      const signedDecisionsForProd = cfg.EVIDENCE_SIGNED_DECISIONS;
      const willSignSomething =
        signedDecisionsForProd !== undefined
          ? signedDecisionsForProd.length > 0
          : !!cfg.ENABLE_CRYPTOGRAPHIC_AUDIT;
      if (!willSignSomething) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['EVIDENCE_SIGNED_DECISIONS'],
          message:
            'Evidence signing must be enabled when NODE_ENV=production. ' +
            'Set EVIDENCE_SIGNED_DECISIONS=deny (or "allow,deny" for full coverage) and ' +
            'configure EVIDENCE_SIGNING_KEY_PEM/EVIDENCE_SIGNING_KEY_FILE, or — for the ' +
            'legacy on/off shorthand — set ENABLE_CRYPTOGRAPHIC_AUDIT=true. Without one of ' +
            'these the audit trail of authorization refusals is not tamper-evident.',
        });
      }

      // Separate public and administrative serving surfaces (defence in
      // depth on top of the existing ADMIN_PORT split). ADMIN_HOST must
      // be set to a non-wildcard interface so a misconfigured ingress /
      // service route cannot expose /admin/* on the public LB. The
      // admin Service in `k8s/tool-gateway-deployment.yaml` is already
      // ClusterIP-only; this rule extends the same guarantee to the
      // app itself.
      const adminHost = cfg.ADMIN_HOST?.trim();
      if (!adminHost || adminHost === '0.0.0.0' || adminHost === '::') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ADMIN_HOST'],
          message:
            'ADMIN_HOST must be set to a non-wildcard interface when NODE_ENV=production. ' +
            `Got ${adminHost === undefined ? '<unset>' : `"${adminHost}"`}. ` +
            'The admin surface controls revocation and kill-switch state; binding it to ' +
            '0.0.0.0 / :: makes a misconfigured ingress capable of exposing /admin/* on the ' +
            'public load-balancer. Recommended values: "127.0.0.1" for sidecar-only access, ' +
            'or the pod\'s internal cluster IP.',
        });
      }
    }

    // Multi-issuer trust hardening cross-field rules.
    if (cfg.REQUIRE_COSIGNATURE_COUNT > 0 && !cfg.COSIGNER_JWKS_FILE && !cfg.COSIGNER_JWKS_INLINE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['COSIGNER_JWKS_FILE'],
        message:
          'COSIGNER_JWKS_FILE or COSIGNER_JWKS_INLINE is required when ' +
          'REQUIRE_COSIGNATURE_COUNT > 0. Without trusted cosigner keys the gateway ' +
          'cannot verify any cosignature and would reject every token (fail-closed).',
      });
    }
    if (
      cfg.REQUIRE_TRANSPARENCY_LOG_PROOF &&
      !cfg.TRANSPARENCY_LOG_JWKS_FILE &&
      !cfg.TRANSPARENCY_LOG_JWKS_INLINE
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['TRANSPARENCY_LOG_JWKS_FILE'],
        message:
          'TRANSPARENCY_LOG_JWKS_FILE or TRANSPARENCY_LOG_JWKS_INLINE is required when ' +
          'REQUIRE_TRANSPARENCY_LOG_PROOF=true. Without trusted log keys the gateway cannot ' +
          'verify any SCT and would reject every token (fail-closed).',
      });
    }

    // Horizontal sharding sanity: index must be within [0, count - 1].
    if (cfg.GATEWAY_SHARD_COUNT > 1 && cfg.GATEWAY_SHARD_INDEX >= cfg.GATEWAY_SHARD_COUNT) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['GATEWAY_SHARD_INDEX'],
        message:
          `GATEWAY_SHARD_INDEX (${cfg.GATEWAY_SHARD_INDEX}) must be less than ` +
          `GATEWAY_SHARD_COUNT (${cfg.GATEWAY_SHARD_COUNT}). ` +
          'Each gateway replica needs a unique zero-based ordinal in the range ' +
          '[0, GATEWAY_SHARD_COUNT - 1]. For a StatefulSet use the pod ordinal from $POD_NAME.',
      });
    }
  });

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

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

// ---------------------------------------------------------------------------
// Agent Runtime schema — `agent-runtime`
// ---------------------------------------------------------------------------

export const AgentRuntimeConfigSchema = z
  .object({
    NODE_ENV,
    PORT: envPort({
      default: 3003,
      description: 'TCP port the agent-runtime health check HTTP server binds to.',
    }),

    // Agent identity
    AGENT_ID: z
      .string()
      .min(1)
      .describe(
        'Unique identifier for this agent. Included in capability-token requests as the ' +
        '`agentId` claim. Required.',
      ),
    GATEWAY_URL: z
      .string()
      .url()
      .describe(
        'URL of the tool-gateway this agent connects to. Required. ' +
        'Example: https://gateway.example.com',
      ),
    ISSUER_URL: z
      .string()
      .url()
      .describe(
        'URL of the capability-issuer this agent authenticates against. Required. ' +
        'Example: https://issuer.example.com',
      ),
    AUTH_TOKEN: z
      .string()
      .min(1)
      .describe(
        'Bootstrap credential presented to the issuer to obtain the first capability token. ' +
        'This is the agent\'s proof of identity (e.g. an OIDC access token or API key). Required.',
      ),

    // Token refresh
    TOKEN_REFRESH_INTERVAL: envPositiveInt({
      default: 600,
      description:
        'How often (seconds) the agent proactively refreshes its capability token before it ' +
        'expires. Default 600 (10 minutes). Set below DEFAULT_TOKEN_TTL on the issuer.',
    }),
  });

export type AgentRuntimeConfig = z.infer<typeof AgentRuntimeConfigSchema>;

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

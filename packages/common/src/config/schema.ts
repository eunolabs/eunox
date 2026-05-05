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
    PORT: envPositiveInt({
      default: 3001,
      description: 'TCP port the issuer HTTP server binds to.',
      min: 1,
      max: 65535,
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

    // Per-IP rate limit (express-rate-limit, secondary defence) ---------------
    // Primary per-(tenant,user,agent) defence is ISSUANCE_RATE_LIMIT_* below.
    // This coarser per-IP limit guards against unauthenticated flooding before
    // the identity-provider round-trip completes.
    RATE_LIMIT_WINDOW_MS: envPositiveInt({
      default: 60000,
      description:
        'Rate-limit window in milliseconds for the per-IP express-rate-limit middleware. Default 60000 (60 s). Applies to all issuer routes before authentication.',
    }),
    RATE_LIMIT_MAX_REQUESTS: envPositiveInt({
      default: 100,
      description:
        'Maximum requests per IP per RATE_LIMIT_WINDOW_MS. Default 100. The per-(tenant,user,agent) issuance rate limit (ISSUANCE_RATE_LIMIT_*) is the primary post-authentication defence; this coarser guard fires before identity resolution.',
    }),

    // Per-(tenant, user, agent) issuance rate limit (F-1, addresses I-1) -----
    // Replaces the legacy per-IP express rate limit as the primary defence
    // against a compromised user account / agent flooding /api/v1/issue.
    // Tenant-aware so the same limiter is safe for a multi-region active/
    // active issuer (F-7) — see docs/MULTI_REGION_ISSUER.md.
    ISSUANCE_RATE_LIMIT_ENABLED: envBoolean({
      default: true,
      description:
        'Enable the per-(tenant, user, agent) issuance rate limit (F-1, addresses I-1). Default true. Disable only in development; in production this is the primary defence against a compromised user/agent flooding /api/v1/issue.',
    }),
    ISSUANCE_RATE_LIMIT_MAX: envPositiveInt({
      default: 60,
      description:
        'Maximum capability-issuance requests permitted per ISSUANCE_RATE_LIMIT_WINDOW_SECONDS for the same (tenantId, userId, agentId) tuple. Default 60.',
    }),
    ISSUANCE_RATE_LIMIT_WINDOW_SECONDS: envPositiveInt({
      default: 60,
      description:
        'Length (seconds) of the tumbling window used by the issuance rate limiter. Default 60.',
    }),
    ISSUANCE_RATE_LIMIT_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for the issuance rate limiter. Default "issrl:".',
    ),
    ISSUANCE_RATE_LIMIT_FAIL_CLOSED: envBoolean({
      default: true,
      description:
        'When true (default), Redis errors during issuance rate-limit lookup deny the request (fail closed). Set to false only when transient Redis loss should not block issuance — note this re-opens the window an attacker could exploit.',
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
  });

export type IssuerConfig = z.infer<typeof IssuerConfigSchema>;

// ---------------------------------------------------------------------------
// Gateway schema — `tool-gateway`
// ---------------------------------------------------------------------------

export const GatewayConfigSchema = z
  .object({
    NODE_ENV,
    EUNO_DEPLOYMENT_TIER,
    PORT: envPositiveInt({
      default: 3002,
      description: 'TCP port the gateway HTTP server binds to.',
      min: 1,
      max: 65535,
    }),
    ADMIN_PORT: envPositiveInt({
      default: 3003,
      description:
        'TCP port the gateway admin HTTP server binds to. Admin routes (/admin/*) are served ' +
        'exclusively on this port so they are unreachable from the public-facing load-balancer. ' +
        'Must differ from PORT. Default 3003.',
      min: 1,
      max: 65535,
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

    // Policy ----------------------------------------------------------------
    POLICY_VERSION: optionalString.describe(
      'Version identifier for the active policy (string, default "1.0.0").',
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

    // Gateway audience (cross-tenant defence) --------------------------------
    GATEWAY_AUDIENCE: optionalString.describe(
      'Expected `aud` claim for capability tokens this gateway will accept. Defaults to "tool-gateway". ' +
      'In multi-tenant deployments set this to a unique per-tenant value (e.g. "tool-gateway:acme-corp-prod") ' +
      'so a token minted for one tenant\'s gateway cannot be replayed at another tenant\'s gateway. ' +
      'MUST match the GATEWAY_AUDIENCE configured on the corresponding capability-issuer instance.',
    ),

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
    PARTNER_DID_REGISTRY_REQUIRED: envBoolean({
      default: false,
      description:
        'When true, TRUSTED_PARTNER_DIDS (the legacy env-var bypass) is rejected at startup with ' +
        'an error. Forces operators to use the two-eyes registry workflow for all partner-DID trust ' +
        'entries. Set to true once the registry is fully adopted and TRUSTED_PARTNER_DIDS removed. ' +
        'Boolean: true | false.',
    }),
    PARTNER_DID_REGISTRY_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for partner-DID registry entries. Default "euno:gateway:partner-did". ' +
      'Override when multiple gateway clusters share one Redis instance.',
    ),

    // Distributed coordination (Redis) --------------------------------------
    REDIS_URL: optionalString.describe(
      'Optional shared Redis URL. When set, revocation, kill-switch, and maxCalls counter state propagate across gateway replicas. Required for multi-instance deployments.',
    ),
    REVOCATION_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for revoked-token entries. Default "revoked:".',
    ),
    REVOCATION_FAIL_OPEN: envBoolean({
      default: false,
      description:
        'When Redis is unreachable, treat lookups as "not revoked" instead of "revoked". Use ONLY if availability matters more than revocation freshness. Boolean: true | false.',
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
    CALL_COUNTER_KEY_PREFIX: optionalString.describe(
      'Optional Redis key prefix for maxCalls counter entries. Default "capcall:".',
    ),

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
      !cfg.EVIDENCE_SIGNING_KEY_FILE
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['EVIDENCE_SIGNING_KEY_PEM'],
        message:
          'When evidence signing is enabled (ENABLE_CRYPTOGRAPHIC_AUDIT=true with EVIDENCE_SIGNED_DECISIONS unset, or EVIDENCE_SIGNED_DECISIONS non-empty), either EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE must be set.',
      });
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
export const EUNO_SERVICE_NAMES = ['issuer', 'gateway'] as const;
export type EunoServiceName = (typeof EUNO_SERVICE_NAMES)[number];

export const EUNO_CONFIG_SCHEMAS = {
  issuer: IssuerConfigSchema,
  gateway: GatewayConfigSchema,
} as const;

export type EunoConfigFor<S extends EunoServiceName> = S extends 'issuer'
  ? IssuerConfig
  : S extends 'gateway'
    ? GatewayConfig
    : never;

/**
 * The shape of a `EunoConfig` for any of the registered services.
 */
export type EunoConfig = IssuerConfig | GatewayConfig;

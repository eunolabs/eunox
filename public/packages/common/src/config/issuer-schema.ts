import { z } from 'zod';
import {
  optionalString, envBoolean, envPositiveInt, envPort, envCsv, envEnum,
  NODE_ENV, EUNO_DEPLOYMENT_TIER
} from './base-schema';

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
      'did:ion resolver URL. Defaults to the public Microsoft resolver ' +
      '(https://ion.msidentity.com/api/v1.0/identifiers). Override for self-hosted ION nodes ' +
      'or air-gapped deployments running a private ION sidecar.',
    ),
    ION_CB_FAILURE_THRESHOLD: envPositiveInt({
      default: 3,
      min: 1,
      description:
        'Number of did:ion resolver failures within ION_CB_WINDOW_SECONDS that open the ION ' +
        'circuit breaker. Once open, resolveDidIon() calls fast-fail with a CapabilityError ' +
        'until the cooldown (ION_CB_COOLDOWN_SECONDS) elapses. ' +
        'Default 3. Lower values trip the circuit faster but may cause more false positives ' +
        'on transient network glitches.',
    }),
    ION_CB_WINDOW_SECONDS: envPositiveInt({
      default: 30,
      min: 1,
      description:
        'Sliding window (seconds) for ION circuit-breaker failure counting. Failures older ' +
        'than this window do not count toward ION_CB_FAILURE_THRESHOLD. Default 30 s.',
    }),
    ION_CB_COOLDOWN_SECONDS: envPositiveInt({
      default: 60,
      min: 1,
      description:
        'Time (seconds) the ION circuit breaker stays open before allowing a single probe ' +
        'request. If the probe succeeds the circuit closes; if it fails the cooldown restarts. ' +
        'Default 60 s.',
    }),

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

    // SCIM 2.0 provisioning (Task 10 — Stage 5) --------------------------------
    // Enables push-based group membership from an enterprise IdP (Okta,
    // Entra ID, Ping Identity). When ISSUER_SCIM_BEARER_TOKEN is set the
    // SCIM v2 endpoints are mounted at /scim/v2/ and validated using
    // constant-time Bearer token comparison. SCIM group → role mapping is
    // configured via ISSUER_SCIM_GROUP_ROLE_MAP. Requires ISSUER_DB_URL.
    ISSUER_SCIM_BEARER_TOKEN: optionalString.describe(
      'Static bearer token presented by the enterprise IdP (Okta, Entra ID, Ping Identity) ' +
      'when pushing SCIM provisioning events to the issuer. ' +
      'Validated with constant-time comparison on every SCIM request. ' +
      'When unset, the /scim/v2/ endpoints are not mounted. ' +
      'Must be ≥32 characters in production. Treat as a long-lived secret: store in a ' +
      'secret manager and rotate at least annually or immediately on exposure. ' +
      'Requires ISSUER_DB_URL.',
    ),
    ISSUER_SCIM_GROUP_ROLE_MAP: optionalString.describe(
      'JSON object mapping SCIM group display names to issuer role keys. ' +
      'Example: \'{"SalesTeam":"sales","EngineeringTeam":"engineer"}\'. ' +
      'When a provisioned user belongs to a mapped group, the corresponding role ' +
      'is merged into the user\'s role set at issuance time (SCIM roles take ' +
      'precedence on conflict with IdP-provided roles). ' +
      'Groups not present in this map are ignored at issuance time. ' +
      'Mapping an admin-tier role (e.g. "operator") requires an explicit operator-JWT ' +
      'review before the mapping is applied — see docs/issuer-idp-setup.md §"SCIM provisioning".',
    ),

    // Secrets abstraction layer (cross-cloud SecretStore) -------------------
    // When SECRET_STORE_PROVIDER is set, runtime secrets (HMAC keys, admin
    // API keys, SCIM tokens, etc.) are read from the configured cloud secret
    // store instead of process.env. See docs/ADAPTERS.md §"Secret store"
    // and createSecretStoreFromEnv() in @euno/common-core for usage.
    SECRET_STORE_PROVIDER: envEnum({
      values: ['env', 'azure-keyvault', 'aws-secretsmanager', 'gcp-secretmanager'] as const,
      default: 'env',
      description:
        'Secrets backend used to resolve runtime secrets. ' +
        '"env" (default): read directly from environment variables (no cloud dependency). ' +
        '"azure-keyvault": read from Azure Key Vault secrets (requires SECRET_STORE_AZURE_VAULT_URL). ' +
        '"aws-secretsmanager": read from AWS Secrets Manager (optionally configured via SECRET_STORE_AWS_REGION). ' +
        '"gcp-secretmanager": read from GCP Secret Manager (requires GCP_PROJECT_ID or SECRET_STORE_GCP_PROJECT_ID). ' +
        'See docs/ADAPTERS.md §"Secret store" for the name-mapping convention.',
    }),
    SECRET_STORE_AZURE_VAULT_URL: optionalString.describe(
      'Azure Key Vault base URL for the secret store. Required when SECRET_STORE_PROVIDER=azure-keyvault. ' +
      'Example: https://my-vault.vault.azure.net/',
    ),
    SECRET_STORE_AZURE_CREDENTIAL_TYPE: envEnum({
      values: ['default', 'managed-identity', 'client-secret'] as const,
      default: 'default',
      description:
        'Azure credential strategy for the secret store Key Vault. One of: default, managed-identity, client-secret. ' +
        'Defaults to "default" (DefaultAzureCredential). Only used when SECRET_STORE_PROVIDER=azure-keyvault.',
    }),
    SECRET_STORE_AZURE_CLIENT_ID: optionalString.describe(
      'Azure service principal client ID for the secret store. ' +
      'Required when SECRET_STORE_AZURE_CREDENTIAL_TYPE=client-secret.',
    ),
    SECRET_STORE_AZURE_CLIENT_SECRET: optionalString.describe(
      'Azure service principal client secret for the secret store. ' +
      'Required when SECRET_STORE_AZURE_CREDENTIAL_TYPE=client-secret.',
    ),
    SECRET_STORE_AZURE_TENANT_ID: optionalString.describe(
      'Azure tenant ID for the secret store. ' +
      'Required when SECRET_STORE_AZURE_CREDENTIAL_TYPE=client-secret.',
    ),
    SECRET_STORE_AWS_REGION: optionalString.describe(
      'AWS region for Secrets Manager. Optional; defaults to the SDK default ' +
      '(AWS_REGION / AWS_DEFAULT_REGION env vars). Only used when SECRET_STORE_PROVIDER=aws-secretsmanager.',
    ),
    SECRET_STORE_AWS_ACCESS_KEY_ID: optionalString.describe(
      'AWS access key ID for Secrets Manager. Optional; falls back to the default credential provider chain.',
    ),
    SECRET_STORE_AWS_SECRET_ACCESS_KEY: optionalString.describe(
      'AWS secret access key for Secrets Manager. Optional; falls back to the default credential provider chain.',
    ),
    SECRET_STORE_AWS_SESSION_TOKEN: optionalString.describe(
      'AWS session token for Secrets Manager (temporary credentials). Optional.',
    ),
    SECRET_STORE_GCP_PROJECT_ID: optionalString.describe(
      'GCP project ID for Secret Manager. When unset, falls back to GCP_PROJECT_ID. ' +
      'Required (directly or via GCP_PROJECT_ID) when SECRET_STORE_PROVIDER=gcp-secretmanager.',
    ),
    SECRET_STORE_GCP_KEY_FILE_PATH: optionalString.describe(
      'Optional path to a GCP service account key file for Secret Manager. ' +
      'Falls back to Application Default Credentials (Workload Identity, GOOGLE_APPLICATION_CREDENTIALS) when unset.',
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

    // ── SecretStore provider cross-field validation ──────────────────────────
    if (cfg.SECRET_STORE_PROVIDER === 'azure-keyvault' && !cfg.SECRET_STORE_AZURE_VAULT_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SECRET_STORE_AZURE_VAULT_URL'],
        message: 'SECRET_STORE_AZURE_VAULT_URL is required when SECRET_STORE_PROVIDER=azure-keyvault.',
      });
    }
    if (
      cfg.SECRET_STORE_PROVIDER === 'azure-keyvault' &&
      cfg.SECRET_STORE_AZURE_CREDENTIAL_TYPE === 'client-secret' &&
      (!cfg.SECRET_STORE_AZURE_CLIENT_ID || !cfg.SECRET_STORE_AZURE_CLIENT_SECRET || !cfg.SECRET_STORE_AZURE_TENANT_ID)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SECRET_STORE_AZURE_CREDENTIAL_TYPE'],
        message:
          'SECRET_STORE_AZURE_CLIENT_ID, SECRET_STORE_AZURE_CLIENT_SECRET, and SECRET_STORE_AZURE_TENANT_ID ' +
          'are required when SECRET_STORE_AZURE_CREDENTIAL_TYPE=client-secret.',
      });
    }
    if (
      cfg.SECRET_STORE_PROVIDER === 'gcp-secretmanager' &&
      !cfg.SECRET_STORE_GCP_PROJECT_ID &&
      !cfg.GCP_PROJECT_ID
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SECRET_STORE_GCP_PROJECT_ID'],
        message:
          'SECRET_STORE_GCP_PROJECT_ID (or GCP_PROJECT_ID) is required when SECRET_STORE_PROVIDER=gcp-secretmanager.',
      });
    }

  });

export type IssuerConfig = z.infer<typeof IssuerConfigSchema>;

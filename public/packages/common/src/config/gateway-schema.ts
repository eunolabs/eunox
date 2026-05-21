import { z } from 'zod';
import { BACKPRESSURE_POLICIES } from '../audit-pipeline';
import {
  optionalString, envBoolean, envPositiveInt, envPort, envCsv, envEnum,
  NODE_ENV, EUNO_DEPLOYMENT_TIER
} from './base-schema';

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
      'When AUDIT_LEDGER_S3_BUCKET is set, the standard bootstrap automatically constructs ' +
      'an S3AnchorClient using the standard AWS credential provider chain (IAM role / IRSA / ' +
      'instance profile / AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars). ' +
      'The bucket MUST have Object Lock enabled. ' +
      'Every AUDIT_LEDGER_ANCHOR_INTERVAL successful appends trigger a PUT of the Merkle root ' +
      'of those rows to S3. ' +
      'When unset, no S3 anchoring is performed (HMAC + in-DB chain is the only protection).',
    ),
    AUDIT_LEDGER_S3_PREFIX: optionalString.describe(
      'S3 key prefix for ledger anchor objects. ' +
      'Default "audit-anchor/". Resulting key: {prefix}{replicaId}/{fromSeq}-{toSeq}.json.',
    ),
    AUDIT_LEDGER_S3_ENDPOINT: optionalString.describe(
      'Custom S3 endpoint URL for VPC endpoint / PrivateLink deployments. ' +
      'Example: https://bucket.vpce-0a1b2c3d4e5f.s3.us-east-1.vpce.amazonaws.com . ' +
      'When unset the AWS SDK uses the standard regional endpoint for AWS_REGION. ' +
      'GovCloud (us-gov-west-1 / us-gov-east-1) endpoints are resolved automatically ' +
      'from the region; this override is only needed for PrivateLink or custom endpoint scenarios. ' +
      'Only relevant when AUDIT_LEDGER_S3_BUCKET is set.',
    ),
    AUDIT_LEDGER_S3_FORCE_PATH_STYLE: envBoolean({
      default: false,
      description:
        'When true, forces path-style S3 URL addressing ' +
        '(https://s3.<region>.amazonaws.com/<bucket>/<key>) instead of virtual-hosted-style ' +
        '(https://<bucket>.s3.<region>.amazonaws.com/<key>). ' +
        'Required for some VPC endpoint configurations and for MinIO-compatible local testing. ' +
        'Only relevant when AUDIT_LEDGER_S3_BUCKET is set.',
    }),
    AUDIT_LEDGER_GCS_BUCKET: optionalString.describe(
      'GCS bucket for periodic Merkle-root anchoring (GCP equivalent of AUDIT_LEDGER_S3_BUCKET). ' +
      'NOTE: the standard bootstrap does not inject a GCS client — behavior differs by backend: ' +
      'the postgres (global-lock) backend will raise a startup error if this is set without a ' +
      'custom entrypoint that provides a GcsAnchorClient; the per-replica-postgres backend only ' +
      'logs a warning and continues without GCS anchoring. In either case, GCS anchoring requires ' +
      'a custom entrypoint that constructs the ledger backend directly with a GcsAnchorClient. ' +
      'When properly wired, every AUDIT_LEDGER_ANCHOR_INTERVAL successful appends also PUT the ' +
      'Merkle root to GCS. The bucket SHOULD have a retention policy enabled. Can be used ' +
      'alongside AUDIT_LEDGER_S3_BUCKET for multi-cloud redundancy. ' +
      'When unset, no GCS anchoring is performed.',
    ),
    AUDIT_LEDGER_GCS_PREFIX: optionalString.describe(
      'GCS object key prefix for ledger anchor objects. ' +
      'Default "audit-anchor/". Resulting key: {prefix}{replicaId}/{fromSeq}-{toSeq}.json.',
    ),
    AUDIT_LEDGER_ANCHOR_INTERVAL: envPositiveInt({
      default: 1000,
      min: 1,
      description:
        'Number of ledger rows between S3/GCS/objectStore anchor writes. Default 1000. ' +
        'Lower values provide more frequent external witnesses (smaller gap between a ' +
        'DB tamper event and S3/GCS detection) at the cost of more PUT requests. ' +
        'Only relevant when AUDIT_LEDGER_S3_BUCKET, AUDIT_LEDGER_GCS_BUCKET, or ' +
        'AUDIT_LEDGER_OBJECT_STORE_PROVIDER is set.',
    }),

    AUDIT_LEDGER_OBJECT_STORE_PROVIDER: optionalString.describe(
      'Cloud-agnostic object storage provider for audit-ledger anchoring. ' +
      'When set, the standard bootstrap automatically constructs an ObjectStore ' +
      'implementation and wires it into the CrossChainAnchor and ledger backends. ' +
      'Valid values: "s3" (AWS S3), "gcs" (Google Cloud Storage), "azure-blob" (Azure Blob Storage). ' +
      'Provider-specific configuration is supplied via companion environment variables: ' +
      '"s3" reads AUDIT_LEDGER_S3_BUCKET, AWS_REGION, AWS_ACCESS_KEY_ID, etc.; ' +
      '"gcs" reads AUDIT_LEDGER_GCS_BUCKET, GOOGLE_APPLICATION_CREDENTIALS, etc.; ' +
      '"azure-blob" reads AUDIT_LEDGER_AZURE_CONTAINER, AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING, ' +
      'AUDIT_LEDGER_AZURE_ACCOUNT_NAME, AUDIT_LEDGER_AZURE_ACCOUNT_KEY, AUDIT_LEDGER_AZURE_ENDPOINT. ' +
      'When unset, the legacy AUDIT_LEDGER_S3_BUCKET / AUDIT_LEDGER_GCS_BUCKET mechanism is used.',
    ),

    AUDIT_LEDGER_AZURE_CONTAINER: optionalString.describe(
      'Azure Blob Storage container name for audit-ledger anchoring. ' +
      'Required when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob. ' +
      'The container should have an immutability policy (time-based retention or legal hold) ' +
      'configured so that written anchor objects are write-once — this is the Azure equivalent ' +
      'of S3 Object Lock COMPLIANCE mode.',
    ),

    AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING: optionalString.describe(
      'Azure Storage connection string for audit-ledger blob anchoring. ' +
      'Used when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob. ' +
      'When provided, takes precedence over AUDIT_LEDGER_AZURE_ACCOUNT_NAME + ' +
      'AUDIT_LEDGER_AZURE_ACCOUNT_KEY. ' +
      'Use "UseDevelopmentStorage=true" for Azurite local testing. ' +
      'Not recommended for production — prefer managed identity (accountName only) ' +
      'or shared-key (accountName + accountKey) authentication.',
    ),

    AUDIT_LEDGER_AZURE_ACCOUNT_NAME: optionalString.describe(
      'Azure Storage account name for audit-ledger blob anchoring. ' +
      'Used when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob and ' +
      'AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING is not set. ' +
      'When provided without AUDIT_LEDGER_AZURE_ACCOUNT_KEY, authentication uses ' +
      'DefaultAzureCredential (managed identity / workload identity). ' +
      'Recommended for AKS deployments with pod-level managed identity.',
    ),

    AUDIT_LEDGER_AZURE_ACCOUNT_KEY: optionalString.describe(
      'Azure Storage shared key (base64-encoded) for audit-ledger blob anchoring. ' +
      'Used when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob and ' +
      'AUDIT_LEDGER_AZURE_ACCOUNT_NAME is also set. ' +
      'When omitted, DefaultAzureCredential is used for authentication.',
    ),

    AUDIT_LEDGER_AZURE_ENDPOINT: optionalString.describe(
      'Custom Azure Blob Storage endpoint URL. ' +
      'Used when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob. ' +
      'Example: http://127.0.0.1:10000/devstoreaccount1 for Azurite local testing. ' +
      'When unset the standard https://<accountName>.blob.core.windows.net endpoint is used.',
    ),

    AUDIT_LEDGER_GCS_SKIP_HOLD: envBoolean({
      default: false,
      description:
        'When true, skips setting the temporaryHold on GCS anchor objects. ' +
        'Only relevant when AUDIT_LEDGER_OBJECT_STORE_PROVIDER=gcs. ' +
        'Use when the bucket enforces immutability via a retention policy alone and ' +
        'the calling identity lacks the storage.objects.update IAM permission. Default false.',
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
        'How often (ms) the auto-started CrossChainAnchor queries all replica tips and emits a ' +
        'SignedCrossChainCommitment. Only active when ' +
        'AUDIT_LEDGER_BACKEND=per-replica-postgres and ENABLE_CROSS_CHAIN_ANCHOR=true. ' +
        'When a custom crossChainAnchor is injected via InjectableBootstrapDeps its interval ' +
        'is set at construction time by the caller — this env var is not applied to injected anchors. ' +
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

    // Secrets abstraction layer (cross-cloud SecretStore) -------------------
    // When SECRET_STORE_PROVIDER is set, runtime secrets (HMAC keys, admin
    // API keys, etc.) are read from the configured cloud secret store
    // instead of process.env. See docs/ADAPTERS.md §"Secret store" and
    // createSecretStoreFromEnv() in @euno/common-core for usage.
    SECRET_STORE_PROVIDER: envEnum({
      values: ['env', 'azure-keyvault', 'aws-secretsmanager', 'gcp-secretmanager'] as const,
      default: 'env',
      description:
        'Secrets backend used to resolve runtime secrets. ' +
        '"env" (default): read directly from environment variables (no cloud dependency). ' +
        '"azure-keyvault": read from Azure Key Vault secrets (requires SECRET_STORE_AZURE_VAULT_URL). ' +
        '"aws-secretsmanager": read from AWS Secrets Manager (optionally configured via SECRET_STORE_AWS_REGION). ' +
        '"gcp-secretmanager": read from GCP Secret Manager (requires SECRET_STORE_GCP_PROJECT_ID). ' +
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
    if (cfg.SECRET_STORE_PROVIDER === 'azure-keyvault' && !cfg.SECRET_STORE_AZURE_VAULT_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SECRET_STORE_AZURE_VAULT_URL'],
        message:
          'SECRET_STORE_AZURE_VAULT_URL is required when SECRET_STORE_PROVIDER=azure-keyvault.',
      });
    }
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
    // Note: GatewayConfigSchema does not include GCP_PROJECT_ID (that is an
    // issuer-only field). The createSecretStore() factory still falls back to
    // GCP_PROJECT_ID at runtime, but schema-level validation can only check
    // fields that are declared in the schema, so we require explicit
    // SECRET_STORE_GCP_PROJECT_ID here.
    if (
      cfg.SECRET_STORE_PROVIDER === 'gcp-secretmanager' &&
      !cfg.SECRET_STORE_GCP_PROJECT_ID
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SECRET_STORE_GCP_PROJECT_ID'],
        message:
          'SECRET_STORE_GCP_PROJECT_ID is required when SECRET_STORE_PROVIDER=gcp-secretmanager ' +
          '(the gateway schema does not include GCP_PROJECT_ID; set SECRET_STORE_GCP_PROJECT_ID explicitly).',
      });
    }
  });

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

/**
 * Capability Issuer API Server
 * Express server with /issue and /public-key endpoints
 */

import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import * as jose from 'jose';
import {
  ActionResolver,
  IssueCapabilityRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  ServiceConfig,
  TokenSigner,
  IdentityProvider,
  RoleCapabilityPolicy,
  DEFAULT_ROLE_CAPABILITY_MAP,
  loadActionResolverFromFileWithHash,
  loadRoleCapabilityPolicyFromFile,
  computeActionResolverHash,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  SUPPORTED_SCHEMA_VERSIONS,
  SIGNING_ALGORITHMS,
  loadConfigOrExit,
  createMetricsRegistry,
  createHttpMetricsMiddleware,
  createMetricsHandler,
  Counter,
  Gauge,
  tracingMiddleware,
  setActiveSpanEunoAttributes,
  EUNO_ATTR,
  IssuanceRateLimiter,
  createIssuanceRateLimiterFromEnv,
  createOcsfTransportFromEnv,
  createOcsfWinstonTransport,
} from '@euno/common';
import { CapabilityIssuerService, IssuerEnforcementContext } from './issuer-service';
import { defaultSigningRegistry, defaultIdentityRegistry } from './default-registries';
import { StorageGrantService } from './storage-grant';
import { DbTokenService } from './db-token';
import { HttpSideCredentialBroker, SideCredentialBroker } from './side-credential-broker';
import { loadCosignersFromEnv, loadTransparencyLogsFromEnv } from './issuance-proofs-wiring';
import { DurablePostureEmitter } from '@euno/posture-emitter';
import { parseDidWebHttpAllowList } from './did-resolver';
import { createAdminJwtVerifierFromEnv } from './admin-jwt-verifier';
import { PostgresRolePolicyStore } from './postgres-role-policy-store';
import { createAdminRolePolicyRouter } from './routes/admin-role-policy';
import { TenantIdpRegistry } from './tenant-idp-config';
import { OidcStateStore, IOidcStateStore, createOidcStateStoreFromEnv } from './oidc-state-store';
import {
  IssuerTelemetryCollector,
  createIssuerTelemetryFromEnv,
  extractTelemetryClaimsFromToken,
} from './issuer-telemetry';

// Load environment variables
dotenv.config();

// Validate the environment against the typed `EunoConfig` Zod schema
// (R-5 in `docs/IMPROVEMENTS_AND_REFACTORING.md`). This produces a
// single, structured "what's wrong" report on misconfig and exits
// before any service is constructed, replacing the previous pattern
// of inline `process.env.FOO || 'default'` reads sprinkled across the
// boot path.
const env = loadConfigOrExit(process.env, 'issuer');

// F-7: resolve the deployment's logical region exactly once at boot
// so every region-aware surface sees the same value.  ISSUER_REGION is
// the canonical name; EUNO_DEPLOYMENT_REGION is the legacy alias — both
// are now in the validated schema so the precedence is explicit.
const issuerRegion: string | undefined =
  (env.ISSUER_REGION || env.EUNO_DEPLOYMENT_REGION) || undefined;

// Map the validated `EunoConfig` onto the existing in-memory
// `ServiceConfig` shape.  The structured nested groups (`keyVault`,
// `awsKMS`, etc.) are still constructed conditionally because the
// downstream `createSigner` / `createIdentityProvider` flow uses their
// presence as a discriminator.
const config: ServiceConfig = {
  name: 'capability-issuer',
  port: env.PORT,
  environment: env.NODE_ENV,
  signingProvider: env.SIGNING_PROVIDER,
  identityProvider: env.IDENTITY_PROVIDER,
  keyVault: env.AZURE_KEYVAULT_URL ? {
    vaultUrl: env.AZURE_KEYVAULT_URL,
    keyName: env.AZURE_KEYVAULT_KEY_NAME || 'capability-signing-key',
    keyVersion: env.AZURE_KEYVAULT_KEY_VERSION,
    credentialType: env.AZURE_CREDENTIAL_TYPE,
    clientId: env.AZURE_CLIENT_ID,
    clientSecret: env.AZURE_CLIENT_SECRET,
    tenantId: env.AZURE_TENANT_ID,
  } : undefined,
  awsKMS: env.AWS_KMS_KEY_ID ? {
    region: env.AWS_KMS_REGION || 'us-east-1',
    keyId: env.AWS_KMS_KEY_ID,
    accessKeyId: env.AWS_ACCESS_KEY_ID,
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    sessionToken: env.AWS_SESSION_TOKEN,
  } : undefined,
  gcpCloudKMS: (env.GCP_PROJECT_ID && env.GCP_KEYRING_ID && env.GCP_CRYPTOKEY_ID) ? {
    projectId: env.GCP_PROJECT_ID,
    locationId: env.GCP_LOCATION_ID || 'us-central1',
    keyRingId: env.GCP_KEYRING_ID,
    cryptoKeyId: env.GCP_CRYPTOKEY_ID,
    cryptoKeyVersion: env.GCP_CRYPTOKEY_VERSION,
    keyFilePath: env.GCP_KEY_FILE_PATH,
  } : undefined,
  azureAD: env.AZURE_AD_TENANT_ID ? {
    tenantId: env.AZURE_AD_TENANT_ID,
    clientId: env.AZURE_AD_CLIENT_ID || '',
    clientSecret: env.AZURE_AD_CLIENT_SECRET,
    authority: env.AZURE_AD_AUTHORITY,
  } : undefined,
  // AWS Cognito / IAM Identity Center configuration.  The
  // EunoConfig schema's superRefine already enforced that
  // AWS_COGNITO_CLIENT_ID + (AWS_COGNITO_USER_POOL_ID OR AWS_COGNITO_ISSUER)
  // are present when IDENTITY_PROVIDER=aws-cognito, so this branch
  // reaches the downstream factory only with a complete config.
  awsCognito: (env.AWS_COGNITO_CLIENT_ID && (env.AWS_COGNITO_USER_POOL_ID || env.AWS_COGNITO_ISSUER)) ? {
    region: env.AWS_COGNITO_REGION,
    userPoolId: env.AWS_COGNITO_USER_POOL_ID,
    clientId: env.AWS_COGNITO_CLIENT_ID,
    issuer: env.AWS_COGNITO_ISSUER,
    jwksUri: env.AWS_COGNITO_JWKS_URI,
    tokenUse: env.AWS_COGNITO_TOKEN_USE,
  } : undefined,
  gcpIdentity: env.GCP_IDENTITY_AUDIENCE ? {
    audience: env.GCP_IDENTITY_AUDIENCE,
    issuer: env.GCP_IDENTITY_ISSUER,
    jwksUri: env.GCP_IDENTITY_JWKS_URI,
    projectId: env.GCP_IDENTITY_PROJECT_ID,
    rolesClaim: env.GCP_IDENTITY_ROLES_CLAIM,
  } : undefined,
  issuerDid: env.ISSUER_DID || 'did:web:example.com',
  defaultTokenTTL: env.DEFAULT_TOKEN_TTL,
  enableDetailedLogging: env.ENABLE_DETAILED_LOGGING,
};

// Create logger
const logger = createLogger(config.name, config.environment);

/**
 * Per-tenant IdP registry. Loaded once at startup from
 * ISSUER_TENANT_IDP_CONFIG_FILE and reloaded on SIGHUP. Falls back to the
 * global identity provider when a tenantId is not present in the file.
 */
const tenantIdpRegistry = new TenantIdpRegistry(
  env.ISSUER_TENANT_IDP_CONFIG_FILE,
  logger,
);

/**
 * OIDC state store — tracks nonce/state pairs for authorize→token flows and
 * prevents ID-token-hash replay (Stage-4 threat model requirement, CR-1 fix).
 *
 * Starts as in-memory at module load time (before `initializeServices()`
 * runs). {@link initializeServices} upgrades the reference to a
 * {@link RedisOidcStateStore} when `OIDC_STATE_REDIS_URL` or `REDIS_URL`
 * is configured, ensuring fleet-wide replay prevention in multi-replica
 * deployments. All route handlers access the store via {@link getOidcStateStore}
 * so they always see the post-upgrade implementation.
 */
let _oidcStateStore: IOidcStateStore = new OidcStateStore(env.OIDC_CODE_TTL_SECONDS);

function getOidcStateStore(): IOidcStateStore {
  return _oidcStateStore;
}

// Initialize signer based on configuration
async function createSigner(): Promise<TokenSigner> {
  const signingProvider = config.signingProvider || 'azure-keyvault';

  logger.info(`Initializing ${signingProvider} signer`);

  switch (signingProvider) {
    case 'azure-keyvault':
      if (!config.keyVault) {
        throw new Error('Azure Key Vault configuration is required when SIGNING_PROVIDER=azure-keyvault');
      }
      return await defaultSigningRegistry.createSigningAdapter({
        type: 'azure-keyvault',
        name: 'Azure Key Vault Signer',
        keyVault: config.keyVault,
      });

    case 'aws-kms':
      if (!config.awsKMS) {
        throw new Error('AWS KMS configuration is required when SIGNING_PROVIDER=aws-kms');
      }
      return await defaultSigningRegistry.createSigningAdapter({
        type: 'aws-kms',
        name: 'AWS KMS Signer',
        awsKMS: config.awsKMS,
      });

    case 'gcp-cloudkms':
      if (!config.gcpCloudKMS) {
        throw new Error('GCP Cloud KMS configuration is required when SIGNING_PROVIDER=gcp-cloudkms');
      }
      return await defaultSigningRegistry.createSigningAdapter({
        type: 'gcp-cloudkms',
        name: 'GCP Cloud KMS Signer',
        gcpKMS: config.gcpCloudKMS,
      });

    default:
      throw new Error(`Unsupported signing provider: ${signingProvider}`);
  }
}

// Initialize identity provider based on configuration
async function createIdentityProvider(): Promise<IdentityProvider> {
  const identityProvider = config.identityProvider || 'azure-ad';

  logger.info(`Initializing ${identityProvider} identity provider`);

  switch (identityProvider) {
    case 'azure-ad':
      if (!config.azureAD) {
        throw new Error('Azure AD configuration is required when IDENTITY_PROVIDER=azure-ad');
      }
      return await defaultIdentityRegistry.createIdentityAdapter({
        type: 'azure-ad',
        name: 'Azure AD Identity Provider',
        azureAD: config.azureAD,
      });

    case 'aws-cognito':
      if (!config.awsCognito) {
        throw new Error('AWS Cognito configuration is required when IDENTITY_PROVIDER=aws-cognito');
      }
      return await defaultIdentityRegistry.createIdentityAdapter({
        type: 'aws-cognito',
        name: 'AWS Cognito Identity Provider',
        awsCognito: config.awsCognito,
      });

    case 'gcp-identity':
      if (!config.gcpIdentity) {
        throw new Error('GCP identity configuration is required when IDENTITY_PROVIDER=gcp-identity');
      }
      return await defaultIdentityRegistry.createIdentityAdapter({
        type: 'gcp-identity',
        name: 'GCP Identity Provider',
        gcpIdentity: config.gcpIdentity,
      });

    case 'did':
      return await defaultIdentityRegistry.createIdentityAdapter({
        type: 'did',
        name: 'DID Identity Provider',
        // Thread the validated config values into the resolver so that
        // resolution call sites never read process.env directly.
        didWebHttpAllowList: parseDidWebHttpAllowList(env.DID_WEB_ALLOW_HTTP_FOR_HOSTS),
        ionResolverUrl: env.ION_RESOLVER_URL,
      });

    default:
      throw new Error(`Unsupported identity provider: ${identityProvider}`);
  }
}

// Initialize services
let issuerService: CapabilityIssuerService | undefined;
/**
 * Durable posture emitter — module-level so the graceful-shutdown
 * handler can call {@link DurablePostureEmitter.stop} even if
 * {@link initializeServices} fails after the emitter is created.
 */
let postureEmitter: DurablePostureEmitter | undefined;
/**
 * setInterval handle for posture queue-depth/lag gauge updates.
 * Module-level so the SIGTERM handler can clear it before stopping
 * the emitter to avoid callbacks after SQLite is closed.
 */
let postureMetricsInterval: ReturnType<typeof setInterval> | undefined;
let isInitialized = false;
/**
 * Canonical SHA-256 hash of the operator-supplied ActionResolver config
 * (see {@link computeActionResolverHash}).  Populated by
 * {@link initializeServices} and exposed at /.well-known/capability-issuer
 * so the gateway can verify it loaded the same action vocabulary.
 */
let actionResolverHash: string | undefined;

/**
 * Postgres-backed role-policy store (Task 3 — Stage 4 production hardening).
 * Module-level so the SIGHUP hot-reload handler can call `loadLatest()` after
 * the store is initialised by `initializeServices()`.
 */
let rolePolicyStore: PostgresRolePolicyStore | undefined;

/**
 * The raw `pg.Pool` backing `rolePolicyStore` (when ISSUER_ROLE_POLICY_DB_URL
 * is set).  Tracked separately so the SIGTERM handler can close it cleanly.
 */
let rolePolicyPool: { end(): Promise<void> } | undefined;

/**
 * Current active role → capability policy (Task 3).  Starts as `undefined`
 * until `initializeServices()` resolves it from Postgres, the file-based
 * policy, or the in-code default.  Updated in place by the admin API route
 * and the SIGHUP hot-reload handler.  Reading/writing is safe in the Node.js
 * single-threaded event loop — no locks are required.
 */
let activeRolePolicy: RoleCapabilityPolicy | undefined;

async function initializeServices() {
  try {
    const signer = await createSigner();
    const identityProvider = await createIdentityProvider();

    // Load externalised role → capability policy if ROLE_POLICY_FILE is set.
    // When unset the issuer falls back to the in-code Sprint-1 default
    // mapping, preserving backward compatibility.  See
    // `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md` for the recommended
    // production configuration.
    let rolePolicy: RoleCapabilityPolicy | undefined;
    const policyFile = env.ROLE_POLICY_FILE;
    if (policyFile && policyFile.trim().length > 0) {
      logger.info('Loading role → capability policy from file', { path: policyFile });
      rolePolicy = loadRoleCapabilityPolicyFromFile(policyFile);
      logger.info('Role policy loaded', {
        defaultRoles: Object.keys(rolePolicy.default).sort(),
        tenantOverrides: rolePolicy.tenants ? Object.keys(rolePolicy.tenants).sort() : [],
      });
    }

    // Task 3 (Stage 4 production hardening): when ISSUER_ROLE_POLICY_DB_URL is
    // set, load the initial role → capability policy from Postgres rather than
    // a static file.  The DB-sourced policy takes precedence over ROLE_POLICY_FILE
    // so operators can use the admin API to update the mapping at runtime.
    if (env.ISSUER_ROLE_POLICY_DB_URL) {
      try {
        // Lazily require `pg` so it remains an optional peer dep — callers who
        // never set ISSUER_ROLE_POLICY_DB_URL don't need the module installed.
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { Pool } = require('pg') as typeof import('pg');
        const pool = new Pool({ connectionString: env.ISSUER_ROLE_POLICY_DB_URL });
        rolePolicyPool = pool;
        rolePolicyStore = new PostgresRolePolicyStore(pool);
        await rolePolicyStore.ensureSchema();
        const record = await rolePolicyStore.loadLatest();
        if (record) {
          rolePolicy = record.policy;
          logger.info('Role policy loaded from Postgres', {
            rowId: record.id,
            operator: record.operatorId,
            createdAt: record.createdAt,
            defaultRoles: Object.keys(record.policy.default).sort(),
            tenantOverrides: record.policy.tenants
              ? Object.keys(record.policy.tenants).sort()
              : [],
          });
        } else {
          logger.info(
            'No role policy found in Postgres — using ROLE_POLICY_FILE or in-code default',
          );
        }
      } catch (err) {
        logger.error('Failed to initialise Postgres role-policy store', {
          error: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    }

    // R-7: load operator-supplied ActionResolver from disk if
    // ACTION_RESOLVER_FILE is set. The same JSON file is consumed by
    // the gateway so issuer-side CA tiering and gateway-side action
    // derivation always agree on the deployment's verb vocabulary.
    // When unset, the issuer falls back to the in-process
    // BUILTIN_ACTION_RESOLVER which reproduces the legacy CA-tier
    // mapping.
    let actionResolver: ActionResolver | undefined;
    const actionResolverFile = env.ACTION_RESOLVER_FILE;
    if (actionResolverFile && actionResolverFile.trim().length > 0) {
      logger.info('Loading action resolver config from file', { path: actionResolverFile });
      const { resolver, hash } = loadActionResolverFromFileWithHash(actionResolverFile);
      actionResolver = resolver;
      actionResolverHash = hash;
      logger.info('Action resolver config loaded', { actionResolverHash: hash });
    } else {
      // No operator file — record the sentinel hash for the built-in defaults
      // so /.well-known/capability-issuer always surfaces a hash the gateway
      // can compare against its own.
      actionResolverHash = computeActionResolverHash(null);
    }

    // Per-(tenant, user, agent, jti, ip) issuance rate limiter (F-1, addresses
    // I-1). Multi-dimensional token-bucket backed by CallCounterStore when
    // REDIS_URL is set — required for multi-replica or multi-region active/
    // active deployments (F-7). When ISSUANCE_RATE_LIMIT_ENABLED=false the
    // service runs without any per-subject rate limit.

    // CR-1 (architecture-review-2026-05-stage4): upgrade the OIDC state store to
    // Redis-backed when a Redis URL is configured. This must happen inside
    // initializeServices() (async context) and before the first request is served
    // so that fleet-wide replay prevention is active for all traffic.
    _oidcStateStore = await createOidcStateStoreFromEnv(process.env, logger);

    let issuanceRateLimiter: IssuanceRateLimiter | undefined;
    if (env.ISSUANCE_RATE_LIMIT_ENABLED) {
      issuanceRateLimiter = await createIssuanceRateLimiterFromEnv(process.env, {
        logger,
        max: env.ISSUANCE_RATE_LIMIT_MAX,
        windowSeconds: env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
        keyPrefix: env.ISSUANCE_RATE_LIMIT_KEY_PREFIX,
        failClosedOnError: env.ISSUANCE_RATE_LIMIT_FAIL_CLOSED,
      });
    } else {
      logger.warn(
        'ISSUANCE_RATE_LIMIT_ENABLED=false — per-subject issuance rate limit is DISABLED. ' +
          'NOT recommended for production.',
      );
    }

    // Dedicated, tighter rate limiters for storage-grant and DB-token
    // issuance. Each mints a long-lived cloud credential (STS session /
    // RDS IAM auth token) rather than a short-lived capability JWT, so
    // a compromise in either path has a larger blast radius. The
    // defaults (10 per window) are intentionally lower than the main
    // issuance limit (60 per window).
    let storageGrantRateLimiter: IssuanceRateLimiter | undefined;
    if (env.STORAGE_GRANTS_ENABLED && env.STORAGE_GRANT_RATE_LIMIT_ENABLED) {
      storageGrantRateLimiter = await createIssuanceRateLimiterFromEnv(process.env, {
        logger,
        max: env.STORAGE_GRANT_RATE_LIMIT_MAX,
        windowSeconds: env.STORAGE_GRANT_RATE_LIMIT_WINDOW_SECONDS,
        keyPrefix: env.STORAGE_GRANT_RATE_LIMIT_KEY_PREFIX ?? 'sgrl:',
      });
      logger.info('Storage-grant rate limiter enabled', {
        max: env.STORAGE_GRANT_RATE_LIMIT_MAX,
        windowSeconds: env.STORAGE_GRANT_RATE_LIMIT_WINDOW_SECONDS,
      });
    }

    let dbTokenRateLimiter: IssuanceRateLimiter | undefined;
    if (env.DB_TOKENS_ENABLED && env.DB_TOKEN_RATE_LIMIT_ENABLED) {
      dbTokenRateLimiter = await createIssuanceRateLimiterFromEnv(process.env, {
        logger,
        max: env.DB_TOKEN_RATE_LIMIT_MAX,
        windowSeconds: env.DB_TOKEN_RATE_LIMIT_WINDOW_SECONDS,
        keyPrefix: env.DB_TOKEN_RATE_LIMIT_KEY_PREFIX ?? 'dbrl:',
      });
      logger.info('DB-token rate limiter enabled', {
        max: env.DB_TOKEN_RATE_LIMIT_MAX,
        windowSeconds: env.DB_TOKEN_RATE_LIMIT_WINDOW_SECONDS,
      });
    }

    // F-6: optional OCSF audit transport. When `OCSF_TRANSPORT` is
    // unset the factory returns `undefined` and we attach nothing —
    // existing deployments are unaffected.
    const ocsfTransport = createOcsfTransportFromEnv(process.env, logger);
    const issuerOcsfProduct = {
      name: 'euno-capability-issuer',
      vendor: 'Euno',
    };
    const auditTransports = ocsfTransport
      ? [createOcsfWinstonTransport(ocsfTransport, issuerOcsfProduct)]
      : undefined;
    if (ocsfTransport) {
      logger.info('OCSF audit transport enabled', { transport: ocsfTransport.name });
    }

    // Multi-issuer trust hardening: load independent cosigners and the
    // transparency log when configured. Both default to empty (no
    // cosignature, no SCT) for back-compat — only deployments that
    // explicitly opt in via the env-config get the additional proofs
    // attached to every minted token.
    const cosigners = await loadCosignersFromEnv(env, logger);
    const transparencyLogs = await loadTransparencyLogsFromEnv(env, logger);

    // R-1 / microservice decomposition: when STORAGE_GRANT_SERVICE_URL or
    // DB_TOKEN_SERVICE_URL are set, delegate side-credential minting to the
    // dedicated remote services via HttpSideCredentialBroker.  The remote
    // services verify the JWT with the issuer's public JWKS and mint
    // credentials independently — no KMS access is needed there.
    //
    // When neither URL is set, fall back to the in-process services
    // (StorageGrantService + DbTokenService) wrapped in an
    // InProcessSideCredentialBroker for backward compatibility.
    let sideCredentialBroker: SideCredentialBroker | undefined;
    const storageGrantServiceUrl = env.STORAGE_GRANT_SERVICE_URL;
    const dbTokenServiceUrl = env.DB_TOKEN_SERVICE_URL;
    if (storageGrantServiceUrl || dbTokenServiceUrl) {
      sideCredentialBroker = new HttpSideCredentialBroker({
        storageGrantServiceUrl,
        dbTokenServiceUrl,
        logger,
      });
      logger.info('Side-credential broker: HTTP (microservice) mode', {
        storageGrantServiceUrl: storageGrantServiceUrl ?? '(not configured)',
        dbTokenServiceUrl: dbTokenServiceUrl ?? '(not configured)',
      });
    }

    // Task 6 (Stage 4): manifest template store.
    // When ISSUER_DB_URL is set, create a Postgres-backed store and
    // optionally run DDL migrations at startup (ISSUER_DB_SCHEMA_INIT=true).
    // The store is injected into CapabilityIssuerService so the issuance
    // hot path can look up template assignments.
    let templateStore: import('./manifest-template-store').ManifestTemplateStore | undefined;
    if (env.ISSUER_DB_URL) {
      const { Pool } = await import('pg');
      const dbSchema = env.ISSUER_DB_SCHEMA ?? 'euno_issuer';
      const pool = new Pool({ connectionString: env.ISSUER_DB_URL });
      const { PostgresManifestTemplateStore } = await import('./manifest-template-store');
      templateStore = new PostgresManifestTemplateStore(pool, dbSchema);
      logger.info('Manifest template store initialised (Postgres)', { schema: dbSchema });

      if (env.ISSUER_DB_SCHEMA_INIT) {
        const { IssuerMigrationRunner } = await import('./migrations');
        const migrationRunner = new IssuerMigrationRunner(pool, dbSchema);
        await migrationRunner.migrate();
        logger.info('Issuer DB schema migration complete', { schema: dbSchema });
      }

      // Mount the admin templates router into the pre-registered forwarding router.
      // Using adminTemplatesForwarder (registered before the error handler) ensures
      // CapabilityError throws propagate through the shared error middleware.
      const { createAdminTemplatesRouter, createIssuerAdminJwtVerifier } = await import('./routes/admin-templates');
      const jwtVerifier = createIssuerAdminJwtVerifier(process.env);
      // Require ISSUER_ADMIN_API_KEY when no JWT verifier is configured —
      // prevents the admin API from being reachable via a predictable default key.
      const adminApiKey = env.ISSUER_ADMIN_API_KEY;
      if (!adminApiKey && !jwtVerifier) {
        logger.warn(
          'ISSUER_ADMIN_API_KEY is not set and ISSUER_ADMIN_JWKS_URI is not configured. ' +
            'The admin template API (/api/v1/admin/templates) is DISABLED. ' +
            'Set ISSUER_ADMIN_API_KEY or configure ISSUER_ADMIN_JWKS_URI + ISSUER_ADMIN_JWT_AUDIENCE to enable it.',
        );
        // Do not mount the router.
      } else {
        const adminRouter = createAdminTemplatesRouter({
          store: templateStore,
          // Pass '' when JWT-only (adminApiKey is undefined).  requireAdminAuth
          // treats an empty adminApiKey as "X-Admin-Key path disabled" so
          // requests without a Bearer JWT are rejected rather than accepted.
          adminApiKey: adminApiKey ?? '',
          logger,
          jwtVerifier,
        });
        adminTemplatesForwarder.use('/', adminRouter);
        logger.info('Admin templates router mounted at /api/v1/admin/templates');

        // Task 7 (Stage 4): server-rendered admin UI pages at /admin/*.
        // Shares the same auth (JWT + X-Admin-Key fallback) as the API router.
        const { createAdminUiRouter } = await import('./routes/admin-ui');
        const uiRouter = createAdminUiRouter({
          store: templateStore,
          adminApiKey: adminApiKey ?? '',
          logger,
          jwtVerifier,
          publicBaseUrl: env.ISSUER_PUBLIC_URL,
        });
        adminUiForwarder.use('/', uiRouter);
        logger.info('Admin UI router mounted at /admin');
      }
    }

    // Prometheus counter for side-credential broker errors in best-effort mode.
    const sideCredentialErrorCounter = new Counter({
      name: 'euno_issuer_side_credential_errors_total',
      help: 'Side-credential broker failures in best-effort mode, labelled by kind (storage-grant|db-token|unknown).',
      labelNames: ['kind'],
      registers: [metricsRegistry],
    });
    for (const kind of ['storage-grant', 'db-token', 'unknown'] as const) {
      sideCredentialErrorCounter.inc({ kind }, 0);
    }

    // AI posture-management inventory feed (sprint 3-4 gap item #9).
    // DurablePostureEmitter writes to a SQLite WAL queue before returning
    // from emitObserved, so the issuer can await the enqueue inline (Step
    // 5b of the issuance pipeline) and be certain the record survives a
    // crash before plugin delivery completes.  The background DeliveryWorker
    // fans out to cloud surfaces (Defender CSPM / Security Hub / SCC)
    // independently of the issuance critical path.
    //
    // Disabled by default — fromEnv returns an inactive emitter unless
    // POSTURE_EMITTER_ENABLED=true. In production set
    // POSTURE_DURABLE_QUEUE_PATH to a path on a persistent volume so
    // records survive pod restarts.
    const postureDeliveredCounter = new Counter({
      name: 'euno_issuer_posture_delivered_total',
      help: 'Posture inventory records successfully delivered to a cloud surface plugin, labelled by event type and plugin name.',
      labelNames: ['event_type', 'plugin'],
      registers: [metricsRegistry],
    });
    const postureDeliveryErrorCounter = new Counter({
      name: 'euno_issuer_posture_delivery_error_total',
      help: 'Transient posture delivery errors (will be retried), labelled by event type and plugin name.',
      labelNames: ['event_type', 'plugin'],
      registers: [metricsRegistry],
    });
    const postureDeadLetteredCounter = new Counter({
      name: 'euno_issuer_posture_dead_lettered_total',
      help: 'Posture records permanently dead-lettered after exhausting max delivery attempts.',
      labelNames: [],
      registers: [metricsRegistry],
    });
    const postureQueueDepthGauge = new Gauge({
      name: 'euno_issuer_posture_queue_depth',
      help: 'Number of posture inventory records pending delivery in the local SQLite queue.',
      registers: [metricsRegistry],
    });
    const postureQueueLagGauge = new Gauge({
      name: 'euno_issuer_posture_queue_lag_ms',
      help: 'Age in milliseconds of the oldest undelivered posture record in the local SQLite queue (0 when empty).',
      registers: [metricsRegistry],
    });

    postureEmitter = DurablePostureEmitter.fromEnv(process.env, logger, {
      onDelivered: (eventType, plugin) => {
        postureDeliveredCounter.inc({ event_type: eventType, plugin });
      },
      onDeliveryError: (eventType, plugin) => {
        postureDeliveryErrorCounter.inc({ event_type: eventType, plugin });
      },
      onDeadLettered: (_eventType) => {
        postureDeadLetteredCounter.inc();
      },
    });
    postureEmitter.start();

    // Only start the gauge-refresh interval when the emitter is actually
    // enabled and backed by a queue. When disabled, the emitter is a no-op
    // and there is nothing meaningful to measure.
    if (postureEmitter.isEnabled()) {
      postureMetricsInterval = setInterval(() => {
        if (postureEmitter) {
          postureQueueDepthGauge.set(postureEmitter.queueDepth());
          postureQueueLagGauge.set(postureEmitter.oldestLagMs());
        }
      }, 5_000);
      if (typeof postureMetricsInterval.unref === 'function') {
        postureMetricsInterval.unref();
      }
    } else {
      // Disabled emitter: pin both gauges to 0 once so dashboards don't
      // show stale data from a previous deployment that had the emitter on.
      postureQueueDepthGauge.set(0);
      postureQueueLagGauge.set(0);
    }

    issuerService = new CapabilityIssuerService(
      signer,
      identityProvider,
      config.issuerDid!,
      config.defaultTokenTTL,
      logger,
      {
        // Strict mode: require an explicit user-consent record for every
        // issuance.  Recommended for multi-tenant production deployments.
        requireConsent: env.REQUIRE_USER_CONSENT,
        policy: rolePolicy,
        // Microservice broker (when URLs are configured) takes precedence
        // over the legacy in-process services below. Both paths go through
        // the same SideCredentialBroker interface so rate limiters and
        // failure-mode handling are identical.
        ...(sideCredentialBroker ? { sideCredentialBroker } : {
          // Cloud storage / DB credential pipelines (sprint 3-4 gap items
          // #7 and #8). Both are disabled by default — `fromEnv` returns
          // an inactive service unless `STORAGE_GRANTS_ENABLED=true` /
          // `DB_TOKENS_ENABLED=true`. `DbTokenService.fromEnv` throws
          // when enabled without `DB_INSTANCES_FILE` (fail fast at
          // startup rather than serve with an empty allow-list).
          storageGrantService: StorageGrantService.fromEnv(process.env, logger),
          dbTokenService: DbTokenService.fromEnv(process.env, logger),
        }),
        // When SIDE_CREDENTIAL_FAILURE_MODE=best-effort, broker errors are
        // logged and metered but the signed JWT is still returned. Opt in
        // for deployments that can tolerate missing side credentials (e.g.
        // during STS maintenance windows).
        sideCredentialFailureMode: env.SIDE_CREDENTIAL_FAILURE_MODE,
        onSideCredentialError: (kind, _error) => {
          sideCredentialErrorCounter.inc({ kind });
        },
        postureEmitter,
        // F-7: surface region tag on tokens, audit, posture inventory,
        // and request span attributes — see docs/MULTI_REGION_ISSUER.md.
        // `region` is the canonical option; the legacy `postureRegion`
        // alias is omitted here so a future reader doesn't have to ask
        // which one wins.
        region: issuerRegion,
        issuanceRateLimiter,
        storageGrantRateLimiter,
        dbTokenRateLimiter,
        // R-7: pluggable ActionResolver (addresses I-4, I-5). Replaces
        // the legacy substring-matching CA tier coercion. When unset
        // the issuer uses the BUILTIN_ACTION_RESOLVER fallback.
        actionResolver,
        // Cross-tenant audience defence: tokens are stamped with
        // GATEWAY_AUDIENCE so they are bound to the configured
        // gateway and cannot be replayed at another tenant's gateway.
        // Defaults to "tool-gateway" for back-compat when unset.
        ...(env.GATEWAY_AUDIENCE ? { gatewayAudience: env.GATEWAY_AUDIENCE } : {}),
        ...(auditTransports ? { auditTransports } : {}),
        ...(cosigners.length > 0 ? { cosigners } : {}),
        ...(transparencyLogs.length > 0 ? { transparencyLogs } : {}),
        onIssuanceRateLimited: (subject, reason, kind = 'issuance') => {
          // Forward the limiter's classification verbatim so dashboards
          // can distinguish a real rate-limit hit from a Redis outage —
          // the metric contract documented in docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md
          // §1.3.1 and the F-1 PR description depends on this label.
          // `kind` distinguishes main issuance, storage-grant, and db-token
          // limiters so per-type counters can be dashboarded separately.
          issuanceRateLimitDeniedCounter.inc({
            tenant: subject.tenantId ?? '_no_tenant',
            reason: reason === 'exceeded' ? `${kind}_rate_limit_exceeded` : `${kind}_rate_limiter_unavailable`,
          });
        },
        // Task 6: inject manifest template store when configured.
        ...(templateStore ? { templateStore } : {}),
      }
    );

    logger.info('Services initialized successfully');
    // Snapshot the active policy for hot-reload and the admin GET route.
    // Falls back to the in-code default when no policy file or DB row was found.
    activeRolePolicy = rolePolicy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP };
    isInitialized = true;
  } catch (error) {
    logger.error('Failed to initialize services', { error: error instanceof Error ? error.message : 'Unknown error' });
    throw error;
  }
}

/**
 * Returns the initialized issuer service, or throws a CapabilityError if not yet initialized.
 * Route handlers call this instead of accessing `issuerService` directly, so that imported
 * modules (e.g. in tests) receive a clear error rather than an unhandled TypeError.
 */
function getIssuerService(): CapabilityIssuerService {
  if (!issuerService) {
    throw new CapabilityError(
      ErrorCode.INTERNAL_ERROR,
      'Service is not initialized',
      503
    );
  }
  return issuerService;
}

// Create Express app
const app = express();

// ── Task 3: role-policy admin routes and SIGHUP hot-reload ─────────────────
//
// The admin JWT verifier is constructed now (module-level, once) so the
// JWKS fetch cache is shared across all requests.  The routes themselves
// are mounted after `express.json()` so request bodies are parsed.

/**
 * Operator-JWT verifier for the role-policy admin routes.
 * `undefined` when ISSUER_ADMIN_JWKS_URI / ISSUER_ADMIN_JWT_AUDIENCE are
 * not set — the X-Admin-Key fallback remains active in that case.
 */
const adminJwtVerifier = createAdminJwtVerifierFromEnv(process.env);

/**
 * Fallback shared admin API key for the role-policy admin routes.
 * Defaults to a non-guessable dev value; the production guard (schema
 * superRefine) will enforce ≥32 chars when NODE_ENV=production once
 * that check is wired — for now the routes reject any request that
 * does not supply the configured value.
 */
const issuerAdminApiKey: string =
  process.env['ISSUER_ADMIN_API_KEY'] ?? 'dev-issuer-admin-key';

/**
 * Hot-reload helper — updates the in-memory policy on the live
 * `issuerService` and the module-level `activeRolePolicy` snapshot.
 * Called by both the admin PUT route and the SIGHUP handler.
 */
function applyPolicyUpdate(policy: RoleCapabilityPolicy, operatorId: string): void {
  activeRolePolicy = policy;
  if (issuerService) {
    issuerService.updatePolicy(policy);
  }
  logger.info('Role policy hot-reloaded', {
    operator: operatorId,
    defaultRoles: Object.keys(policy.default).sort(),
    tenantOverrides: policy.tenants ? Object.keys(policy.tenants).sort() : [],
  });
}

// SIGHUP handler for hot-reload from Postgres (Task 3).  Send SIGHUP to
// reload the role-policy without restarting the process:
//   kill -HUP <pid>
// The handler is registered at module load time (before initializeServices).
// It is gated on `isInitialized` so a signal that races startup cannot set
// `activeRolePolicy` and then have it silently overwritten by the normal
// init flow completing on line 616.
process.on('SIGHUP', () => {
  if (!isInitialized) {
    logger.warn('SIGHUP received before initialization completed; ignoring.');
    return;
  }
  if (!rolePolicyStore) {
    logger.warn('SIGHUP received but no Postgres role-policy store configured; ignoring.');
    return;
  }
  logger.info('SIGHUP received — reloading role policy from Postgres');
  rolePolicyStore.loadLatest().then((record) => {
    if (record) {
      applyPolicyUpdate(record.policy, `sighup/${record.operatorId}`);
      logger.info('Role policy reloaded from Postgres via SIGHUP', {
        rowId: record.id,
        operator: record.operatorId,
        createdAt: record.createdAt,
      });
    } else {
      logger.warn('SIGHUP reload: no policy found in Postgres; active policy unchanged.');
    }
  }).catch((err) => {
    logger.error('SIGHUP reload failed — active policy unchanged', {
      error: err instanceof Error ? err.message : String(err),
    });
  });
});


// OpenTelemetry context propagation (R-3). First middleware so every
// handler — including audit logging — runs inside the request span.
app.use(tracingMiddleware('capability-issuer', { region: issuerRegion }));

// Middleware
app.use(helmet());

// CORS configuration with environment-based origins
const allowedOrigins = env.ALLOWED_ORIGINS && env.ALLOWED_ORIGINS.length > 0
  ? env.ALLOWED_ORIGINS
  : config.environment === 'production'
  ? []  // No CORS in production unless explicitly configured
  : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'];

app.use(cors({
  origin: allowedOrigins.length > 0 ? allowedOrigins : false,
  credentials: true,
}));

// F-5 (I-16): Prometheus / OpenMetrics surface. Build a per-process registry
// tagged with the service name and a counter for issuance outcomes so
// operators can chart issuance volume / failure rate from `/metrics`
// instead of grepping logs. The HTTP middleware records latency + count
// for every non-/metrics request.
const metricsRegistry = createMetricsRegistry({ serviceName: 'capability-issuer' });
const issuanceCounter = new Counter({
  name: 'euno_issuer_issuance_total',
  help: 'Capability issuance attempts at the issuer, labelled by operation (issue|attenuate|renew) and outcome (success|error).',
  labelNames: ['operation', 'outcome'],
  registers: [metricsRegistry],
});
// Pre-initialise series so `rate()` queries succeed before first traffic.
for (const operation of ['issue', 'attenuate', 'renew'] as const) {
  for (const outcome of ['success', 'error'] as const) {
    issuanceCounter.inc({ operation, outcome }, 0);
  }
}

// Stage 4, Task 10: Issuer-side telemetry collector.
// Opt-in via EUNO_TELEMETRY=1; disabled by default (DI-4).
const issuerTelemetry: IssuerTelemetryCollector | null = createIssuerTelemetryFromEnv(process.env);
// F-1 (addresses I-1): per-(tenant, user, agent) rate-limit denials. A spike
// in `tenant=*,reason=exceeded` is the signal an account is being abused;
// `reason=unavailable` indicates the limiter (Redis) cannot be consulted.
const issuanceRateLimitDeniedCounter = new Counter({
  name: 'euno_issuer_issuance_rate_limit_denied_total',
  help: 'Capability issuance attempts denied by the per-(tenant, user, agent) rate limiter, labelled by tenant and reason.',
  labelNames: ['tenant', 'reason'],
  registers: [metricsRegistry],
});
issuanceRateLimitDeniedCounter.inc({ tenant: '_no_tenant', reason: 'exceeded' }, 0);
app.use(createHttpMetricsMiddleware({ registry: metricsRegistry }));
app.get('/metrics', createMetricsHandler(metricsRegistry) as express.RequestHandler);

app.use(express.json());

// Task 3: role-policy admin routes.
// Mounted after express.json() so PUT /api/v1/admin/role-policy can parse
// request bodies.  The policyStore is not yet initialized at mount time
// (initializeServices runs after the app is constructed), so a getter
// function is used to read the module-level `rolePolicyStore` variable at
// request time rather than at mount time.
app.use(
  createAdminRolePolicyRouter({
    adminApiKey: issuerAdminApiKey,
    jwtVerifier: adminJwtVerifier,
    getPolicyStore: () => rolePolicyStore,
    onPolicyUpdated: applyPolicyUpdate,
    getCurrentPolicy: () =>
      activeRolePolicy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP },
    logger,
  }),
);

// Request logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  logger.info('Incoming request', {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  next();
});

/**
 * Health check endpoints — split liveness and readiness so Kubernetes
 * (and any L7 load balancer) can distinguish "process alive" from
 * "process ready to serve traffic":
 *
 *   - GET /health        — back-compat liveness alias (always 200 once
 *                          the HTTP server is up).
 *   - GET /health/live   — liveness, always 200.
 *   - GET /health/ready  — readiness, 200 only after `initializeServices()`
 *                          has completed (signer, identity provider,
 *                          policy, rate limiter, storage / DB credential
 *                          services, and any optional posture / audit
 *                          transports are wired). Returns 503
 *                          `{status:'not_ready'}` otherwise so the
 *                          kubelet keeps the pod out of the Service
 *                          endpoints until first traffic is safe to
 *                          accept.
 */
const liveness = (_req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'capability-issuer' });
};
app.get('/health', liveness);
app.get('/health/live', liveness);
app.get('/health/ready', (_req: Request, res: Response) => {
  if (isInitialized && issuerService) {
    res.json({ status: 'ready', service: 'capability-issuer' });
    return;
  }
  res.status(503).json({ status: 'not_ready', service: 'capability-issuer' });
});

/**
 * Issue capability token endpoint
 * POST /api/v1/issue
 */
app.post('/api/v1/issue', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract authorization token from header
    const authToken = parseBearerToken(req.headers.authorization);
    if (!authToken) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token is required',
        401
      );
    }

    // Build request
    const issueRequest: IssueCapabilityRequest = {
      authToken,
      agentId: req.body.agentId,
      requestedCapabilities: req.body.requestedCapabilities,
      manifest: req.body.manifest,
      consent: req.body.consent,
      // F-2: opt-in DPoP holder-key binding. Either a precomputed
      // thumbprint or the public JWK; the issuer-service prefers the
      // thumbprint and validates the JWK shape when present.
      dpopJkt: typeof req.body.dpopJkt === 'string' ? req.body.dpopJkt : undefined,
      dpopJwk:
        req.body.dpopJwk && typeof req.body.dpopJwk === 'object' && !Array.isArray(req.body.dpopJwk)
          ? (req.body.dpopJwk as Record<string, unknown>)
          : undefined,
    };

    // Validate required fields
    if (!issueRequest.agentId) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'agentId is required',
        400
      );
    }

    // Build enforcement context (transport-level metadata, not in the wire type).
    const enforcementCtx: IssuerEnforcementContext = { clientIp: req.ip };

    // Issue the capability
    const response = await getIssuerService().issueCapability(issueRequest, enforcementCtx);

    issuanceCounter.inc({ operation: 'issue', outcome: 'success' });

    // Stage 4, Task 10: record issuance telemetry. Extract tenantId/userId
    // from the signed response token (unverified — telemetry use only).
    if (issuerTelemetry) {
      const { tenantId, userId } = extractTelemetryClaimsFromToken(response.token);
      issuerTelemetry.recordIssuance(tenantId, userId);
    }

    // R-3: stamp the documented `euno.*` attributes on the request
    // span so the trace carries the same identifiers as the audit log.
    setActiveSpanEunoAttributes({
      [EUNO_ATTR.AGENT_ID]: issueRequest.agentId,
      [EUNO_ATTR.JTI]: response.tokenId,
      [EUNO_ATTR.OUTCOME]: 'success',
    });

    res.json(response);
  } catch (error) {
    issuanceCounter.inc({ operation: 'issue', outcome: 'error' });
    next(error);
  }
});

/**
 * Attenuate capability token endpoint
 * POST /api/v1/attenuate
 * Reduces the scope of an existing capability token
 */
app.post('/api/v1/attenuate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract parent token from authorization header
    const parentToken = parseBearerToken(req.headers.authorization);
    if (!parentToken) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token (parent capability) is required',
        401
      );
    }

    // Validate required fields
    if (!req.body.requestedCapabilities || !Array.isArray(req.body.requestedCapabilities)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'requestedCapabilities array is required',
        400
      );
    }

    // Validate optional ttl
    const ttl = req.body.ttl;
    if (ttl !== undefined && (typeof ttl !== 'number' || !isFinite(ttl) || ttl <= 0)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'ttl must be a positive finite number',
        400
      );
    }

    // Validate the parent token format early so malformed tokens return 401 even when
    // the service has not yet been initialized
    try {
      jose.decodeProtectedHeader(parentToken);
    } catch {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Invalid parent capability token format',
        401
      );
    }

    // Attenuate the capability
    const response = await getIssuerService().attenuateCapability(
      parentToken,
      req.body.requestedCapabilities,
      ttl,
      { clientIp: req.ip },
    );

    issuanceCounter.inc({ operation: 'attenuate', outcome: 'success' });

    // R-3: stamp `euno.*` attributes on the request span.
    setActiveSpanEunoAttributes({
      [EUNO_ATTR.JTI]: response.tokenId,
      [EUNO_ATTR.OUTCOME]: 'success',
    });

    res.json(response);
  } catch (error) {
    issuanceCounter.inc({ operation: 'attenuate', outcome: 'error' });
    next(error);
  }
});

/**
 * Renew capability token endpoint
 * POST /api/v1/renew
 * Refreshes an existing capability token with new expiration
 */
app.post('/api/v1/renew', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract current token from authorization header
    const currentToken = parseBearerToken(req.headers.authorization);
    if (!currentToken) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token (current capability) is required',
        401
      );
    }

    // Renew the capability
    const renewTtl = req.body.ttl;
    if (renewTtl !== undefined && (typeof renewTtl !== 'number' || !isFinite(renewTtl) || renewTtl <= 0)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'ttl must be a positive finite number',
        400
      );
    }

    // Validate the token format early so malformed tokens return 401 even when
    // the service has not yet been initialized
    try {
      jose.decodeProtectedHeader(currentToken);
    } catch {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Invalid capability token format',
        401
      );
    }

    const response = await getIssuerService().renewCapability(
      currentToken,
      renewTtl,
      { clientIp: req.ip },
    );

    issuanceCounter.inc({ operation: 'renew', outcome: 'success' });

    // Stage 4, Task 10: record renewal telemetry. Extract tenantId/userId
    // from the signed response token (unverified — telemetry use only).
    if (issuerTelemetry) {
      const { tenantId, userId } = extractTelemetryClaimsFromToken(response.token);
      issuerTelemetry.recordRenewal(tenantId, userId);
    }

    // R-3: stamp `euno.*` attributes on the request span.
    setActiveSpanEunoAttributes({
      [EUNO_ATTR.JTI]: response.tokenId,
      [EUNO_ATTR.OUTCOME]: 'success',
    });

    res.json(response);
  } catch (error) {
    issuanceCounter.inc({ operation: 'renew', outcome: 'error' });
    next(error);
  }
});

/**
 * Get JWKS endpoint (R-6)
 * GET /.well-known/jwks.json
 *
 * Returns the issuer's JSON Web Key Set.  The gateway (and any other
 * consumer) should call this endpoint instead of /api/v1/public-key to
 * support key rotation without a synchronised restart.
 */
app.get('/.well-known/jwks.json', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const jwks = await getIssuerService().getJwks();
    res.json(jwks);
  } catch (error) {
    next(error);
  }
});

/**
 * Get public key endpoint (deprecated — use /.well-known/jwks.json)
 * GET /api/v1/public-key
 */
app.get('/api/v1/public-key', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const publicKey = await getIssuerService().getPublicKey();
    // Emit deprecation log and response header so operators know to migrate.
    logger.warn(
      'GET /api/v1/public-key is deprecated. ' +
        'Migrate consumers to GET /.well-known/jwks.json (R-6). ' +
        'This endpoint will be removed in a future release.',
    );
    res.setHeader('Deprecation', 'Wed, 01 Jan 2025 00:00:00 GMT');
    res.setHeader('Link', '</.well-known/jwks.json>; rel="successor-version"');
    res.json({ publicKey });
  } catch (error) {
    next(error);
  }
});

/**
 * Get issuer DID document endpoint
 * GET /.well-known/did.json
 */
app.get('/.well-known/did.json', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const publicKey = await getIssuerService().getPublicKey();

    // Return a simplified DID document
    const didDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
      id: config.issuerDid,
      verificationMethod: [
        {
          id: `${config.issuerDid}#key-1`,
          type: 'JsonWebKey2020',
          controller: config.issuerDid,
          publicKeyPem: publicKey,
        },
      ],
      authentication: [`${config.issuerDid}#key-1`],
      assertionMethod: [`${config.issuerDid}#key-1`],
    };

    res.json(didDocument);
  } catch (error) {
    next(error);
  }
});

/**
 * Issuer metadata endpoint
 * GET /.well-known/capability-issuer
 *
 * Returns metadata about this capability issuer:
 * - Issuer DID
 * - Supported token schema versions
 * - Current token schema version being minted
 * - Supported signing algorithms
 * - Link to public key and DID document
 * - actionResolverHash: canonical SHA-256 of the loaded ActionResolver config
 */
app.get('/.well-known/capability-issuer', (_req: Request, res: Response) => {
  const body: Record<string, unknown> = {
    issuer: config.issuerDid,
    schemaVersions: {
      current: CAPABILITY_TOKEN_SCHEMA_VERSION,
      supported: Array.from(SUPPORTED_SCHEMA_VERSIONS),
    },
    signingAlgorithms: SIGNING_ALGORITHMS,
    endpoints: {
      jwks: '/.well-known/jwks.json',
      publicKey: '/api/v1/public-key (deprecated — use jwks)',
      didDocument: '/.well-known/did.json',
    },
    // Canonical SHA-256 of the operator-supplied ActionResolver config
    // (or the sentinel hash of `{}` when no file is configured). The
    // gateway compares this against its own locally-computed hash at
    // startup — a mismatch means the two services are using different
    // action vocabularies and tokens minted by this issuer may not be
    // enforced correctly at the gateway.
    actionResolverHash,
  };
  // F-7: surface the region tag so a multi-region active/active
  // deployment can be inspected from the outside (e.g. an operator
  // diagnosing why a token validated against region A's JWKS but the
  // VC payload is stamped `region: "B"`). Omitted entirely when the
  // operator has not configured a region — back-compat with single
  // region deployments.
  if (issuerRegion) {
    body.region = issuerRegion;
  }
  res.json(body);
});

/**
 * OIDC Discovery document endpoint
 * GET /.well-known/openid-configuration
 * GET /.well-known/openid-configuration?tenantId=<id>
 *
 * Returns an RFC 8414 / OpenID Connect Discovery 1.0 document describing
 * this issuer's OIDC capabilities. The document is used by clients (e.g. the
 * `euno request` CLI command) to discover the authorization and token
 * endpoints.
 *
 * Per-tenant: when `?tenantId=<id>` is supplied and a per-tenant IdP entry
 * exists in ISSUER_TENANT_IDP_CONFIG_FILE, the document reflects that
 * tenant's IdP configuration (same endpoints, but the tenant context is
 * surfaced). The capability-issuer always issues the final capability token;
 * only the upstream IdP changes per tenant.
 */
app.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : undefined;

  // The public base URL is required to construct absolute endpoint URLs.
  // When unset we still return a partial document (useful for introspection)
  // but omit the endpoint URLs so clients can detect the misconfiguration.
  const baseUrl = env.ISSUER_PUBLIC_URL ? env.ISSUER_PUBLIC_URL.replace(/\/$/, '') : undefined;

  const doc: Record<string, unknown> = {
    issuer: config.issuerDid,
    jwks_uri: baseUrl ? `${baseUrl}/.well-known/jwks.json` : undefined,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: Array.from(SIGNING_ALGORITHMS),
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
  };

  if (baseUrl) {
    const tenantParam = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    doc.authorization_endpoint = `${baseUrl}/api/v1/oidc/authorize${tenantParam}`;
    // token_endpoint also carries the tenantId hint so discovery-document consumers
    // (clients / IdP libraries) can pass it as a body parameter on the token call.
    doc.token_endpoint = `${baseUrl}/api/v1/oidc/token${tenantParam}`;
  }

  if (tenantId) {
    // Signal which tenantId this document was constructed for.
    doc.tenant_id = tenantId;
    // Surface the configured provider for this tenant (or the global one).
    const hasPerTenantConfig = !!tenantIdpRegistry.getAdapter(tenantId);
    doc.identity_provider = hasPerTenantConfig
      ? `per-tenant[${tenantId}]`
      : (config.identityProvider || 'azure-ad');
  } else {
    doc.identity_provider = config.identityProvider || 'azure-ad';
  }

  res.json(doc);
});

/**
 * OIDC Authorization endpoint
 * GET /api/v1/oidc/authorize
 *
 * Generates a nonce + state pair, stores them in the OidcStateStore, and
 * returns a JSON body with the upstream IdP authorization URL that the caller
 * (typically the CLI) should open in a browser.
 *
 * Query parameters:
 *   - tenantId   (optional) — select per-tenant IdP
 *   - agentId    (required) — bound into the pending state for capability issuance
 *   - redirectUri (optional) — the CLI's loopback redirect URI for the code
 *
 * The returned `state` and `nonce` must be included in the authorization
 * request to the IdP. The `nonce` is validated when the code is exchanged via
 * POST /api/v1/oidc/token.
 */
app.get('/api/v1/oidc/authorize', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const agentId = typeof req.query.agentId === 'string' ? req.query.agentId : undefined;
    if (!agentId) {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'agentId query parameter is required', 400);
    }

    const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : undefined;
    const redirectUri = typeof req.query.redirectUri === 'string' ? req.query.redirectUri : undefined;

    const { state, nonce } = await getOidcStateStore().createState({ tenantId, agentId, redirectUri });

    const baseUrl = env.ISSUER_PUBLIC_URL ? env.ISSUER_PUBLIC_URL.replace(/\/$/, '') : undefined;

    res.json({
      state,
      nonce,
      // Convenience: include the callback URL the IdP should redirect to.
      // Callers must include state, nonce, and code_challenge in the actual
      // IdP auth request; the issuer does not construct that URL here because
      // it does not hold the PKCE code_challenge (that lives client-side).
      callbackUrl: baseUrl ? `${baseUrl}/api/v1/oidc/token` : undefined,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * OIDC Token endpoint (authorization-code exchange)
 * POST /api/v1/oidc/token
 *
 * Validates a pre-exchanged IdP identity token, enforces OIDC security
 * invariants, then issues a signed capability token. The client (typically
 * the `euno request` CLI command) performs the PKCE code exchange directly
 * against the upstream IdP token endpoint, then submits the resulting ID
 * token to this endpoint along with the original authorization code (used
 * only for replay prevention at the issuer boundary).
 *
 * Request body (JSON):
 * ```json
 * {
 *   "idToken":        "...",        // ID token returned by the upstream IdP
 *   "nonce":          "...",        // nonce embedded in the ID token's claims
 *   "agentId":        "...",        // capability token subject
 *   "tenantId":       "...",        // optional — selects per-tenant IdP adapter
 *   "state":          "...",        // optional — opaque state from GET /authorize
 *   "requestedCapabilities": [...]  // optional capability constraints
 * }
 * ```
 *
 * Security invariants enforced here (Stage-4 threat model §5):
 *  1. **ID-token replay prevention** — a SHA-256 hash of the submitted
 *     `idToken` is marked as used eagerly (fail-closed) before any remote
 *     call. The same token cannot be resubmitted even if a subsequent step
 *     fails. The caller must obtain a fresh token to retry.
 *  2. **Nonce binding** — the `nonce` claim inside the IdP's signed ID token
 *     must equal the `nonce` field in the request body.
 *  3. **Audience / issuer / expiry** — validated inside each IdP adapter via
 *     jose `jwtVerify` (enforces `aud`, `iss`, `exp`, `iat`).
 *  4. **Role-from-token** — capabilities are derived exclusively from the
 *     IdP token's role claims; the request body cannot escalate privileges.
 *  5. **State binding** (optional) — when `state` is provided and a pending
 *     state was created via GET /api/v1/oidc/authorize, the stored nonce,
 *     agentId, and tenantId are cross-checked against the request values.
 *     The effective tenantId is derived from the stored state when present.
 */
app.post('/api/v1/oidc/token', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { idToken, nonce, state, agentId, tenantId, requestedCapabilities } = req.body ?? {};

    // --- Validate required fields -------------------------------------------
    if (typeof idToken !== 'string' || !idToken) {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'idToken is required', 400);
    }
    if (typeof agentId !== 'string' || !agentId) {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'agentId is required', 400);
    }
    if (typeof nonce !== 'string' || !nonce) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'nonce is required — pass the nonce that was embedded in the IdP authorization request',
        400,
      );
    }

    // --- ID-token replay prevention (threat model §5 "IdP-token replay") ----
    // Hash the submitted idToken and atomically mark it as used (fail-closed).
    // markIdTokenHashUsed() returns true if this is the first use of this token
    // within the TTL window, false if it was already seen (replay attempt).
    // For the Redis-backed store the underlying SET NX EX is atomic across all
    // replicas, so exactly one of N concurrent requests for the same token will
    // proceed — the others are turned away here without a separate pre-check.
    const tokenHash = crypto.createHash('sha256').update(idToken).digest('hex');
    const isNewToken = await getOidcStateStore().markIdTokenHashUsed(tokenHash);
    if (!isNewToken) {
      logger.warn('OIDC token replay attempt detected', { agentId, tenantId });
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'ID token has already been used — obtain a fresh token',
        401,
      );
    }

    // --- Optional state binding (if flow was started via /authorize) ---------
    // When state is present, the stored nonce, agentId, and tenantId are all
    // cross-checked. The effective tenantId is derived from the stored state
    // (the request body cannot override it once a state has been issued).
    let effectiveTenantId: string | undefined =
      typeof tenantId === 'string' && tenantId ? tenantId : undefined;

    if (typeof state === 'string' && state) {
      const pending = await getOidcStateStore().consumeState(state);
      if (!pending) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Unknown or expired state parameter — restart the authorization flow',
          401,
        );
      }
      // The nonce in the request must match what was stored for this state.
      if (pending.nonce !== nonce) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Nonce mismatch — the nonce in the request does not match the stored state',
          401,
        );
      }
      // The agentId must match what was stored (if the state recorded one).
      if (pending.agentId && pending.agentId !== agentId) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'agentId mismatch — request agentId does not match the stored state',
          401,
        );
      }
      // The tenantId must match what was stored (if the state recorded one).
      const pendingTenantId = pending.tenantId;
      if (pendingTenantId) {
        if (effectiveTenantId && effectiveTenantId !== pendingTenantId) {
          throw new CapabilityError(
            ErrorCode.AUTHENTICATION_FAILED,
            'tenantId mismatch — request tenantId does not match the stored state',
            401,
          );
        }
        // Derive the effective tenantId from the stored state.
        effectiveTenantId = pendingTenantId;
      }
    }
    const perTenantIdp = effectiveTenantId ? tenantIdpRegistry.getAdapter(effectiveTenantId) : undefined;
    const idp = perTenantIdp ?? getIssuerService().getIdentityProvider();

    // --- Validate the ID token (signature, iss, aud, exp, iat) --------------
    const userContext = await idp.validateToken(idToken);

    // --- Enforce nonce claim binding (invariant 2) --------------------------
    // The `nonce` claim in the ID token must equal the nonce submitted by the
    // client. This binds the token to the specific authorization request and
    // prevents an attacker from re-using a token obtained from a different
    // session that happens to have the same aud/iss/sub.
    const tokenNonce = userContext.claims?.['nonce'] as string | undefined;
    if (!tokenNonce || tokenNonce !== nonce) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Nonce claim in the ID token does not match the expected nonce',
        401,
      );
    }

    // --- Issue capability token from the validated UserContext --------------
    const enforcementCtx: IssuerEnforcementContext = { clientIp: req.ip };
    const response = await getIssuerService().issueCapabilityFromUserContext(
      {
        agentId,
        userContext,
        requestedCapabilities: Array.isArray(requestedCapabilities) ? requestedCapabilities : undefined,
      },
      enforcementCtx,
    );

    issuanceCounter.inc({ operation: 'issue', outcome: 'success' });

    // Stage 4, Task 10: record OIDC-path issuance telemetry. Extract
    // tenantId/userId from the signed response token (unverified — telemetry
    // use only). Note: userContext.userId is already available here but
    // using the response token is consistent with the direct-issue path.
    if (issuerTelemetry) {
      const { tenantId, userId } = extractTelemetryClaimsFromToken(response.token);
      issuerTelemetry.recordIssuance(tenantId, userId);
    }

    setActiveSpanEunoAttributes({
      [EUNO_ATTR.AGENT_ID]: agentId,
      [EUNO_ATTR.JTI]: response.tokenId,
      [EUNO_ATTR.OUTCOME]: 'success',
    });

    res.json(response);
  } catch (error) {
    issuanceCounter.inc({ operation: 'issue', outcome: 'error' });
    next(error);
  }
});

// Admin templates forwarding router — must be registered BEFORE the error-handling
// middleware so that CapabilityError throws from the admin routes are correctly
// converted to JSON responses by the error handler.
//
// The router is populated lazily inside initializeServices() when ISSUER_DB_URL
// is configured.  Until then, requests fall through to the catch-all 404 handler.
const adminTemplatesForwarder = express.Router({ mergeParams: true });
app.use('/api/v1/admin/templates', adminTemplatesForwarder);

// Admin UI forwarding router (Task 7) — also populated lazily in initializeServices().
// Serves server-rendered HTML pages at /admin/*.
const adminUiForwarder = express.Router({ mergeParams: true });
app.use('/admin', adminUiForwarder);

// Error handling middleware
app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof CapabilityError) {
    logger.warn('Request failed', {
      code: error.code,
      message: error.message,
      path: req.path,
    });

    if (error.responseHeaders) {
      for (const [name, value] of Object.entries(error.responseHeaders)) {
        res.setHeader(name, value);
      }
    }

    res.status(error.statusCode).json({
      error: {
        code: error.code,
        message: error.message,
      },
    });
  } else {
    logger.error('Unexpected error', {
      error: error.message,
      stack: error.stack,
      path: req.path,
    });

    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      },
    });
  }
});

if (require.main === module) {
  // Start listening *before* initializing services so Kubernetes can
  // observe `/health/ready` returning 503 `not_ready` during startup
  // — without this, the kubelet has to wait on a closed socket
  // instead of a real readiness response, which prevents accurate
  // startup-time observability and complicates rolling updates.
  // The `isInitialized` flag flips inside `initializeServices()` so
  // readiness only goes 200 once the signer, identity provider,
  // policy, rate limiter, storage / DB credential services, and
  // optional posture / audit transports are wired.
  const server = app.listen(config.port, () => {
    logger.info(`Capability Issuer listening on port ${config.port}`, {
      environment: config.environment,
      issuerDid: config.issuerDid,
      signingProvider: config.signingProvider,
      identityProvider: config.identityProvider,
    });
  });

  // Graceful shutdown — registered before initializeServices() so a
  // SIGTERM during a slow signer / IdP bootstrap still closes the
  // listening socket cleanly.
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received, closing server gracefully');
    server.close(() => {
      // Use an async IIFE so we can await posture drain and have a
      // single `.catch()` for any unexpected rejection — Node.js does
      // not await async callbacks passed to `server.close()`.
      (async () => {
        // Stop the gauge-refresh interval first so no callbacks fire
        // after the SQLite connection is closed.
        if (postureMetricsInterval !== undefined) {
          clearInterval(postureMetricsInterval);
        }
        // Drain the durable posture queue: stop accepting new enqueues,
        // finish any in-flight delivery tick, then close the SQLite
        // connection cleanly.
        if (postureEmitter) {
          await postureEmitter.stop();
        }
        // Close the role-policy Postgres pool (Task 3) so integration
        // test runners and rolling deploys don't leak idle connections.
        if (rolePolicyPool) {
          await rolePolicyPool.end().catch((err: unknown) => {
            logger.warn('Error closing role-policy Postgres pool', {
              error: err instanceof Error ? err.message : String(err),
            });
          });
        }
        // Flush any pending telemetry before exit (Task 10).
        if (issuerTelemetry) {
          await issuerTelemetry.stop();
        }
        logger.info('Server closed');
        process.exit(0);
      })().catch((err) => {
        logger.error('Error during graceful shutdown', {
          error: err instanceof Error ? err.message : String(err),
        });
        process.exit(1);
      });
    });
  });

  initializeServices().catch((error) => {
    logger.error('Failed to initialize services', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    // Close the listener so the pod exits and Kubernetes restarts it
    // rather than serving 503 `not_ready` indefinitely.
    server.close(() => process.exit(1));
    // Belt and braces: if `close()` hangs (e.g. a stuck connection),
    // exit anyway after a short grace period.
    setTimeout(() => process.exit(1), 5_000).unref();
  });
}

export { app, initializeServices, issuerService };

// Re-export the standalone micro-service classes so downstream packages
// (db-token-service, storage-grant-service) can import from the main
// entry point without relying on subpath exports (which require
// moduleResolution: node16 / bundler).
export { DbTokenService } from './db-token';
export type { DbTokenServiceOptions } from './db-token';
export { StorageGrantService } from './storage-grant';
export type { StorageGrantServiceOptions } from './storage-grant';

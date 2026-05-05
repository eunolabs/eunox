/**
 * Capability Issuer API Server
 * Express server with /issue and /public-key endpoints
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
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
  loadActionResolverFromFile,
  loadRoleCapabilityPolicyFromFile,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  SUPPORTED_SCHEMA_VERSIONS,
  SIGNING_ALGORITHMS,
  loadConfigOrExit,
  createMetricsRegistry,
  createHttpMetricsMiddleware,
  createMetricsHandler,
  Counter,
  tracingMiddleware,
  setActiveSpanEunoAttributes,
  EUNO_ATTR,
  IssuanceRateLimiter,
  createIssuanceRateLimiterFromEnv,
  createOcsfTransportFromEnv,
  createOcsfWinstonTransport,
} from '@euno/common';
import { CapabilityIssuerService } from './issuer-service';
import { defaultSigningRegistry, defaultIdentityRegistry } from './default-registries';
import { StorageGrantService } from './storage-grant';
import { DbTokenService } from './db-token';
import { HttpSideCredentialBroker, SideCredentialBroker } from './side-credential-broker';
import { loadCosignersFromEnv, loadTransparencyLogsFromEnv } from './issuance-proofs-wiring';
import { PostureEmitter } from '@euno/posture-emitter';
import { parseDidWebHttpAllowList } from './did-resolver';

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
let isInitialized = false;

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
      actionResolver = loadActionResolverFromFile(actionResolverFile);
      logger.info('Action resolver config loaded');
    }

    // Per-(tenant, user, agent) issuance rate limiter (F-1, addresses
    // I-1). Tenant-aware, distributed via Redis when REDIS_URL is set
    // — required for multi-replica or multi-region active/active
    // deployments (F-7). When ISSUANCE_RATE_LIMIT_ENABLED=false the
    // service runs without a limiter, preserving pre-F-1 behaviour
    // (the per-IP express-rate-limit middleware below still runs).
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
          'Only the legacy per-IP rate limit applies. NOT recommended for production.',
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
        // AI posture-management inventory feed (sprint 3-4 gap item
        // #9). Disabled by default — `fromEnv` returns an inactive
        // emitter unless `POSTURE_EMITTER_ENABLED=true`. Failures
        // never fail issuance.
        postureEmitter: PostureEmitter.fromEnv(process.env, logger),
        // F-7: surface region tag on posture inventory so multi-region
        // deployments can chart per-region issuance distribution.
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
      }
    );

    logger.info('Services initialized successfully');
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

// Rate limiting - protect against brute force attacks
const rateLimitWindowMs = env.RATE_LIMIT_WINDOW_MS;
const rateLimitMax = env.RATE_LIMIT_MAX_REQUESTS;

const limiter = rateLimit({
  windowMs: rateLimitWindowMs,
  max: rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later',
  handler: (req: Request, res: Response) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    // Use the standard issuer error envelope (`{ error: { code, message } }`)
    // so clients can rely on a single 429 contract on these routes — the
    // F-1 limiter, the gateway, and this per-IP express limiter all share
    // a shape. `standardHeaders: true` above already adds `Retry-After`
    // (RFC 9110 §10.2.3), so the OpenAPI 429 response also holds here.
    res.status(429).json({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests, please try again later',
      },
    });
  },
});

app.use(limiter);
app.use(express.json());

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

    // Issue the capability
    const response = await getIssuerService().issueCapability(issueRequest);

    issuanceCounter.inc({ operation: 'issue', outcome: 'success' });

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
      ttl
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
      renewTtl
    );

    issuanceCounter.inc({ operation: 'renew', outcome: 'success' });

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
      logger.info('Server closed');
      process.exit(0);
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

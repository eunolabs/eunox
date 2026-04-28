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
  IssueCapabilityRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  ServiceConfig,
  TokenSigner,
  IdentityProvider,
  RoleCapabilityPolicy,
  loadRoleCapabilityPolicyFromFile,
} from '@euno/common';
import { CapabilityIssuerService } from './issuer-service';
import { defaultSigningRegistry, defaultIdentityRegistry } from './default-registries';

// Load environment variables
dotenv.config();

// Configuration
const config: ServiceConfig = {
  name: 'capability-issuer',
  port: parseInt(process.env.PORT || '3001', 10),
  environment: (process.env.NODE_ENV as any) || 'development',
  signingProvider: (process.env.SIGNING_PROVIDER as any) || 'azure-keyvault',
  identityProvider: (process.env.IDENTITY_PROVIDER as any) || 'azure-ad',
  // Azure Key Vault configuration
  keyVault: process.env.AZURE_KEYVAULT_URL ? {
    vaultUrl: process.env.AZURE_KEYVAULT_URL,
    keyName: process.env.AZURE_KEYVAULT_KEY_NAME || 'capability-signing-key',
    keyVersion: process.env.AZURE_KEYVAULT_KEY_VERSION,
    credentialType: (process.env.AZURE_CREDENTIAL_TYPE as any) || 'default',
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
    tenantId: process.env.AZURE_TENANT_ID,
  } : undefined,
  // AWS KMS configuration
  awsKMS: process.env.AWS_KMS_KEY_ID ? {
    region: process.env.AWS_KMS_REGION || 'us-east-1',
    keyId: process.env.AWS_KMS_KEY_ID,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    sessionToken: process.env.AWS_SESSION_TOKEN,
  } : undefined,
  // GCP Cloud KMS configuration
  gcpCloudKMS: (process.env.GCP_PROJECT_ID && process.env.GCP_KEYRING_ID && process.env.GCP_CRYPTOKEY_ID) ? {
    projectId: process.env.GCP_PROJECT_ID,
    locationId: process.env.GCP_LOCATION_ID || 'us-central1',
    keyRingId: process.env.GCP_KEYRING_ID,
    cryptoKeyId: process.env.GCP_CRYPTOKEY_ID,
    cryptoKeyVersion: process.env.GCP_CRYPTOKEY_VERSION,
    keyFilePath: process.env.GCP_KEY_FILE_PATH,
  } : undefined,
  // Azure AD configuration
  azureAD: process.env.AZURE_AD_TENANT_ID ? {
    tenantId: process.env.AZURE_AD_TENANT_ID,
    clientId: process.env.AZURE_AD_CLIENT_ID || '',
    clientSecret: process.env.AZURE_AD_CLIENT_SECRET,
    authority: process.env.AZURE_AD_AUTHORITY,
  } : undefined,
  // AWS Cognito / IAM Identity Center configuration.
  // Accept either:
  //   * a Cognito user pool: AWS_COGNITO_USER_POOL_ID + AWS_COGNITO_CLIENT_ID
  //   * an IAM Identity Center / generic OIDC source: AWS_COGNITO_ISSUER + AWS_COGNITO_CLIENT_ID
  awsCognito: (process.env.AWS_COGNITO_CLIENT_ID && (process.env.AWS_COGNITO_USER_POOL_ID || process.env.AWS_COGNITO_ISSUER)) ? {
    region: process.env.AWS_COGNITO_REGION,
    userPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
    clientId: process.env.AWS_COGNITO_CLIENT_ID,
    issuer: process.env.AWS_COGNITO_ISSUER,
    jwksUri: process.env.AWS_COGNITO_JWKS_URI,
    tokenUse: (process.env.AWS_COGNITO_TOKEN_USE as 'id' | 'access' | undefined),
  } : undefined,
  // Google Cloud identity configuration
  gcpIdentity: process.env.GCP_IDENTITY_AUDIENCE ? {
    audience: process.env.GCP_IDENTITY_AUDIENCE,
    issuer: process.env.GCP_IDENTITY_ISSUER,
    jwksUri: process.env.GCP_IDENTITY_JWKS_URI,
    projectId: process.env.GCP_IDENTITY_PROJECT_ID,
    rolesClaim: process.env.GCP_IDENTITY_ROLES_CLAIM,
  } : undefined,
  issuerDid: process.env.ISSUER_DID || 'did:web:example.com',
  defaultTokenTTL: parseInt(process.env.DEFAULT_TOKEN_TTL || '900', 10),
  enableDetailedLogging: process.env.ENABLE_DETAILED_LOGGING === 'true',
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
      });

    default:
      throw new Error(`Unsupported identity provider: ${identityProvider}`);
  }
}

// Initialize services
let issuerService: CapabilityIssuerService | undefined;

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
    const policyFile = process.env.ROLE_POLICY_FILE;
    if (policyFile && policyFile.trim().length > 0) {
      logger.info('Loading role → capability policy from file', { path: policyFile });
      rolePolicy = loadRoleCapabilityPolicyFromFile(policyFile);
      logger.info('Role policy loaded', {
        defaultRoles: Object.keys(rolePolicy.default).sort(),
        tenantOverrides: rolePolicy.tenants ? Object.keys(rolePolicy.tenants).sort() : [],
      });
    }

    issuerService = new CapabilityIssuerService(
      signer,
      identityProvider,
      config.issuerDid!,
      config.defaultTokenTTL,
      logger,
      rolePolicy,
    );

    logger.info('Services initialized successfully');
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

// Middleware
app.use(helmet());

// CORS configuration with environment-based origins
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : config.environment === 'production'
  ? []  // No CORS in production unless explicitly configured
  : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'];

app.use(cors({
  origin: allowedOrigins.length > 0 ? allowedOrigins : false,
  credentials: true,
}));

// Rate limiting - protect against brute force attacks
const rateLimitWindowRaw = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '', 10);
const rateLimitMaxRaw = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '', 10);
const rateLimitWindowMs = Number.isFinite(rateLimitWindowRaw) && rateLimitWindowRaw > 0
  ? rateLimitWindowRaw
  : 60000;
const rateLimitMax = Number.isFinite(rateLimitMaxRaw) && rateLimitMaxRaw > 0
  ? rateLimitMaxRaw
  : 100;
if (!Number.isFinite(rateLimitWindowRaw) && process.env.RATE_LIMIT_WINDOW_MS) {
  logger.warn('RATE_LIMIT_WINDOW_MS value is invalid, using default 60000ms');
}
if (!Number.isFinite(rateLimitMaxRaw) && process.env.RATE_LIMIT_MAX_REQUESTS) {
  logger.warn('RATE_LIMIT_MAX_REQUESTS value is invalid, using default 100');
}

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
    res.status(429).json({
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later',
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
 * Health check endpoint
 */
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'capability-issuer' });
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

    res.json(response);
  } catch (error) {
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

    res.json(response);
  } catch (error) {
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

    res.json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * Get public key endpoint
 * GET /api/v1/public-key
 */
app.get('/api/v1/public-key', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const publicKey = await getIssuerService().getPublicKey();
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

// Error handling middleware
app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof CapabilityError) {
    logger.warn('Request failed', {
      code: error.code,
      message: error.message,
      path: req.path,
    });

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
  // Initialize services and start server
  initializeServices()
    .then(() => {
      const server = app.listen(config.port, () => {
        logger.info(`Capability Issuer listening on port ${config.port}`, {
          environment: config.environment,
          issuerDid: config.issuerDid,
          signingProvider: config.signingProvider,
          identityProvider: config.identityProvider,
        });
      });

      // Graceful shutdown
      process.on('SIGTERM', () => {
        logger.info('SIGTERM received, closing server gracefully');
        server.close(() => {
          logger.info('Server closed');
          process.exit(0);
        });
      });
    })
    .catch((error) => {
      logger.error('Failed to start server', { error: error instanceof Error ? error.message : 'Unknown error' });
      process.exit(1);
    });
}

export { app, initializeServices, issuerService };

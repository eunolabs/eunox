/**
 * Capability Issuer API Server
 * Express server with /issue and /public-key endpoints
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import {
  IssueCapabilityRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  ServiceConfig,
} from '@euno/common';
import { CapabilityIssuerService } from './issuer-service';
import { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from './azure-signer';
import { AzureADIdentityProvider, AzureADAdapterConfig } from './azure-identity-provider';

// Load environment variables
dotenv.config();

// Configuration
const config: ServiceConfig = {
  name: 'capability-issuer',
  port: parseInt(process.env.PORT || '3001', 10),
  environment: (process.env.NODE_ENV as any) || 'development',
  keyVault: {
    vaultUrl: process.env.AZURE_KEYVAULT_URL || '',
    keyName: process.env.AZURE_KEYVAULT_KEY_NAME || 'capability-signing-key',
    credentialType: (process.env.AZURE_CREDENTIAL_TYPE as any) || 'default',
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
    tenantId: process.env.AZURE_TENANT_ID,
  },
  azureAD: {
    tenantId: process.env.AZURE_AD_TENANT_ID || '',
    clientId: process.env.AZURE_AD_CLIENT_ID || '',
    clientSecret: process.env.AZURE_AD_CLIENT_SECRET,
    authority: process.env.AZURE_AD_AUTHORITY,
  },
  issuerDid: process.env.ISSUER_DID || 'did:web:example.com',
  defaultTokenTTL: parseInt(process.env.DEFAULT_TOKEN_TTL || '900', 10),
  enableDetailedLogging: process.env.ENABLE_DETAILED_LOGGING === 'true',
};

// Create logger
const logger = createLogger(config.name, config.environment);

// Initialize services with adapter configurations
const signerConfig: AzureKeyVaultAdapterConfig = {
  type: 'azure-keyvault',
  name: 'Azure Key Vault Signer',
  keyVault: config.keyVault!,
};

const identityConfig: AzureADAdapterConfig = {
  type: 'azure-ad',
  name: 'Azure AD Identity Provider',
  azureAD: config.azureAD!,
};

const signer = new AzureKeyVaultSigner(signerConfig);
const identityProvider = new AzureADIdentityProvider(identityConfig);
const issuerService = new CapabilityIssuerService(
  signer,
  identityProvider,
  config.issuerDid!,
  config.defaultTokenTTL,
  logger
);

// Create Express app
const app = express();

// Middleware
app.use(helmet());
app.use(cors());
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
    const response = await issuerService.issueCapability(issueRequest);

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

    // Attenuate the capability
    const response = await issuerService.attenuateCapability(
      parentToken,
      req.body.requestedCapabilities,
      req.body.ttl
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
    const response = await issuerService.renewCapability(
      currentToken,
      req.body.ttl
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
    const publicKey = await issuerService.getPublicKey();
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
    const publicKey = await issuerService.getPublicKey();

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
  // Start server
  const server = app.listen(config.port, () => {
    logger.info(`Capability Issuer listening on port ${config.port}`, {
      environment: config.environment,
      issuerDid: config.issuerDid,
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
}

export { app, issuerService };

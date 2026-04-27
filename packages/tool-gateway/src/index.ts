/**
 * Tool Gateway API Server
 * Express server with capability token validation and enforcement
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { createProxyMiddleware } from 'http-proxy-middleware';
import {
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  ServiceConfig,
  DefaultKillSwitchManager,
} from '@euno/common';
import { JWTTokenVerifier } from './verifier';
import { EnforcementEngine } from './enforcement';
import { createAdminRouter } from './admin-api';
import axios from 'axios';

// Load environment variables
dotenv.config();

// Configuration
const config: ServiceConfig = {
  name: 'tool-gateway',
  port: parseInt(process.env.PORT || '3002', 10),
  environment: (process.env.NODE_ENV as any) || 'development',
  enableCryptographicAudit: process.env.ENABLE_CRYPTOGRAPHIC_AUDIT === 'true',
  policyVersion: process.env.POLICY_VERSION || '1.0.0',
};

const issuerPublicKeyUrl = process.env.ISSUER_PUBLIC_KEY_URL || 'http://localhost:3001/api/v1/public-key';
const adminApiKey = process.env.ADMIN_API_KEY; // Optional: set to enable API key auth for admin endpoints

// Create logger
const logger = createLogger(config.name, config.environment);

// Initialize kill-switch manager
const killSwitchManager = new DefaultKillSwitchManager(logger);

// Initialize verifier and enforcement engine
let verifier: JWTTokenVerifier;
let enforcementEngine: EnforcementEngine;

// Fetch public key from Capability Issuer
async function initializeServices() {
  try {
    logger.info('Fetching public key from Capability Issuer', { url: issuerPublicKeyUrl });
    const response = await axios.get(issuerPublicKeyUrl);
    const publicKey = response.data.publicKey;

    verifier = new JWTTokenVerifier(publicKey);
    enforcementEngine = new EnforcementEngine({
      verifier,
      logger,
      killSwitchManager,
      // evidenceSigner must be supplied externally (e.g. Azure Key Vault backed)
      enableCryptographicAudit: config.enableCryptographicAudit,
      policyVersion: config.policyVersion,
    });

    if (config.enableCryptographicAudit) {
      logger.warn(
        'Cryptographic audit is enabled but no evidenceSigner has been configured. ' +
        'Signed evidence will not be generated until an evidenceSigner implementation is provided.'
      );
    }

    logger.info('Tool Gateway services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    throw error;
  }
}

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
  res.json({ status: 'healthy', service: 'tool-gateway' });
});

/**
 * Admin API endpoints
 * Mount admin API after initialization
 */
let adminRouter: express.Router | null = null;
function mountAdminApi() {
  if (!adminRouter) {
    adminRouter = createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey,
    });
    app.use('/admin', adminRouter);
    logger.info('Admin API mounted');
  }
}

/**
 * Capability validation middleware
 * Validates the capability token before proxying the request
 */
async function validateCapabilityMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction
) {
  try {
    // Extract capability token from Authorization header
    const token = parseBearerToken(req.headers.authorization);
    if (!token) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token is required',
        401
      );
    }

    // Extract action and resource from request
    // For this implementation, we'll use a simple mapping:
    // - GET -> read
    // - POST/PUT/PATCH -> write
    // - DELETE -> delete
    const actionMap: Record<string, string> = {
      GET: 'read',
      POST: 'write',
      PUT: 'write',
      PATCH: 'write',
      DELETE: 'delete',
    };

    const action = actionMap[req.method] || 'read';

    // Extract resource from path, deriving canonical api:// URI
    // req.path has the /proxy prefix already stripped by Express route mounting
    const resourcePath = req.path.replace(/^\/+/, '');
    const resource = `api://${resourcePath}`;

    // Validate the action
    const validationRequest: ValidateActionRequest = {
      token,
      action: action as any,
      resource,
      context: {
        method: req.method,
        path: req.path,
      },
    };

    const result = await enforcementEngine.validateAction(validationRequest);

    if (!result.allowed) {
      throw new CapabilityError(
        ErrorCode.AUTHORIZATION_FAILED,
        result.reason || 'Action not allowed',
        403
      );
    }

    // Attach validation result to request for downstream use
    (req as any).capabilityValidation = result;

    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Validate action endpoint (for testing)
 * POST /api/v1/validate
 */
app.post('/api/v1/validate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = parseBearerToken(req.headers.authorization);
    if (!token) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token is required',
        401
      );
    }

    const validationRequest: ValidateActionRequest = {
      token,
      action: req.body.action,
      resource: req.body.resource,
      context: req.body.context,
    };

    const result = await enforcementEngine.validateAction(validationRequest);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

/**
 * Tool invocation endpoint (Sprint 1 & 2)
 * POST /api/v1/tools/invoke
 *
 * This endpoint is used by agent runtime to invoke tools with capability tokens.
 * Implements the sandboxing requirement: all agent actions go through this gateway.
 */
app.post('/api/v1/tools/invoke', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = parseBearerToken(req.headers.authorization);
    if (!token) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Authorization header with Bearer token is required',
        401
      );
    }

    const { tool, args, resource } = req.body;

    if (!tool) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'tool parameter is required',
        400
      );
    }

    // Determine action type from tool name
    // This is a simple mapping - in production, use a more sophisticated registry
    let action: string;
    if (tool.includes('read') || tool.includes('get') || tool.includes('list')) {
      action = 'read';
    } else if (tool.includes('write') || tool.includes('create') || tool.includes('update')) {
      action = 'write';
    } else if (tool.includes('delete') || tool.includes('remove')) {
      action = 'delete';
    } else {
      action = 'execute'; // Default for other tools
    }

    // Validate the action
    const validationRequest: ValidateActionRequest = {
      token,
      action: action as any,
      resource: resource || `tool://${tool}`,
      context: {
        tool,
        args,
        agentId: req.headers['x-agent-id'],
      },
    };

    const result = await enforcementEngine.validateAction(validationRequest);

    if (!result.allowed) {
      throw new CapabilityError(
        ErrorCode.AUTHORIZATION_FAILED,
        result.reason || 'Tool invocation not allowed',
        403
      );
    }

    // In a real implementation, this would invoke the actual tool
    // For now, return success with mock data
    logger.info('Tool invoked successfully', {
      tool,
      action,
      resource,
      agentId: req.headers['x-agent-id'],
    });

    res.json({
      success: true,
      tool,
      result: {
        message: 'Tool executed successfully (mock implementation)',
        data: args,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Protected proxy endpoints
 * All requests under /proxy/* are validated and then proxied to backend services
 */
app.use(
  '/proxy',
  validateCapabilityMiddleware,
  createProxyMiddleware({
    target: process.env.BACKEND_SERVICE_URL || 'http://localhost:4000',
    changeOrigin: true,
    pathRewrite: {
      '^/proxy': '', // Remove /proxy prefix
    },
    onProxyReq: (proxyReq, req, _res) => {
      logger.info('Proxying request', {
        path: req.path,
        target: proxyReq.path,
      });
    },
    onProxyRes: (proxyRes, req, _res) => {
      logger.info('Proxy response', {
        path: req.path,
        statusCode: proxyRes.statusCode,
      });
    },
    onError: (err, req, res) => {
      logger.error('Proxy error', {
        path: req.path,
        error: err.message,
      });
      (res as Response).status(502).json({
        error: {
          code: 'PROXY_ERROR',
          message: 'Failed to proxy request to backend service',
        },
      });
    },
  })
);

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

// Start server
async function startServer() {
  try {
    await initializeServices();

    // Mount admin API after services are initialized
    mountAdminApi();

    const server = app.listen(config.port, () => {
      logger.info(`Tool Gateway listening on port ${config.port}`, {
        environment: config.environment,
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
  } catch (error) {
    logger.error('Failed to start server', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

export function getEnforcementEngine(): EnforcementEngine {
  if (!enforcementEngine) {
    throw new Error('Enforcement engine has not been initialized');
  }
  return enforcementEngine;
}

export { app };

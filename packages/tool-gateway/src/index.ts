/**
 * Tool Gateway API Server
 * Express server with capability token validation and enforcement
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
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
import { createRevocationStoreFromEnv, RevocationStore } from './revocation-store';
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
let revocationStore: RevocationStore | undefined;

// Fetch public key from Capability Issuer
async function initializeServices() {
  try {
    logger.info('Fetching public key from Capability Issuer', { url: issuerPublicKeyUrl });
    const response = await axios.get(issuerPublicKeyUrl);
    const publicKey = response.data.publicKey;

    // Build the revocation store from environment.  Defaults to in-memory; if
    // REDIS_URL is set we connect to Redis so revocations are shared across
    // gateway replicas.  See docs/DISTRIBUTED_REVOCATION.md.
    revocationStore = await createRevocationStoreFromEnv(process.env, logger);

    verifier = new JWTTokenVerifier(publicKey, undefined, revocationStore);
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

// Rate limiting
const gwRateLimitWindowRaw = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '', 10);
const gwRateLimitMaxRaw = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '', 10);
const gwRateLimitWindowMs = Number.isFinite(gwRateLimitWindowRaw) && gwRateLimitWindowRaw > 0
  ? gwRateLimitWindowRaw
  : 60000;
const gwRateLimitMax = Number.isFinite(gwRateLimitMaxRaw) && gwRateLimitMaxRaw > 0
  ? gwRateLimitMaxRaw
  : 1000; // Higher limit for gateway
if (!Number.isFinite(gwRateLimitWindowRaw) && process.env.RATE_LIMIT_WINDOW_MS) {
  logger.warn('RATE_LIMIT_WINDOW_MS value is invalid, using default 60000ms');
}
if (!Number.isFinite(gwRateLimitMaxRaw) && process.env.RATE_LIMIT_MAX_REQUESTS) {
  logger.warn('RATE_LIMIT_MAX_REQUESTS value is invalid, using default 1000');
}

const limiter = rateLimit({
  windowMs: gwRateLimitWindowMs,
  max: gwRateLimitMax,
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
      tokenVerifier: verifier,
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
 * Server-side tool registry: maps known tool names to their required action.
 * Using an explicit registry prevents misclassification from substring matching
 * and ensures authorization decisions are based on the actual tool semantics.
 * Unknown tools default to 'execute' (most restrictive default).
 */
const TOOL_ACTION_REGISTRY: Record<string, string> = {
  // File operations
  read_file: 'read',
  get_file: 'read',
  list_files: 'read',
  list_directory: 'read',
  write_file: 'write',
  create_file: 'write',
  update_file: 'write',
  append_file: 'write',
  delete_file: 'delete',
  remove_file: 'delete',
  // HTTP/API operations
  http_get: 'read',
  http_post: 'write',
  http_put: 'write',
  http_delete: 'delete',
  // Code execution
  run_code: 'execute',
  execute_command: 'execute',
  run_shell: 'execute',
};

/**
 * Resolves the required action type for a given tool name using an explicit
 * server-side registry.  Using a registry instead of substring matching prevents
 * misclassification and ensures authorization decisions reflect the tool's actual
 * semantics.  Unknown tools default to 'execute', the most restrictive action.
 *
 * @param tool - The tool name to look up (e.g. 'read_file').
 * @returns The action string ('read' | 'write' | 'delete' | 'execute').
 */
function resolveToolAction(tool: string): string {
  return TOOL_ACTION_REGISTRY[tool] ?? 'execute';
}

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

    const { tool, args } = req.body;

    if (!tool) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'tool parameter is required',
        400
      );
    }

    // Derive action from the server-side tool registry (not client-supplied).
    const action = resolveToolAction(tool);

    // Canonicalize resource server-side from the actual tool being invoked.
    // Never trust a client-supplied resource value, which could cause authorization
    // to be evaluated against a different resource than the tool/args actually affect.
    const canonicalResource = `tool://${tool}`;

    // Validate the action
    const validationRequest: ValidateActionRequest = {
      token,
      action: action as any,
      resource: canonicalResource,
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
      resource: canonicalResource,
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
    const shutdown = (signal: string) => {
      logger.info(`${signal} received, closing server gracefully`);
      server.close(async () => {
        try {
          if (revocationStore) {
            await revocationStore.close();
          }
        } catch (err) {
          logger.warn('Error while closing revocation store', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        logger.info('Server closed');
        process.exit(0);
      });
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
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

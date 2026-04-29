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
  EvidenceSigner,
  createSoftwareEvidenceSignerFromEnv,
  KillSwitchManager,
  createKillSwitchManagerFromEnv,
  CallCounterStore,
  createCallCounterStoreFromEnv,
  RedisCallCounterStore,
} from '@euno/common';
import { JWTTokenVerifier } from './verifier';
import { EnforcementEngine } from './enforcement';
import { createAdminRouter } from './admin-api';
import { createRevocationStoreFromEnv, RevocationStore } from './revocation-store';
import { createPartnerIssuerResolverFromEnv } from './partner-issuer-resolver';
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

// Initialize kill-switch manager.  Defaults to the in-process
// DefaultKillSwitchManager; replaced inside initializeServices() with a
// RedisKillSwitchManager when REDIS_URL is configured so kills propagate
// across replicas.  See docs/DISTRIBUTED_KILL_SWITCH.md.
let killSwitchManager: KillSwitchManager = new DefaultKillSwitchManager(logger);
let callCounterStore: CallCounterStore | undefined;

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

    // Build the kill-switch manager from environment.  Defaults to the
    // in-process implementation; if REDIS_URL is set we use the Redis-backed
    // manager so kills (global / session / agent) propagate across every
    // gateway replica.  See docs/DISTRIBUTED_KILL_SWITCH.md.
    killSwitchManager = await createKillSwitchManagerFromEnv(process.env, logger);

    // Build the call-counter store used by `maxCalls` condition
    // enforcement. Defaults to in-memory; when REDIS_URL is set it
    // reuses the same Redis client wiring as the kill-switch manager so
    // call budgets are shared across every gateway replica.
    callCounterStore = await createCallCounterStoreFromEnv(process.env, logger);

    // Build the cross-org partner-issuer trust resolver.  When
    // TRUSTED_PARTNER_DIDS is set, the verifier additionally accepts
    // capability tokens whose `iss` claim is one of the listed partner
    // DIDs and verifies their signatures against keys advertised in the
    // partner's DID document.  When unset, the gateway behaves exactly
    // as in Sprint-1/2 (single shared issuer key only).
    // See `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`.
    const partnerResolver = createPartnerIssuerResolverFromEnv(process.env);
    if (partnerResolver) {
      // Log only the count of configured partner DIDs; the DID strings
      // themselves are technically public but not worth emitting on every
      // boot to logs that may be aggregated.
      const partnerDidCount = (process.env.TRUSTED_PARTNER_DIDS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean).length;
      logger.info('Cross-org partner-issuer trust resolver enabled', {
        partnerDidCount,
      });
    }

    // Optional allow-list of issuers (DIDs or simple identifiers) that
    // the local SPKI key is authorised to sign for.  Only enforced when a
    // partner resolver is also configured — without partners there is
    // nothing to confuse the local key with.
    const localIssuers = (process.env.LOCAL_ISSUER_IDS || '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    verifier = new JWTTokenVerifier(
      publicKey,
      undefined,
      revocationStore,
      partnerResolver,
      localIssuers.length > 0 ? localIssuers : undefined
    );

    // Build the cryptographic evidence signer when audit signing is enabled.
    // Historically the gateway emitted a warning and silently continued
    // unsigned, which let operators believe audit signing was active when it
    // was not. We now treat the missing-signer case as a startup error so
    // misconfiguration cannot survive into a running process. KMS-backed
    // signers can still be supplied programmatically by importing this
    // module, constructing an EnforcementEngine with `evidenceSigner`, and
    // bypassing this default path.
    let evidenceSigner: EvidenceSigner | undefined;
    if (config.enableCryptographicAudit) {
      try {
        evidenceSigner = createSoftwareEvidenceSignerFromEnv(process.env);
      } catch (err) {
        throw new Error(
          'ENABLE_CRYPTOGRAPHIC_AUDIT=true but the configured evidence signer ' +
            'could not be initialised: ' +
            (err instanceof Error ? err.message : String(err)),
        );
      }
      if (!evidenceSigner) {
        throw new Error(
          'ENABLE_CRYPTOGRAPHIC_AUDIT=true but no evidence signer is configured. ' +
            'Provide EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded ' +
            'private key) and optionally EVIDENCE_SIGNING_ALGORITHM / EVIDENCE_SIGNING_KEY_ID, ' +
            'or wire a KMS-backed EvidenceSigner programmatically. Refusing to start ' +
            'with cryptographic audit enabled but no signer attached.',
        );
      }
      logger.info('Cryptographic audit enabled with software evidence signer');
    }

    enforcementEngine = new EnforcementEngine({
      verifier,
      logger,
      killSwitchManager,
      evidenceSigner,
      enableCryptographicAudit: config.enableCryptographicAudit,
      policyVersion: config.policyVersion,
      callCounterStore,
    });

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

    // Extract resource from path, deriving canonical api:// URI.
    // req.path has the /proxy prefix already stripped by Express route mounting.
    //
    // The agent runtime forwards the intended target host (from absolute URLs)
    // either as the first path segment OR as an X-Target-Host header. We
    // prefer the header (cheaper, more explicit) and cross-check the path
    // segment to detect tampering. If neither is supplied (e.g. a relative
    // path was used) we fall back to the legacy path-only resource so this
    // change is backwards compatible.
    const headerHost = (req.headers['x-target-host'] as string | undefined)?.trim();
    const rawPath = req.path.replace(/^\/+/, '');
    const firstSegment = rawPath.split('/')[0] || '';
    // A segment looks like a host if it passes a basic hostname/IP pattern.
    // We no longer require a dot so single-label names like `localhost` are
    // recognised; bracketed IPv6 addresses are also accepted.
    const looksLikeHost = /^(\[[\da-fA-F:]+\]|[A-Za-z0-9.\-]+)(:\d+)?$/.test(firstSegment);

    let resource: string;
    if (headerHost) {
      // Header explicitly identifies the host; use it.
      // Strip the leading path segment only when it equals the header host
      // (case-insensitive).  Using equality rather than the dot-based
      // heuristic means single-label hosts (e.g. `localhost`) and IPv6
      // addresses are handled correctly.
      const pathHasHostSegment = firstSegment.toLowerCase() === headerHost.toLowerCase();
      // If the path encodes a *different* host segment, treat as tampered.
      if (looksLikeHost && !pathHasHostSegment) {
        throw new CapabilityError(
          ErrorCode.AUTHORIZATION_FAILED,
          'Mismatch between X-Target-Host header and proxy path host segment',
          400
        );
      }
      const tail = pathHasHostSegment ? rawPath.slice(firstSegment.length).replace(/^\/+/, '') : rawPath;
      resource = `api://${headerHost}/${tail}`;
    } else if (looksLikeHost) {
      const tail = rawPath.slice(firstSegment.length).replace(/^\/+/, '');
      resource = `api://${firstSegment}/${tail}`;
    } else {
      resource = `api://${rawPath}`;
    }

    // Validate the action. The request body is included in the context
    // so that the enforcement engine can apply the matched capability's
    // `argumentSchema` (if any) — argument-level enforcement is a
    // first-class part of the gateway, not something callers have to
    // remember to invoke.
    const validationRequest: ValidateActionRequest = {
      token,
      action: action as any,
      resource,
      context: {
        method: req.method,
        path: req.path,
        body: req.body,
        query: req.query,
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
        try {
          // Use a structural check rather than `instanceof` so any
          // KillSwitchManager implementation that holds external
          // resources (timers, network connections, …) gets cleaned up
          // – not just the bundled RedisKillSwitchManager.  The
          // in-process default omits `close()` entirely.
          if (typeof killSwitchManager.close === 'function') {
            await killSwitchManager.close();
          }
        } catch (err) {
          logger.warn('Error while closing kill-switch manager', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        try {
          // Same structural check for the call-counter store: only the
          // Redis-backed implementation owns a connection to close.
          if (callCounterStore instanceof RedisCallCounterStore) {
            await callCounterStore.close();
          }
        } catch (err) {
          logger.warn('Error while closing call-counter store', {
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

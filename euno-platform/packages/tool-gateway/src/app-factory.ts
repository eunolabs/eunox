/**
 * Tool Gateway app factory
 * ---------------------------------------------------------------------------
 * Pure composition: assembles an `express.Application` from a fully-wired
 * dependency bag. No env reads, no `listen()`, no Redis connections — those
 * live in `bootstrap.ts`. Test code (e.g. `packages/integration-tests`) can
 * call `createApp(deps)` with hand-rolled fakes and exercise the gateway
 * in-process without HTTP — substantial test-speed improvement.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import express, {
  Express,
  Request,
  Response,
  NextFunction,
} from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import {
  CapabilityError,
  createHttpMetricsMiddleware,
  createMetricsHandler,
  tracingMiddleware,
} from '@euno/common';
import { resolveDID } from '@euno/capability-issuer/adapters';

import { createAdminRouter } from './admin-api';
import { createAuditRouter } from './routes/audit';
import { createHealthRouter } from './routes/health';
import { createProxyRouter } from './routes/proxy';
import { createValidateRouter } from './routes/validate';
import { createToolsRouter } from './routes/tools';
import { createEnforceRouter } from './routes/enforce';
import type { GatewayDependencies } from './bootstrap';

/**
 * Build a fully-configured Express application from a dependency bag.
 * The returned app is stateless with respect to env / I/O — everything it
 * needs is captured in `deps`.
 */
export function createApp(deps: GatewayDependencies): Express {
  const {
    logger,
    enforcementEngine,
    backendServiceUrl,
    allowedOrigins,
    rateLimitWindowMs,
    rateLimitMax,
    metricsRegistry,
  } = deps;
  const isReady = deps.isReady ?? (() => true);

  const app = express();

  // Trust proxy boundary (security-critical for F-2 DPoP `htu`
  // reconstruction). Operators who deploy the gateway behind a
  // TLS-terminating reverse proxy / load balancer MUST set
  // `TRUST_PROXY` so `req.protocol` / `req.hostname` reflect the
  // client-facing scheme + host the agent dialled (the one its DPoP
  // proof was signed against). Without this, Express would return
  // the proxy-internal scheme/host and DPoP verification would fail
  // legitimate requests; routes that previously read raw
  // `X-Forwarded-*` headers without this gate could be tricked by a
  // direct caller into verifying the proof against an attacker-chosen
  // URL. Default `false` (no proxy trust) is the safe stance for
  // direct deployments — see `parseTrustProxy` in bootstrap.ts and
  // the `TRUST_PROXY` env var docs.
  if (deps.trustProxy !== undefined && deps.trustProxy !== false) {
    app.set('trust proxy', deps.trustProxy);
  }

  // OpenTelemetry context propagation (R-3). Mounted as the very first
  // middleware so every downstream handler — including audit logging —
  // runs inside the request's span context.
  // F-7: stamp `euno.region` on every span when GATEWAY_REGION is set,
  // so traces from a multi-region deployment can be filtered/grouped
  // by the region that actually served the request.
  app.use(tracingMiddleware('tool-gateway', { region: deps.region }));

  // Security headers
  app.use(helmet());

  // CORS configuration with environment-based origins
  app.use(
    cors({
      origin: allowedOrigins.length > 0 ? allowedOrigins : false,
      credentials: true,
    }),
  );

  // F-5 (I-16): record HTTP duration + count for every non-/metrics request.
  // Mounted before the rate limiter so 429s are still observed in the
  // latency histogram (operators want to see throttled traffic too).
  app.use(createHttpMetricsMiddleware({ registry: metricsRegistry }));

  // Prometheus scrape endpoint. Plain GET handler so it bypasses the JSON
  // body parser and the rate limiter — Prometheus servers scrape on a tight
  // schedule and must not be throttled.
  app.get('/metrics', createMetricsHandler(metricsRegistry) as express.RequestHandler);

  // Rate limiting
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

  // Remote-enforcer endpoint (Stage-3 Task 9): mounted BEFORE the global
  // body-parser so the route's own 512 KiB body-parser takes precedence.
  // The global express.json() below is then a no-op for already-parsed bodies
  // (Express does not double-parse), giving other routes their own 100 KiB
  // default without changing this route's limit.
  // See docs/stage-3-gateway-protocol.md for the protocol spec.
  app.use(createEnforceRouter({
    enforcementEngine,
    logger,
    actionResolver: deps.actionResolver,
    telemetry: deps.gatewayTelemetry ?? undefined,
  }));

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

  // Health checks (liveness + readiness; resolves I-19)
  app.use(createHealthRouter({ isReady }));

  // Validation testing endpoint
  app.use(createValidateRouter({ enforcementEngine }));

  // Tool invocation endpoint
  app.use(createToolsRouter({ enforcementEngine, logger, actionResolver: deps.actionResolver }));

  // Audit record query endpoint (Task 7) — only mounted when a ledger backend
  // is configured. When no backend is present (e.g. software-only signer mode),
  // the route is simply absent and callers receive a 404.
  if (deps.auditLedgerBackend) {
    app.use(
      createAuditRouter({
        ledgerBackend: deps.auditLedgerBackend,
        verifier: deps.verifier,
        logger,
      }),
    );
  }

  // Protected proxy: validate then forward
  app.use(
    '/proxy',
    createProxyRouter({
      enforcementEngine,
      logger,
      backendServiceUrl,
      actionResolver: deps.actionResolver,
      responseRedactionMaxBytes: deps.responseRedactionMaxBytes,
    }),
  );

  // Error handling middleware
  app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof CapabilityError) {
      logger.warn('Request failed', {
        code: error.code,
        message: error.message,
        path: req.path,
      });
      // Propagate any error-attached response headers (e.g. `Retry-After`
      // for `RATE_LIMIT_EXCEEDED`). The mechanism is generic so a future
      // error code can opt in without touching this middleware.
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
      return;
    }
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
  });

  return app;
}

/**
 * Build a minimal Express application that serves only admin routes.
 *
 * This app is intended to listen on a **separate** port (ADMIN_PORT, default
 * 3003) so it is never reachable through the public-facing load-balancer or
 * the Kubernetes Service that routes external traffic to the gateway. Only
 * the internal ClusterIP admin Service should target this port.
 *
 * Deliberately omits CORS, public rate limiting, and all public routes.
 */
export function createAdminApp(deps: GatewayDependencies): Express {
  const { logger, killSwitchManager, adminApiKey, verifier } = deps;
  const adminApp = express();

  // Mirror the trust-proxy boundary from the public app so req.ip (logged on
  // every admin request and on admin-API auth failures) reflects the real
  // client address rather than the proxy's internal IP.
  if (deps.trustProxy !== undefined && deps.trustProxy !== false) {
    adminApp.set('trust proxy', deps.trustProxy);
  }

  // Security headers (still worthwhile on an internal interface).
  adminApp.use(helmet());

  adminApp.use(express.json());

  // Minimal request logging so admin operations are auditable.
  adminApp.use((req: Request, _res: Response, next: NextFunction) => {
    logger.info('Admin request', {
      method: req.method,
      path: req.path,
      ip: req.ip,
    });
    next();
  });

  adminApp.use(
    '/admin',
    createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey,
      tokenVerifier: verifier,
      epochStore: deps.epochStore,
      partnerResolver: deps.partnerResolver,
      partnerRegistry: deps.partnerRegistry,
      requirePin: deps.requirePin,
      pinAttestationSecret: deps.pinAttestationSecret,
      // When PARTNER_DID_AUTO_FETCH_PIN=true, wire resolveDID so the approval
      // endpoint can auto-compute the pinnedDocSha256 from the live document.
      resolveDidDocument: deps.partnerDidAutoFetchPin ? resolveDID : undefined,
      // Tenant scoping: when ADMIN_TENANT_ID is set, all mutating admin
      // operations must carry a matching tenantId in the request body.
      tenantId: deps.adminTenantId,
      // OCSF transport: when configured, emit Authorization events for every
      // mutating admin action so SIEMs can ingest them without a custom parser.
      ocsfTransport: deps.ocsfTransport,
    }),
  );

  // Error handler — all four parameters are required for Express to recognise
  // this as an error-handling middleware (as opposed to a regular middleware).
  adminApp.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof CapabilityError) {
      logger.warn('Admin request failed', { code: error.code, path: req.path });
      res.status(error.statusCode).json({ error: { code: error.code, message: error.message } });
      return;
    }
    logger.error('Unexpected admin error', { error: error.message, path: req.path });
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
  });

  return adminApp;
}

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

import { createAdminRouter } from './admin-api';
import { createHealthRouter } from './routes/health';
import { createProxyRouter } from './routes/proxy';
import { createValidateRouter } from './routes/validate';
import { createToolsRouter } from './routes/tools';
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
    killSwitchManager,
    verifier,
    adminApiKey,
    backendServiceUrl,
    allowedOrigins,
    rateLimitWindowMs,
    rateLimitMax,
    metricsRegistry,
  } = deps;
  const isReady = deps.isReady ?? (() => true);

  const app = express();

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

  // Admin API
  app.use(
    '/admin',
    createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey,
      tokenVerifier: verifier,
    }),
  );

  // Validation testing endpoint
  app.use(createValidateRouter({ enforcementEngine }));

  // Tool invocation endpoint
  app.use(createToolsRouter({ enforcementEngine, logger }));

  // Protected proxy: validate then forward
  app.use('/proxy', createProxyRouter({ enforcementEngine, logger, backendServiceUrl }));

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

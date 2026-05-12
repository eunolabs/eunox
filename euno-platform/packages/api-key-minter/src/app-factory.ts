import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { CapabilityError, createLogger } from '@euno/common';
import { createMintRouter, MintRouterOptions } from './routes/mint';
import { createAdminKeysRouter, AdminKeysRouterOptions } from './routes/admin-keys';
import { createAdminPoliciesRouter } from './routes/admin-policies';
import { createPingRouter } from './routes/ping';
import { AnomalyDetector } from './anomaly-detector';
import { minterMetrics } from './metrics';
import { InMemoryMintRateLimiter, MintRateLimiter } from './mint-rate-limiter';

type Logger = ReturnType<typeof createLogger>;

export interface MinterDependencies {
  mintRouterOpts: MintRouterOptions;
  adminKeysRouterOpts: AdminKeysRouterOptions;
  logger: Logger;
  /**
   * Optional anomaly detector shared across mint route instances.
   * When provided, it is injected into the mint router.
   */
  anomalyDetector?: AnomalyDetector;
  /**
   * Optional rate limiter for `GET /api/v1/ping`.  Applied per source IP
   * to prevent brute-force API-key enumeration.
   *
   * Kept separate from `mintRouterOpts.rateLimiter` (which is keyed by
   * tenant ID) so the two limits can be tuned independently without sharing
   * counters or affecting each other's in-memory state.
   *
   * When omitted, a default limiter of 20 req / 60 s per IP is created.
   */
  pingRateLimiter?: MintRateLimiter;
}

export function createMinterApp(deps: MinterDependencies): Express {
  const app = express();
  app.use(helmet());
  app.use(express.json());

  app.use((req: Request, _res: Response, next: NextFunction) => {
    deps.logger.info('Minter request', { method: req.method, path: req.path, ip: req.ip });
    next();
  });

  // Inject anomaly detector into mint router opts if provided at the app level.
  const mintRouterOpts: MintRouterOptions = deps.anomalyDetector
    ? { ...deps.mintRouterOpts, anomalyDetector: deps.anomalyDetector }
    : deps.mintRouterOpts;

  app.use(createMintRouter(mintRouterOpts));
  app.use(createAdminKeysRouter(deps.adminKeysRouterOpts));

  // Reuse the verifier from the mint router so /ping and /mint validate keys
  // through the same store + pepper chain, eliminating any risk of drift.
  // Use a dedicated rate limiter (separate from the mint per-tenant limiter)
  // so brute-force protection can be tuned without touching mint throughput.
  const pingRateLimiter =
    deps.pingRateLimiter ??
    new InMemoryMintRateLimiter({ maxMintsPerWindow: 20, windowSeconds: 60 });

  app.use(
    createPingRouter({
      verifier: deps.mintRouterOpts.verifier,
      logger: deps.logger,
      rateLimiter: pingRateLimiter,
    }),
  );

  // Admin policy-management routes (requires X-Admin-Key).
  app.use(
    createAdminPoliciesRouter({
      keyStore: deps.adminKeysRouterOpts.keyStore,
      adminApiKey: deps.adminKeysRouterOpts.adminApiKey,
      logger: deps.logger,
    }),
  );

  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', service: 'api-key-minter' });
  });

  // Prometheus metrics endpoint
  app.get('/metrics', async (_req: Request, res: Response) => {
    try {
      res.set('Content-Type', minterMetrics.registry.contentType);
      res.send(await minterMetrics.registry.metrics());
    } catch {
      res.status(500).send('Error collecting metrics');
    }
  });

  // Error handler
  app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof CapabilityError) {
      deps.logger.warn('Minter request failed', { code: error.code, path: req.path });
      if (error.responseHeaders) {
        for (const [name, value] of Object.entries(error.responseHeaders)) {
          res.setHeader(name, value);
        }
      }
      res.status(error.statusCode).json({ error: { code: error.code, message: error.message } });
      return;
    }
    deps.logger.error('Unexpected minter error', { error: error.message, path: req.path });
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
  });

  return app;
}

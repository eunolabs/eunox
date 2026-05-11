import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { CapabilityError, createLogger } from '@euno/common';
import { createMintRouter, MintRouterOptions } from './routes/mint';
import { createAdminKeysRouter, AdminKeysRouterOptions } from './routes/admin-keys';
import { AnomalyDetector } from './anomaly-detector';
import { minterMetrics } from './metrics';

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

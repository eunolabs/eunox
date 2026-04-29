/**
 * Health-check routes
 * ---------------------------------------------------------------------------
 * Splits liveness and readiness so Kubernetes (and any L7 load balancer) can
 * distinguish "process alive" from "process ready to serve traffic":
 *
 *   - `GET /health/live`   liveness  — always 200 once the HTTP server is up.
 *   - `GET /health/ready`  readiness — 200 only after `initializeServices()`
 *                          has completed; 503 with `{status:'not_ready'}`
 *                          otherwise so the kubelet keeps the pod out of the
 *                          Service endpoints until the issuer's public key has
 *                          been fetched and stores are wired (resolves I-19).
 *   - `GET /health`        liveness alias preserved for back-compat with
 *                          existing manifests / dashboards.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import { Request, Response, Router } from 'express';

export interface HealthRouterOptions {
  /** Returns true once the gateway is ready to serve real traffic. */
  isReady: () => boolean;
}

export function createHealthRouter(opts: HealthRouterOptions): Router {
  const router = Router();
  const { isReady } = opts;

  const liveness = (_req: Request, res: Response) => {
    res.json({ status: 'healthy', service: 'tool-gateway' });
  };

  router.get('/health', liveness);
  router.get('/health/live', liveness);

  router.get('/health/ready', (_req: Request, res: Response) => {
    if (isReady()) {
      res.json({ status: 'ready', service: 'tool-gateway' });
      return;
    }
    res.status(503).json({ status: 'not_ready', service: 'tool-gateway' });
  });

  return router;
}

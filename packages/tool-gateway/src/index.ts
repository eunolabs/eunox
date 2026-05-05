/**
 * Tool Gateway entrypoint
 * ---------------------------------------------------------------------------
 * Thin wrapper that wires `bootstrap.initializeServices()` (env + I/O) to
 * `app-factory.createApp(deps)` (pure composition) and then calls `listen()`
 * with graceful shutdown. All non-trivial logic lives in those modules so
 * tests can build a gateway in-process without HTTP.
 *
 * See R-2 in `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import dotenv from 'dotenv';
import * as http from 'http';

import { createApp, createAdminApp } from './app-factory';
import { initializeServices, type GatewayDependencies } from './bootstrap';
import { EnforcementEngine } from './enforcement';

// Load environment variables once for the running process.
dotenv.config();

// Lazily-initialised so importing this module (e.g. from
// `getEnforcementEngine`) does not start a server.
let bootstrappedDeps: GatewayDependencies | undefined;

/** Returns the single bootstrapped enforcement engine. Throws if uninitialised. */
export function getEnforcementEngine(): EnforcementEngine {
  if (!bootstrappedDeps) {
    throw new Error('Enforcement engine has not been initialized');
  }
  return bootstrappedDeps.enforcementEngine;
}

/**
 * Boot + listen + install graceful shutdown handlers.
 * Exported so callers can drive the lifecycle from outside (e.g. tests).
 */
export async function startServer(): Promise<void> {
  const { deps, setReady } = await initializeServices();
  bootstrappedDeps = deps;

  const app = createApp(deps);
  const adminApp = createAdminApp(deps);

  const { config, logger, revocationStore, epochStore, killSwitchManager, callCounterStore, auditPipeline, auditPipelineDrainTimeoutMs, ocsfTransport, dpopReplayStore } = deps;

  const server = app.listen(config.port, () => {
    setReady(true);
    logger.info(`Tool Gateway listening on port ${config.port}`, {
      environment: config.environment,
    });
  });

  const adminServer = deps.adminHost
    ? adminApp.listen(deps.adminPort, deps.adminHost, () => {
        logger.info(
          `Tool Gateway admin server listening on ${deps.adminHost}:${deps.adminPort}`,
          { environment: config.environment },
        );
      })
    : adminApp.listen(deps.adminPort, () => {
        logger.info(`Tool Gateway admin server listening on port ${deps.adminPort}`, {
          environment: config.environment,
        });
      });

  let isShuttingDown = false;
  const shutdown = (signal: string) => {
    // Guard against double invocation (e.g. SIGINT followed by SIGTERM or
    // a second SIGINT from an impatient operator). Node's server.close() is
    // not idempotent on an already-closing server, so we check here.
    if (isShuttingDown) {
      logger.warn(`${signal} received during shutdown — ignoring`);
      return;
    }
    isShuttingDown = true;
    logger.info(`${signal} received, closing server gracefully`);
    setReady(false);
    // Close both servers concurrently then clean up shared resources.
    // Errors from close() are surfaced so shutdown never silently stalls.
    const closeServer = (srv: http.Server) =>
      new Promise<void>((resolve, reject) =>
        srv.close((err) => (err ? reject(err) : resolve())),
      );
    void Promise.all([closeServer(server), closeServer(adminServer)])
      .catch((err) => {
        logger.warn('Error while closing HTTP server(s)', {
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      })
      .then(async () => {
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
          if (epochStore) {
            await epochStore.close();
          }
        } catch (err) {
          logger.warn('Error while closing epoch store', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        try {
          // Use a structural check rather than `instanceof` so any
          // KillSwitchManager implementation that holds external resources
          // (timers, network connections, …) gets cleaned up – not just the
          // bundled RedisKillSwitchManager. The in-process default omits
          // `close()` entirely.
          if (typeof killSwitchManager.close === 'function') {
            await killSwitchManager.close();
          }
        } catch (err) {
          logger.warn('Error while closing kill-switch manager', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        try {
          // Same structural check used for `killSwitchManager`: only
          // implementations that own external resources (e.g. the Redis-backed
          // store) expose `close()`. The in-memory default omits it.
          const closable = callCounterStore as { close?: () => Promise<void> | void };
          if (typeof closable.close === 'function') {
            await closable.close();
          }
        } catch (err) {
          logger.warn('Error while closing call-counter store', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        // R-9: drain the async audit pipeline before exit so any
        // evidence still buffered in the ring is flushed to the signer.
        // The drain timeout is bounded so SIGTERM cannot hang
        // indefinitely on a misbehaving signer; items still buffered
        // when the deadline expires are counted as drops on the
        // pipeline's metric so the loss is observable.
        try {
          if (auditPipeline) {
            await auditPipeline.drain(auditPipelineDrainTimeoutMs);
          }
        } catch (err) {
          logger.warn('Error while draining audit pipeline', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        // F-6: close the OCSF transport so any buffered HTTP / file
        // handles are released before exit. `close()` waits for any
        // in-flight `send()` calls so the tail of the audit stream is
        // not lost when the process exits.
        try {
          if (ocsfTransport) {
            await ocsfTransport.close();
          }
        } catch (err) {
          logger.warn('Error while closing OCSF transport', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        // F-2: close the DPoP replay store. Only the Redis-backed
        // implementation owns external resources (`close()` is its
        // own method); the in-memory default omits it, so we
        // structurally check before calling.
        try {
          const closableReplay = dpopReplayStore as { close?: () => Promise<void> | void } | undefined;
          if (closableReplay && typeof closableReplay.close === 'function') {
            await closableReplay.close();
          }
        } catch (err) {
          logger.warn('Error while closing DPoP replay store', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        }
        logger.info('Server closed');
        process.exit(0);
      });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  startServer().catch((error) => {
    // The bootstrap logger may not have been created if env loading failed,
    // so fall back to console here. `initializeServices` and `startServer`
    // are expected to log details before rejecting.
    // eslint-disable-next-line no-console
    console.error('Failed to start Tool Gateway server', error);
    process.exit(1);
  });
}

// Re-export the factory + bootstrap so callers (tests, embedders) can build
// an in-process gateway without going through the singleton entrypoint.
export { createApp, createAdminApp } from './app-factory';
export { initializeServices, type GatewayDependencies } from './bootstrap';

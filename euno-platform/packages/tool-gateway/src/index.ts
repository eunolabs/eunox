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

  const {
    config,
    logger,
    revocationStore,
    epochStore,
    killSwitchManager,
    callCounterStore,
    auditPipeline,
    auditPipelineDrainTimeoutMs,
    ocsfTransport,
    dpopReplayStore,
    ledgerPgPool,
    crossChainAnchor,
    gatewayTelemetry = null,
    auditQueryStore,
    durablePostureEmitter,
  } = deps;

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

    // Compute a single overall shutdown deadline so all six phases share the
    // same budget (auditPipelineDrainTimeoutMs). Each phase receives only the
    // time that remains, preventing a pathological close() in an early phase
    // from silently consuming the budget meant for the audit pipeline drain.
    const shutdownDeadlineMs = Date.now() + auditPipelineDrainTimeoutMs;

    /** Milliseconds left in the overall shutdown budget (never negative). */
    const remaining = (): number => Math.max(0, shutdownDeadlineMs - Date.now());

    /**
     * Races `fn` against the remaining shutdown budget so every close
     * operation is bounded by the same Kubernetes grace window.
     *
     * - **Timeout**: logs `logger.error` — the operator's signal that the
     *   SIGTERM grace window may be exceeded and SIGKILL could discard
     *   buffered data.
     * - **Close error**: logs `logger.warn` — a rejected close() is
     *   typically an already-closed connection or broken pipe and does not
     *   necessarily imply data loss.
     * - **Budget exhausted before start**: logs `logger.error` and returns
     *   immediately so no phase can quietly squander the remaining time.
     *
     * Always resolves so one failed close never blocks subsequent phases.
     * The timer handle is always cleared when `fn` settles first, preventing
     * stale timeout callbacks from firing during later phases.  `fn` is
     * invoked via `Promise.resolve().then()` so that synchronous throws are
     * captured as promise rejections instead of bypassing the race.
     */
    const closeWithTimeout = (
      label: string,
      fn: () => Promise<void>,
    ): Promise<void> => {
      const timeoutMs = remaining();
      if (timeoutMs === 0) {
        logger.error(
          `Shutdown: skipping ${label} — overall budget exhausted; ` +
            'SIGKILL may discard buffered data',
          { label },
        );
        return Promise.resolve();
      }

      let timedOut = false;
      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

      const timer = new Promise<void>((resolve) => {
        timeoutHandle = setTimeout(() => {
          timedOut = true;
          logger.error(
            `Shutdown: timed out closing ${label} after ${timeoutMs} ms — ` +
              'SIGKILL may discard buffered data',
            { label, timeoutMs },
          );
          resolve();
        }, timeoutMs);
        // `unref()` prevents an orphaned timer from keeping the Node event
        // loop alive after process.exit(0) is called. During the active
        // shutdown chain the loop is never empty, so unref() only takes
        // effect at process exit — letting the process exit cleanly instead
        // of waiting out any leftover deadline.
        timeoutHandle.unref();
      });

      // Wrap fn() in Promise.resolve().then() so synchronous throws are
      // converted to rejected promises rather than propagating as unhandled
      // exceptions that could abort the entire shutdown sequence.
      const op = Promise.resolve()
        .then(() => fn())
        .then(
          () => {
            // fn() resolved before the deadline — cancel the pending timer so
            // it does not fire during subsequent phases and log a false error.
            if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
          },
          (err: unknown) => {
            if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
            // Suppress the warning when the deadline already fired: the error
            // would be misleading (the operation was abandoned, not just slow).
            if (!timedOut) {
              logger.warn(`Shutdown: error while closing ${label}`, {
                label,
                error: err instanceof Error ? err.message : String(err),
              });
            }
          },
        );

      return Promise.race([op, timer]);
    };

    const closeServer = (srv: http.Server) =>
      new Promise<void>((resolve, reject) =>
        srv.close((err) => (err ? reject(err) : resolve())),
      );

    // Phase 1: stop accepting new requests.
    void Promise.all([
      closeWithTimeout('HTTP server', () => closeServer(server)),
      closeWithTimeout('admin HTTP server', () => closeServer(adminServer)),
    ]).then(async () => {
      // Phase 2: close lightweight cache/state stores concurrently.
      // These hold no durable write buffers so failures are non-critical.
      await Promise.all([
        ...(revocationStore
          ? [closeWithTimeout('revocation store', () => revocationStore.close())]
          : []),
        ...(epochStore
          ? [closeWithTimeout('epoch store', () => epochStore.close())]
          : []),
        // Use structural checks rather than `instanceof` so any
        // KillSwitchManager / CallCounterStore implementation that holds
        // external resources gets cleaned up without coupling this file to
        // concrete types.
        ...(typeof (killSwitchManager as { close?: unknown }).close === 'function'
          ? [
              closeWithTimeout('kill-switch manager', () =>
                (killSwitchManager as { close(): Promise<void> }).close(),
              ),
            ]
          : []),
        ...(typeof (callCounterStore as { close?: unknown }).close === 'function'
          ? [
              closeWithTimeout('call-counter store', () =>
                Promise.resolve(
                  (callCounterStore as unknown as { close(): Promise<void> | void }).close(),
                ),
              ),
            ]
          : []),
      ]);

      // Phase 3: drain the async audit pipeline — must complete BEFORE
      // closing the ledger backend pool so the signer can flush its last
      // batch. drain(timeoutMs) manages its own bounded timeout internally:
      // it stops accepting new items immediately, counts items still buffered
      // at expiry as metric drops, and resolves (never rejects) once the
      // deadline passes. We pass remaining() rather than a fixed constant so
      // the drain consumes only what is left of the overall shutdown budget.
      try {
        if (auditPipeline) {
          await auditPipeline.drain(remaining());
        }
      } catch (err) {
        logger.warn('Shutdown: error while draining audit pipeline', {
          error: err instanceof Error ? err.message : String(err),
        });
      }

      // Phase 4: close the OCSF transport — `close()` waits for any
      // in-flight `send()` calls so the tail of the audit stream is not
      // lost when the process exits.
      if (ocsfTransport) {
        await closeWithTimeout('OCSF transport', () => ocsfTransport.close());
      }

      // Phase 5: close the DPoP replay store. Only the Redis-backed
      // implementation owns external resources; the in-memory default
      // omits `close()`, so we check structurally.
      const closableReplay = dpopReplayStore as
        | { close?: () => Promise<void> | void }
        | undefined;
      if (closableReplay && typeof closableReplay.close === 'function') {
        await closeWithTimeout('DPoP replay store', () =>
          Promise.resolve(closableReplay.close!()),
        );
      }

      // Phase 5.5: stop the CrossChainAnchor timer and wait for any
      // in-flight commitment to complete before closing the DB pool.
      if (crossChainAnchor) {
        await closeWithTimeout('cross-chain anchor', () => crossChainAnchor.stop());
      }

      // Phase 5.6: stop the hosted-mode telemetry collector — flushes any
      // pending per-tenant stats before the process exits so the final
      // reporting window's events are not silently lost.
      if (gatewayTelemetry) {
        await closeWithTimeout('gateway telemetry', () => gatewayTelemetry.stop());
      }

      // Phase 5.7: stop the durable posture emitter — flushes any events
      // that are still in the SQLite WAL queue before the process exits.
      // Stopping after the telemetry collector and before the DB pool so
      // any pending emitObserved calls triggered by in-flight pipeline
      // records can complete.
      if (durablePostureEmitter) {
        await closeWithTimeout('durable posture emitter', () => durablePostureEmitter.stop());
      }

      // Phase 6: close the ledger Postgres pool LAST — after the pipeline
      // has finished writing so in-flight INSERT transactions can commit
      // before the pool is torn down. A stalled pool.end() will exceed the
      // Kubernetes SIGTERM grace window; the timeout makes this visible as
      // a loud error rather than a silent SIGKILL.
      if (ledgerPgPool) {
        await closeWithTimeout('ledger Postgres pool', () => ledgerPgPool.end());
      }

      // Phase 7: close a dedicated audit-query-store pool when present and
      // owning its own pool (i.e. it was injected via
      // `GatewayDependencies.auditQueryStore` with a separate read-replica
      // pool rather than sharing `ledgerPgPool`).  In the typical bootstrap
      // the store shares the write backend's pool and `close()` is a no-op,
      // but calling it here is always safe: `pool.end()` on an already-ended
      // pool resolves immediately without error.
      if (auditQueryStore && typeof (auditQueryStore as { close?: unknown }).close === 'function') {
        await closeWithTimeout('audit query store', () =>
          (auditQueryStore as { close(): Promise<void> }).close(),
        );
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

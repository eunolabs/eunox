/**
 * DPoP module — DPoP replay store construction.
 *
 * Encapsulates the DPoP replay store creation so `bootstrap.ts` does
 * not need to import DPoP-specific symbols or handle the Redis-vs-in-
 * memory branching logic.
 *
 * The `onError` callback MUST be fully bound when passed here — the
 * late-binding pattern from the pre-R-3 bootstrap has been eliminated.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  createDpopReplayStoreFromEnv,
  DpopReplayStore,
  createLogger,
} from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

export interface DpopModuleResult {
  /** Shared DPoP replay store (F-2). */
  dpopReplayStore: DpopReplayStore;
}

/**
 * Construct the DPoP replay store for this gateway instance.
 *
 * Wires Redis when `REDIS_URL` is set (multi-replica — prevents replay
 * within the acceptance window across replicas) or falls back to an
 * `InMemoryDpopReplayStore` (single-replica / dev). See
 * `RedisDpopReplayStore` for the SET NX semantics that make this
 * race-free.
 *
 * @param onError Fully-bound callback invoked on every Redis error.
 *   The caller MUST pre-bind its metrics counter before calling this
 *   function — unlike the previous late-binding pattern in bootstrap.ts.
 */
export async function buildDpopModule(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  onError: () => void,
): Promise<DpopModuleResult> {
  const dpopReplayStore = await createDpopReplayStoreFromEnv(env, logger, onError);
  return { dpopReplayStore };
}

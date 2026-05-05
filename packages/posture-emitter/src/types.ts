/**
 * Plugin contract for the {@link PostureEmitter}. Each plugin is a
 * thin adapter that maps the canonical {@link AgentInventoryRecord}
 * into the per-surface payload (Defender CSPM custom assessment, AWS
 * Security Hub finding, GCP SCC finding) and submits it to the
 * cloud's posture-management API.
 *
 * The five required record fields (`agentId`, `owningTeam`,
 * `capabilityManifestHash`, `runtime`, `region`) MUST appear in the
 * submitted payload **with exactly those keys** so a single dashboard
 * can correlate records across the three surfaces. See
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § "Per-plugin
 * mapping".
 *
 * Plugins MUST be safe to call concurrently. Plugins SHOULD be
 * idempotent on `record.agentId`: repeated emits for the same agent
 * within a short window must not produce duplicate dashboard entries.
 */
import { AgentInventoryRecord } from '@euno/common';

export interface PostureEmitterPlugin {
  /** Stable identifier used in logs and config (`defender-cspm`, `security-hub`, `scc`, `stdout`). */
  readonly name: string;

  /**
   * Push (or update) an inventory record on the posture surface.
   * MUST throw on failure so the facade can log + isolate the error.
   */
  emitObserved(record: AgentInventoryRecord): Promise<void>;

  /**
   * Mark an agent as revoked on the posture surface. Soft-delete
   * semantics: surfaces should keep the record but flag it as
   * revoked at the supplied timestamp.
   */
  emitRevoked(agentId: string, revokedAt: string): Promise<void>;
}

/** Default per-plugin emit timeout. */
export const DEFAULT_PLUGIN_TIMEOUT_MS = 5_000;

/** Default dedupe window for `emitObserved`. */
export const DEFAULT_DEDUPE_WINDOW_MS = 5 * 60 * 1_000;

/** Default periodic refresh interval (1 hour). */
export const DEFAULT_REFRESH_INTERVAL_MS = 60 * 60 * 1_000;

/** Default delivery worker poll interval (ms). */
export const DEFAULT_DELIVERY_POLL_INTERVAL_MS = 1_000;

/** Default maximum delivery attempts before dead-lettering. */
export const DEFAULT_MAX_ATTEMPTS = 10;

/** Default base back-off interval for exponential retry (ms). */
export const DEFAULT_BACKOFF_BASE_MS = 1_000;

/** Default maximum back-off interval for exponential retry (ms). */
export const DEFAULT_BACKOFF_MAX_MS = 300_000;

/** Default events pulled per delivery worker poll tick. */
export const DEFAULT_DELIVERY_BATCH_SIZE = 50;

/**
 * AI Posture Management inventory feed for Euno.
 *
 * Implements `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`. The
 * {@link PostureEmitter} facade fans out canonical
 * {@link AgentInventoryRecord} updates to one or more
 * {@link PostureEmitterPlugin}s in parallel, isolating per-plugin
 * failures and deduplicating rapid re-issuances of the same agent.
 *
 * The five required parity fields (`agentId`, `owningTeam`,
 * `capabilityManifestHash`, `runtime`, `region`) flow through to
 * each cloud surface under their canonical names so a single
 * dashboard can correlate records across Defender CSPM, Security
 * Hub and SCC without per-cloud aliasing.
 *
 * Failure to emit MUST NOT fail the originating issuance — posture
 * is best-effort observability, not a control-plane gate. Callers
 * either `await emitter.emitObserved(...).catch(...)` or invoke
 * with `.catch(...)` and continue.
 */
import {
  AgentCapabilityManifest,
  AgentInventoryRecord,
  CapabilityConstraint,
  Logger,
  canonicalSha256,
} from '@euno/common';
import {
  DEFAULT_DEDUPE_WINDOW_MS,
  DEFAULT_PLUGIN_TIMEOUT_MS,
  DEFAULT_REFRESH_INTERVAL_MS,
  PostureEmitterPlugin,
} from './types';
import { RecordStore } from './record-store';
import { StdoutPosturePlugin } from './plugins/stdout';
import { DefenderCspmPlugin } from './plugins/defender-cspm';
import { SecurityHubPlugin } from './plugins/security-hub';
import { SccPlugin } from './plugins/scc';

export interface PostureEmitterOptions {
  /** When false the facade short-circuits all emit calls. Defaults to true when constructed directly; `fromEnv` honours `POSTURE_EMITTER_ENABLED`. */
  enabled?: boolean;
  /** Plugins to fan out to. */
  plugins: PostureEmitterPlugin[];
  /** Per-plugin timeout. Defaults to {@link DEFAULT_PLUGIN_TIMEOUT_MS}. */
  pluginTimeoutMs?: number;
  /** Window during which a duplicate `emitObserved` is suppressed. */
  dedupeWindowMs?: number;
  /** Optional logger; warnings are logged when a plugin fails. */
  logger?: Logger;
}

/**
 * Re-export of the shared canonical hash so callers don't reach into
 * `@euno/common` for a single helper. Both this re-export and the
 * audit-log evidence path resolve to the same `canonicalSha256`
 * implementation, guaranteeing posture and audit hashes match for
 * the same manifest. See design doc § 2.
 */
export const hashManifest = canonicalSha256;

export class PostureEmitter {
  private readonly enabled: boolean;
  private readonly plugins: PostureEmitterPlugin[];
  private readonly pluginTimeoutMs: number;
  private readonly store: RecordStore;
  private readonly logger?: Logger;

  constructor(opts: PostureEmitterOptions) {
    this.enabled = opts.enabled !== false;
    this.plugins = [...opts.plugins];
    this.pluginTimeoutMs = opts.pluginTimeoutMs ?? DEFAULT_PLUGIN_TIMEOUT_MS;
    this.store = new RecordStore({
      dedupeWindowMs: opts.dedupeWindowMs ?? DEFAULT_DEDUPE_WINDOW_MS,
    });
    if (opts.logger) this.logger = opts.logger;
  }

  /** True when at least one plugin is configured AND emission is enabled. */
  isEnabled(): boolean {
    return this.enabled && this.plugins.length > 0;
  }

  /**
   * Push (or refresh) an inventory record. Calls fan out to every
   * configured plugin in parallel; per-plugin failures are caught
   * and logged but never propagate.
   *
   * Returns silently when:
   *   - the emitter is disabled,
   *   - the record is a duplicate inside the dedupe window
   *     (lastSeen is still updated locally so the periodic refresh
   *     ships an accurate timestamp later).
   */
  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    if (!this.isEnabled()) return;
    const shouldEmit = this.store.upsert(record);
    if (!shouldEmit) return;
    await this.fanOut('emitObserved', (p) => p.emitObserved(record), { agentId: record.agentId });
  }

  /**
   * Soft-delete an agent record on every configured plugin. The
   * agent stays in the local store with `revokedAt` set so the
   * periodic refresh does not re-emit it as `ACTIVE`.
   */
  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    if (!this.isEnabled()) return;
    this.store.markRevoked(agentId, revokedAt);
    await this.fanOut('emitRevoked', (p) => p.emitRevoked(agentId, revokedAt), { agentId });
  }

  /**
   * Start a periodic timer that re-emits every non-revoked record.
   * Returns a function that stops the timer.
   *
   * The interval is unref'd so it does not keep the Node event loop
   * alive on its own.
   */
  startPeriodicRefresh(intervalMs: number = DEFAULT_REFRESH_INTERVAL_MS): () => void {
    if (!this.isEnabled() || intervalMs <= 0) {
      return () => undefined;
    }
    const timer = setInterval(() => {
      void this.refreshOnce();
    }, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
    return () => clearInterval(timer);
  }

  /**
   * Re-emit every active record exactly once. Exposed for tests.
   *
   * Records are refreshed in parallel — refresh duration scales with
   * the slowest plugin rather than `O(records × plugins)`, so a
   * single refresh tick cannot silently overrun the configured
   * interval as the agent fleet grows.
   */
  async refreshOnce(): Promise<void> {
    if (!this.isEnabled()) return;
    const active = this.store.listActive();
    const nowIso = new Date().toISOString();
    await Promise.all(
      active.map(async (record) => {
        const refreshed: AgentInventoryRecord = { ...record, lastSeen: nowIso };
        // Refresh the cached record's lastSeen before re-emitting it.
        // Dedupe-window checks intentionally do not apply on refresh:
        // the periodic refresh is the very thing keeping cloud
        // surfaces from aging records out, so we always want it to
        // hit the network.
        this.store.upsert(refreshed);
        await this.fanOut(
          'emitObserved (refresh)',
          (p) => p.emitObserved(refreshed),
          { agentId: refreshed.agentId },
        );
      }),
    );
  }

  /** Snapshot of the local store. Exposed for tests / introspection. */
  snapshot(): AgentInventoryRecord[] {
    return this.store.listAll();
  }

  private async fanOut(
    op: string,
    invoke: (plugin: PostureEmitterPlugin) => Promise<void>,
    context: { agentId: string },
  ): Promise<void> {
    await Promise.all(
      this.plugins.map(async (plugin) => {
        try {
          await this.withTimeout(invoke(plugin), this.pluginTimeoutMs, plugin.name);
        } catch (err) {
          // Per design § 5: posture emit failures are best-effort and
          // must never propagate. Log + drop.
          this.logger?.warn?.('posture emit failed', {
            op,
            plugin: plugin.name,
            agentId: context.agentId,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }),
    );
  }

  private withTimeout<T>(p: Promise<T>, ms: number, pluginName: string): Promise<T> {
    if (ms <= 0) return p;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`posture-emitter plugin '${pluginName}' timed out after ${ms}ms`));
      }, ms);
      if (typeof timer.unref === 'function') timer.unref();
      p.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }

  /**
   * Build a canonical {@link AgentInventoryRecord} from the fields
   * commonly available at issuance time. Centralised so the issuer
   * service does not duplicate field-mapping logic.
   */
  static buildRecord(input: {
    agentId: string;
    manifest?: AgentCapabilityManifest;
    capabilities?: CapabilityConstraint[];
    region?: string;
    cloudAccount?: string;
    nowIso?: string;
  }): AgentInventoryRecord {
    const nowIso = input.nowIso ?? new Date().toISOString();
    const owningTeam = input.manifest?.metadata?.owner ?? 'unknown';
    const runtime = input.manifest?.metadata?.runtime ?? 'unknown';
    const region = input.region ?? 'unknown';
    const capabilityManifestHash = input.manifest
      ? hashManifest(input.manifest)
      : hashManifest({ agentId: input.agentId });
    const record: AgentInventoryRecord = {
      schemaVersion: '1.0',
      agentId: input.agentId,
      owningTeam,
      capabilityManifestHash,
      runtime,
      region,
      firstSeen: nowIso,
      lastSeen: nowIso,
    };
    if (input.cloudAccount !== undefined) record.cloudAccount = input.cloudAccount;
    if (input.capabilities !== undefined) record.capabilities = input.capabilities;
    return record;
  }

  /**
   * Construct a {@link PostureEmitter} from environment variables.
   *
   * Recognised vars:
   *   - `POSTURE_EMITTER_ENABLED`        — `true` to activate.
   *   - `POSTURE_EMITTER_PLUGINS`        — comma list of plugin names
   *     (`stdout`, `defender-cspm`, `security-hub`, `scc`). Defaults
   *     to `stdout` so a misconfigured production deployment fails
   *     safe rather than dropping records silently.
   *   - `POSTURE_REFRESH_INTERVAL_MS`    — informational; honour by
   *     calling {@link startPeriodicRefresh}.
   *   - Plugin-specific (only read when the plugin is named):
   *     - `AZURE_SUBSCRIPTION_ID`
   *     - `AWS_ACCOUNT_ID`, `AWS_REGION`, `SECURITY_HUB_PRODUCT_ARN`
   *     - `GCP_SCC_SOURCE_NAME`, `GCP_PROJECT_ID`
   *
   * Returns a disabled emitter (no-op) when `POSTURE_EMITTER_ENABLED`
   * is not `true`, so deployments that have not yet wired posture
   * surfaces continue to function unchanged.
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, logger?: Logger): PostureEmitter {
    const enabled = String(env.POSTURE_EMITTER_ENABLED ?? '').toLowerCase() === 'true';
    if (!enabled) {
      const opts: PostureEmitterOptions = { enabled: false, plugins: [] };
      if (logger) opts.logger = logger;
      return new PostureEmitter(opts);
    }
    const requestedRaw = (env.POSTURE_EMITTER_PLUGINS ?? 'stdout').trim();
    const requested = requestedRaw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);

    const plugins: PostureEmitterPlugin[] = [];
    for (const name of requested) {
      try {
        const plugin = buildPluginFromEnv(name, env);
        if (plugin) plugins.push(plugin);
      } catch (err) {
        logger?.warn?.('posture-emitter plugin disabled: misconfigured', {
          plugin: name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    if (plugins.length === 0) {
      // Degrade to stdout so issuance still records something locally.
      plugins.push(new StdoutPosturePlugin());
    }
    const opts: PostureEmitterOptions = { enabled: true, plugins };
    if (logger) opts.logger = logger;
    return new PostureEmitter(opts);
  }
}

function buildPluginFromEnv(
  name: string,
  env: NodeJS.ProcessEnv,
): PostureEmitterPlugin | undefined {
  switch (name) {
    case 'stdout':
      return new StdoutPosturePlugin();
    case 'defender-cspm': {
      const subscriptionId = env.AZURE_SUBSCRIPTION_ID;
      if (!subscriptionId) {
        throw new Error('AZURE_SUBSCRIPTION_ID is required for defender-cspm plugin');
      }
      return new DefenderCspmPlugin({ subscriptionId });
    }
    case 'security-hub': {
      const awsAccountId = env.AWS_ACCOUNT_ID;
      const region = env.AWS_REGION ?? env.AWS_DEFAULT_REGION;
      const productArn = env.SECURITY_HUB_PRODUCT_ARN;
      if (!awsAccountId || !region || !productArn) {
        throw new Error(
          'AWS_ACCOUNT_ID, AWS_REGION and SECURITY_HUB_PRODUCT_ARN are required for security-hub plugin',
        );
      }
      return new SecurityHubPlugin({ awsAccountId, region, productArn });
    }
    case 'scc': {
      const sourceName = env.GCP_SCC_SOURCE_NAME;
      const projectId = env.GCP_PROJECT_ID;
      if (!sourceName || !projectId) {
        throw new Error('GCP_SCC_SOURCE_NAME and GCP_PROJECT_ID are required for scc plugin');
      }
      return new SccPlugin({ sourceName, projectId });
    }
    default:
      throw new Error(`Unknown posture-emitter plugin: '${name}'`);
  }
}

export {
  PostureEmitterPlugin,
  DEFAULT_DEDUPE_WINDOW_MS,
  DEFAULT_PLUGIN_TIMEOUT_MS,
  DEFAULT_REFRESH_INTERVAL_MS,
  DEFAULT_DELIVERY_POLL_INTERVAL_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BACKOFF_BASE_MS,
  DEFAULT_BACKOFF_MAX_MS,
  DEFAULT_DELIVERY_BATCH_SIZE,
} from './types';
export { RecordStore } from './record-store';
export { redactForPosture, RedactOptions } from './redact';
export { StdoutPosturePlugin, StdoutPluginOptions } from './plugins/stdout';
export { DefenderCspmPlugin, DefenderCspmPluginOptions, DefenderCspmClient } from './plugins/defender-cspm';
export { SecurityHubPlugin, SecurityHubPluginOptions, SecurityHubClient } from './plugins/security-hub';
export { SccPlugin, SccPluginOptions, SccClient } from './plugins/scc';
export { DurableQueue, DurableQueueOptions, QueuedEvent, QueuedEventType } from './durable-queue';
export { DeliveryWorker, DeliveryWorkerOptions, DeliveryMetricsHooks } from './delivery-worker';
export {
  DurablePostureEmitter,
  DurablePostureEmitterOptions,
  hashManifest as hashManifestDurable,
} from './durable-emitter';

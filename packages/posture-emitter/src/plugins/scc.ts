/**
 * GCP Security Command Center (SCC) posture-emitter plugin.
 *
 * Each {@link AgentInventoryRecord} becomes an SCC `Finding` of
 * `category` `EUNO_AGENT_INVENTORY` under an operator-configured
 * custom `source`. The five required parity fields are placed in
 * `sourceProperties` under their canonical names — see
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 4.
 *
 * The GCP SDK is lazy-loaded via `require()` so deployments using
 * only Azure / AWS plugins do not need `@google-cloud/security-center`
 * installed.
 */
import { AgentInventoryRecord } from '@euno/common';
import { PostureEmitterPlugin } from '../types';
import { redactForPosture, RedactOptions } from '../redact';

export interface SccPluginOptions extends RedactOptions {
  /** Full SCC source resource name, e.g. `organizations/123/sources/456`. */
  sourceName: string;
  /** GCP project the agent runs in (recorded as `resourceName`). */
  projectId: string;
  /**
   * Test seam — when supplied, used in place of
   * `new SecurityCenterClient()`. The shape matches the subset of
   * the SDK actually called.
   */
  clientFactory?: () => SccClient;
}

/** Minimal subset of `@google-cloud/security-center` used by this plugin. */
export interface SccClient {
  createFinding(request: Record<string, unknown>): Promise<unknown>;
  updateFinding(request: Record<string, unknown>): Promise<unknown>;
}

const FINDING_CATEGORY = 'EUNO_AGENT_INVENTORY';

export class SccPlugin implements PostureEmitterPlugin {
  readonly name = 'scc';
  private readonly sourceName: string;
  private readonly projectId: string;
  private readonly clientFactory: () => SccClient;
  private readonly redactOptions: RedactOptions;
  private cachedClient: SccClient | undefined;

  constructor(opts: SccPluginOptions) {
    if (!opts.sourceName) throw new Error('SccPlugin: sourceName is required');
    if (!opts.projectId) throw new Error('SccPlugin: projectId is required');
    this.sourceName = opts.sourceName;
    this.projectId = opts.projectId;
    this.clientFactory = opts.clientFactory ?? (() => this.createDefaultClient());
    this.redactOptions = {
      includeCloudAccount: opts.includeCloudAccount === true,
      includeManifestUri: opts.includeManifestUri === true,
      includeCapabilities: opts.includeCapabilities === true,
    };
  }

  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    const client = this.getClient();
    const payload = redactForPosture(record, this.redactOptions);
    const finding = {
      parent: this.sourceName,
      findingId: sanitizeFindingId(record.agentId),
      finding: {
        state: 'ACTIVE',
        category: FINDING_CATEGORY,
        findingClass: 'OBSERVATION',
        eventTime: { seconds: Math.floor(Date.parse(record.lastSeen) / 1000) || 0 },
        resourceName: `//cloudresourcemanager.googleapis.com/projects/${this.projectId}`,
        sourceProperties: toSourceProperties(payload),
      },
    };
    // SCC's createFinding is idempotent on (parent, findingId) — a
    // pre-existing finding becomes ALREADY_EXISTS, in which case the
    // caller should fall back to update. The SDK surfaces this as a
    // `code: 6` error.
    try {
      await client.createFinding(finding);
    } catch (err) {
      if (isAlreadyExists(err)) {
        await client.updateFinding({
          finding: {
            name: `${this.sourceName}/findings/${sanitizeFindingId(record.agentId)}`,
            state: 'ACTIVE',
            category: FINDING_CATEGORY,
            findingClass: 'OBSERVATION',
            eventTime: finding.finding.eventTime,
            sourceProperties: toSourceProperties(payload),
          },
        });
        return;
      }
      throw err;
    }
  }

  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    const client = this.getClient();
    await client.updateFinding({
      finding: {
        name: `${this.sourceName}/findings/${sanitizeFindingId(agentId)}`,
        state: 'INACTIVE',
        category: FINDING_CATEGORY,
        findingClass: 'OBSERVATION',
        eventTime: { seconds: Math.floor(Date.parse(revokedAt) / 1000) || 0 },
        sourceProperties: { agentId, revokedAt },
      },
    });
  }

  private getClient(): SccClient {
    if (!this.cachedClient) {
      this.cachedClient = this.clientFactory();
    }
    return this.cachedClient;
  }

  private createDefaultClient(): SccClient {
    /* eslint-disable @typescript-eslint/no-var-requires */
    const { SecurityCenterClient } = require('@google-cloud/security-center');
    /* eslint-enable @typescript-eslint/no-var-requires */
    return new SecurityCenterClient() as SccClient;
  }
}

/**
 * SCC findingId must be `[A-Za-z0-9_-]{1,32}`. Most euno agent IDs
 * are UUID-like, but defensive sanitisation guards against operators
 * using characters outside that set (e.g. `:` in `did:web:...`).
 */
function sanitizeFindingId(agentId: string): string {
  const cleaned = agentId.replace(/[^A-Za-z0-9_-]/g, '_');
  return cleaned.length <= 32 ? cleaned : cleaned.slice(0, 32);
}

function toSourceProperties(record: AgentInventoryRecord): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

function isAlreadyExists(err: unknown): boolean {
  if (typeof err === 'object' && err !== null) {
    const code = (err as { code?: unknown }).code;
    if (code === 6 || code === 'ALREADY_EXISTS') return true;
  }
  return false;
}

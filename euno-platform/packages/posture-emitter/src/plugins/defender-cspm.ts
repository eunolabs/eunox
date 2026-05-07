/**
 * Azure Defender CSPM posture-emitter plugin.
 *
 * Pushes a custom asset / assessment record to Microsoft Defender
 * for Cloud's inventory surface so operators using Defender CSPM's
 * AI security posture management view see every euno-issued agent.
 *
 * **Operationally available path** (until the native AI-posture
 * REST API is GA): submit a `customAssessment` under the operator's
 * subscription. The five required parity fields are emitted under
 * their canonical names inside the assessment's `additionalData`
 * bag — see `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 4.
 *
 * The Azure SDK is lazy-loaded via `require()` so deployments using
 * only AWS / GCP plugins do not need `@azure/arm-security` or
 * `@azure/identity` installed.
 */
import { AgentInventoryRecord } from '@euno/common';
import { PostureEmitterPlugin } from '../types';
import { redactForPosture, RedactOptions } from '../redact';

export interface DefenderCspmPluginOptions extends RedactOptions {
  /** Subscription that owns the custom assessment. */
  subscriptionId: string;
  /** Stable assessment-name prefix; `agentId` is appended. Defaults to `euno-agent-`. */
  assessmentNamePrefix?: string;
  /**
   * Test seam — when supplied, used in place of
   * `new SecurityCenter(credential, subscriptionId)`. The shape
   * matches the subset of the SDK actually called.
   */
  clientFactory?: () => DefenderCspmClient;
}

/** Minimal subset of `@azure/arm-security` used by this plugin. */
export interface DefenderCspmClient {
  assessments: {
    createOrUpdate(
      resourceId: string,
      assessmentName: string,
      assessment: Record<string, unknown>,
    ): Promise<unknown>;
    delete(resourceId: string, assessmentName: string): Promise<unknown>;
  };
}

export class DefenderCspmPlugin implements PostureEmitterPlugin {
  readonly name = 'defender-cspm';
  private readonly subscriptionId: string;
  private readonly assessmentNamePrefix: string;
  private readonly clientFactory: () => DefenderCspmClient;
  private readonly redactOptions: RedactOptions;
  private cachedClient: DefenderCspmClient | undefined;

  constructor(opts: DefenderCspmPluginOptions) {
    if (!opts.subscriptionId) {
      throw new Error('DefenderCspmPlugin: subscriptionId is required');
    }
    this.subscriptionId = opts.subscriptionId;
    this.assessmentNamePrefix = opts.assessmentNamePrefix ?? 'euno-agent-';
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
    const resourceId = `/subscriptions/${this.subscriptionId}`;
    const assessmentName = this.assessmentNamePrefix + record.agentId;
    // The five required parity fields are placed at the top of
    // `additionalData` under their canonical names — no renaming.
    const assessment = {
      properties: {
        displayName: `Euno agent ${record.agentId}`,
        status: { code: 'Healthy' },
        additionalData: payload as unknown as Record<string, unknown>,
      },
    };
    await client.assessments.createOrUpdate(resourceId, assessmentName, assessment);
  }

  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    const client = this.getClient();
    const resourceId = `/subscriptions/${this.subscriptionId}`;
    const assessmentName = this.assessmentNamePrefix + agentId;
    // Soft delete: re-emit with NotApplicable + revokedAt rather than
    // calling delete(), so the operator dashboard still surfaces the
    // historical record.
    await client.assessments.createOrUpdate(resourceId, assessmentName, {
      properties: {
        displayName: `Euno agent ${agentId} (revoked)`,
        status: { code: 'NotApplicable', cause: 'Revoked' },
        additionalData: { agentId, revokedAt },
      },
    });
  }

  private getClient(): DefenderCspmClient {
    if (!this.cachedClient) {
      this.cachedClient = this.clientFactory();
    }
    return this.cachedClient;
  }

  private createDefaultClient(): DefenderCspmClient {
    // Lazy require so deployments without Azure plugins don't pay the
    // SDK install cost.
    /* eslint-disable @typescript-eslint/no-var-requires */
    const { SecurityCenter } = require('@azure/arm-security');
    const { DefaultAzureCredential } = require('@azure/identity');
    /* eslint-enable @typescript-eslint/no-var-requires */
    const credential = new DefaultAzureCredential();
    return new SecurityCenter(credential, this.subscriptionId) as DefenderCspmClient;
  }
}

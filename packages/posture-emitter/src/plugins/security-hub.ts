/**
 * AWS Security Hub posture-emitter plugin.
 *
 * Each {@link AgentInventoryRecord} is shipped to Security Hub as a
 * custom finding via `BatchImportFindings`. The five required parity
 * fields are flattened into `ProductFields` and `Resources[].Tags`
 * with their canonical names (no renaming) so a single dashboard
 * view can correlate the record across the three clouds — see
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 4.
 *
 * The AWS SDK is lazy-loaded via `require()` so deployments using
 * only Azure / GCP plugins do not need `@aws-sdk/client-securityhub`
 * installed.
 */
import { AgentInventoryRecord } from '@euno/common';
import { PostureEmitterPlugin } from '../types';
import { redactForPosture, RedactOptions } from '../redact';

export interface SecurityHubPluginOptions extends RedactOptions {
  /** AWS account that owns the findings. */
  awsAccountId: string;
  /** AWS region (Security Hub is regional). */
  region: string;
  /** ARN of the registered Security Hub product for euno findings. */
  productArn: string;
  /** GeneratorId stamped on every finding. Defaults to `euno/posture-emitter/v1`. */
  generatorId?: string;
  /**
   * Test seam — when supplied, used in place of
   * `new BatchImportFindingsCommand(input)`. Allows unit tests to
   * avoid loading the AWS SDK entirely.
   */
  commandFactory?: (input: unknown) => { input: unknown };
  /**
   * Test seam — when supplied, used in place of
   * `new SecurityHubClient({ region })`. The shape matches the
   * subset of the SDK actually called.
   */
  clientFactory?: () => SecurityHubClient;
}

/** Minimal subset of `@aws-sdk/client-securityhub` used by this plugin. */
export interface SecurityHubClient {
  send(command: { input: unknown }): Promise<unknown>;
}

/** Type of the finding for `Types[]`. */
const FINDING_TYPE =
  'Software and Configuration Checks/AWS Security Best Practices/AI-Inventory';

export class SecurityHubPlugin implements PostureEmitterPlugin {
  readonly name = 'security-hub';
  private readonly awsAccountId: string;
  private readonly region: string;
  private readonly productArn: string;
  private readonly generatorId: string;
  private readonly clientFactory: () => SecurityHubClient;
  private readonly commandFactory: (input: unknown) => { input: unknown };
  private readonly redactOptions: RedactOptions;
  private cachedClient: SecurityHubClient | undefined;

  constructor(opts: SecurityHubPluginOptions) {
    if (!opts.awsAccountId) {
      throw new Error('SecurityHubPlugin: awsAccountId is required');
    }
    if (!opts.region) throw new Error('SecurityHubPlugin: region is required');
    if (!opts.productArn) throw new Error('SecurityHubPlugin: productArn is required');
    this.awsAccountId = opts.awsAccountId;
    this.region = opts.region;
    this.productArn = opts.productArn;
    this.generatorId = opts.generatorId ?? 'euno/posture-emitter/v1';
    this.clientFactory = opts.clientFactory ?? (() => this.createDefaultClient());
    this.commandFactory =
      opts.commandFactory ?? ((input) => this.createDefaultCommand(input));
    this.redactOptions = {
      includeCloudAccount: opts.includeCloudAccount === true,
      includeManifestUri: opts.includeManifestUri === true,
      includeCapabilities: opts.includeCapabilities === true,
    };
  }

  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    const payload = redactForPosture(record, this.redactOptions);
    const finding = this.buildFinding(record, payload, /* revoked */ false);
    await this.send({ Findings: [finding] });
  }

  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    // Soft delete: emit a finding update with workflow `RESOLVED` and
    // `revokedAt` in ProductFields so dashboards can flag-but-keep.
    const finding = {
      SchemaVersion: '2018-10-08',
      Id: this.findingId(agentId),
      ProductArn: this.productArn,
      GeneratorId: this.generatorId,
      AwsAccountId: this.awsAccountId,
      Types: [FINDING_TYPE],
      CreatedAt: revokedAt,
      UpdatedAt: revokedAt,
      Severity: { Label: 'INFORMATIONAL' as const },
      Title: `Euno agent ${agentId} revoked`,
      Description: `Euno agent ${agentId} was revoked at ${revokedAt}`,
      Workflow: { Status: 'RESOLVED' as const },
      ProductFields: { agentId, revokedAt },
      Resources: [
        {
          Type: 'Other',
          Id: `euno-agent:${agentId}`,
          Region: this.region,
        },
      ],
    };
    await this.send({ Findings: [finding] });
  }

  private buildFinding(
    record: AgentInventoryRecord,
    payload: AgentInventoryRecord,
    revoked: boolean,
  ): Record<string, unknown> {
    // Security Hub `ProductFields` requires string-typed values.
    const productFields = flattenStringMap(payload);
    const tags = {
      agentId: record.agentId,
      owningTeam: record.owningTeam,
      capabilityManifestHash: record.capabilityManifestHash,
      runtime: record.runtime,
      region: record.region,
    };
    return {
      SchemaVersion: '2018-10-08',
      Id: this.findingId(record.agentId),
      ProductArn: this.productArn,
      GeneratorId: this.generatorId,
      AwsAccountId: this.awsAccountId,
      Types: [FINDING_TYPE],
      CreatedAt: record.firstSeen,
      UpdatedAt: record.lastSeen,
      Severity: { Label: 'INFORMATIONAL' as const },
      Title: `Euno agent ${record.agentId}`,
      Description: `Euno-issued agent owned by team ${record.owningTeam}`,
      Workflow: { Status: revoked ? 'RESOLVED' : 'NEW' },
      ProductFields: productFields,
      Resources: [
        {
          Type: 'Other',
          Id: `euno-agent:${record.agentId}`,
          Region: record.region || this.region,
          Tags: tags,
        },
      ],
    };
  }

  private findingId(agentId: string): string {
    return `euno-agent/${agentId}`;
  }

  private async send(input: unknown): Promise<void> {
    const client = this.getClient();
    const command = this.commandFactory(input);
    await client.send(command);
  }

  private getClient(): SecurityHubClient {
    if (!this.cachedClient) {
      this.cachedClient = this.clientFactory();
    }
    return this.cachedClient;
  }

  private createDefaultClient(): SecurityHubClient {
    /* eslint-disable @typescript-eslint/no-var-requires */
    const { SecurityHubClient: Client } = require('@aws-sdk/client-securityhub');
    /* eslint-enable @typescript-eslint/no-var-requires */
    return new Client({ region: this.region }) as SecurityHubClient;
  }

  private createDefaultCommand(input: unknown): { input: unknown } {
    /* eslint-disable @typescript-eslint/no-var-requires */
    const { BatchImportFindingsCommand } = require('@aws-sdk/client-securityhub');
    /* eslint-enable @typescript-eslint/no-var-requires */
    return new BatchImportFindingsCommand(input);
  }
}

/**
 * Convert a record into Security Hub's required `Map<string, string>`
 * shape for `ProductFields`. Non-scalar values are JSON-stringified.
 */
function flattenStringMap(record: AgentInventoryRecord): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(record)) {
    if (v === undefined || v === null) continue;
    out[k] = typeof v === 'string' ? v : JSON.stringify(v);
  }
  return out;
}

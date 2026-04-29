/**
 * Stdout posture-emitter plugin.
 *
 * Logs each inventory record as a single-line JSON document on
 * stdout. Used as the default plugin in dev environments, and as a
 * safe no-op in deployments without any cloud posture-management
 * configuration so the issuance pipeline does not break.
 *
 * The output line is prefixed with `posture-emitter:` so log
 * aggregators can filter / route on it without a custom appender.
 */
import { AgentInventoryRecord } from '@euno/common';
import { PostureEmitterPlugin } from '../types';
import { redactForPosture, RedactOptions } from '../redact';

export interface StdoutPluginOptions extends RedactOptions {
  /** Override the default `console.log` sink — used by tests. */
  sink?: (line: string) => void;
}

export class StdoutPosturePlugin implements PostureEmitterPlugin {
  readonly name = 'stdout';
  private readonly sink: (line: string) => void;
  private readonly redactOptions: RedactOptions;

  constructor(opts: StdoutPluginOptions = {}) {
    this.sink = opts.sink ?? ((line) => {
      // eslint-disable-next-line no-console
      console.log(line);
    });
    this.redactOptions = {
      includeCloudAccount: opts.includeCloudAccount === true,
      includeManifestUri: opts.includeManifestUri === true,
      includeCapabilities: opts.includeCapabilities === true,
    };
  }

  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    const payload = redactForPosture(record, this.redactOptions);
    this.sink(`posture-emitter: ${JSON.stringify({ event: 'observed', record: payload })}`);
  }

  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    this.sink(
      `posture-emitter: ${JSON.stringify({ event: 'revoked', agentId, revokedAt })}`,
    );
  }
}

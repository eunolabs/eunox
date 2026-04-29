/**
 * Storage-grant pipeline factory + dispatch. See
 * `docs/sprint-3-4-gaps/07-storage-grants.md` for the full design.
 *
 * The `StorageGrantService` selects the right per-cloud minter from a
 * parsed `storage://...` resource URI, applies the operator-side TTL
 * cap, and returns a {@link StorageGrant} the issuer can attach to the
 * `IssueCapabilityResponse`.
 *
 * The service is **disabled by default** to preserve existing behavior
 * for deployments that have not yet wired cloud-storage IAM. Enable
 * via `STORAGE_GRANTS_ENABLED=true`.
 */

import {
  Action,
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  Logger,
  StorageGrant,
} from '@euno/common';
import {
  StorageGrantMinter,
  StorageGrantMintInput,
  STORAGE_GRANT_DEFAULT_MAX_TTL_SECONDS,
  STORAGE_GRANT_HARD_MAX_TTL_SECONDS,
} from './types';
import { parseStorageUri } from './parse-uri';
import { AzureStorageGrantMinter } from './azure';
import { AwsStorageGrantMinter } from './aws';
import { GcpStorageGrantMinter } from './gcp';

export interface StorageGrantServiceOptions {
  /** Whether the service is active. Defaults to false. */
  enabled?: boolean;
  /** Operator-configured maximum TTL (capped at the hard 1h ceiling). */
  maxTtlSeconds?: number;
  /** Per-cloud minters. Caller may register only the clouds it uses. */
  minters?: Partial<Record<'azure-blob' | 's3' | 'gcs', StorageGrantMinter>>;
  /** Optional logger for warnings about non-canonical URIs. */
  logger?: Logger;
}

export class StorageGrantService {
  private readonly enabled: boolean;
  private readonly maxTtlSeconds: number;
  private readonly minters: Map<string, StorageGrantMinter>;
  private readonly logger?: Logger;

  constructor(opts: StorageGrantServiceOptions = {}) {
    this.enabled = opts.enabled === true;
    const requested = opts.maxTtlSeconds ?? STORAGE_GRANT_DEFAULT_MAX_TTL_SECONDS;
    this.maxTtlSeconds = Math.min(
      Math.max(1, Math.floor(requested)),
      STORAGE_GRANT_HARD_MAX_TTL_SECONDS,
    );
    this.minters = new Map();
    const provided = opts.minters ?? {};
    for (const key of Object.keys(provided) as ('azure-blob' | 's3' | 'gcs')[]) {
      const m = provided[key];
      if (m) this.minters.set(key, m);
    }
    if (opts.logger) {
      this.logger = opts.logger;
    }
  }

  /** True if the service is active and at least one minter is registered. */
  isEnabled(): boolean {
    return this.enabled && this.minters.size > 0;
  }

  /**
   * Build the default service from environment configuration. Each
   * per-cloud minter is registered only when its required configuration
   * variables are present, matching the design's "config-driven, not
   * code-driven" principle.
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, logger?: Logger): StorageGrantService {
    const enabled = String(env.STORAGE_GRANTS_ENABLED ?? '').toLowerCase() === 'true';
    const maxTtl = Number(env.STORAGE_GRANT_MAX_TTL_SECONDS ?? '');
    const minters: NonNullable<StorageGrantServiceOptions['minters']> = {};
    if (enabled) {
      // Azure is the default — no extra config strictly required.
      minters['azure-blob'] = new AzureStorageGrantMinter();
      const region = env.AWS_REGION ?? env.AWS_DEFAULT_REGION;
      const assumeRoleArn = env.AWS_STORAGE_GRANT_ROLE_ARN;
      const awsOpts: { region?: string; assumeRoleArn?: string } = {};
      if (region) awsOpts.region = region;
      if (assumeRoleArn) awsOpts.assumeRoleArn = assumeRoleArn;
      minters['s3'] = new AwsStorageGrantMinter(awsOpts);
      minters['gcs'] = new GcpStorageGrantMinter();
    }
    const opts: StorageGrantServiceOptions = {
      enabled,
      minters,
    };
    if (Number.isFinite(maxTtl) && maxTtl > 0) opts.maxTtlSeconds = maxTtl;
    if (logger) opts.logger = logger;
    return new StorageGrantService(opts);
  }

  /**
   * Inspect the granted capabilities and mint a storage grant for every
   * one whose `resource` is a canonical `storage://...` URI. Returns
   * `undefined` when the service is disabled or when no eligible
   * capabilities are present so callers can attach `storageGrants` only
   * when meaningful.
   *
   * Per the design, a single mint failure aborts the entire issuance —
   * partial grants give the agent a misleading view of what it can
   * access.
   */
  async mintForCapabilities(
    capabilities: CapabilityConstraint[],
    context: { agentId: string; authorizedBy: string; capabilityTtlSeconds: number },
  ): Promise<StorageGrant[] | undefined> {
    if (!this.isEnabled()) return undefined;

    const eligible: { cap: CapabilityConstraint; provider: 'azure-blob' | 's3' | 'gcs' }[] = [];
    for (const cap of capabilities) {
      if (typeof cap.resource !== 'string' || !cap.resource.startsWith('storage://')) {
        continue;
      }
      const parsed = parseStorageUri(cap.resource);
      if (!parsed) {
        // Non-canonical storage URI — audited and skipped per design § 1.
        this.logger?.warn?.('storage_grant_skipped: non_canonical_uri', {
          resource: cap.resource,
        });
        continue;
      }
      eligible.push({ cap, provider: parsed.cloud });
    }
    if (eligible.length === 0) return undefined;

    const ttlSeconds = Math.min(context.capabilityTtlSeconds, this.maxTtlSeconds);
    const grants: StorageGrant[] = [];
    for (const { cap, provider } of eligible) {
      const minter = this.minters.get(provider);
      if (!minter) {
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `No storage-grant minter registered for cloud '${provider}'`,
          500,
        );
      }
      const input: StorageGrantMintInput = {
        resource: cap.resource,
        actions: cap.actions as Action[],
        ttlSeconds,
        agentId: context.agentId,
        authorizedBy: context.authorizedBy,
      };
      try {
        const grant = await minter.mint(input);
        grants.push(grant);
      } catch (err) {
        if (err instanceof CapabilityError) throw err;
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `Storage grant mint failed for ${cap.resource}: ${err instanceof Error ? err.message : 'unknown error'}`,
          502,
        );
      }
    }
    return grants;
  }
}

export { parseStorageUri } from './parse-uri';
export {
  StorageGrantMinter,
  StorageGrantMintInput,
  ParsedStorageUri,
  STORAGE_GRANT_HARD_MAX_TTL_SECONDS,
  STORAGE_GRANT_DEFAULT_MAX_TTL_SECONDS,
} from './types';
export { AzureStorageGrantMinter } from './azure';
export { AwsStorageGrantMinter } from './aws';
export { GcpStorageGrantMinter } from './gcp';

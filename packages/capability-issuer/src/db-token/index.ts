/**
 * DB-token pipeline factory + dispatch. See
 * `docs/sprint-3-4-gaps/08-db-token-issuance.md` for the full design.
 *
 * Disabled by default. Enable via `DB_TOKENS_ENABLED=true` and provide
 * the operator-side instance config via `DB_INSTANCES_FILE`.
 */

import {
  Action,
  CapabilityConstraint,
  CapabilityError,
  DbCredential,
  DbProvider,
  ErrorCode,
  Logger,
  RoleCapabilityPolicy,
} from '@euno/common';
import {
  DbInstanceConfig,
  DbTokenMinter,
  DbTokenMintInput,
  DB_TOKEN_DEFAULT_MAX_TTL_SECONDS,
  DB_TOKEN_HARD_MAX_TTL_SECONDS,
} from './types';
import { parseDbUri } from './parse-uri';
import { loadDbInstancesFromFile } from './instances';
import { AzureSqlTokenMinter } from './azure-sql';
import { RdsTokenMinter } from './rds';
import { CloudSqlTokenMinter } from './cloudsql';

export interface DbTokenServiceOptions {
  enabled?: boolean;
  maxTtlSeconds?: number;
  /** Per-cloud minters keyed by provider. */
  minters?: Partial<Record<DbProvider, DbTokenMinter>>;
  /** Operator-declared instances, keyed by `id`. */
  instances?: Map<string, DbInstanceConfig>;
  logger?: Logger;
}

export class DbTokenService {
  private readonly enabled: boolean;
  private readonly maxTtlSeconds: number;
  private readonly minters: Map<DbProvider, DbTokenMinter>;
  private readonly instances: Map<string, DbInstanceConfig>;
  private readonly logger?: Logger;

  constructor(opts: DbTokenServiceOptions = {}) {
    this.enabled = opts.enabled === true;
    const requested = opts.maxTtlSeconds ?? DB_TOKEN_DEFAULT_MAX_TTL_SECONDS;
    this.maxTtlSeconds = Math.min(
      Math.max(1, Math.floor(requested)),
      DB_TOKEN_HARD_MAX_TTL_SECONDS,
    );
    this.minters = new Map();
    const provided = opts.minters ?? {};
    for (const key of Object.keys(provided) as DbProvider[]) {
      const m = provided[key];
      if (m) this.minters.set(key, m);
    }
    this.instances = opts.instances ?? new Map();
    if (opts.logger) {
      this.logger = opts.logger;
    }
  }

  isEnabled(): boolean {
    return this.enabled && this.minters.size > 0;
  }

  /**
   * Build the default service from environment configuration.
   * Returns a disabled service when `DB_TOKENS_ENABLED!=true`.
   * Throws if enabled but `DB_INSTANCES_FILE` is missing or invalid —
   * the issuer must fail fast at startup rather than serve with an
   * empty (effectively allow-nothing) instance list.
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, logger?: Logger): DbTokenService {
    const enabled = String(env.DB_TOKENS_ENABLED ?? '').toLowerCase() === 'true';
    const maxTtl = Number(env.DB_TOKEN_MAX_TTL_SECONDS ?? '');
    const opts: DbTokenServiceOptions = { enabled };
    if (Number.isFinite(maxTtl) && maxTtl > 0) opts.maxTtlSeconds = maxTtl;
    if (logger) opts.logger = logger;

    if (!enabled) {
      return new DbTokenService(opts);
    }

    const instancesFile = env.DB_INSTANCES_FILE;
    if (!instancesFile) {
      throw new Error(
        'DB_TOKENS_ENABLED=true but DB_INSTANCES_FILE is not set; refusing to start with no permitted instances',
      );
    }
    opts.instances = loadDbInstancesFromFile(instancesFile);
    // When AWS_DB_TOKEN_ROLE_ARN is set, the RDS minter assumes that
    // dedicated role before calling rds:GenerateDbAuthToken so the
    // DB-token code path is isolated from the issuer's ambient IAM
    // credentials (which may include broader KMS grants for JWT signing).
    const rdsAssumeRoleArn = env.AWS_DB_TOKEN_ROLE_ARN || undefined;
    opts.minters = {
      'azure-sql': new AzureSqlTokenMinter(),
      'rds-iam': new RdsTokenMinter(rdsAssumeRoleArn ? { assumeRoleArn: rdsAssumeRoleArn } : {}),
      'cloudsql-iam': new CloudSqlTokenMinter(),
    };
    return new DbTokenService(opts);
  }

  /**
   * Mint a DB credential for every capability whose `resource` is a
   * canonical `db://...` URI. Returns `undefined` when the service is
   * disabled or when no eligible capabilities are present.
   *
   * The agent's `dbUsername` is resolved from the requesting user's
   * roles via {@link RoleCapabilityPolicy.dbUsernamesByRole}. When no
   * role maps to a `dbUsername`, issuance fails with
   * `INSUFFICIENT_PERMISSIONS` — the agent must NEVER be able to
   * choose its DB principal (design § Risks).
   */
  async mintForCapabilities(
    capabilities: CapabilityConstraint[],
    context: {
      agentId: string;
      authorizedBy: string;
      capabilityTtlSeconds: number;
      userRoles: string[];
      policy: RoleCapabilityPolicy;
    },
  ): Promise<DbCredential[] | undefined> {
    if (!this.isEnabled()) return undefined;

    const eligible: { cap: CapabilityConstraint; instance: DbInstanceConfig; database: string }[] = [];
    for (const cap of capabilities) {
      if (typeof cap.resource !== 'string' || !cap.resource.startsWith('db://')) continue;
      const parsed = parseDbUri(cap.resource);
      if (!parsed) {
        this.logger?.warn?.('db_token_skipped: non_canonical_uri', { resource: cap.resource });
        continue;
      }
      const instance = this.instances.get(parsed.instance);
      if (!instance) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `DB instance '${parsed.instance}' is not declared in DB_INSTANCES_FILE`,
          400,
        );
      }
      if (instance.provider !== parsed.cloud) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `DB instance '${parsed.instance}' provider '${instance.provider}' does not match URI cloud '${parsed.cloud}'`,
          400,
        );
      }
      if (!instance.databases.includes(parsed.database)) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Database '${parsed.database}' is not declared on DB instance '${parsed.instance}'`,
          400,
        );
      }
      eligible.push({ cap, instance, database: parsed.database });
    }
    if (eligible.length === 0) return undefined;

    const dbUsername = resolveDbUsername(context.userRoles, context.policy);
    if (!dbUsername) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'No role grants a database principal (dbUsernamesByRole). Cannot mint DB token.',
        403,
      );
    }

    const ttlSeconds = Math.min(context.capabilityTtlSeconds, this.maxTtlSeconds);
    const creds: DbCredential[] = [];
    for (const { cap, instance, database } of eligible) {
      const minter = this.minters.get(instance.provider);
      if (!minter) {
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `No DB-token minter registered for provider '${instance.provider}'`,
          500,
        );
      }
      const input: DbTokenMintInput = {
        resource: cap.resource,
        actions: cap.actions as Action[],
        ttlSeconds,
        agentId: context.agentId,
        authorizedBy: context.authorizedBy,
        dbUsername,
        instance,
        database,
      };
      try {
        creds.push(await minter.mint(input));
      } catch (err) {
        if (err instanceof CapabilityError) throw err;
        throw new CapabilityError(
          ErrorCode.INTERNAL_ERROR,
          `DB token mint failed for ${cap.resource}: ${err instanceof Error ? err.message : 'unknown error'}`,
          502,
        );
      }
    }
    return creds;
  }
}

/**
 * First-role-wins lookup of the IAM-mapped DB principal. Iteration
 * order matches `userContext.roles` so the policy author can
 * disambiguate by ordering roles deliberately.
 */
function resolveDbUsername(
  userRoles: string[],
  policy: RoleCapabilityPolicy,
): string | undefined {
  const map = policy.dbUsernamesByRole;
  if (!map) return undefined;
  for (const role of userRoles) {
    const u = map[role];
    if (u) return u;
  }
  return undefined;
}

export { parseDbUri } from './parse-uri';
export {
  loadDbInstancesFromFile,
  validateInstancesDocument,
} from './instances';
export {
  DbTokenMinter,
  DbTokenMintInput,
  DbInstanceConfig,
  ParsedDbUri,
  DB_TOKEN_HARD_MAX_TTL_SECONDS,
  DB_TOKEN_DEFAULT_MAX_TTL_SECONDS,
} from './types';
export { AzureSqlTokenMinter } from './azure-sql';
export { RdsTokenMinter, RDS_IAM_TOKEN_LIFETIME_SECONDS } from './rds';
export { CloudSqlTokenMinter, CLOUD_SQL_DEFAULT_TOKEN_LIFETIME_SECONDS } from './cloudsql';

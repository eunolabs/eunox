/**
 * Shared types for the DB-token minter pipeline. See
 * `docs/sprint-3-4-gaps/08-db-token-issuance.md` for the design.
 */

import { Action, ResourceId, DbCredential, DbProvider } from '@euno/common';

/**
 * Canonical-form DB resource URI as parsed by {@link parseDbUri}.
 * `db://{cloud}/{instance}/{database}/{schema-or-table}.{action}`
 *
 * The DB engine (postgres / mysql / sqlserver) is an attribute of the
 * **instance**, not the URI — fetched from operator config keyed by
 * `instance`.
 */
export interface ParsedDbUri {
  raw: ResourceId;
  cloud: DbProvider;
  /** Operator-defined instance identifier (key into the instances config). */
  instance: string;
  database: string;
  /** `{schema}.{table}.{action}` or `{table}.{action}`; informational only. */
  objectAndAction: string;
}

/** Operator-side configuration for a single permitted DB instance. */
export interface DbInstanceConfig {
  id: string;
  provider: DbProvider;
  host: string;
  port: number;
  /** Allowed databases on this instance. */
  databases: string[];
  /** Region — required for `rds-iam`. */
  region?: string;
}

/** Input passed to every {@link DbTokenMinter}. */
export interface DbTokenMintInput {
  resource: ResourceId;
  actions: Action[];
  ttlSeconds: number;
  agentId: string;
  authorizedBy: string;
  /**
   * IAM-mapped DB principal resolved from the user's role(s) — never
   * taken from the agent. The minter does not validate this further;
   * the issuer-side dispatcher is the single source of truth.
   */
  dbUsername: string;
  /** Resolved instance config (host / port / region). */
  instance: DbInstanceConfig;
  /** Database name from the URI (already validated against `instance.databases`). */
  database: string;
}

/** Provider-specific minter contract. */
export interface DbTokenMinter {
  readonly provider: DbProvider;
  mint(input: DbTokenMintInput): Promise<DbCredential>;
}

/** Hard ceiling on DB-token TTL (15 min) regardless of operator config. */
export const DB_TOKEN_HARD_MAX_TTL_SECONDS = 900;
/** Default operator cap when `DB_TOKEN_MAX_TTL_SECONDS` is unset (15 min). */
export const DB_TOKEN_DEFAULT_MAX_TTL_SECONDS = 900;

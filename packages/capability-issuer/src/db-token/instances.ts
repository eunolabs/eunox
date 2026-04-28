/**
 * Operator-side DB instance configuration loader.
 *
 * The issuer must NOT mint a token for an arbitrary `db://...`
 * instance. Operators declare each permitted instance up front in a
 * YAML or JSON file pointed to by `DB_INSTANCES_FILE`, preventing an
 * agent from requesting `db://my-attacker-instance/...` and getting a
 * token. See `docs/sprint-3-4-gaps/08-db-token-issuance.md` § 5.
 *
 * To avoid pulling in a YAML dependency for the common case, this
 * loader accepts JSON (preferred) or a tiny strict YAML subset
 * (top-level `instances:` list of objects with primitive scalars). If
 * the file extension is `.yml`/`.yaml`, the YAML loader is used; for
 * `.json` the standard parser is used; for anything else, JSON is
 * tried first then YAML.
 */

import * as fs from 'fs';
import * as path from 'path';
import { DbProvider } from '@euno/common';
import { DbInstanceConfig } from './types';

const VALID_PROVIDERS: ReadonlySet<DbProvider> = new Set([
  'azure-sql',
  'rds-iam',
  'cloudsql-iam',
]);

/** Validate and normalize a parsed instance entry. */
function validateInstance(value: unknown, ctx: string): DbInstanceConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${ctx}: instance entry must be an object`);
  }
  const obj = value as Record<string, unknown>;
  const id = obj.id;
  const provider = obj.provider;
  const host = obj.host;
  const port = obj.port;
  const databases = obj.databases;
  const region = obj.region;
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error(`${ctx}: 'id' must be a non-empty string`);
  }
  if (typeof provider !== 'string' || !VALID_PROVIDERS.has(provider as DbProvider)) {
    throw new Error(
      `${ctx}: 'provider' must be one of ${[...VALID_PROVIDERS].join(', ')} (got '${String(provider)}')`,
    );
  }
  if (typeof host !== 'string' || host.length === 0) {
    throw new Error(`${ctx}: 'host' must be a non-empty string`);
  }
  if (typeof port !== 'number' || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`${ctx}: 'port' must be a positive integer ≤ 65535`);
  }
  if (!Array.isArray(databases) || databases.length === 0) {
    throw new Error(`${ctx}: 'databases' must be a non-empty array of strings`);
  }
  const dbs: string[] = [];
  for (const d of databases) {
    if (typeof d !== 'string' || d.length === 0) {
      throw new Error(`${ctx}: each 'databases' entry must be a non-empty string`);
    }
    dbs.push(d);
  }
  if (provider === 'rds-iam' && (typeof region !== 'string' || region.length === 0)) {
    throw new Error(`${ctx}: 'region' is required for rds-iam instances`);
  }
  const out: DbInstanceConfig = {
    id,
    provider: provider as DbProvider,
    host,
    port,
    databases: dbs,
  };
  if (typeof region === 'string') out.region = region;
  return out;
}

/**
 * Validate a parsed root document into a map keyed by instance id.
 * Duplicate ids are rejected so the operator cannot accidentally
 * shadow one instance with another.
 */
export function validateInstancesDocument(value: unknown): Map<string, DbInstanceConfig> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error("db instances document: must be an object with an 'instances' array");
  }
  const obj = value as Record<string, unknown>;
  if (!Array.isArray(obj.instances)) {
    throw new Error("db instances document: missing or non-array 'instances' field");
  }
  const map = new Map<string, DbInstanceConfig>();
  obj.instances.forEach((entry, i) => {
    const inst = validateInstance(entry, `instances[${i}]`);
    if (map.has(inst.id)) {
      throw new Error(`db instances document: duplicate instance id '${inst.id}'`);
    }
    map.set(inst.id, inst);
  });
  return map;
}

/** Strict, minimal YAML subset parser for our specific schema only. */
function parseSimpleYaml(raw: string): unknown {
  // Accept lines like:
  //   instances:
  //     - id: salesserver
  //       provider: azure-sql
  //       host: ...
  //       port: 1433
  //       databases: [salesdb, archivedb]
  //       region: us-east-1
  // Comments (#) and blank lines are ignored. Quoted strings and
  // multi-line constructs are NOT supported — operators wanting more
  // complex schemas should use JSON.
  const lines = raw.split('\n');
  const instances: Record<string, unknown>[] = [];
  let current: Record<string, unknown> | null = null;
  let inInstances = false;
  for (let rawLine of lines) {
    rawLine = rawLine.replace(/#.*$/, '');
    if (!rawLine.trim()) continue;
    if (/^instances\s*:\s*$/.test(rawLine)) {
      inInstances = true;
      continue;
    }
    if (!inInstances) continue;
    const itemMatch = rawLine.match(/^\s*-\s*(\w+)\s*:\s*(.+?)\s*$/);
    if (itemMatch) {
      current = {};
      instances.push(current);
      const [, key, value] = itemMatch;
      if (key) current[key] = parseScalar(value ?? '');
      continue;
    }
    const fieldMatch = rawLine.match(/^\s+(\w+)\s*:\s*(.+?)\s*$/);
    if (fieldMatch && current) {
      const [, key, value] = fieldMatch;
      if (key) current[key] = parseScalar(value ?? '');
    }
  }
  return { instances };
}

function parseScalar(s: string): unknown {
  if (/^\[.*\]$/.test(s)) {
    return s
      .slice(1, -1)
      .split(',')
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
  }
  const num = Number(s);
  if (!Number.isNaN(num) && /^-?\d+(\.\d+)?$/.test(s)) return num;
  return s;
}

/** Load and validate the instances file at `filePath`. */
export function loadDbInstancesFromFile(filePath: string): Map<string, DbInstanceConfig> {
  const resolved = path.resolve(filePath);
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(
      `Failed to read DB instances file '${resolved}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const ext = path.extname(resolved).toLowerCase();
  let parsed: unknown;
  if (ext === '.json') {
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `DB instances file '${resolved}' is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  } else if (ext === '.yml' || ext === '.yaml') {
    parsed = parseSimpleYaml(raw);
  } else {
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = parseSimpleYaml(raw);
    }
  }
  return validateInstancesDocument(parsed);
}

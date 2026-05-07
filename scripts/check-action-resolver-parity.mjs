#!/usr/bin/env node
/**
 * CI lint: verify that the issuer and gateway ACTION_RESOLVER_FILE configs
 * carry the same action vocabulary.
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-action-resolver-parity.mjs \
 *     --issuer  packages/capability-issuer/action-resolver.json \
 *     --gateway packages/tool-gateway/action-resolver.json
 *
 * Both paths are optional. Omitting a path (or passing an empty string)
 * means "no operator overrides — use built-in defaults only". Two sides
 * that both omit the file trivially agree and the script exits 0.
 *
 * Exit codes:
 *   0 — hashes match (or both omitted)
 *   1 — hashes differ, or a file cannot be read / parsed
 *
 * The script also runs a secondary lint pass that detects duplicate action
 * keys within a single file (the same action defined twice with different
 * casing is a silent privilege-escalation vector because `toCaTier` lower-
 * cases before lookup) and warns about any action key that differs only in
 * casing from another key in the same file.
 *
 * It can be invoked without arguments to compare the files pointed to by
 * the ACTION_RESOLVER_FILE env vars in each service's .env file:
 *
 *   node scripts/check-action-resolver-parity.mjs
 *
 * In that mode it reads each `.env` file with a minimal parser (no `dotenv`
 * dependency) and resolves relative paths against each service's package
 * directory.
 */

import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
let issuerFile;
let gatewayFile;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--issuer' && args[i + 1]) {
    issuerFile = resolve(repoRoot, args[++i]);
  } else if (args[i] === '--gateway' && args[i + 1]) {
    gatewayFile = resolve(repoRoot, args[++i]);
  }
}

// ---------------------------------------------------------------------------
// Auto-detect from .env files when no explicit paths are provided
// ---------------------------------------------------------------------------

/**
 * Parse a .env file and extract the value of a given key. Returns undefined
 * when the file is missing or the key is absent. Intentionally minimal — no
 * variable expansion, no multi-line support — sufficient for reading a single
 * path variable.
 */
function readEnvVar(envFilePath, key) {
  if (!existsSync(envFilePath)) return undefined;
  const content = readFileSync(envFilePath, 'utf8');
  for (const line of content.split('\n')) {
    // Skip comment-only and blank lines.
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed === '') continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) continue;
    const k = trimmed.slice(0, eqIdx).trim();
    if (k !== key) continue;
    let v = trimmed.slice(eqIdx + 1).trim();

    if (v.startsWith('"') || v.startsWith("'")) {
      // Quoted value: find the matching closing quote.  Everything between
      // the opening and closing quote is the literal value; anything after
      // the closing quote (e.g. an inline comment) is silently discarded.
      // This correctly handles `KEY="value # not a comment" # real comment`.
      const quoteChar = v[0];
      const closingIdx = v.indexOf(quoteChar, 1);
      v = closingIdx > 0 ? v.slice(1, closingIdx) : v.slice(1);
    } else {
      // Unquoted value: strip a trailing inline comment (# preceded by
      // whitespace — env-file convention) before returning the value.
      const commentIdx = v.search(/\s+#/);
      if (commentIdx >= 0) v = v.slice(0, commentIdx).trim();
    }

    return v || undefined;
  }
  return undefined;
}

if (issuerFile === undefined) {
  const envPath = join(repoRoot, 'euno-platform', 'packages', 'capability-issuer', '.env');
  const val = readEnvVar(envPath, 'ACTION_RESOLVER_FILE');
  if (val) {
    issuerFile = resolve(join(repoRoot, 'euno-platform', 'packages', 'capability-issuer'), val);
  }
}

if (gatewayFile === undefined) {
  const envPath = join(repoRoot, 'euno-platform', 'packages', 'tool-gateway', '.env');
  const val = readEnvVar(envPath, 'ACTION_RESOLVER_FILE');
  if (val) {
    gatewayFile = resolve(join(repoRoot, 'euno-platform', 'packages', 'tool-gateway'), val);
  }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/**
 * Compute the canonical SHA-256 hash of an ActionResolverConfig.
 *
 * Mirrors computeActionResolverHash() from @euno/common/src/action-resolver.ts:
 *   - null / undefined → sentinel hash of `{}`
 *   - otherwise: sorted-key canonical JSON → SHA-256 hex
 *
 * The canonical JSON is produced by the encode() inner function below, which
 * is a direct port of canonicalize() from @euno/common/src/utils.ts so the
 * CI hash is byte-for-byte identical to the runtime hash even if the config
 * shape gains BigInt values, toJSON() methods, or non-finite numbers.
 *
 * Key behavioural rules (must stay in sync with utils.ts):
 *   - null              → "null"
 *   - undefined         → undefined (omitted from object entries; "null" in arrays)
 *   - boolean           → "true" / "false"
 *   - finite number     → JSON.stringify(n)
 *   - non-finite number → "null"
 *   - bigint            → JSON.stringify(n.toString() + "n")
 *   - function/symbol   → undefined (omitted from object entries)
 *   - object with toJSON() → recurse on toJSON() result
 *   - array             → "[item,item,…]" (undefined items become "null")
 *   - plain object      → "{sorted-key-pairs}" (undefined values omitted)
 *   - circular          → throws TypeError
 */
function computeHash(config) {
  const seen = new WeakSet();

  function encode(value) {
    if (value === null) return 'null';
    if (value === undefined) return undefined;

    const t = typeof value;

    if (t === 'bigint') return JSON.stringify(value.toString() + 'n');
    if (t === 'string') return JSON.stringify(value);
    if (t === 'boolean') return value ? 'true' : 'false';
    if (t === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
    if (t === 'function' || t === 'symbol') return undefined;

    // Object / Array — check for toJSON() first (e.g. Date)
    if (typeof value.toJSON === 'function') return encode(value.toJSON());

    if (seen.has(value)) throw new TypeError('canonicalize: circular reference detected');
    seen.add(value);

    try {
      if (Array.isArray(value)) {
        const parts = value.map((item) => {
          const encoded = encode(item);
          return encoded === undefined ? 'null' : encoded;
        });
        return '[' + parts.join(',') + ']';
      }

      const keys = Object.keys(value).sort();
      const parts = [];
      for (const key of keys) {
        const encoded = encode(value[key]);
        if (encoded === undefined) continue; // omit undefined values (like functions)
        parts.push(JSON.stringify(key) + ':' + encoded);
      }
      return '{' + parts.join(',') + '}';
    } finally {
      seen.delete(value);
    }
  }

  const canonical = encode(config ?? {});
  const str = canonical === undefined ? 'null' : canonical;
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Read and parse each file
// ---------------------------------------------------------------------------

/** Known top-level keys; any other key is flagged as unknown. */
const KNOWN_KEYS = new Set([
  'httpMethodActions',
  'defaultHttpAction',
  'toolActions',
  'defaultToolAction',
  'actionTiers',
  'defaultTier',
]);

/** Valid CA tiers */
const VALID_TIERS = new Set(['read', 'write', 'delete', 'admin']);

let exitCode = 0;

function warn(msg) {
  process.stderr.write(`WARN  ${msg}\n`);
}

function error(msg) {
  process.stderr.write(`ERROR ${msg}\n`);
  exitCode = 1;
}

function lintConfig(label, config) {
  if (typeof config !== 'object' || config === null || Array.isArray(config)) {
    error(`${label}: config must be a JSON object`);
    return;
  }

  // Unknown top-level keys
  for (const k of Object.keys(config)) {
    if (!KNOWN_KEYS.has(k)) {
      warn(`${label}: unknown top-level key '${k}' (ignored by runtime)`);
    }
  }

  // actionTiers: case-collision and invalid tier values
  if (config.actionTiers !== null && typeof config.actionTiers === 'object' && !Array.isArray(config.actionTiers)) {
    const seenLower = new Map(); // lowercase key → original key
    for (const [k, v] of Object.entries(config.actionTiers)) {
      const kLower = k.toLowerCase();
      if (seenLower.has(kLower)) {
        error(
          `${label}: actionTiers contains duplicate action keys that differ only in casing: ` +
            `'${seenLower.get(kLower)}' and '${k}'. This is a silent privilege-escalation ` +
            `vector because toCaTier() lowercases before lookup — one of these entries will ` +
            `silently shadow the other.`,
        );
      } else {
        seenLower.set(kLower, k);
      }
      if (typeof v !== 'string' || !VALID_TIERS.has(v)) {
        error(
          `${label}: actionTiers['${k}'] = '${v}' is not a valid CA tier. ` +
            `Valid tiers: ${[...VALID_TIERS].join(', ')}.`,
        );
      }
    }
  }

  // defaultTier must be a valid tier when present
  if (config.defaultTier !== undefined && !VALID_TIERS.has(config.defaultTier)) {
    error(
      `${label}: defaultTier '${config.defaultTier}' is not a valid CA tier. ` +
        `Valid tiers: ${[...VALID_TIERS].join(', ')}.`,
    );
  }
}

function loadConfig(label, filePath) {
  if (!filePath) {
    process.stdout.write(`INFO  ${label}: no ACTION_RESOLVER_FILE configured — using built-in defaults\n`);
    return { config: null, hash: computeHash(null) };
  }

  if (!existsSync(filePath)) {
    error(`${label}: ACTION_RESOLVER_FILE '${filePath}' does not exist`);
    return null;
  }

  let raw;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    error(`${label}: cannot read '${filePath}': ${err.message}`);
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    error(`${label}: '${filePath}' is not valid JSON: ${err.message}`);
    return null;
  }

  lintConfig(`${label} (${filePath})`, parsed);

  return { config: parsed, hash: computeHash(parsed), filePath };
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

const issuer = loadConfig('issuer', issuerFile);
const gateway = loadConfig('gateway', gatewayFile);

if (issuer && gateway) {
  if (issuer.hash === gateway.hash) {
    process.stdout.write(
      `OK    Action resolver hashes match: ${issuer.hash}\n` +
        (issuer.filePath ? `      issuer:  ${issuer.filePath}\n` : `      issuer:  (built-in defaults)\n`) +
        (gateway.filePath ? `      gateway: ${gateway.filePath}\n` : `      gateway: (built-in defaults)\n`),
    );
  } else {
    error(
      `Action resolver hash MISMATCH:\n` +
        `      issuer  hash: ${issuer.hash}  (${issuer.filePath ?? 'built-in defaults'})\n` +
        `      gateway hash: ${gateway.hash}  (${gateway.filePath ?? 'built-in defaults'})\n` +
        `\n` +
        `  The issuer and gateway are using different action vocabularies.\n` +
        `  Tokens minted by the issuer may not be enforced correctly at the gateway.\n` +
        `  Ensure ACTION_RESOLVER_FILE is identical on both services and re-run.`,
    );
  }
}

process.exit(exitCode);

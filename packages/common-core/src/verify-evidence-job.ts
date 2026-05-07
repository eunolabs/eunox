/**
 * F-9 — Continuous evidence-chain verification job.
 *
 * Wraps {@link AuditEvidenceSigner.verifyEvidence} as a scriptable batch
 * verifier. The intent (per `docs/NEXT_STEPS_BACKLOG.md` § 4 and
 * `docs/IMPROVEMENTS_AND_REFACTORING.md` F-9) is to run this on a schedule
 * (typically daily) over the previous interval's emitted
 * {@link SignedAuditEvidence} records, so that any tampering with the
 * audit log is detected automatically and triggers an alert on the first
 * failure.
 *
 * The job is intentionally:
 *   - **Verify-only** — it accepts only a public key (via
 *     {@link createSoftwareEvidenceVerifierFromEnv}) so the host running
 *     it cannot mint new signatures even if compromised.
 *   - **Format-tolerant** — accepts a single JSON object, a JSON array,
 *     or newline-delimited JSON (`*.jsonl` / `*.ndjson`). Files emitted
 *     by the gateway, by Log Analytics exports, and by manual `jq`
 *     pipelines all flow in unchanged.
 *   - **Fail-closed** — exits with status `1` on the first failed
 *     record so cron / Kubernetes-CronJob alerting fires immediately.
 *     For runs that actually process input records, a machine-readable
 *     JSON summary is written to stdout so operators (or upstream
 *     alerting tools) can inspect the result. Usage / configuration
 *     errors (exit `2`) print human-readable text instead, since there
 *     is no batch result to summarise.
 */

import * as fs from 'fs';
import * as path from 'path';

import type { SignedAuditEvidence } from './wire';
import {
  AuditEvidenceSigner,
  createSoftwareEvidenceVerifierFromEnv,
} from './evidence';

/**
 * One failure in the per-record verification result.
 *
 * - `file`  — path of the input that produced the failure (or `-` for stdin).
 * - `index` — 0-based position of the offending record inside the file
 *             when the failure is record-scoped. **Omitted** when the
 *             failure is file-scoped (e.g. the file could not be read or
 *             parsed). Consumers should treat a missing `index` as
 *             "applies to the whole file".
 * - `evidenceId` — populated when the offending record was successfully
 *             parsed enough to expose its `id`.
 * - `reason` — short human-readable cause; consumers should not rely on
 *             its exact wording for control flow.
 */
export interface VerifyEvidenceFailure {
  file: string;
  index?: number;
  evidenceId?: string;
  reason: string;
}

/**
 * Aggregate result returned by {@link runVerifyEvidence}. Designed to be
 * serialised to stdout as JSON and consumed by an upstream alerting
 * pipeline (Sentinel, PagerDuty webhook, etc.).
 */
export interface VerifyEvidenceReport {
  total: number;
  verified: number;
  failed: number;
  startedAt: string;
  finishedAt: string;
  failures: VerifyEvidenceFailure[];
}

/**
 * Parse a single input source into an array of candidate records.
 *
 * Accepts:
 *   - A JSON object (`{ ... }`) — treated as a single record.
 *   - A JSON array (`[ ... ]`) — each element is a record.
 *   - JSONL / NDJSON — one JSON value per non-empty line. This is the
 *     format Winston / Log Analytics typically export.
 *
 * The parser deliberately falls through from "single JSON document" to
 * "newline-delimited JSON" so it handles both shapes without needing a
 * format flag.
 */
export function parseEvidenceBatch(content: string): unknown[] {
  const trimmed = content.trim();
  if (trimmed.length === 0) {
    return [];
  }

  // Single JSON document path (object or array). We try this first
  // because pretty-printed JSON arrays span many lines and would
  // otherwise be misread as JSONL.
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      // Fall through to JSONL handling below.
    }
  }

  // JSONL / NDJSON path. Empty lines are ignored, malformed lines throw
  // with the line number so the operator can fix the upstream emitter.
  const lines = trimmed.split(/\r?\n/);
  const records: unknown[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.trim().length === 0) {
      continue;
    }
    try {
      records.push(JSON.parse(line));
    } catch (err) {
      throw new Error(
        `failed to parse JSON on line ${i + 1}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return records;
}

/**
 * Type-guard rejecting records that obviously cannot be verified before
 * we waste a crypto call on them. We only check structural shape here;
 * cryptographic validity is delegated to `AuditEvidenceSigner.verifyEvidence`.
 */
function looksLikeSignedEvidence(record: unknown): record is SignedAuditEvidence {
  if (record === null || typeof record !== 'object') {
    return false;
  }
  const r = record as Record<string, unknown>;
  return (
    typeof r.signature === 'string' &&
    typeof r.keyId === 'string' &&
    typeof r.algorithm === 'string' &&
    typeof r.id === 'string' &&
    typeof r.previousHash === 'string' &&
    typeof r.seq === 'number'
  );
}

/**
 * Read a file (or `-` for stdin) and return raw UTF-8 contents.
 */
function readSource(source: string): string {
  if (source === '-') {
    return fs.readFileSync(0, 'utf8');
  }
  return fs.readFileSync(source, 'utf8');
}

/**
 * Expand a CLI argument into one or more input file paths. Directories
 * are walked one level deep for `*.json` / `*.jsonl` / `*.ndjson` files
 * (the typical layout produced by a daily audit-batch exporter that
 * partitions by hour). The single-character argument `-` is preserved
 * verbatim so it is read from stdin.
 */
function expandSource(source: string): string[] {
  if (source === '-') {
    return ['-'];
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(source);
  } catch (err) {
    throw new Error(
      `cannot read input '${source}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (stat.isFile()) {
    return [source];
  }
  if (stat.isDirectory()) {
    return fs
      .readdirSync(source)
      .filter((f) => /\.(jsonl?|ndjson)$/i.test(f))
      .map((f) => path.join(source, f))
      .sort();
  }
  throw new Error(`unsupported input '${source}': not a regular file or directory`);
}

/**
 * Run the verification job over a list of inputs.
 *
 * @param inputs   File paths, directories, or `-` for stdin.
 * @param verifier Verifier to use. Tests may pass a stubbed verifier; the
 *                 CLI entry point uses {@link createSoftwareEvidenceVerifierFromEnv}.
 * @param failFast When `true` (default), stop scanning on the first
 *                 failed record so cron alerts fire immediately. When
 *                 `false`, walk the entire batch and report every failure
 *                 — useful for ad-hoc forensic runs.
 */
export async function runVerifyEvidence(
  inputs: string[],
  verifier: AuditEvidenceSigner,
  options: { failFast?: boolean } = {},
): Promise<VerifyEvidenceReport> {
  const failFast = options.failFast ?? true;
  const startedAt = new Date().toISOString();
  const failures: VerifyEvidenceFailure[] = [];
  let total = 0;
  let verified = 0;

  // Expand directories to files first so the report's `total` reflects
  // the true number of records rather than the number of CLI args.
  const expanded: string[] = [];
  for (const input of inputs) {
    expanded.push(...expandSource(input));
  }

  outer: for (const file of expanded) {
    let raw: string;
    try {
      raw = readSource(file);
    } catch (err) {
      // File-scoped failure: omit `index` per the VerifyEvidenceFailure
      // contract so consumers don't have to special-case a sentinel.
      failures.push({
        file,
        reason: `read failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      if (failFast) {
        break;
      }
      continue;
    }

    let records: unknown[];
    try {
      records = parseEvidenceBatch(raw);
    } catch (err) {
      // File-scoped failure (whole-file parse error): no record index applies.
      failures.push({
        file,
        reason: `parse failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      if (failFast) {
        break;
      }
      continue;
    }

    for (let i = 0; i < records.length; i++) {
      total++;
      const record = records[i];
      if (!looksLikeSignedEvidence(record)) {
        failures.push({
          file,
          index: i,
          reason: 'record is missing required fields (signature, keyId, algorithm, id, previousHash, seq)',
        });
        if (failFast) {
          break outer;
        }
        continue;
      }

      let ok = false;
      try {
        ok = await verifier.verifyEvidence(record);
      } catch (err) {
        failures.push({
          file,
          index: i,
          evidenceId: record.id,
          reason: `verifier threw: ${err instanceof Error ? err.message : String(err)}`,
        });
        if (failFast) {
          break outer;
        }
        continue;
      }

      if (ok) {
        verified++;
      } else {
        failures.push({
          file,
          index: i,
          evidenceId: record.id,
          reason: 'signature did not verify',
        });
        if (failFast) {
          break outer;
        }
      }
    }
  }

  return {
    total,
    verified,
    failed: failures.length,
    startedAt,
    finishedAt: new Date().toISOString(),
    failures,
  };
}

/**
 * CLI entry point. Kept as a separate exported function so tests can
 * drive it deterministically without spawning a child process.
 *
 * Usage (matches the reference in `docs/SPRINT_5_PILOT_LAUNCH.md` G10):
 *   node scripts/verify-evidence.js <evidence.json|dir> [more...] [--all]
 *   cat evidence.jsonl | node scripts/verify-evidence.js -
 *
 * Exit codes:
 *   * `0` — every record verified successfully.
 *   * `1` — at least one record failed verification (alerting trigger).
 *   * `2` — usage error or no verifier configured.
 */
export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  stdout: NodeJS.WritableStream = process.stdout,
  stderr: NodeJS.WritableStream = process.stderr,
): Promise<number> {
  const args = argv.slice(2);
  let failFast = true;
  const inputs: string[] = [];
  for (const arg of args) {
    if (arg === '--all' || arg === '-a') {
      // Forensic mode: keep scanning so the operator sees every bad record.
      failFast = false;
    } else if (arg === '--help' || arg === '-h') {
      stdout.write(
        'Usage: verify-evidence [--all] <evidence.json|dir|-> [...]\n' +
          '  --all  Continue past the first failure and report every bad record.\n' +
          '  -      Read JSON/JSONL evidence from stdin.\n' +
          'Configures the verifier from EVIDENCE_VERIFY_PUBLIC_KEY_{PEM,FILE}\n' +
          '(falling back to EVIDENCE_SIGNING_PUBLIC_KEY_{PEM,FILE}).\n',
      );
      return 0;
    } else if (arg.startsWith('-') && arg !== '-') {
      stderr.write(`verify-evidence: unknown option '${arg}'\n`);
      return 2;
    } else {
      inputs.push(arg);
    }
  }

  if (inputs.length === 0) {
    stderr.write('verify-evidence: no input files supplied (pass `-` to read stdin)\n');
    return 2;
  }

  const verifier = createSoftwareEvidenceVerifierFromEnv(env);
  if (!verifier) {
    stderr.write(
      'verify-evidence: no verifier configured. Set EVIDENCE_VERIFY_PUBLIC_KEY_PEM or ' +
        'EVIDENCE_VERIFY_PUBLIC_KEY_FILE (or the EVIDENCE_SIGNING_PUBLIC_KEY_* fallbacks).\n',
    );
    return 2;
  }

  let report: VerifyEvidenceReport;
  try {
    report = await runVerifyEvidence(inputs, verifier, { failFast });
  } catch (err) {
    stderr.write(
      `verify-evidence: fatal error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 2;
  }

  stdout.write(JSON.stringify(report, null, 2) + '\n');
  return report.failed === 0 ? 0 : 1;
}

// Allow `node packages/common/dist/verify-evidence-job.js` to invoke the
// job directly. The repo-root `scripts/verify-evidence.js` shim delegates
// here after the common package has been built.
/* istanbul ignore next */
if (require.main === module) {
  main(process.argv).then(
    (code) => process.exit(code),
    (err) => {
      // eslint-disable-next-line no-console
      console.error(err);
      process.exit(2);
    },
  );
}

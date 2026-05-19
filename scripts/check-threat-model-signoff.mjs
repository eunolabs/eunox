#!/usr/bin/env node
/**
 * CI lint: verify that threat model documents have been signed off.
 *
 * Checks two threat model files:
 *
 * 1. docs/security/issuer-identity-threat-model.md (Stage 4, CR-2)
 *    Fails if the file still contains `_(add names` placeholder text.
 *
 * 2. docs/security/enterprise-federation-threat-model.md (Stage 5, Task 1)
 *    Fails if the file still contains `_(name)_` or `_(date)_` placeholder
 *    text in the sign-off table, or if it still contains the "Status:
 *    Placeholder" notice from the original stub.
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-threat-model-signoff.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Exit codes:
 *   0 -- all threat models are signed off
 *   1 -- placeholder text found or file missing
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let workspaceRoot = repoRoot;

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (arg === '--root') {
    if (i + 1 >= argv.length) {
      process.stderr.write('ERROR: --root requires a path argument\n');
      process.exit(1);
    }
    workspaceRoot = resolve(argv[++i]);
  } else if (arg.startsWith('--root=')) {
    workspaceRoot = resolve(arg.slice('--root='.length));
  } else {
    process.stderr.write(`ERROR: unknown argument: ${arg}\n`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

/**
 * Check a single threat model file for placeholder text.
 *
 * @param {string} filePath   Absolute path to the file.
 * @param {string[]} placeholders  Substrings whose presence indicates the
 *   document has not been signed off.
 * @param {string} guidance   Human-readable guidance appended to the error.
 * @returns {number} Number of errors found (0 or 1).
 */
function checkFile(filePath, placeholders, guidance) {
  if (!existsSync(filePath)) {
    process.stderr.write(`ERROR threat model file not found: ${filePath}\n`);
    return 1;
  }
  const content = readFileSync(filePath, 'utf8');
  for (const placeholder of placeholders) {
    if (content.includes(placeholder)) {
      process.stderr.write(
        `ERROR ${filePath} still contains the sign-off placeholder ` +
          `"${placeholder}". ${guidance}\n`,
      );
      return 1;
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

let errors = 0;

// Stage-4 issuer identity threat model (architecture-review-2026-05-stage4.md CR-2)
errors += checkFile(
  resolve(workspaceRoot, 'docs/security/issuer-identity-threat-model.md'),
  ['_(add names'],
  'Populate the Authors and Reviewers fields before merging (see architecture-review-2026-05-stage4.md CR-2).',
);

// Stage-5 enterprise federation threat model (stage5executionplan.md Task 1)
errors += checkFile(
  resolve(workspaceRoot, 'docs/security/enterprise-federation-threat-model.md'),
  ['_(name)_', '_(date)_', 'Status: Placeholder'],
  'Complete the sign-off table and remove the placeholder status notice before merging (see stage5executionplan.md §5 Task 1).',
);

if (errors === 0) {
  process.stdout.write('OK threat model sign-off check passed\n');
  process.exit(0);
} else {
  process.exit(1);
}

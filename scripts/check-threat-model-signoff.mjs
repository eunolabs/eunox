#!/usr/bin/env node
/**
 * CI lint: verify that the issuer identity threat model has been signed off.
 *
 * Fails if the threat model file still contains the placeholder text
 * `_(add names` which indicates that the Authors / Reviewers fields have
 * not been populated (see docs/security/issuer-identity-threat-model.md
 * and architecture-review-2026-05-stage4.md CR-2).
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
 *   0 -- threat model is signed off
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
      process.stderr.write('ERROR --root requires a path argument\n');
      process.exit(1);
    }
    workspaceRoot = resolve(argv[++i]);
  } else if (arg.startsWith('--root=')) {
    workspaceRoot = resolve(arg.slice('--root='.length));
  } else {
    process.stderr.write(`ERROR unknown argument: ${arg}\n`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

const THREAT_MODEL_PATH = resolve(
  workspaceRoot,
  'docs/security/issuer-identity-threat-model.md',
);

const PLACEHOLDER = '_(add names';

let errors = 0;

if (!existsSync(THREAT_MODEL_PATH)) {
  process.stderr.write(
    `ERROR threat model file not found: ${THREAT_MODEL_PATH}\n`,
  );
  errors++;
} else {
  const content = readFileSync(THREAT_MODEL_PATH, 'utf8');
  if (content.includes(PLACEHOLDER)) {
    process.stderr.write(
      `ERROR ${THREAT_MODEL_PATH} still contains the sign-off placeholder ` +
        `"${PLACEHOLDER}". Populate the Authors and Reviewers fields before ` +
        `merging (see architecture-review-2026-05-stage4.md CR-2).\n`,
    );
    errors++;
  }
}

if (errors === 0) {
  process.stdout.write('OK threat model sign-off check passed\n');
  process.exit(0);
} else {
  process.exit(1);
}

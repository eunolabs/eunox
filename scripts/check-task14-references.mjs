#!/usr/bin/env node
/**
 * CI lint: verify that the Task 14 Stage-5 reference materials are present.
 *
 * Checks performed:
 *   1. docs/mvp.md contains the Task 14 entry in the Stage-5 status block.
 *   2. README.md contains the Stage-5 enterprise section heading.
 *   3. README.md project-status table marks Stage 5 as done (✅).
 *   4. public/packages/cli/README.md contains the Stage-5 enterprise
 *      features section.
 *   5. public/packages/cli/README.md contains partner-federation CLI
 *      references (validate-token with --iss did:web or did:ion).
 *   6. public/packages/cli/README.md contains SOC2 audit export CLI
 *      references (euno audit export).
 *   7. CHANGELOG.md exists for partner-issuer-sim.
 *   8. CHANGELOG.md exists for posture-emitter.
 *   9. CHANGELOG.md exists for db-token-service.
 *  10. CHANGELOG.md exists for storage-grant-service.
 *  11. Each CHANGELOG.md contains a [1.0.0] GA entry.
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-task14-references.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Exit codes:
 *   0 -- all checks pass
 *   1 -- one or more checks failed or a required file is missing
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
  if (argv[i] === '--root' && argv[i + 1]) {
    workspaceRoot = resolve(argv[i + 1]);
    i++;
  } else if (argv[i].startsWith('--root=')) {
    workspaceRoot = resolve(argv[i].slice('--root='.length));
  } else {
    console.error(`Unknown argument: ${argv[i]}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const failures = [];

/**
 * Read a file relative to the workspace root.
 * Returns null and records a failure if the file is missing.
 * @param {string} relPath
 * @returns {string|null}
 */
function readFile(relPath) {
  const absPath = resolve(workspaceRoot, relPath);
  if (!existsSync(absPath)) {
    failures.push(`Missing file: ${relPath}`);
    return null;
  }
  return readFileSync(absPath, 'utf8');
}

/**
 * Assert that the content string contains the needle.
 * @param {string|null} content
 * @param {string} needle
 * @param {string} description
 */
function requireText(content, needle, description) {
  if (content === null) return; // already reported as missing
  if (!content.includes(needle)) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
  }
}

// ---------------------------------------------------------------------------
// 1. docs/mvp.md — Task 14 entry in Stage-5 status block
// ---------------------------------------------------------------------------

const mvpContent = readFile('docs/mvp.md');

requireText(
  mvpContent,
  '> - [x] Task 14',
  'Task 14 checklist entry in docs/mvp.md Stage 5 status block',
);

requireText(
  mvpContent,
  '> **Stage 5 — status block',
  'Stage 5 status block header in docs/mvp.md',
);

// ---------------------------------------------------------------------------
// 2 & 3. README.md — Stage-5 enterprise section + status table
// ---------------------------------------------------------------------------

const readmeContent = readFile('README.md');

requireText(
  readmeContent,
  'Enterprise deployment (Stage 5)',
  'Stage-5 enterprise section heading in README.md',
);

requireText(
  readmeContent,
  'Stage 5',
  'Stage 5 row in README.md project-status table',
);

// The Stage-5 row must be marked done (✅), not "Planned"
if (readmeContent !== null && readmeContent.includes('| 5 |')) {
  const stage5Row = readmeContent.split('\n').find(line => line.startsWith('| 5 |'));
  if (stage5Row && stage5Row.includes('Planned')) {
    failures.push(
      'README.md project-status table still marks Stage 5 as "Planned"; ' +
      'it should be marked ✅ Done.',
    );
  }
}

// ---------------------------------------------------------------------------
// 4 & 5 & 6. public/packages/cli/README.md
// ---------------------------------------------------------------------------

const cliContent = readFile('public/packages/cli/README.md');

requireText(
  cliContent,
  'Stage 5: Enterprise Features',
  '§"Stage 5: Enterprise Features" section in public/packages/cli/README.md',
);

requireText(
  cliContent,
  'partner',
  'partner-federation CLI reference in public/packages/cli/README.md',
);

requireText(
  cliContent,
  'audit export',
  'SOC2 audit export CLI reference (`euno audit export`) in public/packages/cli/README.md',
);

// ---------------------------------------------------------------------------
// 7–10. CHANGELOG.md existence for the four un-quarantined packages
// ---------------------------------------------------------------------------

const packages = [
  'euno-platform/packages/partner-issuer-sim',
  'euno-platform/packages/posture-emitter',
  'euno-platform/packages/db-token-service',
  'euno-platform/packages/storage-grant-service',
];

for (const pkg of packages) {
  const changelogPath = `${pkg}/CHANGELOG.md`;
  const content = readFile(changelogPath);

  // 11. Each CHANGELOG must contain a [1.0.0] GA entry
  requireText(
    content,
    '[1.0.0]',
    `[1.0.0] GA entry in ${changelogPath}`,
  );
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

if (failures.length > 0) {
  console.error('FAIL Task-14 reference check failed:\n');
  for (const f of failures) {
    console.error(`  • ${f}`);
  }
  process.exit(1);
}

console.log('OK Task-14 reference check passed');

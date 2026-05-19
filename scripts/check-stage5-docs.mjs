#!/usr/bin/env node
/**
 * CI lint: verify that docs/self-host.md contains the Stage-5 consolidated
 * section required by Stage-5 Task 13.
 *
 * Checks performed:
 *   1. docs/self-host.md exists.
 *   2. The file contains the required top-level section heading
 *      "## 12. Stage 5 — Enterprise Deployment".
 *   3. The following required sub-sections are present AND appear in the
 *      correct ascending order (§12.1 before §12.2, §12.2 before §12.3, …):
 *      §12.1  Updated service topology
 *      §12.2  Partner DID federation
 *      §12.3  SCIM 2.0 provisioning
 *      §12.4  Cross-chain audit anchor
 *      §12.5  SOC2 audit-trail export
 *      §12.6  DB Token Service
 *      §12.7  Storage Grant Service
 *      §12.8  AGT in-process guard
 *      §12.9  Discovery endpoint v1.0.0
 *      §12.10 On-prem deployment bundle
 *      §12.11 Stage-5 docker-compose additions
 *      §12.12 did:ion productionization
 *      §12.13 Compliance checklists
 *      §12.14 Stage-5 security checklist
 *   4. The compliance checklists section contains the three required
 *      sub-headings (SOC2, DID federation, SCIM provisioning).
 *   5. The minimum viable air-gapped setup block is present (§12.10.2).
 *   6. The header block references the enterprise-federation-threat-model.
 *   7. The §2 feature matrix no longer contains "Stage 5" as a placeholder
 *      (i.e. Stage-5 features are marked as available, not deferred).
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-stage5-docs.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Exit codes:
 *   0 -- all checks pass
 *   1 -- one or more checks failed or file is missing
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
// File check
// ---------------------------------------------------------------------------

const selfHostPath = resolve(workspaceRoot, 'docs', 'self-host.md');

if (!existsSync(selfHostPath)) {
  console.error(`FAIL docs/self-host.md not found at ${selfHostPath}`);
  process.exit(1);
}

const content = readFileSync(selfHostPath, 'utf8');

// ---------------------------------------------------------------------------
// Required checks
// ---------------------------------------------------------------------------

const failures = [];

/**
 * Assert that the content contains the given string.
 * @param {string} needle
 * @param {string} description
 */
function requireText(needle, description) {
  if (!content.includes(needle)) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
  }
}

// 1. Top-level Stage-5 heading
requireText(
  '## 12. Stage 5 — Enterprise Deployment',
  '§12 top-level heading "## 12. Stage 5 — Enterprise Deployment"',
);

// 2. Required sub-sections — present AND in ascending order
const requiredSubsections = [
  ['### 12.1 Updated service topology',               '§12.1 Updated service topology'],
  ['### 12.2 Partner DID federation',                 '§12.2 Partner DID federation'],
  ['### 12.3 SCIM 2.0 provisioning',                  '§12.3 SCIM 2.0 provisioning'],
  ['### 12.4 Cross-chain audit anchor',               '§12.4 Cross-chain audit anchor'],
  ['### 12.5 SOC2 audit-trail export',                '§12.5 SOC2 audit-trail export'],
  ['### 12.6 DB Token Service',                       '§12.6 DB Token Service'],
  ['### 12.7 Storage Grant Service',                  '§12.7 Storage Grant Service'],
  ['### 12.8 AGT in-process guard',                   '§12.8 AGT in-process guard'],
  ['### 12.9 Discovery endpoint v1.0.0',              '§12.9 Discovery endpoint v1.0.0'],
  ['### 12.10 On-prem deployment bundle',             '§12.10 On-prem deployment bundle'],
  ['### 12.11 Stage-5 docker-compose additions',      '§12.11 Stage-5 docker-compose additions'],
  ['### 12.12 `did:ion` productionization',           '§12.12 did:ion productionization'],
  ['### 12.13 Compliance checklists',                 '§12.13 Compliance checklists'],
  ['### 12.14 Stage-5 security checklist',            '§12.14 Stage-5 security checklist'],
];

let lastPos = -1;
for (const [needle, description] of requiredSubsections) {
  const pos = content.indexOf(needle);
  if (pos === -1) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
    // Reset lastPos so subsequent ordering errors are not cascaded from a missing section
    lastPos = -1;
  } else if (lastPos !== -1 && pos <= lastPos) {
    failures.push(
      `Out of order: ${description} appears before the previous required sub-section ` +
      `(position ${pos} is not after ${lastPos})`,
    );
  } else {
    lastPos = pos;
  }
}

// 3. Three compliance checklist sub-headings inside §12.13
requireText(
  '12.13.1 SOC2 controls checklist',
  '§12.13.1 SOC2 controls checklist',
);
requireText(
  '12.13.2 DID federation checklist',
  '§12.13.2 DID federation checklist',
);
requireText(
  '12.13.3 SCIM provisioning checklist',
  '§12.13.3 SCIM provisioning checklist',
);

// 4. Air-gapped setup section present
requireText(
  '12.10.2 Minimum viable air-gapped setup',
  '§12.10.2 Minimum viable air-gapped setup',
);

// 5. Service topology diagram (ASCII block starting after §12.1)
requireText(
  'Stage 5 full stack',
  'service topology diagram in §12.1 (ASCII art header)',
);

// 6. Enterprise federation threat model referenced in §12
requireText(
  'enterprise-federation-threat-model.md',
  'enterprise-federation-threat-model.md cross-link in §12',
);

// 7. The §2 feature matrix should no longer contain "Stage 5 |" as a plain
//    placeholder cell (the old "❌ — Stage 5" rows). Partial text matches
//    for the specific old placeholder values.
const staleMatrixRows = [
  '❌ — Stage 5 |',
];
for (const staleRow of staleMatrixRows) {
  if (content.includes(staleRow)) {
    failures.push(
      `Stale feature matrix row found: ${JSON.stringify(staleRow)}. ` +
      'Stage-5 features should be marked as available (✅) in §2.',
    );
  }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

if (failures.length > 0) {
  console.error('FAIL Stage-5 docs check failed:\n');
  for (const f of failures) {
    console.error(`  • ${f}`);
  }
  process.exit(1);
}

console.log('OK Stage-5 docs check passed');

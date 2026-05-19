/**
 * Unit tests for scripts/check-threat-model-signoff.mjs
 *
 * Uses Node.js built-in test runner (node:test) -- no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-threat-model-signoff.test.mjs
 *
 * Each test builds a synthetic fixture directory under os.tmpdir() and
 * invokes the script via child_process.spawnSync, asserting exit code and
 * output content.
 *
 * The script checks two threat model files:
 *   - docs/security/issuer-identity-threat-model.md  (Stage 4, CR-2)
 *   - docs/security/enterprise-federation-threat-model.md  (Stage 5, Task 1)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const scriptPath = resolve(__dirname, '..', 'check-threat-model-signoff.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Valid signed-off content for the Stage-4 issuer identity threat model.
 * @type {string}
 */
const ISSUER_SIGNED_OFF = '# Issuer Identity Threat Model\n\n**Authors:** Alice\n**Reviewers:** Bob — 2026-05-18\n';

/**
 * Valid signed-off content for the Stage-5 enterprise federation threat model.
 * @type {string}
 */
const ENTERPRISE_SIGNED_OFF =
  '# Enterprise Federation Threat Model Addendum\n\n' +
  '> **Status:** Approved (2026-05-19)\n\n' +
  '| Engineer 1 | Engineer | 2026-05-19 | no issues |\n' +
  '| Engineer 2 | Engineer | 2026-05-19 | no issues |\n' +
  '| Security Reviewer | Security | 2026-05-19 | approved |\n';

/**
 * Creates a temporary workspace root with both threat model files set to the
 * provided contents.  Pass `null` for a file to omit it entirely.
 *
 * @param {string | null} issuerContent  Content for issuer-identity-threat-model.md
 * @param {string | null} enterpriseContent  Content for enterprise-federation-threat-model.md
 * @returns {string} path to the temporary workspace root
 */
function makeFixture(issuerContent, enterpriseContent) {
  const root = mkdtempSync(join(tmpdir(), 'euno-signoff-test-'));
  const secDir = join(root, 'docs', 'security');
  mkdirSync(secDir, { recursive: true });
  if (issuerContent !== null) {
    writeFileSync(join(secDir, 'issuer-identity-threat-model.md'), issuerContent, 'utf8');
  }
  if (enterpriseContent !== null) {
    writeFileSync(join(secDir, 'enterprise-federation-threat-model.md'), enterpriseContent, 'utf8');
  }
  return root;
}

/**
 * Runs the script against a given workspace root.
 * Returns { exitCode, stdout, stderr }.
 */
function run(root) {
  const result = spawnSync(process.execPath, [scriptPath, '--root', root], {
    encoding: 'utf8',
  });
  return {
    exitCode: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

// ---------------------------------------------------------------------------
// Tests — both files signed off
// ---------------------------------------------------------------------------

test('passes when both threat models are signed off', () => {
  const root = makeFixture(ISSUER_SIGNED_OFF, ENTERPRISE_SIGNED_OFF);
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0, 'should exit 0 when both are signed off');
    assert.match(stdout, /OK threat model sign-off check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tests — Stage-4 issuer identity threat model
// ---------------------------------------------------------------------------

test('fails when issuer identity threat model contains the _(add names placeholder)', () => {
  const root = makeFixture(
    '# Issuer Identity Threat Model\n\n**Authors:** _(add names at review)_\n**Reviewers:** _(add names at review)_\n',
    ENTERPRISE_SIGNED_OFF,
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when placeholder is present');
    assert.match(stderr, /still contains the sign-off placeholder/);
    assert.match(stderr, /_\(add names/);
    assert.match(stderr, /issuer-identity-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the issuer identity threat model file is missing', () => {
  const root = makeFixture(null, ENTERPRISE_SIGNED_OFF);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when file does not exist');
    assert.match(stderr, /threat model file not found/);
    assert.match(stderr, /issuer-identity-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tests — Stage-5 enterprise federation threat model
// ---------------------------------------------------------------------------

test('fails when enterprise threat model contains _(name)_ placeholder in sign-off table', () => {
  const root = makeFixture(
    ISSUER_SIGNED_OFF,
    '# Enterprise Federation Threat Model\n\n> **Status:** Approved\n\n' +
      '| _(name)_ | Engineer | 2026-05-19 | |\n',
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when _(name)_ placeholder is present');
    assert.match(stderr, /still contains the sign-off placeholder/);
    assert.match(stderr, /_\(name\)_/);
    assert.match(stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when enterprise threat model contains _(date)_ placeholder in sign-off table', () => {
  const root = makeFixture(
    ISSUER_SIGNED_OFF,
    '# Enterprise Federation Threat Model\n\n> **Status:** Approved\n\n' +
      '| Engineer 1 | Engineer | _(date)_ | |\n',
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when _(date)_ placeholder is present');
    assert.match(stderr, /still contains the sign-off placeholder/);
    assert.match(stderr, /_\(date\)_/);
    assert.match(stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when enterprise threat model still contains the "Status: Placeholder" stub notice', () => {
  // Fixture has no _(name)_ or _(date)_ so the Status: Placeholder check is
  // the first placeholder matched — exercising that specific code path.
  const root = makeFixture(
    ISSUER_SIGNED_OFF,
    '# Enterprise Federation Threat Model\n\n> **Status: Placeholder — to be completed in Task 1.**\n\n' +
      '| Engineer 1 | Engineer | 2026-05-19 | approved |\n',
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when Status: Placeholder is present');
    assert.match(stderr, /still contains the sign-off placeholder/);
    assert.match(stderr, /Status: Placeholder/);
    assert.match(stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the enterprise federation threat model file is missing', () => {
  const root = makeFixture(ISSUER_SIGNED_OFF, null);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when file does not exist');
    assert.match(stderr, /threat model file not found/);
    assert.match(stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports errors from both files when both have issues', () => {
  const root = makeFixture(
    '# Issuer Identity Threat Model\n\n**Authors:** _(add names at review)_\n',
    '# Enterprise Federation Threat Model\n\n| _(name)_ | Engineer | _(date)_ | |\n',
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when both have placeholders');
    // Both checkFile() calls run independently — stderr must contain error
    // lines for both files.
    assert.match(stderr, /issuer-identity-threat-model/);
    assert.match(stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tests — argument parsing
// ---------------------------------------------------------------------------

test('fails with a useful error message when --root is provided without a value', () => {
  // Pass --root as the last argument with no subsequent path
  const result = spawnSync(process.execPath, [scriptPath, '--root'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 1, 'should exit 1 on missing --root argument');
  assert.match(result.stderr || '', /--root requires a path argument/);
});

test('fails with a useful error message on an unknown argument', () => {
  const root = makeFixture(ISSUER_SIGNED_OFF, ENTERPRISE_SIGNED_OFF);
  try {
    const result = spawnSync(
      process.execPath,
      [scriptPath, '--root', root, '--unknown-flag'],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 1, 'should exit 1 on unknown argument');
    assert.match(result.stderr || '', /unknown argument/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('accepts --root=<path> (equals-sign form)', () => {
  const root = makeFixture(ISSUER_SIGNED_OFF, ENTERPRISE_SIGNED_OFF);
  try {
    const result = spawnSync(process.execPath, [`${scriptPath}`, `--root=${root}`], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, '--root=<path> form should work');
    assert.match(result.stdout || '', /OK/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

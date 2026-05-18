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
 * Creates a temporary workspace root with the given threat model content
 * at docs/security/issuer-identity-threat-model.md.
 *
 * @param {string | null} content  File content, or null to omit the file.
 * @returns {string} path to the temporary workspace root
 */
function makeFixture(content) {
  const root = mkdtempSync(join(tmpdir(), 'euno-signoff-test-'));
  if (content !== null) {
    const secDir = join(root, 'docs', 'security');
    mkdirSync(secDir, { recursive: true });
    writeFileSync(join(secDir, 'issuer-identity-threat-model.md'), content, 'utf8');
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
// Tests
// ---------------------------------------------------------------------------

test('passes when threat model contains no placeholder text', () => {
  const root = makeFixture(
    '# Issuer Identity Threat Model\n\n**Authors:** Alice\n**Reviewers:** Bob — 2026-05-18\n',
  );
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0, 'should exit 0 when signed off');
    assert.match(stdout, /OK threat model sign-off check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when threat model still contains the _(add names placeholder', () => {
  const root = makeFixture(
    '# Issuer Identity Threat Model\n\n**Authors:** _(add names at review)_\n**Reviewers:** _(add names at review)_\n',
  );
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when placeholder is present');
    assert.match(stderr, /still contains the sign-off placeholder/);
    assert.match(stderr, /_\(add names/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the threat model file is missing', () => {
  const root = makeFixture(null); // no file created
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when file does not exist');
    assert.match(stderr, /threat model file not found/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails with a useful error message when --root is provided without a value', () => {
  // Pass --root as the last argument with no subsequent path
  const result = spawnSync(process.execPath, [scriptPath, '--root'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 1, 'should exit 1 on missing --root argument');
  assert.match(result.stderr || '', /--root requires a path argument/);
});

test('fails with a useful error message on an unknown argument', () => {
  const root = makeFixture('# signed off\n');
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
  const root = makeFixture('# Issuer Identity Threat Model\n**Authors:** Alice\n**Reviewers:** Bob\n');
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

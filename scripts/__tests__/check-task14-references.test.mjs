/**
 * Unit tests for scripts/check-task14-references.mjs
 *
 * Uses Node.js built-in test runner (node:test) — no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-task14-references.test.mjs
 *
 * Each test builds a synthetic fixture directory under os.tmpdir() and
 * invokes the script via child_process.spawnSync, asserting exit code and
 * output content.
 *
 * The script validates that the Task-14 Stage-5 reference materials are
 * present across docs/mvp.md, README.md, the CLI README, and the four
 * un-quarantined package CHANGELOGs.
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
const scriptPath = resolve(__dirname, '..', 'check-task14-references.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates a temp directory with the necessary sub-directory structure. */
function makeTmpRoot() {
  const base = mkdtempSync(join(tmpdir(), 'euno-task14-test-'));
  mkdirSync(join(base, 'docs'), { recursive: true });
  mkdirSync(join(base, 'public', 'packages', 'cli'), { recursive: true });
  for (const pkg of [
    'partner-issuer-sim',
    'posture-emitter',
    'db-token-service',
    'storage-grant-service',
  ]) {
    mkdirSync(join(base, 'euno-platform', 'packages', pkg), { recursive: true });
  }
  return base;
}

/** Minimal valid docs/mvp.md content containing a Task 14 entry. */
function makeMvpDoc() {
  return [
    '# MVP',
    '',
    '> **Stage 5 — status block (current)**',
    '>',
    '> - [x] Task 0 — threat model gate',
    '> - [x] Task 14 — Stage-5 status block + reference materials: docs/mvp.md Stage-5 status block completed',
    '',
  ].join('\n');
}

/** Minimal valid README.md content with a Stage-5 enterprise section. */
function makeRootReadme() {
  return [
    '# euno',
    '',
    '| Stage | Ships | Status |',
    '|-------|-------|--------|',
    '| 4 | Capability Issuer | ✅ Done |',
    '| 5 | Enterprise: DID federation, KMS, SOC 2 | ✅ **Done** |',
    '',
    '### Enterprise deployment (Stage 5)',
    '',
    'Stage 5 adds the full enterprise compliance and federation tier.',
    '',
    'See docs/self-host.md §12 for the complete runbook.',
    '',
  ].join('\n');
}

/** Minimal valid CLI README content with Stage-5 enterprise features. */
function makeCliReadme() {
  return [
    '# @euno/cli',
    '',
    '## Stage 5: Enterprise Features',
    '',
    '### Partner DID federation',
    '',
    'euno validate-token eyJ... --iss did:web:partner.example.com',
    '',
    '### SOC 2 audit export',
    '',
    'euno audit export --gateway-url https://gateway.example --admin-key $KEY',
    '',
  ].join('\n');
}

/** Minimal valid CHANGELOG.md content containing a [1.0.0] entry. */
function makeChangelog(pkgName) {
  return [
    `# Changelog — ${pkgName}`,
    '',
    'All notable changes to this package will be documented in this file.',
    '',
    '## [1.0.0] — Stage 5 GA',
    '',
    '### Changed',
    '',
    '- Package status updated from Quarantined to GA.',
    '',
  ].join('\n');
}

/** Writes all fixture files for a fully compliant workspace. */
function writeAllFixtures(root) {
  writeFileSync(join(root, 'docs', 'mvp.md'), makeMvpDoc());
  writeFileSync(join(root, 'README.md'), makeRootReadme());
  writeFileSync(join(root, 'public', 'packages', 'cli', 'README.md'), makeCliReadme());
  for (const pkg of [
    'partner-issuer-sim',
    'posture-emitter',
    'db-token-service',
    'storage-grant-service',
  ]) {
    writeFileSync(
      join(root, 'euno-platform', 'packages', pkg, 'CHANGELOG.md'),
      makeChangelog(pkg),
    );
  }
}

/** Runs the script against a given fixture root. */
function runScript(root) {
  return spawnSync(
    process.execPath,
    [scriptPath, '--root', root],
    { encoding: 'utf8' },
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('passes with all reference materials present', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const result = runScript(root);
    assert.strictEqual(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.match(result.stdout, /OK Task-14 reference check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when docs/mvp.md is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'docs', 'mvp.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Missing file.*mvp\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when docs/mvp.md lacks the Task 14 entry', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeMvpDoc().replace('Task 14', 'Task X');
    writeFileSync(join(root, 'docs', 'mvp.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Task 14/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when README.md is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'README.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Missing file.*README\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when README.md lacks the Stage-5 enterprise section heading', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeRootReadme().replace('Enterprise deployment (Stage 5)', 'REMOVED');
    writeFileSync(join(root, 'README.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Stage-5 enterprise section heading/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when README.md Stage-5 row still says "Planned"', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeRootReadme().replace('✅ **Done**', 'Planned');
    writeFileSync(join(root, 'README.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Planned/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when CLI README is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'public', 'packages', 'cli', 'README.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Missing file.*cli.*README\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when CLI README lacks the Stage-5 enterprise features section', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeCliReadme().replace('Stage 5: Enterprise Features', 'REMOVED');
    writeFileSync(join(root, 'public', 'packages', 'cli', 'README.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Stage 5: Enterprise Features/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when CLI README lacks partner-federation reference', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeCliReadme()
      .replace('Partner DID federation', 'REMOVED')
      .replace('euno validate-token eyJ... --iss did:web:partner.example.com', '');
    writeFileSync(join(root, 'public', 'packages', 'cli', 'README.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /partner/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when CLI README lacks SOC2 audit export reference', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const doc = makeCliReadme()
      .replaceAll('audit export', 'AUDIT_REMOVED');
    writeFileSync(join(root, 'public', 'packages', 'cli', 'README.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /audit export/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when posture-emitter CHANGELOG.md is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'euno-platform', 'packages', 'posture-emitter', 'CHANGELOG.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /posture-emitter.*CHANGELOG/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when db-token-service CHANGELOG.md is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'euno-platform', 'packages', 'db-token-service', 'CHANGELOG.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /db-token-service.*CHANGELOG/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when storage-grant-service CHANGELOG.md is missing', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    rmSync(join(root, 'euno-platform', 'packages', 'storage-grant-service', 'CHANGELOG.md'));
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /storage-grant-service.*CHANGELOG/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when a CHANGELOG.md lacks a [1.0.0] entry', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const badChangelog = makeChangelog('db-token-service').replace('[1.0.0]', '[0.9.0]');
    writeFileSync(
      join(root, 'euno-platform', 'packages', 'db-token-service', 'CHANGELOG.md'),
      badChangelog,
    );
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /\[1\.0\.0\]/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails with a useful error message on an unknown argument', () => {
  const result = spawnSync(
    process.execPath,
    [scriptPath, '--unknown-flag'],
    { encoding: 'utf8' },
  );
  assert.strictEqual(result.status, 1);
  assert.match(result.stderr, /Unknown argument/);
});

test('accepts --root=<path> (equals-sign form)', () => {
  const root = makeTmpRoot();
  try {
    writeAllFixtures(root);
    const result = spawnSync(
      process.execPath,
      [scriptPath, `--root=${root}`],
      { encoding: 'utf8' },
    );
    assert.strictEqual(result.status, 0, `stderr: ${result.stderr}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

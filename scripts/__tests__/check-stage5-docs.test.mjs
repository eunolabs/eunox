/**
 * Unit tests for scripts/check-stage5-docs.mjs
 *
 * Uses Node.js built-in test runner (node:test) — no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-stage5-docs.test.mjs
 *
 * Each test builds a synthetic fixture directory under os.tmpdir() and
 * invokes the script via child_process.spawnSync, asserting exit code and
 * output content.
 *
 * The script checks docs/self-host.md for the Stage-5 consolidated section
 * required by Stage-5 Task 13.
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
const scriptPath = resolve(__dirname, '..', 'check-stage5-docs.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates a temp directory with the necessary directory structure. */
function makeTmpRoot() {
  const base = mkdtempSync(join(tmpdir(), 'euno-stage5-docs-test-'));
  mkdirSync(join(base, 'docs'), { recursive: true });
  return base;
}

/** Minimal valid Stage-5 self-host.md content. */
function makeValidDoc() {
  return [
    '# Self-Hosting euno',
    '',
    '## 2. What you give up versus managed cloud',
    '',
    '| Evidence export (signed OCSF) | Cloud Enterprise | ✅ — available (§12.5) |',
    '',
    '## 12. Stage 5 — Enterprise Deployment',
    '',
    '> **Key documents**',
    '> - enterprise-federation-threat-model.md — Stage 5 threat model',
    '',
    '### 12.1 Updated service topology',
    '',
    '```',
    'Stage 5 full stack',
    '```',
    '',
    '### 12.2 Partner DID federation',
    '',
    '### 12.3 SCIM 2.0 provisioning',
    '',
    '### 12.4 Cross-chain audit anchor',
    '',
    '### 12.5 SOC2 audit-trail export',
    '',
    '### 12.6 DB Token Service',
    '',
    '### 12.7 Storage Grant Service',
    '',
    '### 12.8 AGT in-process guard',
    '',
    '### 12.9 Discovery endpoint v1.0.0',
    '',
    '### 12.10 On-prem deployment bundle (Helm + air-gap)',
    '',
    '#### 12.10.2 Minimum viable air-gapped setup',
    '',
    'Details here.',
    '',
    '### 12.11 Stage-5 docker-compose additions (`full` profile)',
    '',
    '### 12.12 `did:ion` productionization',
    '',
    '### 12.13 Compliance checklists',
    '',
    '#### 12.13.1 SOC2 controls checklist',
    '',
    '#### 12.13.2 DID federation checklist',
    '',
    '#### 12.13.3 SCIM provisioning checklist',
    '',
    '### 12.14 Stage-5 security checklist',
    '',
  ].join('\n');
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

test('passes with a fully compliant self-host.md', () => {
  const root = makeTmpRoot();
  try {
    writeFileSync(join(root, 'docs', 'self-host.md'), makeValidDoc());
    const result = runScript(root);
    assert.strictEqual(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.match(result.stdout, /OK Stage-5 docs check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when self-host.md is missing', () => {
  const root = makeTmpRoot();
  try {
    // Do not create self-host.md
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /not found/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the Stage-5 top-level heading is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace(
      '## 12. Stage 5 — Enterprise Deployment',
      '## 12. Stage 4 only',
    );
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Stage 5 — Enterprise Deployment/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when a required sub-section is absent (§12.4 cross-chain)', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace(
      '### 12.4 Cross-chain audit anchor',
      '### 12.4 REMOVED',
    );
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Cross-chain audit anchor/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when sub-sections appear out of order (§12.5 before §12.4)', () => {
  const root = makeTmpRoot();
  try {
    // Swap §12.4 and §12.5 so ordering is violated
    const valid = makeValidDoc();
    const doc = valid
      .replace('### 12.4 Cross-chain audit anchor', '### 12.4 SWAP_PLACEHOLDER')
      .replace('### 12.5 SOC2 audit-trail export', '### 12.4 Cross-chain audit anchor')
      .replace('### 12.4 SWAP_PLACEHOLDER', '### 12.5 SOC2 audit-trail export');
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /[Oo]ut of order/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when §12.13.1 SOC2 controls checklist is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace('12.13.1 SOC2 controls checklist', '12.13.1 REMOVED');
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /SOC2 controls checklist/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when §12.13.2 DID federation checklist is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace('12.13.2 DID federation checklist', '12.13.2 REMOVED');
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /DID federation checklist/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when §12.13.3 SCIM provisioning checklist is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace('12.13.3 SCIM provisioning checklist', '12.13.3 REMOVED');
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /SCIM provisioning checklist/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when air-gapped setup section is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace(
      '12.10.2 Minimum viable air-gapped setup',
      '12.10.2 REMOVED',
    );
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /air-gapped setup/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the service topology diagram marker is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace('Stage 5 full stack', 'TOPOLOGY REMOVED');
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /topology diagram/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when the enterprise-federation-threat-model cross-link is absent', () => {
  const root = makeTmpRoot();
  try {
    const doc = makeValidDoc().replace(
      'enterprise-federation-threat-model.md',
      'some-other-doc.md',
    );
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /enterprise-federation-threat-model/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when a stale "Stage 5 |" placeholder cell remains in the §2 feature matrix', () => {
  const root = makeTmpRoot();
  try {
    // Add back the old stale marker
    const doc = makeValidDoc() +
      '\n| Cross-chain audit anchor | Stage 5 | ❌ — Stage 5 |\n';
    writeFileSync(join(root, 'docs', 'self-host.md'), doc);
    const result = runScript(root);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /Stale feature matrix row/);
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
    writeFileSync(join(root, 'docs', 'self-host.md'), makeValidDoc());
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

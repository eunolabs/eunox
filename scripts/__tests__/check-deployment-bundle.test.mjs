/**
 * Unit tests for scripts/check-deployment-bundle.mjs
 *
 * Uses Node.js built-in test runner (node:test) — no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-deployment-bundle.test.mjs
 *
 * Each test builds a synthetic fixture directory under os.tmpdir() and
 * invokes the script via child_process.spawnSync, asserting exit code and
 * stderr content.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, unlinkSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const scriptPath = resolve(__dirname, '..', 'check-deployment-bundle.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpRoot() {
  const base = mkdtempSync(join(tmpdir(), 'euno-deploy-bundle-test-'));
  mkdirSync(join(base, 'docs'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'euno', 'templates'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'gateway'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'issuer'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'api-key-minter'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'db-token-service'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'storage-grant-service'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'posture-emitter'), { recursive: true });
  mkdirSync(join(base, 'infra'), { recursive: true });
  mkdirSync(join(base, 'scripts'), { recursive: true });
  return base;
}

function makeSchema(title) {
  return JSON.stringify({
    '$schema': 'https://json-schema.org/draft-07/schema#',
    title,
    type: 'object',
    properties: { env: { type: 'object', properties: {}, additionalProperties: false } },
    required: ['env'],
  });
}

function makeValidBundle(base) {
  // Helm per-service schemas
  for (const svc of ['gateway', 'issuer', 'api-key-minter', 'db-token-service', 'storage-grant-service', 'posture-emitter']) {
    writeFileSync(join(base, 'k8s', 'helm', svc, 'values.schema.json'), makeSchema(`${svc} Helm values`));
  }

  // Umbrella chart
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'Chart.yaml'), [
    'apiVersion: v2',
    'name: euno',
    'description: Umbrella chart covering tool-gateway, capability-issuer, api-key-minter,',
    '  db-token-service, storage-grant-service, posture-emitter.',
    'version: 1.0.0',
  ].join('\n'));
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values.yaml'), '# values\n');
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'templates', '_helpers.tpl'), '{{/* helpers */}}\n');

  // Air-gap image list
  writeFileSync(join(base, 'k8s', 'air-gap-images.txt'), [
    '# images',
    'ghcr.io/edgeobs/euno/tool-gateway:1.0.0@sha256:abc1',
    'ghcr.io/edgeobs/euno/capability-issuer:1.0.0@sha256:abc2',
    'ghcr.io/edgeobs/euno/api-key-minter:1.0.0@sha256:abc3',
    'ghcr.io/edgeobs/euno/db-token-service:1.0.0@sha256:abc4',
    'ghcr.io/edgeobs/euno/storage-grant-service:1.0.0@sha256:abc5',
    'ghcr.io/edgeobs/euno/posture-emitter:1.0.0@sha256:abc6',
  ].join('\n'));

  // pull-air-gap-images.sh
  writeFileSync(join(base, 'scripts', 'pull-air-gap-images.sh'), [
    '#!/bin/sh',
    'PRIVATE_REGISTRY="${PRIVATE_REGISTRY:-}"',
    '# reads k8s/air-gap-images.txt',
    'IMAGE_LIST_FILE="${IMAGE_LIST_FILE:-air-gap-images.txt}"',
  ].join('\n'));

  // docker-compose.yml
  writeFileSync(join(base, 'infra', 'docker-compose.yml'), [
    'version: "3.9"',
    'volumes:',
    '  posture-data:',
    '    driver: local',
    'services:',
    '  posture-emitter:',
    '    image: euno/posture-emitter:local',
    '    volumes:',
    '      - posture-data:/data',
    '    profiles: ["full"]',
  ].join('\n'));

  // smoke-test.sh
  writeFileSync(join(base, 'infra', 'smoke-test.sh'), [
    '#!/bin/sh',
    'DB_TOKEN_SERVICE_URL="${DB_TOKEN_SERVICE_URL:-}"',
    'STORAGE_GRANT_SERVICE_URL="${STORAGE_GRANT_SERVICE_URL:-}"',
    '# DB Token Service section',
    'if [ -n "$DB_TOKEN_SERVICE_URL" ]; then',
    '  echo "DB Token Service checks"',
    'fi',
    '# Storage Grant Service section',
    'if [ -n "$STORAGE_GRANT_SERVICE_URL" ]; then',
    '  echo "Storage Grant Service checks"',
    'fi',
  ].join('\n'));

  // DEPLOYMENT.md
  writeFileSync(join(base, 'docs', 'DEPLOYMENT.md'), [
    '# Deployment Notes',
    '',
    '## Stage-5 on-prem deployment',
    '',
    'The `k8s/helm/euno/` umbrella chart.',
    'See `k8s/air-gap-images.txt` and `scripts/pull-air-gap-images.sh`.',
    'posture-emitter: single-writer SQLite drainer.',
    '',
    '### Restricted-network checklist',
    '',
    '| Endpoint | Required for |',
    '|---|---|',
    '| KMS | Token signing |',
  ].join('\n'));
}

function run(root) {
  return spawnSync(process.execPath, [scriptPath, '--root', root], {
    encoding: 'utf8',
    timeout: 15000,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('passes on a fully valid deployment bundle', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    const result = run(base);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.match(result.stdout, /all checks passed/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when posture-emitter helm schema is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    // Remove posture-emitter schema
    unlinkSync(join(base, 'k8s', 'helm', 'posture-emitter', 'values.schema.json'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /posture-emitter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when api-key-minter helm schema is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    unlinkSync(join(base, 'k8s', 'helm', 'api-key-minter', 'values.schema.json'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /api-key-minter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when a helm schema has invalid JSON', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'k8s', 'helm', 'gateway', 'values.schema.json'), '{not valid json}');
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Invalid JSON/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when a helm schema is missing the env property', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(
      join(base, 'k8s', 'helm', 'issuer', 'values.schema.json'),
      JSON.stringify({ '$schema': 'https://json-schema.org/draft-07/schema#', title: 'issuer', type: 'object', properties: {} }),
    );
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /env/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when umbrella Chart.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    unlinkSync(join(base, 'k8s', 'helm', 'euno', 'Chart.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Chart\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when umbrella Chart.yaml does not declare apiVersion: v2', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'Chart.yaml'), 'apiVersion: v1\nname: euno\nversion: 1.0.0\n');
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /apiVersion: v2/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when umbrella Chart.yaml does not reference posture-emitter', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'Chart.yaml'), [
      'apiVersion: v2',
      'name: euno',
      'description: covers tool-gateway only',
      'version: 1.0.0',
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /posture-emitter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when air-gap-images.txt is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    unlinkSync(join(base, 'k8s', 'air-gap-images.txt'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /air-gap/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when air-gap-images.txt is missing a service image', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    // Omit posture-emitter from the image list
    writeFileSync(join(base, 'k8s', 'air-gap-images.txt'), [
      'ghcr.io/edgeobs/euno/tool-gateway:1.0.0@sha256:abc1',
      'ghcr.io/edgeobs/euno/capability-issuer:1.0.0@sha256:abc2',
      'ghcr.io/edgeobs/euno/api-key-minter:1.0.0@sha256:abc3',
      'ghcr.io/edgeobs/euno/db-token-service:1.0.0@sha256:abc4',
      'ghcr.io/edgeobs/euno/storage-grant-service:1.0.0@sha256:abc5',
      // posture-emitter intentionally omitted
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /posture-emitter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when pull-air-gap-images.sh is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    unlinkSync(join(base, 'scripts', 'pull-air-gap-images.sh'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /pull-air-gap-images/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when docker-compose.yml does not include posture-emitter', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'infra', 'docker-compose.yml'), [
      'version: "3.9"',
      'volumes:',
      '  posture-data:',
      '    driver: local',
      'services:',
      '  gateway:',
      '    image: euno/tool-gateway:local',
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /posture-emitter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when docker-compose.yml is missing posture-data volume', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'infra', 'docker-compose.yml'), [
      'version: "3.9"',
      'services:',
      '  posture-emitter:',
      '    image: euno/posture-emitter:local',
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /posture-data/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when smoke-test.sh does not reference DB_TOKEN_SERVICE_URL', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'infra', 'smoke-test.sh'), [
      '#!/bin/sh',
      'STORAGE_GRANT_SERVICE_URL="${STORAGE_GRANT_SERVICE_URL:-}"',
      '# Storage Grant Service section',
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /DB_TOKEN_SERVICE_URL/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when smoke-test.sh does not reference STORAGE_GRANT_SERVICE_URL', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'infra', 'smoke-test.sh'), [
      '#!/bin/sh',
      'DB_TOKEN_SERVICE_URL="${DB_TOKEN_SERVICE_URL:-}"',
      '# DB Token Service section',
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /STORAGE_GRANT_SERVICE_URL/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when DEPLOYMENT.md is missing the Stage-5 section', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'docs', 'DEPLOYMENT.md'), '# Deployment Notes\n\nNo Stage 5 here.\n');
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Stage-5 on-prem deployment/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when DEPLOYMENT.md is missing the restricted-network checklist', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    writeFileSync(join(base, 'docs', 'DEPLOYMENT.md'), [
      '# Deployment Notes',
      '',
      '## Stage-5 on-prem deployment',
      '',
      'See `k8s/air-gap-images.txt` and `scripts/pull-air-gap-images.sh`.',
      'k8s/helm/euno umbrella chart.',
      'posture-emitter drainer.',
      // intentionally omit Restricted-network checklist
    ].join('\n'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Restricted-network checklist/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails with a useful error message on an unknown argument', () => {
  const result = spawnSync(process.execPath, [scriptPath, '--unknown-flag'], {
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown argument/);
});

test('accepts --root=<path> (equals-sign form)', () => {
  const base = makeTmpRoot();
  try {
    makeValidBundle(base);
    const result = spawnSync(process.execPath, [`${scriptPath}`, `--root=${base}`], {
      encoding: 'utf8',
      timeout: 15000,
    });
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

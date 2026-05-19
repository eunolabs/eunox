#!/usr/bin/env node
/**
 * CI lint: verify that the Stage-5 on-prem deployment bundle is complete.
 *
 * Checks performed:
 *   1. Per-service Helm value schemas exist for all six services:
 *      gateway, issuer, api-key-minter, db-token-service,
 *      storage-grant-service, posture-emitter.
 *   2. Each schema file is valid JSON with the required top-level structure
 *      ($schema, title, properties.env).
 *   3. The umbrella chart files exist:
 *      k8s/helm/euno/Chart.yaml, k8s/helm/euno/values.yaml,
 *      k8s/helm/euno/templates/_helpers.tpl.
 *   4. k8s/air-gap-images.txt exists and lists all six Euno service images.
 *   5. scripts/pull-air-gap-images.sh exists and is not empty.
 *   6. infra/docker-compose.yml includes the posture-emitter service.
 *   7. infra/smoke-test.sh references DB_TOKEN_SERVICE_URL and
 *      STORAGE_GRANT_SERVICE_URL (Stage-5 round-trip checks).
 *   8. docs/DEPLOYMENT.md contains the §"Stage-5 on-prem deployment" section.
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-deployment-bundle.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
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

function requireFile(relPath, description) {
  const abs = resolve(workspaceRoot, relPath);
  if (!existsSync(abs)) {
    failures.push(`Missing file: ${description} (expected at ${relPath})`);
    return null;
  }
  return readFileSync(abs, 'utf8');
}

function requireText(content, needle, description) {
  if (content === null) return; // already failed above
  if (!content.includes(needle)) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
  }
}

function requireValidJson(content, relPath) {
  if (content === null) return null;
  try {
    return JSON.parse(content);
  } catch (e) {
    failures.push(`Invalid JSON: ${relPath} — ${e.message}`);
    return null;
  }
}

function requireJsonField(obj, keyPath, relPath) {
  if (obj === null) return;
  let cur = obj;
  for (const key of keyPath) {
    if (cur == null || typeof cur !== 'object' || !(key in cur)) {
      failures.push(`Missing JSON field: ${keyPath.join('.')} in ${relPath}`);
      return;
    }
    cur = cur[key];
  }
}

// ---------------------------------------------------------------------------
// Check 1 — Per-service Helm value schemas
// ---------------------------------------------------------------------------

const helmServices = [
  'gateway',
  'issuer',
  'api-key-minter',
  'db-token-service',
  'storage-grant-service',
  'posture-emitter',
];

for (const svc of helmServices) {
  const relPath = `k8s/helm/${svc}/values.schema.json`;
  const content = requireFile(relPath, `Helm values schema for ${svc}`);
  const obj = requireValidJson(content, relPath);
  if (obj !== null) {
    requireJsonField(obj, ['$schema'], relPath);
    requireJsonField(obj, ['title'], relPath);
    requireJsonField(obj, ['properties', 'env'], relPath);
  }
}

// ---------------------------------------------------------------------------
// Check 2 — Umbrella chart files
// ---------------------------------------------------------------------------

requireFile('k8s/helm/euno/Chart.yaml', 'umbrella chart Chart.yaml');
requireFile('k8s/helm/euno/values.yaml', 'umbrella chart values.yaml');
requireFile('k8s/helm/euno/templates/_helpers.tpl', 'umbrella chart _helpers.tpl');

// The Chart.yaml must list all six services as comment references or declare
// dependencies; at minimum it must exist and declare apiVersion: v2.
const chartYaml = requireFile('k8s/helm/euno/Chart.yaml', 'umbrella chart Chart.yaml');
requireText(chartYaml, 'apiVersion: v2', 'umbrella chart: apiVersion: v2');
requireText(chartYaml, 'tool-gateway', 'umbrella chart: references tool-gateway');
requireText(chartYaml, 'posture-emitter', 'umbrella chart: references posture-emitter');

// ---------------------------------------------------------------------------
// Check 3 — Air-gap image list
// ---------------------------------------------------------------------------

const airGapImages = requireFile('k8s/air-gap-images.txt', 'air-gap image list');

const requiredImages = [
  'tool-gateway',
  'capability-issuer',
  'api-key-minter',
  'db-token-service',
  'storage-grant-service',
  'posture-emitter',
];

for (const img of requiredImages) {
  requireText(airGapImages, img, `air-gap image list: includes ${img}`);
}

// ---------------------------------------------------------------------------
// Check 4 — pull-air-gap-images.sh
// ---------------------------------------------------------------------------

const pullScript = requireFile('scripts/pull-air-gap-images.sh', 'pull-air-gap-images.sh');
requireText(pullScript, 'PRIVATE_REGISTRY', 'pull-air-gap-images.sh: references PRIVATE_REGISTRY');
requireText(pullScript, 'air-gap-images.txt', 'pull-air-gap-images.sh: references air-gap-images.txt');

// ---------------------------------------------------------------------------
// Check 5 — docker-compose.yml includes posture-emitter
// ---------------------------------------------------------------------------

const dockerCompose = requireFile('infra/docker-compose.yml', 'infra/docker-compose.yml');
requireText(dockerCompose, 'posture-emitter', 'docker-compose.yml: includes posture-emitter service');
requireText(dockerCompose, 'posture-data', 'docker-compose.yml: posture-data named volume');

// ---------------------------------------------------------------------------
// Check 6 — smoke-test.sh Stage-5 additions
// ---------------------------------------------------------------------------

const smokeTest = requireFile('infra/smoke-test.sh', 'infra/smoke-test.sh');
requireText(smokeTest, 'DB_TOKEN_SERVICE_URL', 'smoke-test.sh: DB_TOKEN_SERVICE_URL Stage-5 check');
requireText(smokeTest, 'STORAGE_GRANT_SERVICE_URL', 'smoke-test.sh: STORAGE_GRANT_SERVICE_URL Stage-5 check');
requireText(smokeTest, 'DB Token Service', 'smoke-test.sh: DB Token Service section');
requireText(smokeTest, 'Storage Grant Service', 'smoke-test.sh: Storage Grant Service section');

// ---------------------------------------------------------------------------
// Check 7 — DEPLOYMENT.md Stage-5 section
// ---------------------------------------------------------------------------

const deploymentMd = requireFile('docs/DEPLOYMENT.md', 'docs/DEPLOYMENT.md');
requireText(deploymentMd, 'Stage-5 on-prem deployment', 'DEPLOYMENT.md: Stage-5 on-prem deployment section');
requireText(deploymentMd, 'air-gap-images.txt', 'DEPLOYMENT.md: references air-gap-images.txt');
requireText(deploymentMd, 'pull-air-gap-images.sh', 'DEPLOYMENT.md: references pull-air-gap-images.sh');
requireText(deploymentMd, 'k8s/helm/euno', 'DEPLOYMENT.md: references k8s/helm/euno');
requireText(deploymentMd, 'posture-emitter', 'DEPLOYMENT.md: references posture-emitter');
requireText(deploymentMd, 'Restricted-network checklist', 'DEPLOYMENT.md: restricted-network checklist');

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

if (failures.length === 0) {
  console.log('check-deployment-bundle: all checks passed.');
  process.exit(0);
} else {
  console.error('check-deployment-bundle: FAILED');
  for (const f of failures) {
    console.error(`  FAIL: ${f}`);
  }
  process.exit(1);
}

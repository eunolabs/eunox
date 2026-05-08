/**
 * Unit tests for scripts/check-license-boundary.mjs
 *
 * Uses Node.js built-in test runner (node:test) -- no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-license-boundary.test.mjs
 *
 * Each test builds a synthetic workspace fixture under os.tmpdir() and
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
const scriptPath = resolve(__dirname, '..', 'check-license-boundary.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Creates a temporary workspace root with the given packages.
 * Each entry in `pkgs` becomes packages/<name>/package.json.
 *
 * @param {Array<{ name: string, license?: string, deps?: Record<string,string> }>} pkgs
 * @returns {string} path to the temporary workspace root
 */
function makeFixture(pkgs) {
  const root = mkdtempSync(join(tmpdir(), 'euno-license-test-'));
  const packagesDir = join(root, 'packages');
  mkdirSync(packagesDir);

  // Write a root package.json so the script discovers packages via the
  // "workspaces" field rather than falling back to a hardcoded path.
  writeFileSync(
    join(root, 'package.json'),
    JSON.stringify({ name: 'test-workspace', workspaces: ['packages/*'] }, null, 2),
  );

  for (const p of pkgs) {
    const pkgDir = join(packagesDir, p.name.replace(/^@[^/]+\//, ''));
    mkdirSync(pkgDir, { recursive: true });
    const manifest = { name: p.name };
    if (p.license !== undefined) manifest.license = p.license;
    if (p.deps) manifest.dependencies = p.deps;
    if (p.devDeps) manifest.devDependencies = p.devDeps;
    if (p.peerDeps) manifest.peerDependencies = p.peerDeps;
    if (p.optionalDeps) manifest.optionalDependencies = p.optionalDeps;
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify(manifest, null, 2));
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

test('passes when all packages are Apache-2.0 with no cross-license deps', () => {
  const root = makeFixture([
    { name: '@test/core', license: 'Apache-2.0' },
    { name: '@test/cli', license: 'Apache-2.0', deps: { '@test/core': 'workspace:*' } },
  ]);
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0, 'should exit 0');
    assert.match(stdout, /OK\s+License boundary check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('passes when BUSL package depends on Apache-2.0 package (allowed direction)', () => {
  const root = makeFixture([
    { name: '@test/core', license: 'Apache-2.0' },
    { name: '@test/infra', license: 'BUSL-1.1', deps: { '@test/core': 'workspace:*' } },
  ]);
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0, 'BUSL -> Apache-2.0 is fine');
    assert.match(stdout, /OK\s+License boundary check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails on a direct Apache-2.0 -> BUSL-1.1 dependency', () => {
  const root = makeFixture([
    { name: '@test/core', license: 'Apache-2.0', deps: { '@test/infra': 'workspace:*' } },
    { name: '@test/infra', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 on violation');
    assert.match(stderr, /LICENSE BOUNDARY VIOLATION/);
    assert.match(stderr, /@test\/core/);
    assert.match(stderr, /@test\/infra/);
    assert.match(stderr, /Apache-2\.0/);
    assert.match(stderr, /BUSL-1\.1/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails on a transitive Apache-2.0 -> BUSL-1.1 dependency', () => {
  // core (Apache-2.0) -> adapter (Apache-2.0) -> infra (BUSL-1.1)
  // The script should catch the transitive violation core -> infra.
  const root = makeFixture([
    { name: '@test/core', license: 'Apache-2.0', deps: { '@test/adapter': 'workspace:*' } },
    { name: '@test/adapter', license: 'Apache-2.0', deps: { '@test/infra': 'workspace:*' } },
    { name: '@test/infra', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'transitive violation should fail');
    assert.match(stderr, /LICENSE BOUNDARY VIOLATION/);
    // Path must be mentioned
    assert.match(stderr, /@test\/adapter/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when a package is missing the license field', () => {
  const root = makeFixture([
    { name: '@test/no-license' }, // no license field
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'missing license should fail');
    assert.match(stderr, /missing "license" field/);
    assert.match(stderr, /@test\/no-license/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails when a package uses an unrecognized license string', () => {
  const root = makeFixture([
    { name: '@test/weird', license: 'MIT' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'unrecognized license should fail');
    assert.match(stderr, /unrecognized license/);
    assert.match(stderr, /MIT/);
    assert.match(stderr, /@test\/weird/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports ALLOW for allowlisted violations and still exits 0', () => {
  // The ALLOWLIST in the script is keyed to real repo package names
  // (e.g. @euno/cli -> @euno/common). Use those exact names in the fixture
  // so the allowlist path is actually exercised: an Apache-2.0 -> BUSL-1.1
  // edge that would otherwise be a violation is reported as ALLOW instead.
  const root = makeFixture([
    { name: '@euno/common', license: 'BUSL-1.1' },
    { name: '@euno/cli', license: 'Apache-2.0', deps: { '@euno/common': 'workspace:*' } },
  ]);
  try {
    const { exitCode, stdout, stderr } = run(root);
    assert.equal(exitCode, 0, 'allowlisted violation should still exit 0');
    assert.match(stdout, /ALLOW @euno\/cli -> @euno\/common/);
    assert.match(stdout, /OK/);
    assert.doesNotMatch(stderr, /LICENSE BOUNDARY VIOLATION/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('passes when packages directory is empty', () => {
  const root = mkdtempSync(join(tmpdir(), 'euno-license-test-'));
  const packagesDir = join(root, 'packages');
  mkdirSync(packagesDir);
  writeFileSync(
    join(root, 'package.json'),
    JSON.stringify({ name: 'test-workspace', workspaces: ['packages/*'] }, null, 2),
  );
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0);
    assert.match(stdout, /OK/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('error message names all three parts: from package, to package, and path', () => {
  const root = makeFixture([
    { name: '@test/a', license: 'Apache-2.0', deps: { '@test/b': '1.0.0' } },
    { name: '@test/b', license: 'Apache-2.0', deps: { '@test/c': '1.0.0' } },
    { name: '@test/c', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1);
    // Both the direct source and the final BUSL target should be named
    assert.match(stderr, /@test\/a/);
    assert.match(stderr, /@test\/c/);
    // The intermediate hop should appear in the path
    assert.match(stderr, /@test\/b/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// @euno/mcp-specific coverage (Task 12)
//
// These tests ensure that the script catches the exact edge that Task 12
// guards against: @euno/mcp (Apache-2.0) depending on @euno/common-infra
// (BUSL-1.1) in any dependency field.
// ---------------------------------------------------------------------------

test('@euno/mcp -> @euno/common-infra in dependencies is caught', () => {
  const root = makeFixture([
    { name: '@euno/mcp', license: 'Apache-2.0', deps: { '@euno/common-infra': 'workspace:*' } },
    { name: '@euno/common-infra', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'should exit 1 when @euno/mcp depends on @euno/common-infra');
    assert.match(stderr, /LICENSE BOUNDARY VIOLATION/);
    assert.match(stderr, /@euno\/mcp/);
    assert.match(stderr, /@euno\/common-infra/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('@euno/mcp -> @euno/common-infra in devDependencies is caught', () => {
  const root = makeFixture([
    {
      name: '@euno/mcp',
      license: 'Apache-2.0',
      devDeps: { '@euno/common-infra': 'workspace:*' },
    },
    { name: '@euno/common-infra', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'devDependencies edge should also be caught');
    assert.match(stderr, /LICENSE BOUNDARY VIOLATION/);
    assert.match(stderr, /@euno\/mcp/);
    assert.match(stderr, /@euno\/common-infra/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('@euno/mcp -> @euno/common-infra transitive via an Apache-2.0 shim is caught', () => {
  // Uses @euno/mcp as the origin (rather than @euno/cli) to verify the scan
  // root is not limited to packages already in the ALLOWLIST.
  // Transitive path: @euno/mcp -> @euno/some-shared -> @euno/common-infra
  const root = makeFixture([
    {
      name: '@euno/mcp',
      license: 'Apache-2.0',
      deps: { '@euno/some-shared': 'workspace:*' },
    },
    {
      name: '@euno/some-shared',
      license: 'Apache-2.0',
      deps: { '@euno/common-infra': 'workspace:*' },
    },
    { name: '@euno/common-infra', license: 'BUSL-1.1' },
  ]);
  try {
    const { exitCode, stderr } = run(root);
    assert.equal(exitCode, 1, 'transitive edge through Apache-2.0 shim should be caught');
    assert.match(stderr, /LICENSE BOUNDARY VIOLATION/);
    assert.match(stderr, /@euno\/mcp/);
    assert.match(stderr, /@euno\/common-infra/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('@euno/mcp with only @euno/common-core dependency passes', () => {
  // Confirms the healthy production dependency direction clears the lint.
  const root = makeFixture([
    {
      name: '@euno/mcp',
      license: 'Apache-2.0',
      deps: { '@euno/common-core': 'workspace:*' },
    },
    { name: '@euno/common-core', license: 'Apache-2.0' },
  ]);
  try {
    const { exitCode, stdout } = run(root);
    assert.equal(exitCode, 0, '@euno/mcp -> @euno/common-core (Apache) should pass');
    assert.match(stdout, /OK\s+License boundary check passed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

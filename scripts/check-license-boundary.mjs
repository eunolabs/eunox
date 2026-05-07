#!/usr/bin/env node
/**
 * CI lint: verify that no Apache-2.0 workspace package depends -- directly
 * or transitively -- on a BUSL-1.1 workspace package.
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-license-boundary.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Checks performed:
 *   1. Every packages/<name>/package.json must have a "license" field.
 *   2. Every "license" value must be one of the recognized SPDX identifiers
 *      (Apache-2.0, BUSL-1.1).
 *   3. No Apache-2.0 package may depend -- directly or transitively, via any
 *      of dependencies / devDependencies / peerDependencies /
 *      optionalDependencies -- on a BUSL-1.1 package within the workspace.
 *      Edges to non-workspace (external npm) packages are out of scope.
 *
 * Known violations can be explicitly allowlisted (see ALLOWLIST below).
 * Each entry documents the offending edge and the plan to remove it.
 *
 * Exit codes:
 *   0 -- all checks pass (allowlisted violations are still reported as ALLOW)
 *   1 -- at least one un-allowlisted violation, missing license, or parse error
 */

import { readFileSync, existsSync, readdirSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let workspaceRoot = repoRoot;

function usageAndExit(msg) {
  if (msg) process.stderr.write('ERROR ' + msg + '\n');
  process.stderr.write(
    'Usage: node scripts/check-license-boundary.mjs [--root <path>]\n',
  );
  process.exit(1);
}

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (arg === '--root') {
    if (i + 1 >= argv.length) {
      usageAndExit('--root requires a path argument');
    }
    workspaceRoot = resolve(argv[++i]);
  } else if (arg.startsWith('--root=')) {
    const value = arg.slice('--root='.length);
    if (!value) {
      usageAndExit('--root= requires a non-empty path argument');
    }
    workspaceRoot = resolve(value);
  } else {
    usageAndExit('unknown argument: ' + arg);
  }
}

// ---------------------------------------------------------------------------
// License classification
// ---------------------------------------------------------------------------

/** License identifiers that must not be pulled in by open packages. */
const RESTRICTED_LICENSES = new Set(['BUSL-1.1']);

/**
 * License identifiers that are "open" -- packages with these licenses must
 * not transitively reach a RESTRICTED package.
 */
const OPEN_LICENSES = new Set(['Apache-2.0']);

/** Union of all recognized license strings. */
const ALL_RECOGNIZED = new Set([...OPEN_LICENSES, ...RESTRICTED_LICENSES]);

// ---------------------------------------------------------------------------
// Allowlist of known violations
//
// Format of each key: "<from-package>-><to-package>"  (both workspace names)
//
// Add an entry here only when the violation is intentional, tracked, and
// scheduled for removal. The CI check will print ALLOW rather than ERROR.
// Remove the entry as soon as the dependency is fixed.
// ---------------------------------------------------------------------------
const ALLOWLIST = new Map([
  // @euno/cli (Apache-2.0) currently imports @euno/common (BUSL-1.1), the
  // substage-0.3 compat shim that re-exports common-core + common-infra.
  // Tracked in docs/repo-split.md -- cli must be migrated to depend on
  // @euno/common-core directly before @euno/cli is published to npm.
  ['@euno/cli->@euno/common', 'cli uses the 0.3 compat shim; migrate to common-core before publishing'],
  ['@euno/cli->@euno/common-infra', 'transitive via @euno/common (0.3 compat shim)'],
]);

// ---------------------------------------------------------------------------
// Load workspace package metadata
// ---------------------------------------------------------------------------

const packagesDir = join(workspaceRoot, 'packages');

if (!existsSync(packagesDir)) {
  process.stderr.write('ERROR packages directory not found: ' + packagesDir + '\n');
  process.exit(1);
}

const packageMap = new Map(); // name -> { name, license, deps, pkgPath }

let exitCode = 0;

function reportError(msg) {
  process.stderr.write('ERROR ' + msg + '\n');
  exitCode = 1;
}

const packageDirs = readdirSync(packagesDir, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort(); // deterministic ordering across platforms/filesystems

for (const dir of packageDirs) {
  const pkgPath = join(packagesDir, dir, 'package.json');
  if (!existsSync(pkgPath)) continue;

  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    reportError('Cannot parse ' + pkgPath + ': ' + e.message);
    continue;
  }

  const name = pkg.name;
  if (!name || typeof name !== 'string') {
    reportError(pkgPath + ': missing or invalid "name" field');
    continue;
  }

  const license = pkg.license;
  if (!license || typeof license !== 'string') {
    reportError(name + ': missing "license" field in ' + pkgPath);
    continue;
  }
  if (!ALL_RECOGNIZED.has(license)) {
    reportError(
      name + ': unrecognized license "' + license + '" -- recognized values: ' +
        [...ALL_RECOGNIZED].sort().join(', '),
    );
    continue;
  }

  // Collect all dependency names across all four dep fields.
  const deps = new Set();
  for (const depField of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const depObj = pkg[depField];
    if (depObj && typeof depObj === 'object') {
      for (const dep of Object.keys(depObj)) {
        deps.add(dep);
      }
    }
  }

  packageMap.set(name, { name, license, deps, pkgPath });
}

// Bail out early if structural errors were found -- the graph may be incomplete.
if (exitCode !== 0) {
  process.stderr.write('\nAborting: fix the errors above before the graph check can run.\n');
  process.exit(exitCode);
}

// ---------------------------------------------------------------------------
// Build workspace-scoped adjacency list and compute transitive closure
// ---------------------------------------------------------------------------

/**
 * Returns all workspace packages directly depended on by pkgName.
 * External npm packages are excluded.
 */
function directWorkspaceDeps(pkgName) {
  const pkg = packageMap.get(pkgName);
  if (!pkg) return [];
  return [...pkg.deps].filter((d) => packageMap.has(d));
}

/**
 * Computes the set of all workspace packages transitively reachable from
 * startName (excluding startName itself). Returns a Map from reachable
 * package name to the shortest path from startName to that package.
 */
function transitiveReachable(startName) {
  const reached = new Map(); // name -> path[]
  const queue = [[startName, [startName]]];
  let head = 0; // use a head index to avoid O(n) shift() on each dequeue

  while (head < queue.length) {
    const [current, path] = queue[head++];
    for (const dep of directWorkspaceDeps(current)) {
      if (dep === startName) continue; // ignore self-loops
      if (!reached.has(dep)) {
        const depPath = path.concat([dep]);
        reached.set(dep, depPath);
        queue.push([dep, depPath]);
      }
    }
  }

  return reached;
}

// ---------------------------------------------------------------------------
// Violation detection
// ---------------------------------------------------------------------------

const violations = [];
const allowedEdges = [];

for (const [pkgName, pkg] of packageMap.entries()) {
  if (!OPEN_LICENSES.has(pkg.license)) continue; // only check open-licensed packages

  const reachable = transitiveReachable(pkgName);

  for (const [depName, path] of reachable.entries()) {
    const dep = packageMap.get(depName);
    if (!dep) continue;
    if (!RESTRICTED_LICENSES.has(dep.license)) continue;

    const edgeKey = pkgName + '->' + depName;

    if (ALLOWLIST.has(edgeKey)) {
      allowedEdges.push({ from: pkgName, to: depName, path, reason: ALLOWLIST.get(edgeKey) });
    } else {
      violations.push({ from: pkgName, to: depName, path });
    }
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const sortByEdge = (a, b) => (a.from + '->' + a.to).localeCompare(b.from + '->' + b.to);
allowedEdges.sort(sortByEdge);
violations.sort(sortByEdge);

for (const entry of allowedEdges) {
  const pathStr = entry.path.join(' -> ');
  process.stdout.write('ALLOW ' + entry.from + ' -> ' + entry.to + '  [' + pathStr + ']  (' + entry.reason + ')\n');
}

if (violations.length > 0) {
  for (const v of violations) {
    const fromPkg = packageMap.get(v.from);
    const toPkg = packageMap.get(v.to);
    const pathStr = v.path.join(' -> ');
    reportError(
      'LICENSE BOUNDARY VIOLATION: ' + v.from + ' (' + fromPkg.license + ') has a (direct or transitive) dependency on ' +
        v.to + ' (' + toPkg.license + ').\n' +
        '  Path: ' + pathStr + '\n' +
        '  Apache-2.0 packages must never depend on BUSL-1.1 packages.\n' +
        '  Fix: remove the dependency, or add an entry to the ALLOWLIST in\n' +
        '  scripts/check-license-boundary.mjs with an explanation and a ticket.',
    );
  }
  process.exit(exitCode);
}

const openCount = [...packageMap.values()].filter((p) => OPEN_LICENSES.has(p.license)).length;
const restrictedCount = packageMap.size - openCount;
process.stdout.write(
  'OK    License boundary check passed.\n' +
    '      Checked ' + openCount + ' Apache-2.0 package(s) against ' + restrictedCount + ' BUSL-1.1 package(s).\n' +
    (allowedEdges.length > 0
      ? '      ' + allowedEdges.length + ' known violation(s) allowlisted -- see ALLOWLIST in scripts/check-license-boundary.mjs.\n'
      : ''),
);
process.exit(0);

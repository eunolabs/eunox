/**
 * Jest global setup — ensure @euno/common-core is built before the test suite
 * runs subprocess tests.
 *
 * Integration tests in `test/transport-stdio.test.ts`,
 * `src/__tests__/cli-validate.test.ts`, and `src/__tests__/cli-kill.test.ts`
 * spawn the euno-mcp CLI via `ts-node/register` in child processes.  Those
 * subprocesses resolve `@euno/common-core` through Node.js's standard CJS
 * module resolution, which follows the package's `"main"` field
 * (`dist/index.js`).  When the workspace is freshly cloned and the common
 * package has not yet been built, the dist artefacts are absent and every
 * spawned subprocess fails with `MODULE_NOT_FOUND`.
 *
 * Jest's `moduleNameMapper` (which redirects `@euno/common-core` to the source
 * tree) only applies within the Jest worker processes — it cannot influence the
 * module resolution of spawned Node.js children.  Building the common package
 * here, once before the entire test suite, is therefore the correct and minimal
 * fix.
 *
 * The build is skipped when `dist/index.js` already exists so that repeated
 * `npm test` invocations in already-built environments pay no extra cost.
 */

'use strict';

const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

module.exports = async function globalSetup() {
  const commonCoreDir = path.resolve(__dirname, '..', 'common');
  const distEntry = path.join(commonCoreDir, 'dist', 'index.js');

  if (!fs.existsSync(distEntry)) {
    process.stderr.write(
      '[jest-globalSetup] @euno/common-core dist not found — building now…\n',
    );
    execSync('npm run build', { cwd: commonCoreDir, stdio: 'inherit' });
    process.stderr.write('[jest-globalSetup] @euno/common-core built successfully.\n');
  }
};

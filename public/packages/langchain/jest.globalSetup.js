/**
 * Jest global setup — ensure @euno/common-core is built before the test suite
 * runs subprocess tests.
 *
 * @euno/langchain depends on @euno/mcp which depends on @euno/common-core.
 * The moduleNameMapper redirects imports within Jest workers, but spawned
 * subprocesses use the built dist/ artifacts. Building common-core here ensures
 * the dist/ artifacts are available for any subprocess tests.
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

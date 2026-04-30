#!/usr/bin/env node
/*
 * F-9 — Continuous evidence-chain verification job entry point.
 *
 * This file is the documented invocation surface (see
 * `docs/SPRINT_5_PILOT_LAUNCH.md` G10 and `docs/NEXT_STEPS_BACKLOG.md` § 4):
 *
 *   node scripts/verify-evidence.js <evidence.json|dir|-> [...]
 *
 * The actual implementation lives in `@euno/common` so it is type-checked
 * and unit-tested with the rest of the platform; this shim simply
 * delegates after the common package has been built.
 */

'use strict';

let job;
try {
  // Resolve from the workspace-installed @euno/common (works in CI and
  // production images where dependencies are hoisted to the repo root).
  // eslint-disable-next-line node/no-missing-require
  job = require('@euno/common/verify-evidence-job');
} catch (err) {
  // Fall back to the in-tree build output for local development before
  // the workspace symlink has been created, or when the consumer is
  // running from a checkout without npm install. Re-throw any error
  // that is not a missing-module / unexposed-subpath error so genuine
  // runtime failures still surface.
  const fallbackable = err && (err.code === 'MODULE_NOT_FOUND' || err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED');
  if (!fallbackable) {
    throw err;
  }
  // eslint-disable-next-line node/no-missing-require
  job = require('../packages/common/dist/verify-evidence-job');
}

job
  .main(process.argv)
  .then((code) => process.exit(code))
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(2);
  });

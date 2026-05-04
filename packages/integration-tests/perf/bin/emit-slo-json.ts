#!/usr/bin/env node
/**
 * Emit `slo.json` next to `slo.ts` so the k6 scripts (which run in
 * Goja, not Node, and have no access to the TS toolchain) can `open()`
 * a single source-of-truth and apply the same thresholds.
 *
 * Run as part of `npm run perf:slo:emit`. The k6 scripts read the file
 * at the path baked in by their `import open(...)` calls — see
 * `perf/k6/README.md`.
 */

import * as fs from 'fs';
import * as path from 'path';
import { DEFAULT_LOAD_PROFILE, SLOS } from '../slo';

const out = path.resolve(__dirname, '..', 'k6', 'slo.json');
const payload = {
  generatedAt: new Date().toISOString(),
  defaultLoadProfile: DEFAULT_LOAD_PROFILE,
  scenarios: SLOS,
};
fs.writeFileSync(out, JSON.stringify(payload, null, 2) + '\n');
process.stdout.write(`wrote ${out}\n`);

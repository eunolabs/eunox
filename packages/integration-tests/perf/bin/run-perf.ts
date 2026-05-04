#!/usr/bin/env node
/**
 * Perf-suite CLI.
 *
 * Usage:
 *   npm run perf                          # run every scenario
 *   npm run perf -- --scenario gateway-proxy-get
 *   npm run perf -- --duration 10 --connections 50
 *   npm run perf -- --json reports/perf-$(date +%s).json
 *   npm run perf -- --quick               # 1-second smoke runs (CI)
 *
 * Exits non-zero if any scenario fails its SLO so the suite can be
 * wired into CI gates. JSON output (when requested) captures every
 * percentile so a regression hunter can diff two runs.
 */

import * as fs from 'fs';
import * as path from 'path';
import { buildHarness } from '../lib/harness';
import { buildScenarios } from '../scenarios';
import { ScenarioResult, formatScenarioLine, runScenario } from '../lib/runner';
import { SCENARIO_NAMES } from '../slo';

interface CliOptions {
  scenario?: string;
  durationSeconds?: number;
  connections?: number;
  jsonPath?: string;
  list: boolean;
  quick: boolean;
  help: boolean;
}

function parseArgs(argv: readonly string[]): CliOptions {
  const opts: CliOptions = { list: false, quick: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--scenario':
        opts.scenario = argv[++i];
        break;
      case '--duration':
        opts.durationSeconds = Number(argv[++i]);
        break;
      case '--connections':
        opts.connections = Number(argv[++i]);
        break;
      case '--json':
        opts.jsonPath = argv[++i];
        break;
      case '--list':
        opts.list = true;
        break;
      case '--quick':
        opts.quick = true;
        break;
      case '-h':
      case '--help':
        opts.help = true;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function printHelp(): void {
  process.stdout.write(
    [
      'Euno perf suite — load-test artefacts (I-22).',
      '',
      'Options:',
      '  --scenario <name>   run one scenario (see --list)',
      '  --duration <sec>    override per-scenario duration',
      '  --connections <n>   override per-scenario connection count',
      '  --quick             1-second smoke runs (suitable for CI smoke gates)',
      '  --json <path>       write the full results to <path>',
      '  --list              list scenario names and exit',
      '  -h, --help          show this help',
      '',
      'Exit code is 0 only when every executed scenario meets its SLO.',
      '',
    ].join('\n'),
  );
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    printHelp();
    return;
  }
  if (opts.list) {
    for (const n of SCENARIO_NAMES) process.stdout.write(`${n}\n`);
    return;
  }

  const harness = await buildHarness();
  const all = buildScenarios(harness);
  const selected = opts.scenario
    ? all.filter((s) => s.name === opts.scenario)
    : all;

  if (selected.length === 0) {
    await harness.shutdown();
    process.stderr.write(
      `no scenarios match --scenario "${opts.scenario}". Use --list to see names.\n`,
    );
    process.exit(2);
  }

  const baseUrlFor = (target: 'gateway' | 'gateway-admin' | 'issuer') => {
    if (target === 'gateway') return harness.gatewayUrl;
    if (target === 'gateway-admin') return harness.adminUrl;
    return harness.issuerUrl;
  };

  const results: ScenarioResult[] = [];
  process.stdout.write(`running ${selected.length} scenario(s)...\n\n`);

  try {
    for (const def of selected) {
      const r = await runScenario(def, {
        baseUrlFor,
        durationSeconds: opts.quick ? 1 : opts.durationSeconds,
        connections: opts.connections,
      });
      process.stdout.write(`${formatScenarioLine(r)}\n`);
      for (const f of r.failures) process.stdout.write(`        ↳ ${f}\n`);
      results.push(r);
    }
  } finally {
    await harness.shutdown();
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  process.stdout.write(`\nsummary: ${passed} passed, ${failed} failed\n`);

  if (opts.jsonPath) {
    const out = path.resolve(opts.jsonPath);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(
      out,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          node: process.version,
          platform: `${process.platform}-${process.arch}`,
          results,
        },
        null,
        2,
      ),
    );
    process.stdout.write(`wrote ${out}\n`);
  }

  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`perf runner failed: ${(err as Error).stack ?? err}\n`);
  process.exit(2);
});

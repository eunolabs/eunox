#!/usr/bin/env ts-node
/**
 * Stage 2 readiness check — @euno/mcp
 *
 * Prints the current status of the three measurable gate conditions that
 * must ALL be true before work on Stage 2 begins (see docs/mvp.md §"Gate to
 * Stage 2 — measurable").
 *
 * Usage:
 *   npx ts-node scripts/stage2-readiness.ts
 *   EUNO_TELEMETRY_API=https://... npx ts-node scripts/stage2-readiness.ts
 *
 * Criterion 1 and 3 are manual signals tracked elsewhere. This script
 * queries the telemetry store for Criterion 2 and reports "UNKNOWN" for
 * the others with a pointer to where each is tracked.
 *
 * Exit codes:
 *   0 — all three criteria met (READY)
 *   1 — one or more criteria definitively not met (NOT READY)
 *   2 — one or more criteria could not be evaluated (UNKNOWN);
 *       C1 and C3 are always UNKNOWN (manual signals); C2 is UNKNOWN
 *       when EUNO_TELEMETRY_API is unset or the API is unreachable
 */

import * as https from 'https';
import * as http from 'http';
import * as process from 'process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TelemetryStats {
  distinctInstalls7d: number;
  dailyActiveInstallsMin: number; // min across the 7-day window
  totalEnforcementEvents: number;
}

interface CriterionResult {
  met: boolean | 'UNKNOWN';
  label: string;
  detail: string;
  trackingPointer: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const TELEMETRY_API_URL =
  // Empty string means the API is not configured; queryTelemetry() returns null early.
  process.env['EUNO_TELEMETRY_API'] ?? '';

const CRITERION_2_THRESHOLD_INSTALLS = 50;
const CRITERION_2_THRESHOLD_DAYS = 7;
const TELEMETRY_API_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fetchJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const statusCode = res.statusCode ?? 0;
        if (statusCode < 200 || statusCode >= 300) {
          reject(
            new Error(
              `Telemetry API returned HTTP ${statusCode} ${res.statusMessage ?? ''}`.trimEnd(),
            ),
          );
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (e) {
          reject(new Error(`Failed to parse telemetry response: ${(e as Error).message}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(TELEMETRY_API_TIMEOUT_MS, () => {
      req.destroy(new Error(`Telemetry API request timed out after ${TELEMETRY_API_TIMEOUT_MS / 1000} s`));
    });
  });
}

async function queryTelemetry(): Promise<TelemetryStats | null> {
  if (!TELEMETRY_API_URL) {
    return null;
  }
  try {
    const data = (await fetchJson(
      `${TELEMETRY_API_URL}/v1/stats/stage2-gate`,
    )) as TelemetryStats;
    return data;
  } catch (_e) {
    return null;
  }
}

function pad(s: string, n: number): string {
  return s.padEnd(n, ' ');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  process.stdout.write('Stage 2 readiness check — @euno/mcp\n');
  process.stdout.write('='.repeat(60) + '\n\n');

  // Criterion 2 — telemetry-queryable
  const stats = await queryTelemetry();

  const criteria: CriterionResult[] = [
    // ── Criterion 1: unsolicited feature asks ──────────────────────────────
    {
      met: 'UNKNOWN',
      label: 'C1 — Feature asks',
      detail: `Need >= 10 unsolicited inbound asks for richer conditions or cross-process state.`,
      trackingPointer:
        'Track via GitHub issues labelled "stage-2-signal" — ' +
        'see .github/ISSUE_TEMPLATE/feature-ask.md.',
    },

    // ── Criterion 2: telemetry ─────────────────────────────────────────────
    {
      met: stats
        ? stats.distinctInstalls7d >= CRITERION_2_THRESHOLD_INSTALLS &&
          stats.dailyActiveInstallsMin >= 1
        : 'UNKNOWN',
      label: 'C2 — Telemetry',
      detail: stats
        ? `${stats.distinctInstalls7d} distinct installs with >=1 event/day over ${CRITERION_2_THRESHOLD_DAYS} days ` +
          `(need ${CRITERION_2_THRESHOLD_INSTALLS}). ` +
          `Min daily-active across window: ${stats.dailyActiveInstallsMin}.`
        : TELEMETRY_API_URL
          ? 'Telemetry API unreachable — cannot evaluate.'
          : 'EUNO_TELEMETRY_API not set — cannot evaluate. ' +
            'Set it to the telemetry service base URL and re-run.',
      trackingPointer: TELEMETRY_API_URL
        ? `${TELEMETRY_API_URL}/v1/stats/stage2-gate`
        : 'Set EUNO_TELEMETRY_API env var to query live data.',
    },

    // ── Criterion 3: design-partner conversation ───────────────────────────
    {
      met: 'UNKNOWN',
      label: 'C3 — Design partner',
      detail:
        `Need >= 1 conversation with a team that is already self-rolling ` +
        `a cross-process MCP enforcement equivalent.`,
      trackingPointer: 'Track manually in CRM / Notion.',
    },
  ];

  let allMet = true;
  for (const c of criteria) {
    const statusChar =
      c.met === true ? '✅' : c.met === false ? '❌' : '⚠️ ';
    if (c.met !== true) allMet = false;
    process.stdout.write(`${statusChar}  ${pad(c.label, 22)}  ${c.detail}\n`);
    process.stdout.write(`   ${pad('', 22)}  Tracking: ${c.trackingPointer}\n\n`);
  }

  process.stdout.write('='.repeat(60) + '\n');
  if (allMet) {
    process.stdout.write('READY — all three Stage 2 gate criteria are met.\n');
    process.exit(0);
  } else {
    const unknownCount = criteria.filter((c) => c.met === 'UNKNOWN').length;
    const notMetCount = criteria.filter((c) => c.met === false).length;
    if (notMetCount > 0) {
      process.stdout.write(`NOT READY — ${notMetCount} criterion/criteria not met.\n`);
      process.exit(1);
    } else {
      process.stdout.write(
        `UNKNOWN — ${unknownCount} criterion/criteria require manual verification.\n`,
      );
      process.exit(2);
    }
  }
}

main().catch((err) => {
  process.stderr.write(`Error: ${(err as Error).message}\n`);
  process.exit(1);
});

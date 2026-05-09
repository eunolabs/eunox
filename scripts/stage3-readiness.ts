#!/usr/bin/env ts-node
/**
 * Stage 3 readiness check — @euno/mcp
 *
 * Prints the current status of the three measurable gate conditions that
 * must ALL be true before work on Stage 3 begins (see docs/mvp.md §"Gate to
 * Stage 3 — measurable").
 *
 * Usage:
 *   npx ts-node scripts/stage3-readiness.ts
 *   EUNO_TELEMETRY_API=https://... npx ts-node scripts/stage3-readiness.ts
 *
 * Criterion 2 and 3 are manual signals tracked elsewhere.  This script
 * queries the telemetry store for Criterion 1 and reports "UNKNOWN" for
 * the others with a pointer to where each is tracked.
 *
 * Exit codes:
 *   0 — all three criteria met (READY)
 *   1 — one or more criteria definitively not met (NOT READY)
 *   2 — one or more criteria could not be evaluated (UNKNOWN);
 *       C2 and C3 are always UNKNOWN (manual signals); C1 is UNKNOWN
 *       when EUNO_TELEMETRY_API is unset or the API is unreachable
 *
 * Privacy note on Criterion 1 team-size estimation
 * -------------------------------------------------
 * A fully automated per-install team-size estimate is not possible without
 * tracking user identifiers, IPs, or hostnames — all of which are
 * non-negotiable exclusions from our telemetry schema.
 *
 * Instead, C1 is partially automated using the `peakConcurrentSessions`
 * field added to the telemetry event in Task 12: an install that regularly
 * shows peakConcurrentSessions ≥ 3 is a strong (privacy-preserving) signal
 * of shared team use.  The telemetry backend aggregates this server-side.
 * C1 still requires at least one direct conversation per team to confirm;
 * the telemetry check is a filter, not a substitute, for that confirmation.
 */

import * as https from 'https';
import * as http from 'http';
import * as process from 'process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Stage3TelemetryStats {
  /** Distinct install IDs that sent at least one event in the last 14 days. */
  distinctInstalls14d: number;
  /** Of those, the number where peakConcurrentSessions ≥ 3 in any single event. */
  installsWithPeakSessions3Plus: number;
  /** Number of those installs where we have confirmed a direct team conversation. */
  confirmedTeams: number;
}

export interface CriterionResult {
  met: boolean | 'UNKNOWN';
  label: string;
  detail: string;
  trackingPointer: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Minimum number of confirmed teams to satisfy C1. */
export const C1_THRESHOLD_TEAMS = 5;
/** Minimum peakConcurrentSessions signal installs needed as a qualifying filter for C1. */
export const C1_THRESHOLD_INSTALLS_SIGNAL = 5;
/** Minimum distinct installs with activity in the 14-day window. */
export const C1_THRESHOLD_DISTINCT_INSTALLS = 5;
/** Minimum unsolicited asks to satisfy C2. */
export const C2_THRESHOLD_ASKS = 3;

const TELEMETRY_API_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function fetchJson(url: string, timeoutMs = TELEMETRY_API_TIMEOUT_MS): Promise<unknown> {
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
    req.setTimeout(timeoutMs, () => {
      req.destroy(
        new Error(`Telemetry API request timed out after ${timeoutMs / 1000} s`),
      );
    });
  });
}

export async function queryTelemetry(apiUrl: string): Promise<Stage3TelemetryStats | null> {
  if (!apiUrl) {
    return null;
  }
  try {
    const data = (await fetchJson(
      `${apiUrl}/v1/stats/stage3-gate`,
    )) as Stage3TelemetryStats;
    return data;
  } catch (_e) {
    return null;
  }
}

export function evaluateCriterion1(
  stats: Stage3TelemetryStats | null,
  apiUrl: string,
): CriterionResult {
  const c1Met: boolean | 'UNKNOWN' = stats
    ? (() => {
        // Definitively not met if the telemetry signal is clearly insufficient.
        if (
          stats.distinctInstalls14d < C1_THRESHOLD_DISTINCT_INSTALLS &&
          stats.installsWithPeakSessions3Plus < C1_THRESHOLD_INSTALLS_SIGNAL
        ) {
          return false;
        }
        // Met if we have enough confirmed teams.
        if (stats.confirmedTeams >= C1_THRESHOLD_TEAMS) {
          return true;
        }
        // Signal is there but not yet fully confirmed — still UNKNOWN.
        return 'UNKNOWN';
      })()
    : 'UNKNOWN';

  return {
    met: c1Met,
    label: 'C1 — Team adoption',
    detail: stats
      ? `${stats.distinctInstalls14d} distinct installs active in last 14 days; ` +
        `${stats.installsWithPeakSessions3Plus} with peakConcurrentSessions≥3 (team-size signal); ` +
        `${stats.confirmedTeams}/${C1_THRESHOLD_TEAMS} confirmed teams.`
      : apiUrl
        ? 'Telemetry API unreachable — cannot evaluate automatically. ' +
          'C1 requires manual tracking of confirmed teams.'
        : 'EUNO_TELEMETRY_API not set — cannot evaluate automatically. ' +
          'C1 requires manual tracking of confirmed teams. ' +
          'Set EUNO_TELEMETRY_API to query the peakConcurrentSessions signal.',
    trackingPointer: apiUrl
      ? `${apiUrl}/v1/stats/stage3-gate — plus manual CRM/Notion for confirmed teams.`
      : 'Set EUNO_TELEMETRY_API env var to query the telemetry signal. ' +
        'Manual tracking in CRM/Notion for confirmed team conversations.',
  };
}

export function evaluateCriterion2(): CriterionResult {
  return {
    met: 'UNKNOWN',
    label: 'C2 — Feature asks',
    detail:
      `Need >= ${C2_THRESHOLD_ASKS} unsolicited asks for "how do I share this policy across ` +
      `the team" or "how do I see what the agent did from my laptop".`,
    trackingPointer:
      'Track via GitHub issues labelled "stage-3-signal" — ' +
      'see .github/ISSUE_TEMPLATE/stage-3-signal.md.',
  };
}

export function evaluateCriterion3(): CriterionResult {
  return {
    met: 'UNKNOWN',
    label: 'C3 — Hand-rolled audit',
    detail:
      `Need >= 1 conversation with a team that has already implemented some hand-rolled ` +
      `cross-process MCP enforcement or audit equivalent.`,
    trackingPointer: 'Track manually in CRM / Notion.',
  };
}

export function buildCriteria(
  stats: Stage3TelemetryStats | null,
  apiUrl: string,
): CriterionResult[] {
  return [
    evaluateCriterion1(stats, apiUrl),
    evaluateCriterion2(),
    evaluateCriterion3(),
  ];
}

export function computeOverallResult(criteria: CriterionResult[]): {
  status: 'ready' | 'not-ready' | 'unknown';
  exitCode: 0 | 1 | 2;
} {
  const allMet = criteria.every((c) => c.met === true);
  if (allMet) return { status: 'ready', exitCode: 0 };

  const notMetCount = criteria.filter((c) => c.met === false).length;
  if (notMetCount > 0) return { status: 'not-ready', exitCode: 1 };

  return { status: 'unknown', exitCode: 2 };
}

function pad(s: string, n: number): string {
  return s.padEnd(n, ' ');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function main(apiUrl = process.env['EUNO_TELEMETRY_API'] ?? ''): Promise<void> {
  process.stdout.write('Stage 3 readiness check — @euno/mcp\n');
  process.stdout.write('='.repeat(60) + '\n\n');

  const stats = await queryTelemetry(apiUrl);
  const criteria = buildCriteria(stats, apiUrl);

  for (const c of criteria) {
    const statusChar =
      c.met === true ? '✅' : c.met === false ? '❌' : '⚠️ ';
    process.stdout.write(`${statusChar}  ${pad(c.label, 22)}  ${c.detail}\n`);
    process.stdout.write(`   ${pad('', 22)}  Tracking: ${c.trackingPointer}\n\n`);
  }

  process.stdout.write('='.repeat(60) + '\n');

  const { status, exitCode } = computeOverallResult(criteria);
  const unknownCount = criteria.filter((c) => c.met === 'UNKNOWN').length;
  const notMetCount = criteria.filter((c) => c.met === false).length;

  if (status === 'ready') {
    process.stdout.write('READY — all three Stage 3 gate criteria are met.\n');
  } else if (status === 'not-ready') {
    process.stdout.write(`NOT READY — ${notMetCount} criterion/criteria not met.\n`);
  } else {
    process.stdout.write(
      `UNKNOWN — ${unknownCount} criterion/criteria require manual verification.\n`,
    );
  }

  process.exit(exitCode);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exit(1);
  });
}


#!/usr/bin/env ts-node
/**
 * Stage 4 readiness check — euno-platform
 *
 * Prints the current status of the two measurable gate conditions that must
 * BOTH be true before work on Stage 4 begins (see docs/mvp.md §"Gate to
 * Stage 4 — measurable").
 *
 * Usage:
 *   npx ts-node scripts/stage4-readiness.ts
 *   EUNO_TELEMETRY_API=https://... npx ts-node scripts/stage4-readiness.ts
 *
 * Gate conditions
 * ---------------
 * C1 — ≥1 paying team (any plan).
 *   Partially automated: the telemetry backend receives hosted-mode events
 *   (`subcommand: 'hosted-enforce'`) from the `GatewayTelemetryCollector`
 *   added in Task 16.  An install whose events carry a non-empty tenantId AND
 *   where `sessionsStarted ≥ 1` in the 14-day window is a candidate paying
 *   team.  Manual confirmation is always required (telemetry does not carry
 *   billing state).
 *
 * C2 — A security or compliance question raised in writing.
 *   Manual signal.  Track in GitHub issues labelled "stage-4-signal" or in
 *   CRM / Notion.  Examples: audit retention policy, SSO, SOC2, GDPR.
 *
 * Exit codes:
 *   0 — both criteria met (READY)
 *   1 — one or more criteria definitively not met (NOT READY)
 *   2 — one or more criteria could not be evaluated (UNKNOWN);
 *       both C1 and C2 are UNKNOWN until manually confirmed
 *
 * Privacy note on Criterion 1 (paying team signal)
 * -------------------------------------------------
 * The hosted-mode telemetry emitted by GatewayTelemetryCollector carries
 * `installId = 'tenant:' + tenantId` and `sessionsStarted` (unique session
 * count per reporting window) — no user IDs, IP addresses, tool names, or
 * argument values. The `confirmedPayingTeams` stat in the telemetry API is a
 * manual override that must be set by a human after verifying billing state.
 */

import * as https from 'https';
import * as http from 'http';
import * as process from 'process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Stage4TelemetryStats {
  /**
   * Distinct tenant IDs that sent at least one hosted-mode enforce event
   * (subcommand: 'hosted-enforce') in the last 14 days.
   */
  distinctHostedTenants14d: number;
  /**
   * Of those, the number where we have confirmed billing / contract.
   * This is a manual field — the telemetry backend stores it as an
   * operator-set override, not derived from event data.
   */
  confirmedPayingTeams: number;
  /**
   * Number of written security or compliance questions received.
   * Topics: audit retention, SSO, SOC2, GDPR, HIPAA, CISO review, etc.
   * Manual field set by the operator.
   */
  confirmedSecurityQuestions: number;
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

/** Minimum number of confirmed paying teams to satisfy C1. */
export const C1_THRESHOLD_PAYING_TEAMS = 1;
/**
 * Minimum distinct hosted tenants to act as a preliminary telemetry signal
 * for C1 (not sufficient alone — requires confirmedPayingTeams).
 */
export const C1_THRESHOLD_HOSTED_TENANTS = 1;
/** Minimum written security/compliance questions to satisfy C2. */
export const C2_THRESHOLD_SECURITY_QUESTIONS = 1;

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

export async function queryTelemetry(apiUrl: string): Promise<Stage4TelemetryStats | null> {
  if (!apiUrl) {
    return null;
  }
  try {
    const data = (await fetchJson(
      `${apiUrl}/v1/stats/stage4-gate`,
    )) as Stage4TelemetryStats;
    return data;
  } catch (_e) {
    return null;
  }
}

export function evaluateCriterion1(
  stats: Stage4TelemetryStats | null,
  apiUrl: string,
): CriterionResult {
  const c1Met: boolean | 'UNKNOWN' = stats
    ? (() => {
        // Definitively not met when there is no telemetry signal at all.
        if (
          stats.distinctHostedTenants14d < C1_THRESHOLD_HOSTED_TENANTS &&
          stats.confirmedPayingTeams < C1_THRESHOLD_PAYING_TEAMS
        ) {
          return false;
        }
        // Met when a paying team is explicitly confirmed.
        if (stats.confirmedPayingTeams >= C1_THRESHOLD_PAYING_TEAMS) {
          return true;
        }
        // Hosted-mode events present but billing not confirmed — UNKNOWN.
        return 'UNKNOWN';
      })()
    : 'UNKNOWN';

  return {
    met: c1Met,
    label: 'C1 — Paying team',
    detail: stats
      ? `${stats.distinctHostedTenants14d} distinct hosted tenant(s) active in last 14 days; ` +
        `${stats.confirmedPayingTeams}/${C1_THRESHOLD_PAYING_TEAMS} confirmed paying team(s).`
      : apiUrl
        ? 'Telemetry API unreachable — cannot evaluate automatically. ' +
          'C1 requires manual confirmation of at least one paying team.'
        : 'EUNO_TELEMETRY_API not set — cannot evaluate automatically. ' +
          'C1 requires manual confirmation of at least one paying team. ' +
          'Set EUNO_TELEMETRY_API to query the hosted-tenant signal.',
    trackingPointer: apiUrl
      ? `${apiUrl}/v1/stats/stage4-gate — plus manual CRM/Notion for confirmed billing.`
      : 'Set EUNO_TELEMETRY_API env var to query the hosted-tenant signal. ' +
        'Manual confirmation of billing state in CRM/Notion.',
  };
}

export function evaluateCriterion2(
  stats: Stage4TelemetryStats | null,
  apiUrl: string,
): CriterionResult {
  const c2Met: boolean | 'UNKNOWN' = stats
    ? stats.confirmedSecurityQuestions >= C2_THRESHOLD_SECURITY_QUESTIONS
      ? true
      : stats.confirmedSecurityQuestions === 0
        ? 'UNKNOWN'
        : false
    : 'UNKNOWN';

  return {
    met: c2Met,
    label: 'C2 — Security/compliance question',
    detail: stats
      ? `${stats.confirmedSecurityQuestions}/${C2_THRESHOLD_SECURITY_QUESTIONS} written ` +
        `security or compliance question(s) received. ` +
        `Topics: audit retention, SSO, SOC2, GDPR, HIPAA, CISO review.`
      : apiUrl
        ? 'Telemetry API unreachable — cannot evaluate automatically. ' +
          'C2 requires at least one written security or compliance question.'
        : 'EUNO_TELEMETRY_API not set — cannot evaluate automatically. ' +
          'C2 requires manual tracking of written security/compliance questions.',
    trackingPointer:
      'Track via GitHub issues labelled "stage-4-signal" — ' +
      'or in CRM/Notion. ' +
      'Examples: "What is your audit-log retention policy?", "Do you support SSO?", ' +
      '"Does this pass a SOC2 Type II audit?".',
  };
}

export function buildCriteria(
  stats: Stage4TelemetryStats | null,
  apiUrl: string,
): CriterionResult[] {
  return [
    evaluateCriterion1(stats, apiUrl),
    evaluateCriterion2(stats, apiUrl),
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

export async function main(apiUrl = process.env['EUNO_TELEMETRY_API'] ?? ''): Promise<0 | 1 | 2> {
  process.stdout.write('Stage 4 readiness check — euno-platform\n');
  process.stdout.write('='.repeat(60) + '\n\n');

  const stats = await queryTelemetry(apiUrl);
  const criteria = buildCriteria(stats, apiUrl);

  for (const c of criteria) {
    let statusChar: string;
    if (c.met === true) {
      statusChar = '✅';
    } else if (c.met === false) {
      statusChar = '❌';
    } else {
      statusChar = '⚠️ ';
    }
    process.stdout.write(`${statusChar}  ${pad(c.label, 35)}  ${c.detail}\n`);
    process.stdout.write(`   ${pad('', 35)}  Tracking: ${c.trackingPointer}\n\n`);
  }

  process.stdout.write('='.repeat(60) + '\n');

  const { status, exitCode } = computeOverallResult(criteria);
  const unknownCount = criteria.filter((c) => c.met === 'UNKNOWN').length;
  const notMetCount = criteria.filter((c) => c.met === false).length;

  if (status === 'ready') {
    process.stdout.write('READY — both Stage 4 gate criteria are met.\n');
    process.stdout.write(
      'Stage 3 is shipped. Stage 4 (Capability Issuer + Identity) may begin.\n',
    );
  } else if (status === 'not-ready') {
    process.stdout.write(`NOT READY — ${notMetCount} criterion/criteria not met.\n`);
  } else {
    process.stdout.write(
      `UNKNOWN — ${unknownCount} criterion/criteria require manual verification.\n`,
    );
  }

  return exitCode;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`Error: ${(err as Error).message}\n`);
      process.exit(1);
    });
}

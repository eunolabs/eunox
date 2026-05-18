#!/usr/bin/env ts-node
/**
 * Stage 5 readiness check — euno-platform
 *
 * Prints the current status of the single measurable gate condition that must
 * be true before work on Stage 5 begins (see docs/mvp.md §"Gate to
 * Stage 5 — measurable").
 *
 * Usage:
 *   npx ts-node scripts/stage5-readiness.ts
 *   EUNO_TELEMETRY_API=https://... npx ts-node scripts/stage5-readiness.ts
 *
 * Gate condition
 * --------------
 * C1 — Enterprise inbound: ≥1 enterprise inquiry from a company with a
 *   security team, mentioning compliance, on-prem, or "our CISO needs to
 *   review this."  The telemetry backend exposes this as
 *   `confirmedEnterpriseInbound` on the `/v1/stats/stage5-gate` endpoint;
 *   it is a manual override set by an operator after verifying the inquiry,
 *   not derived automatically from event data.
 *
 * Exit codes:
 *   0 — criterion met (READY)
 *   1 — criterion definitively not met (NOT READY)
 *   2 — criterion could not be evaluated (UNKNOWN);
 *       C1 is UNKNOWN when EUNO_TELEMETRY_API is unset, the API is
 *       unreachable, or the confirmedEnterpriseInbound count is 0 (which
 *       is indistinguishable from "not yet tracked")
 *
 * Privacy note
 * ------------
 * The telemetry backend stores only an operator-set integer counter
 * (`confirmedEnterpriseInbound`).  No company names, contact details, or
 * deal-stage information are sent through the telemetry channel.  Sales and
 * CRM tracking happen out-of-band.
 */

import * as https from 'https';
import * as http from 'http';
import * as process from 'process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Stage5TelemetryStats {
  /**
   * Number of confirmed enterprise inquiries that mentioned compliance,
   * on-prem deployment, or a security-team review requirement ("CISO review").
   * This is a manual field — set by the operator after qualifying the inquiry;
   * not derived automatically from telemetry event data.
   */
  confirmedEnterpriseInbound: number;
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

/** Minimum number of confirmed enterprise inquiries to satisfy C1. */
export const C1_THRESHOLD_ENTERPRISE_INBOUND = 1;

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

export async function queryTelemetry(apiUrl: string): Promise<Stage5TelemetryStats | null> {
  if (!apiUrl) {
    return null;
  }
  try {
    const data = (await fetchJson(
      `${apiUrl}/v1/stats/stage5-gate`,
    )) as Stage5TelemetryStats;
    return data;
  } catch (_e) {
    return null;
  }
}

export function evaluateCriterion1(
  stats: Stage5TelemetryStats | null,
  apiUrl: string,
): CriterionResult {
  const c1Met: boolean | 'UNKNOWN' = stats
    ? (() => {
        if (stats.confirmedEnterpriseInbound >= C1_THRESHOLD_ENTERPRISE_INBOUND) {
          return true;
        }
        // A count of 0 is indistinguishable from "not yet tracked" — UNKNOWN.
        if (stats.confirmedEnterpriseInbound === 0) {
          return 'UNKNOWN';
        }
        return false;
      })()
    : 'UNKNOWN';

  return {
    met: c1Met,
    label: 'C1 — Enterprise inbound',
    detail: stats
      ? `${stats.confirmedEnterpriseInbound}/${C1_THRESHOLD_ENTERPRISE_INBOUND} confirmed enterprise ` +
        `${stats.confirmedEnterpriseInbound === 1 ? 'inquiry' : 'inquiries'} ` +
        `(company with a security team mentioning compliance, on-prem, or CISO review).`
      : apiUrl
        ? 'Telemetry API unreachable — cannot evaluate automatically. ' +
          'C1 requires manual confirmation of at least one qualifying enterprise inquiry.'
        : 'EUNO_TELEMETRY_API not set — cannot evaluate automatically. ' +
          'C1 requires manual confirmation of at least one qualifying enterprise inquiry. ' +
          'Set EUNO_TELEMETRY_API to query the enterprise-inbound signal.',
    trackingPointer: apiUrl
      ? `${apiUrl}/v1/stats/stage5-gate — plus manual CRM/Notion for confirmed enterprise inquiries.`
      : 'Set EUNO_TELEMETRY_API env var to query the enterprise-inbound signal. ' +
        'Manual confirmation in CRM/Notion: company has a security team; inquiry mentioned ' +
        'compliance, on-prem deployment, or "our CISO needs to review this."',
  };
}

export function buildCriteria(
  stats: Stage5TelemetryStats | null,
  apiUrl: string,
): CriterionResult[] {
  return [evaluateCriterion1(stats, apiUrl)];
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
  process.stdout.write('Stage 5 readiness check — euno-platform\n');
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
    process.stdout.write('READY — Stage 5 gate criterion is met.\n');
    process.stdout.write(
      'Stage 4 is shipped. Stage 5 (Enterprise + Full Vision) may begin.\n',
    );
  } else if (status === 'not-ready') {
    process.stdout.write(`NOT READY — ${notMetCount} ${notMetCount === 1 ? 'criterion' : 'criteria'} not met.\n`);
  } else {
    process.stdout.write(
      `UNKNOWN — ${unknownCount} ${unknownCount === 1 ? 'criterion' : 'criteria'} require${unknownCount === 1 ? 's' : ''} manual verification.\n`,
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

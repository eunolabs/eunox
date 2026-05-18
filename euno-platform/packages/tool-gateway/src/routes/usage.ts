/**
 * `GET /admin/usage` and `POST /admin/usage/reset` — billing metering API
 * ---------------------------------------------------------------------------
 * Stage 3, Task 17 — Pricing & billing plumbing.
 *
 * These handlers are attached to the admin router (internal port only) so
 * they inherit admin-key authentication and are never reachable from the
 * public load balancer.
 *
 * ## GET /admin/usage
 *
 * Returns per-tenant usage counters for the current billing period, alongside
 * the gateway's configured audit-retention window (a key billing dimension for
 * the Cloud Team tier).
 *
 * Optional query parameters:
 *   - `tenantId` — Restrict response to a single tenant.
 *
 * Response shape:
 * ```json
 * {
 *   "snapshotAt": "<ISO-8601>",
 *   "auditRetentionDays": 7,
 *   "tenants": [
 *     {
 *       "tenantId": "acme-corp",
 *       "enforcementEvents": 42,
 *       "allowDecisions": 40,
 *       "denyDecisions": 2,
 *       "killSwitchInvocations": 1,
 *       "issuanceEvents": 5,
 *       "renewalEvents": 2,
 *       "periodStart": "<ISO-8601>"
 *     }
 *   ]
 * }
 * ```
 *
 * Per-user breakdowns (`issuancesByUser`, `renewalsByUser`) are intentionally
 * omitted from this response — they contain user identifiers (often email
 * addresses) and can be arbitrarily large. Consult the audit log endpoints
 * for per-user forensics.
 *
 * When `tenantId` is supplied the `"tenants"` array always contains exactly
 * one entry — a zero-count snapshot is returned for tenants that have had no
 * activity this period (the caller does not need to distinguish "new tenant"
 * from "zero activity tenant").
 *
 * ## POST /admin/usage/reset
 *
 * Resets billing-period counters. Intended to be called at month-end before
 * handing the usage snapshot to a billing operator for invoicing.
 *
 * Optional body field:
 *   - `tenantId` (string) — Reset only that tenant's counters. Omit to reset
 *     all tenants.
 *
 * ## Billing integration
 *
 * For the first hand-invoiced design partner, the workflow is:
 *   1. `GET /admin/usage` at month-end — record the numbers.
 *   2. Invoice the customer.
 *   3. `POST /admin/usage/reset` — start the next period.
 *
 * A future billing integration (Stripe, Lago, …) can drive the same seam
 * programmatically without touching the enforcement or admin-key logic.
 *
 * See `docs/pricing-stage-3.md` for the tier definitions that map these
 * numbers to a bill.
 */

import { Router, Request, Response } from 'express';
import { TenantUsageSnapshot, UsageMeter } from '@euno/common';

export interface UsageRouterOptions {
  usageMeter: UsageMeter;
  /**
   * Configured audit-log retention in days. Surfaced in the response so
   * billing operators can confirm which tier the tenant is on without
   * consulting environment-variable documentation.
   *
   * Pass `undefined` when the gateway has no explicit retention policy
   * configured (e.g. self-host with operator-managed storage).
   */
  auditRetentionDays?: number;
}

/**
 * Strips per-user breakdown fields from a {@link TenantUsageSnapshot} before
 * sending it over the wire.
 *
 * `issuancesByUser` and `renewalsByUser` contain user identifiers (often
 * email addresses). They are kept in-process for support and forensics but
 * **must not** appear in the default billing-API response:
 *   - They constitute PII under most privacy regulations.
 *   - For high-cardinality tenants the maps can be arbitrarily large.
 *
 * Callers that need per-user breakdown for a specific support case should
 * query the audit log directly via the audit endpoints.
 */
function toPublicSnapshot(
  snap: TenantUsageSnapshot,
): Omit<TenantUsageSnapshot, 'issuancesByUser' | 'renewalsByUser'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { issuancesByUser: _iu, renewalsByUser: _ru, ...rest } = snap;
  return rest;
}

/**
 * Mount the billing usage endpoints onto the provided router.
 *
 * The router is the already-authenticated admin router, so no additional
 * authentication is applied here. Every handler assumes the caller has
 * already passed the admin-key check in `authenticateAdmin`.
 */
export function mountUsageRoutes(router: Router, opts: UsageRouterOptions): void {
  const { usageMeter, auditRetentionDays } = opts;

  /**
   * GET /usage
   *
   * Return the current billing-period usage snapshot.
   *
   * Query parameters:
   *   ?tenantId=<string>  — restrict to a single tenant
   */
  router.get('/usage', (req: Request, res: Response): void => {
    const rawTenantId = req.query['tenantId'];
    const trimmedTenantId =
      typeof rawTenantId === 'string' ? rawTenantId.trim() : '';
    const filterTenantId = trimmedTenantId.length > 0 ? trimmedTenantId : undefined;

    let tenants;
    if (filterTenantId !== undefined) {
      // getUsage never throws — returns a zero snapshot for unknown tenants.
      const snap = usageMeter.getUsage(filterTenantId);
      // Only include tenants that exist in the store; a zero snapshot for an
      // unknown tenant is still a valid response for targeted queries — the
      // operator may be checking a tenant that has had no activity this period.
      tenants = [toPublicSnapshot(snap)];
    } else {
      tenants = usageMeter.getAllUsage().slice().sort(
        (a, b) => a.tenantId.localeCompare(b.tenantId),
      ).map(toPublicSnapshot);
    }

    res.json({
      snapshotAt: new Date().toISOString(),
      ...(auditRetentionDays !== undefined ? { auditRetentionDays } : {}),
      tenants,
    });
  });

  /**
   * POST /usage/reset
   *
   * Reset billing-period counters.
   *
   * Body (JSON, optional):
   *   { "tenantId": "<string>" }  — reset only this tenant
   *   {}                           — reset all tenants
   */
  router.post('/usage/reset', (req: Request, res: Response): void => {
    const tenantId =
      typeof req.body?.tenantId === 'string' && req.body.tenantId.length > 0
        ? (req.body.tenantId as string)
        : undefined;

    usageMeter.resetPeriod(tenantId);

    res.json({
      message:
        tenantId !== undefined
          ? `Billing period reset for tenant "${tenantId}"`
          : 'Billing period reset for all tenants',
      resetAt: new Date().toISOString(),
      ...(tenantId !== undefined ? { tenantId } : {}),
    });
  });
}

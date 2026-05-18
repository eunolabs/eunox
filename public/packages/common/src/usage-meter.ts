/**
 * Billing metering surface — Stage 3, Task 17; extended in Stage 4, Task 10
 * ---------------------------------------------------------------------------
 * Provides per-tenant usage counters that feed the billing/pricing surface
 * described in `docs/pricing-stage-3.md`. The in-process implementation is
 * intentionally simple: it accumulates counts since the last `resetPeriod()`
 * call, which is all a hand-invoiced first design-partner needs.
 *
 * The interface is a seam: a future task can replace `InMemoryUsageMeter` with
 * a Postgres- or Redis-backed implementation without touching the callers
 * (enforcement engine, admin API). Per the cross-cutting obligation in
 * `docs/stage3executionplan.md`, types live in `@euno/common` and are consumed
 * by both `tool-gateway` and, eventually, `@euno/mcp`.
 *
 * ## What is metered
 *
 * | Dimension                   | Unit            | Notes                                  |
 * |-----------------------------|-----------------|----------------------------------------|
 * | Enforcement events          | integer count   | Each `validateAction` call (allow+deny)|
 * | Allow decisions             | integer count   | Subset of enforcement events           |
 * | Deny decisions              | integer count   | Subset of enforcement events           |
 * | Kill-switch invocations     | integer count   | Global activate + per-session/agent    |
 * | Issuance events             | integer count   | Successful `POST /api/v1/issue` calls  |
 * | Renewal events              | integer count   | Successful `POST /api/v1/renew` calls  |
 * | Audit retention days        | configuration   | Surfaced alongside live counters       |
 *
 * ## Billing period
 *
 * The meter tracks a `periodStart` timestamp and accumulates counts until
 * `resetPeriod()` is called. For a hand-invoiced customer the operator
 * queries `GET /admin/usage` at month-end, exports the numbers, then calls
 * `POST /admin/usage/reset` to start the next period. Automated billing
 * integration can drive the same seam.
 *
 * ## Per-user metering
 *
 * `recordIssuance` and `recordRenewal` accept a `userId` parameter so that
 * implementations can maintain a per-user breakdown for support and forensics.
 * Billing always aggregates at the tenant level (`issuanceEvents`,
 * `renewalEvents` in {@link TenantUsageSnapshot}). The optional
 * `issuancesByUser` and `renewalsByUser` fields carry per-user counts for
 * operational queries; they are not used for invoicing.
 */

// ---------------------------------------------------------------------------
// Snapshot type (returned by queries — lives in @euno/common per the rule)
// ---------------------------------------------------------------------------

/**
 * Per-tenant usage snapshot returned by {@link UsageMeter.getUsage} and
 * {@link UsageMeter.getAllUsage}.
 *
 * All counts are cumulative since the start of the current billing period
 * ({@link periodStart}). They are reset to zero when the caller invokes
 * {@link UsageMeter.resetPeriod}.
 */
export interface TenantUsageSnapshot {
  /** The tenant these counters belong to. */
  readonly tenantId: string;
  /**
   * Total enforcement checks since {@link periodStart} (allow + deny).
   * This is the primary billing unit for the Cloud Team and Cloud Enterprise
   * tiers (see `docs/pricing-stage-3.md`).
   */
  readonly enforcementEvents: number;
  /** Enforcement events that resulted in an `allow` decision. */
  readonly allowDecisions: number;
  /** Enforcement events that resulted in a `deny` decision. */
  readonly denyDecisions: number;
  /**
   * Number of kill-switch invocations since {@link periodStart}.
   *
   * Counts: global kill activation, per-session kill, per-agent kill.
   * Global kill deactivation, session/agent revival, and reset-all do
   * **not** count as invocations because they represent operational
   * recovery rather than active blocking.
   */
  readonly killSwitchInvocations: number;
  /**
   * Total successful capability-token issuances since {@link periodStart}.
   * Counts every successful `POST /api/v1/issue` call attributed to this
   * tenant. Used for billing and capacity planning.
   */
  readonly issuanceEvents: number;
  /**
   * Total successful capability-token renewals since {@link periodStart}.
   * Counts every successful `POST /api/v1/renew` call attributed to this
   * tenant. Used for billing and capacity planning.
   */
  readonly renewalEvents: number;
  /**
   * Per-user issuance breakdown since {@link periodStart}.
   *
   * Keys are user identifiers (e.g. `user@corp.com`) as supplied to
   * {@link UsageMeter.recordIssuance}. Values are per-user issuance counts.
   *
   * **Forensics / support use only** — billing uses only the tenant-level
   * {@link issuanceEvents} aggregate. Absent when the implementation does
   * not track per-user breakdown.
   */
  readonly issuancesByUser?: Readonly<Record<string, number>>;
  /**
   * Per-user renewal breakdown since {@link periodStart}.
   *
   * **Forensics / support use only** — billing uses only the tenant-level
   * {@link renewalEvents} aggregate. Absent when the implementation does
   * not track per-user breakdown.
   */
  readonly renewalsByUser?: Readonly<Record<string, number>>;
  /**
   * ISO-8601 UTC timestamp when the current period started (last
   * `resetPeriod()` call, or gateway start time when never reset).
   */
  readonly periodStart: string;
}

// ---------------------------------------------------------------------------
// Meter interface
// ---------------------------------------------------------------------------

/**
 * Seam for per-tenant billing metering.
 *
 * Implementations MUST be safe to call concurrently from asynchronous
 * handlers (though Node.js's single-threaded event loop means true
 * parallelism is never an issue, future Rust/WASM embeddings of this
 * interface may not share that guarantee).
 */
export interface UsageMeter {
  /**
   * Record one enforcement decision for the given tenant.
   *
   * Called by the enforcement engine after every `validateAction` that can
   * be attributed to a verified token carrying a `tenantId` claim.
   */
  recordEnforcement(tenantId: string, decision: 'allow' | 'deny'): void;

  /**
   * Record a kill-switch invocation for the given tenant.
   *
   * Called by the admin API on:
   *   - `POST /admin/kill-switch/global/activate`
   *   - `POST /admin/kill-switch/session/:id/kill`
   *   - `POST /admin/kill-switch/agent/:id/kill`
   */
  recordKillSwitchInvocation(tenantId: string): void;

  /**
   * Record a successful capability-token issuance for the given tenant and
   * user.
   *
   * Called by the capability-issuer after a successful `POST /api/v1/issue`
   * or `POST /api/v1/oidc/token` that produces a signed token. The `userId`
   * is the identity resolved from the upstream IdP token (e.g. the `email`
   * or `sub` claim). Implementations may store per-user breakdowns for
   * support and forensics; billing aggregates at the tenant level only.
   */
  recordIssuance(tenantId: string, userId: string): void;

  /**
   * Record a successful capability-token renewal for the given tenant and
   * user.
   *
   * Called by the capability-issuer after a successful `POST /api/v1/renew`.
   * The `userId` is extracted from the `authorizedBy.userId` claim of the
   * presented token. Implementations may store per-user breakdowns for
   * support and forensics; billing aggregates at the tenant level only.
   */
  recordRenewal(tenantId: string, userId: string): void;

  /**
   * Return the current usage snapshot for a single tenant.
   *
   * Returns a snapshot with all-zero counters and `periodStart = now`
   * when the tenant has never been seen — the caller does not need to
   * distinguish "new tenant" from "zero activity tenant".
   */
  getUsage(tenantId: string): TenantUsageSnapshot;

  /**
   * Return usage snapshots for every tenant ever observed by this meter
   * instance — including tenants whose counters have been reset to zero by
   * a prior `resetPeriod()` call.
   *
   * **Note:** `resetPeriod()` zeroes counters but retains tenant entries, so
   * a tenant that was active before the last reset and has had no activity
   * since will still appear here (with all-zero counts). This is intentional:
   * the entry keeps its `periodStart` timestamp, making it easy to verify that
   * the period was correctly advanced.
   *
   * The order of the returned snapshots is unspecified. Callers that
   * present the list to an operator SHOULD sort by `tenantId`.
   */
  getAllUsage(): TenantUsageSnapshot[];

  /**
   * Reset billing-period counters.
   *
   * @param tenantId — When supplied, only that tenant's counters are reset.
   *   When omitted, ALL tenant counters are reset and `periodStart` is
   *   advanced to `now` for every tenant.
   *
   * After a reset, the tenant entry still exists in the store (with zero
   * counters) so a subsequent `getUsage(tenantId)` does not fabricate a
   * new `periodStart`.
   */
  resetPeriod(tenantId?: string): void;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/** Mutable counters tracked per tenant inside the in-memory store. */
interface MutableTenantCounters {
  enforcementEvents: number;
  allowDecisions: number;
  denyDecisions: number;
  killSwitchInvocations: number;
  issuanceEvents: number;
  renewalEvents: number;
  /** Per-user issuance counts (forensics; not used for billing). */
  issuancesByUser: Record<string, number>;
  /** Per-user renewal counts (forensics; not used for billing). */
  renewalsByUser: Record<string, number>;
  periodStart: string; // ISO-8601
}

/**
 * Single-process in-memory implementation of {@link UsageMeter}.
 *
 * Suitable for:
 * - Hand-invoiced design-partner billing (query at month end).
 * - Single-replica self-host deployments.
 * - Unit and integration tests.
 *
 * **Limitations:** Counts are lost on gateway restart. Multi-replica
 * deployments accumulate counts independently per replica; operators must
 * sum across replicas. A future Redis-backed or Postgres-backed implementation
 * can replace this class via the {@link UsageMeter} seam.
 */
export class InMemoryUsageMeter implements UsageMeter {
  /** Map from tenantId → mutable counters. */
  private readonly counters = new Map<string, MutableTenantCounters>();

  /**
   * Obtain or create the counter entry for `tenantId`.
   *
   * Creating on first access is safe because `tenantId` values come from
   * verified JWT tokens and have already been authenticated — we are not
   * open to arbitrary tenant injection.
   */
  private getOrCreate(tenantId: string): MutableTenantCounters {
    let entry = this.counters.get(tenantId);
    if (!entry) {
      entry = {
        enforcementEvents: 0,
        allowDecisions: 0,
        denyDecisions: 0,
        killSwitchInvocations: 0,
        issuanceEvents: 0,
        renewalEvents: 0,
        issuancesByUser: {},
        renewalsByUser: {},
        periodStart: new Date().toISOString(),
      };
      this.counters.set(tenantId, entry);
    }
    return entry;
  }

  /** @inheritdoc */
  recordEnforcement(tenantId: string, decision: 'allow' | 'deny'): void {
    const entry = this.getOrCreate(tenantId);
    entry.enforcementEvents += 1;
    if (decision === 'allow') {
      entry.allowDecisions += 1;
    } else {
      entry.denyDecisions += 1;
    }
  }

  /** @inheritdoc */
  recordKillSwitchInvocation(tenantId: string): void {
    this.getOrCreate(tenantId).killSwitchInvocations += 1;
  }

  /** @inheritdoc */
  recordIssuance(tenantId: string, userId: string): void {
    const entry = this.getOrCreate(tenantId);
    entry.issuanceEvents += 1;
    entry.issuancesByUser[userId] = (entry.issuancesByUser[userId] ?? 0) + 1;
  }

  /** @inheritdoc */
  recordRenewal(tenantId: string, userId: string): void {
    const entry = this.getOrCreate(tenantId);
    entry.renewalEvents += 1;
    entry.renewalsByUser[userId] = (entry.renewalsByUser[userId] ?? 0) + 1;
  }

  /** @inheritdoc */
  getUsage(tenantId: string): TenantUsageSnapshot {
    const entry = this.counters.get(tenantId);
    if (!entry) {
      // Never seen — return a zero snapshot with periodStart = now. This is
      // semantically correct: the tenant has had zero activity this period.
      return {
        tenantId,
        enforcementEvents: 0,
        allowDecisions: 0,
        denyDecisions: 0,
        killSwitchInvocations: 0,
        issuanceEvents: 0,
        renewalEvents: 0,
        periodStart: new Date().toISOString(),
      };
    }
    return {
      tenantId,
      enforcementEvents: entry.enforcementEvents,
      allowDecisions: entry.allowDecisions,
      denyDecisions: entry.denyDecisions,
      killSwitchInvocations: entry.killSwitchInvocations,
      issuanceEvents: entry.issuanceEvents,
      renewalEvents: entry.renewalEvents,
      issuancesByUser: { ...entry.issuancesByUser },
      renewalsByUser: { ...entry.renewalsByUser },
      periodStart: entry.periodStart,
    };
  }

  /** @inheritdoc */
  getAllUsage(): TenantUsageSnapshot[] {
    return Array.from(this.counters.entries()).map(([tenantId, entry]) => ({
      tenantId,
      enforcementEvents: entry.enforcementEvents,
      allowDecisions: entry.allowDecisions,
      denyDecisions: entry.denyDecisions,
      killSwitchInvocations: entry.killSwitchInvocations,
      issuanceEvents: entry.issuanceEvents,
      renewalEvents: entry.renewalEvents,
      issuancesByUser: { ...entry.issuancesByUser },
      renewalsByUser: { ...entry.renewalsByUser },
      periodStart: entry.periodStart,
    }));
  }

  /** @inheritdoc */
  resetPeriod(tenantId?: string): void {
    const now = new Date().toISOString();
    if (tenantId !== undefined) {
      const entry = this.counters.get(tenantId);
      if (entry) {
        entry.enforcementEvents = 0;
        entry.allowDecisions = 0;
        entry.denyDecisions = 0;
        entry.killSwitchInvocations = 0;
        entry.issuanceEvents = 0;
        entry.renewalEvents = 0;
        entry.issuancesByUser = {};
        entry.renewalsByUser = {};
        entry.periodStart = now;
      }
      // If the tenant has no entry yet, nothing to reset — a no-op is correct.
    } else {
      for (const entry of this.counters.values()) {
        entry.enforcementEvents = 0;
        entry.allowDecisions = 0;
        entry.denyDecisions = 0;
        entry.killSwitchInvocations = 0;
        entry.issuanceEvents = 0;
        entry.renewalEvents = 0;
        entry.issuancesByUser = {};
        entry.renewalsByUser = {};
        entry.periodStart = now;
      }
    }
  }
}

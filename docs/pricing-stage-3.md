# Pricing Decisions — Stage 3

> **Status:** Decided — Task 17 (Stage 3 billing plumbing).
> This document is the single source of truth for the Stage 3 pricing
> curve. It MUST be updated before any Stage 4 rate or tier change is
> shipped.

---

## Tier Table (Stage 3 commitments)

| Tier | Audience | Price | Billing unit | Boundary |
|------|----------|-------|--------------|----------|
| **OSS / self-host** | Individual developer | Free | — | Local `@euno/mcp` enforcement only; no hosted services |
| **OSS + self-host gateway (BSL)** | Small team running own infra | Free for non-competing use | — | All packages; BYO Redis / Postgres / KMS |
| **Cloud Free** | Hobby / evaluation | Free up to 50 agents / 10 000 enforcement events per month | Enforcement events | Hosted gateway + API-key façade; 7-day audit retention |
| **Cloud Team** | Tech lead / small team | $49/seat/month, or $2 / 1 000 enforcement events above free tier | Seats **or** enforcement events | 90-day retention; kill-switch UI; SSO via OIDC |
| **Cloud Enterprise** | Engineering org | Contract (volume discount, annual) | Contract | Long retention; on-prem option; evidence export; SOC 2 attestation; SCIM |

### Why these units?

*Enforcement events* (each `POST /api/v1/enforce` call that reaches a
decision) are the primary metering dimension because:

1. They map directly to agent activity — one tool call = one enforcement
   event — so the bill is predictable and explainable to an engineering
   lead.
2. The gateway already counts decisions in Prometheus
   (`euno_gateway_decisions_total`). The billing meter mirrors the same
   signal per-tenant via `UsageMeter.recordEnforcement()`.
3. Retention and kill-switch invocations are secondary billing signals:
   they distinguish the Cloud Team tier from Cloud Free without
   introducing a second metering loop.

*Seats* (Cloud Team) are offered as an alternative billing mode for teams
that prefer a flat predictable cost over usage-based pricing. The lower of
the two charges applies within the same month.

---

## What is metered (implementation)

The `UsageMeter` interface (`@euno/common/usage-meter`) accumulates the
following counters per tenant since the last `resetPeriod()` call:

| Counter | Source | Billing tier gate |
|---------|--------|-------------------|
| `enforcementEvents` | `EnforcementEngine.validateAction` (post-token-verify) | Cloud Free limit; Cloud Team overage |
| `allowDecisions` | Same, decision = `allow` | Informational |
| `denyDecisions` | Same, decision = `deny` | Informational |
| `killSwitchInvocations` | Admin API: global activate, session kill, agent kill | Cloud Team feature gate |
| `auditRetentionDays` | Configuration (`AUDIT_LEDGER_RETENTION_DAYS`) | Cloud Free = 7; Cloud Team = 90; Enterprise = configurable |

Counters are reset per billing period by calling `POST /admin/usage/reset`.

---

## Admin API surface

`GET /admin/usage` — current period snapshot:

```http
GET /admin/usage HTTP/1.1
X-Admin-API-Key: <key>
```

```json
{
  "snapshotAt": "2025-01-31T23:59:59.000Z",
  "auditRetentionDays": 90,
  "tenants": [
    {
      "tenantId": "acme-corp",
      "enforcementEvents": 8423,
      "allowDecisions": 8100,
      "denyDecisions": 323,
      "killSwitchInvocations": 2,
      "periodStart": "2025-01-01T00:00:00.000Z"
    }
  ]
}
```

`POST /admin/usage/reset` — advance the billing period:

```http
POST /admin/usage/reset HTTP/1.1
X-Admin-API-Key: <key>
Content-Type: application/json

{}
```

Optional body field `tenantId` resets only that tenant.

---

## Hand-invoice workflow (first design partner)

Until automated billing (Stripe, Lago, …) is wired in Stage 4:

1. At month-end, call `GET /admin/usage` and record the numbers.
2. Compare against the tier table above to produce an invoice.
3. Call `POST /admin/usage/reset` to start the new period.
4. Email the invoice.

The admin endpoints require `ADMIN_API_KEY` authentication and are exposed
only on the internal admin port (`ADMIN_PORT`, default 9000) — they are
never reachable from the public load balancer.

---

## Upgrade wedges

### Free → Cloud Team

The hard gate is **90-day audit retention**. Free tenants' evidence is
pruned after 7 days. A compliance request (SOC 2 audit, security review)
immediately forces the upgrade because historical evidence is required.

Secondary gate: **kill-switch UI** — the global and per-agent kill switch
is available in the hosted UI only on Cloud Team and above.

### Cloud Team → Cloud Enterprise

- **Signed-evidence export** (forensic export via the audit query API with
  KMS-signed batch commitments).
- **On-prem KMS** — bring your own Azure Key Vault / AWS KMS / GCP Cloud
  KMS signing key so private-key material never leaves the customer's
  network.
- **SCIM provisioning** for seat management.
- **Contract SLA** with a named support contact.

---

## Free-tier limits (enforcement)

| Dimension | Cloud Free limit | Behaviour at limit |
|-----------|------------------|--------------------|
| Agents | 50 concurrent | 51st agent's tokens rejected at mint time |
| Enforcement events / month | 10 000 | Gateway returns HTTP 429 with `QUOTA_EXCEEDED` after the limit; audit evidence is still written |

Limits are enforced by the `GatewayQuotaEngine` (per-token) and by the
per-tenant `UsageMeter` (per-billing-period aggregate). The per-tenant
aggregate check is intentionally advisory in Stage 3 — the gateway logs
a warning rather than hard-blocking when the aggregate limit is reached,
because Stage 3 has no automated billing system to adjudicate overages. A
manual operator review step is expected before enforcement becomes hard in
Stage 4.

---

## Decisions deferred to Stage 4

- **Automated billing integration** (Stripe usage records, Lago metering
  API, or equivalent). The `UsageMeter` seam is ready; the integration
  itself is Stage 4 work.
- **Per-tenant quota enforcement** at the aggregate level (hard 429 after
  N enforcement events across a billing period). Stage 3 only accumulates
  the counter; Stage 4 enforces the hard cap.
- **Seat counting** — Cloud Team seat-based billing requires a seat
  management API (create seat, remove seat, list seats). Not shipped in
  Stage 3.
- **Upgrade flow** — the self-serve upgrade from Cloud Free to Cloud Team
  requires a checkout integration. Not shipped in Stage 3; the first
  design partner is hand-invoiced.

---

## Rationale for the chosen meter dimensions

**Why enforcement events and not API calls?**
API calls include health checks, JWKS refreshes, and admin operations.
Enforcement events are the meaningful unit — they represent an agent
attempting an action. The correlation between enforcement events and
business value is tight and auditable.

**Why kill-switch invocations as a secondary signal?**
Kill-switch use is a high-severity operational action. Tracking it per
tenant surfaces anomalies (unexpected kill storms) and provides a hook for
future incident-response SLA metering. It does not gate tier access in
Stage 3 but the counter is available for future use.

**Why not seats as the primary unit?**
Seat-based pricing is familiar but hard to define for AI agents — is a
"seat" a human operator or an automated agent process? Enforcement events
avoid this ambiguity and scale naturally with usage, which aligns incentives
(operators who over-build agents pay proportionally).

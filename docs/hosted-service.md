# eunox as a Hosted Service

> **Audience:** Engineering leads, product, and infrastructure teams planning the
> transition from the current self-hostable Go monorepo to a fully managed,
> multi-tenant SaaS offering.
>
> **Related documents:**
>
> - [`docs/architecture.md`](./architecture.md) — current system context and component map
> - [`docs/multi-tenancy.md`](./multi-tenancy.md) — tenant isolation model and threat model
> - [`docs/tiers.md`](./tiers.md) — tier definitions and feature matrix
> - [`docs/upgrade-to-hosted.md`](./upgrade-to-hosted.md) — self-hosted → cloud migration path
> - [`docs/deployment.md`](./deployment.md) — build and configuration reference

---

## Table of Contents

1. [What "hosted" means for eunox](#1-what-hosted-means-for-eunox)
2. [Hosted service architecture](#2-hosted-service-architecture)
   - [Control plane](#21-control-plane)
   - [Data plane](#22-data-plane)
   - [Tenant provisioning pipeline](#23-tenant-provisioning-pipeline)
   - [Regional topology](#24-regional-topology)
3. [Subscription model](#3-subscription-model)
   - [Tiers and entitlements](#31-tiers-and-entitlements)
   - [Quota enforcement](#32-quota-enforcement)
   - [Trial and free-tier limits](#33-trial-and-free-tier-limits)
4. [Payment components](#4-payment-components)
   - [Metering pipeline](#41-metering-pipeline)
   - [Billing service](#42-billing-service)
   - [Payment processor integration](#43-payment-processor-integration)
   - [Invoicing and receipts](#44-invoicing-and-receipts)
   - [Dunning and subscription lifecycle](#45-dunning-and-subscription-lifecycle)
5. [Execution plan](#5-execution-plan)
   - [Phase 1: Hosted MVP (weeks 1-6)](#phase-1-hosted-mvp-weeks-1-6)
   - [Phase 2: Billing and metering (weeks 7-12)](#phase-2-billing-and-metering-weeks-7-12)
   - [Phase 3: Enterprise tier (weeks 13-20)](#phase-3-enterprise-tier-weeks-13-20)
   - [Phase 4: Growth and compliance (weeks 21-28)](#phase-4-growth-and-compliance-weeks-21-28)

---

## 1. What "hosted" means for eunox

The current repository ships a self-hostable stack: operators run their own
Capability Issuer, Tool Gateway, Redis cluster, Postgres instance, and KMS.
A "hosted" offering removes this burden entirely — eunox operates the
infrastructure, manages upgrades and availability, and exposes the same
cryptographic guarantees as the self-hosted stack but via a shared-infrastructure,
multi-tenant platform.

The hosted service must preserve every security invariant that makes eunox valuable:

- **Fail-closed enforcement** — a billing failure must never cause enforcement
  to fail-open. The enforcement hot path is isolated from the billing path.
- **Cryptographic audit evidence** — each enforcement decision remains KMS-signed
  regardless of tier; the difference between tiers is retention and export rights,
  not the signing itself.
- **Tenant isolation** — row-level scoping in Postgres, namespaced Redis keys, and
  per-tenant signing keys ensure no cross-tenant data leakage.

---

## 2. Hosted service architecture

### 2.1 Control plane

The control plane handles tenant provisioning, policy management, capability
issuance, and administrative operations. It is not in the critical enforcement
path and can tolerate higher latency than the data plane.

```
┌──────────────────────────────────────────────────────────────────┐
│                        Control plane                              │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  Console UI  │  │  Admin API   │  │  Provisioning API    │   │
│  │  (web app)   │  │  (REST)      │  │  (tenant onboarding) │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│         │                 │                       │               │
│  ┌──────▼─────────────────▼───────────────────────▼───────────┐  │
│  │              Capability Issuer (cmd/issuer)                 │  │
│  │  • OIDC token exchange → capability JWT                     │  │
│  │  • Per-tenant signing key (KMS-backed)                      │  │
│  │  • Policy / manifest store (Postgres)                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │          API-Key Minter (cmd/minter)                      │    │
│  │  • Issues sk-<prefix>.<secret> keys → JWT exchange        │    │
│  │  • Per-tenant key policies in Postgres                    │    │
│  │  • Admin JWT auth (X-Admin-Api-Key deprecated)            │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │          Billing Service (new — see §4)                   │    │
│  │  • Consumes metering events from gateway                  │    │
│  │  • Syncs with payment processor (Stripe)                  │    │
│  │  • Enforces subscription entitlements                     │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Data plane

The data plane is the enforcement hot path. Every AI agent tool call passes
through here. It must be stateless, horizontally scalable, and isolated from
any billing or provisioning operations.

```
┌──────────────────────────────────────────────────────────────────┐
│                         Data plane                                │
│                                                                   │
│   AI Agent ──────────► Tool Gateway (cmd/gateway)                │
│                         │                                         │
│                    ┌────▼──────────────────┐                     │
│                    │  Enforcement Engine   │                     │
│                    │  • JWT verify (JWKS)  │                     │
│                    │  • Condition eval     │                     │
│                    │  • Kill-switch check  │                     │
│                    │  • DPoP replay guard  │                     │
│                    └────┬──────────────────┘                     │
│                         │                                         │
│          ┌──────────────┼──────────────────┐                     │
│          │              │                  │                      │
│   ┌──────▼──────┐  ┌────▼──────┐  ┌───────▼────────┐           │
│   │ Redis HA    │  │ Postgres  │  │ KMS Evidence   │           │
│   │ kill-switch │  │ audit     │  │ Signer         │           │
│   │ call-ctr    │  │ ledger    │  │ (per-region)   │           │
│   │ revocation  │  │           │  └────────────────┘           │
│   └─────────────┘  └───────────┘                                │
│                                                                   │
│   ────────────────────────────────────────────────────────       │
│   Metering events (async, non-blocking)                          │
│   └──► Metering queue → Billing service (control plane)          │
└──────────────────────────────────────────────────────────────────┘
```

Key invariant: metering events are written to a queue **after** the enforcement
decision is committed. A queue consumer failure never blocks an enforcement
decision.

### 2.3 Tenant provisioning pipeline

When a new user signs up, the provisioning pipeline:

1. Creates a tenant record in the control-plane Postgres.
2. Provisions a per-tenant KMS key (or key alias pointing to a shared hardware
   partition — see tier table in §3).
3. Creates a default policy manifest and policy ID.
4. Mints the tenant's first API key pair via the minter, returning `sk-…`.
5. Registers the tenant in the billing service and attaches a Stripe customer ID.
6. Writes JWKS configuration so the gateway trusts the tenant's issuer key.

Provisioning is idempotent: if interrupted, it can be replayed safely using the
tenant's UUID as the idempotency key.

### 2.4 Regional topology

For initial launch, a single primary region suffices. The target steady-state
topology is:

```
┌────────────────────────────────────────────────────────────────────┐
│  Region: us-east-1 (primary)                                        │
│                                                                     │
│  Control plane (single-region):                                     │
│    issuer  ·  minter  ·  billing-service  ·  console API            │
│    Postgres (primary) with PITR snapshots                           │
│                                                                     │
│  Data plane (multi-AZ):                                             │
│    gateway × N pods  ·  Redis HA (Sentinel or Cluster mode)         │
│    Postgres (replica for audit reads)                               │
│    KMS (regional endpoint)                                          │
└─────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Region: eu-west-1 (Phase 3 — data residency)                       │
│    Full stack replica for GDPR data-residency requirements          │
│    Independent Postgres (no cross-region audit data transfer)       │
│    Independent KMS                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

Multi-region routing uses DNS-based geolocation to direct enforcement traffic
to the closest data-plane region. Control-plane operations (policy updates,
key minting, billing) remain in the primary region for simplicity.

---

## 3. Subscription model

### 3.1 Tiers and entitlements

The subscription model maps directly onto the tiers described in
[`docs/tiers.md`](./tiers.md). The table below focuses on the system-level
entitlement flags that the billing service writes to the tenant record:

| Entitlement flag             | Free   | Team  | Enterprise   |
| ---------------------------- | ------ | ----- | ------------ |
| `max_agents`                 | 5      | ∞     | ∞            |
| `max_events_per_month`       | 50 000 | ∞     | ∞            |
| `audit_retention_days`       | 7      | 90    | configurable |
| `sso_enabled`                | false  | true  | true         |
| `evidence_export_enabled`    | false  | false | true         |
| `partner_federation_enabled` | false  | false | true         |
| `scim_enabled`               | false  | false | true         |
| `sla_tier`                   | none   | 99.9% | 99.99%       |
| `dedicated_support`          | false  | false | true         |

Entitlement flags are cached by the gateway at startup and refreshed on a
configurable TTL (default 5 minutes). Changes take effect within one TTL window —
there is intentionally no hard real-time cutoff to avoid enforcement disruption.

### 3.2 Quota enforcement

Quota enforcement operates in two modes:

**Soft quota (Free tier):** When `eunox_enforcement_requests_total{tenant}` crosses
90% of `max_events_per_month`, the billing service sends a warning email.
At 100%, enforcement is **not blocked** — decisions continue to be served,
but an overage flag is set on the tenant record. At the next billing cycle the
tenant is either upgraded automatically (if auto-upgrade is enabled) or notified
that events over the quota may be billed as overage.

**Hard quota (configurable):** Enterprise tenants can opt in to a hard daily cap
(`hard_quota_enabled: true`). When the daily cap is reached, the gateway returns
`HTTP 429` with `X-Quota-Reason: daily_cap_exceeded` for the remainder of the
UTC day. This is never the default — it requires explicit opt-in.

The enforcement hot path reads the quota state from Redis. The billing service
writes quota state to Redis when a threshold is crossed; it does not need to be
in the hot path.

### 3.3 Trial and free-tier limits

New signups receive a 14-day trial with Team-tier entitlements. At trial expiry,
the tenant is downgraded to Free unless a payment method has been added.
Trial events do not count toward the Free-tier monthly quota.

---

## 4. Payment components

### 4.1 Metering pipeline

The metering pipeline converts enforcement events into billable units.

```
Gateway (data plane)
  │
  │  async, after decision committed
  ▼
Metering event queue (Redis Streams or SQS)
  │
  ▼
Metering consumer (new service: cmd/metering-consumer)
  │  • Aggregates events per tenant per billing window
  │  • Deduplicates by jti (event ID)
  │  • Writes to metering_records table in Postgres
  ▼
Billing service
  │  • Reads metering_records to compute invoice line items
  │  • Pushes usage records to Stripe Billing (Meter API)
  ▼
Stripe → Invoice → Payment
```

**Schema: `metering_records`**

| Column             | Type        | Notes                              |
| ------------------ | ----------- | ---------------------------------- |
| `id`               | UUID        | Primary key                        |
| `tenant_id`        | text        | FK → tenants                       |
| `event_type`       | text        | `enforce`, `audit_write`, `export` |
| `count`            | bigint      | Aggregated count for the window    |
| `window_start`     | timestamptz | Billing window start               |
| `window_end`       | timestamptz | Billing window end                 |
| `pushed_to_stripe` | boolean     | True once pushed to Stripe         |
| `created_at`       | timestamptz |                                    |

### 4.2 Billing service

The billing service (`cmd/billing`) is a Go HTTP service that:

- Exposes a webhook endpoint for Stripe events (`POST /webhooks/stripe`).
- Pushes metering aggregates to Stripe's Usage Records API on each billing cycle.
- Writes entitlement changes back to the tenant record when a subscription
  transitions (trial → free, free → team, etc.).
- Provides an internal API consumed by the provisioning pipeline and the
  console (`GET /internal/v1/tenants/:id/entitlements`).

The billing service is deliberately **not** in the enforcement hot path. Its
database is the same Postgres instance as the rest of the control plane, but it
uses a separate schema (`billing.*`) to isolate migrations.

### 4.3 Payment processor integration

eunox uses [Stripe](https://stripe.com) as the payment processor. The integration
uses the following Stripe primitives:

| Stripe primitive      | Purpose                                                                                            |
| --------------------- | -------------------------------------------------------------------------------------------------- |
| `Customer`            | One per eunox tenant (created at provisioning)                                                     |
| `Subscription`        | Tracks tier, status, trial period                                                                  |
| `Meter` (new Billing) | Tracks enforcement events per tenant per month                                                     |
| `MeterEvent`          | Pushed by metering consumer after aggregation                                                      |
| `Invoice`             | Generated monthly by Stripe; sent to customer                                                      |
| `PaymentMethod`       | Card / ACH / SEPA stored in Stripe Vault                                                           |
| `Webhook`             | `customer.subscription.updated`, `invoice.paid`, `invoice.payment_failed` events → billing service |

**Key design decisions:**

- Payment-method data never enters eunox infrastructure. All card details are
  collected via Stripe Elements (Stripe-hosted widget) and stored in Stripe Vault.
- Stripe webhook signatures are verified using `webhook.ConstructEvent` before
  processing. Replayed or tampered events are rejected.
- Stripe customer IDs are stored in the `tenants` table (`stripe_customer_id`).
  No PII from Stripe is mirrored into eunox.

### 4.4 Invoicing and receipts

Invoices are generated and emailed by Stripe. eunox does not send invoices
directly. The console UI provides a link to the Stripe customer portal
(`/billing/portal` → Stripe-hosted portal) where users can:

- View invoice history and download PDFs.
- Update payment methods.
- Cancel or upgrade their subscription.

Custom invoicing (purchase orders, custom billing periods) is available on the
Enterprise tier and handled out-of-band via the sales team. The billing service
supports manually-entered `stripe_subscription_id` for these cases.

### 4.5 Dunning and subscription lifecycle

Stripe handles dunning (payment retry and failure notification) automatically via
Smart Retries. The billing service listens for the following webhook events and
acts on them:

| Webhook event                          | Action                                             |
| -------------------------------------- | -------------------------------------------------- |
| `invoice.payment_succeeded`            | Set `subscription_status = active`                 |
| `invoice.payment_failed`               | Set `subscription_status = past_due`; send warning |
| `customer.subscription.deleted`        | Downgrade tenant to Free tier; retain audit data   |
| `customer.subscription.trial_will_end` | Email 3-day trial expiry notice                    |
| `customer.subscription.updated`        | Refresh entitlement flags                          |

When a subscription moves to `past_due`, enforcement continues uninterrupted for
a **grace period of 14 days**. After the grace period, the tenant is downgraded to
Free-tier entitlements. Audit data is always retained for the contracted retention
window even after downgrade — data is never deleted due to billing status alone.

---

## 5. Execution plan

The execution plan is structured as four phases. Each phase delivers a
releasable increment of the hosted service.

### Phase 1: Hosted MVP (weeks 1-6)

**Goal:** Single-region, manually provisioned hosted service with Free and Team
tiers. No self-serve billing; customers contact sales for Team.

| Task | Owner    | Output                                                                                     |
| ---- | -------- | ------------------------------------------------------------------------------------------ |
| 1.1  | Infra    | Kubernetes cluster in us-east-1 with gateway, issuer, minter; Redis HA; Postgres with PITR |
| 1.2  | Platform | Automated tenant provisioning script (idempotent, KMS key creation, JWKS registration)     |
| 1.3  | Platform | Stripe customer creation wired into provisioning                                           |
| 1.4  | Platform | Console login (OIDC SSO via a managed IdP) and API-key display                             |
| 1.5  | Platform | `eunox-mcp upgrade-to-hosted` pointing at the hosted gateway URL                           |
| 1.6  | Ops      | Alerting: p99 enforcement latency, Redis HA health, Postgres WAL lag                       |
| 1.7  | Docs     | Public `docs/hosted-service.md` (this document); pricing page on marketing site            |

**Exit criteria:** 10 external beta tenants running enforcement through the hosted
gateway; SLO dashboards green; zero P1 incidents for 5 consecutive days.

---

### Phase 2: Billing and metering (weeks 7-12)

**Goal:** Self-serve Free and Team subscriptions with automated billing.

| Task | Owner    | Output                                                                      |
| ---- | -------- | --------------------------------------------------------------------------- |
| 2.1  | Platform | `cmd/metering-consumer`: Redis Streams → `metering_records` (Postgres)      |
| 2.2  | Platform | `cmd/billing`: Stripe Meter integration; `MeterEvent` push on billing cycle |
| 2.3  | Platform | Stripe webhook handler: subscription lifecycle events → entitlement refresh |
| 2.4  | Platform | Free-tier soft quota: warning email at 90%, overage flag at 100%            |
| 2.5  | Frontend | Self-serve signup flow: email → OIDC IdP → provisioning → Stripe checkout   |
| 2.6  | Frontend | Console billing page: current usage meter, plan, Stripe portal link         |
| 2.7  | Ops      | Metering pipeline monitoring: consumer lag, push success rate               |
| 2.8  | Security | PCI DSS scope review: confirm no card data touches eunox infra              |

**Exit criteria:** End-to-end self-serve signup → Free-tier enforcement → upgrade
to Team → Stripe invoice generated and paid; metering consumer lag < 60 seconds.

---

### Phase 3: Enterprise tier (weeks 13-20)

**Goal:** Enterprise tier fully operational with data residency, dedicated support,
and compliance evidence export.

| Task | Owner    | Output                                                                              |
| ---- | -------- | ----------------------------------------------------------------------------------- |
| 3.1  | Infra    | eu-west-1 region: full stack replica, independent Postgres, independent KMS         |
| 3.2  | Infra    | DNS geolocation routing: US tenants → us-east-1, EU tenants → eu-west-1             |
| 3.3  | Platform | Topology C provisioning: dedicated Postgres and Redis per Enterprise tenant         |
| 3.4  | Platform | Evidence export API (`GET /api/v1/audit/export`) behind Enterprise entitlement flag |
| 3.5  | Platform | Partner DID federation config in console (Enterprise)                               |
| 3.6  | Platform | SCIM 2.0 provisioning endpoint behind Enterprise entitlement flag                   |
| 3.7  | Sales    | Custom invoicing support: purchase orders, NET-30 billing via manual Stripe entries |
| 3.8  | Security | SOC 2 Type I readiness assessment; audit log evidence package                       |
| 3.9  | Ops      | 99.99% SLA monitoring; dedicated PagerDuty rotation for Enterprise tenants          |

**Exit criteria:** 3 paying Enterprise tenants in production; EU data-residency
tested (audit records do not leave eu-west-1); SOC 2 Type I report issued.

---

### Phase 4: Growth and compliance (weeks 21-28)

**Goal:** Reach 1 000 paying tenants; SOC 2 Type II; HIPAA BAA; annual contract
support.

| Task | Owner    | Output                                                                                  |
| ---- | -------- | --------------------------------------------------------------------------------------- |
| 4.1  | Platform | Annual subscription billing (Stripe billing cycles, prorated upgrades)                  |
| 4.2  | Platform | Usage-based overages for Team: enforcement events above quota billed at per-1k rate     |
| 4.3  | Platform | Multi-region metering aggregation: single Stripe customer across regions                |
| 4.4  | Infra    | apac-southeast-1 region (Phase 4): Singapore / Australia data residency                 |
| 4.5  | Security | SOC 2 Type II observation period (12 weeks) and report                                  |
| 4.6  | Legal    | HIPAA Business Associate Agreement template; Topology C deployment guide for healthcare |
| 4.7  | Sales    | Partner program: embedded licensing for ISVs building on eunox                          |
| 4.8  | Platform | Admin JWT auth migration: deprecate X-Admin-Api-Key fully (was deprecated in Task 15)   |

**Exit criteria:** 1 000 active tenants; SOC 2 Type II report issued; HIPAA BAA
available; no hard quota incidents (unintentional enforcement blocks).

---

## Summary

| Phase          | Weeks | Milestone                                      |
| -------------- | ----- | ---------------------------------------------- |
| 1 — Hosted MVP | 1–6   | Single-region hosted service; 10 beta tenants  |
| 2 — Billing    | 7–12  | Self-serve Free and Team; Stripe metering live |
| 3 — Enterprise | 13–20 | Multi-region; data residency; SOC 2 Type I     |
| 4 — Growth     | 21–28 | 1 000 tenants; SOC 2 Type II; HIPAA BAA        |

The enforcement hot path remains architecturally isolated from all billing and
provisioning components at every phase. Billing failures downgrade entitlements
within a 14-day grace period — they never cause enforcement to fail-open.

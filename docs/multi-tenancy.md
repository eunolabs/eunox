# Multi-Tenancy Isolation Model

> **Audience:** Architects, security engineers, and operators evaluating eunox
> tenant isolation guarantees.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Tenant Identification](#tenant-identification)
3. [Data Isolation](#data-isolation)
4. [Enforcement Isolation](#enforcement-isolation)
5. [Administrative Isolation](#administrative-isolation)
6. [Rate Limiting and Fair Use](#rate-limiting-and-fair-use)
7. [Observability and Metrics](#observability-and-metrics)
8. [Threat Model](#threat-model)
9. [Deployment Topologies](#deployment-topologies)
10. [Compliance Considerations](#compliance-considerations)

---

## Architecture Overview

Eunox implements a **shared-infrastructure, logical-isolation** multi-tenancy
model. All tenants share the same service binaries, database instances, and
Redis clusters, with isolation enforced at the application layer through
consistent `tenant_id` scoping across all data paths.

```
┌─────────────────────────────────────────────────────┐
│                   Load Balancer                       │
└─────────────┬───────────────────────────┬───────────┘
              │                           │
     ┌────────▼────────┐        ┌────────▼────────┐
     │  Gateway (Pod)  │        │  Gateway (Pod)  │
     │  tenant_id=acme │        │  tenant_id=corp │
     └────────┬────────┘        └────────┬────────┘
              │                           │
     ┌────────▼───────────────────────────▼────────┐
     │           Shared PostgreSQL Instance          │
     │   ┌─────────────────────────────────────┐    │
     │   │  Row-level tenant_id filtering       │    │
     │   │  Composite indexes (tenant_id, ...)  │    │
     │   └─────────────────────────────────────┘    │
     └──────────────────────────────────────────────┘
```

### Design Principles

1. **Tenant boundary at the gateway:** Each gateway deployment is configured
   with a single `GATEWAY_TENANT_ID` that scopes all operations.
2. **Defense in depth:** Even if a request bypasses gateway-level scoping,
   database queries enforce tenant filtering at the query layer.
3. **Cryptographic binding:** Capability tokens embed the issuing tenant in
   the `authorizedBy.tenantId` claim, making cross-tenant token reuse
   detectable.

---

## Tenant Identification

### Configuration

Tenant scoping is configured and enforced differently per service:

| Service | Tenant Context Source | Required | Notes                                                    |
| ------- | --------------------- | -------- | -------------------------------------------------------- |
| Gateway | `GATEWAY_TENANT_ID`   | Yes      | Used for admin/auth scoping and tenant-scoped operations |
| Issuer  | Identity token claims | Yes      | No dedicated `ISSUER_TENANT_ID` setting                  |
| Minter  | Request/auth context  | Yes      | No dedicated `MINTER_TENANT_ID` setting                  |

### Token-Level Tenancy

Capability tokens include tenant identity in the `authorizedBy` claim:

```json
{
  "authorizedBy": {
    "userId": "user@example.com",
    "roles": ["developer"],
    "tenantId": "acme-corp"
  }
}
```

This claim is:

- Set by the issuer at token creation time
- Immutable after issuance (protected by digital signature)
- Validated on audit queries to enforce tenant-scoped access

---

## Data Isolation

### Database Layer

Eunox uses **row-level application filtering** (not PostgreSQL Row-Level
Security policies). Every table containing tenant data includes a
`tenant_id NOT NULL` column:

| Table           | Tenant Column | Indexed                                                          |
| --------------- | ------------- | ---------------------------------------------------------------- |
| `audit_records` | `tenant_id`   | `idx_audit_records_tenant_timestamp` (tenant_id, timestamp DESC) |
| `api_keys`      | `tenant_id`   | `idx_api_keys_tenant` (tenant_id)                                |
| `key_policies`  | `tenant_id`   | `idx_key_policies_tenant` (tenant_id)                            |

### Query Isolation

All database queries include a `WHERE tenant_id = $1` predicate:

- **Audit queries** (`pkg/audit/backend.go`): `QueryFilter.TenantID` is
  mandatory for non-admin queries
- **API key queries** (`internal/minter/`): All CRUD operations scope by
  tenant
- **Admin operations**: Cross-tenant queries require explicit
  `acknowledgesCrossTenantImpact: true` in the request body

### Redis Isolation

Redis keys are namespaced by tenant where applicable:

| Key Pattern                     | Purpose                  |
| ------------------------------- | ------------------------ |
| `kill_switch:{tenant_id}`       | Per-tenant kill switch   |
| `revocations:{tenant_id}:{jti}` | Token revocation entries |
| `callcounter:{key}:{windowSec}` | API call counting        |
| `partner_dids`                  | Global (cross-tenant)    |

### Cross-Tenant Safeguards

The gateway admin API implements a **cross-tenant acknowledgement gate** for
operations that may affect multiple tenants (e.g., global usage resets):

```json
POST /admin/usage/reset
{
  "acknowledgesCrossTenantImpact": true,
  "reason": "billing cycle reset"
}
```

Operations lacking this flag that would affect data outside the configured
tenant are rejected with HTTP 403.

---

## Enforcement Isolation

### Token Verification

The enforcement pipeline validates tokens independently of tenant context —
any valid, non-revoked, non-expired token with matching capabilities is
accepted. This is by design: the **issuer** is the trust boundary, not the
gateway.

**Isolation guarantee:** A token issued for Tenant A cannot grant access in
Tenant B's deployment because:

1. Each tenant deployment uses its own issuer with distinct signing keys
2. The gateway verifies signatures against its configured JWKS
3. A different tenant's signing key will not be in the trusted JWKS set

### Single-Tenant Deployments (Recommended)

For strongest isolation, deploy one gateway + issuer pair per tenant:

```
Tenant A: gateway-a (JWKS → issuer-a keys)
Tenant B: gateway-b (JWKS → issuer-b keys)
```

### Shared-Issuer Deployments

When a single issuer serves multiple tenants (e.g., SaaS platform), current
gateway enforcement paths do not enforce token tenant matching during
enforcement decisions. Treat shared-issuer multi-tenant enforcement as unsafe
unless additional tenant checks are implemented.

---

## Administrative Isolation

### Admin Authentication Scoping

Admin JWT tokens include a tenant claim:

```go
type AdminIdentity struct {
    OperatorID string
    TenantID   string
}
```

Admin operations are scoped:

- An admin token for Tenant A cannot manage Tenant B's policies
- The deprecated `X-Admin-Api-Key` static key is tenant-bound via gateway
  configuration

### Idempotency Cache

The admin idempotency cache key includes `tenantID` to prevent cross-tenant
cache collisions:

```
{method}|{path}|{tenantID}|{idempotencyKey}
```

---

## Rate Limiting and Fair Use

### Current Implementation

| Scope           | Mechanism       | Granularity  |
| --------------- | --------------- | ------------ |
| Admin endpoints | Per-IP limiter  | 10 req/min   |
| Public API      | Per-key limiter | Configurable |
| Health checks   | Exempt          | —            |

### Per-Tenant Rate Limiting

Per-tenant rate limiting is achieved through **per-key limits** on the API
key minter. Each API key belongs to a tenant, and its call counter enforces
the configured quota:

```
maxcalls:{sessionId}:{toolName} → callcounter:{key}:{windowSec}
```

### Fair Use Enforcement

For shared infrastructure deployments, tenant-level fairness is enforced via:

1. **API key quotas:** Each tenant's keys have independent call limits
2. **Usage tracking:** `UsageTracker` in the gateway records per-tenant
   request volumes for billing and capacity planning
3. **Kill switch:** Per-tenant kill switch allows emergency throttling
   without affecting other tenants

---

## Observability and Metrics

### Tenant Attribution in Logs

All structured log entries include `tenant_id` when processing
tenant-scoped requests:

```json
{ "level": "info", "msg": "enforce", "tenant_id": "acme", "decision": "allow" }
```

### Prometheus Metrics

Enforcement metrics are recorded with decision labels. For tenant-level
dashboards, correlate with audit records or deploy separate gateway instances
per tenant (recommended for production).

### Audit Trail

Every enforcement decision, token issuance, and administrative action is
recorded in the tenant-scoped audit ledger with full attribution:

- `tenant_id` — owning tenant
- `actor` — authenticated principal
- `timestamp` — wall-clock time
- `chain_hash` — tamper-evident linkage

---

## Threat Model

### Threats and Mitigations

| Threat                                        | Severity | Mitigation                                                                              |
| --------------------------------------------- | -------- | --------------------------------------------------------------------------------------- |
| **T1: Cross-tenant token replay**             | High     | Tokens are signed with per-tenant keys; JWKS sets are isolated per deployment           |
| **T2: SQL injection bypassing tenant filter** | High     | Parameterized queries only; no dynamic SQL; ORM-free query construction                 |
| **T3: Admin escalation to other tenant**      | High     | Admin JWT `tenantId` claim validated; cross-tenant ops require explicit acknowledgement |
| **T4: Shared Redis key collision**            | Medium   | Keys namespaced by tenant_id; partner DID store is intentionally global                 |
| **T5: Noisy neighbor (resource exhaustion)**  | Medium   | Per-key quotas; per-tenant kill switch; deploy separate instances for strict isolation  |
| **T6: Audit data leakage across tenants**     | Medium   | `QueryFilter.TenantID` mandatory on all non-admin queries; audit export scoped          |
| **T7: Metadata leakage via error messages**   | Low      | Errors never include cross-tenant identifiers; generic 403/404 responses                |

### Residual Risks

1. **Shared database instance:** A compromised database credential exposes
   all tenants. Mitigation: Use separate database credentials per tenant
   where possible, or deploy dedicated instances for high-security tenants.

2. **Global partner DID registry:** The partner DID store is shared across
   tenants by design (federation is cross-organizational). A compromised
   partner DID affects all tenants that trust that partner.

3. **Metrics aggregation:** Prometheus metrics in shared deployments are
   aggregated across tenants. For strict metric isolation, deploy separate
   gateway instances per tenant.

---

## Deployment Topologies

### Topology A: Shared Everything (Development / Small SaaS)

```
All tenants → Single Gateway → Single Issuer → Single DB
```

- **Isolation:** Application-layer only
- **Cost:** Lowest
- **Risk:** Highest (shared blast radius)

### Topology B: Shared Database, Separate Services (Recommended)

```
Tenant A → Gateway-A + Issuer-A ─┐
                                  ├→ Shared PostgreSQL (row-level filtering)
Tenant B → Gateway-B + Issuer-B ─┘
```

- **Isolation:** Compute-level + application-layer
- **Cost:** Medium
- **Risk:** Database compromise still affects all tenants

### Topology C: Fully Isolated (Enterprise / Regulated)

```
Tenant A → Gateway-A + Issuer-A → DB-A → Redis-A
Tenant B → Gateway-B + Issuer-B → DB-B → Redis-B
```

- **Isolation:** Full infrastructure isolation
- **Cost:** Highest
- **Risk:** Lowest (no shared blast radius)

---

## Compliance Considerations

### GDPR

- **Data residency:** Deploy Topology C with per-region database instances
  to meet data residency requirements
- **Right to erasure:** See [audit-retention-compliance.md](./audit-retention-compliance.md)
  for chain-compatible data removal strategies
- **Data minimization:** Tokens embed minimal claims; audit records use
  pseudonymized actor identifiers where possible

### SOC 2

- **Logical access controls (CC6):** Tenant boundaries enforced at
  application, network, and (optionally) infrastructure layers
- **System operations (CC7):** Per-tenant audit trail with tamper-evident
  chain
- **Risk assessment (CC3):** This document serves as the multi-tenancy
  threat model

### HIPAA (Healthcare Deployments)

For HIPAA-regulated deployments, use **Topology C** (fully isolated) with:

- Dedicated database instances per covered entity
- Encryption at rest with tenant-specific KMS keys
- Audit log retention of 6 years minimum
- BAA (Business Associate Agreement) coverage for managed services

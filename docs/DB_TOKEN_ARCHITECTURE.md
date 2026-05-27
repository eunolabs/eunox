# DB Token Service — Architecture & Trust Model

This document describes the architecture, trust model, and relationship to the
Minter for the DB Token Service (`cmd/db-token-svc`,
`internal/dbtokensvc`). It answers the questions posed in OQ-3 of the
[Technical Architecture Review](TECHNICAL_REVIEW_2026_05_26.md).

---

## 1. Overview

The DB Token Service mints **short-lived, cloud-native database credentials** on
behalf of agents that present valid capability tokens containing `db://` resource
claims. It translates capability-based authorization into cloud-provider-specific
database authentication tokens (AWS RDS IAM tokens, Azure AD access tokens,
GCP OAuth2 tokens).

**Key distinction from the Minter:** The Minter manages long-lived API keys for
app-to-app authentication. The DB Token Service provides ephemeral database
credentials derived from capability tokens — they serve different trust domains
and lifecycle models.

---

## 2. Architecture

### 2.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  Agent Runtime (Untrusted Zone)                                      │
│  ├── Holds capability token with db:// claims                        │
│  └── Calls POST /api/v1/db-tokens                                   │
└─────────────────────┬────────────────────────────────────────────────┘
                      │ HTTPS (Bearer token)
                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│  DB Token Service (port 3005) — Trusted Zone                         │
│                                                                      │
│  ┌──────────────────┐   ┌──────────────────┐                        │
│  │  Token Verifier  │   │  Cloud DB        │                        │
│  │  (JWKS-based)    │   │  Adapter         │                        │
│  └────────┬─────────┘   └────────┬─────────┘                        │
│           │                      │                                   │
│  1. Verify JWT signature         │ 3. Mint credential                │
│  2. Extract db:// caps           │                                   │
│  3. Map resource → DB user       │                                   │
└───────────┼──────────────────────┼───────────────────────────────────┘
            │                      │
            ▼                      ▼
┌──────────────────┐   ┌───────────────────────────────────────────────┐
│  Issuer JWKS     │   │  Cloud Database APIs                          │
│  Endpoint        │   │  ├── AWS RDS (IAM Authentication)             │
└──────────────────┘   │  ├── Azure SQL (Azure AD tokens)              │
                       │  └── GCP Cloud SQL (OAuth2 tokens)            │
                       └───────────────────────────────────────────────┘
```

### 2.2 Request Flow

```
1. Agent → POST /api/v1/db-tokens
   Headers: Authorization: Bearer <capability-jwt>
   Body: { "database": "mydb", "ttlSeconds": 900 }

2. Token Verifier:
   a. Fetches JWKS from issuer (cached 5 min)
   b. Validates JWT signature, expiry, audience
   c. Extracts db:// resource URIs from capabilities
   d. Maps db:// resource → database username via CapabilityMapping

3. Authorization check:
   - Requested database must match a db:// capability in the token
   - Username derived from policy mapping (not agent-chosen)

4. Cloud Adapter mints credential:
   - AWS: IAM auth token (presigned SigV4 URL, 15 min)
   - Azure: Azure AD access token (1 hour, Azure-controlled)
   - GCP: OAuth2 access token (1 hour, GCP-controlled)

5. Response: { "username": "agent_readonly", "token": "...",
              "host": "mydb.cluster.us-east-1.rds.amazonaws.com",
              "port": 5432, "database": "mydb",
              "expiresAt": "2026-05-27T00:00:00Z", "adapter": "aws-rds" }
```

---

## 3. Token Differentiation

### 3.1 Capability Tokens vs. Database Tokens

| Dimension | Capability Token (JWT) | Database Token |
|-----------|----------------------|----------------|
| **Issuer** | Euno Capability Issuer | Cloud provider (AWS/Azure/GCP) |
| **Format** | JWT (signed with KMS) | Provider-specific (presigned URL, OAuth2 token) |
| **Lifetime** | 5–15 min (configurable) | 15 min – 1 hour (provider-determined) |
| **Scope** | Tools, resources, conditions | Single database + username |
| **Audience** | Gateway / services | Database endpoint |
| **Verification** | JWKS endpoint | Cloud IAM infrastructure |
| **Revocation** | Gateway revocation list (Redis) | Not individually revocable (TTL-based) |
| **Binding** | DPoP proof-of-possession | IP-based (database firewall) |

### 3.2 Database Tokens vs. Minter API Keys

| Dimension | Database Token | Minter API Key |
|-----------|---------------|----------------|
| **Purpose** | Ephemeral DB access for agents | Persistent app-to-app auth |
| **Lifetime** | Minutes (auto-expires) | Long-lived (explicit revocation) |
| **Rotation** | Not needed (ephemeral) | Pepper-based rotation with old-pepper grace |
| **Storage** | Never stored (generated on-demand) | HMAC hash stored in PostgreSQL |
| **Format** | Cloud-native token | `sk-{keyId}.{secret}` |
| **Trust root** | Capability token → cloud IAM | Admin API key → minter database |
| **Revocation** | TTL expiry only | Explicit DELETE via admin API |

---

## 4. Trust Model

### 4.1 Trust Chain

```
Enterprise IdP (root of trust)
    │
    ▼ OIDC identity token
Capability Issuer (issues scoped JWTs)
    │
    ▼ Capability token with db:// claims
DB Token Service (verifies token, maps to DB user)
    │
    ▼ Cloud-native DB credential
Database (verifies via cloud IAM)
```

### 4.2 Policy-Based Username Mapping

The DB Token Service does **not** let agents choose their database username.
Instead, it uses a `CapabilityMapping` that maps capability resource URIs to
database users:

```go
type CapabilityMapping struct {
    ResourceToUsername map[string]string
    // Example:
    // "db://analytics-db/reports" → "agent_readonly"
    // "db://main-db/users"       → "agent_writer"
}
```

This ensures:
1. **Least privilege**: Each capability maps to a specific DB role
2. **No escalation**: Agents cannot request a higher-privilege username
3. **Audit trail**: The mapping is deterministic and auditable
4. **Policy-driven**: Operators control the mapping via configuration

If a `PolicyUserID` is present in the token claims, it takes precedence
(allowing the issuer to specify the database user at token issuance time).

### 4.3 Mutual Authentication

```
Agent ←──── mTLS (optional) ───→ DB Token Service
                                         │
                                    IRSA / Workload Identity
                                         │
                                         ▼
                                   Cloud IAM ──→ Database
```

1. **Agent → Service**: Bearer capability JWT (verified via JWKS)
2. **Service → Cloud**: IAM role (IRSA, managed identity, workload identity)
3. **Cloud → Database**: IAM authentication (no shared passwords)

No shared secrets exist in this chain.

---

## 5. Rotation and Revocation

### 5.1 Token Rotation

Database tokens are **ephemeral** — they are generated fresh for each request
and expire automatically. There is no rotation mechanism because there is no
persistent state to rotate.

If an agent needs continued access, it requests a new token. This requires a
valid (non-expired, non-revoked) capability token, ensuring continuous
authorization validation.

### 5.2 Revocation Model

| Level | Mechanism | Latency |
|-------|-----------|---------|
| **Capability token** | Gateway revocation list (Redis) | <1s (pub/sub) |
| **Database token** | TTL expiry (no early revocation) | Up to 15 min (AWS) / 1 hour (Azure/GCP) |
| **Agent session** | Kill switch (session scope) | <1s (pub/sub) |
| **Agent identity** | Kill switch (agent scope) | <1s (pub/sub) |

**Important:** Cloud database tokens cannot be individually revoked before
expiry. Mitigation:
- Short TTLs (15 min default for AWS, capped by service MaxTTL)
- Kill switch prevents new token issuance immediately
- Database firewall rules can block the agent's IP if needed

### 5.3 Credential Lifecycle

```
  ┌──────────────────────────────────────────────────────┐
  │         Credential Lifecycle (DB Token)               │
  │                                                       │
  │  Issue ──→ Active ──→ Expired                        │
  │    │          │                                       │
  │    │          │ (no revocation — TTL only)            │
  │    │          └──→ (agent must request new token)     │
  │    │                                                  │
  │    └──→ Denied (token expired, revoked, or killed)   │
  └──────────────────────────────────────────────────────┘
```

---

## 6. Cloud Provider Integration

### 6.1 AWS RDS IAM Authentication

- **Credential**: Presigned `GetCallerIdentity`-style URL (SigV4)
- **Max lifetime**: 15 minutes (AWS hard limit for RDS IAM tokens)
- **Credential source**: IRSA (recommended), instance profile, static (dev)
- **Database requirement**: RDS/Aurora with IAM authentication enabled
- **Port**: Default 5432 (PostgreSQL), configurable
- **Username**: Mapped from capability via `CapabilityMapping`

### 6.2 Azure SQL with Azure AD

- **Credential**: Azure AD access token (OAuth2)
- **Typical lifetime**: 1 hour (Azure AD controlled)
- **Resource scope**: `https://database.windows.net/.default`
- **Credential source**: Managed identity, workload identity federation
- **Database requirement**: Azure SQL with Azure AD authentication enabled
- **Port**: Default 1433, configurable

### 6.3 GCP Cloud SQL IAM Authentication

- **Credential**: OAuth2 access token
- **Typical lifetime**: 1 hour (GCP controlled)
- **Scope**: `https://www.googleapis.com/auth/sqlservice.login`
- **Credential source**: Application Default Credentials (ADC), service account
- **Database requirement**: Cloud SQL with IAM database authentication enabled
- **Instance format**: `project:region:instance`
- **Port**: Default 5432, configurable

---

## 7. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_TOKEN_SVC_PORT` | 3005 | HTTP listen port |
| `DB_TOKEN_SVC_ADAPTER` | aws-rds | Cloud adapter: `aws-rds`, `azure-sql`, `gcp-cloudsql` |
| `ISSUER_JWKS_URL` | (required) | Issuer's JWKS endpoint |
| `ISSUER_JWT_AUDIENCE` | — | Expected audience claim |
| `NODE_ENV` | — | Set to `production` to reject stub adapters |
| `AWS_REGION` | — | AWS region for RDS token generation |
| `DB_TOKEN_SVC_RDS_ENDPOINT` | — | RDS cluster endpoint |
| `DB_TOKEN_SVC_AZURE_SERVER` | — | Azure SQL server FQDN |
| `DB_TOKEN_SVC_GCP_INSTANCE` | — | GCP instance connection name |

---

## 8. Health Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health/live` | GET | Liveness probe — service process is running |
| `/health/ready` | GET | Readiness probe — service process is running (always returns 200) |

---

## 9. Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `db_tokens_minted_total` | Counter | `adapter`, `status` | Total credential mints |
| `db_token_mint_duration_seconds` | Histogram | `adapter` | Minting latency |

Alert recommendations:
- `db_tokens_minted_total{status="error"}` rate > 0 for 5 min
- `db_token_mint_duration_seconds` p99 > 2s (SigV4/OAuth2 should be fast)
- Health ready endpoint returning non-200

---

## 10. Relationship to the Minter

```
                    ┌──────────────────────────┐
                    │   API Key Minter         │
                    │   (port 3004)            │
                    │                          │
                    │   Purpose: Long-lived    │
                    │   API keys for apps      │
                    │                          │
                    │   Format: sk-{id}.{sec}  │
                    │   Storage: PostgreSQL    │
                    │   Rotation: Pepper-based │
                    └──────────────────────────┘

                    ┌──────────────────────────┐
                    │   DB Token Service       │
                    │   (port 3005)            │
                    │                          │
                    │   Purpose: Ephemeral     │
                    │   DB creds for agents    │
                    │                          │
                    │   Format: Cloud-native   │
                    │   Storage: None          │
                    │   Rotation: Not needed   │
                    └──────────────────────────┘
```

These services operate in **different trust domains**:
- The Minter serves operators/apps that need persistent API keys
- The DB Token Service serves agents that need temporary database access

They share no state, no credentials, and no configuration. Their only
commonality is being part of the same platform and using the same observability
patterns (slog, Prometheus, health endpoints).

---

## 11. Related Documents

- [Storage Grant Architecture](STORAGE_GRANT_ARCHITECTURE.md) — Similar pattern for storage credentials
- [Agent Runtime Security](AGENT_RUNTIME_SECURITY.md) — How agents acquire and use tokens
- [Architecture Overview](ARCHITECTURE.md) — System-wide component interactions
- [Deployment Guide](DEPLOYMENT.md) — Production deployment patterns
- [Multi-Cloud](multi-cloud.md) — Cross-cloud credential management

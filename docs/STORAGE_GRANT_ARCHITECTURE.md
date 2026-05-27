# Storage Grant Service — Trust Model & Architecture

This document describes the architecture, trust model, and audit integration
for the Storage Grant Service (`cmd/storage-grant-svc`,
`internal/storagegrantsvc`). It answers the questions posed in OQ-2 of the
[Technical Architecture Review](TECHNICAL_REVIEW_2026_05_26.md).

---

## 1. Overview

The Storage Grant Service mints **short-lived, cloud-native storage credentials**
(presigned URLs, SAS tokens, signed URLs) on behalf of agents that present valid
capability tokens containing `storage://` resource claims. It acts as a
credential broker between the capability-based access control layer and
cloud-provider-specific storage APIs.

**Key principle:** Agents never hold long-lived cloud credentials. They receive
time-limited, scope-limited URLs that expire automatically.

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  Agent Runtime (Untrusted Zone)                                     │
│  ├── Holds capability token with storage:// claims                  │
│  └── Calls POST /api/v1/storage-grants                             │
└─────────────────────┬───────────────────────────────────────────────┘
                      │ HTTPS (Bearer token)
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Storage Grant Service (port 3006) — Trusted Zone                   │
│                                                                     │
│  ┌──────────────────┐   ┌──────────────────┐                       │
│  │  Token Verifier  │   │  Cloud Adapter   │                       │
│  │  (JWKS-based)    │   │  (pluggable)     │                       │
│  └────────┬─────────┘   └────────┬─────────┘                       │
│           │                      │                                  │
│  1. Verify JWT signature         │ 3. Mint credential               │
│  2. Extract storage:// caps      │                                  │
└───────────┼──────────────────────┼──────────────────────────────────┘
            │                      │
            ▼                      ▼
┌──────────────────┐   ┌────────────────────────────────────────────┐
│  Issuer JWKS     │   │  Cloud Storage APIs                        │
│  Endpoint        │   │  ├── AWS S3 (SigV4 presigned URLs)         │
└──────────────────┘   │  ├── Azure Blob (User-delegation SAS)      │
                       │  └── GCP GCS (V4 signed URLs)              │
                       └────────────────────────────────────────────┘
```

### 2.2 Request Flow

```
1. Agent → POST /api/v1/storage-grants
   Headers: Authorization: Bearer <capability-jwt>
   Body: { "bucket": "...", "path": "...", "permission": "read", "ttlSeconds": 900 }

2. Service extracts the capability JWT from the Authorization header

3. Token Verifier:
   a. Fetches JWKS from issuer (cached 5 min)
   b. Validates JWT signature (ES256/RS256)
   c. Validates claims (exp, iss, aud)
   d. Extracts storage:// resource URIs from capabilities

4. Authorization check:
   - Requested bucket/path must match a storage:// capability in the token
   - Requested permission must be allowed by the capability

5. Cloud Adapter mints credential:
   - AWS: Presigned URL with SigV4
   - Azure: User-delegation SAS token
   - GCP: V4 signed URL with RSA signature

6. Response: { "url": "...", "bucket": "...", "path": "...",
              "permission": "read", "expiresAt": "2026-05-27T00:00:00Z",
              "adapter": "aws-s3" }
```

---

## 3. Trust Model

### 3.1 Trust Chain

```
Enterprise IdP (root of trust)
    │
    ▼ OIDC identity token
Capability Issuer (issues scoped JWTs)
    │
    ▼ Capability token with storage:// claims
Storage Grant Service (verifies token, mints credential)
    │
    ▼ Short-lived presigned URL / SAS token
Cloud Storage (verifies signature, grants access)
```

### 3.2 What Each Party Trusts

| Party | Trusts | Verifies |
|-------|--------|----------|
| Agent | Issuer (to issue tokens), Storage Grant Service (to mint URLs) | Nothing (cannot verify) |
| Storage Grant Service | Issuer's JWKS (JWT signatures), Cloud provider credentials | Token signature, expiry, capability scope |
| Cloud Storage | The signing key (AWS access key, Azure delegation key, GCP service account) | URL signature, expiry timestamp |

### 3.3 Security Invariants

1. **No credential amplification:** The grant's scope never exceeds the capability
   token's scope. If the token grants `storage://bucket-a/prefix/*:read`, the
   service only issues read URLs for objects under `bucket-a/prefix/`.

2. **No credential persistence:** Agents receive URLs that expire. There is no
   refresh mechanism — agents must request new grants (re-validating their token).

3. **No shared secrets exposed:** The service holds cloud provider credentials
   (IAM roles, managed identities) but never exposes them to agents. Only
   derived, time-limited artifacts are returned.

4. **Production safety:** Stub adapters (used in tests) are rejected when
   `NODE_ENV=production`, preventing test credentials from leaking into production.

---

## 4. Grant Scoping

### 4.1 Time-Limited (TTL)

| Parameter | Default | Maximum | Enforcement |
|-----------|---------|---------|-------------|
| `ttlSeconds` (request body) | 15 min | 60 min | Hard cap in service config |
| AWS presigned URL | 15 min | 7 days (AWS limit) | Service enforces MaxTTL |
| Azure SAS token | 15 min | User-delegation key expiry | Service enforces MaxTTL |
| GCP V4 signed URL | 15 min | 7 days (GCP limit) | Service enforces MaxTTL |

If the capability token expires before the requested TTL, the grant TTL is
capped to the token's remaining lifetime.

### 4.2 Resource-Limited

Grants are scoped to:
- **Specific bucket**: Cannot access other buckets
- **Specific path prefix**: Cannot access other prefixes (when configured)
- **Specific permission**: Read only (write and delete are planned for a future release)

### 4.3 Single-Use vs. Multi-Use

- **AWS presigned URLs**: Multi-use within TTL (anyone with the URL can use it)
- **Azure SAS tokens**: Multi-use within TTL
- **GCP V4 signed URLs**: Multi-use within TTL

**Mitigation for URL leakage:** Short TTLs (default 15 min) limit exposure window.
For high-security deployments, operators should set aggressive TTLs (5 min or less).

---

## 5. Grant Replay Prevention

### 5.1 At the Capability Layer

- Each capability token has a unique `jti` (JWT ID)
- Tokens are DPoP-bound (proof-of-possession prevents token replay)
- Tokens are short-lived and revocable

### 5.2 At the Grant Layer

Presigned URLs themselves are not replay-protected (they are bearer artifacts).
However:

1. **TTL limits exposure**: URLs expire quickly
2. **Path scoping**: URLs are bound to specific objects/prefixes
3. **Permission scoping**: Read URLs cannot be used for writes
4. **Audit trail**: All grant issuances are logged with agent identity, resource,
   and permission for post-hoc analysis

### 5.3 Grant Escalation Prevention

An agent cannot escalate a grant because:

1. The grant's scope is derived from the capability token's `storage://` claims
2. The service verifies that the requested bucket/path/permission is within scope
3. Cloud provider signatures are bound to specific resources and permissions
4. There is no mechanism to extend TTL (agent must re-request with a valid token)

---

## 6. Audit Integration

### 6.1 What Is Logged

Every grant issuance produces a structured log entry:

```json
{
  "event": "storage_grant_issued",
  "timestamp": "2026-05-26T23:00:00Z",
  "agent_did": "did:web:example.com:agents:agent-1",
  "tenant_id": "tenant-abc",
  "token_jti": "tok_abc123",
  "adapter": "aws-s3",
  "bucket": "data-lake-prod",
  "path": "exports/2026/05/report.csv",
  "permission": "read",
  "ttl_seconds": 900,
  "expires_at": "2026-05-26T23:15:00Z",
  "request_id": "req_xyz789"
}
```

### 6.2 Integration with Audit Ledger

The Storage Grant Service integrates with the platform's audit infrastructure:

1. **Structured logging (slog)**: All grant operations are logged with sufficient
   context for correlation
2. **Prometheus metrics**: `storage_grants_minted_total{adapter,status}` counter and
   `storage_grant_mint_duration_seconds{adapter}` histogram
3. **Request ID propagation**: X-Request-ID header is forwarded for cross-service
   correlation
4. **Capability token JTI**: Logged with every grant for token→grant traceability

### 6.3 Forensic Queries

Operators can answer:
- "Which agent accessed bucket X in the last hour?" — Filter by agent_did + bucket
- "Was this presigned URL legitimately issued?" — Match URL parameters against grant log
- "What was the blast radius of a compromised token?" — Query by token_jti

---

## 7. Cloud Provider Integration Details

### 7.1 AWS S3 (SigV4 Presigned URLs)

```
Agent → Storage Grant Service → AWS STS/IMDS → Presigned URL
                                                    │
                                                    ▼
                                            S3 verifies SigV4
```

- **Credential source**: IAM Role for Service Account (IRSA on EKS), instance
  profile, or static credentials (dev only)
- **Signing**: AWS Signature Version 4 with credential scope
- **Permissions**: `s3:GetObject`, `s3:PutObject`
- **Bucket policy**: Should restrict to IRSA role ARN for least privilege

### 7.2 Azure Blob Storage (User-Delegation SAS)

```
Agent → Storage Grant Service → Azure AD → User-Delegation Key → SAS Token
                                                                       │
                                                                       ▼
                                                           Blob Storage verifies SAS
```

- **Credential source**: Managed identity or workload identity federation
- **Signing**: HMAC-SHA256 with user-delegation key (24h validity)
- **API version**: 2024-11-04
- **Permissions**: Read (`r`), Write (`w`)
- **Container scoping**: SAS is bound to specific container + blob path

### 7.3 GCP Cloud Storage (V4 Signed URLs)

```
Agent → Storage Grant Service → IAM signBlob API → V4 Signed URL
                                     or                    │
                               Local RSA key               ▼
                                                  GCS verifies V4 signature
```

- **Credential source**: Service account key (local) or IAM `signBlob` API (keyless)
- **Signing**: RSA-SHA256 (PKCS#1 v1.5)
- **Permissions**: Mapped to HTTP methods (GET for read, PUT for write — currently only read is authorized)
- **Max TTL**: 7 days (GCP limit, service enforces lower)

---

## 8. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_GRANT_SVC_PORT` | 3006 | HTTP listen port |
| `STORAGE_GRANT_SVC_ADAPTER` | aws-s3 | Cloud adapter: `aws-s3`, `azure-blob`, `gcp-gcs` |
| `ISSUER_JWKS_URL` | (required) | Issuer's JWKS endpoint for token verification |
| `ISSUER_JWT_AUDIENCE` | — | Expected audience claim (optional) |
| `NODE_ENV` | — | Set to `production` to reject stub adapters |
| `AWS_REGION` | — | AWS region for S3 presigning |
| `STORAGE_GRANT_SVC_BUCKET` | — | Default bucket name |
| `STORAGE_GRANT_SVC_AZURE_ACCOUNT` | — | Azure storage account name |
| `STORAGE_GRANT_SVC_AZURE_CONTAINER` | — | Azure blob container name |
| `GCP_PROJECT_ID` | — | GCP project for GCS signing |
| `STORAGE_GRANT_SVC_GCP_BUCKET` | — | GCS bucket name |

---

## 9. Deployment Considerations

### 9.1 High Availability

The Storage Grant Service is **stateless** — it can be horizontally scaled behind
a load balancer. All state is in the capability token (input) and the cloud
provider's signing infrastructure (external).

### 9.2 Failure Modes

| Failure | Impact | Behavior |
|---------|--------|----------|
| Issuer JWKS unreachable | Cannot verify tokens | Returns 401 (`invalid_token`); JWKS cache (5 min TTL) provides grace |
| Cloud credentials expired | Cannot sign URLs | Returns 500; relies on IMDS/workload identity refresh |
| Invalid token | No grant issued | Returns 401 with reason |
| Requested resource out of scope | No grant issued | Returns 403 with denial reason |

### 9.3 Monitoring

Key metrics to alert on:
- `storage_grants_minted_total{status="error"}` — Grant failures
- `storage_grant_mint_duration_seconds` p99 > 1s — Signing latency
- `storage_grants_minted_total{status="error"}` rate > 0 for 5 min — Sustained failures

---

## 10. Related Documents

- [Agent Runtime Security](AGENT_RUNTIME_SECURITY.md) — How agents acquire and use tokens
- [DB Token Architecture](DB_TOKEN_ARCHITECTURE.md) — Similar pattern for database credentials
- [Architecture Overview](ARCHITECTURE.md) — System-wide component interactions
- [Deployment Guide](DEPLOYMENT.md) — Production deployment patterns
- [Multi-Cloud](multi-cloud.md) — Cross-cloud credential management

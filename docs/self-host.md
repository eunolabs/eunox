# Self-Hosting euno — BYO-GW Guide

> **Target audience:** Platform engineers and security teams running euno
> infrastructure on their own cloud or on-premises.
>
> **Status:** Stage 3 documentation. Self-hosting is available under the
> [BSL 1.1](../LICENSE) license (non-competing use; the gateway source converts to
> Apache-2.0 four years after each release). Review the license before deploying
> in a competing product.
>
> **Related documents:**
> - [`docs/stage-3-design.md`](./stage-3-design.md) — authoritative architecture decisions
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — build and configuration reference
> - [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) — system context and component map
> - [`docs/capability-model.md`](./capability-model.md) — enforcement invariants
> - [`docs/security/minter-threat-model.md`](./security/minter-threat-model.md) — minter threat model
> - [`docs/migrating-from-local.md`](./migrating-from-local.md) — upgrading from `@euno/mcp` local mode

---

## 1. What self-hosting means

Self-hosting means you run **all** of the following infrastructure yourself, using the BSL-licensed images from this repository:

| Component | Package | Purpose |
|---|---|---|
| **Capability Issuer** | `euno-platform/packages/capability-issuer` | Issues signed JWT capability tokens from your identity store and KMS |
| **Tool Gateway** | `euno-platform/packages/tool-gateway` | Enforces capability tokens on every agent tool call |
| **Redis** | BYO (≥ 6.2) | Shared state: call counters, kill-switch, revocation list, DPoP replay cache |
| **Postgres** | BYO (≥ 14) | Durable truth: audit ledger, kill-switch persistence, revocation durability |
| **KMS / signing key** | BYO (Azure Key Vault, AWS KMS, GCP Cloud KMS, or local for dev) | Signs capability tokens (issuer) and audit evidence (gateway) |

`@euno/mcp` itself (the agent-side proxy) is Apache-2.0 and does not require a
self-hosted gateway. You only need this guide if you want persistent shared state
— shared kill-switch, shared call counters, and a queryable audit ledger — across
more than one agent process.

---

## 2. What you give up versus managed cloud

The self-host bundle intentionally excludes the managed minter façade. The table
below maps every Cloud feature to its self-host equivalent.

| Feature | Cloud (Managed) | Self-host (BSL) |
|---|---|---|
| Local enforcement (`@euno/mcp` only) | ✅ | ✅ |
| stdio + HTTP proxy transports | ✅ | ✅ |
| All condition types (Stage 1–2) | ✅ | ✅ |
| Local HMAC audit log | ✅ | ✅ |
| `euno-mcp validate-token` / `stats` | ✅ | ✅ |
| Remote enforcer mode (`enforcer: url`) | ✅ | ✅ |
| KMS-backed audit signer | ✅ | ✅ (BYO KMS) |
| Redis call-counter store | ✅ | ✅ (BYO Redis) |
| Redis kill-switch manager | ✅ | ✅ (BYO Redis) |
| Postgres audit ledger | ✅ | ✅ (BYO Postgres) |
| Audit query API | Cloud-managed retention | ✅ (you manage retention) |
| Kill-switch admin API | ✅ | ✅ |
| **API-key minter façade** (`sk-...` → JWT) | ✅ | ❌ — issue tokens directly via capability-issuer |
| SSO via OIDC | Cloud Team + | ❌ — bring your own IdP integration |
| Evidence export (signed OCSF) | Cloud Enterprise | ❌ — Stage 5 |
| On-prem signing key (BYO HSM) | Cloud Enterprise | ✅ |
| SOC2 attestation docs | Cloud Enterprise | ❌ — self-managed |
| Cross-chain audit anchor | Stage 5 | ❌ — Stage 5 |

### The key difference: no managed minter

In the managed Cloud offering, `@euno/mcp` sends an `sk-...` API key; the cloud
minter verifies it and mints a short-lived signed JWT before the request reaches
the gateway.

**Self-hosters must issue their own JWT capability tokens** via the
`capability-issuer` service (or any compatible issuer). The `@euno/mcp`
remote-enforcer mode accepts a pre-issued JWT in the `Authorization` header
instead of an `sk-...` API key when pointed at a self-hosted gateway. The gateway
verifier path is identical — the cryptographic-token invariant is preserved, only
the issuance front-door changes.

---

## 3. Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Your infrastructure (self-hosted)                                  │
│                                                                     │
│  ┌─────────────────┐   sign   ┌──────────────────────────────────┐  │
│  │  Capability     │ ───────► │  KMS / signing key               │  │
│  │  Issuer         │          │  (Azure KV, AWS KMS, GCP KMS)    │  │
│  │  :3001          │          └──────────────────────────────────┘  │
│  │                 │  JWKS    ┌──────────────────────────────────┐  │
│  │  POST /issue    │ ◄──────  │  Tool Gateway :3002              │  │
│  └────────┬────────┘          │                                  │  │
│           │ JWT               │  POST /api/v1/enforce            │  │
│           │                   │  GET  /api/v1/audit/records      │  │
│           ▼                   │  POST /admin/kill-switch/...     │  │
│  ┌────────────────┐           │                                  │  │
│  │  @euno/mcp     │ ─ JWT ──► │  verifier → PDP → audit         │  │
│  │  (agent proxy) │           └──────────┬───────────────────────┘  │
│  └────────────────┘                      │  R/W                     │
│                                          ▼                          │
│                              ┌────────────────────┐                 │
│                              │  Redis :6379        │                 │
│                              │  call counters,     │                 │
│                              │  kill-switch,       │                 │
│                              │  revocation         │                 │
│                              └────────────────────┘                 │
│                              ┌────────────────────┐                 │
│                              │  Postgres :5432     │                 │
│                              │  audit ledger,      │                 │
│                              │  kill-switch,       │                 │
│                              │  revocation         │                 │
│                              └────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

The Capability Issuer and the Tool Gateway are separate processes with separate
credentials. The gateway never writes to the issuance database; the issuer never
writes to the enforcement audit ledger. Keep credentials segregated as specified
in the threat model (`docs/security/minter-threat-model.md` §"Audit trail").

---

## 4. Minimum viable issuer recipe

This section shows the smallest configuration that produces a valid capability
token and satisfies the gateway's verifier — no Redis, Postgres, or enterprise OIDC
provider required for development.

> **Scope:** Development and internal team use. For production deployments and
> compliance-sensitive environments, skip to §5.
>
> **A KMS-compatible signing provider is required** — the capability-issuer
> `SIGNING_PROVIDER` accepts `azure-keyvault`, `aws-kms`, and `gcp-cloudkms`
> only. There is no software-PEM signing path. The minimum viable recipe uses
> AWS KMS. For true air-gapped local development,
> [LocalStack](https://github.com/localstack/localstack) emulates the AWS KMS
> API locally — no cloud account needed.

### 4.1 Concepts

A capability token is a signed JWT that carries an `AgentCapabilityManifest` (your
policy YAML/JSON) as claims. To issue one you need:

1. **A signing key in a KMS** — the issuer signs every token via a cloud KMS key.
   The minimum viable recipe uses an AWS KMS asymmetric key (EC P-256 / ES256).
   See §5.1 for Azure Key Vault and GCP Cloud KMS alternatives.
2. **An issuer DID** — the `iss` claim in every token. The gateway fetches the
   public JWKS from this DID's `/.well-known/jwks.json` endpoint (or the
   `ISSUER_JWKS_URL` you configure directly).
3. **A caller identity token** — the issuer's `POST /api/v1/issue` endpoint
   requires an `Authorization: Bearer <token>` that the configured identity
   provider validates. With `IDENTITY_PROVIDER=did`, callers present a DID-bound
   JWT, avoiding a dependency on Azure AD / Cognito / GCP Identity.
4. **A policy manifest** — a YAML file matching the `AgentCapabilityManifest`
   schema (see [`docs/CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md)).

### 4.2 Step-by-step

#### Step 1 — Create an AWS KMS asymmetric signing key

```bash
# Create a directory for the self-host stack (outside the repo)
mkdir -p /srv/euno/keys && chmod 700 /srv/euno/keys

# Create an EC P-256 asymmetric signing key in AWS KMS (ES256)
# Note: you must have the AWS CLI configured with sufficient IAM permissions.
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "euno capability-issuer signing key (dev)" \
  --region us-east-1

# The output includes "KeyId" — copy it; you'll need it in Step 3.
# Example output: "KeyId": "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-..."
```

> **LocalStack alternative:** To avoid a real AWS account for local development,
> run `docker run --rm -p 4566:4566 localstack/localstack` and set
> `AWS_ENDPOINT_URL=http://localhost:4566` plus dummy `AWS_ACCESS_KEY_ID=test`
> / `AWS_SECRET_ACCESS_KEY=test` in issuer.env. LocalStack supports the KMS
> `SignCommand` API needed by the issuer.
>
> **Production note:** Use an HSM-backed key in production (AWS CloudHSM-origin
> CMK, Azure Managed HSM key, or GCP HSM protection level). For the Azure
> Managed HSM provisioning procedure and non-exportability verification steps,
> see `docs/stage-3-design.md` §1.3. Other KMS providers are described in §5.1.

#### Step 2 — Write a capability policy manifest

Create `/srv/euno/policies/agent.yaml` following the pattern from
[`public/packages/mcp/policies/filesystem.policy.yaml`](../public/packages/mcp/policies/filesystem.policy.yaml):

```yaml
agentId: "my-agent"
name: "My Agent"
version: "0.1.0"
metadata:
  description: "Example self-host policy"
requiredCapabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: pathPattern
        allowedPaths: ["/data/**"]
```

Validate the manifest before deploying:

```bash
npx -y @euno/mcp validate-policy /srv/euno/policies/agent.yaml
```

#### Step 3 — Configure the capability issuer

Create `/srv/euno/issuer.env`:

```bash
# Runtime
NODE_ENV=production
PORT=3001
EUNO_DEPLOYMENT_TIER=single-replica

# Signing: AWS KMS asymmetric key (ES256).
# Replace the key ARN with the one from Step 1.
SIGNING_PROVIDER=aws-kms
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AWS_KMS_REGION=us-east-1
# Credentials: use the standard AWS credential chain (instance profile / IRSA / env vars).
# For local dev with LocalStack, add:
# AWS_ACCESS_KEY_ID=test
# AWS_SECRET_ACCESS_KEY=test
# AWS_ENDPOINT_URL=http://localstack:4566
ISSUER_DID=did:web:issuer.example.com   # replace with your actual public hostname

# Identity: DID-based — no enterprise OIDC provider required
IDENTITY_PROVIDER=did

# Token TTL: 15 minutes (900 s). Align with your session length.
DEFAULT_TOKEN_TTL=900

# Audience: must match the gateway's GATEWAY_AUDIENCE
GATEWAY_AUDIENCE=tool-gateway:my-team

# Logging
ENABLE_DETAILED_LOGGING=false
```

#### Step 4 — Configure the tool gateway

Create `/srv/euno/gateway.env`:

```bash
# Runtime
NODE_ENV=production
PORT=3002
ADMIN_PORT=3003
EUNO_DEPLOYMENT_TIER=single-replica

# Audience: must match GATEWAY_AUDIENCE in issuer.env
GATEWAY_AUDIENCE=tool-gateway:my-team

# Verifier: point at the issuer's JWKS endpoint
ISSUER_JWKS_URL=http://capability-issuer:3001/.well-known/jwks.json

# Audit evidence signing: local EC P-256 key for dev (no KMS required for the gateway).
# Generate:
#   openssl ecparam -name prime256v1 -genkey -noout \
#     | openssl pkcs8 -topk8 -nocrypt -out /srv/euno/keys/audit-signing.pem
#   chmod 600 /srv/euno/keys/audit-signing.pem
ENABLE_CRYPTOGRAPHIC_AUDIT=true
EVIDENCE_SIGNED_DECISIONS=deny
EVIDENCE_SIGNING_KEY_FILE=/app/keys/audit-signing.pem
EVIDENCE_SIGNING_ALGORITHM=ES256

# Admin API
ADMIN_API_KEY=<generate-with-openssl-rand-base64-32>

# Redis circuit-breaker mode — MUST be set explicitly; no silent default.
# fail-closed: enforce counter and revocation checks even when Redis is slow.
REDIS_CIRCUIT_OPEN_MODE=fail-closed

# Audit ledger: disabled (no external ledger backend for dev; evidence is
# written to local log files only and AUDIT_LEDGER_BACKEND=none means
# the audit query API returns no results).
AUDIT_LEDGER_BACKEND=none
```

#### Step 5 — Start the local stack

```bash
docker compose -f /srv/euno/docker-compose.yml up
```

See §4.5 for the `docker-compose.yml`.

#### Step 6 — Issue a capability token

```bash
# Issue a capability token for a specific agent
# The Authorization header carries a DID-bound JWT (IDENTITY_PROVIDER=did path).
curl -s -X POST http://localhost:3001/api/v1/issue \
  -H "Authorization: Bearer <did-bound-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "my-agent",
    "requestedCapabilities": [
      {
        "resource": "read_file",
        "actions": ["call"],
        "conditions": [
          { "type": "pathPattern", "allowedPaths": ["/data/**"] }
        ]
      }
    ]
  }'
# → { "token": "eyJ...", "expiresAt": 1747000000, "tokenId": "jti-...", "capabilities": [...] }
```

Store the returned `token` value; it is what `@euno/mcp` will forward in
`Authorization: Bearer` when calling `POST /api/v1/enforce`.

#### Step 7 — Configure @euno/mcp to use the self-hosted gateway

In your `claude_desktop_config.json` (or equivalent MCP host config), pass the
pre-issued JWT instead of an `sk-...` API key:

```jsonc
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--enforcer-url", "http://localhost:3002",
        "--enforcer-api-key", "<the-jwt-from-step-6>",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

> **Token expiry:** The JWT expires after `DEFAULT_TOKEN_TTL` seconds. The
> `--enforcer-api-key` is a static bearer token — `@euno/mcp` does not
> automatically re-issue it. Before the token expires, re-issue a fresh JWT
> from the issuer (§6.1) and update the config, then restart the proxy.

### 4.3 Minimum viable issuer: what you skipped

This recipe intentionally omits:

- **Redis** — single-replica mode uses in-process call counters and kill-switch.
  These do not persist across gateway restarts and are not shared across replicas.
- **Postgres** — `AUDIT_LEDGER_BACKEND=none` disables the external ledger backend.
  Evidence is written to local log files only; the audit query API returns no results.
- **Enterprise OIDC** — the `IDENTITY_PROVIDER=did` path requires callers to
  present a DID-bound JWT. For a team using a corporate IdP (Azure AD, Okta,
  AWS Cognito), replace with the appropriate `IDENTITY_PROVIDER` value and
  provide the matching config block.
- **Gateway-side KMS evidence signing** — the gateway signs audit evidence with a
  local PEM key (`EVIDENCE_SIGNING_KEY_FILE`). For production, replace with
  `AUDIT_SIGNING_KMS_PROVIDER` (see §5.1).

Capabilities that require the omitted components:

| Omitted component | Impact |
|---|---|
| Redis | Call-rate counters (`maxCalls`) are per-replica only; kill-switch changes are not shared across gateway replicas; revocation list is in-memory |
| Postgres | Audit records are ephemeral (lost on restart); audit query API returns no results |
| Enterprise OIDC | Callers must present DID-bound JWTs; Azure AD / Cognito / GCP-issued OIDC tokens are not accepted |
| Gateway-side KMS | Audit evidence signatures are produced by a software PEM key; a compromised host leaks the audit signing key |

### 4.4 Docker Compose for the local stack

Create `/srv/euno/docker-compose.yml`:

```yaml
# Local self-host stack: capability-issuer + tool-gateway (no Redis, no Postgres)
# Use for development and single-developer testing only.
# For production, use the full stack in §5.3.

version: "3.9"

services:
  capability-issuer:
    build:
      context: /path/to/euno-platform    # root of the euno-platform monorepo
      dockerfile: euno-platform/packages/capability-issuer/Dockerfile
    image: euno/capability-issuer:local
    container_name: euno-issuer
    env_file: /srv/euno/issuer.env
    volumes:
      - /srv/euno/policies:/app/policies:ro
    ports:
      - "3001:3001"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3001/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5

  tool-gateway:
    build:
      context: /path/to/euno-platform
      dockerfile: euno-platform/packages/tool-gateway/Dockerfile
    image: euno/tool-gateway:local
    container_name: euno-gateway
    env_file: /srv/euno/gateway.env
    volumes:
      - /srv/euno/keys:/app/keys:ro
    depends_on:
      capability-issuer:
        condition: service_healthy
    ports:
      - "3002:3002"
      - "127.0.0.1:3003:3003"    # admin — host-side loopback only
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3002/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5
```

---

## 5. Production self-host setup

### 5.1 Replace the local signing key with KMS

For production, the capability-issuer signing key MUST be stored in a managed
KMS or HSM. The three supported backends are:

| Backend | `SIGNING_PROVIDER` value | FIPS 140-2 Level | Per-tenant key isolation |
|---|---|---|---|
| Azure Key Vault (Managed HSM) | `azure-keyvault` | Level 3 (HSM keys) | ✅ via `keysByPolicyHash` |
| AWS KMS | `aws-kms` | Level 3 (CloudHSM-backed CMKs) | ✅ separate CMK per tenant |
| GCP Cloud KMS | `gcp-cloudkms` | Level 3 (HSM protection level) | ✅ separate CryptoKey per tenant |

**Azure Key Vault (recommended for hosted or Azure-primary deployments):**

```bash
# issuer.env additions / replacements
SIGNING_PROVIDER=azure-keyvault
AZURE_KEYVAULT_URL=https://my-vault.vault.azure.net/
AZURE_KEYVAULT_KEY_NAME=capability-signing-key
AZURE_CREDENTIAL_TYPE=managed-identity   # use workload identity in Kubernetes
```

**AWS KMS:**

```bash
SIGNING_PROVIDER=aws-kms
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/mrk-abc123
AWS_KMS_REGION=us-east-1
# Credentials via EC2 instance profile / EKS IRSA — no key/secret required
```

**GCP Cloud KMS:**

```bash
SIGNING_PROVIDER=gcp-cloudkms
GCP_PROJECT_ID=my-project
GCP_LOCATION_ID=us-central1
GCP_KEYRING_ID=euno-signing
GCP_CRYPTOKEY_ID=capability-signing-key
# Credentials via Workload Identity — no key file required in production
```

For the gateway's evidence signer (audit signing), replace the local PEM with
the same KMS provider:

```bash
# gateway.env additions — replaces EVIDENCE_SIGNING_KEY_FILE
AUDIT_SIGNING_KMS_PROVIDER=aws-kms   # or azure-keyvault / gcp-cloudkms
# AWS KMS example:
AUDIT_SIGNING_AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/mrk-def456
```

See `docs/stage-3-design.md` §1.3 for the Azure Managed HSM
provisioning procedure and the non-exportability verification steps.

### 5.2 Add Redis and Postgres

For multi-replica production deployments set `EUNO_DEPLOYMENT_TIER=multi-replica`
and provide:

**Redis (call counters, kill-switch, revocation):**

```bash
# Both issuer.env and gateway.env
REDIS_URL=rediss://:<password>@redis.internal:6379

# Each store has an independent key prefix (no global collision risk):
KILL_SWITCH_KEY_PREFIX=killswitch:
CALL_COUNTER_KEY_PREFIX=capcall:
REVOCATION_KEY_PREFIX=revoked:

# Circuit-breaker mode — must be explicit:
REDIS_CIRCUIT_OPEN_MODE=fail-closed   # hosted default; change to fail-open for planned maintenance windows
```

**Postgres (audit ledger, kill-switch persistence, revocation durability):**

```bash
# gateway.env
AUDIT_LEDGER_BACKEND=postgres
AUDIT_LEDGER_PG_URL=postgresql://audit_writer:pass@postgres.internal:5432/euno_audit
AUDIT_LEDGER_HMAC_SECRET=<openssl rand -hex 32>   # per-row tamper-detection secret
AUDIT_LEDGER_RUN_MIGRATIONS=true   # set to false after first run; manage schema externally in production
```

The gateway creates the following tables automatically when
`AUDIT_LEDGER_RUN_MIGRATIONS=true` (see `docs/stage-3-design.md` §2 for the full
schema):

```sql
-- Audit ledger (append-only)
CREATE TABLE euno_audit_ledger (
  seq           BIGINT PRIMARY KEY,
  record_id     TEXT NOT NULL UNIQUE,
  replica_id    TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  record_hash   TEXT NOT NULL,
  payload       JSONB NOT NULL,
  row_hmac      BYTEA NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Kill-switch entries (row-presence = switch active)
CREATE TABLE euno_kill_switch_entries (
  entry_type TEXT NOT NULL,
  entry_id   TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (entry_type, entry_id)
);

-- Revoked tokens
CREATE TABLE revoked_tokens (
  jti          TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  expires_at   BIGINT NOT NULL,
  revoked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_by   TEXT
);
```

> **Credentials:** Use a dedicated Postgres role for the gateway with only
> `INSERT` + `SELECT` on the audit ledger table. Never grant `UPDATE` or `DELETE`
> on audit rows — these would let an attacker silently erase evidence. The audit
> HMAC secret must be rotated by provisioning a new table name
> (`AUDIT_LEDGER_TABLE`) rather than in-place updates.

### 5.3 Full production docker-compose

```yaml
# Production self-host stack: issuer + gateway + Redis + Postgres
# Replace all placeholder values before deploying.

version: "3.9"

volumes:
  postgres_data:
  redis_data:

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: euno
      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"
      POSTGRES_DB: euno
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U euno"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass "${REDIS_PASSWORD}" --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "127.0.0.1:6379:6379"
    healthcheck:
      test: ["CMD-SHELL", "redis-cli -a ${REDIS_PASSWORD} ping | grep PONG"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  capability-issuer:
    build:
      context: /path/to/euno-platform
      dockerfile: euno-platform/packages/capability-issuer/Dockerfile
    image: euno/capability-issuer:latest
    container_name: euno-issuer
    env_file: ./issuer.env
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379"
    depends_on:
      redis:
        condition: service_healthy
    ports:
      - "3001:3001"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3001/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  tool-gateway:
    build:
      context: /path/to/euno-platform
      dockerfile: euno-platform/packages/tool-gateway/Dockerfile
    image: euno/tool-gateway:latest
    container_name: euno-gateway
    env_file: ./gateway.env
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379"
      AUDIT_LEDGER_PG_URL: "postgresql://euno:${POSTGRES_PASSWORD}@postgres:5432/euno"
    depends_on:
      capability-issuer:
        condition: service_healthy
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    ports:
      - "3002:3002"
      - "127.0.0.1:3003:3003"    # admin port — never expose publicly
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3002/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped
```

Run with:

```bash
export POSTGRES_PASSWORD=$(openssl rand -base64 24)
export REDIS_PASSWORD=$(openssl rand -base64 24)
docker compose -f docker-compose.yml up -d
```

---

## 6. Token issuance reference

### 6.1 Issue a capability token

```bash
# Issue a token for a specific agent
# The Authorization header must carry a caller identity token validated by
# the configured IDENTITY_PROVIDER (DID-bound JWT for IDENTITY_PROVIDER=did).
curl -s -X POST http://localhost:3001/api/v1/issue \
  -H "Authorization: Bearer <caller-identity-token>" \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{
  "agentId": "my-agent",
  "requestedCapabilities": [
    {
      "resource": "read_file",
      "actions": ["call"],
      "conditions": [
        { "type": "pathPattern", "allowedPaths": ["/data/**"] }
      ]
    }
  ]
}
EOF
```

The response body contains:

```jsonc
{
  "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiJ9...",
  "expiresAt": 1747000000,     // unix-seconds
  "tokenId": "jti-xxxxxxxx",
  "capabilities": [...]
}
```

### 6.2 Inspect a token

```bash
npx -y @euno/mcp validate-token <token>
# Prints: issuer DID, agentId, conditions, expiry, and signature status
```

### 6.3 Configure @euno/mcp with a pre-issued token

```jsonc
// claude_desktop_config.json or equivalent
{
  "mcpServers": {
    "my-governed-server": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--enforcer-url", "http://gateway.internal:3002",
        "--enforcer-api-key", "<token-from-step-6-1>",
        "--enforcer-timeout", "5000",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

`@euno/mcp` includes the token as `Authorization: Bearer <token>` on every
`POST /api/v1/enforce` call. The gateway verifies the JWT signature and expiry on
each request. Token expiry is not automatically handled by `@euno/mcp` — re-issue
a fresh JWT from the issuer before the token expires and update the config, then
restart the proxy.

---

## 7. Querying the audit log

Self-hosters with `AUDIT_LEDGER_BACKEND=postgres` have access to the audit query
API on the gateway:

```bash
# Query audit records for a specific agent
curl -s "http://gateway.internal:3002/api/v1/audit/records?agentId=my-agent&limit=50" \
  -H "Authorization: Bearer <token-with-audit-scope>"

# Filter by time range and decision
curl -s "http://gateway.internal:3002/api/v1/audit/records?decision=deny&since=2026-05-11T00:00:00Z" \
  -H "Authorization: Bearer <token-with-audit-scope>"
```

Responses are OCSF API Activity records (class_uid 6003). The query API returns
records as-is — no reshaping. See the OpenAPI spec in `docs/openapi/` for the
full parameter reference.

---

## 8. Admin operations

The admin API is served on `ADMIN_PORT` (default 3003) and is bound to
`ADMIN_HOST` (should be `127.0.0.1` or an in-cluster-only address). See
[`docs/ADMIN_API_CURL_RECIPES.md`](./ADMIN_API_CURL_RECIPES.md) for the full
reference.

```bash
# Kill all sessions for a specific agent
curl -s -X POST "http://localhost:3003/admin/kill-switch/agent/my-agent/kill" \
  -H "X-Admin-Api-Key: <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Revoke a specific token by JTI
curl -s -X POST http://localhost:3003/admin/revoke \
  -H "X-Admin-Api-Key: <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{ "tokenId": "<jti-from-token>", "expiresAt": 1747000000 }'

# Revive an agent after a kill-switch was activated
curl -s -X POST "http://localhost:3003/admin/kill-switch/agent/my-agent/revive" \
  -H "X-Admin-Api-Key: <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

---

## 9. Security checklist for production

Before routing production traffic through a self-hosted gateway, verify every
item in this checklist:

- [ ] **Signing key is HSM-backed.** `SIGNING_PROVIDER` is `azure-keyvault`,
      `aws-kms`, or `gcp-cloudkms`. A local PEM key is not acceptable in production.
- [ ] **Key is non-exportable.** Confirm at the KMS level (not just IAM policy).
      For Azure Managed HSM, follow the non-exportability verification procedure in
      `docs/stage-3-design.md` §1.3.
- [ ] **Admin port is not publicly reachable.** `ADMIN_HOST=127.0.0.1` and the
      admin port (3003) is not in the public-facing load-balancer ingress rules.
- [ ] **`REDIS_CIRCUIT_OPEN_MODE` is set explicitly.** The gateway logs an error
      and defaults to `fail-closed` when this variable is absent. Confirm the
      deployed value matches your operational posture.
- [ ] **Postgres role has no `UPDATE` / `DELETE` on audit tables.** The audit
      ledger is append-only; delete/update grants defeat the tamper-evidence model.
- [ ] **HMAC secret is not stored in the container image.** `AUDIT_LEDGER_HMAC_SECRET`
      must come from your secret manager at runtime, not be baked into the image.
- [ ] **TLS is terminated in front of the gateway.** The services listen on
      plain HTTP internally. Place a TLS-terminating load balancer or reverse proxy
      in front of ports 3002 and 3001 before exposing them over a network you do
      not fully control.
- [ ] **`GATEWAY_AUDIENCE` matches between issuer and gateway.** A mismatch
      means every token is rejected at the `aud` claim check. The error appears in
      the gateway log as `aud mismatch`.
- [ ] **Audit HMAC secret rotation plan is documented.** Rotate by provisioning
      a new `AUDIT_LEDGER_TABLE` name; never `UPDATE` existing audit rows.
- [ ] **Redis TLS is enabled in production.** Use `rediss://` (not `redis://`)
      for `REDIS_URL` to prevent credential exposure in transit.
- [ ] **`EUNO_DEPLOYMENT_TIER=multi-replica` when running more than one gateway
      replica.** Single-replica mode uses in-process state that is not shared across
      pods; call-counter limits and kill-switch state will diverge silently if
      multiple replicas run in single-replica mode.

---

## 10. Upgrading from @euno/mcp local mode

See [`docs/migrating-from-local.md`](./migrating-from-local.md) (Task 18) for
the step-by-step upgrade path, including the manual policy migration and the
interactive `euno-mcp upgrade-to-hosted` command (Task 15) that automates the
config change.

The short version:

1. Deploy this stack (§5.3).
2. Issue a capability token for your agent (§6.1).
3. Change `"enforcer": "local"` to `"enforcer": "http://gateway.internal:3002"` and add
   `"enforcerApiKey": "<token>"` in your MCP host config.
4. Run `euno-mcp validate-token <token>` to confirm the gateway accepts it.
5. Tail gateway logs to confirm enforcement events are landing in Postgres.

The policy YAML format is identical between local mode and the hosted gateway —
no policy rewrite is required.

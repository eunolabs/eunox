# Self-Hosting euno — BYO-GW Guide

> **Target audience:** Platform engineers and security teams running euno
> infrastructure on their own cloud or on-premises.
>
> **Status:** Stage 5 (Enterprise) documentation. Self-hosting is available under the
> [BSL 1.1](../LICENSE) license (non-competing use; the gateway source converts to
> Apache-2.0 four years after each release). Review the license before deploying
> in a competing product.
>
> **Related documents:**
> - [`docs/stage-3-design.md`](./stage-3-design.md) — authoritative Stage 3 architecture decisions
> - [`docs/stage-4-design.md`](./stage-4-design.md) — Stage 4 hosted-identity architecture
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — build and configuration reference
> - [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) — system context and component map
> - [`docs/capability-model.md`](./capability-model.md) — enforcement invariants
> - [`docs/security/minter-threat-model.md`](./security/minter-threat-model.md) — minter threat model
> - [`docs/security/enterprise-federation-threat-model.md`](./security/enterprise-federation-threat-model.md) — Stage 5 enterprise threat model
> - [`docs/migrating-from-local.md`](./migrating-from-local.md) — upgrading from `@euno/mcp` local mode
> - [`docs/issuer-idp-setup.md`](./issuer-idp-setup.md) — IdP wiring recipes (including SCIM §8)
> - [`docs/ADAPTERS.md`](./ADAPTERS.md) — identity and signing adapter reference
> - [`docs/agent-sdk.md`](./agent-sdk.md) — AGT in-process guard SDK reference
> - [`docs/issuer-operator-runbook.md`](./issuer-operator-runbook.md) — operator runbook
> - [`docs/openapi/capability-issuer-discovery.yaml`](./openapi/capability-issuer-discovery.yaml) — discovery endpoint OpenAPI spec

---

## 1. What self-hosting means

Self-hosting means you run **all** of the following infrastructure yourself, using the BSL-licensed images from this repository:

| Component | Package | Purpose |
|---|---|---|
| **Capability Issuer** | `internal/issuer` | Issues signed JWT capability tokens from your identity store and KMS |
| **Tool Gateway** | `internal/gateway` | Enforces capability tokens on every agent tool call |
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
| Evidence export (signed OCSF) | Cloud Enterprise | ✅ — `GET /api/v1/audit/export` (§12.5) |
| On-prem signing key (BYO HSM) | Cloud Enterprise | ✅ |
| SOC2 attestation docs | Cloud Enterprise | ✅ — see §12.13 compliance checklists |
| Cross-chain audit anchor | Cloud Enterprise | ✅ — `AUDIT_LEDGER_BACKEND=per-replica-postgres` (§12.4) |
| Partner DID federation | Cloud Enterprise | ✅ — two-eyes DID registry (§12.2) |
| SCIM 2.0 provisioning | Cloud Enterprise | ✅ — `/scim/v2/` endpoints (§12.3) |
| DB credential issuance | Cloud Enterprise | ✅ — db-token-service (§12.6) |
| Storage-grant issuance | Cloud Enterprise | ✅ — storage-grant-service (§12.7) |
| AGT in-process guard | Cloud Enterprise | ✅ — `createAgtGuard()` (§12.8) |
| Discovery endpoint v1.0.0 | Cloud Enterprise | ✅ — `/.well-known/capability-issuer` (§12.9) |
| Helm chart + air-gap bundle | Cloud Enterprise | ✅ — `k8s/helm/` (§12.10) |

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
[`pkg//policies/filesystem.policy.yaml`](../pkg//policies/filesystem.policy.yaml):

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
      context: /path/to/eunox    # root of the eunox monorepo
      dockerfile: internal/issuer/Dockerfile
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
      context: /path/to/eunox
      dockerfile: internal/gateway/Dockerfile
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
      context: /path/to/eunox
      dockerfile: internal/issuer/Dockerfile
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
      context: /path/to/eunox
      dockerfile: internal/gateway/Dockerfile
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

---

## 11. Stage 4 — hosted identity and manifest templates

Stage 4 ships the **capability issuer** as a first-class component of the
self-host bundle. The issuer handles token minting from real user identities
(Entra ID / AWS Cognito), role-to-capability policy management, and
manifest-template authoring. This section explains how to configure the issuer
in a self-hosted deployment and how it differs from the managed cloud product.

### 11.1 Updated feature matrix

The following rows have changed since Stage 3. Rows not listed here are
unchanged from §2.

| Feature | Cloud (Managed) | Self-host (BSL) |
|---|---|---|
| **Capability issuer** | Managed (multi-tenant) | ✅ BYO single-tenant issuer |
| **Entra ID / AWS Cognito IdP wiring** | Managed | ✅ — configure via env vars |
| **Per-tenant IdP configuration** | Managed | ✅ — `ISSUER_TENANT_IDP_CONFIG_FILE` JSON |
| **Manifest template store** | Cloud Team+ | ✅ BYO Postgres (`ISSUER_DB_URL`) |
| **Admin operator-JWT auth** | Managed JWKS | ✅ BYO JWKS endpoint |
| **SSO via OIDC** | Cloud Team+ | ✅ (single IdP or per-tenant) |
| **API-key minter façade** (`sk-...` → JWT) | ✅ | ❌ — issue tokens directly |

> **BYO-Issuer note:** Self-hosters now run the issuer alongside the gateway.
> The managed minter façade (§2, "The key difference: no managed minter") is
> still absent — self-hosters issue tokens directly via the OIDC token endpoint
> or the `/api/v1/issue` API-key path, depending on their IdP setup.

### 11.2 Issuer configuration reference

The issuer is configured entirely via environment variables validated on startup
by the same `loadConfigOrExit` mechanism used by the gateway. The full schema
is in `pkg//src/config/schema.ts` (`IssuerConfigSchema`).
The table below covers the variables a self-host operator must review before
going to production.

#### 11.2.1 Identity provider (IdP)

| Variable | Default | Notes |
|---|---|---|
| `IDENTITY_PROVIDER` | `azure-ad` | `azure-ad` \| `aws-cognito` \| `gcp-identity` |
| `AZURE_AD_TENANT_ID` | — | Required when `IDENTITY_PROVIDER=azure-ad` |
| `AZURE_AD_CLIENT_ID` | — | Required when `IDENTITY_PROVIDER=azure-ad` |
| `AWS_COGNITO_USER_POOL_ID` | — | Required when `IDENTITY_PROVIDER=aws-cognito` (or set `AWS_COGNITO_ISSUER`) |
| `AWS_COGNITO_CLIENT_ID` | — | Required when `IDENTITY_PROVIDER=aws-cognito` |
| `GCP_IDENTITY_AUDIENCE` | — | Required when `IDENTITY_PROVIDER=gcp-identity` |
| `ISSUER_TENANT_IDP_CONFIG_FILE` | — | Path to per-tenant IdP JSON (§11.3). Hot-reloaded on SIGHUP. |

#### 11.2.2 Token signing key

The issuer signs capability tokens via a cloud KMS. Local file-based keys are
**not supported** — a KMS key is required for all deployments.

| Variable | Default | Notes |
|---|---|---|
| `SIGNING_PROVIDER` | `azure-keyvault` | `azure-keyvault` \| `aws-kms` \| `gcp-cloudkms` |

**Azure Key Vault** (`SIGNING_PROVIDER=azure-keyvault`):

| Variable | Default | Notes |
|---|---|---|
| `AZURE_KEYVAULT_URL` | — | Required. E.g. `https://your-vault.vault.azure.net/` |
| `AZURE_KEYVAULT_KEY_NAME` | `capability-signing-key` | Key name inside the vault. |
| `AZURE_KEYVAULT_KEY_VERSION` | *(latest)* | Pin to a specific key version in production. |
| `AZURE_CREDENTIAL_TYPE` | `default` | `default` \| `managed-identity` \| `client-secret` |

**AWS KMS** (`SIGNING_PROVIDER=aws-kms`):

| Variable | Default | Notes |
|---|---|---|
| `AWS_KMS_KEY_ID` | — | Required. KMS key ARN or ID. |
| `AWS_KMS_REGION` | `us-east-1` | AWS region of the key. |

**GCP Cloud KMS** (`SIGNING_PROVIDER=gcp-cloudkms`):

| Variable | Default | Notes |
|---|---|---|
| `GCP_PROJECT_ID` | — | Required. GCP project containing the key ring. |
| `GCP_KEYRING_ID` | — | Required. KMS key ring ID. |
| `GCP_CRYPTOKEY_ID` | — | Required. KMS crypto key ID. |
| `GCP_CRYPTOKEY_VERSION` | *(primary)* | Pin to a specific key version in production. |
| `GCP_LOCATION_ID` | `us-central1` | KMS location. |

#### 11.2.3 Manifest template store (Postgres)

| Variable | Default | Notes |
|---|---|---|
| `ISSUER_DB_URL` | — | `postgres://…` DSN. When unset, template store is disabled (direct-manifest mode only). |
| `ISSUER_DB_SCHEMA` | `public` | Postgres schema for template tables. Must be a valid SQL identifier. |
| `ISSUER_DB_SCHEMA_INIT` | `false` | Set to `true` on first run to create tables automatically. |

#### 11.2.4 Admin API authentication

Operator endpoints (`PUT /api/v1/admin/role-policy`, `/api/v1/admin/templates/*`) are
protected by one of two auth mechanisms — configure exactly one:

| Variable | Default | Notes |
|---|---|---|
| `ISSUER_ADMIN_JWKS_URI` | — | URL of your operator JWKS endpoint. Preferred for production. |
| `ISSUER_ADMIN_JWT_AUDIENCE` | — | Required when `ISSUER_ADMIN_JWKS_URI` is set. |
| `ISSUER_ADMIN_JWT_ISSUER` | — | Optional issuer check on operator JWTs. |
| `ISSUER_ADMIN_API_KEY` | — | Shared-secret fallback. Must be ≥ 32 chars and not equal to `dev-issuer-admin-key` in production. |

> In production, `NODE_ENV=production` **requires** either
> `ISSUER_ADMIN_JWKS_URI` or a strong `ISSUER_ADMIN_API_KEY`. The issuer
> refuses to start if neither is set.

#### 11.2.5 Rate limiting and other settings

| Variable | Default | Notes |
|---|---|---|
| `ISSUANCE_RATE_LIMIT_ENABLED` | `true` | Set to `false` only in development. |
| `ISSUANCE_RATE_LIMIT_MAX` | `60` | Max issuances per `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS` per `(tenantId, userId, agentId)` tuple. |
| `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS` | `60` | Tumbling window (seconds) for the per-user rate limiter. |
| `ISSUER_REGION` | — | Logical region tag stamped into issued tokens (`region` claim). |
| `DEFAULT_TOKEN_TTL` | `900` | Default capability-token lifetime (seconds). Can be overridden per-request. |
| `EUNO_TELEMETRY` | *(unset)* | Set to `1` to enable opt-in issuer telemetry (per-tenant 5-min flush to `EUNO_TELEMETRY_URL`). |

### 11.3 Per-tenant IdP configuration

When you serve multiple tenants from a single issuer instance, each tenant can
authenticate against its own IdP. The `ISSUER_TENANT_IDP_CONFIG_FILE` variable
points to a JSON file that maps tenant IDs to IdP configurations.

#### 11.3.1 File format

```json
{
  "tenants": {
    "acme-corp": {
      "provider": "azure-ad",
      "azureAD": {
        "tenantId": "acme.onmicrosoft.com",
        "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "clientSecret": "<optional-for-graph-access>"
      }
    },
    "beta-inc": {
      "provider": "aws-cognito",
      "awsCognito": {
        "region": "us-east-1",
        "userPoolId": "us-east-1_XXXXXXXXX",
        "clientId": "XXXXXXXXXXXXXXXXXXXXXXXXXX"
      }
    }
  }
}
```

The top-level `tenants` object is keyed by logical `tenantId` values (the value
that appears in issued tokens). Each entry must specify:
- `provider`: one of `azure-ad`, `aws-cognito`, or `gcp-identity`
- A provider-specific sub-object: `azureAD`, `awsCognito`, or `gcpIdentity`

When a request carries a `tenantId` not found in the file, the issuer falls back
to the global `IDENTITY_PROVIDER` + provider-specific variables. The file is
hot-reloaded on `SIGHUP` — no restart required after adding a new tenant.

#### 11.3.2 Hot-reload

```bash
# After updating the JSON file:
kill -HUP $(cat /var/run/euno-issuer.pid)
# Issuer logs: "SIGHUP received: reloading tenant IdP config"
```

### 11.4 Manifest template seed data

Manifest templates are stored in Postgres and managed via the admin API.
On a fresh deployment, seed your initial templates using the admin API:

```bash
# Create a template (requires ISSUER_ADMIN_API_KEY or operator JWT)
curl -X POST https://issuer.internal:4000/api/v1/admin/templates \
  -H "Authorization: Bearer <operator-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "read-only-analyst",
    "description": "Standard read-only analyst policy for all agents",
    "ownerTenantId": "acme-corp",
    "manifest": {
      "schemaVersion": "1.0.0",
      "capabilities": [
        {
          "action": "call",
          "resource": "res://data/reports/**",
          "conditions": [{ "type": "maxCallsPerDay", "limit": 200 }]
        }
      ]
    },
    "bindings": []
  }'
```

The template store supports multiple versions per template (`POST /…/versions`).
The issuer's hot path automatically resolves the latest active version for any
`(tenantId, agentId, role)` tuple that has a binding.

If you prefer to seed templates programmatically at startup, write a migration
script that calls the admin API before the issuer starts serving traffic.

#### 11.4.1 Template binding format

```json
{
  "agentId": "agent-abc123",
  "role": "analyst",
  "ownerTenantId": "acme-corp",
  "version": 1
}
```

Bindings link a `(tenantId, agentId, role)` tuple to a specific template
version. Use `version: null` to always follow the latest version (useful during
initial rollout; pin to a specific version for production stability).

### 11.5 Signing-key trade-offs for self-hosters

The issuer delegates all token signing to a cloud KMS. Local file-based keys
are **not supported** — all deployments require a KMS key. The choice of KMS
provider affects your blast radius if the key-management plane is compromised.

| Mode | `SIGNING_PROVIDER` | Use case |
|---|---|---|
| **Azure Key Vault** | `azure-keyvault` | Entra ID deployments; managed identity is the preferred credential |
| **AWS KMS** | `aws-kms` | Cognito / AWS-native deployments; IAM role for credentials |
| **GCP Cloud KMS** | `gcp-cloudkms` | GCP-native deployments; ADC or service-account key file |

> **Full trade-off analysis:** See
> [`docs/security/issuer-identity-threat-model.md §7`](./security/issuer-identity-threat-model.md)
> for the complete security assessment of each mode, including blast radius,
> key rotation procedure, and recommendations for multi-region deployments.

**Quick setup — AWS KMS (single-tenant example):**

```env
SIGNING_PROVIDER=aws-kms
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/mrk-...
AWS_KMS_REGION=us-east-1
# IAM role attached to the ECS/EKS task provides credentials automatically.
```

**Quick setup — Azure Key Vault (managed identity):**

```env
SIGNING_PROVIDER=azure-keyvault
AZURE_KEYVAULT_URL=https://your-vault.vault.azure.net/
AZURE_KEYVAULT_KEY_NAME=capability-signing-key
AZURE_CREDENTIAL_TYPE=managed-identity
```

**Recovery procedure for key loss or rotation:**

1. Create a new key version (or a new key) in your KMS.
2. Update `AWS_KMS_KEY_ID` / `AZURE_KEYVAULT_KEY_NAME` + `AZURE_KEYVAULT_KEY_VERSION` / `GCP_CRYPTOKEY_VERSION` and restart the issuer. The issuer publishes the new public key at `GET /.well-known/jwks.json` automatically within one startup cycle.
3. All tokens signed by the old key become unverifiable if the old key version is disabled or deleted. Coordinate a key rotation window with your token TTL (`DEFAULT_TOKEN_TTL`) to minimise disruption.
4. If using a Postgres token store (`ISSUER_DB_URL`), call `POST /api/v1/admin/revoke-all` with the old key ID to update the revocation ledger before decommissioning the key.

### 11.6 Admin operator-JWT setup

Operator JWTs authenticate admin API calls (`PUT /api/v1/admin/role-policy`,
`/api/v1/admin/templates/*`, etc.). This is the recommended auth mechanism for
production; the shared-secret `ISSUER_ADMIN_API_KEY` fallback is available for
bootstrapping or non-production environments.

#### 11.6.1 Entra ID (Azure AD) — operator app registration

1. Create a separate **app registration** for the issuer admin (distinct from
   the user-facing app in §2 of `docs/issuer-idp-setup.md`).
2. Expose an **App Role** named `IssuerAdmin` with `allowedMemberTypes: Application`.
3. Grant the operator tool's managed identity (or client credentials) the
   `IssuerAdmin` role.
4. Set:
   ```env
   ISSUER_ADMIN_JWKS_URI=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
   ISSUER_ADMIN_JWT_AUDIENCE=api://<app-id-of-admin-registration>
   ISSUER_ADMIN_JWT_ISSUER=https://sts.windows.net/<tenant-id>/
   ```

#### 11.6.2 AWS Cognito — machine-to-machine credentials

1. Create a Cognito User Pool App Client with `client_credentials` grant.
2. Define a **resource server** scope (e.g. `issuer-admin/write`).
3. Set:
   ```env
   ISSUER_ADMIN_JWKS_URI=https://cognito-idp.<region>.amazonaws.com/<user-pool-id>/.well-known/jwks.json
   ISSUER_ADMIN_JWT_AUDIENCE=<app-client-id>
   ISSUER_ADMIN_JWT_ISSUER=https://cognito-idp.<region>.amazonaws.com/<user-pool-id>
   ```

#### 11.6.3 Custom / self-hosted JWKS

Any JWKS-compliant endpoint works. The issuer fetches the JWKS at startup and
on a 5-minute background refresh. Operator JWTs are verified against the key
set using the standard RS256 / ES256 algorithms.

### 11.7 IdP wiring recipes

#### 11.7.1 AWS Cognito (single-tenant, global IdP)

```env
IDENTITY_PROVIDER=aws-cognito
AWS_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
AWS_COGNITO_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXX

# Signing key (AWS KMS — matches the Cognito deployment)
SIGNING_PROVIDER=aws-kms
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/mrk-...
AWS_KMS_REGION=us-east-1

# Admin auth (shared-secret for bootstrapping; replace with JWKS in production)
ISSUER_ADMIN_API_KEY=<random-32+-char-string>
NODE_ENV=production
```

**Cognito group → role mapping** is configured via the role-policy admin API
(`PUT /api/v1/admin/role-policy`). Set `ISSUER_ADMIN_API_KEY` to bootstrap,
then push a policy:

```bash
curl -X PUT https://issuer.internal:4000/api/v1/admin/role-policy \
  -H "X-Admin-Key: <ISSUER_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": {
      "Administrators": ["admin", "read", "write"],
      "Analysts": ["read"]
    }
  }'
```

#### 11.7.2 Entra ID (Azure AD) (single-tenant, global IdP)

```env
IDENTITY_PROVIDER=azure-ad
AZURE_AD_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_AD_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Signing key (Azure Key Vault — matches the Entra ID deployment)
SIGNING_PROVIDER=azure-keyvault
AZURE_KEYVAULT_URL=https://your-vault.vault.azure.net/
AZURE_KEYVAULT_KEY_NAME=capability-signing-key
AZURE_CREDENTIAL_TYPE=managed-identity

# Admin auth via Entra app roles (see §11.6.1)
ISSUER_ADMIN_JWKS_URI=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
ISSUER_ADMIN_JWT_AUDIENCE=api://<admin-app-id>
ISSUER_ADMIN_JWT_ISSUER=https://sts.windows.net/<tenant-id>/
NODE_ENV=production
```

**Entra App Role → euno role mapping:**

```bash
# Push a role-policy that maps Entra App Roles to euno capability roles.
curl -X PUT https://issuer.internal:4000/api/v1/admin/role-policy \
  -H "Authorization: Bearer <operator-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": {
      "Agent.Write": ["write", "read"],
      "Agent.Read": ["read"]
    }
  }'
```

### 11.8 Full Stage-4 docker-compose additions

Add the following services to the base docker-compose from §4.4 / §5.3 to
bring up the complete Stage-4 stack:

```yaml
services:
  capability-issuer:
    image: ghcr.io/euno/capability-issuer:stage4
    depends_on:
      - db
      - mock-oidc      # Remove in production; use real IdP
    environment:
      IDENTITY_PROVIDER: aws-cognito
      AWS_COGNITO_USER_POOL_ID: "${AWS_COGNITO_USER_POOL_ID}"
      AWS_COGNITO_CLIENT_ID: "${AWS_COGNITO_CLIENT_ID}"
      SIGNING_PROVIDER: aws-kms
      AWS_KMS_KEY_ID: "${AWS_KMS_KEY_ID}"
      AWS_KMS_REGION: "${AWS_REGION:-us-east-1}"
      ISSUER_DB_URL: "postgres://euno:euno@db:5432/euno"
      ISSUER_DB_SCHEMA_INIT: "true"
      ISSUER_ADMIN_API_KEY: "${ISSUER_ADMIN_API_KEY}"
      NODE_ENV: production
      PORT: "4000"
    ports:
      - "4000:4000"

  # Minimal OIDC mock for local development / smoke tests.
  # Remove from production deployments and replace with a real IdP.
  mock-oidc:
    image: ghcr.io/euno/mock-oidc:stage4
    environment:
      PORT: "4100"
    ports:
      - "4100:4100"
```

See `infra/docker-compose.yml` (smoke profile) for the full working example
including gateway wiring and the seed policy bind-mount.

### 11.9 Stage-4 security checklist

In addition to the items in §9, review the following before going to production:

- [ ] **Signing key**: KMS-backed (`SIGNING_PROVIDER=azure-keyvault|aws-kms|gcp-cloudkms`) required for all deployments. Confirm the KMS key ARN/URL is pinned to a specific version in production.
- [ ] **Admin auth**: `ISSUER_ADMIN_JWKS_URI` configured (not just `ISSUER_ADMIN_API_KEY`) for operator access.
- [ ] **IdP hygiene**: CA pinning or JWKS cache validation enabled on the IdP connection (see `docs/issuer-idp-setup.md §8`).
- [ ] **Tenant isolation**: If running multi-tenant, confirm `ISSUER_TENANT_IDP_CONFIG_FILE` maps each tenant to its own IdP entry. Shared IdP requires per-tenant role-policy enforcement.
- [ ] **Template versioning**: Pin active template bindings to specific versions once stable. Avoid `version: null` in production.
- [ ] **Role-policy audit**: Review the OCSF audit log after every `PUT /api/v1/admin/role-policy` call. The issuer logs `operatorId`, timestamp, and the full policy diff.
- [ ] **SIGHUP tested**: Confirm hot-reload works for your IdP config and role policy (`kill -HUP <pid>`) before relying on it for zero-downtime updates.
- [ ] **Full threat model**: `docs/security/issuer-identity-threat-model.md` reviewed and sign-off obtained from engineer + security.


---

## 12. Stage 5 — Enterprise Deployment

Stage 5 graduates euno from an enterprise-IdP-integrated issuance platform
(Stage 4) to a **compliance-signed, fully air-gappable enterprise deployment**
targeting the CISO and external auditor as primary buyers. Four previously
quarantined packages are promoted to stable (`1.0.0`), six capabilities are
added to existing packages, and all Stage-5 features ship in both the hosted
product and the self-host bundle at parity.

> **Key documents for this section**
> - [`docs/stage5executionplan.md`](./stage5executionplan.md) — full Stage-5 execution plan (Tasks 0–13)
> - [`docs/security/enterprise-federation-threat-model.md`](./security/enterprise-federation-threat-model.md) — approved threat model (BLOCKING gate for Tasks 3, 6, 10)
> - [`docs/issuer-idp-setup.md`](./issuer-idp-setup.md) §8 — SCIM 2.0 provisioning (Okta, Entra ID, Ping Identity)
> - [`docs/ADAPTERS.md`](./ADAPTERS.md) §"Partner Federation" — DID adapter reference
> - [`docs/agent-sdk.md`](./agent-sdk.md) §"AGT in-process guard" — defense-in-depth SDK guide
> - [`docs/openapi/capability-issuer-discovery.yaml`](./openapi/capability-issuer-discovery.yaml) — discovery v1.0.0 contract
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — Stage-5 on-prem deployment and Helm guide

### 12.1 Updated service topology

The Stage-5 self-host stack adds four services to the Stage-4 base:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Your infrastructure (self-hosted — Stage 5 full stack)                      │
│                                                                              │
│  ┌────────────────┐ sign ┌─────────────────────────────────────────────┐     │
│  │  Capability    │────► │  KMS / signing key                          │     │
│  │  Issuer :3001  │      │  (Azure KV, AWS KMS, GCP KMS)               │     │
│  │                │      └─────────────────────────────────────────────┘     │
│  │  OIDC / SCIM   │                                                          │
│  │  /scim/v2/*    │ ◄──  Okta / Entra ID / Ping Identity (SCIM push)         │
│  │  /.well-known/ │                                                          │
│  │  capability-   │      ┌─────────────────────────────────────────────┐     │
│  │  issuer        │      │  Partner Issuer (remote org)                │     │
│  └───────┬────────┘      │  did:web / did:ion                          │     │
│          │ JWT            │  issues tokens from partner signing key     │     │
│          │                └──────────────────┬──────────────────────────┘    │
│          ▼                                   │ partner JWT                   │
│  ┌───────────────────┐                       │                               │
│  │  @euno/mcp        │── JWT ──────────────► │                               │
│  │  (agent proxy)    │                       ▼                               │
│  │  + AgtGuard       │             ┌─────────────────────────────────────┐   │
│  │  (in-process)     │             │  Tool Gateway :3002                 │   │
│  └───────────────────┘             │                                     │   │
│                                    │  POST /api/v1/enforce               │   │
│                                    │  GET  /api/v1/audit/records         │   │
│                                    │  GET  /api/v1/audit/export  (new)   │   │
│                                    │  GET  /api/v1/audit/chain-proof(new)│   │
│                                    │  POST /admin/partner-dids/proposals │   │
│                                    │  POST /admin/kill-switch/...        │   │
│                                    └──────────────┬──────────────────────┘   │
│                                                   │  R/W                     │
│           ┌───────────────────────────────────────┤                          │
│           │                                       │                          │
│  ┌────────▼──────┐    ┌───────────┐    ┌──────────▼──────┐                  │
│  │   Redis       │    │  Postgres │    │  Posture         │                  │
│  │  (>= 6.2)     │    │  (>= 14)  │    │  Emitter         │                  │
│  │  revocation   │    │  audit    │    │  (OCSF export    │                  │
│  │  kill-switch  │    │  ledger   │    │   durable queue) │                  │
│  │  partner-DID  │    │  scim     │    └──────────────────┘                  │
│  │  circuit-brk  │    │  tables   │                                          │
│  └───────────────┘    └───────────┘                                          │
│                                                                              │
│  ┌────────────────────┐   ┌──────────────────────┐                           │
│  │  db-token-service  │   │ storage-grant-service │                          │
│  │  :5050             │   │ :5051                 │                          │
│  │  POST /exchange    │   │ POST /grant           │                          │
│  │  (CAP token ->     │   │ (CAP token ->         │                          │
│  │   DB credentials)  │   │  presigned URL/SAS)   │                          │
│  └────────────────────┘   └──────────────────────┘                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Updated service list

| Service | Package | Stage | Purpose |
|---|---|---|---|
| **Capability Issuer** | `capability-issuer` | 4+ | Issues JWT capability tokens; Stage-5 adds SCIM endpoints, OIDC discovery v1.0.0 |
| **Tool Gateway** | `tool-gateway` | 3+ | Enforces capability tokens; Stage-5 adds partner-DID verification, audit-export endpoint, chain-proof endpoint |
| **DB Token Service** | `db-token-service` | **5** | Exchanges a capability token for short-lived scoped database credentials |
| **Storage Grant Service** | `storage-grant-service` | **5** | Exchanges a capability token for short-lived presigned URLs or SAS tokens |
| **Posture Emitter** | `posture-emitter` | **5** | Durable WAL-queue that fans OCSF evidence records to compliance sinks |
| **Partner Issuer Sim** | `partner-issuer-sim` | **5** | Reference simulator for partner-org DID-backed issuers (integration harness) |
| **Redis** | BYO (>= 6.2) | 3+ | Revocation, kill-switch, call-counter, partner-DID circuit-breaker |
| **Postgres** | BYO (>= 14) | 3+ | Audit ledger, kill-switch persistence, SCIM tables (`scim_users`, `scim_groups`, `scim_group_members`) |
| **KMS** | BYO | 3+ | Signs capability tokens (issuer) and audit evidence (gateway) |

---

### 12.2 Partner DID federation

> **Threat model gate:** `docs/security/enterprise-federation-threat-model.md`
> must be approved before any partner-federation code or configuration merges
> to production. See §1 and §2 of that document for partner-DID-compromise and
> DID-document-spoofing mitigations.
>
> **Reference:** `docs/ADAPTERS.md` §"Partner Federation"; Stage-5 Task 3.

Partner federation lets a remote organization issue capability tokens from
their own W3C DID-backed signing key. The euno gateway accepts and
cryptographically verifies those tokens without sharing key material.

#### 12.2.1 How it works

1. The partner operator registers their DID with your gateway via the admin
   API's two-eyes approval workflow.
2. When the gateway receives a token whose `iss` claim is a DID, it resolves
   the DID document (via `did:web`, `did:ion`, or `did:key`), extracts the
   public key, and verifies the JWT signature.
3. A per-DID `RedisCircuitBreaker` protects against slow or unreachable partner
   DID resolvers — the circuit opens after N failures and forces a cached
   decision until the cooldown elapses.

#### 12.2.2 Gateway configuration reference

| Variable | Default | Description |
|---|---|---|
| `PARTNER_DID_REGISTRY_REQUIRED` | `true` in production | When `true`, `TRUSTED_PARTNER_DIDS` is a startup error — use the two-eyes registry. |
| `TRUSTED_PARTNER_DIDS` | — | Comma-separated DID allowlist (dev / bootstrap only; blocked in production). |
| `PARTNER_DID_CACHE_TTL_SECONDS` | `300` | Positive-resolution DID cache TTL (seconds). |
| `PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS` | `30` | Negative-resolution (NXDID) cache TTL (seconds). |
| `PARTNER_DID_REQUIRE_PIN` | `false` | When `true`, every partner DID registration must include a pin attestation. |
| `PARTNER_DID_CB_FAILURE_THRESHOLD` | `5` | Failures within `PARTNER_DID_CB_WINDOW_SECONDS` that open the circuit breaker. |
| `PARTNER_DID_CB_WINDOW_SECONDS` | `60` | Sliding window (seconds) for circuit-breaker failure counting. |
| `PARTNER_DID_CB_COOLDOWN_SECONDS` | `120` | Cooldown (seconds) before the circuit breaker enters half-open. |
| `PARTNER_ISSUER_DISCOVERY_URL` | — | URL of a partner `/.well-known/capability-issuer` document. When set, auto-seeds the partner DID at startup (bypasses two-eyes — dev/staging only). |

#### 12.2.3 Registering a partner DID (production workflow)

```bash
DID="did:web:partner.example.com"

# Step 1 — First-eye submits a proposal
curl -X POST https://gateway.internal:3003/admin/partner-dids/proposals \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID"'","note":"Partner Acme Corp onboarding"}'
# Returns: { "proposalId": "prop_xxx", "status": "pending" }

# Step 2 — Second-eye approves (different admin credential)
curl -X POST https://gateway.internal:3003/admin/partner-dids/proposals/prop_xxx/approve \
  -H "X-Admin-Api-Key: <SECOND_ADMIN_API_KEY>"
# Returns: { "did": "did:web:partner.example.com", "status": "active" }
```

For pin attestation (recommended in production):

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/proposals \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:web:partner.example.com",
    "pinAttestation": "<base64-sha256-of-did-document-public-key>",
    "note": "Pinned attestation verified out-of-band 2026-05-19"
  }'
```

#### 12.2.4 DID resolver configuration for air-gapped deployments

| Variable | Default | Description |
|---|---|---|
| `ION_RESOLVER_URL` | `https://ion.msidentity.com/api/v1.0/identifiers` | Override for a self-hosted ION node or open-source ION sidecar. |
| `DID_WEB_ALLOW_HTTP_FOR_HOSTS` | — | Hostnames where `did:web` may resolve over plain HTTP (development only). |

For fully air-gapped deployments run the open-source
[ION](https://github.com/decentralized-identity/ion) sidecar and set
`ION_RESOLVER_URL=http://ion-sidecar:3000/identifiers`.

See `docs/issuer-idp-setup.md` §"DID-based partner issuers" for the full
`did:ion` configuration recipe.

#### 12.2.5 Prometheus circuit-breaker metrics

```
euno_partner_did_circuit_breaker_state{did="...",state="open|closed|half-open"} 1
```

Alert on `euno_partner_did_circuit_breaker_state{state="open"} == 1` to
detect a partner resolver outage within minutes.

---

### 12.3 SCIM 2.0 provisioning

> **Threat model gate:** `docs/security/enterprise-federation-threat-model.md`
> §§3–4 ("SCIM bearer token exposure" and "SCIM privilege escalation") must be
> reviewed before enabling SCIM in production.
>
> **Reference:** `docs/issuer-idp-setup.md` §8; Stage-5 Task 10.

SCIM 2.0 provisioning lets enterprise identity teams push users and group
memberships directly from **Okta**, **Microsoft Entra ID**, or **Ping
Identity** to the capability issuer, eliminating manual role assignment.

#### 12.3.1 How it works

When `ISSUER_SCIM_BEARER_TOKEN` is set, the issuer mounts SCIM v2 endpoints
at `/scim/v2/`. The enterprise IdP pushes user and group lifecycle events
(CREATE / UPDATE / DELETE) to these endpoints. At issuance time
`IssueController` queries the SCIM tables for the authenticating user's group
memberships and merges them with the IdP-provided roles. SCIM groups are the
authoritative authorization model and take precedence on conflict.

If the SCIM DB lookup fails (database outage), the issuer falls back to
IdP-only roles (fail-open for service continuity — see §12.13.3 for
hardening options).

#### 12.3.2 Configuration

```env
# Required — minimum 32 characters; rotate immediately on exposure
ISSUER_SCIM_BEARER_TOKEN=<at-least-32-chars-random-secret>

# Optional — JSON mapping SCIM group displayName -> issuer role key
ISSUER_SCIM_GROUP_ROLE_MAP='{"SalesTeam":"sales","EngineeringTeam":"engineer"}'

# Required — SCIM data stored in Postgres alongside existing issuer tables
ISSUER_DB_URL=postgres://euno:euno@db:5432/euno
ISSUER_DB_SCHEMA_INIT=true   # creates SCIM tables on first run
```

#### 12.3.3 SCIM endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scim/v2/Users` | Provision a new user |
| `GET` | `/scim/v2/Users` | List users (`?filter=`, `?count=`, `?startIndex=`) |
| `GET` | `/scim/v2/Users/:id` | Get user by SCIM ID |
| `PUT` | `/scim/v2/Users/:id` | Replace user (idempotent) |
| `PATCH` | `/scim/v2/Users/:id` | Update attributes or active status |
| `DELETE` | `/scim/v2/Users/:id` | Deprovision user (soft-delete) |
| `POST` | `/scim/v2/Groups` | Provision a new group |
| `GET` | `/scim/v2/Groups` | List groups |
| `GET` | `/scim/v2/Groups/:id` | Get group by SCIM ID |
| `PUT` | `/scim/v2/Groups/:id` | Replace group (full membership; idempotent) |
| `PATCH` | `/scim/v2/Groups/:id` | Update membership delta |
| `DELETE` | `/scim/v2/Groups/:id` | Remove group |

All endpoints require `Authorization: Bearer <ISSUER_SCIM_BEARER_TOKEN>`.
Wrong token returns `401 WWW-Authenticate: Bearer realm="SCIM"`.

For IdP setup recipes (Okta, Entra ID, Ping Identity SCIM configuration
walkthroughs), see `docs/issuer-idp-setup.md` §8.

#### 12.3.4 Privilege escalation guard

The `ISSUER_SCIM_GROUP_ROLE_MAP` must not map any SCIM group to the `operator`
role without a recorded two-engineer sign-off. See
`docs/security/enterprise-federation-threat-model.md` §"SCIM privilege
escalation" for the full treatment.

---

### 12.4 Cross-chain audit anchor

> **Reference:** `docs/issuer-operator-runbook.md` §"Cross-chain anchor";
> `docs/runbooks/ledger-hmac-rotation.md`; Stage-5 Task 5.

The cross-chain anchor binds per-replica audit chains together with a periodic
Merkle commitment stored in S3 Object-Lock (or Azure Confidential Ledger). An
attacker who forges signed evidence records (requires KMS key compromise)
cannot conceal the tampering once the S3 commitment is checked against the
live chain.

#### 12.4.1 Configuration

```env
# Enable per-replica audit chains
AUDIT_LEDGER_BACKEND=per-replica-postgres
AUDIT_LEDGER_PG_URL=postgres://euno_audit:secret@db:5432/euno
AUDIT_LEDGER_HMAC_SECRET=<64-hex-chars from openssl rand -hex 32>
AUDIT_LEDGER_RUN_MIGRATIONS=true       # single-replica / dev only

# Cross-chain commitment interval (default 60 000 ms = 1 minute)
AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS=60000

# S3 Object-Lock bucket for external Merkle anchoring
AUDIT_LEDGER_S3_BUCKET=my-audit-anchor-bucket
AUDIT_LEDGER_S3_PREFIX=audit-anchor/
AUDIT_LEDGER_ANCHOR_INTERVAL=1000      # rows between S3 anchor writes
```

#### 12.4.2 Azure Confidential Ledger alternative

```env
AUDIT_LEDGER_BACKEND=acl
AUDIT_LEDGER_ACL_ENDPOINT=https://<name>.confidentialledger.azure.com
# Auth via DefaultAzureCredential (workload identity, managed identity,
# or AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET).
```

> **Dependency note:** The gateway dynamically requires
> `@azure-rest/confidential-ledger` and `@azure/identity` when
> `AUDIT_LEDGER_BACKEND=acl`. Both must be present in your deployment image.

#### 12.4.3 Verifying chain integrity offline

```bash
# Fetch chain-proof records for a time window
curl -s "https://gateway.internal:3002/api/v1/audit/chain-proof" \
  "?since=2026-05-01T00:00:00Z&until=2026-06-01T00:00:00Z" \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" | jq .

# Response:
# {
#   "commits": [ /* SignedCrossChainCommitment[] */ ],
#   "chainHead": "<latest-commitment-hash>"
# }
```

Verify `chainHead` against the S3 Object-Lock anchors to detect DB-level
tampering between checkpoints. For HMAC rotation procedure see
`docs/runbooks/ledger-hmac-rotation.md`.

---

### 12.5 SOC2 audit-trail export

> **Threat model gate:** `docs/security/enterprise-federation-threat-model.md`
> §"SOC2 export endpoint exposure" must be reviewed before enabling the export
> endpoint.
>
> **Reference:** `docs/security/soc2-mapping.md`; Stage-5 Task 6.

The `GET /api/v1/audit/export` endpoint returns a paginated, cursor-based OCSF
evidence bundle that a compliance team can hand directly to an auditor. Every
record is signed with the gateway's KMS key; offline verification uses the
issuer's published JWKS.

#### 12.5.1 Export endpoint

```bash
# First page — logical access controls
curl -s "https://gateway.internal:3002/api/v1/audit/export?scope=soc2-cc6" \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" | jq .

# Response:
# {
#   "cursor": "<opaque-base64>",   -- expires after 24 h
#   "records": [ /* SignedAuditEvidence[] */ ],
#   "verificationUri": "/.well-known/jwks.json"
# }

# Subsequent page
curl -s "https://gateway.internal:3002/api/v1/audit/export?cursor=<cursor>" \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" | jq .
```

| Parameter | Values | Description |
|---|---|---|
| `scope` | `soc2-cc6`, `soc2-cc7`, `all` | `cc6` = logical access controls; `cc7` = system operations. |
| `cursor` | opaque string | Pagination cursor from previous response. Expires 24 h after issue. |
| `pageSize` | 1–1000 | Max records per page (default 100). |

#### 12.5.2 Offline evidence verification

```bash
# Verify an evidenceJwt field against the issuer JWKS
node -e "
  const { createRemoteJWKSet, jwtVerify } = require('jose');
  const jwks = createRemoteJWKSet(
    new URL('https://issuer.internal:3001/.well-known/jwks.json'));
  jwtVerify(process.env.EVIDENCE_JWT, jwks)
    .then(r => console.log('VALID', r.payload))
    .catch(e => { console.error('INVALID', e.message); process.exit(1); });
"
```

See `docs/security/soc2-mapping.md` for the full OCSF `class_uid` to SOC2
control mapping and the auditor-facing export procedure.

#### 12.5.3 Posture emitter wiring

```env
POSTURE_EMITTER_ENABLED=true
POSTURE_EMITTER_PLUGINS=durable         # SQLite WAL queue
POSTURE_DURABLE_QUEUE_PATH=/var/lib/euno/posture.db  # persistent volume path
```

For HA (multi-replica) deployments use a Redis-stream queue drainer. See
`docs/DEPLOYMENT.md` §"Posture-emitter queue topology for HA issuers" for the
full HA topology diagram.

---

### 12.6 DB Token Service

> **Reference:** `internal/db-token-service/`; Stage-5 Task 7.
> **Status:** GA (v1.0.0)

The `db-token-service` exchanges a capability token for short-lived scoped
database IAM credentials. Credential TTL is bounded by the capability token
TTL and cannot outlive the capability that authorized it.

#### 12.6.1 Configuration

```env
# Service identity
PORT=5050
ISSUER_DID=did:web:capability-issuer.example.com
ISSUER_JWKS_URI=https://capability-issuer.example.com/.well-known/jwks.json
GATEWAY_AUDIENCE=tool-gateway

# DB credential minting
DB_TOKENS_ENABLED=true
DB_TOKEN_MAX_TTL_SECONDS=900        # max credential TTL; must be <= capability token TTL
DB_INSTANCES_FILE=/app/config/db-instances.json
DB_USERNAME_POLICY_FILE=/app/config/db-usernames.json

# Cloud IAM (set one block for your provider)
# AWS RDS IAM
AWS_DB_TOKEN_ROLE_ARN=arn:aws:iam::123456789012:role/euno-db-token-role
# Azure SQL AAD — set AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET or use workload identity
```

**`db-instances.json` format (operator allow-list):**

```json
[
  {
    "id": "salesserver",
    "provider": "azure-sql",
    "host": "salesserver.database.windows.net",
    "port": 1433,
    "databases": ["salesdb"]
  }
]
```

**`db-usernames.json` format (role → DB username policy):**

```json
{
  "default": {},
  "dbUsernamesByRole": {
    "DataAnalyst": "euno_readonly",
    "DBAdmin": "euno_readwrite"
  }
}
```

#### 12.6.2 Token exchange

```bash
curl -X POST https://db-token-service.internal:5050/api/v1/db-tokens \
  -H "Authorization: Bearer <capability-token>" \
  -H "Content-Type: application/json" \
  -d '{ "agentId": "my-agent" }'

# Response:
# {
#   "credentials": [
#     {
#       "provider": "azure-sql",
#       "instanceId": "salesserver",
#       "database": "salesdb",
#       "username": "euno_readonly",
#       "token": "<short-lived-AAD-access-token>",
#       "expiresAt": "2026-05-19T06:15:00Z"
#     }
#   ]
# }
```

#### 12.6.3 Operational endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness — always returns `{ status: "healthy" }` |
| `GET /health/ready` | Readiness — 503 when `DB_TOKENS_ENABLED=false` or no minters configured |
| `GET /.well-known/db-token-service` | Service metadata (issuerDid, audience, endpoints) |

> **Blast radius note:** A stolen DB credential grants access only to the
> exact DB instance and user listed in the capability constraint. The credential
> expires at or before the capability token TTL. All DB access is logged at
> the database layer. See `docs/security/enterprise-federation-threat-model.md`
> §"DB credential blast radius" for the full analysis.

---

### 12.7 Storage Grant Service

> **Reference:** `internal/storage-grant-service/`; Stage-5 Task 7.
> **Status:** GA (v1.0.0)

The `storage-grant-service` exchanges a capability token for short-lived
presigned URLs (AWS S3 / GCP Cloud Storage) or SAS tokens (Azure Blob).
The grant is scoped to the exact bucket or container declared in the capability
constraint.

#### 12.7.1 Configuration

```env
# Service identity
PORT=5051
ISSUER_DID=did:web:capability-issuer.example.com
ISSUER_JWKS_URI=https://capability-issuer.example.com/.well-known/jwks.json
GATEWAY_AUDIENCE=tool-gateway

# Storage grant minting
STORAGE_GRANTS_ENABLED=true
STORAGE_GRANT_MAX_TTL_SECONDS=900

# Cloud IAM (set one block for your provider)
# AWS S3
AWS_STORAGE_GRANT_ROLE_ARN=arn:aws:iam::123456789012:role/euno-storage-grant-role
# Azure Blob — use workload identity or AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
# GCP Cloud Storage — use Workload Identity Federation or GOOGLE_APPLICATION_CREDENTIALS
```

#### 12.7.2 Grant exchange

```bash
curl -X POST https://storage-grant-service.internal:5051/api/v1/storage-grants \
  -H "Authorization: Bearer <capability-token>" \
  -H "Content-Type: application/json" \
  -d '{ "agentId": "my-agent" }'

# Response:
# {
#   "grants": [
#     {
#       "provider": "azure-blob",
#       "resource": "storage://azure/datasets/reports",
#       "url": "https://datasets.blob.core.windows.net/reports/data.csv?sv=...&sig=...",
#       "sasToken": "<user-delegation-SAS-token>",
#       "expiresAt": "2026-05-19T06:15:00Z"
#     }
#   ]
# }
```

#### 12.7.3 Operational endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness — always returns `{ status: "healthy" }` |
| `GET /health/ready` | Readiness — 503 when `STORAGE_GRANTS_ENABLED=false` or no minters configured |
| `GET /.well-known/storage-grant-service` | Service metadata (issuerDid, audience, endpoints) |

---

### 12.8 AGT in-process guard

> **Reference:** `docs/agent-sdk.md` §"AGT in-process guard";
> `docs/diagrams.md` Set D; Stage-5 Task 8.

The AGT guard (`createAgtGuard()` from `@euno/agent-runtime`) is an in-process
capability pre-screen that sits between the agent logic and the outer gateway.
It implements the **defense-in-depth Set-D architecture**. The guard is a soft
layer only — the outer gateway remains the sole hard enforcement boundary.

> **Security caveat:** The in-process guard can be bypassed by an attacker
> who controls the agent process. It is defense-in-depth, not a security
> boundary. See `docs/agent-sdk.md` §"Why two guards?" and
> `docs/security/enterprise-federation-threat-model.md`
> §"In-process guard bypass".

#### 12.8.1 Quick-start wiring

```typescript
import { createAgtGuard, type AgtGuardOptions } from '@euno/agent-runtime';

const guard = createAgtGuard({
  tokenSupplier: () => fetchCapabilityToken(),  // called before each tool invoke
  policy: agentCapabilityManifest,

  onDeny(toolName, reason) {
    logger.warn('AGT guard blocked', { toolName, reason });
  },

  onGatewayDeny(toolName, gatewayErrorCode) {
    // Guard allowed; outer gateway denied.  The gateway audit log is the record.
    logger.warn('Gateway denied after guard allow', { toolName, gatewayErrorCode });
  },
} satisfies AgtGuardOptions);

// Use guard.invokeTool() instead of calling the tool directly.
const response = await guard.invokeTool('read_file', { path: '/tmp/output.txt' });
```

See `docs/agent-sdk.md` §"AGT in-process guard" for the full API reference,
response shape, and token-supplier contract.

---

### 12.9 Discovery endpoint v1.0.0

> **Reference:** `docs/openapi/capability-issuer-discovery.yaml`;
> Stage-5 Task 9.

The `/.well-known/capability-issuer` endpoint is promoted to a **stable,
versioned contract** (`schemaVersion: "1.0.0"`). Fields published under
`1.0.0` will not be removed or renamed before `2.0.0`.

#### 12.9.1 Response shape

```json
{
  "schemaVersion": "1.0.0",
  "issuer": "did:web:issuer.example.com",
  "signingAlgorithms": ["ES256"],
  "endpoints": {
    "jwks": "/.well-known/jwks.json",
    "didDocument": "/.well-known/did.json"
  },
  "partnerFederation": {
    "registrationEndpoint": "/admin/partner-dids/proposals"
  },
  "scim": { "baseUri": "/scim/v2" },
  "auditExport": {
    "endpoint": "/api/v1/audit/export",
    "chainProof": "/api/v1/audit/chain-proof"
  },
  "capabilities": [
    "partner-federation",
    "scim-provisioning",
    "cross-chain-anchor",
    "db-token-service",
    "storage-grant-service"
  ],
  "actionResolverHash": "<sha256-hex>"
}
```

Responses include `Cache-Control: public, max-age=300` and an `ETag` header
(quoted SHA-256 hex of the body). Send `If-None-Match` on subsequent requests;
the server returns `304 Not Modified` when the document has not changed.

#### 12.9.2 Gateway auto-bootstrap

```env
PARTNER_ISSUER_DISCOVERY_URL=https://partner.example.com/.well-known/capability-issuer
# Bypasses two-eyes approval; blocked in production by default.
# Set PARTNER_DID_REGISTRY_REQUIRED=false to allow (dev/staging only).
```

The gateway reads `body.issuer` (the partner DID) from the document and
auto-registers it. Partner keys are resolved independently via DID-document
resolution.

---

### 12.10 On-prem deployment bundle (Helm + air-gap)

> **Reference:** `docs/DEPLOYMENT.md` §"Stage-5 on-prem deployment";
> Stage-5 Task 11.

The `k8s/helm/` directory contains per-service Helm chart values schemas for
`tool-gateway`, `capability-issuer`, `db-token-service`, `storage-grant-service`,
and `agent-runtime`. Postgres and Redis are expected to be operator-provisioned.

#### 12.10.1 Minimal namespace install

```bash
# Gateway
helm install euno-gateway ./k8s/helm/gateway \
  --set env.NODE_ENV=production \
  --set env.GATEWAY_AUDIENCE=my-org \
  --set env.REDIS_URL="rediss://redis.internal:6380" \
  --set env.AUDIT_LEDGER_BACKEND=per-replica-postgres \
  --set env.AUDIT_LEDGER_PG_URL="postgres://euno_audit:secret@db.internal:5432/euno" \
  --set env.AUDIT_LEDGER_HMAC_SECRET="<64-hex-chars>" \
  --set env.GATEWAY_ADMIN_API_KEY="<admin-key>" \
  --set env.EUNO_DEPLOYMENT_TIER=multi-replica

# Issuer
helm install euno-issuer ./k8s/helm/issuer \
  --set env.NODE_ENV=production \
  --set env.IDENTITY_PROVIDER=azure-ad \
  --set env.AZURE_AD_TENANT_ID="<tenant>" \
  --set env.AZURE_AD_CLIENT_ID="<client>" \
  --set env.SIGNING_PROVIDER=azure-keyvault \
  --set env.AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net/" \
  --set env.ISSUER_DB_URL="postgres://euno:secret@db.internal:5432/euno" \
  --set env.ISSUER_DB_SCHEMA_INIT=true \
  --set env.ISSUER_SCIM_BEARER_TOKEN="<scim-token>" \
  --set env.EUNO_DEPLOYMENT_TIER=multi-replica
```

Values schemas are auto-generated from `pkg//src/config/schema.ts`.
Regenerate with `npm run gen:helm-schema` from the repository root.

#### 12.10.2 Minimum viable air-gapped setup

A fully air-gapped deployment requires the following egress endpoints to be
reachable from within the cluster, proxied, or replaced with on-prem
equivalents:

| Endpoint | Required for | Air-gap replacement |
|---|---|---|
| KMS endpoint (Azure KV / AWS KMS / GCP KMS) | Token signing | BYO HSM with PKCS#11 adapter |
| Postgres | Audit ledger, SCIM tables, issuer state | On-prem Postgres (no egress) |
| Redis | Revocation, kill-switch, circuit-breaker | On-prem Redis (no egress) |
| `https://ion.msidentity.com/api/v1.0/identifiers` | `did:ion` DID resolution | Self-hosted ION node (`ION_RESOLVER_URL=http://ion-sidecar:3000/identifiers`) |
| IdP (Entra ID / Cognito) | User authentication | On-prem OIDC provider |
| SCIM source (Okta / Entra ID) | Group push | On-prem LDAP-to-SCIM bridge |
| S3 Object-Lock bucket | Cross-chain anchor | MinIO with Object-Lock in the cluster |
| `EUNO_TELEMETRY_API` | Telemetry (opt-in only) | Set `EUNO_TELEMETRY=0` to disable |

> For completely disconnected deployments, use `did:key` or `did:web` with
> `DID_WEB_ALLOW_HTTP_FOR_HOSTS` pointing at an in-cluster DID host.
> `did:ion` requires the ION sidecar; all other DID methods work fully offline.

**Minimum viable air-gapped env block:**

```env
# Shared
NODE_ENV=production
EUNO_DEPLOYMENT_TIER=single-replica
EUNO_TELEMETRY=0

# Issuer
IDENTITY_PROVIDER=azure-ad
AZURE_AD_TENANT_ID=<tenant>
AZURE_AD_CLIENT_ID=<client>
SIGNING_PROVIDER=azure-keyvault
AZURE_KEYVAULT_URL=https://your-vault.vault.azure.net/
ISSUER_DB_URL=postgres://euno:secret@localhost:5432/euno
ISSUER_DB_SCHEMA_INIT=true
ISSUER_ADMIN_API_KEY=<admin-key>
ION_RESOLVER_URL=http://localhost:3000/identifiers   # local ION sidecar

# Gateway
GATEWAY_AUDIENCE=my-org
ISSUER_JWKS_URL=http://localhost:3001/.well-known/jwks.json
AUDIT_LEDGER_BACKEND=postgres
AUDIT_LEDGER_PG_URL=postgres://euno:secret@localhost:5432/euno
AUDIT_LEDGER_HMAC_SECRET=<64-hex-chars>
AUDIT_LEDGER_RUN_MIGRATIONS=true
GATEWAY_ADMIN_API_KEY=<gateway-admin-key>
ADMIN_HOST=127.0.0.1
```

#### 12.10.3 Network policies

`k8s/network-policies.yaml` restricts ingress/egress at the Kubernetes
NetworkPolicy layer. Apply it before routing production traffic.
`k8s/network-policies-dev-overlay.yaml` opens broad egress for development
(label `euno.dev/dev-only: 'true'`). **Do not apply the dev overlay in
production clusters.**

---

### 12.11 Stage-5 docker-compose additions (`full` profile)

Add the following services to the Stage-4 base docker-compose (§11.8) to
bring up the complete Stage-5 stack. See `infra/docker-compose.yml` (`full`
profile) for the full working example.

```yaml
services:
  db-token-service:
    image: ghcr.io/euno/db-token-service:1.0.0
    depends_on: [capability-issuer, db]
    environment:
      DB_TOKENS_ENABLED: "true"
      DB_TOKEN_MAX_TTL_SECONDS: "900"
      DB_TOKEN_ALLOW_LIST_FILE: "/app/config/db-instances.json"
      AWS_DB_TOKEN_ROLE_ARN: "${AWS_DB_TOKEN_ROLE_ARN}"
      NODE_ENV: production
      PORT: "5050"
    ports: ["5050:5050"]
    profiles: ["full"]

  storage-grant-service:
    image: ghcr.io/euno/storage-grant-service:1.0.0
    depends_on: [capability-issuer]
    environment:
      STORAGE_GRANTS_ENABLED: "true"
      STORAGE_GRANT_MAX_TTL_SECONDS: "900"
      AWS_STORAGE_GRANT_ROLE_ARN: "${AWS_STORAGE_GRANT_ROLE_ARN}"
      NODE_ENV: production
      PORT: "5051"
    ports: ["5051:5051"]
    profiles: ["full"]

  posture-emitter-drainer:
    # Single-writer SQLite drainer — do NOT scale to more than 1 replica.
    image: ghcr.io/euno/posture-emitter:1.0.0
    depends_on: [redis]
    environment:
      POSTURE_EMITTER_ENABLED: "true"
      POSTURE_EMITTER_PLUGINS: "durable"
      POSTURE_DURABLE_QUEUE_PATH: "/data/posture.db"
      NODE_ENV: production
    volumes:
      - posture-data:/data
    profiles: ["full"]

  partner-issuer-sim:
    # Reference simulator for partner-org DID-backed issuers.
    image: ghcr.io/euno/partner-issuer-sim:1.0.0
    environment:
      PORT: "4200"
      PARTNER_ISSUER_DID: "did:web:localhost:4200"
    ports: ["4200:4200"]
    profiles: ["full"]

volumes:
  posture-data:
```

---

### 12.12 `did:ion` productionization

> **Reference:** `docs/issuer-idp-setup.md` §"DID-based partner issuers";
> Stage-5 Task 2.

The `resolveDidIon()` function is wrapped with a `RedisCircuitBreaker`. A
`/healthz/did-ion` endpoint resolves a known ION document and returns
`{ "status": "ok" | "degraded" }`. Wire this into your readiness probe to
detect ION resolver outages before they affect partner-token issuance.

| Variable | Default | Description |
|---|---|---|
| `ION_RESOLVER_URL` | `https://ion.msidentity.com/api/v1.0/identifiers` | Public or self-hosted resolver URL. |

For air-gapped deployments, point `ION_RESOLVER_URL` at a local ION sidecar:

```bash
# Run the open-source ION sidecar alongside your issuer
docker run -p 3000:3000 ghcr.io/decentralized-identity/ion:latest
```

---

### 12.13 Compliance checklists

#### 12.13.1 SOC2 controls checklist

Use when preparing a SOC2 Type II audit package.

**CC6 — Logical and Physical Access Controls**

- [ ] `ISSUER_SCIM_BEARER_TOKEN` is stored in a secret manager (not a `.env`
      file). Rotation cadence documented and <= 90 days.
- [ ] `ISSUER_SCIM_GROUP_ROLE_MAP` reviewed and signed off by two engineers
      before any group is mapped to `operator` or `admin`.
- [ ] `ISSUER_ADMIN_JWKS_URI` configured (not just `ISSUER_ADMIN_API_KEY`) so
      operator access uses short-lived JWTs.
- [ ] Admin port (`ADMIN_PORT`) bound to `127.0.0.1` or an in-cluster-only
      interface. Confirm it is excluded from public-facing load-balancer rules.
- [ ] `AUDIT_LEDGER_BACKEND` set to `postgres`, `per-replica-postgres`, or
      `acl` (not `none` or `in-memory`) in production.
- [ ] Postgres service account has `INSERT` + `SELECT` on the audit table only.
      No `UPDATE` or `DELETE` — the append-only model is the tamper-evidence
      guarantee.
- [ ] `AUDIT_LEDGER_HMAC_SECRET` sourced from secret manager at runtime.
      Rotation procedure documented (`docs/runbooks/ledger-hmac-rotation.md`).
- [ ] Partner DID registrations require two-eyes approval
      (`PARTNER_DID_REGISTRY_REQUIRED=true`, the production default).
- [ ] `PARTNER_DID_REQUIRE_PIN=true` set for all production partner onboardings.

**CC7 — System Operations**

- [ ] `GET /api/v1/audit/export?scope=soc2-cc6` end-to-end tested. Export
      cursor expires after 24 h; export job completes within the window.
- [ ] `GET /api/v1/audit/chain-proof` returns valid commits. Chain-head
      monotonicity verified after each test run.
- [ ] Posture emitter queue depth monitored. Alert threshold set.
- [ ] Cross-chain anchor interval (`AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS`)
      documented relative to RPO.
- [ ] S3 Object-Lock bucket confirmed enabled (or ACL alternative active).
- [ ] `AUDIT_LEDGER_RETENTION_DAYS` set to match contractual retention tier
      (minimum 365 for SOC2 Type II).

Items from Stage-4 §11.9 (signing-key, admin-auth, IdP hygiene, tenant
isolation, template versioning, role-policy audit, SIGHUP, threat-model
sign-off) also apply.

#### 12.13.2 DID federation checklist

Use for each new partner DID onboarding.

- [ ] **Threat model reviewed.** `docs/security/enterprise-federation-threat-model.md`
      §§1–2 reviewed with the security team before the first partner DID is
      registered in production.
- [ ] **Two-eyes approval completed.** `POST /admin/partner-dids/proposals`
      submitted by first-eye, approved by a different admin. Proposal ID and
      approval timestamp recorded.
- [ ] **Pin attestation captured.** `pinAttestation` included in the proposal.
      The base64-SHA-256 of the partner's public key verified out-of-band
      (phone call or signed email) before approval.
- [ ] **Circuit-breaker tuning reviewed.** `PARTNER_DID_CB_FAILURE_THRESHOLD`,
      `PARTNER_DID_CB_WINDOW_SECONDS`, `PARTNER_DID_CB_COOLDOWN_SECONDS` match
      the partner's SLA for DID document availability.
- [ ] **Prometheus alert wired.**
      `euno_partner_did_circuit_breaker_state{state="open"} == 1` fires a P2
      alert within 5 minutes of circuit opening.
- [ ] **Revocation procedure documented.** Removing the partner DID from the
      registry forces re-evaluation on every subsequent request. Runbook tested
      in staging.
- [ ] **Blast radius documented.** All sessions with `iss = <partner DID>` are
      within blast radius of a partner-key compromise. Session count reviewed
      and accepted.
- [ ] **`did:ion` health check enabled** (if partner uses `did:ion`).
      `/healthz/did-ion` wired into readiness probe and monitoring.

#### 12.13.3 SCIM provisioning checklist

Use before enabling SCIM in production.

- [ ] **Threat model reviewed.** `docs/security/enterprise-federation-threat-model.md`
      §§3–4 reviewed with the security team.
- [ ] **`ISSUER_SCIM_BEARER_TOKEN`** is >= 32 characters, sourced from a secret
      manager, and has a rotation cadence <= 90 days.
- [ ] **`ISSUER_SCIM_GROUP_ROLE_MAP`** reviewed by two engineers. No SCIM group
      maps to `operator` without explicit sign-off in a change ticket.
- [ ] **Postgres migration verified.** `scim_users`, `scim_groups`,
      `scim_group_members` tables created (`ISSUER_DB_SCHEMA_INIT=true` on
      first start).
- [ ] **SCIM push tested end-to-end** (IdP -> issuer -> issuance):
  1. Push a test user with a known group.
  2. Authenticate as that user via the OIDC token endpoint.
  3. Confirm the issued capability token reflects the expected SCIM-derived
     capabilities.
- [ ] **Removal tested.** Remove user from SCIM group; confirm next issuance
      for that user reflects the reduced capability set.
- [ ] **Fail-open behavior acknowledged.** If the SCIM DB lookup fails, the
      issuer falls back to IdP-only roles. For fail-closed behavior, ensure
      Postgres is highly available and consider setting
      `ISSUER_SCIM_CACHE_TTL_SECONDS=0` (deny on SCIM outage).
- [ ] **IdP SCIM configuration verified** (see `docs/issuer-idp-setup.md` §8):
  - Base URL: `https://issuer.example.com/scim/v2`
  - Authentication: HTTP Header `Authorization: Bearer <ISSUER_SCIM_BEARER_TOKEN>`
  - Supported operations: Users, Groups, Push Groups

---

### 12.14 Stage-5 security checklist

In addition to §9 (Stage-3) and §11.9 (Stage-4), review the following before
routing production traffic through a Stage-5 deployment:

- [ ] **Enterprise threat model approved.** `docs/security/enterprise-federation-threat-model.md`
      signed off by >= 2 engineers + 1 security reviewer before partner
      federation or SCIM is deployed to production.
- [ ] **Partner DID registry enabled.** `PARTNER_DID_REGISTRY_REQUIRED=true`
      (production default). `TRUSTED_PARTNER_DIDS` env-var bypass is not used.
- [ ] **SCIM bearer token in secret manager.** `ISSUER_SCIM_BEARER_TOKEN` not
      in a `.env` file or committed to version control.
- [ ] **SOC2 export not publicly reachable.** `GET /api/v1/audit/export`
      requires `X-Admin-Api-Key`. Admin port (3003) excluded from public
      load-balancer ingress rules.
- [ ] **In-process guard is soft.** Security posture does not rely on
      `createAgtGuard()` as a security boundary. Outer gateway is the sole hard
      enforcement point.
- [ ] **Air-gap egress checklist completed.** For air-gapped deployments,
      every egress endpoint in §12.10.2 is reachable via a controlled proxy or
      replaced with an on-prem equivalent.
- [ ] **Cross-chain anchor lag alert wired.** Alert fires when time since the
      last `SignedCrossChainCommitment` exceeds
      `AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS * 3`.
- [ ] **DB credential blast radius documented.** If `db-token-service` is
      deployed, the minimum-privilege DB role is provisioned and credential TTL
      is <= capability token TTL.
- [ ] **Full Stage-5 threat model reviewed.**
      `docs/security/enterprise-federation-threat-model.md` sign-off obtained.

---

## 13. Stage 5 — Posture Emitter Reference

The **durable posture emitter** feeds AI-posture inventory records to cloud
security management surfaces (Azure Defender CSPM, AWS Security Hub,
GCP Security Command Center) for every signed enforcement event.  It uses a
local SQLite WAL queue to guarantee delivery across pod restarts.

### 13.1 How it works

Every time the gateway signs an audit-evidence record (via the async audit
pipeline) the `PostureEmitterPlugin` shim converts the `SignedAuditEvidence`
into an `AgentInventoryRecord` and writes it to the durable queue.  A
background delivery worker fans out the record to each configured plugin,
retrying with exponential back-off until all plugins acknowledge.

Posture emission is **best-effort** — a failed enqueue is logged at `warn`
level and never affects the enforcement decision.

### 13.2 Environment variables

| Variable | Default | Description |
|---|---|---|
| `POSTURE_EMITTER_ENABLED` | `false` | Set `true` to activate. |
| `POSTURE_EMITTER_PLUGINS` | `stdout` | Comma-separated plugin list: `stdout`, `defender-cspm`, `security-hub`, `scc`. |
| `POSTURE_DURABLE_QUEUE_PATH` | `:memory:` (error in production) | Path to the SQLite WAL queue on a persistent volume, e.g. `/var/lib/euno/posture-queue.db`. **Required in production.** |
| `POSTURE_DURABLE_POLL_INTERVAL_MS` | `1000` | Worker poll interval. |
| `POSTURE_DURABLE_MAX_ATTEMPTS` | `10` | Max delivery attempts before dead-lettering. |
| `POSTURE_DURABLE_BATCH_SIZE` | `50` | Events per poll tick. |
| `AZURE_SUBSCRIPTION_ID` | — | Required when `defender-cspm` is in `POSTURE_EMITTER_PLUGINS`. |
| `AWS_ACCOUNT_ID`, `AWS_REGION`, `SECURITY_HUB_PRODUCT_ARN` | — | Required for `security-hub`. |
| `GCP_SCC_SOURCE_NAME`, `GCP_PROJECT_ID` | — | Required for `scc`. |

### 13.3 Field mapping (enforcement events)

At enforcement time the gateway has the signed audit record but not the full
capability manifest.  The posture records produced from enforcement events
carry the following values:

| `AgentInventoryRecord` field | Source |
|---|---|
| `agentId` | `SignedAuditEvidence.agentId` |
| `owningTeam` | `SignedAuditEvidence.tenantId` (falls back to `'unknown'`) |
| `capabilityManifestHash` | `SignedAuditEvidence.capabilityId` (token JTI — proxy) |
| `runtime` | `'unknown'` — not available in enforcement evidence |
| `region` | `'unknown'` — not available in enforcement evidence |
| `firstSeen`, `lastSeen` | `SignedAuditEvidence.ts` |

For accurate `runtime`, `region`, and the real `capabilityManifestHash`,
correlate enforcement records (keyed by `agentId`) with issuance records
produced by the capability issuer's own `PostureEmitter`.

### 13.4 Production deployment checklist

- [ ] Set `POSTURE_EMITTER_ENABLED=true` and `POSTURE_EMITTER_PLUGINS` to
  at least one production target.
- [ ] Mount a persistent volume at `/var/lib/euno/` and set
  `POSTURE_DURABLE_QUEUE_PATH=/var/lib/euno/posture-queue.db` so events
  survive pod restarts.
- [ ] Set `AUDIT_PIPELINE_ENABLED=true` — the posture sink runs inside the
  audit pipeline's `onSigned` callback.  Without an active pipeline the sink
  is never called.
- [ ] Confirm the gateway's Prometheus scrape includes
  `euno_posture_emitter_*` gauges (queue depth, oldest lag) after wiring.


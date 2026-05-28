---
title: "Deploying the eunox self-host stack: Redis, Postgres, KMS, and Helm"
description: "Step-by-step deployment guide for the BSL 1.1 self-host tier. Covers the Docker Compose development setup, the production Helm umbrella chart, service configuration, Redis HA, Postgres schema bootstrap, KMS integration, and air-gap deployments."
pubDate: "2026-05-28"
---

_This is the deployment guide for the **Self-Host (BSL 1.1)** tier. If you only need in-process enforcement for a single agent with no shared state, start with [post 33: deploying eunox OSS](./33-deploy-oss.md). For a full tier comparison, see [`docs/pricing.md`](https://github.com/edgeobs/eunox/blob/main/docs/pricing.md)._

---

The self-host tier gives you the complete gateway stack under your own control: capability issuer, tool gateway, API-key minter, posture emitter, and all enterprise services. You bring the infrastructure (Redis, Postgres, KMS); eunox brings the enforcement, issuance, and audit machinery.

**License:** BSL 1.1 (non-competing use; converts to Apache-2.0 four years after each release). Review the [LICENSE](https://github.com/edgeobs/eunox/blob/main/LICENSE) before deploying in a competing product.

**When to use this tier:**

- You need a shared kill-switch that spans multiple agent processes.
- You want centralized, queryable audit records across agents and services.
- You require call-budget enforcement shared across replicas.
- Your compliance posture requires on-premises or private-cloud infrastructure.
- You need SCIM 2.0 agent provisioning, DID federation, or HSM-backed signing keys.

---

## What you are deploying

| Service               | Port              | Binary               | Purpose                                              |
| --------------------- | ----------------- | -------------------- | ---------------------------------------------------- |
| Capability Issuer     | 3001              | `cmd/issuer`         | Issues signed JWT capability tokens via your KMS     |
| Tool Gateway          | 3002 / 3003 admin | `cmd/gateway`        | Enforces capability tokens on every agent tool call  |
| API-key Minter        | 3004              | `cmd/minter`         | Issues `sk-...` API keys that map to capability JWTs |
| DB Token Service      | 3005              | `cmd/db-token-svc`   | Short-lived database credentials for agents          |
| Storage Grant Service | 3006              | `cmd/storage-grant-svc` | Presigned URL generation for agents              |
| Posture Emitter       | 3008              | `cmd/posture-emitter`| Security posture reporting to CSPM platforms         |

For a first deployment, you only need the **Capability Issuer** and **Tool Gateway**. The other services can be added incrementally as your requirements grow.

---

## Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2
- A cloud KMS account (AWS KMS, Azure Key Vault, or GCP Cloud KMS) for the signing key
- Redis ≥ 6.2 (BYO or managed)
- Postgres ≥ 14 (BYO or managed)
- Go 1.25+ if building from source (or use the published container images)

---

## Part 1 — Development / single-node setup

This setup is suitable for local development and single-developer evaluation. It omits Redis and Postgres; all state is in-memory and ephemeral.

### 1.1 Create the workspace

```bash
mkdir -p /srv/eunox/keys /srv/eunox/policies
chmod 700 /srv/eunox/keys
```

### 1.2 Generate an audit signing key

The gateway needs a key to sign tamper-evident audit evidence. For development, a local EC P-256 PEM key is sufficient:

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out /srv/eunox/keys/audit-signing.pem
chmod 600 /srv/eunox/keys/audit-signing.pem
```

In production, replace this with a KMS-backed key (see Part 2).

### 1.3 Create a KMS signing key for the issuer

The capability issuer signs every JWT it issues via a cloud KMS key. The minimum viable recipe uses AWS KMS with a `ECC_NIST_P256` asymmetric key:

```bash
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "eunox capability-issuer signing key (dev)" \
  --region us-east-1
# Copy the "KeyId" (ARN) from the output
```

> **No AWS account?** Use [LocalStack](https://github.com/localstack/localstack): run `docker run --rm -p 4566:4566 localstack/localstack` and set `AWS_ENDPOINT_URL=http://localhost:4566` plus `AWS_ACCESS_KEY_ID=test` / `AWS_SECRET_ACCESS_KEY=test` in `issuer.env`.

### 1.4 Write environment files

**`/srv/eunox/issuer.env`:**

```bash
NODE_ENV=development
PORT=3001
EUNOX_DEPLOYMENT_TIER=single-replica
ISSUER_DID=did:web:localhost%3A3001
SIGNING_PROVIDER=aws-kms
AWS_KMS_KEY_ID=<your-key-arn>
AWS_KMS_REGION=us-east-1
IDENTITY_PROVIDER=did
DEFAULT_TOKEN_TTL=900
GATEWAY_AUDIENCE=tool-gateway:dev
```

**`/srv/eunox/gateway.env`:**

```bash
NODE_ENV=development
PORT=3002
ADMIN_PORT=3003
EUNOX_DEPLOYMENT_TIER=single-replica
GATEWAY_AUDIENCE=tool-gateway:dev
ISSUER_JWKS_URL=http://capability-issuer:3001/.well-known/jwks.json
ADMIN_API_KEY=dev-admin-key-not-for-production
REDIS_CIRCUIT_OPEN_MODE=fail-closed
AUDIT_LEDGER_BACKEND=none
ENABLE_CRYPTOGRAPHIC_AUDIT=true
EVIDENCE_SIGNED_DECISIONS=deny
EVIDENCE_SIGNING_KEY_FILE=/app/keys/audit-signing.pem
EVIDENCE_SIGNING_ALGORITHM=ES256
```

### 1.5 Create a policy

**`/srv/eunox/policies/agent.yaml`:**

```yaml
agentId: "my-agent"
name: "My Agent"
version: "0.1.0"
requiredCapabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: pathPattern
        allowedPaths: ["/data/**"]
```

### 1.6 Start the development stack

**`/srv/eunox/docker-compose.dev.yml`:**

```yaml
version: "3.9"
services:
  capability-issuer:
    image: ghcr.io/edgeobs/eunox/issuer:1.0.0
    env_file: /srv/eunox/issuer.env
    volumes:
      - /srv/eunox/policies:/app/policies:ro
    ports: ["3001:3001"]
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3001/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5

  tool-gateway:
    image: ghcr.io/edgeobs/eunox/gateway:1.0.0
    env_file: /srv/eunox/gateway.env
    volumes:
      - /srv/eunox/keys:/app/keys:ro
    depends_on:
      capability-issuer:
        condition: service_healthy
    ports:
      - "3002:3002"
      - "127.0.0.1:3003:3003"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3002/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5
```

```bash
docker compose -f /srv/eunox/docker-compose.dev.yml up -d
```

### 1.7 Issue a capability token and verify the gateway

```bash
# Issue a token (DID-identity path — see docs/self-host.md §6 for details)
TOKEN=$(curl -s -X POST http://localhost:3001/api/v1/issue \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{"agentId":"my-agent","requestedCapabilities":[{"resource":"read_file","actions":["call"]}]}' \
  | jq -r .token)

# Test enforcement (allowed call)
curl -s -X POST http://localhost:3002/api/v1/enforce \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{"tool":"read_file","args":{"path":"/data/report.csv"}}'
# → {"decision":"allow", ...}

# Health check
curl -s http://localhost:3002/health/ready
# → {"status":"ready"}
```

---

## Part 2 — Production setup

### 2.1 Replace the local PEM key with KMS for audit signing

```bash
# gateway.env — replace the PEM signing block with KMS:
# (remove EVIDENCE_SIGNING_KEY_FILE and EVIDENCE_SIGNING_ALGORITHM)
AUDIT_SIGNING_KMS_PROVIDER=aws-kms
AUDIT_SIGNING_AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/mrk-def456
```

For Azure Key Vault or GCP Cloud KMS, see the full reference in [`docs/deployment.md`](https://github.com/edgeobs/eunox/blob/main/docs/deployment.md) under "Configuration Reference → Issuer → Signing Provider".

### 2.2 Add Redis (required for multi-replica)

Redis provides the shared state layer: call counters, kill-switch, revocation list, and DPoP replay cache. For production, configure Redis Sentinel or Redis Cluster for HA:

> **Critical:** The gateway performs a **fatal startup check** in production mode: if any configured Redis URL points to a single-node Redis instance, the service refuses to start. Multi-node Redis is enforced at boot when `NODE_ENV=production`.

```bash
# gateway.env additions
EUNOX_DEPLOYMENT_TIER=multi-replica
REDIS_URL=rediss://:${REDIS_PASSWORD}@redis-sentinel.internal:6379
REVOCATION_REDIS_URL=rediss://:${REDIS_PASSWORD}@redis-sentinel.internal:6379
KILL_SWITCH_REDIS_URL=rediss://:${REDIS_PASSWORD}@redis-sentinel.internal:6379
CALL_COUNTER_REDIS_URL=rediss://:${REDIS_PASSWORD}@redis-sentinel.internal:6379
REDIS_CIRCUIT_OPEN_MODE=fail-closed
```

### 2.3 Add Postgres (audit ledger, kill-switch persistence)

```bash
# gateway.env additions
AUDIT_LEDGER_BACKEND=postgres
AUDIT_LEDGER_PG_URL=postgresql://audit_writer:${AUDIT_PG_PASSWORD}@postgres.internal:5432/eunox
AUDIT_LEDGER_HMAC_SECRET=$(openssl rand -hex 32)
AUDIT_LEDGER_RUN_MIGRATIONS=true   # set false after first run in production
```

The gateway bootstraps the schema from `migrations/audit/` automatically on first start. To run migrations manually:

```bash
go run ./cmd/gateway -- migrate-up
```

### 2.4 Production environment checklist

Before going live, verify these settings in both `issuer.env` and `gateway.env`:

- `NODE_ENV=production`
- `ADMIN_API_KEY` is a random 32+ byte value (not `dev-admin-key-not-for-production`)
- `SIGNING_PROVIDER` points to a cloud KMS (not a local PEM file)
- `REDIS_URL` points to a multi-node Redis cluster or Sentinel (HA required in production)
- `AUDIT_LEDGER_RUN_MIGRATIONS=false` (after initial bootstrap)
- TLS is terminated upstream (load balancer or sidecar) on port 3002
- Admin port (3003) is not exposed publicly — bind to loopback or a VPN-only interface

---

## Part 3 — Kubernetes / Helm deployment

For production Kubernetes deployments, use the Helm umbrella chart:

```bash
# Deploy all services into the eunox-system namespace
helm install eunox k8s/helm/eunox/ \
  --namespace eunox-system \
  --create-namespace \
  -f k8s/helm/eunox/values.yaml
```

The umbrella chart deploys all six services as separate Deployments with individual HorizontalPodAutoscalers. Before deploying, create a `values-prod.yaml` that overrides:

```yaml
gateway:
  replicaCount: 3
  env:
    NODE_ENV: production
    EUNOX_DEPLOYMENT_TIER: multi-replica
    REDIS_URL: "rediss://:$(REDIS_PASSWORD)@redis.internal:6379"
    AUDIT_LEDGER_BACKEND: postgres
    AUDIT_LEDGER_PG_URL: "******postgres.internal:5432/eunox"
    # ... other production env vars

issuer:
  replicaCount: 2
  env:
    NODE_ENV: production
    SIGNING_PROVIDER: azure-keyvault
    AZURE_KEYVAULT_URL: "https://my-vault.vault.azure.net/"
    AZURE_KEYVAULT_KEY_NAME: capability-signing-key
    AZURE_CREDENTIAL_TYPE: managed-identity
```

For cloud-specific guidance see [`docs/deploy-eks.md`](https://github.com/edgeobs/eunox/blob/main/docs/deploy-eks.md) (EKS) and [`docs/deploy-gke.md`](https://github.com/edgeobs/eunox/blob/main/docs/deploy-gke.md) (GKE).

---

## Part 4 — Air-gap deployments

For deployments in networks with no outbound internet access, use the air-gap image bundle:

```bash
# On a machine with internet access:
./scripts/pull-air-gap-images.sh
# Produces: air-gap-images.tar

# Transfer to the air-gapped environment and load:
docker load < air-gap-images.tar

# Or push to your private registry:
./scripts/pull-air-gap-images.sh --push registry.internal:5000
```

The complete list of images is in `k8s/air-gap-images.txt`. For DID resolution in air-gapped environments, deploy a local DID resolver (the `did:web` resolver only requires HTTPS to the DID document host; point it at your internal domain).

---

## Part 5 — Wiring @eunox/mcp to the self-hosted gateway

Once the stack is running, configure `@eunox/mcp` to use your gateway instead of local enforcement. In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-server-governed": {
      "command": "npx",
      "args": [
        "-y", "@eunox/mcp", "proxy",
        "--enforcer-url", "https://gateway.example.com",
        "--enforcer-api-key", "<your-issued-jwt>",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

The JWT is issued by the capability issuer (`POST /api/v1/issue`). For team environments with many agents, automate issuance via the issuer API or set up SCIM-based agent provisioning (see [`docs/self-host.md`](https://github.com/edgeobs/eunox/blob/main/docs/self-host.md) §12 for the SCIM integration).

---

## Where to go from here

- **Full configuration reference:** [`docs/deployment.md`](https://github.com/edgeobs/eunox/blob/main/docs/deployment.md) — every environment variable for every service.
- **Self-host guide:** [`docs/self-host.md`](https://github.com/edgeobs/eunox/blob/main/docs/self-host.md) — the comprehensive 13-section operator guide including enterprise deployment, SCIM, DID federation, and compliance checklists.
- **Redis failure modes:** [`docs/redis-failure-modes.md`](https://github.com/edgeobs/eunox/blob/main/docs/redis-failure-modes.md) — how the gateway behaves under Redis degradation.
- **Health checks:** [`docs/health-checks.md`](https://github.com/edgeobs/eunox/blob/main/docs/health-checks.md) — liveness and readiness endpoint reference.
- **Issuer runbook:** [`docs/issuer-operator-runbook.md`](https://github.com/edgeobs/eunox/blob/main/docs/issuer-operator-runbook.md) — day-two operations for the capability issuer.

_Previous: [post 33 — deploying eunox OSS](./33-deploy-oss.md). For the full series index, see [`docs/blog-articles.md`](https://github.com/edgeobs/eunox/blob/main/docs/blog-articles.md)._

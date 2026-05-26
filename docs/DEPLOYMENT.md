# Deployment Guide

> **Audience:** Platform operators deploying eunox services to production.
> For local development, see the [repo guide](./repo-guide.md).

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Services Overview](#services-overview)
3. [Configuration Reference](#configuration-reference)
   - [Gateway](#gateway)
   - [Issuer](#issuer)
   - [Minter](#minter)
   - [Posture Emitter](#posture-emitter)
4. [Production Requirements](#production-requirements)
5. [Redis HA](#redis-ha-for-production)
6. [Deployment Targets](#deployment-targets)
7. [Health Checks](#health-checks)

---

## Quick Start

### Single-node (development / pilot)

```bash
# Build the gateway binary
go build -o ./bin/gateway ./cmd/gateway

# Run gateway with minimal config
GATEWAY_NODE_ENV=development \
GATEWAY_PORT=3002 \
GATEWAY_ADMIN_PORT=3003 \
  ./bin/gateway
```

### Production (Kubernetes)

```bash
# Deploy via Helm umbrella chart
helm install eunox k8s/helm/eunox/ \
  --namespace eunox-system \
  --create-namespace \
  -f k8s/helm/eunox/values.yaml
```

See [deploy-eks.md](./deploy-eks.md) and [deploy-gke.md](./deploy-gke.md) for
cloud-specific guides.

---

## Services Overview

| Service               | Default Port                 | Binary                  | Description                                                                         |
| --------------------- | ---------------------------- | ----------------------- | ----------------------------------------------------------------------------------- |
| Gateway               | 3002 (public) / 3003 (admin) | `cmd/gateway`           | Policy enforcement proxy                                                            |
| Issuer                | 3001                         | `cmd/issuer`            | Capability token issuance                                                           |
| Minter                | 3004                         | `cmd/minter`            | API-key lifecycle management                                                        |
| DB Token Service      | 3005                         | `cmd/db-token-svc`      | Short-lived database credentials                                                    |
| Storage Grant Service | 3006                         | `cmd/storage-grant-svc` | Presigned URL generation                                                            |
| Posture Emitter       | 3008                         | `cmd/posture-emitter`   | Security posture reporting (SQLite via pure-Go modernc.org/sqlite; no CGO required) |

---

## Configuration Reference

All services are configured via environment variables. Variables marked
**Required (prod)** must be set when `NODE_ENV=production`.

### Gateway

The gateway uses the `GATEWAY_` prefix for all configuration variables.

#### Core

| Variable                       | Type   | Default          | Required | Description                                                      |
| ------------------------------ | ------ | ---------------- | -------- | ---------------------------------------------------------------- |
| `GATEWAY_NODE_ENV`             | enum   | `development`    | —        | `development`, `staging`, `production`                           |
| `GATEWAY_EUNO_DEPLOYMENT_TIER` | enum   | `single-replica` | —        | `single-replica`, `multi-replica`, `multi-region-active-active`  |
| `GATEWAY_PORT`                 | int    | `3002`           | —        | Public HTTP listen port                                          |
| `GATEWAY_ADMIN_PORT`           | int    | `3003`           | —        | Admin API listen port                                            |
| `GATEWAY_ADMIN_HOST`           | string | —                | prod     | Bind address for admin API (non-wildcard required in production) |
| `GATEWAY_ADMIN_API_KEY`        | string | —                | prod     | Shared secret for admin endpoints                                |
| `GATEWAY_BACKEND_SERVICE_URL`  | string | —                | —        | Upstream service URL for proxied requests                        |
| `GATEWAY_ALLOWED_ORIGINS`      | string | —                | —        | Comma-separated CORS origins                                     |

#### Token Verification

| Variable                              | Type   | Default        | Required | Description                                                                                     |
| ------------------------------------- | ------ | -------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `GATEWAY_ISSUER_JWKS_URL`             | string | —              | —        | JWKS endpoint for capability token verification                                                 |
| `GATEWAY_EUNO_REQUIRE_KID`            | bool   | `true`         | —        | Require `kid` header in JWTs                                                                    |
| `GATEWAY_EUNO_JWKS_CACHE_TTL_SECONDS` | int    | `300`          | —        | JWKS cache duration                                                                             |
| `GATEWAY_GATEWAY_AUDIENCE`            | string | `tool-gateway` | —        | Expected `aud` claim value                                                                      |
| `GATEWAY_HOSTED_MODE`                 | bool   | `false`        | —        | Enable hosted multi-tenant mode (requires unique `GATEWAY_GATEWAY_AUDIENCE`)                    |
| `GATEWAY_TENANT_ID`                   | string | —              | prod     | Tenant identifier (fallback: `TENANT_ID` env var); required when `GATEWAY_ADMIN_API_KEY` is set |

#### Rate Limiting

| Variable                          | Type | Default | Required | Description                  |
| --------------------------------- | ---- | ------- | -------- | ---------------------------- |
| `GATEWAY_RATE_LIMIT_WINDOW_MS`    | int  | `60000` | —        | Sliding window duration (ms) |
| `GATEWAY_RATE_LIMIT_MAX_REQUESTS` | int  | `1000`  | —        | Max requests per window      |

#### Redis

| Variable                         | Type   | Default | Required | Description                               |
| -------------------------------- | ------ | ------- | -------- | ----------------------------------------- |
| `GATEWAY_REDIS_URL`              | string | —       | —        | Primary Redis (DPoP replay, shared state) |
| `GATEWAY_REVOCATION_REDIS_URL`   | string | —       | —        | Dedicated Redis for token revocation      |
| `GATEWAY_KILL_SWITCH_REDIS_URL`  | string | —       | —        | Dedicated Redis for kill switch           |
| `GATEWAY_CALL_COUNTER_REDIS_URL` | string | —       | —        | Dedicated Redis for call counters         |

> **Production:** All Redis URLs must point to Sentinel or Cluster endpoints.
> Single-node Redis is rejected at boot. See [Redis HA](#redis-ha-for-production).

#### Telemetry

| Variable                     | Type | Default  | Required | Description                                              |
| ---------------------------- | ---- | -------- | -------- | -------------------------------------------------------- |
| `GATEWAY_EUNO_TELEMETRY`     | bool | `true`   | —        | Enable telemetry collection (override: `EUNO_TELEMETRY`) |
| `GATEWAY_TELEMETRY_FLUSH_MS` | int  | `300000` | —        | Telemetry flush interval (min 1000ms)                    |

---

### Issuer

The issuer reads environment variables without a service prefix.

#### Core

| Variable               | Type   | Default          | Required | Description                            |
| ---------------------- | ------ | ---------------- | -------- | -------------------------------------- |
| `NODE_ENV`             | enum   | `development`    | —        | `development`, `staging`, `production` |
| `EUNO_DEPLOYMENT_TIER` | enum   | `single-replica` | —        | Deployment tier                        |
| `PORT`                 | int    | `3001`           | —        | HTTP listen port                       |
| `ADMIN_API_KEY`        | string | —                | prod     | Admin endpoint shared secret           |
| `ISSUER_DID`           | string | —                | —        | Issuer DID identifier                  |
| `ISSUER_URL`           | string | —                | —        | Public issuer URL                      |
| `AUDIENCE`             | string | —                | —        | Default token audience                 |
| `LOG_LEVEL`            | string | —                | —        | Logging level                          |

#### Token Issuance

| Variable                | Type   | Default | Required | Description                         |
| ----------------------- | ------ | ------- | -------- | ----------------------------------- |
| `DEFAULT_TOKEN_TTL`     | int    | `900`   | —        | Default token lifetime (seconds)    |
| `MAX_TOKEN_TTL`         | int    | `86400` | —        | Maximum token lifetime (seconds)    |
| `ROLE_POLICY_FILE`      | string | —       | —        | Path to role→capability policy file |
| `RATE_LIMIT_PER_MINUTE` | int    | `60`    | —        | Per-identity rate limit             |
| `REDIS_URL`             | string | —       | —        | Redis for rate limiting / state     |

#### Signing Provider

| Variable                  | Type   | Default          | Required | Description                                             |
| ------------------------- | ------ | ---------------- | -------- | ------------------------------------------------------- |
| `SIGNING_PROVIDER`        | enum   | `azure-keyvault` | —        | `azure-keyvault`, `aws-kms`, `gcp-cloudkms`, `software` |
| `AZURE_KEYVAULT_URL`      | string | —                | if azure | Key Vault URL                                           |
| `AZURE_KEYVAULT_KEY_NAME` | string | —                | if azure | Signing key name                                        |
| `AWS_KMS_REGION`          | string | —                | if aws   | KMS region                                              |
| `AWS_KMS_KEY_ID`          | string | —                | if aws   | KMS key ARN or alias                                    |
| `GCP_PROJECT_ID`          | string | —                | if gcp   | GCP project                                             |
| `GCP_KEYRING_ID`          | string | —                | if gcp   | Cloud KMS keyring                                       |
| `GCP_CRYPTOKEY_ID`        | string | —                | if gcp   | Cloud KMS key                                           |

#### Identity Provider

| Variable                   | Type   | Default    | Required    | Description                                              |
| -------------------------- | ------ | ---------- | ----------- | -------------------------------------------------------- |
| `IDENTITY_PROVIDER`        | enum   | `azure-ad` | —           | `azure-ad`, `aws-cognito`, `gcp-identity`, `did`, `oidc` |
| `OIDC_ISSUER_URL`          | string | —          | if oidc     | OIDC issuer URL                                          |
| `AZURE_AD_TENANT_ID`       | string | —          | if azure-ad | Entra ID tenant                                          |
| `AZURE_AD_CLIENT_ID`       | string | —          | if azure-ad | Application client ID                                    |
| `AWS_COGNITO_REGION`       | string | —          | if cognito  | Cognito region                                           |
| `AWS_COGNITO_USER_POOL_ID` | string | —          | if cognito  | User pool ID                                             |
| `GCP_IDENTITY_AUDIENCE`    | string | —          | if gcp      | Expected audience for GCP identity tokens                |

---

### Minter

The minter uses the `MINTER_` prefix for most variables.

#### Core

| Variable                   | Type   | Default                      | Required | Description                            |
| -------------------------- | ------ | ---------------------------- | -------- | -------------------------------------- |
| `NODE_ENV`                 | enum   | `development`                | —        | `development`, `staging`, `production` |
| `MINTER_PORT`              | int    | `3004`                       | —        | HTTP listen port                       |
| `MINTER_ISSUER_DID`        | string | `did:web:minter.eunox.local` | —        | Minter's DID                           |
| `MINTER_GATEWAY_AUDIENCE`  | string | `tool-gateway`               | —        | Target gateway audience                |
| `MINTER_TOKEN_TTL_SECONDS` | int    | `300`                        | —        | Minted token lifetime                  |
| `LOG_LEVEL`                | string | —                            | —        | Logging level                          |

#### Security (required in production)

| Variable                | Type   | Default | Required | Description                                  |
| ----------------------- | ------ | ------- | -------- | -------------------------------------------- |
| `MINTER_ADMIN_API_KEY`  | string | —       | prod     | Admin key (≥32 chars, not `dev-admin-key`)   |
| `MINTER_PEPPER_HEX`     | string | —       | prod     | 64 hex-char HMAC pepper for API key hashing  |
| `MINTER_AUDIT_DB_URL`   | string | —       | prod     | PostgreSQL connection string for audit store |
| `MINTER_API_KEY_DB_URL` | string | —       | prod     | PostgreSQL connection string for key store   |

#### Signing

| Variable                   | Type   | Default | Required | Description                                 |
| -------------------------- | ------ | ------- | -------- | ------------------------------------------- |
| `MINTER_KMS_PROVIDER`      | enum   | —       | —        | `azure-keyvault`, `aws-kms`, `gcp-cloudkms` |
| `MINTER_PRIVATE_KEY_PEM`   | string | —       | —        | Software signing key (if no KMS)            |
| `MINTER_PUBLIC_KEY_PEM`    | string | —       | —        | Public key for verification                 |
| `MINTER_SIGNING_ALGORITHM` | string | —       | —        | JWS algorithm (e.g., `ES256`)               |

#### Rate Limiting

| Variable                           | Type   | Default | Required | Description             |
| ---------------------------------- | ------ | ------- | -------- | ----------------------- |
| `REDIS_URL`                        | string | —       | —        | Redis for rate limiting |
| `MINTER_RATE_LIMIT_MAX`            | int    | `100`   | —        | Max mints per window    |
| `MINTER_RATE_LIMIT_WINDOW_SECONDS` | int    | `60`    | —        | Rate limit window       |

#### Admin JWT Authentication (optional)

| Variable                    | Type   | Default | Required | Description                                 |
| --------------------------- | ------ | ------- | -------- | ------------------------------------------- |
| `MINTER_ADMIN_JWKS_URI`     | string | —       | —        | JWKS endpoint for operator JWT verification |
| `MINTER_ADMIN_JWT_AUDIENCE` | string | —       | —        | Required JWT audience claim                 |

---

### Posture Emitter

#### Core

| Variable                  | Type   | Default          | Required | Description                                                  |
| ------------------------- | ------ | ---------------- | -------- | ------------------------------------------------------------ |
| `NODE_ENV`                | enum   | `development`    | —        | `development`, `staging`, `production`                       |
| `EUNO_DEPLOYMENT_TIER`    | enum   | `single-replica` | —        | Deployment tier                                              |
| `PORT`                    | int    | `3008`           | —        | HTTP listen port                                             |
| `POSTURE_EMITTER_ENABLED` | bool   | `true`           | —        | Enable posture emission                                      |
| `POSTURE_EMITTER_PLUGINS` | string | `stdout`         | —        | Comma-separated: `defender`, `security-hub`, `scc`, `stdout` |

#### Queue Configuration

| Variable                           | Type   | Default            | Required | Description                     |
| ---------------------------------- | ------ | ------------------ | -------- | ------------------------------- |
| `POSTURE_DURABLE_QUEUE_PATH`       | string | `posture-queue.db` | —        | SQLite queue file path          |
| `POSTURE_DURABLE_POLL_INTERVAL_MS` | int    | `1000`             | —        | Queue poll interval (min 100ms) |
| `POSTURE_DURABLE_MAX_ATTEMPTS`     | int    | `10`               | —        | Max delivery attempts           |
| `POSTURE_DURABLE_BATCH_SIZE`       | int    | `50`               | —        | Batch processing size           |
| `POSTURE_PLUGIN_TIMEOUT_MS`        | int    | `5000`             | —        | Per-plugin timeout (min 100ms)  |

#### Backoff & Deduplication

| Variable                         | Type | Default  | Required | Description                          |
| -------------------------------- | ---- | -------- | -------- | ------------------------------------ |
| `POSTURE_BACKOFF_BASE_MS`        | int  | `1000`   | —        | Exponential backoff base (min 100ms) |
| `POSTURE_BACKOFF_MAX_MS`         | int  | `300000` | —        | Max backoff (min 1000ms)             |
| `POSTURE_DEDUPE_WINDOW_MS`       | int  | `300000` | —        | Deduplication window (0 = disabled)  |
| `POSTURE_HEALTH_MAX_QUEUE_DEPTH` | int  | `10000`  | —        | Unhealthy queue depth threshold      |

#### Plugin-Specific

**Microsoft Defender (plugin=defender):**

| Variable                          | Type   | Default        | Required    | Description            |
| --------------------------------- | ------ | -------------- | ----------- | ---------------------- |
| `DEFENDER_SUBSCRIPTION_ID`        | string | —              | if defender | Azure subscription ID  |
| `DEFENDER_ASSESSMENT_NAME_PREFIX` | string | `eunox-agent-` | —           | Assessment name prefix |

**AWS Security Hub (plugin=security-hub):**

| Variable                    | Type   | Default                    | Required        | Description              |
| --------------------------- | ------ | -------------------------- | --------------- | ------------------------ |
| `AWS_ACCOUNT_ID`            | string | —                          | if security-hub | AWS account ID           |
| `AWS_REGION`                | string | —                          | if security-hub | AWS region               |
| `SECURITY_HUB_PRODUCT_ARN`  | string | —                          | if security-hub | Security Hub product ARN |
| `SECURITY_HUB_GENERATOR_ID` | string | `eunox/posture-emitter/v1` | —               | Finding generator ID     |

**GCP Security Command Center (plugin=scc):**

| Variable              | Type   | Default | Required | Description     |
| --------------------- | ------ | ------- | -------- | --------------- |
| `GCP_SCC_SOURCE_NAME` | string | —       | if scc   | SCC source name |
| `GCP_PROJECT_ID`      | string | —       | if scc   | GCP project ID  |

---

## Production Requirements

When `NODE_ENV=production` (or `GATEWAY_NODE_ENV=production` for gateway):

1. **Minter** rejects startup if:
   - `MINTER_ADMIN_API_KEY` is missing, shorter than 32 chars, or equals `dev-admin-key`
   - `MINTER_PEPPER_HEX` is missing or not 64 hex characters
   - No signing key configured (no KMS provider and no PEM key)
   - `MINTER_AUDIT_DB_URL` is missing
   - `MINTER_API_KEY_DB_URL` is missing

2. **Gateway** rejects startup if:
   - Any configured Redis URL is single-node (see below)
   - `GATEWAY_ADMIN_API_KEY` is set but `GATEWAY_TENANT_ID` (or `TENANT_ID`) is empty

   Recommended (not enforced at startup):
   - Bind `GATEWAY_ADMIN_HOST` to `127.0.0.1` rather than a wildcard address

3. **Hosted mode** (`GATEWAY_HOSTED_MODE=true`):
   - It is strongly recommended to set `GATEWAY_GATEWAY_AUDIENCE` to a unique
     non-default value (not `tool-gateway`) to prevent cross-tenant replay attacks

---

## Redis HA for Production

In production, all Redis URLs must indicate a high-availability topology.
Single-node Redis (`redis://host:6379`) is **rejected at boot**.

Accepted patterns:

| Pattern              | Example                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| Sentinel scheme      | `redis-sentinel://host1:26379,host2:26379/0?sentinel_master_name=mymaster` |
| Cluster scheme       | `redis-cluster://host1:6379,host2:6379`                                    |
| Multiple hosts       | `redis://host1:6379,host2:6379,host3:6379`                                 |
| Sentinel query param | `redis://host:6379?sentinelMasterName=mymaster`                            |

The development Docker Compose and `k8s/redis.yaml` use single-node Redis
(labelled `eunox.dev/dev-only: 'true'`). These are **not suitable for production**.

---

## Deployment Targets

| Target         | Guide                                                       |
| -------------- | ----------------------------------------------------------- |
| Amazon EKS     | [deploy-eks.md](./deploy-eks.md)                            |
| Google GKE     | [deploy-gke.md](./deploy-gke.md)                            |
| Helm (any K8s) | `k8s/helm/eunox/` — umbrella chart                          |
| Docker Compose | `infra/docker-compose.yml` (dev/pilot only)                 |
| Air-gapped     | `k8s/air-gap-images.txt` + `scripts/pull-air-gap-images.sh` |

---

## Health Checks

All services expose:

| Endpoint            | Purpose                                               |
| ------------------- | ----------------------------------------------------- |
| `GET /health/live`  | Liveness probe — always 200 if process is running     |
| `GET /health/ready` | Readiness probe — 200 when dependencies are connected |

Gateway also exposes `GET /healthz/did-ion` for DID resolution readiness.

Configure Kubernetes probes:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /health/ready
    port: http
  initialDelaySeconds: 5
  periodSeconds: 5
```

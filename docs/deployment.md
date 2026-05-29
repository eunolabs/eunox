# Deployment Guide

> **Audience:** Platform operators deploying eunox services to production.
> For local development, see the [repo guide](./repo-guide.md).
>
> **Related blog posts:**
>
> - [Post 33: Deploying eunox OSS](https://eunolabs.ai/blog/33-deploy-oss) — 5-minute OSS quickstart (`eunox-mcp`, local enforcement, no server required)
> - [Post 34: Deploying the self-host stack](https://eunolabs.ai/blog/34-deploy-self-host) — Docker Compose dev setup, Helm production deployment, Redis HA, KMS, air-gap

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
8. [Multi-AZ Reference Architecture](#multi-az-reference-architecture)

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

| Variable                        | Type   | Default          | Required | Description                                                      |
| ------------------------------- | ------ | ---------------- | -------- | ---------------------------------------------------------------- |
| `GATEWAY_NODE_ENV`              | enum   | `development`    | —        | `development`, `staging`, `production`                           |
| `GATEWAY_EUNOX_DEPLOYMENT_TIER` | enum   | `single-replica` | —        | `single-replica`, `multi-replica`, `multi-region-active-active`  |
| `GATEWAY_PORT`                  | int    | `3002`           | —        | Public HTTP listen port                                          |
| `GATEWAY_ADMIN_PORT`            | int    | `3003`           | —        | Admin API listen port                                            |
| `GATEWAY_ADMIN_HOST`            | string | —                | prod     | Bind address for admin API (non-wildcard required in production) |
| `GATEWAY_ADMIN_API_KEY`         | string | —                | prod     | Shared secret for admin endpoints                                |
| `GATEWAY_BACKEND_SERVICE_URL`   | string | —                | —        | Upstream service URL for proxied requests                        |
| `GATEWAY_ALLOWED_ORIGINS`       | string | —                | —        | Comma-separated CORS origins                                     |

#### Token Verification

| Variable                               | Type   | Default        | Required | Description                                                                                     |
| -------------------------------------- | ------ | -------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `GATEWAY_ISSUER_JWKS_URL`              | string | —              | —        | JWKS endpoint for capability token verification                                                 |
| `GATEWAY_EUNOX_REQUIRE_KID`            | bool   | `true`         | —        | Require `kid` header in JWTs                                                                    |
| `GATEWAY_EUNOX_JWKS_CACHE_TTL_SECONDS` | int    | `300`          | —        | JWKS cache duration                                                                             |
| `GATEWAY_GATEWAY_AUDIENCE`             | string | `tool-gateway` | —        | Expected `aud` claim value                                                                      |
| `GATEWAY_HOSTED_MODE`                  | bool   | `false`        | —        | Enable hosted multi-tenant mode (requires unique `GATEWAY_GATEWAY_AUDIENCE`)                    |
| `GATEWAY_TENANT_ID`                    | string | —              | prod     | Tenant identifier (fallback: `TENANT_ID` env var); required when `GATEWAY_ADMIN_API_KEY` is set |

#### Rate Limiting

| Variable                              | Type | Default | Required | Description                       |
| ------------------------------------- | ---- | ------- | -------- | --------------------------------- |
| `GATEWAY_RATE_LIMIT_WINDOW_MS`        | int  | `60000` | —        | Sliding window duration (ms)      |
| `GATEWAY_RATE_LIMIT_MAX_REQUESTS`     | int  | `1000`  | —        | Max requests per window           |
| `GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE` | int  | `10`    | —        | Max admin requests per IP per min |

> **⚠️ Admin Rate Limiter Scope (IF-7):** The admin endpoint rate limiter uses an
> **in-memory store per replica**. In a multi-replica deployment behind a load
> balancer, each replica maintains independent rate limit state. This means an
> attacker can distribute requests across N replicas to achieve N× the configured
> limit.
>
> **This is acceptable** when the admin API is bound to `127.0.0.1` (the default),
> because only local processes can reach it — the load balancer cannot route
> external traffic to admin endpoints.
>
> **If you expose admin endpoints to a network** (by setting `GATEWAY_ADMIN_HOST`
> to a non-loopback address), you MUST either:
>
> 1. Route all admin traffic to a single replica (sticky sessions or dedicated admin replica), or
> 2. Switch to a Redis-backed rate limiter for admin endpoints (not yet implemented; tracked as a future enhancement).
>
> See also: `internal/gateway/admin_ratelimit.go`

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

| Variable                     | Type | Default  | Required | Description                                               |
| ---------------------------- | ---- | -------- | -------- | --------------------------------------------------------- |
| `GATEWAY_EUNOX_TELEMETRY`    | bool | `true`   | —        | Enable telemetry collection (override: `EUNOX_TELEMETRY`) |
| `GATEWAY_TELEMETRY_FLUSH_MS` | int  | `300000` | —        | Telemetry flush interval (min 1000ms)                     |

---

### Issuer

The issuer reads environment variables without a service prefix.

#### Core

| Variable                | Type   | Default          | Required | Description                            |
| ----------------------- | ------ | ---------------- | -------- | -------------------------------------- |
| `NODE_ENV`              | enum   | `development`    | —        | `development`, `staging`, `production` |
| `EUNOX_DEPLOYMENT_TIER` | enum   | `single-replica` | —        | Deployment tier                        |
| `PORT`                  | int    | `3001`           | —        | HTTP listen port                       |
| `ADMIN_API_KEY`         | string | —                | prod     | Admin endpoint shared secret           |
| `ISSUER_DID`            | string | —                | —        | Issuer DID identifier                  |
| `ISSUER_URL`            | string | —                | —        | Public issuer URL                      |
| `AUDIENCE`              | string | —                | —        | Default token audience                 |
| `LOG_LEVEL`             | string | —                | —        | Logging level                          |

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
| `EUNOX_DEPLOYMENT_TIER`   | enum   | `single-replica` | —        | Deployment tier                                              |
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

---

## Distributed Tracing (OTLP)

All four services ship with OpenTelemetry distributed tracing. Tracing is **opt-in**
and is a no-op (noop provider) when `OTEL_EXPORTER_OTLP_ENDPOINT` is not set.

### Environment Variables

These are standard [OpenTelemetry environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/) and must **not** be prefixed with a service name:

| Variable                      | Default                      | Description                                         |
| ----------------------------- | ---------------------------- | --------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty — tracing disabled)_ | gRPC collector address, e.g. `otel-collector:4317`  |
| `OTEL_EXPORTER_OTLP_INSECURE` | `false`                      | Set `true` to disable TLS (same-cluster collectors) |
| `OTEL_TRACES_SAMPLER_ARG`     | `1.0`                        | Trace sampling ratio in `[0.0, 1.0]`                |

### Service Names

Spans are emitted under the following `service.name` resource attributes:

| Service         | `service.name`    |
| --------------- | ----------------- |
| Gateway         | `gateway`         |
| Issuer          | `issuer`          |
| Minter          | `minter`          |
| Posture Emitter | `posture-emitter` |

### Example: Jaeger (development)

```yaml
# infra/docker-compose.yml snippet
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686" # Jaeger UI
      - "4317:4317" # OTLP gRPC

environment:
  OTEL_EXPORTER_OTLP_ENDPOINT: jaeger:4317
  OTEL_EXPORTER_OTLP_INSECURE: "true"
  OTEL_TRACES_SAMPLER_ARG: "1.0"
```

### Example: OpenTelemetry Collector (production)

```yaml
# Kubernetes ConfigMap snippet
env:
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: "otel-collector.observability.svc.cluster.local:4317"
  - name: OTEL_EXPORTER_OTLP_INSECURE
    value: "true" # TLS termination at collector
  - name: OTEL_TRACES_SAMPLER_ARG
    value: "0.1" # 10 % head-based sampling in production
```

---

## Posture Emitter — Deployment Model

The posture emitter runs as a **singleton sidecar** (one instance per node).
It must never be scaled horizontally on the same node; the SQLite queue
uses an exclusive lock that rejects a second writer.

**Kubernetes**: deploy as a `DaemonSet` with `hostPath` for `POSTURE_DURABLE_QUEUE_PATH`.

**VMs / bare metal**: run as a `systemd` unit; queue path must be on local storage.

For horizontal scaling across nodes or multi-replica deployments see
[`docs/posture-scaling.md`](./posture-scaling.md).

---

## Multi-AZ Reference Architecture

This section documents the recommended high-availability topology for production
deployments. It satisfies the multi-AZ reference architecture requirement from
[`docs/gateway-chokepoint-critique.md`](./gateway-chokepoint-critique.md) §P1-4.

### Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│  Region: us-east-1 (or equivalent)                                │
│                                                                   │
│  ┌────────────────────────────┐   ┌────────────────────────────┐  │
│  │  Availability Zone A       │   │  Availability Zone B       │  │
│  │                            │   │                            │  │
│  │  ┌──────────────────────┐  │   │  ┌──────────────────────┐  │  │
│  │  │  Gateway Pod (×N/2)  │  │   │  │  Gateway Pod (×N/2)  │  │  │
│  │  │  port 3002 (public)  │  │   │  │  port 3002 (public)  │  │  │
│  │  │  port 3003 (admin)   │  │   │  │  port 3003 (admin)   │  │  │
│  │  └──────────┬───────────┘  │   │  └──────────┬───────────┘  │  │
│  │             │              │   │             │              │  │
│  │  ┌──────────┴───────────┐  │   │  ┌──────────┴───────────┐  │  │
│  │  │  Issuer Pod (×N/2)   │  │   │  │  Issuer Pod (×N/2)   │  │  │
│  │  │  port 3001           │  │   │  │  port 3001           │  │  │
│  │  └──────────────────────┘  │   │  └──────────────────────┘  │  │
│  │                            │   │                            │  │
│  │  ┌──────────────────────┐  │   │  ┌──────────────────────┐  │  │
│  │  │ Redis Sentinel A     │  │   │  │ Redis Sentinel B     │  │  │
│  │  │ (voting member)      │◄─┼───┼─►│ (voting member)      │  │  │
│  │  └──────────────────────┘  │   │  └──────────────────────┘  │  │
│  │                            │   │                            │  │
│  └────────────────────────────┘   └────────────────────────────┘  │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  Shared Services (region-scoped, AZ-agnostic)               │  │
│  │                                                             │  │
│  │  ┌───────────────────┐  ┌──────────────────┐                │  │
│  │  │  Redis Primary    │  │  Redis Replica   │                │  │
│  │  │  (AZ A)           │  │  (AZ B)          │                │  │
│  │  │                   │◄─┤  (async repl.)   │                │  │
│  │  └───────────────────┘  └──────────────────┘                │  │
│  │                                                             │  │
│  │  ┌───────────────────┐  ┌──────────────────┐                │  │
│  │  │ PostgreSQL        │  │ PostgreSQL       │                │  │
│  │  │ Primary (AZ A)    │  │ Read Replica     │                │  │
│  │  │ (audit writes)    │  │ (AZ B)           │                │  │
│  │  └───────────────────┘  └──────────────────┘                │  │
│  │                                                             │  │
│  │  ┌─────────────────────────────────────────┐                │  │
│  │  │  L7 Load Balancer / Kubernetes Ingress  │                │  │
│  │  │  (routes :443 → gateway :3002)          │                │  │
│  │  │  PodDisruptionBudget: minAvailable=1    │                │  │
│  │  └─────────────────────────────────────────┘                │  │
│  │                                                             │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### Failure Domain Labels

| Component               | Failure Domain | AZ Affinity                                                 |
| ----------------------- | -------------- | ----------------------------------------------------------- |
| Gateway pods            | Pod-level      | Spread across AZ A and AZ B via `topologySpreadConstraints` |
| Issuer pods             | Pod-level      | Spread across AZ A and AZ B                                 |
| Redis Sentinels         | Node-level     | One sentinel per AZ; 3rd sentinel on any AZ for quorum      |
| Redis Primary           | Host-level     | AZ A (Sentinel promotes replica on failure)                 |
| Redis Replica           | Host-level     | AZ B (receives async replication from Primary)              |
| PostgreSQL Primary      | Host-level     | AZ A                                                        |
| PostgreSQL Read Replica | Host-level     | AZ B (audit query reads; enforcement does not depend on it) |
| Load Balancer           | Regional       | Spans both AZs; distributes to healthy gateway pods         |

### RTO / RPO Table

| Failure Scenario                               | RTO (Recovery Time Objective)                   | RPO (Recovery Point Objective)      | Notes                                                                           |
| ---------------------------------------------- | ----------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------- |
| Single gateway pod crash                       | < 30 s                                          | 0 (stateless)                       | Kubernetes restarts pod; other replicas serve traffic                           |
| AZ A network partition                         | < 60 s                                          | 0 (stateless gateway)               | Load balancer stops routing to AZ A; AZ B serves all traffic                    |
| Redis Primary failure                          | < 30 s                                          | Up to last async replication lag    | Sentinel promotes AZ B replica; gateway reconnects automatically                |
| Redis Sentinel quorum loss (≥2 sentinels down) | Manual recovery required                        | N/A                                 | Enforce degraded-mode procedures; see `docs/redis-failure-modes.md`             |
| PostgreSQL Primary failure                     | < 5 min (manual failover) or < 60 s (automated) | Up to WAL lag                       | Audit write failures logged; enforcement unaffected; promote replica            |
| Full AZ A loss                                 | < 2 min                                         | 0 (gateway) / WAL lag (PostgreSQL)  | AZ B serves gateway + issuer; Redis sentinel promotes AZ B replica              |
| Full region loss                               | Manual region failover                          | Depends on cross-region replication | Out of scope for single-region topology; see `docs/multi-region-consistency.md` |

### Kubernetes Topology Configuration

#### Gateway Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
  namespace: eunox-system
spec:
  replicas: 4 # minimum 2; 4 for N+1 redundancy across 2 AZs
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  template:
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: gateway
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: gateway
                topologyKey: kubernetes.io/hostname
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: gateway-pdb
  namespace: eunox-system
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: gateway
```

#### Redis Sentinel (example — adjust for your Redis operator)

```yaml
# Three Sentinels for quorum: one per AZ (AZ A, AZ B) + one tiebreaker
# Primary in AZ A; Replica in AZ B
sentinel:
  replicas: 3
  quorum: 2
  downAfterMilliseconds: 5000
  failoverTimeout: 30000
redis:
  replicas: 2
  persistence:
    enabled: true
    size: 8Gi
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app: redis
          topologyKey: topology.kubernetes.io/zone
```

### Health Check Wiring

```yaml
# Gateway Kubernetes probe configuration
livenessProbe:
  httpGet:
    path: /health/live
    port: 3002
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 3002
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 2

# Optional: wire ION health check as a startup probe if partner federation is in use
startupProbe:
  httpGet:
    path: /healthz/did-ion
    port: 3002
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 6
```

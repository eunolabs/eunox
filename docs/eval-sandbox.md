# Evaluation Sandbox Topology

> **Audience:** New evaluators, proof-of-concept deployments, and developer
> environments that need to test Eunox policy enforcement without a full production
> infrastructure dependency.

---

## Purpose

This document describes a _sandbox topology_ for evaluating the Eunox gateway and
enforcement engine without Redis, PostgreSQL, or any external service dependencies.
This is the correct alternative to an "advisory/bypass" mode: instead of weakening
enforcement semantics, the sandbox isolates the blast radius through topology — using
embedded in-process backends against non-production data.

Full enforcement semantics are preserved. Every enforcement request is evaluated by
the same capability engine, JWKS verifier, and policy engine used in production. The
difference is the _backing stores_: the sandbox uses in-memory stores instead of Redis
and SQLite instead of PostgreSQL.

---

## Sandbox Stack

```
┌─────────────────────────────────────────────────────────────┐
│  Developer Machine / CI Container                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Eunox Gateway (sandbox mode)                       │   │
│  │  GATEWAY_NODE_ENV=development                        │   │
│  │                                                     │   │
│  │  ┌─────────────────┐  ┌──────────────────────────┐  │   │
│  │  │  In-memory       │  │  SQLite audit store      │  │   │
│  │  │  kill-switch     │  │  (file: /tmp/audit.db)   │  │   │
│  │  │  revocation      │  └──────────────────────────┘  │   │
│  │  │  rate limiter    │                                 │   │
│  │  └─────────────────┘  ┌──────────────────────────┐  │   │
│  │                        │  Local policy YAML        │  │   │
│  │                        │  (hot-reload enabled)     │  │   │
│  │                        └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Eunox Issuer (dev mode)                            │   │
│  │  ISSUER_NODE_ENV=development                         │   │
│  │  JWT signing: local dev key (not production key)    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Agent under test                                   │   │
│  │  Connects to gateway on 127.0.0.1:3002              │   │
│  │  Uses sandbox API key (non-production)              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**No external dependencies.** The sandbox runs entirely on a single machine or CI
container. No Redis, no PostgreSQL, no cloud provider, no internet connectivity required
after pulling the container images.

---

## Quick Start

### 1. Start the sandbox with Docker Compose

```bash
# Clone and enter the repo
git clone https://github.com/eunolabs/eunox
cd eunox

# Start sandbox (no Redis, no PostgreSQL)
docker compose --profile sandbox up
```

The sandbox profile starts:

- `gateway` (sandbox mode, port 3002)
- `issuer` (dev mode, port 3001)

### 2. Obtain a sandbox capability token

```bash
# Request a capability token from the dev issuer
curl -s -X POST http://localhost:3001/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: dev-api-key-sandbox" \
  -d '{
    "agentId": "my-agent",
    "capabilities": ["tool:read:*"],
    "ttl": 3600
  }' | jq -r .token
```

### 3. Test enforcement

```bash
TOKEN="<paste token from step 2>"

# Allowed: read operation
curl -s -X POST http://localhost:3002/api/v1/enforce \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{"tool":"filesystem","action":"read","context":{}}' | jq

# Denied: write operation (not in capabilities)
curl -s -X POST http://localhost:3002/api/v1/enforce \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{"tool":"filesystem","action":"write","context":{}}' | jq
```

### 4. Edit policy and see hot-reload

```bash
# Edit the local policy file
$EDITOR infra/sandbox/policy.yaml

# Gateway hot-reloads within 5 seconds (default poll interval)
# No restart required
```

---

## Environment Variables

All sandbox configuration is via environment variables. The sandbox profile sets these
defaults; override them as needed.

| Variable                          | Sandbox Default                               | Description                                    |
| --------------------------------- | --------------------------------------------- | ---------------------------------------------- |
| `GATEWAY_NODE_ENV`                | `development`                                 | Disables Redis requirement, enables dev CORS   |
| `GATEWAY_ISSUER_JWKS_URL`         | `http://localhost:3001/.well-known/jwks.json` | Dev issuer JWKS                                |
| `GATEWAY_REDIS_URL`               | _(empty)_                                     | When empty, in-memory stores are used          |
| `GATEWAY_ADMIN_API_KEY`           | `dev-admin-key`                               | Sandbox-only admin key                         |
| `GATEWAY_POLICY_PATH`             | `./infra/sandbox/policy.yaml`                 | Local policy file                              |
| `GATEWAY_AUDIT_DB`                | `file:/tmp/audit.db`                          | SQLite audit database                          |
| `GATEWAY_TOKEN_CACHE_TTL_SECONDS` | `30`                                          | Enable token cache for sandbox                 |
| `ISSUER_NODE_ENV`                 | `development`                                 | Dev issuer: no production signing key required |
| `ISSUER_SIGNING_KEY_PATH`         | `./infra/sandbox/dev-signing-key.pem`         | Dev signing key                                |

---

## What the Sandbox Does NOT Do

The following production features are **intentionally disabled** in the sandbox to
eliminate external dependencies:

| Feature          | Production                            | Sandbox                        |
| ---------------- | ------------------------------------- | ------------------------------ |
| Kill-switch      | Redis pub/sub (sub-second)            | In-memory (process-local only) |
| Revocation store | Redis set                             | In-memory map                  |
| Rate limiter     | Redis-backed (shared across replicas) | In-memory (single process)     |
| DPoP JTI store   | Redis GETDEL                          | In-memory map                  |
| Audit store      | PostgreSQL                            | SQLite file                    |
| Multi-replica    | Yes (N replicas, shared Redis)        | No (single process)            |
| TLS              | Required in production                | Disabled (HTTP only)           |

**Enforcement semantics are identical.** The policy engine, capability token
verification, condition evaluation, and obligation handling are the same code paths
used in production. The only difference is the backing stores.

---

## What the Sandbox is NOT For

The sandbox is **not** a substitute for a production deployment in:

1. **Load testing.** In-memory stores do not reflect Redis latency or PostgreSQL
   write throughput. Use the staging topology for performance testing.

2. **Multi-agent concurrency testing.** The single-process in-memory kill-switch does
   not simulate Redis pub/sub propagation delays. For kill-switch propagation tests,
   use a local Redis container (`docker compose --profile redis up`).

3. **Revocation validation.** The in-memory revocation store is reset on restart.
   For revocation tests, use a Redis container.

4. **Compliance evidence.** Sandbox audit logs (SQLite) are not tamper-evident and
   cannot be used as SOC 2 or HIPAA evidence. Use PostgreSQL with the audit chain
   verification tool.

---

## Upgrading from Sandbox to Production

When you are ready to move from sandbox to a production or staging deployment:

1. Provision Redis (Sentinel or Cluster) — see `docs/deployment.md §Redis`
2. Provision PostgreSQL — see `docs/deployment.md §Database`
3. Set `GATEWAY_NODE_ENV=production` and `GATEWAY_REDIS_URL=<sentinel-url>`
4. Run the production Redis HA validation: `GATEWAY_NODE_ENV=production ./gateway`
   will exit with a clear error if single-node Redis is detected
5. Replace the sandbox signing key with a production KMS-backed key
6. Run `docs/runbooks/gateway-triage.md §Pre-launch checklist`

See `docs/deployment.md` for the full production deployment guide and the multi-AZ
reference architecture.

---

## Sandbox Docker Compose Profile

The sandbox profile is defined in `infra/docker-compose.yml` under the `sandbox`
profile. Key differences from the `full` profile:

- No Redis or PostgreSQL containers
- No volume mounts for production secrets
- Hot-reload policy from local `infra/sandbox/policy.yaml`
- Dev signing key (RSA-2048, generated at first run if missing)

See `infra/docker-compose.yml` for the complete configuration.

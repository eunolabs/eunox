# Deployment Notes

Stage 1 does not require deployment: `@euno/mcp` runs locally as a stdio or
HTTP MCP proxy and writes local audit evidence under `~/.euno/`.

The hosted platform services are frozen during Stages 1–2 and are not the
recommended entry point for new users. When deploying the platform for an
internal design partner, use the current workspace paths:

| Service | Workspace | Default port |
| --- | --- | --- |
| Capability Issuer | `euno-platform/packages/capability-issuer` | 3001 |
| Tool Gateway | `euno-platform/packages/tool-gateway` | 3002 |
| Shared infra implementations | `euno-platform/packages/common-infra` | n/a |
| Public shared contract | `public/packages/common` | n/a |

## Build and validation

From the repository root:

```bash
npm install
npm run lint
npm run test
npm run build
```

## Configuration

Generate service-specific environment templates with the CLI:

```bash
npm run build -w @euno/cli
euno config dump-template --service issuer > euno-platform/packages/capability-issuer/.env.example
euno config dump-template --service gateway > euno-platform/packages/tool-gateway/.env.example
```

Production deployments need an issuer signing key, a gateway verifier
configuration, a protected backend URL, and the selected optional backing stores
(Redis/Postgres/KMS) configured through the typed config schema in
`public/packages/common/src/config/schema.ts` and the implementations in
`euno-platform/packages/common-infra`.

## Containerization

There are no maintained Dockerfiles in the repository today. If a design partner
needs containers before the hosted platform is productized, build from the root
workspace so `@euno/common-core`, `@euno/common-infra`, and the target service are
compiled together. Do not resurrect old `packages/*` Dockerfile snippets; they
predate the two-folder split and are intentionally removed from this guide.

---

## Audit Ledger backend selection (DI-2)

The gateway's cryptographic audit ledger supports two PostgreSQL backends.
Choose the right one for your deployment topology.

### `PostgresLedgerBackend` — global advisory lock (simple; single-tenant or low-write deployments)

Set `AUDIT_LEDGER_BACKEND=postgres`.

Every append acquires `pg_advisory_xact_lock`, a cluster-wide exclusive lock.
All replicas and all tenants queue behind the same lock, so peak write throughput
is bounded by the lock-round-trip latency (~1–5 ms on a local cluster → roughly
**200–1 000 appends / second** for the whole cluster regardless of replica count).

This backend is the correct choice when:
- You have a single gateway replica, **or**
- You have a single active tenant, **or**
- Your audit write rate is comfortably below ~500 appends / second.

For multi-tenant deployments, you can enable per-tenant advisory lock sharding
(`advisoryLockMode: 'per-tenant'`) to reduce per-tenant lock-wait latency:
different tenants will no longer block each other at the advisory-lock step.
**Note:** total cluster throughput is still bounded by the global `seq` primary
key — concurrent writers from different tenants race on INSERT and may trigger
retries (up to 3, with linear back-off).  Per-tenant mode is **not** a
throughput multiplier; it is a latency optimisation for multi-tenant workloads
at moderate concurrency.  For true throughput scaling, use
`PerReplicaPostgresLedgerBackend` instead (set `advisoryLockMode: 'per-tenant'`
in code; this is not yet exposed as a standalone env var — wire it via
`createLedgerSignerFromConfig` options).

### `PerReplicaPostgresLedgerBackend` — lock-free (recommended for multi-replica or multi-tenant production)

Set `AUDIT_LEDGER_BACKEND=per-replica-postgres`.

**This is the recommended default for any Stage 3+ production deployment.**

Each gateway replica maintains its own independent chain segment in the same
PostgreSQL table.  Write serialisation is handled by an in-process queue
(no cross-replica advisory lock), so throughput scales **linearly with the
number of replicas**:

| Replicas | Approx. cluster appends / s |
|----------|-----------------------------|
| 1 | ~200–1 000 |
| 2 | ~400–2 000 |
| 4 | ~800–4 000 |
| N | N × (200–1 000) |

Use `AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS` (default: 60 000 ms) and
`AUDIT_LEDGER_S3_BUCKET` to enable periodic `CrossChainAnchor` snapshots that
bind all replica chains into a single `SignedCrossChainCommitment`, providing
cross-replica tamper evidence equivalent to the global chain.

> **Schema note:** `PerReplicaPostgresLedgerBackend` uses a different table
> schema (`euno_audit_ledger_v2` by default, `record_id TEXT PRIMARY KEY`).
> Do not reuse the `euno_audit_ledger` table created by `PostgresLedgerBackend`;
> the two schemas are incompatible.  Set `AUDIT_LEDGER_TABLE` to a distinct name
> if you need both backends in the same database.

### HMAC secret provisioning

Both backends require `AUDIT_LEDGER_HMAC_SECRET` — a 256-bit secret used for
per-row tamper detection.  Generate one with:

```bash
openssl rand -hex 32
```

Store it in your secrets manager (Azure Key Vault, AWS Secrets Manager,
GCP Secret Manager, or HashiCorp Vault) and inject it at runtime.  **Never
commit the secret to source control.**

See `docs/runbooks/ledger-hmac-rotation.md` for the rotation procedure.

---

## Minter production configuration (Task 1)

The API-key minter enforces **fail-closed startup** when `NODE_ENV=production`.
The following env vars **must** be set; the minter refuses to start if any are
absent and logs a single error message listing all violations:

| Env var | Requirement |
|---|---|
| `MINTER_ADMIN_API_KEY` | Secret value ≥ 32 characters; the default `dev-admin-key` cannot be used in production. |
| `MINTER_PEPPER_HEX` | 64-character hex string (32-byte pepper); generate with `openssl rand -hex 32`. |
| `MINTER_KMS_PROVIDER` **or** `MINTER_PRIVATE_KEY_PEM` + `MINTER_PUBLIC_KEY_PEM` | At least one signing-key source must be configured; ephemeral keys are not permitted. |
| `MINTER_AUDIT_DB_URL` | Postgres connection string for the durable mint-audit store. |
| `MINTER_API_KEY_DB_URL` | Postgres connection string for the durable API-key store (Task 2). |

Additionally, any Redis URL that is configured (`REDIS_URL`, `ANOMALY_REDIS_URL`,
`MINTER_PING_REDIS_URL`) must use a Sentinel or Cluster scheme in production
(see §"Redis HA for production" below).

Development and CI clusters may omit any of these variables; the minter will
start with safe in-process fallbacks (no warnings emitted for absent variables
in non-production environments).

---

## Durable API-key store (Task 2)

Set `MINTER_API_KEY_DB_URL` to a Postgres connection string so that issued API
keys, their revocation status, and their policy-capability mappings survive
service restarts and rolling deploys.

```
MINTER_API_KEY_DB_URL=postgres://minter_app:secret@db:5432/minter_keys
```

### Schema

The `PostgresApiKeyStore` manages a single `api_keys` table.  To let the
minter create the table at startup, set `MINTER_API_KEY_SCHEMA_INIT=true`.
For production deployments, prefer running DDL via a dedicated migration
tool under a privileged role:

```sql
CREATE TABLE IF NOT EXISTS api_keys (
  id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  prefix           TEXT        NOT NULL UNIQUE,
  key_digest       TEXT        NOT NULL,
  hmac_key_version TEXT        NOT NULL,
  tenant_id        TEXT        NOT NULL,
  policy_id        TEXT        NOT NULL,
  capabilities     JSONB       NOT NULL DEFAULT '[]',
  scopes           TEXT[]      NOT NULL DEFAULT '{}',
  label            TEXT,
  created_at       TIMESTAMPTZ NOT NULL,
  last_used_at     TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS api_keys_policy_idx ON api_keys (policy_id)
  WHERE revoked_at IS NULL;
```

### Role-level access control

The minter's application role (`minter_app`) needs `INSERT`, `SELECT`, and
`UPDATE` on `api_keys`.  It does not need `DELETE` or `TRUNCATE`.

For hardened multi-tenant deployments, enable PostgreSQL Row-Level Security on
`api_keys` — see §"Minter database multi-tenancy isolation (OQ-2)" below.

---

## Mint audit guarantees (Task 3)

Audit writes are **synchronous and mandatory**.  The mint route does not return
a `200 OK` until `auditStore.record()` has completed successfully.

If the audit store is unavailable (network partition, database outage, etc.)
the mint request fails with **503 Service Unavailable** and the capability token
is not returned to the client.  The client should treat a 503 as a transient
failure and retry.

### Rationale

Separating the mint decision (token issuance) from the audit record would allow
a token to be issued but not audited.  Because the mint audit trail is the
primary forensics artefact for key-compromise blast-radius enumeration (see
`docs/security/minter-threat-model.md §2–3`), losing audit records is a higher
risk than occasionally failing a mint request.

### Alert on persistent audit failures

The `euno_minter_audit_failure_total{stage="write"}` counter increments on
every failed audit write.  Configure an alert that fires when the counter grows
for more than 1 minute:

```yaml
- alert: MinterAuditStoreUnavailable
  expr: increase(euno_minter_audit_failure_total{stage="write"}[1m]) > 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: Minter audit store is rejecting writes
    description: >
      Mint requests are failing with 503 because the audit store is unavailable.
      All capability token issuance is blocked until the audit store recovers.
```

Load this rule alongside `euno-platform/packages/api-key-minter/prometheus/minter-alert-rules.yaml`.

---

## GCP Cloud KMS per-tenant key isolation (DI-1)

When `MINTER_KMS_PROVIDER=gcp-cloudkms`, **`MINTER_TENANT_KEY_MAP` is required**.

Unlike Azure Key Vault and AWS KMS, GCP Cloud KMS cannot scope signing
credentials to individual tenants through shared signer config.  All tenants
that share a default GCP signing key share the same token-issuing surface — a
compromise of one tenant's token allows minting tokens for other tenants.

`MINTER_TENANT_KEY_MAP` must be a JSON object mapping each tenant audience to a
full `CryptoKeyVersion` resource path:

```bash
MINTER_TENANT_KEY_MAP='{"tenant-acme":"projects/my-proj/locations/us-east1/keyRings/minter/cryptoKeys/acme-signing/cryptoKeyVersions/1","tenant-beta":"projects/my-proj/locations/us-east1/keyRings/minter/cryptoKeys/beta-signing/cryptoKeyVersions/1"}'
```

The minter will refuse to start when this variable is absent for GCP, logging a
clear error message referencing `docs/security/minter-threat-model.md §1`.

---

## Minter database multi-tenancy isolation (OQ-2)

The `mint_audit` table uses application-layer `tenant_id` filtering: every query
includes `WHERE tenant_id = $1` so a single Postgres database can serve multiple
tenants.  This is correct but relies on the application never issuing a
cross-tenant query.

For hardened multi-tenant deployments, enable **PostgreSQL Row-Level Security
(RLS)** on the `mint_audit` and `api_keys` tables so the database itself enforces
the `tenant_id` boundary even if a bug or compromise allows a cross-tenant query
through the application layer.

### Enabling RLS (run once per database, requires a Postgres superuser)

```sql
-- Set the application user (replace 'minter_app' with your actual role).
-- The minter connects as this role; all queries are filtered by the policy.

-- 1. Enable RLS on audit table.
ALTER TABLE mint_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE mint_audit FORCE ROW LEVEL SECURITY;

-- 2. Create a policy that restricts read/write to the current tenant context.
--    The application sets the tenant via a session-local parameter before each query:
--    SET LOCAL euno.tenant_id = 'tenant-acme';
CREATE POLICY mint_audit_tenant_isolation ON mint_audit
  USING (tenant_id = current_setting('euno.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('euno.tenant_id', true));

-- 3. Repeat for api_keys table.
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON api_keys
  USING (tenant_id = current_setting('euno.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('euno.tenant_id', true));

-- 4. Grant the application role SELECT/INSERT/UPDATE/DELETE (no BYPASSRLS).
GRANT SELECT, INSERT, UPDATE, DELETE ON mint_audit TO minter_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO minter_app;
```

> **⚠️ DO NOT apply this RLS configuration yet.** The minter application does not
> currently inject `SET LOCAL euno.tenant_id = ...` before each query.  Applying
> `ENABLE ROW LEVEL SECURITY` and the policy without that application-layer wiring
> **will break all writes immediately** — every INSERT/UPDATE will be blocked by the
> policy.  This SQL is provided as a readiness reference so the schema migration is
> prepared when the application-layer wiring is completed.  Before applying, verify
> that OQ-2 in `docs/architecture-review-2026-05.md` has been marked "Done" with
> the session-parameter wiring confirmed in the implementation notes.

---

## Redis HA for production (CR-3)

The gateway and issuer use Redis as a shared backing store for four
runtime-security state stores:

| Store | Purpose | Default fail mode |
|---|---|---|
| Revocation (`RevocationStore`) | JTI block-list | fail-closed → 401 all traffic |
| Kill-switch (`KillSwitchManager`) | Global / session / agent kill | local cache only until Redis recovers |
| Call counters (`CallCounterStore`) | Per-token `maxCalls` enforcement | fail-open: per-replica counting |
| DPoP replay (`DpopReplayStore`) | Proof-replay prevention | fail-open: replay accepted |

A single-node Redis instance (`k8s/redis.yaml`) is provided for development
and pilot clusters **only**.  For production you **must** replace it with a
high-availability Redis deployment.

### Choosing an HA topology

| Option | Minimum nodes | Automatic failover | Horizontal scale |
|---|---|---|---|
| **Redis Sentinel** | 3 sentinels + 1 replica | ✓ (sentinel quorum) | ✗ (single primary) |
| **Redis Cluster** | 6 nodes (3 primary + 3 replica) | ✓ (per-shard) | ✓ |
| **Managed Redis** | varies by provider | ✓ | depends on tier |

Recommended production choices:
- **Azure Cache for Redis** — Standard C1+ tier (primary/replica pair) or
  Premium tier for cluster mode and geo-replication.
- **AWS ElastiCache (Redis OSS)** — cluster mode enabled, ≥ 2 shards,
  Multi-AZ automatic failover.
- **GCP Memorystore for Redis** — Standard tier (read replicas + automatic
  failover) or Cluster tier.
- **Self-managed Redis Sentinel** — ≥ 3 sentinels, quorum 2, at least one
  replica.

### URL formats

**Redis Sentinel** (ioredis `sentinels` array via connection string):
```
redis+sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379?name=mymaster
```
or use the ioredis `Sentinel` constructor via `REDIS_URL`.

**Redis Cluster**:
```
# Multiple seed nodes separated by commas
redis://redis-node-0:6379,redis-node-1:6379,redis-node-2:6379
```

**TLS** (prefix `rediss://`):
```
rediss+sentinel://sentinel1:26379,sentinel2:26379?name=mymaster
```

The gateway accepts any URL that `ioredis` understands.  Sentinel and
Cluster URLs are automatically recognised by the startup validator (CR-3) and
suppress the single-node warning.  A URL containing commas (multiple seed
nodes) is treated as a Cluster URL.

### Per-store Redis URL overrides

Each control-surface store can point at its own dedicated Redis instance.
This is recommended so an outage on one store does not cascade to others:

| Env var | Store |
|---|---|
| `REVOCATION_REDIS_URL` | Revocation + epoch stores |
| `KILL_SWITCH_REDIS_URL` | Kill-switch manager |
| `CALL_COUNTER_REDIS_URL` | maxCalls call-counter store |
| `REDIS_URL` | Shared fallback for any store that lacks a dedicated URL |

### Grace period (brief Redis blip tolerance)

Set `REDIS_GRACE_PERIOD_MS=5000` (recommended production value) so a brief
Redis network blip (≤ 5 seconds) does not immediately cause a service
brownout.  During the grace window the revocation store serves its local
write-through cache: tokens confirmed revoked locally are still denied;
tokens not yet seen locally are allowed through.  After the grace window, the
configured `REVOCATION_UNAVAILABLE_MODE` applies (default: `fail-closed`).

```
REDIS_GRACE_PERIOD_MS=5000
```

If you also set `REVOCATION_STALE_READABLE=true`, the grace period is
redundant (the store always serves from local cache on Redis outage) but
harmless.

### Startup validation

When `NODE_ENV=production` and a Redis URL is configured that does not
match a Sentinel or Cluster pattern, the gateway **refuses to start** with a
fatal error:

```
CR-3: Gateway refused to start — REDIS_URL appears to point at a single-node Redis instance...
```

This check is **fatal in production** (Task 4).  Pilot and development clusters
may continue to use single-node Redis (`redis://` scheme) by setting
`NODE_ENV=development`.

### Alerting

Load `euno-platform/packages/tool-gateway/prometheus/gateway-alert-rules.yaml`
into your Prometheus instance.  The `EunoGatewayRevocationStoreUnavailable`
alert fires when `euno_gateway_revocation_unavailable_total` increments for
2 consecutive minutes, which under fail-closed mode means all traffic is
being denied.

---

## Source IP trust (CR-2)


Set `ENFORCE_SOURCE_IP_MODE=gateway` (the default) so the gateway derives the
effective source IP from the TCP connection / `X-Forwarded-For` headers rather
than accepting the client-supplied `context.sourceIp`.

When the gateway sits behind a reverse proxy or load balancer, also set
`TRUST_PROXY` to the appropriate value (e.g. `1` for one hop, or a CIDR of your
load-balancer IP range).  Misconfiguring `TRUST_PROXY` with a too-broad value can
allow clients to spoof their IP via forged `X-Forwarded-For` headers.

---

## Egress network boundaries (Task 5)

The Kubernetes network policies in `k8s/network-policies.yaml` follow a
**production-safe default**: only in-cluster pod selectors are allowed in
egress rules.  No `0.0.0.0/0` or `::/0` ipBlock rules appear in that file.

### Base manifest (`network-policies.yaml`)

The base manifest permits egress from gateway and issuer pods to:

| Destination | Rule type |
|---|---|
| kube-system (DNS) | `namespaceSelector` |
| In-cluster Redis (`app=redis`) | `podSelector` |
| Capability Issuer (`app=capability-issuer`) | `podSelector` |
| In-cluster services (gateway proxy targets) | `podSelector: {}` (gateway only) |

All other egress, including to managed Redis endpoints and external backend
services, must be explicitly added as `ipBlock` rules scoped to the private
endpoint CIDRs of those services.

### Adding managed Redis and backend CIDRs

Uncomment and fill in the placeholder `ipBlock` examples in
`network-policies.yaml` once you know the CIDRs:

```yaml
# Managed Redis private endpoint (add under gateway and issuer egress):
- to:
  - ipBlock:
      cidr: 10.0.0.0/28      # replace with actual private endpoint CIDR
  ports:
  - protocol: TCP
    port: 6380                # 6380 for Azure Cache TLS; 6379 for plain

# External backend services (add under gateway egress):
- to:
  - ipBlock:
      cidr: 203.0.113.0/24   # replace with actual backend CIDR
  ports:
  - protocol: TCP
    port: 443
```

### Dev / staging clusters

In environments where CIDRs are not yet known, apply the broad-egress overlay:

```bash
kubectl apply -f k8s/network-policies.yaml
kubectl apply -f k8s/network-policies-dev-overlay.yaml
```

`network-policies-dev-overlay.yaml` adds **separate** NetworkPolicy objects
(labelled `euno.dev/dev-only: 'true'`) that allow broad internet egress.
Because Kubernetes NetworkPolicy is additive, this overlay opens the firewall
surface without modifying the base manifest.

**Do not apply the overlay in production clusters.**

### Kustomize / Helm integration

In a Kustomize setup, add `network-policies-dev-overlay.yaml` to `resources:`
only in your dev/staging overlay directory.  The production base directory
should include only `network-policies.yaml`.

In Helm, conditionally render the overlay template using a value such as
`networkPolicy.devEgressOverlay: true` set per environment.


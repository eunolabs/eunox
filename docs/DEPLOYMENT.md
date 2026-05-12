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

For multi-tenant deployments that stay within the throughput envelope, enable the
per-tenant advisory lock sharding to allow concurrent writes from independent
tenants (set `advisoryLockMode: 'per-tenant'` in code; this is not yet exposed as
a standalone env var — wire it via `createLedgerSignerFromConfig` options).

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

> **Note:** This RLS configuration is a hardening option — the minter application
> does not yet inject `SET LOCAL euno.tenant_id = ...` before each query.  Enabling
> RLS without that change will block all writes.  Wiring the session parameter is
> a future hardening task tracked in the architecture review.

---

## Source IP trust (CR-2)

Set `ENFORCE_SOURCE_IP_MODE=gateway` (the default) so the gateway derives the
effective source IP from the TCP connection / `X-Forwarded-For` headers rather
than accepting the client-supplied `context.sourceIp`.

When the gateway sits behind a reverse proxy or load balancer, also set
`TRUST_PROXY` to the appropriate value (e.g. `1` for one hop, or a CIDR of your
load-balancer IP range).  Misconfiguring `TRUST_PROXY` with a too-broad value can
allow clients to spoof their IP via forged `X-Forwarded-For` headers.


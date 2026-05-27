# Issuer Operator Runbook

## Deployment Topology

The capability issuer runs as an Express service (`internal/issuer`) behind the gateway. In the hosted product it is deployed as a container alongside the gateway and KMS. In self-host mode it is included as the `issuer` service in `infra/docker-compose.yml` (full profile).

```
Client → [API Gateway :3002] → [Capability Issuer :3001] → [KMS Signer]
                                        ↓
                              [Identity Provider (Entra/Cognito/GCP)]
```

## Rate Limiting

Per-subject rate limiting is enforced before any signing operation. The bucket key is `(tenantId, userId, agentId, jti, ip)`.

### Default parameters (hosted)

| Parameter                | Default            | Env var override            |
| ------------------------ | ------------------ | --------------------------- |
| `windowSeconds`          | 60                 | `RATE_LIMIT_WINDOW_SECONDS` |
| Recommended hosted limit | 20 requests/window | `RATE_LIMIT_MAX_REQUESTS`   |

Rate limiting applies equally to `/issue`, `/attenuate`, and `/renew`. A denied request returns HTTP 429 with a `Retry-After` header indicating seconds until the window resets.

### Fail-closed semantics

If the rate limiter throws an unexpected error the issuer **denies** the request (429) rather than failing open. This prevents a limiter outage from becoming an unlimited issuance window.

## Token Attenuation & Renewal Configuration

- `POST /api/v1/attenuate` — attenuates a parent token to a narrower capability set. Inherits `cnf.jkt` and `region` from the parent.
- `POST /api/v1/renew` — renews an expiring token, preserving `cnf.jkt`, `region`, and `policyHash`.

Both endpoints use the same rate limiter as `/api/v1/issue` but with a different bucket key: `/attenuate` and `/renew` include the parent/current token `jti` in the subject, while fresh `/issue` requests do not. They share the same limiter policy (window, max-requests) but do **not** share the same per-subject bucket as `/issue`.

## KMS Key Rotation

1. Generate new key pair in KMS.
2. Add new public key to `/.well-known/jwks.json` (multi-key JWKS).
3. Update the provider-specific signing-key env var on the issuer deployment:
   - Azure Key Vault: `AZURE_KEYVAULT_KEY_NAME` / `AZURE_KEYVAULT_KEY_VERSION`
   - AWS KMS: `AWS_KMS_KEY_ID`
   - GCP Cloud KMS: `GCP_KMS_KEY_NAME` / `GCP_KMS_KEY_VERSION`
4. Roll pods. New tokens are signed with the new key; verifiers accept both keys.
5. After all old tokens have expired, remove the old key from JWKS.

## Alerting

Wire Prometheus alerts on:

- `eunox_issuer_issuance_rate_limit_denied_total` — spike indicates abuse or misconfiguration.
- `eunox_issuer_issuance_total{outcome="error"}` — sustained errors indicate KMS or IdP degradation.
- p99 latency of `/api/v1/issue` > 2s — KMS or IdP degradation.

## Multi-Replica Considerations

When running more than one issuer replica (or multiple regions in an
active/active topology), several state stores transition from per-pod
in-memory maps to fleet-wide Redis-backed counters. The table below
lists every store, its default backing, the minimum replica count at
which Redis becomes **required**, and the relevant env var.

| Store                                                          | Default backing                                     | Redis-required at    | Env var                                                                   | Notes                                                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------- | --------------------------------------------------- | -------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Issuance rate limiter**                                      | In-memory per replica                               | ≥ 2 replicas         | `REDIS_URL` (or `ISSUANCE_RATE_LIMIT_KEY_PREFIX` for namespace isolation) | Without Redis each pod enforces the limit independently; effective budget is `ISSUANCE_RATE_LIMIT_MAX × replica-count`. `EUNOX_DEPLOYMENT_TIER=multi-replica` with `NODE_ENV=production` **requires** `REDIS_URL` (schema-enforced).                                                                        |
| **Storage-grant rate limiter**                                 | In-memory per replica                               | ≥ 2 replicas         | `REDIS_URL` (shared) or `STORAGE_GRANT_RATE_LIMIT_KEY_PREFIX`             | Same per-pod multiplication risk as the issuance limiter; enabled only when `STORAGE_GRANTS_ENABLED=true`.                                                                                                                                                                                                  |
| **DB-token rate limiter**                                      | In-memory per replica                               | ≥ 2 replicas         | `REDIS_URL` (shared) or `DB_TOKEN_RATE_LIMIT_KEY_PREFIX`                  | Same per-pod multiplication risk; enabled only when `DB_TOKENS_ENABLED=true`.                                                                                                                                                                                                                               |
| **OIDC state store** (nonce + ID-token-hash replay prevention) | In-memory per replica _(single-replica / dev only)_ | ≥ 2 replicas         | `OIDC_STATE_REDIS_URL` (preferred) or `REDIS_URL` (fallback)              | `RedisOidcStateStore` is now the default when either Redis URL is configured. Without Redis, a replay attack can succeed by targeting a pod that has not seen the original exchange. The factory emits a structured `warn` when falling back to in-memory so misconfigured deployments are visible in logs. |
| **Usage meter** (gateway-side)                                 | In-memory per gateway replica                       | ≥ 2 gateway replicas | `USAGE_METER_REDIS_URL` or `REDIS_URL` on the gateway                     | The issuer itself does not hold a usage meter; metering is gateway-side. Under HA the gateway bootstraps a Redis-backed `UsageMeter` when a Redis URL is available, falling back to in-memory with a `warn`.                                                                                                |
| **Issuer telemetry collector**                                 | In-memory per replica; flushed on graceful shutdown | All replica counts   | `EUNOX_TELEMETRY=1` (opt-in); no Redis path                               | The `IssuerTelemetryCollector` aggregates counters in-process and ships them via the configured telemetry sink (HTTP/stdout) at shutdown. It is not fleet-wide; each replica reports independently. Aggregate fleet-level metrics require summing across replicas at the sink.                              |

### Minimum viable multi-replica setup

For a two-replica issuer with no optional features:

```
REDIS_URL=redis://redis:6379          # shared for rate limiter + OIDC state
OIDC_STATE_REDIS_URL=redis://redis:6379   # explicit; overrides REDIS_URL for OIDC store
EUNOX_DEPLOYMENT_TIER=multi-replica    # enforces REDIS_URL at boot
NODE_ENV=production
```

In this configuration:

- The issuance rate limiter is fleet-wide.
- OIDC replay prevention is fleet-wide (both the nonce/state and the
  ID-token-hash maps are in Redis with per-key TTL).
- Usage metering is gateway-side and requires its own `REDIS_URL`
  on the gateway deployment.

### Single-replica exception

`EUNOX_DEPLOYMENT_TIER=single-replica` (the default) suppresses the
`REDIS_URL` requirement and leaves all stores in-memory. This is the
intended configuration for development and for self-host operators
who have accepted the single-point-of-failure trade-off. Setting
`EUNOX_DEPLOYMENT_TIER=single-replica` on a deployment that is actually
running multiple pods is a misconfiguration that silently degrades
rate-limit enforcement and replay prevention.

---

## Tenant IdP Hot-Reload Semantics (SIGHUP)

`TenantIdpRegistry.reload()` swaps the tenant-provider map synchronously.
This means:

- A request that has already resolved an IdP adapter continues to completion
  on that adapter, even if a SIGHUP arrives mid-flight.
- Requests that start after the reload observe the new provider map and a
  freshly-cleared adapter cache.
- No partial mix of old/new config is exposed within a single issuance
  request; the hand-off boundary is the adapter lookup.

Operationally, treat SIGHUP as **atomic for new requests** and
**drain-safe for in-flight requests**.

---

## Token Revocation

OIDC-path capability tokens are revoked exclusively via the **gateway admin API**
(`eunox revoke <jti>` or `POST /admin/revoke`). The capability issuer maintains
**no separate revocation list**. This means:

- The gateway is the single canonical revocation source for all tokens regardless
  of how they were originally issued (API-key path or OIDC path).
- Revoking a token via the gateway blocks enforcement at the gateway layer; the
  issuer does not need to be notified and takes no additional action.
- Verifiers that bypass the gateway and check the issuer JWKS directly will not
  observe revocations; all enforcement must be routed through the gateway.

This design is intentional: centralising revocation state in the gateway avoids
distributed consensus and keeps the issuer stateless with respect to live tokens.

To revoke a token:

```sh
eunox revoke <token-jti>
# or
curl -X POST https://<gateway>/admin/revoke \
  -H "X-Admin-Api-Key: $EUNOX_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tokenId": "<token-jti>"}'
```

---

## Cross-Chain Anchor (per-replica-postgres backend)

When `AUDIT_LEDGER_BACKEND=per-replica-postgres`, each gateway replica maintains its own independent hash chain. A **cross-chain commitment** periodically snapshots all replica chain tips into a single tamper-evident `SignedCrossChainCommitment` that can be verified externally without database access.

### Enabling the anchor

Set the following environment variables on every gateway replica:

```
AUDIT_LEDGER_BACKEND=per-replica-postgres
ENABLE_CROSS_CHAIN_ANCHOR=true
AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS=60000    # optional, default 60 s
```

The gateway auto-starts a `CrossChainAnchor` on boot. The anchor:

1. Every `AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS` milliseconds, queries `eunox_audit_ledger_v2` for every known replica's latest `(replicaId, seq, tipHash)`.
2. Sorts tips alphabetically by `replicaId` (deterministic leaf ordering).
3. Computes a balanced binary Merkle root over `canonicalSha256(tip)` for each tip.
4. Signs the `CrossChainCommitment` with the same KMS key used for per-record evidence (`AUDIT_SIGNING_KMS_PROVIDER`).
5. Emits a `SignedCrossChainCommitment` to the in-memory ring buffer and to the `eunox_cross_chain_anchor_lag_seconds` Prometheus gauge.

Commitments are stored in-process in a bounded ring buffer (≤ 10 000 entries ≈ 7 days at the default 60 s interval).

### Querying the chain-proof endpoint

```sh
curl -H "X-Admin-Api-Key: $GATEWAY_ADMIN_API_KEY" \
  "https://<gateway>/api/v1/audit/chain-proof?since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z"
```

**Response shape:**

```json
{
  "commits": [
    /* SignedCrossChainCommitment[] */
  ],
  "chainHead": "<hex-encoded SHA-256 of latest commitment in store>"
}
```

| Field       | Description                                                                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `commits`   | Commitments within the `since`/`until` window. Empty array when none match.                                                                                                     |
| `chainHead` | `canonicalSha256` of the most recent commitment across all time (not filtered). Use this to detect gaps between successive calls. `null` if no commitment has been emitted yet. |

**Query parameters:**

| Parameter | Type            | Description                               |
| --------- | --------------- | ----------------------------------------- |
| `since`   | ISO 8601 string | Inclusive lower bound on `commitment.ts`. |
| `until`   | ISO 8601 string | Inclusive upper bound on `commitment.ts`. |

Both bounds are optional. Omit both to retrieve all in-memory commitments.

### Offline verification

Any `SignedCrossChainCommitment` can be verified offline:

```sh
# 1. Fetch the gateway JWKS
curl https://<gateway>/.well-known/jwks.json > jwks.json

# 2. Verify the commitment using any JWT library
# The signature is a base64-encoded digital signature over SHA-256(canonicalJSON(commitment)).
# The canonical form includes all commitment fields EXCEPT signature, keyId, and algorithm.
# Example using the Go eunox CLI:
eunox audit verify-commitment --commitment commit.json --jwks jwks.json
```

The `signature` is a base64-encoded digital signature over `SHA-256(canonicalJSON(commitment))` where the canonical form includes all `CrossChainCommitment` fields **excluding** `signature`, `keyId`, and `algorithm`. The signing key matches the gateway's evidence signing key (same `keyId`).

### Prometheus metric

| Metric                                 | Type  | Description                                                                                                                                           |
| -------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eunox_cross_chain_anchor_lag_seconds` | Gauge | Seconds since the last successful commitment. Zero until first commitment. Alert when this exceeds `2 × AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS / 1000`. |

**Alert rule example (Prometheus):**

```yaml
- alert: CrossChainAnchorLag
  expr: eunox_cross_chain_anchor_lag_seconds > 120
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Cross-chain anchor is behind on {{ $labels.instance }}"
    description: >
      The CrossChainAnchor has not emitted a commitment for
      {{ $value | humanizeDuration }}. This may indicate a Postgres query
      failure. Check the gateway error logs for 'CrossChainAnchor error'.
```

### Security model

- **Authentication**: `GET /api/v1/audit/chain-proof` requires `X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>` (timing-safe comparison). The route is absent (404) when `ENABLE_CROSS_CHAIN_ANCHOR=false`.
- **Signing key**: Commitments are signed by the same KMS key as per-record evidence. An attacker who obtains the HMAC secret (`AUDIT_LEDGER_HMAC_SECRET`) can forge **HMAC metadata** on individual rows but cannot forge the commitment **signature** (which requires the KMS private key). See `docs/security/minter-threat-model.md` and `docs/runbooks/ledger-hmac-rotation.md` for HMAC key rotation procedures.
- **S3 anchoring**: The bootstrap does not wire an S3 client by default. To publish commitments to S3 Object-Lock, construct `PerReplicaPostgresLedgerBackend` with an `S3AnchorClient` in a custom entrypoint. See `CrossChainAnchorOptions` in `pkg/audit/anchor.go`.

### Azure Confidential Ledger (ACL) backend

As an alternative to `per-replica-postgres`, set:

```
AUDIT_LEDGER_BACKEND=acl
AUDIT_LEDGER_ACL_ENDPOINT=https://<name>.confidential-ledger.azure.com
```

The ACL backend uses `DefaultAzureCredential` for authentication (workload identity, managed identity, or `AZURE_*` env vars). It provides TEE-backed immutability with a single-replica hash chain (no cross-replica locking). The ACL backend does not require `CrossChainAnchor` because the Azure Confidential Ledger service provides its own external tamper evidence.

**Prerequisites**: `@azure/confidential-ledger` and `@azure/identity` must be installed in the deployment image.

---

## On-Call Playbook: IdP Outage

The issuer is **fail-closed** on IdP validation failure: if `validateToken()` throws, the request is rejected with 401. Existing valid tokens continue to work (verification is stateless JWKS-based).

**Steps:**

1. Check IdP status page. If IdP is down, inform users; no issuer action needed.
2. If JWKS endpoint is unreachable, the gateway will reject all incoming tokens. Cache JWKS with a TTL and rotate on next successful fetch.
3. Escalate to IdP vendor if outage persists > 15 min.
4. To temporarily allow a specific service account during an IdP outage, contact the eunox platform team; emergency issuance requires out-of-band operator access and is not available via a self-service CLI command.

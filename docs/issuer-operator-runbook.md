# Issuer Operator Runbook

## Deployment Topology

The capability issuer runs as an Express service (`euno-platform/packages/capability-issuer`) behind the gateway. In the hosted product it is deployed as a container alongside the gateway and KMS. In self-host mode it is included as the `issuer` service in `infra/docker-compose.yml` (full profile).

```
Client → [API Gateway :3002] → [Capability Issuer :3001] → [KMS Signer]
                                        ↓
                              [Identity Provider (Entra/Cognito/GCP)]
```

## F-1 Rate Limiting

Per-subject rate limiting is enforced before any signing operation (F-1). The bucket key is `(tenantId, userId, agentId, jti, ip)`.

### Default parameters (hosted)

| Parameter | Default | Env var override |
|-----------|---------|-----------------|
| `windowSeconds` | 60 | `RATE_LIMIT_WINDOW_SECONDS` |
| Recommended hosted limit | 20 requests/window | `RATE_LIMIT_MAX_REQUESTS` |

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
- `euno_issuer_issuance_rate_limit_denied_total` — spike indicates abuse or misconfiguration.
- `euno_issuer_issuance_total{outcome="error"}` — sustained errors indicate KMS or IdP degradation.
- p99 latency of `/api/v1/issue` > 2s — KMS or IdP degradation.

## Multi-Replica Considerations

When running more than one issuer replica (or multiple regions in an
active/active topology), several state stores transition from per-pod
in-memory maps to fleet-wide Redis-backed counters. The table below
lists every store, its default backing, the minimum replica count at
which Redis becomes **required**, and the relevant env var.

| Store | Default backing | Redis-required at | Env var | Notes |
|---|---|---|---|---|
| **Issuance rate limiter** | In-memory per replica | ≥ 2 replicas | `REDIS_URL` (or `ISSUANCE_RATE_LIMIT_KEY_PREFIX` for namespace isolation) | Without Redis each pod enforces the limit independently; effective budget is `ISSUANCE_RATE_LIMIT_MAX × replica-count`. `EUNO_DEPLOYMENT_TIER=multi-replica` with `NODE_ENV=production` **requires** `REDIS_URL` (schema-enforced). |
| **Storage-grant rate limiter** | In-memory per replica | ≥ 2 replicas | `REDIS_URL` (shared) or `STORAGE_GRANT_RATE_LIMIT_KEY_PREFIX` | Same per-pod multiplication risk as the issuance limiter; enabled only when `STORAGE_GRANTS_ENABLED=true`. |
| **DB-token rate limiter** | In-memory per replica | ≥ 2 replicas | `REDIS_URL` (shared) or `DB_TOKEN_RATE_LIMIT_KEY_PREFIX` | Same per-pod multiplication risk; enabled only when `DB_TOKENS_ENABLED=true`. |
| **OIDC state store** (nonce + ID-token-hash replay prevention) | In-memory per replica *(single-replica / dev only)* | ≥ 2 replicas | `OIDC_STATE_REDIS_URL` (preferred) or `REDIS_URL` (fallback) | **CR-1 resolved (2026-05-18):** `RedisOidcStateStore` is now the default when either Redis URL is configured. Without Redis, a replay attack can succeed by targeting a pod that has not seen the original exchange. The factory emits a structured `warn` when falling back to in-memory so misconfigured deployments are visible in logs. |
| **Usage meter** (gateway-side) | In-memory per gateway replica | ≥ 2 gateway replicas | `USAGE_METER_REDIS_URL` or `REDIS_URL` on the gateway | The issuer itself does not hold a usage meter; metering is gateway-side. Under HA the gateway bootstraps a Redis-backed `UsageMeter` when a Redis URL is available, falling back to in-memory with a `warn`. |
| **Issuer telemetry collector** | In-memory per replica; flushed on graceful shutdown | All replica counts | `EUNO_TELEMETRY=1` (opt-in); no Redis path | The `IssuerTelemetryCollector` aggregates counters in-process and ships them via the configured telemetry sink (HTTP/stdout) at shutdown. It is not fleet-wide; each replica reports independently. Aggregate fleet-level metrics require summing across replicas at the sink. |

### Minimum viable multi-replica setup

For a two-replica issuer with no optional features:

```
REDIS_URL=redis://redis:6379          # shared for rate limiter + OIDC state
OIDC_STATE_REDIS_URL=redis://redis:6379   # explicit; overrides REDIS_URL for OIDC store
EUNO_DEPLOYMENT_TIER=multi-replica    # enforces REDIS_URL at boot
NODE_ENV=production
```

In this configuration:
- The issuance rate limiter is fleet-wide.
- OIDC replay prevention is fleet-wide (both the nonce/state and the
  ID-token-hash maps are in Redis with per-key TTL).
- Usage metering is gateway-side and requires its own `REDIS_URL`
  on the gateway deployment.

### Single-replica exception

`EUNO_DEPLOYMENT_TIER=single-replica` (the default) suppresses the
`REDIS_URL` requirement and leaves all stores in-memory. This is the
intended configuration for development and for self-host operators
who have accepted the single-point-of-failure trade-off. Setting
`EUNO_DEPLOYMENT_TIER=single-replica` on a deployment that is actually
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
(`euno revoke <jti>` or `POST /admin/revoke`). The capability issuer maintains
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
euno revoke <token-jti>
# or
curl -X POST https://<gateway>/admin/revoke \
  -H "X-Admin-Api-Key: $EUNO_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tokenId": "<token-jti>"}'
```

---

## On-Call Playbook: IdP Outage

The issuer is **fail-closed** on IdP validation failure: if `validateToken()` throws, the request is rejected with 401. Existing valid tokens continue to work (verification is stateless JWKS-based).

**Steps:**
1. Check IdP status page. If IdP is down, inform users; no issuer action needed.
2. If JWKS endpoint is unreachable, the gateway will reject all incoming tokens. Cache JWKS with a TTL and rotate on next successful fetch.
3. Escalate to IdP vendor if outage persists > 15 min.
4. To temporarily allow a specific service account during an IdP outage, contact the Euno platform team; emergency issuance requires out-of-band operator access and is not available via a self-service CLI command.

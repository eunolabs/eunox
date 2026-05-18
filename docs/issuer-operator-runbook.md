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

## On-Call Playbook: IdP Outage

The issuer is **fail-closed** on IdP validation failure: if `validateToken()` throws, the request is rejected with 401. Existing valid tokens continue to work (verification is stateless JWKS-based).

**Steps:**
1. Check IdP status page. If IdP is down, inform users; no issuer action needed.
2. If JWKS endpoint is unreachable, the gateway will reject all incoming tokens. Cache JWKS with a TTL and rotate on next successful fetch.
3. Escalate to IdP vendor if outage persists > 15 min.
4. To temporarily allow a specific service account during an IdP outage, contact the Euno platform team; emergency issuance requires out-of-band operator access and is not available via a self-service CLI command.

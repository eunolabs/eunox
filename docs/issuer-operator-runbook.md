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

Both endpoints share the same rate-limit bucket as `/api/v1/issue`.

## KMS Key Rotation

1. Generate new key pair in KMS.
2. Add new public key to `/.well-known/jwks.json` (multi-key JWKS).
3. Update `SIGNING_KEY_ID` env var on the issuer deployment.
4. Roll pods. New tokens are signed with the new key; verifiers accept both keys.
5. After all old tokens have expired, remove the old key from JWKS.

## Alerting

Wire Prometheus alerts on:
- `euno_issuance_rate_limited_total` — spike indicates abuse or misconfiguration.
- `euno_issuance_errors_total{code="SIGNING_ERROR"}` — KMS connectivity issue.
- p99 latency of `/api/v1/issue` > 2s — KMS or IdP degradation.

## On-Call Playbook: IdP Outage

The issuer is **fail-closed** on IdP validation failure: if `validateToken()` throws, the request is rejected with 401. Existing valid tokens continue to work (verification is stateless JWKS-based).

**Steps:**
1. Check IdP status page. If IdP is down, inform users; no issuer action needed.
2. If JWKS endpoint is unreachable, the gateway will reject all incoming tokens. Cache JWKS with a TTL and rotate on next successful fetch.
3. Escalate to IdP vendor if outage persists > 15 min.
4. To temporarily allow a specific service account, issue a token manually via `POST /api/v1/oidc/token` with a pre-validated `UserContext` (requires break-glass procedure documented in `docs/break-glass.md`).

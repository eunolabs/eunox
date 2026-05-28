# Gateway Operator Runbook

> **Audience:** Platform operators running the Eunox Tool Gateway in production.
> For development setup, see [docs/repo-guide.md](./repo-guide.md).
> For issuer-specific operations, see [docs/issuer-operator-runbook.md](./issuer-operator-runbook.md).

---

## Deployment Topology

The gateway is a stateless Go binary that enforces capability tokens on every
tool call from an AI agent. A typical production deployment looks like:

```
          ┌──────────────────────────────────────────┐
          │  Load Balancer (L7 / Kubernetes Ingress)  │
          └────────────────┬─────────────────────────┘
                           │
           ┌───────────────┴───────────────┐
           │                               │
    ┌──────┴──────┐                 ┌──────┴──────┐
    │  Gateway-A  │  (AZ-1)         │  Gateway-B  │  (AZ-2)
    │  port 3002  │                 │  port 3002  │
    │  admin 3003 │                 │  admin 3003 │
    └──────┬──────┘                 └──────┬──────┘
           │                               │
           └──────────────┬────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
  │ Redis       │  │ Capability  │  │ Audit DB    │
  │ Sentinel HA │  │ Issuer JWKS │  │ PostgreSQL  │
  └─────────────┘  └─────────────┘  └─────────────┘
```

The gateway does not hold persistent state itself. All state lives in Redis
(kill-switch subscriptions, revocation cache, rate-limit counters, DPoP JTI
store) and the downstream issuer/audit services.

---

## SLA Targets

| Metric | Target | Alert Threshold |
|--------|--------|----------------|
| Availability | 99.9% (43 min/month) | Page on < 99.5% over 5-min window |
| P99 latency (`/api/v1/enforce`) | < 50 ms | Warn at 100 ms; page at 500 ms |
| P99 latency (proxy pass-through) | < backend + 10 ms overhead | Warn at 200 ms above baseline |
| Error rate (5xx) | < 0.1% | Page on > 1% over 5-min window |

---

## Health Check Endpoints

| Endpoint | Port | Meaning |
|----------|------|---------|
| `GET /health/live` | 3002 | Process is alive. Always 200 unless the process is crashed. Wire as Kubernetes `livenessProbe`. |
| `GET /health/ready` | 3002 | Ready to serve traffic. Returns 503 during startup drain or when `IsReady` returns false. Wire as Kubernetes `readinessProbe`. |
| `GET /healthz/did-ion` | 3002 | ION/DID resolver is reachable. Returns 503 when the ION endpoint is down. Wire into external synthetic monitoring if partner federation is in use. |
| `GET /health/live` | 3003 | Admin port liveness (same semantics). |
| `GET /health/ready` | 3003 | Admin port readiness. |

---

## Configuration Reference (Key Variables)

All environment variables are prefixed `GATEWAY_` at runtime (the config loader
prepends the service prefix). See `docs/deployment.md §Gateway` for the full list.

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `GATEWAY_NODE_ENV` | Yes | `development` | `production` enables HA validation and CORS enforcement |
| `GATEWAY_PORT` | No | `3002` | Public API port |
| `GATEWAY_ADMIN_PORT` | No | `3003` | Admin API port |
| `GATEWAY_ADMIN_HOST` | Production | — | Bind address for admin port; required in production to prevent public exposure |
| `GATEWAY_ISSUER_JWKS_URL` | Production | — | URL of the capability issuer's JWKS endpoint |
| `GATEWAY_BACKEND_SERVICE_URL` | No | — | Upstream backend to proxy authorized requests to |
| `GATEWAY_REDIS_URL` | Production | — | Primary Redis URL (Sentinel/Cluster required in production) |
| `GATEWAY_KILL_SWITCH_REDIS_URL` | No | falls back to `REDIS_URL` | Override for kill-switch Redis |
| `GATEWAY_REVOCATION_REDIS_URL` | No | falls back to `REDIS_URL` | Override for revocation Redis |
| `GATEWAY_RATE_LIMITER_REDIS_URL` | No | falls back to `REDIS_URL` | Override for rate-limit Redis |
| `GATEWAY_EUNOX_DEPLOYMENT_TIER` | No | `single-replica` | Set `multi-replica` to enforce Redis requirements |
| `GATEWAY_ADMIN_API_KEY` | No | — | Static admin key (deprecated; prefer `ADMIN_JWKS_URI`) |
| `GATEWAY_ADMIN_JWKS_URI` | No | — | JWKS URI for admin JWT auth |
| `GATEWAY_TRUSTED_PROXY_CIDRS` | No | — | Comma-separated CIDRs for XFF trust (e.g., `10.0.0.0/8`) |
| `GATEWAY_EUNOX_JWKS_CACHE_TTL_SECONDS` | No | `300` | Issuer JWKS cache TTL |
| `GATEWAY_RATE_LIMIT_MAX_REQUESTS` | No | `1000` | Max requests per window per client IP |
| `GATEWAY_RATE_LIMIT_WINDOW_MS` | No | `60000` | Rate limit window in milliseconds |

---

## Alert Thresholds

Wire the following Prometheus alerts. Metric names use the `eunox_` prefix.
Metrics marked _(planned)_ are not yet emitted by the gateway and will fire no
alerts until they are added; treat those rules as forward-looking configuration.

### P1 — Immediate Action Required

```yaml
# NOTE: redis_health_state is planned — not yet emitted by the gateway.
- alert: GatewayKillSwitchRedisDown
  expr: redis_health_state{component="killswitch"} == 1
  for: 30s
  annotations:
    summary: "Gateway kill-switch Redis degraded — all enforce/proxy calls are being blocked"

# NOTE: redis_health_state is planned — not yet emitted by the gateway.
- alert: GatewayRevocationRedisDown
  expr: redis_health_state{component="revocation"} == 1
  for: 30s
  annotations:
    summary: "Gateway revocation Redis degraded — uncached token checks fail-closed"

- alert: GatewayHighErrorRate
  expr: rate(eunox_gateway_enforce_total{decision="error"}[5m]) / rate(eunox_gateway_enforce_total[5m]) > 0.01
  for: 5m
  annotations:
    summary: "Gateway enforce error rate > 1%"
```

### P2 — Degraded but Serving

```yaml
# NOTE: redis_health_state is planned — not yet emitted by the gateway.
- alert: GatewayRateLimiterRedisDown
  expr: redis_health_state{component="ratelimit"} == 1
  for: 5m
  annotations:
    summary: "Gateway rate-limiter Redis degraded — per-instance fallback active"

- alert: GatewayHighP99Latency
  expr: histogram_quantile(0.99, rate(eunox_gateway_enforce_duration_seconds_bucket[5m])) > 0.5
  for: 5m
  annotations:
    summary: "Gateway P99 enforce latency > 500ms"

# NOTE: eunox_audit_write_errors_total is planned — not yet emitted by the gateway.
- alert: GatewayAuditWriteErrors
  expr: rate(eunox_audit_write_errors_total[10m]) > 0.1
  for: 10m
  annotations:
    summary: "Sustained audit write failures — ledger may have gaps"
```

### P3 — Advisory

```yaml
# NOTE: redis_health_state is planned — not yet emitted by the gateway.
- alert: GatewayCallCounterRedisDown
  expr: redis_health_state{component="callcounter"} == 1
  for: 15m
  annotations:
    summary: "Gateway call-counter Redis degraded — billing accuracy impacted"

- alert: GatewayIONHealthDegraded
  expr: eunox_gateway_ion_health == 0
  for: 5m
  annotations:
    summary: "ION/DID resolver unreachable — partner federation calls will fail"
```

---

## Recovery Procedures

### Redis Outage

1. **Identify scope:** Check which Redis-backed components are degraded:
   ```bash
   curl -s http://gateway.internal:3002/health/ready | jq .
   ```
   The response body lists degraded components when the gateway is wired with a
   `RedisMonitor`.

2. **Kill switch / revocation degraded (P1):**
   - All enforce calls fail-closed (503). Legitimate traffic is blocked.
   - Escalate to Redis on-call immediately.
   - If Redis cannot recover quickly, consider activating a maintenance window and
     routing traffic to a healthy region.

3. **Rate limiter degraded (P2):**
   - Enforcement continues with per-instance rate limits.
   - Effective aggregate limit = `RATE_LIMIT_MAX_REQUESTS × replica count`.
   - Monitor for abuse spikes; manually block abusive IPs via load balancer rules
     if needed until Redis recovers.

4. **Call counter degraded (P3):**
   - Enforcement continues; call counts are under-reported.
   - Note the outage window and reconcile billing from audit logs after recovery.

5. **Redis recovery:**
   - Verify `redis_health_state` metrics _(planned — not yet emitted)_ return to 0 for all components.
   - Check `/health/ready` returns 200.
   - Review audit logs for the outage window for under-counted usage.

### JWKS Endpoint Unavailable

1. **Within cache window (< `GATEWAY_EUNOX_JWKS_CACHE_TTL_SECONDS` seconds):**
   Enforcement is unaffected. Investigate the issuer service independently.

2. **Cache expired:**
   All enforce/proxy calls return 401. Check issuer service health:
   ```bash
   curl -sf $GATEWAY_ISSUER_JWKS_URL | jq 'keys'
   ```
   If the issuer is down, restore the issuer service — the gateway will resume
   automatically when JWKS becomes reachable again.

3. **Circuit breaker open:**
   The gateway will not retry until the circuit breaker half-opens (default: 30 s).
   Do not restart the gateway to force a retry; this causes a pod churn storm.
   Wait for the circuit breaker to reset naturally once the issuer recovers.

### Kill Switch Accidentally Activated

See [docs/runbooks/kill-switch.md](./runbooks/kill-switch.md) for the full
activation and deactivation procedure.

Quick deactivation:
```bash
curl -X POST https://gateway.internal:3003/admin/kill-switch/global/deactivate \
  -H "Authorization: ******"
```

### Gateway Pod Crash / OOMKilled

1. Check pod logs for the cause:
   ```bash
   kubectl logs -n eunox-system deployment/gateway --previous | tail -50
   ```
2. Check for memory pressure: the gateway does not hold large in-memory caches
   except the JWKS set and the in-process telemetry buffer. OOM is uncommon but
   can occur with very large audit query responses.
3. Increase memory limits (`resources.limits.memory`) if OOM is sustained.
4. Restart is safe — the gateway is stateless. Redis reconnects on next request.

---

## Key Rotation

### Capability Issuer Signing Key

1. Add the new public key to the issuer's JWKS endpoint (alongside the old key).
2. The gateway's JWKS cache will pick up the new key within `GATEWAY_EUNOX_JWKS_CACHE_TTL_SECONDS`.
3. Rotate the signing key in the issuer deployment (see `docs/issuer-operator-runbook.md §KMS Key Rotation`).
4. After all tokens signed by the old key have expired, remove the old key from JWKS.

No gateway restart is required.

### Admin API Key / JWT

1. Update `GATEWAY_ADMIN_API_KEY` or rotate the admin JWKS signing key.
2. If using static key (`GATEWAY_ADMIN_API_KEY`), update the secret in your secrets
   manager and trigger a rolling restart.
3. If using JWT auth (`GATEWAY_ADMIN_JWKS_URI`), rotate the signing key and update
   the JWKS endpoint. The gateway fetches admin JWKS on each admin request — no
   restart required.

---

## Multi-Replica Considerations

When running more than one gateway replica, state stores must be Redis-backed
to avoid per-instance divergence.

| Store | Default backing | Redis-required at | Env var |
|-------|----------------|-------------------|---------|
| Kill-switch subscription | In-memory per replica | ≥ 2 replicas | `GATEWAY_KILL_SWITCH_REDIS_URL` |
| Revocation cache | In-memory per replica | ≥ 2 replicas | `GATEWAY_REVOCATION_REDIS_URL` |
| Rate limiter | In-memory per replica | ≥ 2 replicas | `GATEWAY_RATE_LIMITER_REDIS_URL` |
| Call counter | In-memory per replica | ≥ 2 replicas | `GATEWAY_CALL_COUNTER_REDIS_URL` |
| DPoP JTI store | In-memory per replica | ≥ 2 replicas (replay window risk) | `GATEWAY_DPOP_REDIS_URL` |
| Partner DIDs | In-memory per replica | ≥ 2 replicas | `GATEWAY_PARTNER_DIDS_REDIS_URL` |

Set `GATEWAY_EUNOX_DEPLOYMENT_TIER=multi-replica` to enforce Redis requirements at boot.

**Minimum viable multi-replica configuration:**
```bash
GATEWAY_NODE_ENV=production
GATEWAY_EUNOX_DEPLOYMENT_TIER=multi-replica
GATEWAY_REDIS_URL=redis-sentinel://sentinel:26379/eunox-master
GATEWAY_ISSUER_JWKS_URL=https://issuer.internal/api/v1/jwks
GATEWAY_ADMIN_HOST=127.0.0.1    # bind admin port to localhost only
```

---

## Capacity Planning

The gateway is CPU-bound during token verification (ECDSA/EdDSA signature
checks). Memory usage is low (< 64 MB base + JWKS cache).

| Metric | Typical | Notes |
|--------|---------|-------|
| CPU per 1000 req/s | ~0.5 vCPU | Measured under P256 tokens; EdDSA is ~2× faster |
| Memory | 32–64 MB | Increases with large partner DID registries |
| Redis connections | 4–6 per replica | One per Redis-backed component |

Start with 2 replicas × `requests: {cpu: "250m", memory: "64Mi"}` and scale
horizontally based on `eunox_gateway_enforce_duration_seconds` P99.

---

## Escalation Path

| Symptom | First Responder | Escalate To |
|---------|----------------|------------|
| All requests 503 (Redis down) | Platform on-call | Redis on-call |
| All requests 401 (JWKS expired) | Platform on-call | Issuer on-call |
| Kill switch activated unexpectedly | Platform on-call | Security on-call |
| Audit write errors > 10 min | Platform on-call | Database on-call |
| Partner federation 401 | Platform on-call | Partner integration team |

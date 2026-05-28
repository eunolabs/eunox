# Redis Failure Mode Policies

This document defines the failure mode behavior for each Redis-dependent component
in the Eunox gateway. These policies ensure predictable behavior during Redis
outages and inform operator expectations for incident response.

## Policy Summary

| Component | Failure Policy | Rationale |
|-----------|---------------|-----------|
| Kill Switch | **Fail-Closed** | Unknown state must not allow potentially dangerous agents to operate |
| Revocation | **Fail-Closed** | Revoked tokens must not be accepted when revocation state is unknown |
| Rate Limiter | **Fail-Open** | Temporary over-provisioning is preferable to total service denial |
| Call Counter | **Fail-Open** | Usage tracking can be reconciled; blocking traffic is unacceptable |

## Detailed Policies

### Kill Switch (`pkg/killswitch`)

**Policy: Fail-Closed**

When Redis is unreachable:
- The local pub/sub cache retains the last-known kill state.
- If initial state load fails on startup, **all requests are blocked** until Redis
  recovers and state is loaded.
- The health reporter marks the component as degraded, causing `/health/ready` to
  return 503.

**Rationale:** The kill switch is a security control. Allowing traffic through when
we cannot determine whether an agent/session has been killed could permit malicious
or compromised agents to execute. The blast radius of a false-positive (blocking
legitimate traffic) is preferable to the blast radius of a false-negative (allowing
a killed agent to operate).

**Implementation:** `pkg/killswitch.ResilientRedis` wraps the standard Redis
implementation and ensures fail-closed semantics.

### Revocation (`pkg/revocation`)

**Policy: Fail-Closed**

When Redis is unreachable:
- Tokens recently checked are served from a local TTL cache (default: 60s stale TTL).
- Tokens **not** in the cache are treated as **revoked** (denied).
- The health reporter marks the component as degraded.

**Rationale:** Token revocation is a security boundary. If an operator revokes a
token due to a security incident, that revocation must be honored even if Redis is
temporarily unavailable. The cost of rejecting a few valid requests is far lower
than the cost of accepting a revoked credential.

**Cache behavior:**
- On successful Redis read: result is cached with a timestamp.
- On Redis failure: cache serves entries younger than `StaleTTL`.
- For cache misses during failure: returns "revoked" (fail-closed default).

**Implementation:** `pkg/revocation.ResilientRedis` with `redisfailover.FallbackCache`.

### Rate Limiter (`pkg/ratelimit`)

**Policy: Fail-Open with Local Fallback**

When Redis is unreachable:
- The distributed rate limiter falls back to an **in-memory sliding window** limiter.
- The in-memory limiter applies the same rate/window configuration but is instance-local.
- Effective limits are multiplied by the number of running instances during fallback.
- The health reporter marks the component as degraded.

**Rationale:** Rate limiting protects against abuse but is not a security boundary.
Blocking all traffic due to a Redis outage would cause a complete service outage,
which is disproportionate. The worst case during fallback is that the aggregate rate
limit is `N × per-instance-limit` (where N is the number of instances), which provides
degraded-but-present protection.

**Recovery:** When Redis reconnects, the distributed limiter resumes and the local
fallback state is abandoned. There may be a brief window where limits are slightly
more permissive as the distributed state rebuilds.

**Implementation:** `pkg/ratelimit.ResilientRedisLimiter`.

### Call Counter (`pkg/callcounter`)

**Policy: Fail-Open (Degrade Gracefully)**

When Redis is unreachable:
- Returns a count of 0 (allowing the request).
- Usage data may be under-counted during the outage.
- The health reporter marks the component as degraded.

**Rationale:** Call counters are used for billing and usage tracking, not for
security enforcement. Temporary under-counting during an outage is acceptable
and can be reconciled when Redis recovers (e.g., via audit log replay). Blocking
requests because we can't count them would cause unnecessary service disruption.

**Reconciliation:** Operators should monitor `redis_health_state{component="callcounter"}`
and correlate any degraded periods with audit logs to identify under-counted usage.

**Implementation:** `pkg/callcounter.ResilientRedis`.

## Health Check Integration

The `redisfailover.Monitor` aggregates health state from all Redis-dependent
components. It can be wired into the application's readiness handler to surface
Redis degradation to Kubernetes. When any component is in a degraded state, the
recommended pattern causes:

- `/health/ready` to return HTTP 503 with a JSON body listing degraded components.
- `/health/live` to be **unaffected** (the process is still alive and functional).
- Kubernetes to stop routing traffic to the instance, allowing healthy instances
  to handle load until Redis recovers.

> **Note:** This integration is opt-in. It must be explicitly wired during
> application startup as shown below. The gateway's built-in `/health/ready`
> handler does not consult the monitor unless a `RedisMonitor` dependency is
> provided.

### Wiring the Monitor in Application Startup

```go
monitor := redisfailover.NewMonitor()

// Register components
ksReporter := monitor.Register("killswitch")
revReporter := monitor.Register("revocation")
rlReporter := monitor.Register("ratelimit")
ccReporter := monitor.Register("callcounter")

// Wire up resilient stores
ks := killswitch.NewResilientRedis(ksInner, ksReporter)
rev := revocation.NewResilientRedis(revInner, revReporter, nil)
rl := ratelimit.NewResilientRedis(rlPrimary, rlCfg, rlReporter)
cc := callcounter.NewResilientRedis(ccInner, ccReporter)

// Health check handler
http.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
    if !monitor.IsReady() {
        w.WriteHeader(http.StatusServiceUnavailable)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":   "degraded",
            "degraded": monitor.DegradedComponents(),
        })
        return
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
})
```

## Monitoring & Alerting

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `redis_health_state{component}` | Gauge | 0=healthy, 1=degraded |
| `redis_fallback_cache_hits{component}` | Counter | Cache hits during degradation |
| `redis_fallback_cache_misses{component}` | Counter | Cache misses (triggering policy) |

### Recommended Alerts

- **P1:** Any `redis_health_state == 1` for > 30 seconds on kill-switch or revocation
  (fail-closed means legitimate traffic is being blocked).
- **P2:** Any `redis_health_state == 1` for > 5 minutes on rate-limiter
  (distributed rate limiting is degraded).
- **P3:** `redis_health_state == 1` on call-counter for > 15 minutes
  (billing accuracy is impacted).

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `REDIS_FAILOVER_STALE_TTL_SECONDS` | `60` | How long cached entries are valid during degradation |
| `REDIS_HEALTH_CHECK_INTERVAL_SECONDS` | `5` | How often Redis connectivity is probed |

## Testing Failure Modes

To verify failure mode behavior in staging:

1. **Simulate Redis outage:** Use `redis-cli DEBUG SLEEP 30` or network policy to
   block Redis access.
2. **Observe behavior:**
   - Kill switch: new requests should be blocked (fail-closed).
   - Revocation: uncached tokens should be rejected (fail-closed).
   - Rate limiter: requests should flow with per-instance limits (fail-open).
   - Call counter: requests should flow; counts may be inaccurate (fail-open).
3. **Verify health endpoint:** `/health/ready` should return 503 with degraded components.
4. **Restore Redis:** Verify all components recover and health returns 200.

---

## Non-Redis Failure Modes

This section documents the gateway's behavior when non-Redis dependencies are
unavailable. These failure modes complement the Redis policies above and form the
complete picture of gateway degradation behavior required for operator runbooks
and enterprise readiness reviews.

### JWKS Endpoint Unavailable

The gateway verifies every capability token against the issuer's JWKS endpoint
(`GATEWAY_ISSUER_JWKS_URL`). The `JWKSClient` caches the key set in memory for
a configurable TTL (default: 5 minutes) and wraps fetches in a circuit breaker.

| Scenario | HTTP Behavior | Rationale |
|----------|--------------|-----------|
| JWKS unreachable, cached keys present | Enforcement proceeds normally until the cache TTL expires | Fail-open for the cache window; avoids disruption during transient network blips |
| JWKS unreachable, cache expired (`POST /api/v1/enforce`) | Token verification fails → **200 OK** with `EnforceResponse{decision:"deny"}` | `/enforce` always returns 200; the denial is expressed in the response body |
| JWKS unreachable, cache expired (`ANY /proxy/*`) | Token verification fails → **401 Unauthorized** | The proxy path returns a plain HTTP error rather than an enforcement-response body |
| JWKS circuit breaker open (`POST /api/v1/enforce`) | Returns `JWKS fetch blocked by circuit breaker` error → **200 OK** with deny decision | Same as cache-expired path on `/enforce` |
| JWKS circuit breaker open (`ANY /proxy/*`) | Returns `JWKS fetch blocked by circuit breaker` error → **401 Unauthorized** | Prevents thundering-herd retries against a down issuer |
| JWKS reachable but returns malformed JSON | Same as unreachable (parse error) | Treat malformed key set as unavailable |

**Health surface:** JWKS unavailability is not surfaced on `/health/ready` by default
because the cache may still be valid. Monitor `eunox_jwks_fetch_errors_total`
_(planned — not yet emitted)_ to detect sustained failures before the cache window
expires.

**Operator action:** If the cache has expired, `/proxy` calls will return 401 and
`/enforce` calls will return 200 with a deny decision. The issuer service is the
root cause. See `docs/runbooks/gateway-triage.md` §"All enforcement calls return 401".

### PostgreSQL / Audit Database Unavailable

The gateway writes audit log entries via the `audit.Pipeline` interface. These
writes are **best-effort and non-blocking**: enforcement decisions are returned to
the caller before the audit write completes or is confirmed. A write failure is
logged but does not affect the HTTP response.

| Scenario | HTTP Behavior | Rationale |
|----------|--------------|-----------|
| Audit pipeline write fails | **200/403 enforcement response is unaffected**; write failure logged at `WARN` | Audit is an accounting concern, not a security enforcement boundary |
| Audit query store unavailable (read path) | `GET /api/v1/audit*` returns **503 Service Unavailable** | Query routes cannot serve results; enforcement is unaffected |
| PostgreSQL unreachable at startup (audit only) | Gateway starts normally; audit writes fail until DB recovers | The gateway binary does not hold a startup dependency on the audit DB |

**Operator action:** Monitor `eunox_audit_write_errors_total` _(planned — not yet
emitted)_. Sustained audit failures mean the audit ledger has a gap; reconcile
via log replay when the DB recovers. See `docs/audit-chain-architecture.md` for
the write-ahead buffer and flush guarantee.

### DPoP JTI Store Unavailable

The DPoP replay detection store (`DPoPStore`) is used on every enforce call that
carries a DPoP proof. The gateway ships two implementations:

- **`InMemoryDPoPStore`** (default; no external dependency) — never returns an
  error for `MarkUsed`. An in-process restart clears replay state, creating a
  small window where a captured proof could be replayed. Acceptable for
  single-replica deployments.
- **`RedisDPoPStore`** — backed by Redis. Subject to the same Redis failure modes
  as other components.

| Scenario | HTTP Behavior | Rationale |
|----------|--------------|-----------|
| `InMemoryDPoPStore` in use (no external failure path) | Replay detection always succeeds | No network dependency |
| `RedisDPoPStore` Redis error on `MarkUsed` | DPoP verification returns an error → **401 Unauthorized** | Cannot confirm the proof has not been replayed; fail-closed |
| DPoP proof absent on a sender-constrained token | **401 Unauthorized** with `DPoP proof required` | `cnf.jkt` binding is a hard requirement |

**Operator action:** For `RedisDPoPStore`, a Redis outage will deny all requests
carrying DPoP proofs. Switch to `InMemoryDPoPStore` under `single-replica` deployments
to eliminate this dependency, accepting the reduced replay protection window.

### DID / ION Endpoint Unavailable

The gateway optionally resolves decentralized identifiers via `IONResolver`
(configured via `GATEWAY_ION_RESOLVER_URL`). This path is used for cross-org
partner federation flows.

| Scenario | HTTP Behavior | Rationale |
|----------|--------------|-----------|
| ION endpoint unreachable, partner DID cached | Partner verification proceeds using cached DID document | Short-circuit serves the common case |
| ION endpoint unreachable, DID not cached | Partner token verification fails → **401 Unauthorized** on cross-org calls | Cannot resolve partner public key; fail-closed |
| `GET /healthz/did-ion` called during outage | Returns **503 Service Unavailable** with `{"status":"unhealthy","error":"<error message>"}` | Surfaces the dependency health to external health checks |
| ION endpoint unreachable, local-issuer tokens only | **No impact** | ION resolution is only exercised for partner tokens; local token verification uses the JWKS cache described above |

**Health surface:** `/healthz/did-ion` is the dedicated liveness probe for the
ION endpoint. Wire this into your monitoring stack if you use partner federation.

### Backend Service Unavailable

The gateway proxies authorized requests to a configurable backend
(`GATEWAY_BACKEND_SERVICE_URL`). The proxy path is reached only after all enforcement
checks pass.

| Scenario | HTTP Behavior | Rationale |
|----------|--------------|-----------|
| Backend not configured (`GATEWAY_BACKEND_SERVICE_URL` empty) | **502 Bad Gateway** with `no backend configured` | Misconfiguration error; enforcement is unaffected |
| Backend unreachable (connection refused / timeout) | **502 Bad Gateway** | Standard reverse-proxy behavior; the enforcement decision has already been logged |
| Backend returns 5xx | **5xx forwarded to caller** | The gateway does not retry; the caller is responsible for retry logic |

**Operator action:** Backend unavailability means enforcement is succeeding but
downstream calls are failing. Check the backend service health independently of
the gateway. The gateway access log records `proxy_duration_seconds` which can
be used to correlate backend latency spikes.

## Combined Failure Summary

| Dependency | Failure Policy | Requests Affected | Health Signal |
|------------|---------------|-------------------|---------------|
| Redis (kill switch) | **Fail-closed** | All enforce/proxy | `/health/ready` 503 |
| Redis (revocation) | **Fail-closed** (stale cache window) | All enforce/proxy | `/health/ready` 503 |
| Redis (rate limiter) | **Fail-open** (per-instance fallback) | Enforce/proxy | `/health/ready` 503 |
| Redis (call counter) | **Fail-open** | Enforce/proxy | `/health/ready` 503 |
| JWKS endpoint | **Fail-open** (within cache TTL), then **fail-closed** | All enforce/proxy | `eunox_jwks_fetch_errors_total` |
| Audit database | **Fail-open** (non-blocking writes) | None (enforcement unaffected) | `eunox_audit_write_errors_total` |
| DPoP store (Redis) | **Fail-closed** | Enforce calls with DPoP proofs | Redis health metrics |
| DID/ION resolver | **Fail-closed** (partner federation only) | Cross-org partner calls | `/healthz/did-ion` |
| Backend service | **Fail-open** (502 returned) | Post-enforcement proxy | `eunox_proxy_errors_total` |

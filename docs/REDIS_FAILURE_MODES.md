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

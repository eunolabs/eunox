# Runbook: Gateway Triage

**Severity**: P1 (varies by symptom — see table below)  
**Last Updated**: 2026-05-28  
**Owner**: Platform Operations

## Overview

This runbook is a decision tree for diagnosing gateway-related failures during
an agent workflow incident. It covers the five most common failure categories:

1. [All enforcement calls return 401](#all-enforcement-calls-return-401)
2. [All enforcement calls return 503](#all-enforcement-calls-return-503)
3. [All enforcement calls return 403](#all-enforcement-calls-return-403)
4. [Requests pass enforcement but backend calls fail](#requests-pass-enforcement-but-backend-calls-fail-502)
5. [Requests are being rate-limited unexpectedly](#requests-are-being-rate-limited-429)

For each symptom, follow the branch of the decision tree until you identify the
root cause. Refer to `docs/redis-failure-modes.md` and
`docs/gateway-operator-runbook.md` for detailed recovery procedures.

---

## Quick-Reference: Symptom → Probable Cause

| HTTP Status | Error Message | Probable Cause | Section |
|-------------|--------------|----------------|---------|
| 401 | `token verification failed` | JWKS endpoint down or cache expired | [§1](#all-enforcement-calls-return-401) |
| 401 | `JWT missing required kid header` | Token minted without `kid` claim | [§1](#all-enforcement-calls-return-401) |
| 401 | `JWKS fetch blocked by circuit breaker` | Issuer persistently unreachable | [§1](#all-enforcement-calls-return-401) |
| 401 | `token has expired` | Token TTL exceeded; agent must renew | [§1](#all-enforcement-calls-return-401) |
| 503 | `kill switch check unavailable` | Redis (kill-switch) unreachable | [§2](#all-enforcement-calls-return-503) |
| 503 | `revocation check unavailable` | Redis (revocation) unreachable + cache miss | [§2](#all-enforcement-calls-return-503) |
| 403 | `kill switch active` | Kill switch intentionally or accidentally activated | [§3](#all-enforcement-calls-return-403) |
| 403 | `token revoked` | Token explicitly revoked | [§3](#all-enforcement-calls-return-403) |
| 403 | `capability condition not met` | Time window / IP range / max-calls constraint violated | [§3](#all-enforcement-calls-return-403) |
| 403 | `action not permitted` | Token does not grant the requested tool/action | [§3](#all-enforcement-calls-return-403) |
| 502 | `no backend configured` | `GATEWAY_BACKEND_SERVICE_URL` missing | [§4](#requests-pass-enforcement-but-backend-calls-fail-502) |
| 502 | (upstream error) | Backend service down | [§4](#requests-pass-enforcement-but-backend-calls-fail-502) |
| 429 | `rate limit exceeded` | Request rate above configured limit | [§5](#requests-are-being-rate-limited-429) |

---

## Log Fields to Inspect

Every gateway log entry is structured JSON. Key fields for triage:

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Unique ID; correlate with client `X-Request-Id` header |
| `agent_did` | string | Subject DID from the capability token |
| `decision` | string | `allow`, `deny`, or `error` |
| `reason` | string | Human-readable denial reason |
| `error_code` | string | Machine-readable error code (e.g., `authorization_failed`) |
| `component` | string | `killswitch`, `revocation`, `enforcement`, `proxy`, etc. |
| `duration_ms` | number | Total request duration in milliseconds |
| `redis_health_state` | string | `healthy` or `degraded` (when logged on degradation) |

**Filter by agent DID:**
```bash
kubectl logs -n eunox-system deployment/gateway | \
  jq 'select(.agent_did == "did:web:example.com:agents:triage-123")'
```

**Filter by request ID:**
```bash
kubectl logs -n eunox-system deployment/gateway | \
  jq 'select(.request_id == "a1b2c3d4-...")'
```

**Count denials by reason in the last 5 minutes:**
```bash
kubectl logs -n eunox-system deployment/gateway --since=5m | \
  jq -r 'select(.decision == "deny") | .reason' | sort | uniq -c | sort -rn
```

---

## Metrics to Check First

Before following the decision tree, check the Prometheus dashboard for these
signals:

```promql
# Error rate (1 = 100%)
rate(eunox_gateway_enforce_total{decision="deny"}[5m])
  / rate(eunox_gateway_enforce_total[5m])

# Redis health (0=healthy, 1=degraded)
redis_health_state

# JWKS fetch errors
rate(eunox_jwks_fetch_errors_total[5m])

# P99 latency
histogram_quantile(0.99, rate(eunox_gateway_enforce_duration_seconds_bucket[5m]))
```

---

## 1. All Enforcement Calls Return 401

### Decision Tree

```
401 on /enforce or /proxy?
│
├── Error message: "token verification failed" or "JWKS fetch blocked"?
│   │
│   ├── YES → JWKS endpoint problem
│   │   │
│   │   ├── Is eunox_jwks_fetch_errors_total rising?
│   │   │   ├── YES → Issuer service is down or unreachable
│   │   │   │         Check: curl -sf $GATEWAY_ISSUER_JWKS_URL
│   │   │   │         Action: Restore issuer service → gateway auto-recovers
│   │   │   │
│   │   │   └── NO → Cache has expired; check issuer logs for recent errors
│   │   │
│   │   └── JWKS cache still valid (< GATEWAY_EUNOX_JWKS_CACHE_TTL_SECONDS old)?
│   │       ├── YES → Token was issued with unknown key; check token kid vs JWKS
│   │       └── NO → Wait for circuit breaker half-open (30 s) or restore issuer
│   │
├── Error message: "token has expired"?
│   │
│   └── YES → Agent token TTL exceeded
│             Action: Agent must call POST /api/v1/renew or re-issue token
│             Check: Is the token TTL policy too short for the workflow?
│
├── Error message: "JWT missing required kid header"?
│   │
│   └── YES → Token minted without kid claim
│             Action: Check issuer version; GATEWAY_EUNOX_REQUIRE_KID=true is enforced
│             Workaround (non-prod only): Set GATEWAY_EUNOX_REQUIRE_KID=false
│
└── Error message: "DPoP proof required" or "DPoP verification failed"?
    │
    └── YES → DPoP sender-constraint violation
              Check: Is the agent sending a DPoP proof in the DPoP header?
              Check: Is the DPoP JTI already used (replay detected)?
              Action: Agent must generate a new DPoP proof for each request
```

### Verification Commands

```bash
# Check if JWKS is reachable
curl -sf $GATEWAY_ISSUER_JWKS_URL | jq 'keys'

# Decode a failing token (base64 only; do not trust output for security decisions)
echo "PASTE_TOKEN_HERE" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub,iss,exp,kid:.header.kid}'

# Check circuit breaker state in logs
kubectl logs -n eunox-system deployment/gateway --since=10m | \
  jq 'select(.msg | test("circuit breaker"))'
```

---

## 2. All Enforcement Calls Return 503

503 on enforcement always indicates that a fail-closed Redis component is
unavailable. **This is a P1 incident.** Legitimate traffic is being blocked.

### Decision Tree

```
503 on /enforce or /proxy?
│
├── Body: "kill switch check unavailable"?
│   │
│   └── YES → Kill-switch Redis is unreachable
│             │
│             ├── Check: redis_health_state{component="killswitch"} == 1?
│             │   └── YES → Redis connectivity loss
│             │             Action: See docs/gateway-operator-runbook.md §Redis Outage
│             │
│             └── Check: Is this a new gateway deployment?
│                 └── YES → Redis URL misconfigured; check GATEWAY_KILL_SWITCH_REDIS_URL
│                           or GATEWAY_REDIS_URL
│
├── Body: "revocation check unavailable"?
│   │
│   └── YES → Revocation Redis is unreachable AND local cache is exhausted
│             │
│             ├── Check: redis_health_state{component="revocation"} == 1?
│             │   └── YES → Redis connectivity loss
│             │             Note: 60 s stale TTL (REDIS_FAILOVER_STALE_TTL_SECONDS)
│             │             provides a grace window; 503 means cache also exhausted
│             │
│             └── Action: See docs/gateway-operator-runbook.md §Redis Outage
│
└── 503 on /health/ready (not on enforcement)?
    │
    └── This is a readiness probe failure; may be during startup drain.
        Check: kubectl describe pod -n eunox-system <pod-name>
        Check: Is IsReady() returning false (lifecycle drain in progress)?
```

### Verification Commands

```bash
# Check Redis health state
kubectl exec -n eunox-system deployment/gateway -- \
  wget -qO- http://localhost:3002/health/ready | jq .

# Check Redis connectivity directly
kubectl exec -n eunox-system <gateway-pod> -- \
  redis-cli -u $GATEWAY_REDIS_URL PING

# Check Prometheus for degraded components
curl -sf http://prometheus.internal/api/v1/query \
  --data-urlencode 'query=redis_health_state' | jq '.data.result'
```

---

## 3. All Enforcement Calls Return 403

403 means the gateway is healthy and enforcement is working — the request was
correctly denied. This is the expected behavior for a capability policy violation.

### Decision Tree

```
403 on /enforce or /proxy?
│
├── Body: "kill switch active"?
│   │
│   └── YES → Kill switch is activated
│             │
│             ├── Was this intentional? Check kill-switch status:
│             │   curl -H "Authorization: ******" \
│             │     https://gateway.internal:3003/admin/v1/kill-switch
│             │
│             ├── Intentional (security incident):
│             │   Action: Follow docs/runbooks/kill-switch.md
│             │
│             └── Accidental or unknown:
│                 Action: Deactivate immediately (see docs/runbooks/kill-switch.md)
│                 Escalate to security on-call for incident review
│
├── Body: "token revoked"?
│   │
│   └── YES → Token was explicitly revoked
│             Check: Who revoked it and when? Query audit log:
│               GET /api/v1/audit?agentDid=<agent-did>&action=revoke
│             Action: If revocation was erroneous, the token cannot be un-revoked.
│                     Issue a new token to the agent.
│
├── Body: "action not permitted" or "capability condition not met"?
│   │
│   ├── "action not permitted":
│   │   The token's capability set does not include the requested tool/action.
│   │   Check: Does the token's 'capabilities[].actions' include the requested action?
│   │   Action: Re-issue token with broader capability set, or fix the agent's request.
│   │
│   └── "capability condition not met":
│       A condition is blocking the request. Common causes:
│       │
│       ├── Time window: Current time is outside the capability's valid window
│       │   Check: Token exp/nbf vs current time
│       │
│       ├── IP range: Client IP not in allowed CIDR
│       │   Check: X-Forwarded-For vs capability ipRanges condition
│       │   Check: Is GATEWAY_TRUSTED_PROXY_CIDRS configured correctly?
│       │
│       └── Max calls: Call count limit reached for this capability
│           Check: GET /admin/v1/usage for the agent's call count
│           Action: Increase max_calls in the capability policy, or wait for reset
│
└── Body: "enforcement engine error" (500 disguised as 403 in some paths)?
    └── YES → Unexpected engine error; see gateway logs for stack trace
```

---

## 4. Requests Pass Enforcement But Backend Calls Fail (502)

502 means enforcement succeeded but the backend service is unavailable or
misconfigured.

### Decision Tree

```
502 on proxied requests?
│
├── Body: "no backend configured"?
│   │
│   └── YES → GATEWAY_BACKEND_SERVICE_URL is not set
│             Action: Set the env var and restart gateway
│
├── 502 with upstream error?
│   │
│   ├── Check: Is the backend service running?
│   │   kubectl get pods -n <backend-namespace>
│   │
│   ├── Check: Can the gateway reach the backend?
│   │   kubectl exec -n eunox-system <gateway-pod> -- \
│   │     wget -qO- $GATEWAY_BACKEND_SERVICE_URL/health 2>&1
│   │
│   └── Check: eunox_gateway_proxy_duration_seconds P99 for latency spike
│
└── Intermittent 502?
    └── Check: Backend pod count; possible AZ routing to a terminating pod
              Action: Increase backend replicas or add retry at the gateway level
```

---

## 5. Requests Are Being Rate-Limited (429)

### Decision Tree

```
429 on /enforce or /proxy?
│
├── Affects a single agent/IP?
│   │
│   ├── YES → The agent is over the per-IP rate limit
│   │   Check: What is GATEWAY_RATE_LIMIT_MAX_REQUESTS? (default: 1000 req/60s)
│   │   Action: Adjust the limit for legitimate high-volume agents, or add retry
│   │           with exponential backoff on the agent side
│   │
│   └── Is this a new deployment?
│       └── YES → Check GATEWAY_TRUSTED_PROXY_CIDRS; all requests may share a
│                 single IP if the load balancer IP is not trusted
│
├── Affects all agents globally?
│   │
│   ├── Check: Is redis_health_state{component="ratelimit"} == 1?
│   │   └── YES → Rate-limiter Redis degraded; per-instance fallback active.
│   │             Effective limit = RATE_LIMIT_MAX_REQUESTS × replica_count.
│   │             This means limits are HIGHER, not lower.
│   │             If 429s are increasing, the backend may be overloaded.
│   │
│   └── Is this an admin endpoint (3003)?
│       └── YES → Admin rate limit applies: GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE
│                 (default: 10 req/min per IP). Reduce admin call frequency.
│
└── Retry-After header present?
    └── YES → Honor the Retry-After value; implement client-side backoff
```

---

## Escalation

| Symptom | On-Call Tier | SLA to Escalate |
|---------|-------------|-----------------|
| 503 (Redis down, P1) | Platform → Redis | Immediately |
| 401 (JWKS expired) | Platform → Issuer | < 5 min |
| 403 (kill switch active, unplanned) | Platform → Security | Immediately |
| 502 (backend down) | Platform → Backend service owner | < 10 min |
| 429 (unexpected global) | Platform | < 15 min |

**Post-incident:** File an incident report and run the chaos suite against
the failure scenario. If a gap exists in `docs/chaos-results.md`, add a test
and update the results document.

# Runbook: Kill Switch Activation

**Severity**: P1 — Emergency  
**Last Updated**: 2026-05-26  
**Owner**: Platform Operations

## Overview

The kill switch is an emergency mechanism that immediately halts all policy enforcement at the gateway. When activated, all `/api/v1/enforce` requests are denied with a `503 Service Unavailable` response.

## When to Activate

- Active security incident requiring immediate revocation of all access
- Compromised signing key (before rotation is complete)
- Runaway automation causing harm
- Regulatory requirement for immediate shutdown

## Activation Procedure

### Via Admin API (Preferred)

```bash
# Activate kill switch for specific tenant
curl -X POST https://gateway.internal:3003/admin/v1/kill-switch \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "reason": "Security incident #1234"}'
```

### Via Redis (Direct)

```bash
# Connect to Redis sentinel/cluster
redis-cli -h redis-sentinel.eunox-system.svc -p 26379
> SENTINEL get-master-addr-by-name eunox-master
# Connect to master
redis-cli -h <master-ip> -p 6379
> SET eunox:kill-switch:global "1"
```

### Via Kubernetes ConfigMap (Fallback)

```bash
kubectl -n eunox-system patch configmap eunox-gateway-config \
  --type merge -p '{"data":{"KILL_SWITCH_ENABLED":"true"}}'
kubectl -n eunox-system rollout restart deployment/eunox-gateway
```

## Verification

```bash
# Should return 503
curl -s -o /dev/null -w "%{http_code}" \
  https://gateway.example.com/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"subject":"test","resource":"test","action":"test"}'
# Expected: 503
```

## Deactivation

```bash
# Via Admin API
curl -X POST https://gateway.internal:3003/admin/v1/kill-switch \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "reason": "Incident resolved #1234"}'

# Verify enforcement resumes
curl -s -o /dev/null -w "%{http_code}" \
  https://gateway.example.com/api/v1/enforce \
  -H "Content-Type: application/json" \
  -H "Authorization: ******" \
  -d '{"subject":"did:key:...","resource":"tool://test","action":"execute"}'
# Expected: 200 (or 403 for valid deny)
```

## Monitoring

- **Metric**: `eunox_gateway_kill_switch_active{tenant}` gauge
- **Alert**: `EunoxKillSwitchActive` fires when kill switch has been active > 5 minutes without acknowledgment
- **Dashboard**: Grafana > eunox Operations > Kill Switch panel

## Post-Incident

1. Document incident timeline in post-mortem
2. Verify all affected clients have recovered
3. Review audit log for actions taken during kill switch period
4. Update runbook if procedures need improvement

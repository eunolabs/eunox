# Runbook: MinterHighFailureRate

> **Alert:** `MinterHighFailureRate` — severity **warning**
>
> **Condition:** The ratio of denied or errored mint calls to total mint calls for a single
> tenant exceeds 50% over 5 minutes.
>
> **Alert source:** `prometheus/minter-alert-rules.yaml` (Rule 4); also fires via
> `euno_minter_anomaly_alerts_total{rule="failure_clustering"}` for sub-minute in-process detection.

## Likely causes

- API-key enumeration or credential stuffing attack (many invalid keys tried).
- Tenant's API key has been rotated server-side but the agent is using the old key.
- Policy store is returning errors (DB down, corrupt policy record).
- Bug in a new minter deployment rejecting valid requests.

## Immediate actions

1. Identify the tenant from `$labels.tenant`.
2. Break down failures by result type from `mint_audit`:
   ```sql
   SELECT result, denial_reason, COUNT(*)
   FROM mint_audit
   WHERE tenant_id = '<tenant>'
     AND minted_at > NOW() - INTERVAL '10 minutes'
   GROUP BY result, denial_reason
   ORDER BY COUNT(*) DESC;
   ```
3. If `result = 'denied'` with `denial_reason` like `invalid_api_key` → likely
   enumeration or stale client key. Apply CDN-level rate limiting for the tenant's IP
   range and notify the tenant.
4. If `result = 'error'` → check for policy-store or DB errors in the minter logs.
5. If the high failure rate coincides with a new minter deployment → roll back and
   investigate.

## Escalation

Escalate to security on-call if the failure pattern is consistent with an active attack
(high request volume, many source IPs, no matching tenant contact).

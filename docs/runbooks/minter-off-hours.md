# Runbook: MinterOffHoursMint

> **Alert:** `MinterOffHoursMint` — severity **warning**
>
> **Condition:** A low-activity tenant (< 10 mints in the previous 7 days) mints a token
> during 22:00–06:00 UTC.
>
> **Alert source:** `prometheus/minter-alert-rules.yaml` (Rule 2); also fires via
> `eunox_minter_anomaly_alerts_total{rule="off_hours_low_activity"}` for sub-minute in-process detection.

## Likely causes

- Legitimate maintenance window or batch job configured by the tenant.
- Credential compromise: an attacker with a stolen API key minting outside business hours.

## Immediate actions

1. Identify the tenant from `$labels.tenant` in the alert.
2. Check `mint_audit` for the off-hours activity:
   ```sql
   SELECT minted_at, caller_ip, api_key_prefix, agent_id, result
   FROM mint_audit
   WHERE tenant_id = '<tenant>'
   AND (minted_at::time >= '22:00' OR minted_at::time < '06:00')
   ORDER BY minted_at DESC
   LIMIT 20;
   ```
3. If the IP and agent ID match the tenant's known infrastructure → likely legitimate;
   note in the incident log and close.
4. If the IP or agent ID is unknown → treat as potential compromise.
   - Revoke the affected API key prefix.
   - Contact the tenant.
   - Escalate to security on-call if tokens were minted for sensitive capabilities.

## Escalation

Escalate to the security on-call if the activity cannot be attributed to a known tenant
workload within 30 minutes.

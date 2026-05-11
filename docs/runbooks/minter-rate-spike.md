# Runbook: MinterRateSpike

> **Alert:** `MinterRateSpike` — severity **critical**
>
> **Condition:** A single tenant's mint rate exceeds 10× its 1-hour rolling average for ≥ 2 minutes.
>
> **Alert source:** `prometheus/minter-alert-rules.yaml` (Rule 1); also fires via
> `euno_minter_anomaly_alerts_total{rule="rate_spike"}` for sub-minute in-process detection.

## Likely causes

- Runaway agent process refreshing tokens in a tight loop.
- Legitimate traffic spike (product launch, batch job).
- Credential compromise: an attacker minting tokens continuously with a stolen API key.

## Immediate actions

1. Identify the tenant from `$labels.tenant` in the alert.
2. Query `mint_audit` to inspect the source IPs and `api_key_prefix` values:
   ```sql
   SELECT caller_ip, api_key_prefix, COUNT(*)
   FROM mint_audit
   WHERE tenant_id = '<tenant>'
     AND minted_at > NOW() - INTERVAL '10 minutes'
   GROUP BY caller_ip, api_key_prefix
   ORDER BY COUNT(*) DESC;
   ```
3. If a single IP or key prefix dominates → likely credential misuse or runaway agent.
   - Rotate the affected API key via the admin API.
   - Contact the tenant.
4. If traffic is spread across many IPs → likely a product launch or DDoS attempt.
   - Apply per-tenant rate limiting at the CDN layer.
5. If the minting pattern looks adversarial (off-hours, unknown IPs, policy mismatches),
   invoke the emergency key rotation procedure ([minter-threat-model.md §3](../security/minter-threat-model.md#3-key-rotation-procedure)).

## Escalation

Page the security on-call if step 5 is reached or if you cannot determine the cause
within 15 minutes.

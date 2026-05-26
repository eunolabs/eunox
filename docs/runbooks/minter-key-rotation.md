# Runbook: MinterEmergencyKeyRotation

> **Alert:** `MinterEmergencyKeyRotation` — severity **critical**
>
> **Condition:** An emergency key rotation event has been recorded for the minter signing
> key (`euno_minter_key_rotation_total{reason="emergency"}` increases).
>
> **Alert source:** `prometheus/minter-alert-rules.yaml` (Rule 5).

## Context

This alert fires the moment an emergency key rotation row is written to the minter audit
store (reason = `emergency`). It is a notification alert, not a "something broke" alert —
the rotation procedure has already been initiated by an operator.

## Verify the rotation is in progress

1. Confirm the rotation was initiated by an authorized operator:
   ```sql
   SELECT minted_at, kid, reason
   FROM mint_audit
   WHERE result = 'key_rotation'
     AND reason = 'emergency'
   ORDER BY minted_at DESC
   LIMIT 1;
   ```
2. Confirm the new key `kid` is live in the JWKS endpoint:
   ```bash
   curl https://gateway.eunox.example/.well-known/jwks.json | jq '.keys[].kid'
   ```

## Check rotation procedure progress

The full emergency rotation procedure is in
[minter-threat-model.md §3](../security/minter-threat-model.md#3-key-rotation-procedure)
steps 5a–8. Verify each step has been completed:

- [ ] Global kill switch invoked (`POST /admin/kill-switch/global`).
- [ ] All JTIs signed by the compromised `kid` bulk-revoked.
- [ ] Affected tenants notified with the list of potentially-forged JTIs.
- [ ] Global kill switch lifted after new key is active and old-key JTIs are revoked.
- [ ] Old `kid` removed from JWKS endpoint.
- [ ] Old key version disabled in HSM.
- [ ] `KEY_ROTATION_COMPLETE` row written to the minter audit store.

## Post-incident

File a security incident report within 24 hours covering: timeline, blast radius (from
`mint_audit WHERE kid = $compromised_kid`), affected tenants, and remediation steps taken.

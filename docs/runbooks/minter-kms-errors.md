# Runbook: MinterKmsErrorCluster

> **Alert:** `MinterKmsErrorCluster` — severity **critical**
>
> **Condition:** The total KMS error rate across all providers exceeds 5 errors/second for
> ≥ 1 minute.
>
> **Alert source:** `prometheus/minter-alert-rules.yaml` (Rule 3).
> Use `eunox_minter_kms_error_total{error_class="..."}` to break down by error class
> (`sign_failed`, `auth_error`, `timeout`, `unavailable`).

## Likely causes

- HSM endpoint is unreachable (network partition, provider outage).
- IAM / workload identity token has expired or been revoked.
- KMS key version has been disabled or deleted.
- Minter pod misconfiguration (wrong key ARN / vault URL after a deploy).

## Immediate actions

1. Check the cloud provider's status page for KMS/HSM incidents.
2. Inspect minter pod logs for the specific error class:
   ```bash
   kubectl logs -n minter deployment/eunox-minter --tail=200 | grep "KMS\|kms\|HSM"
   ```
3. Verify the workload identity is valid:
   - Azure: `az account get-access-token --resource https://vault.azure.net`
   - AWS: `aws sts get-caller-identity` from within the pod.
   - GCP: `gcloud auth print-identity-token` from within the pod.
4. If the key version was recently rotated, confirm `MINTER_ACTIVE_KID` env var points to
   the new version.
5. If the HSM is unreachable and there is no provider incident, the minter will deny all
   mint requests (fail-closed). No tokens can be forged — this is safe. Notify affected
   tenants and wait for the provider to recover.

## Escalation

Page the infrastructure on-call immediately if the HSM is unreachable and you cannot
identify the cause within 5 minutes. This blocks all token issuance.

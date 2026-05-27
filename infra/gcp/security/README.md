# GCP security analytics rules (Sprint-1 OBS parity)

This directory provides the **GCP** parity of
`infra/sentinel/analytic-rules.json`. The same five Sentinel rules
(denial spikes, write-in-readonly, invalid-token bursts, kill-switch
activation, token-revocation spikes) are expressed three different ways:

| File                         | Format                                 | Purpose                                                                         |
| ---------------------------- | -------------------------------------- | ------------------------------------------------------------------------------- |
| `cloud-logging-queries.json` | Cloud Logging filter JSON              | Authoritative queries — runnable in Logs Explorer or via `gcloud logging read`. |
| `cloud-monitoring-alerts.tf` | Terraform (log-based metrics + alerts) | Materializes each filter as a metric + alert policy.                            |
| `scc-custom-modules.yaml`    | Security Command Center custom modules | Surfaces alerts as SCC findings (requires SCC Premium).                         |

## Deployment

1. **Provision infra** with `infra/terraform/gcp/main.tf` (creates the log buckets and Pub/Sub topic).
2. **Deploy alerts**:

   ```bash
   cd infra/gcp/security
   terraform init
   terraform apply -var="project_id=<your-project>"
   ```

3. **(Optional) Register SCC custom modules** — one per module entry:

   ```bash
   for i in 0 1 2 3 4; do
     yq ".modules[$i]" scc-custom-modules.yaml > /tmp/eunox-mod.yaml
     gcloud scc custom-modules sha create \
       --organization=$ORG_ID \
       --display-name="$(yq '.displayName' /tmp/eunox-mod.yaml)" \
       --custom-config-from-file=/tmp/eunox-mod.yaml
   done
   ```

4. **Subscribe** Pub/Sub `eunox-scc-findings` to your alerting destination
   (PagerDuty, Slack via Cloud Functions, etc.) — the topic was created
   by `infra/terraform/gcp/main.tf`.

## Mapping to `infra/sentinel/analytic-rules.json`

| Sentinel rule (KQL)            | GCP equivalent                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `eunox-deny-spike`             | `eunox_deny_spike` log-based metric + `eunox - Capability denial spike` policy |
| `eunox-write-in-readonly`      | `eunox_write_in_readonly` metric + matching alert policy                       |
| `eunox-invalid-token-burst`    | `eunox_invalid_token_burst` metric + matching alert policy                     |
| `eunox-kill-switch-activated`  | `eunox_kill_switch_activated` metric + matching alert policy                   |
| `eunox-token-revocation-spike` | `eunox_token_revocation_spike` metric + matching alert policy                  |

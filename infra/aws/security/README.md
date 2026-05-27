# AWS security analytics rules (Sprint-1 OBS parity)

This directory provides the **AWS** parity of
`infra/sentinel/analytic-rules.json`. The same five Sentinel rules
(denial spikes, write-in-readonly, invalid-token bursts, kill-switch
activation, token-revocation spikes) are expressed three different ways:

| File                            | Format                        | Purpose                                                                             |
| ------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------- |
| `cloudwatch-logs-insights.json` | CloudWatch Logs Insights JSON | Authoritative queries, runnable in the console or via `aws logs get-query-results`. |
| `cloudwatch-alarms.yaml`        | CloudFormation template       | Materializes Metric Filters + Alarms + an SNS topic for incident routing.           |
| `security-hub-insights.json`    | Security Hub insight JSON     | Groups the alarm-derived findings into operational dashboards.                      |

## Deployment

1. **Provision infra** with `infra/terraform/aws/` (creates the log groups and enables Security Hub).
2. **Deploy alarms**:

   ```bash
   aws cloudformation deploy \
     --template-file infra/aws/security/cloudwatch-alarms.yaml \
     --stack-name eunox-security-alerts \
     --capabilities CAPABILITY_NAMED_IAM
   ```

3. **Register Security Hub insights** (one per object in the JSON file):

   ```bash
   jq -c '.insights[]' infra/aws/security/security-hub-insights.json | \
     while read insight; do
       aws securityhub create-insight --cli-input-json "$insight"
     done
   ```

4. **Subscribe SNS to your alerting destination** (PagerDuty, Slack via
   AWS Chatbot, Lambda fanout, etc.).

## Mapping to `infra/sentinel/analytic-rules.json`

| Sentinel rule (KQL)            | This directory                                                    |
| ------------------------------ | ----------------------------------------------------------------- |
| `eunox-deny-spike`             | `DenialFilter` + `DenialSpikeAlarm` + first insight               |
| `eunox-write-in-readonly`      | `WriteInReadOnlyFilter` + `WriteInReadOnlyAlarm` + second insight |
| `eunox-invalid-token-burst`    | `InvalidTokenFilter` + `InvalidTokenBurstAlarm` + third insight   |
| `eunox-kill-switch-activated`  | `KillSwitchFilter` + `KillSwitchAlarm` + fourth insight           |
| `eunox-token-revocation-spike` | `RevocationFilter` + `TokenRevocationSpikeAlarm` + fifth insight  |

# Cross-Cloud Demonstration Runbook

> Sprint 6 (optional) deliverable from
> [`execution-plan.md`](./execution-plan.md): *"Demonstrate portability
> by deploying a minimal version in another environment (e.g., AWS or
> GCP). Issue a similar capability for an agent and verify cross-cloud
> acceptance by trusting the other environment's public key/DID."*
>
> This runbook proves the multi-cloud parity matrix in
> [`SPRINT_5_PILOT_LAUNCH.md` § 6](./SPRINT_5_PILOT_LAUNCH.md#6-cloud-portability-matrix)
> with a concrete, scripted exercise. It uses the existing
> infrastructure-as-code under `infra/terraform/aws/` and
> `infra/terraform/gcp/` — no new IaC is added in Sprint 6.

---

## 1. Goals and exit criteria

The Milestone 3 exit criterion is:

> *"Cross-cloud demonstration proves equivalent capability issuance,
> signing, enforcement, and audit behavior across Azure plus at least
> one AWS or Google Cloud deployment profile. Success requires
> identical allow/deny outcomes for the same capability manifests,
> audit log field parity for required evidence fields, and gateway
> latency within the documented p99 target."*

To pass we need to show, on **at least one of {AWS, GCP}**:

| # | Demonstration step                                                     | Pass criterion                                                            |
|---|------------------------------------------------------------------------|----------------------------------------------------------------------------|
| 1 | Issue a capability token using the cloud's KMS as the signer           | JWT verifies against the cloud's public key                                |
| 2 | Verify that token at the Tool Gateway running in the same cloud        | Same allow/deny outcome as Azure for the same manifest                     |
| 3 | Verify the token at the Azure Tool Gateway after trusting the cloud's DID/JWKS | Same allow/deny outcome — proves cross-cloud trust                  |
| 4 | Compare audit log records side-by-side                                 | All required evidence fields present in both                               |
| 5 | Measure gateway latency                                                | p99 within the same documented target (≤ 25 ms)                            |

---

## 2. Prerequisites

- An existing Azure pilot deployment from
  [`SPRINT_5_PILOT_LAUNCH.md`](./SPRINT_5_PILOT_LAUNCH.md).
- For the AWS path: AWS account with admin, `terraform` ≥ 1.5, `aws` CLI ≥ 2.13.
- For the GCP path: GCP project with Owner role, `terraform` ≥ 1.5, `gcloud` ≥ 460.
- A built copy of every Euno container image in your registry of
  choice (ECR / Artifact Registry / ACR). The Dockerfiles are
  unchanged across clouds.

---

## 3. Path A — AWS demonstration

### 3.1 Provision infrastructure

```bash
cd infra/terraform/aws
cp terraform.tfvars.example terraform.tfvars
# edit region, prefix, vpc_cidr, etc.
terraform init
terraform apply
```

This creates the EKS cluster, asymmetric KMS key for capability
signing, IAM roles for IRSA, an ECR repository, the Cognito user pool,
and CloudWatch log groups (parity with Bicep, see
[`infra/README.md`](../infra/README.md)).

### 3.2 Deploy the gateway profile

```bash
# Edge JWT enforcement at AWS API Gateway
ls infra/aws/api-gateway/
# Apply the Lambda authorizer and OpenAPI as documented in
# infra/aws/api-gateway/README.md
```

### 3.3 Configure the Capability Issuer for AWS KMS

Set the issuer's environment to use the AWS KMS signer
(`AWSKMSSigner` ships in `packages/capability-issuer`):

```bash
SIGNER_TYPE=aws-kms
AWS_REGION=us-east-1
AWS_KMS_KEY_ID=<from terraform output kms_key_id>
ISSUER_DID=did:web:agents-aws.example.com
```

Publish the public key at `https://agents-aws.example.com/.well-known/did.json`.

### 3.4 Run the parity test

The integration tests under `packages/integration-tests/` already
exercise the issue → verify path against any compliant signer + gateway.
Run them against the AWS deployment:

```bash
cd packages/integration-tests
ISSUER_URL=https://issuer-aws.example.com \
  GATEWAY_URL=https://gateway-aws.example.com \
  npm test
```

Pass criterion: every test that passes against Azure also passes
against AWS, with the **same** allow/deny outcomes for the **same**
manifests.

### 3.5 Cross-trust (Azure gateway accepting an AWS-issued token)

In the Azure gateway pod, add the AWS issuer's DID to the trusted
issuer list:

```yaml
# k8s/namespace-and-config.yaml — in the gateway ConfigMap
TRUSTED_ISSUERS: >
  did:web:agents.example.com,
  did:web:agents-aws.example.com
```

Reapply, then issue a token from the AWS issuer and use it against the
Azure gateway. The gateway resolves the AWS DID, fetches its JWKS,
verifies the signature, and applies the **same** policy logic. The
allow/deny decision must match what the AWS gateway returned for the
same call.

### 3.6 Audit-log field parity

Run:

```bash
# Azure side
az monitor log-analytics query --workspace <law-id> \
  --analytics-query "ContainerLogV2 | where LogMessage has 'Capability check' | project parse_json(extract(@'(\\{.*\\})\\s*\$', 1, LogMessage))" \
  -o json > /tmp/azure-events.json

# AWS side
aws logs filter-log-events \
  --log-group-name /euno/tool-gateway \
  --filter-pattern '"Capability check"' \
  > /tmp/aws-events.json
```

Compare the parsed JSON payloads. The required fields per
[`docs/IMPLEMENTATION.md`](./IMPLEMENTATION.md) audit schema are:

`timestamp, agentId, sessionId, action, resource, capabilityId,
decision, reason, parentCapabilityId (if delegated), issuer (DID)`.

Every field must be present and identical in shape on both sides.

### 3.7 Latency

```bash
# Azure
az monitor app-insights metrics show \
  --app <appinsights> \
  --metric requests/duration \
  --aggregation P95 P99

# AWS
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name Latency \
  --statistics p95 p99 \
  --period 300
```

p99 must remain ≤ 25 ms on both clouds for the same workload. If AWS
exceeds the target, scale the gateway service before declaring
failure (parity is a *like-for-like* test).

---

## 4. Path B — GCP demonstration

The GCP path is structurally identical to the AWS path; only the
provisioning commands and signer configuration differ.

### 4.1 Provision infrastructure

```bash
cd infra/terraform/gcp
cp terraform.tfvars.example terraform.tfvars
# edit project_id, region, etc.
terraform init
terraform apply
```

This creates GKE with Workload Identity, the asymmetric Cloud KMS
signing key, GCP service accounts + Workload Identity bindings, an
Artifact Registry repository, dedicated Cloud Logging buckets, and a
Pub/Sub topic for SCC findings (parity with Bicep, see
[`infra/README.md`](../infra/README.md)).

### 4.2 Deploy the gateway profile

```bash
ls infra/gcp/api-gateway/
# Apply the OpenAPI to GCP API Gateway, or import the Apigee
# VerifyJWT policy, per infra/gcp/api-gateway/README.md
```

### 4.3 Configure the Capability Issuer for Cloud KMS

```bash
SIGNER_TYPE=gcp-cloud-kms
GCP_PROJECT_ID=<from terraform output project_id>
GCP_KMS_KEY_RESOURCE=<from terraform output kms_key_resource>
ISSUER_DID=did:web:agents-gcp.example.com
```

Publish the public key at `https://agents-gcp.example.com/.well-known/did.json`.

### 4.4 Parity test, cross-trust, audit, latency

Follow [§ 3.4](#34-run-the-parity-test) through [§ 3.7](#37-latency)
verbatim, substituting `gateway-gcp.example.com` and the GCP CLI.

For the GCP audit log query:

```bash
gcloud logging read \
  'resource.type="k8s_container" AND jsonPayload.message=~"Capability check"' \
  --limit 100 --format json > /tmp/gcp-events.json
```

For the latency query:

```bash
gcloud monitoring time-series list \
  --filter='metric.type="run.googleapis.com/request_latencies"' \
  --interval-end-time=$(date -u +%FT%TZ) \
  --interval-start-time=$(date -u -d '-1 hour' +%FT%TZ)
```

---

## 5. Reporting the result

The cross-cloud demonstration is captured in the **Sprint 6 final
pilot report** ([`SPRINT_6_STABILIZATION_HANDOFF.md` § 6](./SPRINT_6_STABILIZATION_HANDOFF.md#6-final-pilot-report-template))
under "Cross-cloud demo (optional Sprint 6 item)". Attach:

1. Parity test output (`integration-tests` summary on each cloud).
2. Side-by-side audit log JSON (anonymized).
3. p95 / p99 latency screenshots from both clouds.
4. The `TRUSTED_ISSUERS` ConfigMap diff that authorized the cross-trust.

If the demo passes on AWS **or** GCP, the Milestone 3 cross-cloud
exit criterion is met. If neither cloud is exercised, mark the row in
the final report as `skipped` and note that the cross-cloud
*architecture* is in place (terraform + adapter signers + DID-based
trust) but a live demo was deferred to Sprint 7+.

---

## 6. What to do if a step fails

| Failure                                              | Most likely cause                                                | Fix                                                                                            |
|------------------------------------------------------|------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| AWS / GCP gateway returns 500 on a known-good token  | DID document not reachable from the cloud's egress               | Make `.well-known/did.json` publicly resolvable; do not put it behind auth.                     |
| Allow on Azure, deny on AWS for the same manifest    | Issuer manifest mapping different in the two deployments         | Diff the issuer ConfigMap; the manifest *must* be byte-identical to claim parity.               |
| Audit fields missing on one side                     | Logger format set to `simple` on one side, `json` on the other   | Set `LOG_FORMAT=json` everywhere — required by the Sentinel KQL too.                            |
| p99 latency above target on AWS only                 | Lambda authorizer cold-start dominating p99                      | Enable provisioned concurrency on the authorizer; rerun the latency capture after warm-up.      |
| Cross-trust gateway rejects valid AWS-issued token   | `TRUSTED_ISSUERS` not picked up                                  | Verify pod env var, restart the gateway deployment.                                             |

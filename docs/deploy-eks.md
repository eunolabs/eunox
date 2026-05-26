# Deploying Euno on Amazon EKS

> **Target audience:** Platform engineers deploying the Euno platform on AWS
> Elastic Kubernetes Service (EKS).
>
> **Status:** Multi-cloud Phase 1 documentation.
>
> **Related documents:**
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — full environment-variable reference
> - [`docs/secrets-aws.md`](./secrets-aws.md) — AWS Secrets Manager integration
> - [`docs/issuer-idp-setup.md`](./issuer-idp-setup.md) — IdP setup (Cognito SCIM §10)
> - [`docs/multi-cloud-plan.md`](./multi-cloud-plan.md) — multi-cloud runbook index
> - [`docs/self-host.md`](./self-host.md) — self-host overview

---

## 1. Prerequisites

| Requirement | Version / notes |
|---|---|
| AWS CLI | ≥ 2.13 |
| `eksctl` | ≥ 0.180 |
| `kubectl` | ≥ 1.29 |
| Helm | ≥ 3.14 |
| AWS account with permissions to create EKS clusters, IAM roles, ECR, ACM, ALB |  |

---

## 2. Cluster setup

### 2.1 Create an EKS cluster with `eksctl`

```bash
eksctl create cluster \
  --name euno-prod \
  --region us-east-1 \
  --version 1.29 \
  --nodegroup-name euno-nodes \
  --node-type m6i.large \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 6 \
  --managed \
  --with-oidc
```

The `--with-oidc` flag creates an IAM OIDC provider for the cluster, which is
required for IAM Roles for Service Accounts (IRSA).

### 2.2 Verify the OIDC provider

```bash
aws eks describe-cluster --name euno-prod --region us-east-1 \
  --query "cluster.identity.oidc.issuer" --output text
# https://oidc.eks.us-east-1.amazonaws.com/id/<OIDC_ID>

aws iam list-open-id-connect-providers | grep <OIDC_ID>
```

---

## 3. IAM Roles for Service Accounts (IRSA)

IRSA allows individual pods to assume scoped IAM roles without static
credentials. This is the recommended credential model for EKS — do **not**
use long-lived access keys in pod environment variables.

### 3.1 `capability-issuer` IAM role

The issuer needs:
- **AWS Cognito** read access (for token validation) — no IAM policy required;
  Cognito public JWKs are fetched over HTTPS.
- **AWS KMS** signing access (if `SIGNING_PROVIDER=aws-kms`).
- **AWS Secrets Manager** read access (if using Secrets Manager for secrets).

Create the role:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
OIDC_PROVIDER=$(aws eks describe-cluster --name euno-prod --region us-east-1 \
  --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||')

cat > /tmp/issuer-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_PROVIDER}:sub": "system:serviceaccount:euno:euno-issuer",
        "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
      }
    }
  }]
}
EOF

aws iam create-role \
  --role-name euno-issuer-role \
  --assume-role-policy-document file:///tmp/issuer-trust-policy.json

# KMS signing (attach if SIGNING_PROVIDER=aws-kms)
aws iam attach-role-policy \
  --role-name euno-issuer-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EunoKmsSigningPolicy

# Secrets Manager read (attach if using ASCP or if the app reads directly)
aws iam attach-role-policy \
  --role-name euno-issuer-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EunoSecretsReadPolicy
```

See [`docs/secrets-aws.md`](./secrets-aws.md) §3 for the `EunoSecretsReadPolicy`
(`§3.1`) and `EunoKmsSigningPolicy` (`§3.2`) IAM policy documents.

### 3.2 `tool-gateway` IAM role

The gateway needs:
- **AWS KMS** signing access (for audit evidence signing if `SIGNING_PROVIDER=aws-kms`).
- **AWS Secrets Manager** read access (for `AUDIT_LEDGER_HMAC_SECRET`, etc.).
- **S3 Object Lock** write access (if `ENABLE_CROSS_CHAIN_ANCHOR=true`).

```bash
cat > /tmp/gateway-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_PROVIDER}:sub": "system:serviceaccount:euno:euno-gateway",
        "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
      }
    }
  }]
}
EOF

aws iam create-role \
  --role-name euno-gateway-role \
  --assume-role-policy-document file:///tmp/gateway-trust-policy.json

aws iam attach-role-policy \
  --role-name euno-gateway-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EunoKmsSigningPolicy

aws iam attach-role-policy \
  --role-name euno-gateway-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EunoSecretsReadPolicy

# S3 anchor (attach only if ENABLE_CROSS_CHAIN_ANCHOR=true)
aws iam attach-role-policy \
  --role-name euno-gateway-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EunoS3AnchorPolicy
```

### 3.3 Annotate Kubernetes ServiceAccounts

The Helm chart creates `ServiceAccount` resources for each service. Annotate
them with the IAM role ARN before or after install:

```bash
kubectl annotate serviceaccount euno-issuer \
  -n euno \
  eks.amazonaws.com/role-arn=arn:aws:iam::${ACCOUNT_ID}:role/euno-issuer-role

kubectl annotate serviceaccount euno-gateway \
  -n euno \
  eks.amazonaws.com/role-arn=arn:aws:iam::${ACCOUNT_ID}:role/euno-gateway-role
```

Alternatively, supply the annotation via Helm values:

```yaml
# k8s/helm/euno/values-aws.yaml excerpt
issuer:
  serviceAccountAnnotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/euno-issuer-role"

gateway:
  serviceAccountAnnotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/euno-gateway-role"
```

---

## 4. ECR image configuration

### 4.1 Authenticate Docker to ECR

```bash
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789012.dkr.ecr.us-east-1.amazonaws.com
```

### 4.2 Push Euno images to ECR

For air-gapped or locked-down deployments, pull the images from the public
registry and push them to your private ECR repositories.

```bash
#!/bin/bash
# push-images-to-ecr.sh
# Usage: AWS_ACCOUNT_ID=123456789012 AWS_REGION=us-east-1 ./push-images-to-ecr.sh

set -euo pipefail

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?set AWS_ACCOUNT_ID}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
EUNO_VERSION="${EUNO_VERSION:-1.0.0}"

IMAGES=(
  tool-gateway
  capability-issuer
  api-key-minter
  db-token-service
  storage-grant-service
  posture-emitter
)

aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

for img in "${IMAGES[@]}"; do
  SRC="ghcr.io/edgeobs/euno/${img}:${EUNO_VERSION}"
  DST="${ECR_REGISTRY}/euno/${img}:${EUNO_VERSION}"
  docker pull "${SRC}"
  docker tag  "${SRC}" "${DST}"
  docker push "${DST}"
done

echo "All images pushed to ${ECR_REGISTRY}/euno/"
```

### 4.3 EKS image pull configuration

Because EKS nodes have automatic ECR authentication for repositories in the
same AWS account, no `imagePullSecrets` are required when your ECR repositories
are in the same account as the cluster.

For cross-account ECR:

```bash
# Create an image pull secret using ECR credentials
kubectl create secret docker-registry ecr-pull-secret \
  --docker-server=123456789012.dkr.ecr.us-east-1.amazonaws.com \
  --docker-username=AWS \
  --docker-password=$(aws ecr get-login-password --region us-east-1) \
  --namespace euno
```

Then reference it in your Helm values:

```yaml
global:
  imagePullSecrets:
    - name: ecr-pull-secret
```

---

## 5. ALB Ingress Controller and ACM certificate

### 5.1 Install the AWS Load Balancer Controller

```bash
# Add the IAM policy for the AWS Load Balancer Controller
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.7.1/docs/install/iam_policy.json

aws iam create-policy \
  --policy-name AWSLoadBalancerControllerIAMPolicy \
  --policy-document file://iam_policy.json

# Create an IRSA service account for the controller
eksctl create iamserviceaccount \
  --cluster euno-prod \
  --namespace kube-system \
  --name aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# Install via Helm
helm repo add eks https://aws.github.io/eks-charts
helm repo update eks
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=euno-prod \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

### 5.2 Request an ACM certificate

```bash
aws acm request-certificate \
  --domain-name euno.example.com \
  --subject-alternative-names "*.euno.example.com" \
  --validation-method DNS \
  --region us-east-1
# Note the CertificateArn from the output
```

Complete DNS validation in Route 53 or your DNS provider using the CNAME
records shown in the ACM console.

### 5.3 Ingress resource

Create an Ingress that routes external traffic to the gateway and issuer:

```yaml
# k8s/ingress-aws.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: euno-ingress
  namespace: euno
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:123456789012:certificate/<cert-id>"
    alb.ingress.kubernetes.io/ssl-redirect: "443"
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP":80},{"HTTPS":443}]'
    alb.ingress.kubernetes.io/healthcheck-path: /healthz
spec:
  ingressClassName: alb
  rules:
    - host: euno.example.com
      http:
        paths:
          - path: /api/v1/
            pathType: Prefix
            backend:
              service:
                name: euno-tool-gateway
                port:
                  number: 3002
    - host: issuer.euno.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: euno-capability-issuer
                port:
                  number: 3001
```

> **Note:** The gateway admin port (`3003`) must **not** be exposed via the
> public ALB. Restrict admin access to internal VPC endpoints or use a private
> ALB with `alb.ingress.kubernetes.io/scheme: internal`.

---

## 6. Helm deployment

### 6.1 Install the Helm chart

```bash
kubectl create namespace euno

helm install euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values-aws.yaml \
  --set gateway.secretEnv.AUDIT_LEDGER_HMAC_SECRET="${AUDIT_LEDGER_HMAC_SECRET}" \
  --set gateway.secretEnv.ADMIN_API_KEY="${ADMIN_API_KEY}" \
  --set gateway.secretEnv.REDIS_URL="${REDIS_URL}" \
  --set gateway.secretEnv.AUDIT_LEDGER_PG_URL="${AUDIT_LEDGER_PG_URL}" \
  --set issuer.secretEnv.ISSUER_DB_URL="${ISSUER_DB_URL}"
```

When using AWS Secrets Manager via the External Secrets Operator, the
`secretEnv` map can be left empty in Helm and secrets injected by ExternalSecret
resources instead. See [`docs/secrets-aws.md`](./secrets-aws.md).

### 6.2 AWS-specific `values-aws.yaml` overrides

```yaml
# Full file: k8s/helm/euno/values-aws.yaml
# See that file for inline documentation of every override.
```

The complete `values-aws.yaml` is at `k8s/helm/euno/values-aws.yaml` in this
repository.

### 6.3 Verify the deployment

```bash
kubectl get pods -n euno
kubectl logs -n euno -l app=euno-tool-gateway --tail=50
kubectl logs -n euno -l app=euno-capability-issuer --tail=50

# Health checks
kubectl exec -n euno deploy/euno-tool-gateway -- \
  curl -s http://localhost:3002/healthz | jq .
kubectl exec -n euno deploy/euno-capability-issuer -- \
  curl -s http://localhost:3001/healthz | jq .
```

---

## 7. CloudWatch and Security Hub observability

### 7.1 Prometheus → CloudWatch Metrics (ADOT Collector)

Install the AWS Distro for OpenTelemetry (ADOT) Collector to scrape Prometheus
metrics from Euno pods and forward them to CloudWatch.

#### 7.1.1 Install ADOT add-on

```bash
# Enable the ADOT add-on on the cluster
aws eks create-addon \
  --cluster-name euno-prod \
  --addon-name adot \
  --region us-east-1

# Create the IRSA service account for ADOT
eksctl create iamserviceaccount \
  --cluster euno-prod \
  --namespace opentelemetry-operator-system \
  --name adot-collector \
  --attach-policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy \
  --approve
```

#### 7.1.2 ADOT Collector configuration

Deploy an `OpenTelemetryCollector` custom resource that scrapes the Euno
Prometheus endpoints and ships metrics to CloudWatch.

```yaml
# k8s/otel-collector-aws.yaml
apiVersion: opentelemetry.io/v1alpha1
kind: OpenTelemetryCollector
metadata:
  name: euno-adot
  namespace: euno
spec:
  serviceAccount: adot-collector
  config: |
    receivers:
      prometheus:
        config:
          scrape_configs:
            - job_name: euno-gateway
              scrape_interval: 30s
              static_configs:
                - targets: ["euno-tool-gateway:3002"]
              metrics_path: /metrics
            - job_name: euno-issuer
              scrape_interval: 30s
              static_configs:
                - targets: ["euno-capability-issuer:3001"]
              metrics_path: /metrics

    processors:
      resource:
        attributes:
          - key: ClusterName
            value: euno-prod
            action: upsert
          - key: Namespace
            value: euno
            action: upsert

    exporters:
      awsemf:
        region: us-east-1
        namespace: Euno
        log_group_name: /euno/metrics
        log_stream_name: "{PodName}"
        dimension_rollup_option: NoDimensionRollup
        metric_declarations:
          - dimensions: [[ClusterName, Namespace]]
            metric_name_selectors:
              - "euno_capability_tokens_issued_total"
              - "euno_audit_events_total"
              - "euno_tool_calls_denied_total"
              - "euno_cross_chain_anchor_lag_seconds"
              - "euno_partner_did_circuit_breaker_state"

    service:
      pipelines:
        metrics:
          receivers: [prometheus]
          processors: [resource]
          exporters: [awsemf]
```

Key Euno metrics forwarded to CloudWatch:

| Metric | Description | CloudWatch dimension |
|---|---|---|
| `euno_capability_tokens_issued_total` | Tokens issued per tenant | `ClusterName`, `Namespace` |
| `euno_audit_events_total` | Signed audit events per tool | `ClusterName`, `Namespace` |
| `euno_tool_calls_denied_total` | Denials per `denial_reason` label | `ClusterName`, `Namespace` |
| `euno_cross_chain_anchor_lag_seconds` | S3 anchor write lag | `ClusterName`, `Namespace` |
| `euno_partner_did_circuit_breaker_state` | ION circuit breaker state | `ClusterName`, `Namespace` |

### 7.2 OCSF audit events → Security Hub findings

The tool-gateway emits OCSF-structured audit evidence records. Map them to
AWS Security Hub findings using the following pattern:

#### 7.2.1 CloudWatch Logs → Lambda → Security Hub pipeline

```
tool-gateway audit ledger
  → CloudWatch Logs (via ADOT or fluent-bit)
    → CloudWatch Logs subscription filter
      → Lambda (ocsf-to-securityhub-finding)
        → Security Hub BatchImportFindings API
```

#### 7.2.2 OCSF → Security Hub finding field mapping

| OCSF field | Security Hub finding field |
|---|---|
| `evidence.agentId` | `Resources[0].Id` |
| `evidence.toolName` | `Resources[0].Details.Other.toolName` |
| `evidence.outcome` (`deny`) | `Severity.Label = HIGH` |
| `evidence.outcome` (`allow`) | `Severity.Label = INFORMATIONAL` |
| `evidence.ts` | `CreatedAt` / `UpdatedAt` |
| `evidence.denialReason` | `Description` |
| `evidence.tenantId` | `AwsAccountId` |
| `evidence.capabilityId` | `Resources[0].Details.Other.capabilityId` |

Example Lambda handler (Node.js). The Lambda is triggered by a CloudWatch Logs
subscription filter; the event payload is base64-encoded gzip JSON.

```javascript
// lambda/ocsf-to-securityhub.mjs
import zlib from 'zlib';
import { SecurityHubClient, BatchImportFindingsCommand } from '@aws-sdk/client-securityhub';

const hub = new SecurityHubClient({});

export async function handler(event) {
  // CloudWatch Logs subscription filter payload: base64-encoded gzip JSON.
  const payload = Buffer.from(event.awslogs.data, 'base64');
  const logData = JSON.parse(zlib.gunzipSync(payload).toString('utf8'));

  const findings = [];

  for (const logEvent of logData.logEvents) {
    let evidence;
    try {
      evidence = JSON.parse(logEvent.message);
    } catch {
      continue; // skip non-JSON log lines
    }
    if (evidence.outcome !== 'deny') continue; // only import denials

    findings.push({
      SchemaVersion: '2018-10-08',
      Id: `euno/${evidence.evidenceId}`,
      ProductArn: `arn:aws:securityhub:${process.env.AWS_REGION}::product/aws/securityhub`,
      GeneratorId: 'euno-tool-gateway',
      AwsAccountId: evidence.tenantId ?? process.env.AWS_ACCOUNT_ID,
      Types: ['Software and Configuration Checks/Industry and Regulatory Standards'],
      CreatedAt: new Date(evidence.ts).toISOString(),
      UpdatedAt: new Date(evidence.ts).toISOString(),
      Severity: { Label: 'HIGH' },
      Title: `Euno capability enforcement: tool call denied`,
      Description: evidence.denialReason ?? 'capability enforcement denial',
      Resources: [{
        Type: 'Other',
        Id: evidence.agentId,
        Details: {
          Other: {
            toolName: evidence.toolName,
            capabilityId: evidence.capabilityId ?? '',
          },
        },
      }],
    });
  }

  if (findings.length > 0) {
    await hub.send(new BatchImportFindingsCommand({ Findings: findings }));
  }
}
```

### 7.3 CloudWatch Insights query templates

Use the following Log Insights queries against the `/euno/audit` log group
(or wherever fluent-bit / ADOT forwards the gateway logs).

#### Denial-reason histogram (last 24 h)

```
fields @timestamp, evidence.denialReason, evidence.agentId, evidence.toolName
| filter evidence.outcome = "deny"
| stats count(*) as denials by evidence.denialReason
| sort denials desc
| limit 20
```

#### Top denied agents

```
fields @timestamp, evidence.agentId, evidence.outcome
| filter evidence.outcome = "deny"
| stats count(*) as denials by evidence.agentId
| sort denials desc
| limit 10
```

#### Audit lag monitoring (cross-chain anchor)

```
fields @timestamp, euno_cross_chain_anchor_lag_seconds
| filter ispresent(euno_cross_chain_anchor_lag_seconds)
| stats max(euno_cross_chain_anchor_lag_seconds) as max_lag_s by bin(5m)
| sort @timestamp desc
```

---

## 8. Upgrade and rollback

```bash
# Upgrade
helm upgrade euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values-aws.yaml \
  --set gateway.image.tag=1.1.0 \
  --set issuer.image.tag=1.1.0

# Rollback
helm rollback euno --namespace euno
```

---

## 9. Security checklist for EKS

- [ ] OIDC provider is enabled and IRSA is the only credential mechanism — no
      long-lived access keys in pod environment variables.
- [ ] Node instance profile has the minimum permissions required by the EKS
      managed node group (no broad `AdministratorAccess`).
- [ ] ECR repositories are private with immutable image tags enabled.
- [ ] ACM certificate is issued for the correct domain; HTTP→HTTPS redirect is
      active on the ALB.
- [ ] Gateway admin port (`3003`) is not reachable from the public ALB — use
      an internal ALB or restrict via Network Policy.
- [ ] Kubernetes Network Policies restrict pod-to-pod traffic to the minimum
      required (gateway ↔ Redis, gateway ↔ Postgres, issuer ↔ Postgres).
- [ ] Pod Security Admission is set to `restricted` for the `euno` namespace.
- [ ] `AUDIT_LEDGER_HMAC_SECRET` and `ADMIN_API_KEY` are sourced from Secrets
      Manager — never stored in plaintext in Helm values or ConfigMaps.
      See [`docs/secrets-aws.md`](./secrets-aws.md).
- [ ] CloudWatch Logs retention is set to at least 90 days for the
      `/euno/audit` log group (SOC 2 CC7 requirement).
- [ ] Security Hub findings are reviewed weekly; high-severity denials trigger
      automated alerts via EventBridge.

---

## 10. S3 audit anchor — endpoint configuration (Phase 2)

The cross-chain audit anchor writes Merkle roots to an S3 Object Lock bucket.
The standard bootstrap auto-creates the S3 client when `AUDIT_LEDGER_S3_BUCKET`
is set — no custom entrypoint required.

### 10.1 Standard configuration

```bash
AUDIT_LEDGER_S3_BUCKET=euno-prod-audit-anchors
AUDIT_LEDGER_ANCHOR_INTERVAL=1000   # write every 1000 audit rows
ENABLE_CROSS_CHAIN_ANCHOR=true
# Region is taken from AWS_REGION (the standard EKS IRSA env var)
```

The bucket MUST have Object Lock enabled in `COMPLIANCE` mode.  The writing pod's
IRSA role needs `s3:PutObject` and `s3:PutObjectRetention` on the bucket.

### 10.2 VPC endpoint / PrivateLink configuration

When traffic to S3 must stay within the VPC (zero-internet-egress clusters),
use an S3 Interface VPC Endpoint and configure Euno with the endpoint URL:

```bash
# Create a VPC Interface Endpoint for S3 (one-time setup):
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0a1b2c3d \
  --service-name com.amazonaws.us-east-1.s3 \
  --vpc-endpoint-type Interface \
  --subnet-ids subnet-1a2b3c4d subnet-5e6f7a8b \
  --security-group-ids sg-01234567 \
  --private-dns-enabled

# Pod environment override:
AUDIT_LEDGER_S3_ENDPOINT=https://bucket.vpce-0a1b2c3d4e5f.s3.us-east-1.vpce.amazonaws.com
```

For path-style URL addressing (required by some VPC endpoint configurations):

```bash
AUDIT_LEDGER_S3_FORCE_PATH_STYLE=true
```

### 10.3 GovCloud (us-gov-*) regions

GovCloud endpoints are resolved automatically from `AWS_REGION`:

```bash
AWS_REGION=us-gov-west-1
AUDIT_LEDGER_S3_BUCKET=eunoxvcloud-audit-anchors
# No AUDIT_LEDGER_S3_ENDPOINT override needed for standard GovCloud S3
```

FIPS endpoints are selected by the AWS SDK when `AWS_USE_FIPS_ENDPOINT=true`
is set in the pod environment.

### 10.4 IAM policy for S3 anchor

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EunoS3Anchor",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectRetention"
      ],
      "Resource": "arn:aws:s3:::euno-prod-audit-anchors/*"
    }
  ]
}
```

Attach this policy to the `euno-gateway` IRSA role (see §3).

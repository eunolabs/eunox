# Eunox AWS CDK Constructs

TypeScript CDK constructs for deploying the Eunox Capability-Native Agent
Governance platform on AWS. Three stacks are provided, ordered from smallest
to largest scope:

| Stack                  | Description                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| `EunoxGatewayStack`    | Core infrastructure: EKS Fargate, RDS, ElastiCache, KMS, S3 Object Lock, Secrets Manager, IAM, ECR |
| `EunoxIssuerStack`     | Extends gateway with Cognito User Pool, SCIM endpoint wiring, issuer IRSA role                     |
| `EunoxEnterpriseStack` | Extends issuer with partner DID registry, SOC 2 audit pipeline, Security Hub, CloudWatch alarms    |

Each stack is a superset of the previous one — deploy `EunoxEnterpriseStack`
to get all resources, or deploy `EunoxGatewayStack` alone for a minimal
tool-gateway deployment.

---

## Prerequisites

- Node.js ≥ 18
- AWS CDK v2 CLI: `npm install -g aws-cdk`
- AWS credentials configured (IRSA-compatible IAM role or `~/.aws/credentials`)
- A bootstrapped CDK environment: `cdk bootstrap aws://<account>/<region>`

---

## Quick start

```bash
# 1. Install dependencies
cd infra/aws/cdk
npm install

# 2. Configure deployment
export CDK_DEFAULT_ACCOUNT=123456789012
export CDK_DEFAULT_REGION=us-east-1
export EUNOX_NAME_PREFIX=eunox
export EUNOX_ENVIRONMENT=prod

# 3. Preview changes
EUNOX_CDK_STACK=enterprise cdk diff EunoxEnterprise

# 4. Deploy
EUNOX_CDK_STACK=enterprise cdk deploy EunoxEnterprise
```

---

## Stacks

### EunoxGatewayStack

Provisions the core runtime infrastructure:

- **VPC** — 3-AZ, public/private/isolated subnets, 3 NAT gateways
- **EKS Fargate cluster** — `eunox-system` Fargate profile, OIDC issuer for IRSA
- **RDS PostgreSQL 15** — Multi-AZ, encrypted, audit-ledger + API-key databases
- **ElastiCache Redis 7** — HA replication group, TLS + auth token
- **KMS RSA-2048 key** — `SIGN_VERIFY` for capability-token signing
- **S3 Object Lock bucket** — COMPLIANCE mode, ~7-year retention (SOC 2 CC7.4)
- **Secrets Manager** — HMAC key, admin API key, Redis auth token
- **ECR repositories** — one per Eunox service image (immutable tags)
- **IAM IRSA role for tool-gateway** — KMS Verify, Secrets Manager read, S3 PutObject
- **CloudWatch log groups** — `/eunox/runtime` and `/eunox/audit`

```typescript
import * as cdk from "aws-cdk-lib";
import { EunoxGatewayStack } from "@eunox/aws-cdk";

const app = new cdk.App();
new EunoxGatewayStack(app, "EunoxGateway", {
  env: { account: "123456789012", region: "us-east-1" },
  namePrefix: "eunox",
  environment: "prod",
});
```

### EunoxIssuerStack

Extends `EunoxGatewayStack` with:

- **Cognito User Pool** — MFA optional, email-verified, operator/agent-user groups
- **Cognito App Client** — `ALLOW_USER_SRP_AUTH`, 15-min access token TTL
- **Cognito User Pool Domain** — hosted UI / SCIM bridge endpoint
- **IAM IRSA role for capability-issuer** — KMS Sign, Cognito read, Secrets Manager read
- **`PARTNER_DID_PIN_SECRET`** — Secrets Manager secret for partner DID PIN
- **SSM parameters** — Cognito User Pool ID and App Client ID (non-sensitive)

See `docs/issuer-idp-setup.md §10` for the Cognito SCIM bridge wiring guide.

### EunoxEnterpriseStack

Extends `EunoxIssuerStack` with:

- **Partner DID registry** — DynamoDB table with `ByStatus` GSI for
  circuit-breaker queries (consumed by `PartnerIssuerResolver`)
- **CloudTrail trail** — management + data events (S3, Secrets Manager, KMS);
  satisfies SOC 2 CC6.1 / CC7.2 / CC7.3
- **Kinesis Firehose → S3 data lake** — OCSF audit event streaming with GZIP
  compression and intelligent tiering for long-term retention
- **Security Hub** — CIS AWS Foundations Benchmark standard (can be disabled)
- **CloudWatch alarms** — denial spike, invalid-token burst, kill-switch
  activation; all route to an SNS topic
- **SNS alarm topic** — plug in PagerDuty, Slack, or an email subscription

---

## Environment variables

| Variable              | Default                | Description                                      |
| --------------------- | ---------------------- | ------------------------------------------------ |
| `EUNOX_CDK_STACK`     | (all)                  | Stack tier: `gateway`, `issuer`, or `enterprise` |
| `EUNOX_NAME_PREFIX`   | `eunox`                | Resource name prefix (3-12 lowercase chars)      |
| `EUNOX_ENVIRONMENT`   | `pilot`                | Deployment environment label                     |
| `EUNOX_ALARM_EMAIL`   | —                      | Email address for CloudWatch alarm SNS topic     |
| `CDK_DEFAULT_ACCOUNT` | (from AWS credentials) | AWS account ID                                   |
| `CDK_DEFAULT_REGION`  | (from AWS credentials) | AWS region                                       |

---

## Post-deploy wiring

After deploying, retrieve the stack outputs and wire them into the Helm chart:

```bash
# Get outputs
cdk --outputs-file cdk-outputs.json deploy EunoxEnterprise

# Apply to Helm (EKS)
helm upgrade --install eunox ./k8s/helm/eunox \
  --namespace eunox \
  -f k8s/helm/eunox/values.yaml \
  -f k8s/helm/eunox/values-aws.yaml \
  --set gateway.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=<GatewayRoleArn> \
  --set issuer.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=<IssuerRoleArn>
```

See `docs/deploy-eks.md` for the complete EKS deployment guide.

---

## Running the unit tests

```bash
cd infra/aws/cdk
npm install
npm test
```

Tests use `aws-cdk-lib/assertions` to synthesize each stack into a
CloudFormation template and assert on the resources produced. No AWS
credentials are required to run the tests.

---

## Security notes

- All S3 buckets enforce SSL (`enforceSSL: true`) and block public access.
- Object Lock is set to COMPLIANCE mode for audit buckets to prevent tampering.
- KMS keys have `RemovalPolicy.RETAIN` to prevent accidental deletion.
- Secrets Manager secrets use `RemovalPolicy.RETAIN` so secrets survive stack
  deletion.
- All ECR repositories use immutable image tags and scan on push.

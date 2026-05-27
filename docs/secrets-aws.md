# AWS Secrets Manager Integration

> **Target audience:** Platform engineers configuring eunox to read secrets
> from AWS Secrets Manager at pod startup on EKS.
>
> **Status:** Multi-cloud Phase 1 documentation.
>
> **Related documents:**
>
> - [`docs/deploy-eks.md`](./deploy-eks.md) — full EKS deployment guide
> - [`docs/deployment.md`](./deployment.md) — environment-variable reference

---

## 1. Overview

By default, eunox reads sensitive configuration values (HMAC secrets, admin API
keys, database URLs) from environment variables supplied at container startup.
On EKS, these can be sourced from **AWS Secrets Manager** instead of being
stored in plaintext Kubernetes Secrets.

Two integration patterns are supported:

| Approach                                          | How secrets reach the pod                                                           | Best for                                  |
| ------------------------------------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------- |
| **External Secrets Operator (ESO)**               | Kubernetes `Secret` objects synced from Secrets Manager by an in-cluster controller | Teams already using ESO; GitOps workflows |
| **AWS Secrets and Configuration Provider (ASCP)** | Secrets mounted as files (or env vars) via the Secrets Store CSI driver             | Minimal footprint; audit log per-mount    |

Both patterns use IRSA — the pod never holds an AWS access key. See
[`docs/deploy-eks.md`](./deploy-eks.md) §3 for IRSA setup.

---

## 2. Secrets to manage

The following eunox secrets should be stored in AWS Secrets Manager in
production deployments:

| Secret name (recommended)             | eunox environment variable | Description                                                                                        |
| ------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------- |
| `eunox/prod/audit-ledger-hmac-secret` | `AUDIT_LEDGER_HMAC_SECRET` | 64-hex-char HMAC key for audit ledger integrity                                                    |
| `eunox/prod/gateway-admin-api-key`    | `ADMIN_API_KEY`            | Gateway admin API key (≥ 32 chars; referred to as `GATEWAY_ADMIN_API_KEY` in the multi-cloud plan) |
| `eunox/prod/partner-did-pin-secret`   | `PARTNER_DID_PIN_SECRET`   | Secret for partner DID pin derivation                                                                              |
| `eunox/prod/redis-url`                | `REDIS_URL`                | Redis connection string (incl. password)                                                           |
| `eunox/prod/audit-ledger-pg-url`      | `AUDIT_LEDGER_PG_URL`      | PostgreSQL connection string for the audit ledger                                                  |
| `eunox/prod/issuer-db-url`            | `ISSUER_DB_URL`            | PostgreSQL connection string for the capability issuer                                             |
| `eunox/prod/issuer-scim-bearer-token` | `ISSUER_SCIM_BEARER_TOKEN` | SCIM 2.0 provisioning bearer token                                                                 |

Create each secret:

```bash
aws secretsmanager create-secret \
  --name eunox/prod/audit-ledger-hmac-secret \
  --secret-string "$(openssl rand -hex 32)" \
  --region us-east-1

aws secretsmanager create-secret \
  --name eunox/prod/gateway-admin-api-key \
  --secret-string "$(openssl rand -base64 32 | tr -d '\n')" \
  --region us-east-1

# Repeat for remaining secrets …
```

---

## 3. IAM policies

### 3.1 `EunoSecretsReadPolicy` — Secrets Manager read

Both ESO and ASCP require an IAM policy that permits `secretsmanager:GetSecretValue`
on the relevant secrets.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EunoSecretsRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:eunox/prod/*"
      ]
    }
  ]
}
```

Save this as `EunoSecretsReadPolicy` (referenced in the IRSA setup in
[`docs/deploy-eks.md`](./deploy-eks.md) §3):

```bash
aws iam create-policy \
  --policy-name EunoSecretsReadPolicy \
  --policy-document file://iam-policies/eunox-secrets-read.json
```

### 3.2 `EunoKmsSigningPolicy` — KMS signing

The `capability-issuer` and `tool-gateway` pods need KMS signing access when
`SIGNING_PROVIDER=aws-kms`. This policy must be scoped to the specific key ARN.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EunoKmsSigning",
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": ["arn:aws:kms:us-east-1:123456789012:key/<key-id>"]
    }
  ]
}
```

Create the policy:

```bash
aws iam create-policy \
  --policy-name EunoKmsSigningPolicy \
  --policy-document file://iam-policies/eunox-kms-signing.json
```

> **Key requirements:** The KMS key must be an asymmetric key with key usage
> `SIGN_VERIFY` and key spec `RSA_2048` (or `ECC_NIST_P256` for ECDSA).
> Set `AWS_KMS_KEY_ID` in the service env to the full key ARN or key alias.

---

## 4. External Secrets Operator (ESO)

### 4.1 Install ESO

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update external-secrets

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true
```

### 4.2 `SecretStore`

Create an ESO `SecretStore` in the `eunox` namespace that uses the IRSA
service account to authenticate to Secrets Manager:

```yaml
# k8s/eso-secret-store-aws.yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: eunox-aws-secrets
  namespace: eunox
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: eunox-gateway # the IRSA-annotated service account
```

### 4.3 `ExternalSecret` for `tool-gateway`

```yaml
# k8s/eso-gateway-secrets.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: eunox-gateway-secrets
  namespace: eunox
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: eunox-aws-secrets
    kind: SecretStore
  target:
    name: eunox-gateway-secret
    creationPolicy: Owner
  data:
    - secretKey: AUDIT_LEDGER_HMAC_SECRET
      remoteRef:
        key: eunox/prod/audit-ledger-hmac-secret
    - secretKey: ADMIN_API_KEY
      remoteRef:
        key: eunox/prod/gateway-admin-api-key
    - secretKey: PARTNER_DID_PIN_SECRET
      remoteRef:
        key: eunox/prod/partner-did-pin-secret
    - secretKey: REDIS_URL
      remoteRef:
        key: eunox/prod/redis-url
    - secretKey: AUDIT_LEDGER_PG_URL
      remoteRef:
        key: eunox/prod/audit-ledger-pg-url
```

### 4.4 `ExternalSecret` for `capability-issuer`

```yaml
# k8s/eso-issuer-secrets.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: eunox-issuer-secrets
  namespace: eunox
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: eunox-aws-secrets
    kind: SecretStore
  target:
    name: eunox-issuer-secret
    creationPolicy: Owner
  data:
    - secretKey: ISSUER_DB_URL
      remoteRef:
        key: eunox/prod/issuer-db-url
    - secretKey: ISSUER_SCIM_BEARER_TOKEN
      remoteRef:
        key: eunox/prod/issuer-scim-bearer-token
```

### 4.5 Reference the synced `Secret` in Helm

Tell the Helm chart to use the Kubernetes `Secret` created by ESO rather than
supplying `secretEnv` values directly:

```yaml
# values-aws.yaml excerpt
gateway:
  existingSecret: eunox-gateway-secret

issuer:
  existingSecret: eunox-issuer-secret
```

> ESO syncs secrets on the `refreshInterval`. Rotation in Secrets Manager is
> picked up on the next sync cycle; a rolling restart is needed for the pods
> to load the new values. Set `refreshInterval: 5m` if you need faster
> rotation pickup.

---

## 5. AWS Secrets and Configuration Provider (ASCP)

ASCP mounts secrets directly from Secrets Manager as files or environment
variables using the **Secrets Store CSI Driver**, without creating a
Kubernetes `Secret` object.

### 5.1 Install the Secrets Store CSI Driver and ASCP provider

```bash
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true

# Install the AWS provider
kubectl apply -f \
  https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
```

### 5.2 `SecretProviderClass` for `tool-gateway`

```yaml
# k8s/ascp-gateway.yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: eunox-gateway-ascp
  namespace: eunox
spec:
  provider: aws
  secretObjects:
    - secretName: eunox-gateway-secret
      type: Opaque
      data:
        - objectName: audit-ledger-hmac-secret
          key: AUDIT_LEDGER_HMAC_SECRET
        - objectName: gateway-admin-api-key
          key: ADMIN_API_KEY
        - objectName: partner-did-pin-secret
          key: PARTNER_DID_PIN_SECRET
        - objectName: redis-url
          key: REDIS_URL
        - objectName: audit-ledger-pg-url
          key: AUDIT_LEDGER_PG_URL
  parameters:
    objects: |
      - objectName: "eunox/prod/audit-ledger-hmac-secret"
        objectType: "secretsmanager"
        objectAlias: "audit-ledger-hmac-secret"
      - objectName: "eunox/prod/gateway-admin-api-key"
        objectType: "secretsmanager"
        objectAlias: "gateway-admin-api-key"
      - objectName: "eunox/prod/partner-did-pin-secret"
        objectType: "secretsmanager"
        objectAlias: "partner-did-pin-secret"
      - objectName: "eunox/prod/redis-url"
        objectType: "secretsmanager"
        objectAlias: "redis-url"
      - objectName: "eunox/prod/audit-ledger-pg-url"
        objectType: "secretsmanager"
        objectAlias: "audit-ledger-pg-url"
```

### 5.3 Reference in Helm

```yaml
# values-aws.yaml excerpt (ASCP variant)
gateway:
  existingSecret: eunox-gateway-secret
  volumeMounts:
    - name: secrets-store
      mountPath: /mnt/secrets
      readOnly: true
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: eunox-gateway-ascp
```

> ASCP requires a volume mount to trigger the CSI driver even when you only
> need `secretObjects` env-var sync. The mount path `/mnt/secrets` is not
> read by the eunox process itself — only the synced Kubernetes `Secret` is.

---

## 6. ESO vs. ASCP — comparison

| Concern                                   | External Secrets Operator                                                  | ASCP (Secrets Store CSI)                                            |
| ----------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Kubernetes Secret object created          | ✅ Yes (synced by controller)                                              | ✅ Yes (via `secretObjects`)                                        |
| Secret present in `etcd`                  | ✅ Yes (encrypted at rest)                                                 | ✅ Yes (via `secretObjects`)                                        |
| Volume mount required                     | ❌ No                                                                      | ✅ Yes (triggers CSI driver)                                        |
| Rotation without pod restart              | ✅ On next `refreshInterval` (pod restart still needed for env-var reload) | ✅ `enableSecretRotation=true` (env-var reload still needs restart) |
| Additional cluster components             | ESO controller + CRDs                                                      | CSI driver + AWS provider DaemonSet                                 |
| GitOps friendly                           | ✅ CRD manifests are declarative                                           | ✅ `SecretProviderClass` is declarative                             |
| Works without IRSA (EC2 instance profile) | ✅ Yes                                                                     | ✅ Yes                                                              |
| AWS-native (no third-party operator)      | ❌ ESO is open-source third-party                                          | ✅ AWS-maintained provider                                          |
| Multi-cloud secret store support          | ✅ Azure, GCP, Vault, …                                                    | ⚠️ AWS-only provider                                                |

**Recommendation:**

- Use **ESO** if you already run it for other workloads or need multi-cloud
  secret store support (e.g. Azure Key Vault for the Azure deployment of the
  same chart).
- Use **ASCP** if you prefer AWS-native components and want to minimise
  third-party operators in the cluster.

---

## 7. Secret rotation

Both ESO and ASCP can automatically reload secrets when they are rotated in
Secrets Manager. However, environment variables are **not** reloaded in a
running process — a rolling restart is required.

Trigger a rolling restart after rotation:

```bash
kubectl rollout restart deployment/eunox-tool-gateway -n eunox
kubectl rollout restart deployment/eunox-capability-issuer -n eunox
```

Automate this with an EventBridge rule that triggers a Lambda function on the
`RotateSecret` event.

---

## 8. Security checklist

- [ ] All secrets listed in §2 are stored in AWS Secrets Manager — none are
      committed to source control or stored as plaintext in ConfigMaps.
- [ ] The `EunoSecretsReadPolicy` IAM policy uses the principle of least
      privilege — only `GetSecretValue` and `DescribeSecret` on the
      `eunox/prod/*` prefix.
- [ ] IRSA is used for pod authentication — no long-lived access keys in
      pod environment variables.
- [ ] Secrets Manager resource-based policy restricts cross-account access.
- [ ] Secret rotation is configured for `AUDIT_LEDGER_HMAC_SECRET` and
      `ADMIN_API_KEY` (rotation cadence: ≤ 90 days for SOC 2 CC6.1).
- [ ] CloudTrail is capturing `secretsmanager:GetSecretValue` calls for the
      `eunox/prod/*` prefix; alerts are configured for unexpected access
      patterns.

---

## 9. Native SDK integration — `AwsSecretsManagerSecretStore` (Phase 2)

eunox now ships a native `AwsSecretsManagerSecretStore` implementation in
`@eunox/common-core` that fetches secrets from Secrets Manager at runtime using
the standard AWS SDK v3 credential provider chain (IRSA, EC2 instance profile,
`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars).

### 9.1 ARN-based fallback pattern

Instead of managing external Kubernetes Secrets or volume mounts, operators can
tell eunox to fetch specific secrets directly from Secrets Manager at startup by
setting `AWS_SECRETS_ARN_*` environment variables.

```bash
# Pod environment (e.g. injected via EKS Pod Identity / IRSA-annotated Deployment)
SECRET_STORE_PROVIDER=aws-secretsmanager
AWS_REGION=us-east-1

# Pin individual secrets to their Secrets Manager ARNs:
AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET=arn:aws:secretsmanager:us-east-1:123456789012:secret:eunox/prod/audit-ledger-hmac-secret
AWS_SECRETS_ARN_ADMIN_API_KEY=arn:aws:secretsmanager:us-east-1:123456789012:secret:eunox/prod/gateway-admin-api-key

# Secrets without an ARN override are still read from env vars (fallback):
PARTNER_DID_PIN_SECRET=changeme   # still a plain env var for non-sensitive overrides
```

`createSecretStoreFromEnv()` (called automatically by service startup)
auto-builds the `arnsBySecretName` map from every `AWS_SECRETS_ARN_<NAME>`
variable it finds. For any name without an ARN entry, the store returns the
value of `process.env[name]` directly — identical to the default
`EnvSecretStore` behaviour.

This **incremental migration** approach lets operators move secrets to Secrets
Manager one at a time without changing the rest of the configuration.

### 9.2 IAM policy addition

The pod's IRSA role needs `secretsmanager:GetSecretValue` on each pinned ARN.
The existing `EunoSecretsReadPolicy` from §3.1 already covers the `eunox/prod/*`
prefix. If you use explicit ARNs outside that prefix, add them to the policy
`Resource` array.

### 9.3 ASCP / ESO vs. native SDK

| Approach                             | Requires cluster component | Requires Kubernetes Secret | Direct Secrets Manager call at startup |
| ------------------------------------ | -------------------------- | -------------------------- | -------------------------------------- |
| ESO                                  | ✅ ESO controller          | ✅ synced `Secret`         | ❌                                     |
| ASCP                                 | ✅ CSI driver              | ✅ via `secretObjects`     | ❌                                     |
| **Native SDK (`AWS_SECRETS_ARN_*`)** | ❌ None                    | ❌ None                    | ✅                                     |

Use the native SDK approach when you want to minimise cluster components and
are comfortable with the pod startup latency of a Secrets Manager API call
(typically < 50 ms for same-region calls).

### 9.4 EdDSA shim for partner DID (`did:ion`) use cases (Phase 2)

AWS KMS does not natively support Ed25519 keys. For partner-issued tokens using
EdDSA signatures (`did:ion` / `did:key#Ed25519`), configure the `AwsEdDsaSigner`
shim:

```bash
# Store the PEM-encoded Ed25519 PKCS#8 private key in Secrets Manager:
aws secretsmanager create-secret \
  --name eunox/prod/partner-eddsa-key \
  --secret-string "$(cat partner-ed25519-key.pem)" \
  --region us-east-1

# Pod environment:
AWS_EDDSA_KEY_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:eunox/prod/partner-eddsa-key
AWS_EDDSA_KEY_ID=partner-signing-key-v1   # JWT kid claim (optional; defaults to ARN)
```

The `AwsEdDsaSigner` fetches the PEM from Secrets Manager on the first sign
call, caches it in memory, and signs locally using `jose` (EdDSA / Ed25519).

**IAM policy** — the same `EunoSecretsReadPolicy` covers the EdDSA key secret
if it is under the `eunox/prod/*` prefix. Add it to the `Resource` array if
stored elsewhere.

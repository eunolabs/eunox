# GCP Secret Manager Integration

> **Target audience:** Platform engineers configuring eunox to read secrets
> from GCP Secret Manager at pod startup on GKE.
>
> **Status:** Multi-cloud Phase 1 documentation.
>
> **Related documents:**
>
> - [`docs/deploy-gke.md`](./deploy-gke.md) — full GKE deployment guide
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — environment-variable reference
> - [`docs/multi-cloud-plan.md`](./multi-cloud-plan.md) — multi-cloud runbook index

---

## 1. Overview

By default, eunox reads sensitive configuration values (HMAC secrets, admin API
keys, database URLs) from environment variables supplied at container startup.
On GKE, these can be sourced from **GCP Secret Manager** instead of being
stored in plaintext Kubernetes Secrets.

Two integration patterns are supported:

| Approach                            | How secrets reach the pod                                                          | Best for                                                           |
| ----------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **External Secrets Operator (ESO)** | Kubernetes `Secret` objects synced from Secret Manager by an in-cluster controller | Teams already using ESO; GitOps workflows; multi-cloud deployments |
| **Secret Manager Add-on**           | Secrets mounted as files via the Secrets Store CSI Driver                          | Minimal footprint; GCP-native; per-mount audit log                 |

Both patterns use **Workload Identity Federation** — the pod never holds a
JSON service account key file. See [`docs/deploy-gke.md`](./deploy-gke.md) §3
for Workload Identity setup.

---

## 2. Secrets to manage

The following eunox secrets should be stored in GCP Secret Manager in
production deployments:

| Secret name (recommended)             | eunox environment variable | Description                                            |
| ------------------------------------- | -------------------------- | ------------------------------------------------------ |
| `eunox-prod-audit-ledger-hmac-secret` | `AUDIT_LEDGER_HMAC_SECRET` | 64-hex-char HMAC key for audit ledger integrity        |
| `eunox-prod-gateway-admin-api-key`    | `ADMIN_API_KEY`            | Gateway admin API key (≥ 32 chars)                     |
| `eunox-prod-partner-did-pin-secret`   | `PARTNER_DID_PIN_SECRET`   | Secret for partner DID pin derivation (Stage 5)        |
| `eunox-prod-redis-url`                | `REDIS_URL`                | Redis connection string (incl. password)               |
| `eunox-prod-audit-ledger-pg-url`      | `AUDIT_LEDGER_PG_URL`      | PostgreSQL connection string for the audit ledger      |
| `eunox-prod-issuer-db-url`            | `ISSUER_DB_URL`            | PostgreSQL connection string for the capability issuer |
| `eunox-prod-issuer-scim-bearer-token` | `ISSUER_SCIM_BEARER_TOKEN` | SCIM 2.0 provisioning bearer token                     |

Create each secret:

```bash
PROJECT_ID="my-gcp-project"

gcloud secrets create eunox-prod-audit-ledger-hmac-secret \
  --project "${PROJECT_ID}" \
  --replication-policy automatic

echo -n "$(openssl rand -hex 32)" | \
  gcloud secrets versions add eunox-prod-audit-ledger-hmac-secret \
  --project "${PROJECT_ID}" \
  --data-file=-

gcloud secrets create eunox-prod-gateway-admin-api-key \
  --project "${PROJECT_ID}" \
  --replication-policy automatic

echo -n "$(openssl rand -base64 32 | tr -d '\n')" | \
  gcloud secrets versions add eunox-prod-gateway-admin-api-key \
  --project "${PROJECT_ID}" \
  --data-file=-

# Repeat for remaining secrets …
```

---

## 3. IAM bindings

### 3.1 Secret Accessor role — scoped to individual secrets

Bind each GCP service account to only the secrets it needs, following the
principle of least privilege. Avoid the project-wide `roles/secretmanager.secretAccessor`
binding shown in the cluster setup guide — use per-secret bindings in production.

```bash
# Grant gateway service account access to gateway secrets only
for SECRET in \
  eunox-prod-audit-ledger-hmac-secret \
  eunox-prod-gateway-admin-api-key \
  eunox-prod-partner-did-pin-secret \
  eunox-prod-redis-url \
  eunox-prod-audit-ledger-pg-url; do

  gcloud secrets add-iam-policy-binding "${SECRET}" \
    --project "${PROJECT_ID}" \
    --member "serviceAccount:eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role "roles/secretmanager.secretAccessor"
done

# Grant issuer service account access to issuer secrets only
for SECRET in \
  eunox-prod-issuer-db-url \
  eunox-prod-issuer-scim-bearer-token; do

  gcloud secrets add-iam-policy-binding "${SECRET}" \
    --project "${PROJECT_ID}" \
    --member "serviceAccount:eunox-issuer@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role "roles/secretmanager.secretAccessor"
done
```

### 3.2 Verify the bindings

```bash
gcloud secrets get-iam-policy eunox-prod-audit-ledger-hmac-secret \
  --project "${PROJECT_ID}"
```

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

Create an ESO `SecretStore` in the `eunox` namespace that uses the Workload
Identity-bound service account to authenticate to Secret Manager:

```yaml
# k8s/eso-secret-store-gcp.yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: eunox-gcp-secrets
  namespace: eunox
spec:
  provider:
    gcpsm:
      projectID: my-gcp-project
      auth:
        workloadIdentity:
          clusterLocation: us-central1
          clusterName: eunox-prod
          serviceAccountRef:
            name: eunox-gateway # the Workload Identity-annotated service account
```

### 4.3 `ExternalSecret` for `tool-gateway`

```yaml
# k8s/eso-gateway-secrets-gcp.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: eunox-gateway-secrets
  namespace: eunox
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: eunox-gcp-secrets
    kind: SecretStore
  target:
    name: eunox-gateway-secret
    creationPolicy: Owner
  data:
    - secretKey: AUDIT_LEDGER_HMAC_SECRET
      remoteRef:
        key: eunox-prod-audit-ledger-hmac-secret
    - secretKey: ADMIN_API_KEY
      remoteRef:
        key: eunox-prod-gateway-admin-api-key
    - secretKey: PARTNER_DID_PIN_SECRET
      remoteRef:
        key: eunox-prod-partner-did-pin-secret
    - secretKey: REDIS_URL
      remoteRef:
        key: eunox-prod-redis-url
    - secretKey: AUDIT_LEDGER_PG_URL
      remoteRef:
        key: eunox-prod-audit-ledger-pg-url
```

### 4.4 `ExternalSecret` for `capability-issuer`

```yaml
# k8s/eso-issuer-secrets-gcp.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: eunox-issuer-secrets
  namespace: eunox
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: eunox-gcp-secrets
    kind: SecretStore
  target:
    name: eunox-issuer-secret
    creationPolicy: Owner
  data:
    - secretKey: ISSUER_DB_URL
      remoteRef:
        key: eunox-prod-issuer-db-url
    - secretKey: ISSUER_SCIM_BEARER_TOKEN
      remoteRef:
        key: eunox-prod-issuer-scim-bearer-token
```

### 4.5 Reference the synced `Secret` in Helm

```yaml
# values-gcp.yaml excerpt
gateway:
  existingSecret: eunox-gateway-secret

issuer:
  existingSecret: eunox-issuer-secret
```

> ESO syncs secrets on the `refreshInterval`. Rotation in Secret Manager is
> picked up on the next sync cycle; a rolling restart is needed for the pods
> to load the new values.

---

## 5. Secret Manager Add-on (Secrets Store CSI Driver)

The **Secret Manager Add-on** mounts secrets directly from GCP Secret Manager
as files (or synced Kubernetes Secrets) via the **Secrets Store CSI Driver**.

### 5.1 Enable the add-on on the GKE cluster

```bash
gcloud container clusters update "${CLUSTER_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --update-addons GcpFilestoreCsiDriver=DISABLED \
  --update-addons SecretManagerAddon=ENABLED
```

Alternatively, enable it at cluster creation time:

```bash
gcloud container clusters create "${CLUSTER_NAME}" \
  ... \
  --addons SecretManagerAddon
```

### 5.2 `SecretProviderClass` for `tool-gateway`

```yaml
# k8s/spc-gateway-gcp.yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: eunox-gateway-spc
  namespace: eunox
spec:
  provider: gcp
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
    secrets: |
      - resourceName: "projects/my-gcp-project/secrets/eunox-prod-audit-ledger-hmac-secret/versions/latest"
        fileName: "audit-ledger-hmac-secret"
      - resourceName: "projects/my-gcp-project/secrets/eunox-prod-gateway-admin-api-key/versions/latest"
        fileName: "gateway-admin-api-key"
      - resourceName: "projects/my-gcp-project/secrets/eunox-prod-partner-did-pin-secret/versions/latest"
        fileName: "partner-did-pin-secret"
      - resourceName: "projects/my-gcp-project/secrets/eunox-prod-redis-url/versions/latest"
        fileName: "redis-url"
      - resourceName: "projects/my-gcp-project/secrets/eunox-prod-audit-ledger-pg-url/versions/latest"
        fileName: "audit-ledger-pg-url"
```

### 5.3 Reference in Helm

```yaml
# values-gcp.yaml excerpt (Secret Manager Add-on variant)
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
          secretProviderClass: eunox-gateway-spc
```

> The Secret Manager Add-on requires a volume mount to trigger the CSI driver
> even when you only need the synced Kubernetes `Secret`. The mount path
> `/mnt/secrets` is not read by the eunox process — only the synced Secret is.

---

## 6. ESO vs. Secret Manager Add-on — comparison

| Concern                              | External Secrets Operator                               | Secret Manager Add-on (CSI)                                       |
| ------------------------------------ | ------------------------------------------------------- | ----------------------------------------------------------------- |
| Kubernetes Secret object created     | ✅ Yes (synced by controller)                           | ✅ Yes (via `secretObjects`)                                      |
| Secret present in `etcd`             | ✅ Yes (encrypted at rest)                              | ✅ Yes (via `secretObjects`)                                      |
| Volume mount required                | ❌ No                                                   | ✅ Yes (triggers CSI driver)                                      |
| Rotation without pod restart         | ✅ On next `refreshInterval` (pod restart still needed) | ✅ With auto-rotation enabled (restart still needed for env vars) |
| Additional cluster components        | ESO controller + CRDs                                   | CSI driver + GCP provider                                         |
| GitOps friendly                      | ✅ CRD manifests are declarative                        | ✅ `SecretProviderClass` is declarative                           |
| Works with Workload Identity         | ✅ Yes                                                  | ✅ Yes                                                            |
| GCP-native (no third-party operator) | ❌ ESO is open-source third-party                       | ✅ GCP-maintained add-on                                          |
| Multi-cloud secret store support     | ✅ Azure, AWS, Vault, …                                 | ⚠️ GCP-only (CSI driver supports multiple providers)              |

**Recommendation:**

- Use **ESO** if you already run it for other workloads or need multi-cloud
  secret store support (e.g. Azure Key Vault for the Azure deployment of the
  same chart, or AWS Secrets Manager for an AWS deployment).
- Use the **Secret Manager Add-on** if you prefer GCP-native components and
  want to minimise third-party operators in the cluster.

---

## 7. Secret rotation

Both ESO and the Secret Manager Add-on can automatically reload secrets when
they are rotated in GCP Secret Manager. However, environment variables are
**not** reloaded in a running process — a rolling restart is required.

Trigger a rolling restart after rotation:

```bash
kubectl rollout restart deployment/eunox-tool-gateway -n eunox
kubectl rollout restart deployment/eunox-capability-issuer -n eunox
```

Automate this with a Cloud Pub/Sub notification and a Cloud Run service that
calls the GKE API after a `SECRET_VERSION_ADD` event:

```bash
# Enable Secret Manager notifications
gcloud secrets update eunox-prod-audit-ledger-hmac-secret \
  --project "${PROJECT_ID}" \
  --add-topics "projects/${PROJECT_ID}/topics/eunox-secret-rotation"
```

---

## 8. Security checklist

- [ ] All secrets listed in §2 are stored in GCP Secret Manager — none are
      committed to source control or stored as plaintext in ConfigMaps.
- [ ] Per-secret IAM bindings are used (§3.1) — not a project-wide
      `roles/secretmanager.secretAccessor` binding.
- [ ] Workload Identity Federation is used for pod authentication — no JSON
      service account key files in pod environments or mounted secrets.
- [ ] Secret Manager audit logs (`data_access` type `DATA_READ`) are enabled
      and retained for at least 90 days (SOC 2 CC6.1).
- [ ] Secret rotation is configured for `AUDIT_LEDGER_HMAC_SECRET` and
      `ADMIN_API_KEY` (rotation cadence: ≤ 90 days).
- [ ] Secret versions that are no longer in use are disabled or destroyed
      to limit the blast radius of a key compromise.
- [ ] Cloud Audit Logs alerts are configured for unexpected
      `secretmanager.googleapis.com/access` events on `eunox-prod-*` secrets.

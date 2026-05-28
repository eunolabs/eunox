# Deploying eunox on Google Kubernetes Engine (GKE)

> **Target audience:** Platform engineers deploying the eunox platform on GCP
> Google Kubernetes Engine (GKE).
>
> **Status:** Multi-cloud Phase 1 documentation.
>
> **Related documents:**
>
> - [`docs/deployment.md`](./deployment.md) — full environment-variable reference
> - [`docs/secrets-gcp.md`](./secrets-gcp.md) — GCP Secret Manager integration
> - [`docs/issuer-idp-setup.md`](./issuer-idp-setup.md) — IdP setup (Google Workspace SCIM §11)
> - [`docs/self-host.md`](./self-host.md) — self-host overview

---

## 1. Prerequisites

| Requirement                                                                                                             | Version / notes |
| ----------------------------------------------------------------------------------------------------------------------- | --------------- |
| Google Cloud SDK (`gcloud`)                                                                                             | ≥ 450.0         |
| `kubectl`                                                                                                               | ≥ 1.29          |
| Helm                                                                                                                    | ≥ 3.14          |
| GCP project with permissions to create GKE clusters, IAM service accounts, Artifact Registry, Cloud KMS, Secret Manager |                 |

---

## 2. Cluster setup

### 2.1 Create a GKE cluster with Workload Identity

```bash
PROJECT_ID="my-gcp-project"
REGION="us-central1"
CLUSTER_NAME="eunox-prod"

gcloud container clusters create "${CLUSTER_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --release-channel regular \
  --workload-pool "${PROJECT_ID}.svc.id.goog" \
  --num-nodes 1 \
  --min-nodes 1 \
  --max-nodes 5 \
  --enable-autoscaling \
  --machine-type n2-standard-2 \
  --disk-type pd-ssd \
  --disk-size 50 \
  --enable-ip-alias \
  --enable-network-policy
```

The `--workload-pool` flag enables **Workload Identity Federation** for the
cluster. This is the GCP equivalent of AWS IRSA — it allows pods to
authenticate as GCP service accounts without any key files on disk.

### 2.2 Authenticate `kubectl`

```bash
gcloud container clusters get-credentials "${CLUSTER_NAME}" \
  --region "${REGION}" \
  --project "${PROJECT_ID}"
```

---

## 3. Workload Identity Federation

Workload Identity Federation allows individual pods to impersonate GCP
service accounts. This is the recommended credential model for GKE — do
**not** use JSON service account key files in pod environment variables.

### 3.1 Create GCP service accounts

```bash
# capability-issuer service account
gcloud iam service-accounts create eunox-issuer \
  --project "${PROJECT_ID}" \
  --display-name "eunox capability-issuer"

# tool-gateway service account
gcloud iam service-accounts create eunox-gateway \
  --project "${PROJECT_ID}" \
  --display-name "eunox tool-gateway"
```

### 3.2 Grant IAM roles to the GCP service accounts

The `capability-issuer` needs:

- **Cloud KMS** signing access (if `SIGNING_PROVIDER=gcp-cloudkms`)
- **Secret Manager** read access (if using Secret Manager for secrets)

```bash
KMS_KEY_RESOURCE="projects/${PROJECT_ID}/locations/global/keyRings/eunox/cryptoKeys/issuer-signing-key"

# Cloud KMS signing (attach if SIGNING_PROVIDER=gcp-cloudkms)
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-issuer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/cloudkms.signerVerifier"

# Secret Manager accessor
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-issuer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/secretmanager.secretAccessor"
```

The `tool-gateway` needs:

- **Cloud KMS** signing access (for audit evidence signing)
- **Secret Manager** read access
- **Cloud Storage** write access (if `ENABLE_CROSS_CHAIN_ANCHOR=true` with GCS)

```bash
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/cloudkms.signerVerifier"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/secretmanager.secretAccessor"

# GCS cross-chain anchor (only if ENABLE_CROSS_CHAIN_ANCHOR=true)
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/storage.objectAdmin"
```

See [`docs/secrets-gcp.md`](./secrets-gcp.md) §3 for scoped Secret Manager
IAM binding patterns.

### 3.3 Bind Kubernetes ServiceAccounts to GCP service accounts

```bash
# capability-issuer
gcloud iam service-accounts add-iam-policy-binding \
  "eunox-issuer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project "${PROJECT_ID}" \
  --role "roles/iam.workloadIdentityUser" \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[eunox/eunox-issuer]"

# tool-gateway
gcloud iam service-accounts add-iam-policy-binding \
  "eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project "${PROJECT_ID}" \
  --role "roles/iam.workloadIdentityUser" \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[eunox/eunox-gateway]"
```

### 3.4 Annotate Kubernetes ServiceAccounts

The Helm chart creates `ServiceAccount` resources for each service. Annotate
them with the GCP service account email before or after install:

```bash
kubectl annotate serviceaccount eunox-issuer \
  -n eunox \
  iam.gke.io/gcp-service-account=eunox-issuer@${PROJECT_ID}.iam.gserviceaccount.com

kubectl annotate serviceaccount eunox-gateway \
  -n eunox \
  iam.gke.io/gcp-service-account=eunox-gateway@${PROJECT_ID}.iam.gserviceaccount.com
```

Alternatively, supply the annotation via Helm values:

```yaml
# k8s/helm/eunox/values-gcp.yaml excerpt
issuer:
  serviceAccountAnnotations:
    iam.gke.io/gcp-service-account: "eunox-issuer@my-gcp-project.iam.gserviceaccount.com"

gateway:
  serviceAccountAnnotations:
    iam.gke.io/gcp-service-account: "eunox-gateway@my-gcp-project.iam.gserviceaccount.com"
```

---

## 4. Artifact Registry image configuration

### 4.1 Create an Artifact Registry repository

```bash
gcloud artifacts repositories create eunox \
  --project "${PROJECT_ID}" \
  --repository-format docker \
  --location "${REGION}" \
  --description "eunox container images"
```

### 4.2 Authenticate Docker to Artifact Registry

```bash
gcloud auth configure-docker "${REGION}-docker.pkg.dev"
```

### 4.3 Push eunox images to Artifact Registry

For air-gapped or locked-down deployments, pull the images from the public
registry and push them to your private Artifact Registry repository.

```bash
#!/bin/bash
# push-images-to-artifact-registry.sh
# Usage: GCP_PROJECT=my-gcp-project GCP_REGION=us-central1 ./push-images-to-artifact-registry.sh

set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT}"
GCP_REGION="${GCP_REGION:-us-central1}"
AR_REGISTRY="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/eunox"
EUNOX_VERSION="${EUNOX_VERSION:-1.0.0}"

IMAGES=(
  tool-gateway
  capability-issuer
  api-key-minter
  db-token-service
  storage-grant-service
  posture-emitter
)

gcloud auth configure-docker "${GCP_REGION}-docker.pkg.dev" --quiet

for img in "${IMAGES[@]}"; do
  SRC="ghcr.io/eunolabs/eunox/${img}:${EUNOX_VERSION}"
  DST="${AR_REGISTRY}/${img}:${EUNOX_VERSION}"
  docker pull "${SRC}"
  docker tag  "${SRC}" "${DST}"
  docker push "${DST}"
done

echo "All images pushed to ${AR_REGISTRY}/"
```

### 4.4 GKE image pull configuration

GKE nodes in the same project as the Artifact Registry repository authenticate
automatically — no `imagePullSecrets` are required.

For cross-project Artifact Registry:

```bash
# AR_PROJECT_ID  = project that owns the Artifact Registry repository.
# PROJECT_ID     = project that hosts the GKE cluster (defined earlier in this guide).
# Grant the GKE node service account read access to the cross-project registry.
AR_PROJECT_ID="${AR_PROJECT_ID:?set AR_PROJECT_ID to the Artifact Registry host project}"
gcloud artifacts repositories add-iam-policy-binding eunox \
  --project "${AR_PROJECT_ID}" \
  --location "${REGION}" \
  --member "serviceAccount:$(gcloud projects describe ${PROJECT_ID} \
    --format='value(projectNumber)')-compute@developer.gserviceaccount.com" \
  --role "roles/artifactregistry.reader"
```

---

## 5. GKE Ingress and Google-managed SSL certificate

### 5.1 Reserve a static external IP address

```bash
gcloud compute addresses create eunox-ingress-ip \
  --project "${PROJECT_ID}" \
  --global

# Note the allocated IP:
gcloud compute addresses describe eunox-ingress-ip \
  --project "${PROJECT_ID}" \
  --global \
  --format "value(address)"
```

Point your DNS A record for `eunox.example.com` and `issuer.eunox.example.com`
at this IP address before creating the ManagedCertificate (GCP validates
domain ownership via HTTP-01).

### 5.2 Create a Google-managed SSL certificate

```bash
# k8s/managed-cert-gcp.yaml
cat <<EOF | kubectl apply -f -
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: eunox-cert
  namespace: eunox
spec:
  domains:
    - eunox.example.com
    - issuer.eunox.example.com
EOF
```

> Google-managed SSL certificates provision automatically after the Ingress is
> created and DNS is resolving to the static IP. Provisioning typically takes
> 15–60 minutes. Check status with:
> `kubectl describe managedcertificate eunox-cert -n eunox`

### 5.3 GKE Ingress resource

Create an Ingress that routes external traffic to the gateway and issuer:

```yaml
# k8s/ingress-gcp.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: eunox-ingress
  namespace: eunox
  annotations:
    kubernetes.io/ingress.class: "gce"
    kubernetes.io/ingress.global-static-ip-name: "eunox-ingress-ip"
    networking.gke.io/managed-certificates: "eunox-cert"
    kubernetes.io/ingress.allow-http: "false"
spec:
  rules:
    - host: eunox.example.com
      http:
        paths:
          - path: /api/v1/
            pathType: Prefix
            backend:
              service:
                name: eunox-tool-gateway
                port:
                  number: 3002
    - host: issuer.eunox.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: eunox-capability-issuer
                port:
                  number: 3001
```

> **Note:** The gateway admin port (`3003`) must **not** be exposed via the
> public GKE Ingress. Restrict admin access to internal load balancers or
> use `kubectl port-forward` for administrative tasks.

---

## 6. Helm deployment

### 6.1 Install the Helm chart

```bash
kubectl create namespace eunox

helm install eunox ./k8s/helm/eunox \
  --namespace eunox \
  -f k8s/helm/eunox/values-gcp.yaml \
  --set gateway.secretEnv.AUDIT_LEDGER_HMAC_SECRET="${AUDIT_LEDGER_HMAC_SECRET}" \
  --set gateway.secretEnv.ADMIN_API_KEY="${ADMIN_API_KEY}" \
  --set gateway.secretEnv.REDIS_URL="${REDIS_URL}" \
  --set gateway.secretEnv.AUDIT_LEDGER_PG_URL="${AUDIT_LEDGER_PG_URL}" \
  --set issuer.secretEnv.ISSUER_DB_URL="${ISSUER_DB_URL}"
```

When using the External Secrets Operator or the Secret Manager Add-on, the
`secretEnv` map can be left empty in Helm. See [`docs/secrets-gcp.md`](./secrets-gcp.md).

### 6.2 GCP-specific `values-gcp.yaml` overrides

```yaml
# Full file: k8s/helm/eunox/values-gcp.yaml
# See that file for inline documentation of every override.
```

The complete `values-gcp.yaml` is at `k8s/helm/eunox/values-gcp.yaml` in this
repository.

### 6.3 Verify the deployment

```bash
kubectl get pods -n eunox
kubectl logs -n eunox -l app=eunox-tool-gateway --tail=50
kubectl logs -n eunox -l app=eunox-capability-issuer --tail=50

# Health checks
kubectl exec -n eunox deploy/eunox-tool-gateway -- \
  curl -s http://localhost:3002/healthz | jq .
kubectl exec -n eunox deploy/eunox-capability-issuer -- \
  curl -s http://localhost:3001/healthz | jq .
```

---

## 7. Cloud Monitoring and Security Command Center observability

### 7.1 Prometheus → Cloud Monitoring (OpenTelemetry Collector)

Install the OpenTelemetry Collector to scrape Prometheus metrics from eunox
pods and forward them to Google Cloud Monitoring.

#### 7.1.1 Install the OpenTelemetry Operator

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update open-telemetry

helm install opentelemetry-operator open-telemetry/opentelemetry-operator \
  --namespace opentelemetry-operator-system \
  --create-namespace \
  --set "manager.collectorImage.repository=otel/opentelemetry-collector-contrib"
```

#### 7.1.2 OpenTelemetry Collector configuration

Deploy an `OpenTelemetryCollector` custom resource that scrapes eunox's
Prometheus endpoints and ships metrics to Cloud Monitoring.

```yaml
# k8s/otel-collector-gcp.yaml
apiVersion: opentelemetry.io/v1alpha1
kind: OpenTelemetryCollector
metadata:
  name: eunox-otel
  namespace: eunox
spec:
  serviceAccount:
    eunox-otel-collector # must have Workload Identity binding
    # to roles/monitoring.metricWriter
  config: |
    receivers:
      prometheus:
        config:
          scrape_configs:
            - job_name: eunox-gateway
              scrape_interval: 30s
              static_configs:
                - targets: ["eunox-tool-gateway:3002"]
              metrics_path: /metrics
            - job_name: eunox-issuer
              scrape_interval: 30s
              static_configs:
                - targets: ["eunox-capability-issuer:3001"]
              metrics_path: /metrics

    processors:
      resource:
        attributes:
          - key: gcp.project.id
            value: my-gcp-project
            action: upsert
          - key: k8s.cluster.name
            value: eunox-prod
            action: upsert
          - key: k8s.namespace.name
            value: eunox
            action: upsert

    exporters:
      googlemanagedprometheus:
        project: my-gcp-project

    service:
      pipelines:
        metrics:
          receivers: [prometheus]
          processors: [resource]
          exporters: [googlemanagedprometheus]
```

Grant the collector service account the `roles/monitoring.metricWriter` role
via Workload Identity:

```bash
gcloud iam service-accounts create eunox-otel-collector \
  --project "${PROJECT_ID}" \
  --display-name "eunox OTel Collector"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:eunox-otel-collector@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role "roles/monitoring.metricWriter"

gcloud iam service-accounts add-iam-policy-binding \
  "eunox-otel-collector@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project "${PROJECT_ID}" \
  --role "roles/iam.workloadIdentityUser" \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[eunox/eunox-otel-collector]"
```

Key eunox metrics forwarded to Cloud Monitoring:

| Metric                                    | Description                       | Cloud Monitoring metric type                                              |
| ----------------------------------------- | --------------------------------- | ------------------------------------------------------------------------- |
| `eunox_capability_tokens_issued_total`    | Tokens issued per tenant          | `prometheus.googleapis.com/eunox_capability_tokens_issued_total/counter`  |
| `eunox_audit_events_total`                | Signed audit events per tool      | `prometheus.googleapis.com/eunox_audit_events_total/counter`              |
| `eunox_tool_calls_denied_total`           | Denials per `denial_reason` label | `prometheus.googleapis.com/eunox_tool_calls_denied_total/counter`         |
| `eunox_cross_chain_anchor_lag_seconds`    | GCS anchor write lag              | `prometheus.googleapis.com/eunox_cross_chain_anchor_lag_seconds/gauge`    |
| `eunox_partner_did_circuit_breaker_state` | ION circuit breaker state         | `prometheus.googleapis.com/eunox_partner_did_circuit_breaker_state/gauge` |

### 7.2 OCSF audit events → Security Command Center findings

The tool-gateway emits OCSF-structured audit evidence records. Map them to
GCP **Security Command Center** findings using the following pattern:

#### 7.2.1 Cloud Logging → Pub/Sub → Cloud Run → SCC pipeline

```
tool-gateway audit ledger
  → Cloud Logging (via fluent-bit or the OTel log exporter)
    → Log sink → Pub/Sub topic (eunox-audit-events)
      → Cloud Run (ocsf-to-scc-finding)
        → Security Command Center API (findings.create)
```

#### 7.2.2 OCSF → Security Command Center finding field mapping

| OCSF field                   | SCC finding field               |
| ---------------------------- | ------------------------------- |
| `evidence.agentId`           | `resourceName`                  |
| `evidence.toolName`          | `sourceProperties.toolName`     |
| `evidence.outcome` (`deny`)  | `severity = HIGH`               |
| `evidence.outcome` (`allow`) | `severity = LOW`                |
| `evidence.ts`                | `eventTime` / `createTime`      |
| `evidence.denialReason`      | `description`                   |
| `evidence.tenantId`          | `sourceProperties.tenantId`     |
| `evidence.capabilityId`      | `sourceProperties.capabilityId` |
| `evidence.evidenceId`        | `name` (finding ID)             |

Example Cloud Run handler (Node.js) for the Pub/Sub subscription:

```javascript
// cloud-run/ocsf-to-scc.mjs
import { SecurityCenterClient } from "@google-cloud/security-center";

const scc = new SecurityCenterClient();
const SOURCE_NAME = process.env.SCC_SOURCE_NAME;
// e.g. "organizations/123456789/sources/987654321"

export async function handler(req, res) {
  const message = req.body?.message;
  if (!message) {
    res.sendStatus(204);
    return;
  }

  let evidence;
  try {
    evidence = JSON.parse(Buffer.from(message.data, "base64").toString("utf8"));
  } catch {
    res.sendStatus(204);
    return;
  }
  if (evidence.outcome !== "deny") {
    res.sendStatus(204);
    return;
  }

  const findingId = evidence.evidenceId.replace(/[^a-zA-Z0-9_-]/g, "_");
  await scc.createFinding({
    parent: SOURCE_NAME,
    findingId,
    finding: {
      name: `${SOURCE_NAME}/findings/${findingId}`,
      resourceName: evidence.agentId,
      state: "ACTIVE",
      severity: "HIGH",
      findingClass: "THREAT",
      description: evidence.denialReason ?? "capability enforcement denial",
      eventTime: {
        seconds: Math.floor(new Date(evidence.ts).getTime() / 1000),
      },
      sourceProperties: {
        toolName: { stringValue: evidence.toolName ?? "" },
        tenantId: { stringValue: evidence.tenantId ?? "" },
        capabilityId: { stringValue: evidence.capabilityId ?? "" },
      },
    },
  });

  res.sendStatus(200);
}
```

### 7.3 Log-based metrics for denial histograms in Cloud Logging

Use Cloud Logging log-based metrics and Cloud Monitoring alerting to track
denial-reason histograms.

#### Create a log-based metric for denied tool calls

```bash
gcloud logging metrics create eunox_tool_calls_denied \
  --project "${PROJECT_ID}" \
  --description "eunox tool call denials by denial reason" \
  --log-filter 'resource.type="k8s_container" jsonPayload.evidence.outcome="deny"' \
  --value-extractor 'EXTRACT(jsonPayload.evidence.denialReason)' \
  --label-extractor 'denial_reason=EXTRACT(jsonPayload.evidence.denialReason)' \
  --label-extractor 'agent_id=EXTRACT(jsonPayload.evidence.agentId)'
```

#### Cloud Logging query templates (Cloud Logging query language)

**Denial-reason histogram (last 24 h):**

```
resource.type="k8s_container"
resource.labels.namespace_name="eunox"
jsonPayload.evidence.outcome="deny"
timestamp >= "2024-01-01T00:00:00Z"
```

Use the **Log Analytics** view with aggregation:

```sql
SELECT
  JSON_VALUE(json_payload.evidence.denialReason) AS denial_reason,
  COUNT(*) AS denials
FROM `my-gcp-project.global._Default._AllLogs`
WHERE
  resource.type = 'k8s_container'
  AND JSON_VALUE(json_payload.evidence.outcome) = 'deny'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY denial_reason
ORDER BY denials DESC
LIMIT 20
```

**Top denied agents:**

```sql
SELECT
  JSON_VALUE(json_payload.evidence.agentId) AS agent_id,
  COUNT(*) AS denials
FROM `my-gcp-project.global._Default._AllLogs`
WHERE
  resource.type = 'k8s_container'
  AND JSON_VALUE(json_payload.evidence.outcome) = 'deny'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY agent_id
ORDER BY denials DESC
LIMIT 10
```

**Audit lag monitoring (cross-chain anchor):**

```sql
SELECT
  timestamp,
  JSON_VALUE(json_payload.eunox_cross_chain_anchor_lag_seconds) AS lag_seconds
FROM `my-gcp-project.global._Default._AllLogs`
WHERE
  resource.type = 'k8s_container'
  AND JSON_VALUE(json_payload.eunox_cross_chain_anchor_lag_seconds) IS NOT NULL
ORDER BY timestamp DESC
LIMIT 100
```

---

## 8. Upgrade and rollback

```bash
# Upgrade
helm upgrade eunox ./k8s/helm/eunox \
  --namespace eunox \
  -f k8s/helm/eunox/values-gcp.yaml \
  --set gateway.image.tag=1.1.0 \
  --set issuer.image.tag=1.1.0

# Rollback
helm rollback eunox --namespace eunox
```

---

## 9. Security checklist for GKE

- [ ] Workload Identity Federation is enabled on the cluster and all service
      accounts use it — no JSON service account key files in pod environment
      variables or mounted secrets.
- [ ] Node service accounts have the minimal GKE node permissions only
      (`roles/container.nodeServiceAccount`); no broad `roles/editor` or
      `roles/owner`.
- [ ] Artifact Registry repositories are private with vulnerability scanning
      enabled (`gcloud artifacts repositories update --enable-vulnerability-scanning`).
- [ ] Google-managed SSL certificate is active for the correct domains;
      HTTP traffic is rejected via `kubernetes.io/ingress.allow-http: "false"`.
- [ ] Gateway admin port (`3003`) is not reachable from the public GKE Ingress —
      use an internal load balancer or `kubectl port-forward` for admin access.
- [ ] GKE Binary Authorization is enabled to enforce image provenance.
- [ ] Kubernetes Network Policies restrict pod-to-pod traffic to the minimum
      required (gateway ↔ Redis, gateway ↔ Postgres, issuer ↔ Postgres).
- [ ] Pod Security Admission is set to `restricted` for the `eunox` namespace.
- [ ] `AUDIT_LEDGER_HMAC_SECRET` and `ADMIN_API_KEY` are sourced from GCP
      Secret Manager — never stored in plaintext in Helm values or ConfigMaps.
      See [`docs/secrets-gcp.md`](./secrets-gcp.md).
- [ ] Cloud Logging log retention is set to at least 90 days for the `eunox`
      log bucket (SOC 2 CC7 requirement).
- [ ] Security Command Center findings are reviewed weekly; high-severity
      denials trigger automated alerts via Cloud Monitoring alerting policies.

# Sprint 5 — Production Pilot Launch on Azure

> **Milestone 3, Sprint 5** of [`execution-plan.md`](./execution-plan.md):
> *"Deploy the system in a controlled production pilot with real (or
> realistic) data … emphasis on end-to-end security verification, performance,
> and preparation for scaling."*
>
> Sprint 5 is **operational** — the code is the same code that passed Sprint 4
> exit criteria; this sprint is about packaging it for reproducible
> provisioning, lighting up Azure-native observability, executing a
> structured Go/No-Go, and running hypercare for the pilot users.

---

## 1. What ships in Sprint 5

| Capability                                          | Artifact                                                                    |
|-----------------------------------------------------|-----------------------------------------------------------------------------|
| Reproducible provisioning of every Azure resource   | [`infra/bicep/main.bicep`](../infra/bicep/main.bicep)                       |
| Example deployment parameters                       | [`infra/bicep/main.parameters.example.json`](../infra/bicep/main.parameters.example.json) |
| Sentinel scheduled analytic rules                   | [`infra/sentinel/analytic-rules.json`](../infra/sentinel/analytic-rules.json) |
| HA hardening for control plane + data plane         | [`k8s/ha-policies.yaml`](../k8s/ha-policies.yaml) (HPA + PDB)               |
| Cloud-portability matrix                            | [§ 6 below](#6-cloud-portability-matrix)                                    |
| Pilot Go/No-Go checklist                            | [§ 3 below](#3-gono-go-checklist)                                           |
| Hypercare runbook                                   | [§ 5 below](#5-hypercare)                                                   |
| Pilot metrics & feedback collection                 | [§ 4 below](#4-metrics--feedback-collection)                                |
| Sentinel & Application Insights tuning workflow     | [§ 7 below](#7-monitoring-fine-tuning)                                      |
| Microsoft Purview integration notes                 | [§ 8 below](#8-microsoft-purview-integration)                               |

The **production deployment** itself reuses the existing Kubernetes manifests
under `k8s/`:

- `capability-issuer-deployment.yaml` — already runs **2 replicas** with
  pod-level + container-level security context, AppArmor, SELinux, read-only
  root filesystem, and Kubernetes Secrets for credentials.
- `tool-gateway-deployment.yaml` — already runs **3 replicas**, same security
  posture, mounted on the agent egress path.
- `agent-runtime.yaml` — sidecar example for low-latency tool-call paths.
- `network-policies.yaml` — default-deny + allowlist egress (gateway only).
- `pod-security-standards.yaml` — `restricted` PSS enforced on the namespace.

Sprint 5 layers on **`ha-policies.yaml`** (PDB + HPA) so that:

- **Capability Issuer** scales 2 → 8 pods on CPU > 65% / memory > 75%, with
  `minAvailable: 1` during voluntary disruptions.
- **Tool Gateway** scales 3 → 20 pods on CPU > 60% / memory > 70%, with
  `minAvailable: 2` (hot-path service).

---

## 2. Pre-deployment provisioning (one command, two outputs)

```bash
# Create the resource group then run the Bicep
az group create --name euno-pilot-rg --location eastus
az deployment group create \
  --resource-group euno-pilot-rg \
  --template-file infra/bicep/main.bicep \
  --parameters @infra/bicep/main.parameters.example.json
```

The deployment outputs the values you'll need for the rest of the rollout:

| Output                      | Used in                                                                  |
|-----------------------------|--------------------------------------------------------------------------|
| `keyVaultUri`               | `AZURE_KEYVAULT_URL` env var on the Capability Issuer.                   |
| `signingKeyVersionUrl`      | Audit + JWKS publication.                                                |
| `acrLoginServer`            | `docker push` target for issuer/gateway/agent images.                    |
| `appInsightsConnectionString` | Optional `APPLICATIONINSIGHTS_CONNECTION_STRING` env var (auto-instrumentation). |
| `aksOidcIssuerUrl`          | Federated identity credential on the issuer's user-assigned identity.    |
| `issuerIdentityClientId`    | `azure.workload.identity/client-id` annotation on the issuer ServiceAccount. |

After the Bicep completes, deploy the workloads:

```bash
az aks get-credentials --resource-group euno-pilot-rg --name <aksName>

# Apply manifests in order
kubectl apply -f k8s/namespace-and-config.yaml
kubectl apply -f k8s/network-policies.yaml
kubectl apply -f k8s/pod-security-standards.yaml
kubectl apply -f k8s/security-policies/   # AppArmor + SELinux profiles (DaemonSet/MachineConfig)
kubectl apply -f k8s/capability-issuer-deployment.yaml
kubectl apply -f k8s/tool-gateway-deployment.yaml
kubectl apply -f k8s/agent-runtime.yaml
kubectl apply -f k8s/ha-policies.yaml     # NEW in Sprint 5: HPA + PDB
```

Finally onboard the workspace to Sentinel (Azure portal: *Sentinel → Add
workspace*) and deploy the analytic rules:

```bash
az deployment group create \
  --resource-group euno-pilot-rg \
  --template-file infra/sentinel/analytic-rules.json \
  --parameters workspaceName=<lawName>
```

---

## 3. Go/No-Go checklist

Hold this meeting at the **end of the Sprint 5 deployment, before** real
users are routed to the pilot.  All items must be **GO** for unanimous
approval.

| #   | Owner    | Item                                                                 | GO criterion                                                                                          |
|-----|----------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| G1  | CP       | Issuer signing key lives in Key Vault, never on disk.                | `az keyvault key show` returns the key; no `PRIVATE_KEY_PEM` env var anywhere.                         |
| G2  | CP       | `/.well-known/did.json` resolves over HTTPS at the issuer's domain.  | `curl -sf https://<domain>/.well-known/did.json \| jq .id` matches `ISSUER_DID`.                       |
| G3  | CP       | Token TTL is 15 minutes; renewal endpoint works end-to-end.          | Manual: `POST /api/v1/issue` then `POST /api/v1/renew` using returned token.                           |
| G4  | DP       | Gateway rejects forged / expired / unsigned tokens.                  | Run the security suite in `packages/tool-gateway/tests` against the deployed gateway.                  |
| G5  | DP       | Network policies block all egress from the agent runtime except gateway. | `kubectl exec` into an agent pod and `curl https://example.com` → blocked; `curl tool-gateway:3002/health` → 200. |
| G6  | DP       | Kill switch verified for `global`, `session`, and `agent` scopes.    | Live drill: see [INCIDENT_RESPONSE_RUNBOOK.md](./INCIDENT_RESPONSE_RUNBOOK.md) §3.                     |
| G7  | DP       | Token revocation propagates ≤ 5 s across all gateway replicas.       | Required when running > 1 gateway replica → Redis distributed revocation must be enabled.              |
| G8  | OBS      | All Sentinel analytic rules deployed, none in `Disabled` state.      | `az sentinel alert-rule list -w <law>` shows 5 enabled scheduled rules.                                |
| G9  | OBS      | Application Insights receiving traces from issuer + gateway.         | "Live Metrics" view in Application Insights shows traffic from both deployments.                       |
| G10 | OBS      | Audit log evidence chain verifiable with the public DID key.         | Run `node scripts/verify-evidence.js <evidence.json>` against a sample emitted by the gateway.         |
| G11 | DX       | Pilot users have signed off on UAT cases (allow + deny).             | Signed UAT report attached to release ticket.                                                          |
| G12 | DX       | Rollback plan tested in staging within the last 7 days.              | Staging change-record reference + measured RTO ≤ 10 minutes.                                           |
| G13 | All      | On-call rotation published in the incident channel.                  | Calendar invite with primary + secondary for the next 14 days.                                         |

If any item is **NO-GO**, document the gap, set an owner and ETA, and reschedule.

---

## 4. Metrics & feedback collection

During the pilot, capture the following daily.  The CLI in
`packages/cli` and the Sentinel workspace produce all of these.

### Operational metrics (per gateway replica)

| Metric                          | Source                                           | Healthy range (per replica) |
|---------------------------------|--------------------------------------------------|-----------------------------|
| Tool calls / minute             | `ContainerLogV2` `LogMessage has 'Proxying request'` | Workload-dependent          |
| Allow rate                      | `LogMessage has 'Capability check passed'`       | > 95 %                      |
| Deny rate                       | `LogMessage has 'Capability check failed'`       | < 5 % (steady-state)        |
| p50 / p95 / p99 gateway latency | App Insights `requests.duration`                 | p50 < 2 ms, p95 < 5 ms, p99 < 25 ms |
| Token issuance latency          | App Insights `requests.duration` on `/issue`     | p95 < 1 s                   |
| Active sessions                 | Distinct `sessionId` from logs                   | Workload-dependent          |
| Gateway → backend errors        | `LogMessage has 'Proxy error'`                   | ~ 0                         |

Collect into App Insights via diagnostic settings (already wired by Bicep) and
plot in the **Workbook** under *Application Insights → Workbooks*.  Suggested
KQL is included as comments in `infra/sentinel/analytic-rules.json`.

### Security metrics

- **False-positive denials** vs **true-positive denials** — review the
  Sentinel incidents queue daily; tag with `FalsePositive` / `TruePositive`
  custom property.
- **Token renewal frequency** — App Insights `customEvents` named
  `token.renewed` (already emitted by the issuer logger as `info` records).
- **Sentinel alerts triggered** — track count by rule name to drive tuning
  (see [§ 7](#7-monitoring-fine-tuning)).

### User feedback

Run a 15-minute weekly check-in with each pilot user and capture:

1. Did the agent complete the intended task?
2. Were there any "unexpected" denials?  (Should match Sentinel false-positive count.)
3. Time-to-first-action after agent launch (target: < 2 s including issuance).
4. Any UI / CLI friction points.

Track in a single shared issue tracker board with `pilot/feedback` label.

---

## 5. Hypercare

Hypercare = the first **2 calendar weeks** after the pilot is live.  During
hypercare:

- **On-call:** primary + secondary engineer per team (CP, DP, OBS, DX).
  Rotation calendar pinned in the incident channel.
- **War-room sync:** 15 minutes daily at 09:30 local time, covering:
  - New Sentinel incidents in the last 24 h.
  - Latency / error trend vs. baseline.
  - User-reported issues.
  - Any open action items from the previous day.
- **Response targets** (see also [INCIDENT_RESPONSE_RUNBOOK.md](./INCIDENT_RESPONSE_RUNBOOK.md)):

  | Severity                                     | Acknowledge | Mitigate |
  |----------------------------------------------|-------------|----------|
  | SEV-1 — kill-switch fired or write attempted from read-only session | 5 min       | 30 min   |
  | SEV-2 — denial spike from a single agent      | 15 min      | 2 h      |
  | SEV-3 — latency above p95 budget              | 1 h         | 24 h     |
  | SEV-4 — false-positive deny reported by user  | 4 h         | next sprint |

- **Change-freeze:** no production changes outside of incident remediation
  during hypercare without sign-off from the Sprint 5 lead.

---

## 6. Cloud portability matrix

The system relies entirely on standard protocols (OIDC, OAuth, JWT, W3C VC,
W3C DID, JOSE, SHA-256 + RSA / ECDSA), so every Azure component has a direct
substitute on AWS and GCP.  In the pilot we run on Azure; this matrix is the
contract for Sprint 6's optional cross-cloud demo and for any future
multi-cloud deployment.

| Concern                       | Azure (pilot)                       | AWS                                          | GCP                                       | Implementation status in this repo                       |
|-------------------------------|-------------------------------------|----------------------------------------------|-------------------------------------------|-----------------------------------------------------------|
| Identity provider             | Microsoft Entra ID (OIDC + Graph)   | AWS Cognito + IAM Identity Center            | Cloud Identity / Workforce Identity Fed.  | Pluggable `IdentityAdapter` — `azure-ad` shipped today, `did` shipped, others can extend `IdentityAdapter`. |
| Capability signing key        | Azure Key Vault (RSA / EC, HSM)     | AWS KMS                                      | GCP Cloud KMS                             | All three signers shipped: `AzureSigner`, `AWSKMSSigner`, `GCPCloudKMSSigner`. |
| Tool gateway / API gateway    | Azure API Management (`validate-jwt`) + this gateway | API Gateway + Lambda Authorizer + this gateway | Apigee or Cloud Run + this gateway        | The gateway in `packages/tool-gateway` is cloud-agnostic; APIM/AWS/GCP fronts only add edge concerns (TLS, WAF). |
| Container orchestration       | AKS                                 | EKS                                          | GKE                                       | Manifests in `k8s/` are vanilla Kubernetes (no AKS-only resources). |
| Logs & traces store           | Log Analytics + Application Insights | CloudWatch Logs + X-Ray                      | Cloud Logging + Cloud Trace               | All packages emit structured JSON via Winston; ingest via the platform's stdout collector. |
| SIEM / detections             | Microsoft Sentinel (KQL)            | Amazon GuardDuty + Security Lake             | Chronicle / SecOps                        | Detection logic lives in `infra/sentinel/analytic-rules.json` as KQL; the queries port to OpenSearch/Chronicle queries. |
| Sensitivity labels for retrieval | Microsoft Purview               | AWS Macie + custom labels                    | DLP API + custom labels                   | Documented integration in [§ 8](#8-microsoft-purview-integration). |
| Distributed revocation store  | Azure Cache for Redis (Sentinel)    | ElastiCache for Redis                        | Memorystore for Redis                     | The gateway uses any RFC-compliant Redis (`REDIS_URL`); no provider-specific code. |
| Workload identity             | Azure AD Workload Identity          | IRSA (IAM Roles for Service Accounts)        | Workload Identity Federation              | Bicep wires up Azure Workload Identity; for AWS/GCP, swap the ServiceAccount annotations. |

The single line every engineer should remember:

> **The capability tokens, evidence signatures, and DID Documents are all
> standards-based.  Anything that can run a Node 18 container, present an
> OIDC token, and call a KMS sign API can host the pilot.**

---

## 7. Monitoring fine-tuning

Sentinel ships with conservative thresholds.  After the first 7 days of real
traffic, tune them with this loop:

1. Pull baseline counts from each rule for the last 7 days:

   ```kusto
   SecurityIncident
   | where TimeGenerated > ago(7d)
   | where Title startswith "Euno -"
   | summarize Incidents = count(), FalsePositives = countif(Status == "Closed" and Classification == "FalsePositive")
       by Title
   | extend FpRate = todouble(FalsePositives) / Incidents
   ```

2. Adjust:
   - If `FpRate > 0.4` → increase the rule's threshold or shorten the
     suppression window.
   - If a rule fires < once per week → consider widening the query.
   - If `Incidents == 0` over 7 days for a rule that *should* fire (e.g.
     denial spike) → check whether the underlying log shape changed.

3. Update `infra/sentinel/analytic-rules.json` and re-deploy the Sentinel
   ARM template.  All adjustments are version-controlled.

For Application Insights:

- Sample at **100 %** during hypercare; drop to 10–20 % once the baseline is
  stable.
- Add a Live Metrics workbook for the on-call dashboard.
- Configure **Smart Detection** for `requests.failed` and
  `requests.performance` on both deployments.

---

## 8. Microsoft Purview integration

Recommended **only when** the pilot agents touch labeled documents (e.g.
SharePoint Online, OneDrive, Fabric).  When enabled:

1. Ensure the corpus is labeled in Purview (Confidential, Highly
   Confidential, Public, …).
2. In your retrieval layer (RAG / search) **filter by label and identity
   policy** before returning chunks to the agent.  Never let the model decide
   which labels it can see.
3. Emit the label distribution per completion as a custom event:

   ```text
   completion.label.distribution = { "Confidential": 4, "Public": 12 }
   ```

4. Add a Sentinel analytic rule that fires when a low-privilege identity
   retrieves a Highly Confidential document (template included in
   `infra/sentinel/analytic-rules.json` as a commented-out 6th rule the
   tenant can enable once labels exist).

This satisfies the Sprint 5 plan's call-out:
> *"Label the corpus. Filter retrieval by label and identity policy. Log
> label distribution per completion. Alert when a low-privilege identity
> retrieves high-sensitivity labels."*

---

## 9. Sprint 5 exit criteria (recap from the execution plan)

- [x] Pilot deployable to production with a single Bicep run.
- [x] Issuer + Gateway each running ≥ 2 replicas with HPA + PDB.
- [x] Application Insights and Log Analytics receiving telemetry.
- [x] Sentinel scheduled rules deployed and enabled.
- [x] Documentation, runbooks, and FAQs finalized.
- [x] Cloud-portability matrix published.
- [x] Go/No-Go checklist runnable by an operator who didn't build the system.

The remaining "Sprint 5 exit criteria" from the execution plan
(p95 latency, p99 latency, no security incidents) are **measured during the
pilot itself** — see [§ 4](#4-metrics--feedback-collection).

# API-Key Minter Threat Model

> **Status:** Pending sign-off (requires ≥ 2 engineers + 1 security reviewer outside the
> implementer before minter code merges to `main` — see [stage3executionplan.md §Task 1](../stage3executionplan.md#task-1--api-key-minter-threat-model-blocking-per-mvp-lines-660691)).
>
> **Last updated:** 2026-05-10
>
> **Authors:** _(add names at review)_
>
> **Reviewers:** _(add names + dates at sign-off)_

---

## Background

The API-key minter is a thin façade in front of `euno-platform/packages/tool-gateway`.
Its sole job is to translate a long-lived API key into a short-lived signed JWT capability
token, so that developers can upgrade from local enforcement to the hosted gateway with a
single config change:

```jsonc
// Stage 1–2: local enforcement
{ "enforcer": "local" }

// Stage 3: hosted gateway
{ "enforcer": "https://gateway.euno.example", "apiKey": "sk-..." }
```

The minter holds the platform's managed signing key. That key has authority to mint a
valid `AgentCapabilityManifest` JWT for **any tenant, any policy, any agent** on the
platform. It is the highest-value target in the entire system — equivalent in sensitivity
to a managed certificate authority or an OAuth authorization server whose tokens directly
authorize real-world actions.

This document answers the seven questions required by [mvp.md §"Minter threat model"
(lines 660–691)](../mvp.md) before the minter may ship to a paying customer.

---

## 1. Key Storage

### Requirement

Managed HSM — key material is never software-resident. Non-exportability must be enforced
**at the HSM level**, not merely by access-policy configuration.

### Design

The minter uses one of the three KMS drivers already implemented in
`euno-platform/packages/capability-issuer/src/{azure-signer,aws-kms-signer,gcp-cloudkms-signer}.ts`.
All three implement the `SigningAdapter` / `TokenSigner` interface from `@euno/common`.
The **chosen driver for the hosted offering is Azure Managed HSM** (not Standard Key
Vault). Self-hosters may use AWS CloudHSM or GCP Cloud HSM (HSM protection level). The
reasoning:

| Dimension | Azure Managed HSM | AWS CloudHSM | GCP Cloud HSM |
|---|---|---|---|
| FIPS 140-2 Level 3 | ✓ (dedicated HSM cluster) | ✓ (dedicated cluster) | ✓ (HSM protection level on Cloud KMS) |
| Key non-exportability enforced at HSM | ✓ — `keyOps` excludes `export`; HSM firmware refuses export regardless of IAM | ✓ — CMK with `Origin=AWS_CLOUDHSM` cannot be exported by any IAM action | ✓ — `protectionLevel=HSM` keys have no `ExportCryptoKey` permission at all |
| Per-tenant key isolation | ✓ — one Key Vault per tenant (or per-tenant key version with separate access policy) | ✓ — one CMK ARN per tenant | ✓ — one CryptoKey per tenant key ring |
| Managed multi-region HA | ✓ — Managed HSM is geo-replicated | ✗ — single AZ (CloudHSM cluster spans AZs manually) | ✓ — global key rings with regional key versions |

#### Non-exportability — exact API assertions

**Azure Managed HSM:**
Keys are created with `keyOps` that **omit** `export`. Because Managed HSM is a FIPS 140-2
Level 3 HSM, the firmware enforces this at the hardware level: no IAM override can extract
raw key material. Verify at key creation time:

```bash
az keyvault key create \
  --hsm-name $MINTER_HSM \
  --name minter-signing-key \
  --kty EC-HSM \
  --curve P-256 \
  --ops sign verify \
  --protection hsm

# Assert non-exportability — the key MUST NOT include 'export' in key_ops:
az keyvault key show --hsm-name $MINTER_HSM --name minter-signing-key \
  --query "key.keyOps" --output tsv
# Expected output: sign verify   (no 'export')
```

The `az keyvault key download` command will fail with `(KeyNotExportable)` regardless of
caller permissions.

**AWS KMS (CloudHSM-backed CMK):**
Create with `Origin=AWS_CLOUDHSM`. The API enforces non-exportability:

```bash
aws kms create-key \
  --origin AWS_CLOUDHSM \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "euno-minter-signing-key"

# Assert non-exportability — GetKeyPolicy must show no ExportKey action is allowed;
# additionally, aws kms get-key-metadata --key-id $KEY_ID should show Origin=AWS_CLOUDHSM.
# Attempting export via aws kms export-key-material returns AccessDeniedException for CloudHSM keys.
```

**GCP Cloud KMS (HSM protection level):**

```bash
gcloud kms keys create minter-signing-key \
  --keyring $MINTER_KEYRING \
  --location global \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256 \
  --protection-level hsm

# Assert non-exportability — HSM-protected keys have no ExportCryptoKey permission
# at all: the permission does not exist on the IAM policy surface for HSM keys.
# Attempting gcloud kms keys versions export ... returns PERMISSION_DENIED.
```

### Operational controls

- Key creation is performed by a designated **HSM admin identity** (separate from the
  minter service identity). The minter service principal holds only the `sign` and
  `verify` permissions — it cannot create, delete, or update keys.
- All HSM admin operations (key create, key rotate, access-policy changes) are logged to
  the cloud provider's audit trail (Azure Monitor Activity Log / AWS CloudTrail / GCP
  Cloud Audit Logs) and to the separate minter audit store described in §6.
- Key material is stored exclusively in the HSM. No key material is ever logged,
  transmitted, or persisted to any other store.

---

## 2. Blast Radius per Key Compromise

### Threat

Compromise of the minter signing key allows an attacker to:
1. Mint valid JWTs for any tenant and policy on demand.
2. Assign arbitrary capabilities to agents — bypassing all enforcement guarantees.
3. Forge audit records that appear legitimate (the records carry the minter's `kid`).

### Blast-radius containment design

| Layer | Mechanism |
|---|---|
| **Short TTL** | Minted tokens expire in ≤ 5 minutes (configurable per tenant down to 1 minute). An attacker with a compromised key can only mint tokens during the window between key compromise and key rotation. The `@euno/mcp` remote-enforcer client refreshes transparently before expiry. |
| **Per-issuance audit trail** | Every mint call writes an immutable row to the mint-audit store (see §6). On key compromise, the audit trail provides a complete enumeration of every token ever minted with the compromised key: tenant, agent, jti, policy fingerprint, `iat`, and `exp`. This is the blast-radius surface — no rows in the audit log = no exposure. |
| **Revocation list** | The gateway's existing `RevocationStore` (Redis-backed with Redis-circuit-breaker fail-closed, plus Postgres dual-write via the `LedgerAuditEvidenceSigner` ledger backend) covers the unexpired window. On key compromise, the rotation procedure (§3) bulk-revokes all JTIs issued after the estimated compromise time and before the new key becomes active. |
| **Per-tenant key isolation** | Per-tenant signing keys (§4) bound the blast radius to a single tenant's token population if a tenant-scoped key is compromised, not the entire platform. A compromise of the platform root (used for bootstrapping only) is the worst case — mitigated by the audit trail and short TTL. |
| **JWKS rotation window** | The gateway verifier respects `kid`. The compromised key's `kid` is removed from the JWKS endpoint immediately on rotation (§3), causing all in-flight tokens signed by the old key to fail verification within their remaining TTL (≤ 5 minutes). |

### Enumeration procedure on compromise

1. Query the mint-audit store: `SELECT * FROM mint_audit WHERE kid = $compromised_kid ORDER BY minted_at`.
2. For each row, post the `jti` to the revocation store (the gateway's revocation API accepts bulk JTI lists).
3. Issue a platform-wide kill-switch if the compromise window is unclear (§3, step 5).

---

## 3. Key Rotation Procedure

### Pre-conditions

- The new signing key has been created in the HSM (§1 controls apply to new key creation).
- The new key's `kid` has been published to the JWKS endpoint (`/.well-known/jwks.json`).
- The rotation is logged to the minter audit store before any step below is taken.

### Rotation procedure

1. **Create new key in HSM** — follow §1 creation steps for the provider. Record the new
   `kid` in the minter config database.

2. **Dual-publish JWKS** — add the new `kid` to the JWKS endpoint while keeping the old
   `kid` present. The gateway verifier already supports multiple keys via `kid` routing
   (`JWTTokenVerifier` checks `protectedHeader.kid` against all keys in the JWKS cache).
   **Do not remove the old key yet.**

3. **Switch minter to sign with new key** — deploy minter with `MINTER_ACTIVE_KID` set to
   the new `kid`. All new mint operations use the new key.

4. **Wait for old tokens to expire** — the maximum TTL is 5 minutes. After the TTL window,
   no valid in-flight token carries the old `kid`.

5. **If emergency rotation (key compromise suspected):**
   a. Invoke the platform-wide kill switch (`POST /admin/kill-switch/global`) immediately.
      This blocks all token validations system-wide within the kill-switch propagation
      window (pub/sub propagation: single-digit milliseconds intra-DC; worst case bounded
      by `refreshIntervalMs = 30 s`).
   b. Bulk-revoke all JTIs in the mint-audit store signed with the compromised `kid`
      (per §2 enumeration procedure).
   c. Notify affected tenants with the list of potentially-forged JTIs from the audit log.
   d. Lift the global kill switch after new key is active and old-key JTIs are revoked.

6. **Remove old key from JWKS** — once no valid token can carry the old `kid`, remove it
   from the JWKS endpoint. The gateway's `JwksTokenVerifier` will reject any future token
   claiming the old `kid` (key not in JWKS → verification failure → deny).

7. **Deactivate old key in HSM** — disable (not delete) the old key version in the HSM so
   it can be audited but cannot be used for signing.

8. **Record completion** — write a `KEY_ROTATION_COMPLETE` row to the minter audit store
   with: old `kid`, new `kid`, rotation timestamp, operator identity, reason code
   (SCHEDULED or EMERGENCY).

### Testing requirement

The rotation procedure is tested end-to-end in `euno-platform/packages/integration-tests/`
before Stage 3 ships. The test:
- Mints a token with the old key.
- Rotates to a new key.
- Asserts the old-key token is rejected by the verifier after TTL expiry.
- Asserts a new-key token is accepted.
- Asserts the audit store records both the rotation event and the token's jti.

---

## 4. Scope Isolation

### Threat

A platform-wide signing key means that a compromised minter can issue tokens for
**any tenant** at maximum privilege, not just the attacker's own tenant.

### Design — per-tenant signing keys behind a single root

**Recommendation: per-tenant keys, single HSM root.**

Each tenant is assigned a dedicated signing key in the HSM. The tenant's tokens carry a
`kid` that maps to their key, and the JWKS endpoint returns only that tenant's key for
that `kid`. The platform root key is used only to bootstrap new tenant key creation
(a brief admin operation) and is otherwise offline.

| Property | Per-tenant keys | Platform-wide key |
|---|---|---|
| Blast radius on key compromise | Single tenant | All tenants |
| JWKS complexity | O(tenants) public keys | 1 public key |
| HSM cost | O(tenants) key operations | 1 key |
| Audit trail granularity | Per-tenant, per-kid | All under one kid |

For the hosted offering the per-tenant cost is dominated by API latency (a single KMS
`sign` call), not by the number of keys. Azure Managed HSM, AWS KMS, and GCP Cloud KMS
all support thousands of keys without additional hardware.

### Capability scope constraint

The minter **cannot** issue tokens outside the tenant's registered capability set. On each
mint call:
1. The minter loads the tenant's `AgentCapabilityManifest` from the policy store (looked
   up by `apiKey` prefix → `policyId`).
2. It validates that the requested agent ID is in the tenant's allowed agent list.
3. It signs the manifest **as-stored** — it does not accept a caller-supplied manifest.
   The only caller input is `{ apiKey, agentId, sessionId }`. Capability content is
   determined entirely by the stored policy.

This means a compromised **API key** (not the HSM key) can only produce tokens within the
scope of that key's stored policy — it cannot escalate to other tenants or to capabilities
not in the policy.

A compromised **HSM key** is still bounded to the capability contents that the minter
would look up for a given `(apiKey, agentId)` pair — but because the attacker can supply
arbitrary `(apiKey, agentId)` pairs, the effective blast radius is all tenants with valid
API keys. This is why per-tenant key isolation matters.

---

## 5. Credential Access Path

### Threat

The minter's signing API is the most sensitive endpoint in the system. An attacker who can
call `POST /mint` with a valid API key can produce unlimited short-lived tokens within
that tenant's policy scope. An attacker who can call the minter's internal KMS sign path
directly bypasses even that constraint.

### Design

#### External access path (client → minter)

```
[Agent process]
    ↓  HTTPS (TLS 1.3, SNI verified)
[CDN / load balancer] — WAF rules: rate-limit per API-key prefix, block non-POST /mint
    ↓  Internal mTLS
[Minter service]
    ↓  SDK-authenticated KMS API call (IAM role, no long-lived credential)
[HSM]
```

- The minter service is not reachable from the public internet except through the CDN/LB.
  Internal traffic uses mTLS with a short-lived certificate rotated by the service mesh
  (e.g., Istio / AWS ACM / GCP Certificate Authority Service).
- The minter has **no inbound admin port**. Configuration changes (policy updates, key
  rotation triggers) arrive via a separate admin API that is network-isolated to the
  operator's management VLAN / VPN.
- API-key validation is rate-limited per `sk-` prefix at the CDN layer (N attempts/minute
  configurable per tenant) before the request reaches the minter process.

#### Minter → HSM access path

- The minter service authenticates to the HSM using its **workload identity** (Azure
  Managed Identity / AWS IAM role bound to pod SA / GCP Workload Identity). No static
  credentials are stored in the minter process or its container image.
- The IAM role is granted **only** the `sign` and `verify` permissions on the specific key
  version — not `create`, `delete`, `rotate`, or `get-key-material`.
- **Hardware attestation from caller (Kubernetes pod):** On Kubernetes, the service account
  token is bound to the pod's node and projected into the pod via
  `automountServiceAccountToken: true` with a short TTL (1 hour). For Azure: the Managed
  Identity federated credential verifies the pod's service-account OIDC token against the
  AKS OIDC issuer. For AWS: IAM Roles for Service Accounts (IRSA) binds the IAM role to
  the pod's OIDC-projected service account. For GCP: Workload Identity binds the GSA to
  the KSA. In all cases, the HSM's IAM plane verifies the pod's runtime identity before
  issuing a sign authorization — a stolen static credential is not sufficient.
- **Second factor for HSM admin operations:** Key creation, rotation, and access-policy
  changes require a second approver from the HSM admin group (enforced at the HSM access
  policy level for Azure Managed HSM; enforced via quorum-based IAM policies for AWS/GCP).
  This prevents a single compromised admin identity from silently rotating the minter key.

#### Network isolation

- Minter pods run in a dedicated Kubernetes namespace with a `NetworkPolicy` that allows:
  - **Ingress:** only from the load balancer pod selector.
  - **Egress:** only to the HSM endpoint (FQDN allowlist), the policy-store database, and
    the mint-audit store (separate Postgres credentials, separate schema).
  - All other egress is denied.
- The minter has no direct access to the gateway's enforcement Postgres schema, the
  revocation Redis instance, or any other service beyond what is listed above.

---

## 6. Audit Trail

### Requirement

Every mint call is logged with: caller identity, tenant, policy fingerprint, and resulting
JWT `jti`. The log must be **immutable** — append-only store with credentials separate
from the minter itself.

### Design

The minter writes to a dedicated `mint_audit` table in a Postgres instance whose
credentials **are not available to the minter process** at runtime. Writes are forwarded
through a lightweight append-only audit sidecar that holds the write credentials; the
minter communicates with the sidecar over a Unix socket (no network path to the Postgres
instance from the minter pod).

```
Minter pod:
  minter process  →  [Unix socket]  →  audit-sidecar process (separate UID, write-only credential)
                                              ↓
                                   [Postgres mint_audit table]
                                   (separate RDS instance / Postgres schema, separate IAM role)
```

The audit-sidecar accepts only append operations (no read, no update, no delete). Its
Postgres role is: `GRANT INSERT ON mint_audit TO audit_writer`. No `SELECT`, `UPDATE`, or
`DELETE` is granted to the sidecar. The DBA role (held by operators, not the minter) can
read and analyze the table.

#### Mint-audit row schema

```sql
CREATE TABLE mint_audit (
  id            BIGSERIAL PRIMARY KEY,
  minted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  caller_ip     INET NOT NULL,
  caller_ua     TEXT,
  api_key_prefix TEXT NOT NULL,          -- first 8 chars of sk-..., never the full key
  tenant_id     TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  session_id    TEXT NOT NULL,
  policy_id     TEXT NOT NULL,
  policy_fingerprint TEXT NOT NULL,      -- SHA-256 of canonical policy JSON
  jti           TEXT NOT NULL UNIQUE,    -- the JWT jti of the minted token
  kid           TEXT NOT NULL,           -- which signing key was used
  exp           BIGINT NOT NULL,         -- unix seconds: token expiry
  result        TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
  denial_reason TEXT                     -- populated when result != 'ok'
);

CREATE INDEX ON mint_audit (tenant_id, minted_at DESC);
CREATE INDEX ON mint_audit (kid, minted_at DESC);  -- for key-compromise blast-radius query
CREATE INDEX ON mint_audit (jti);                  -- for per-token lookup on revocation
```

#### Tamper evidence

Each row is protected by a per-row HMAC-SHA-256 over the canonical JSON of the row
fields, computed with a secret held only by the audit sidecar (not the minter process and
not the DBA). This is the same pattern used by `LedgerAuditEvidenceSigner` in
`euno-platform/packages/common-infra/src/ledger-signer.ts`. An attacker who compromises
the Postgres instance cannot forge valid HMAC values without also compromising the sidecar
process and its secret — two separate compromises required.

Optionally (configurable), every N rows the sidecar computes a Merkle root and writes it
to an S3 Object-Lock bucket. This provides an external witness: a DB-level compromise
that deletes rows creates a detectable gap in the Merkle chain.

#### What is NOT logged

- The full API key (only the prefix is stored — same principle as password hashing).
- The JWT payload beyond `jti`, `kid`, and `exp`.
- Personally identifiable information beyond tenant and agent IDs (which are stable
  opaque identifiers, not human names).

---

## 7. Monitoring and Alerting

### Metrics

The minter exposes the following Prometheus metrics (consistent with the naming convention
in `public/packages/common/src/metrics.ts`):

| Metric | Type | Labels | Description |
|---|---|---|---|
| `euno_minter_mint_total` | Counter | `tenant`, `result` (`ok`/`denied`/`error`) | Total mint calls |
| `euno_minter_mint_latency_seconds` | Histogram | `tenant` | End-to-end mint latency |
| `euno_minter_kms_sign_latency_seconds` | Histogram | `provider` | HSM sign latency |
| `euno_minter_kms_error_total` | Counter | `provider`, `error_class` | KMS errors |
| `euno_minter_anomaly_alerts_total` | Counter | `tenant`, `rule` | Times an anomaly rule fired |
| `euno_minter_key_rotation_total` | Counter | `kid`, `reason` | Key rotations (scheduled / emergency) |

### Alerting rules

The following rules are defined in the minter's alert configuration and are tested against
a synthetic test tenant before Stage 3 ships. "Low-activity tenant" is defined as fewer
than 10 successful mints in the previous 7 days.

#### Rule 1 — Mint-rate spike per tenant

```yaml
# Fires when a single tenant's mint rate exceeds 10× its 1-hour rolling average.
alert: MinterRateSpike
expr: |
  rate(euno_minter_mint_total{result="ok"}[5m]) by (tenant)
  > 10 * avg_over_time(rate(euno_minter_mint_total{result="ok"}[5m])[1h:5m]) by (tenant)
for: 2m
labels:
  severity: critical
annotations:
  summary: "Abnormal mint rate for tenant {{ $labels.tenant }}"
  runbook: "https://docs.euno.example/runbooks/minter-rate-spike"
```

#### Rule 2 — Off-hours minting for low-activity tenant

```yaml
# Fires when a tenant with < 10 mints/week mints during 22:00–06:00 UTC.
alert: MinterOffHoursMint
expr: |
  (
    increase(euno_minter_mint_total{result="ok"}[5m]) by (tenant) > 0
    and on(tenant) (
      increase(euno_minter_mint_total{result="ok"}[7d]) by (tenant) < 10
    )
  )
  and (hour() >= 22 or hour() < 6)
for: 0m
labels:
  severity: warning
annotations:
  summary: "Off-hours mint for low-activity tenant {{ $labels.tenant }}"
  runbook: "https://docs.euno.example/runbooks/minter-off-hours"
```

#### Rule 3 — KMS error clustering

```yaml
# Fires when more than 5 KMS errors occur in 1 minute across any provider.
alert: MinterKmsErrorCluster
expr: rate(euno_minter_kms_error_total[1m]) > 5
for: 1m
labels:
  severity: critical
annotations:
  summary: "KMS errors clustering on {{ $labels.provider }}"
  runbook: "https://docs.euno.example/runbooks/minter-kms-errors"
```

#### Rule 4 — Mint failure spike

```yaml
# Fires when the error/denied rate for any tenant exceeds 50% over 5 minutes,
# which may indicate a credential stuffing or API-key enumeration attack.
alert: MinterHighFailureRate
expr: |
  rate(euno_minter_mint_total{result=~"denied|error"}[5m]) by (tenant)
  /
  rate(euno_minter_mint_total[5m]) by (tenant)
  > 0.5
for: 2m
labels:
  severity: warning
annotations:
  summary: "High mint failure rate for tenant {{ $labels.tenant }}"
  runbook: "https://docs.euno.example/runbooks/minter-high-failure"
```

#### Rule 5 — Emergency key rotation

```yaml
# Fires immediately when an emergency key rotation is recorded.
alert: MinterEmergencyKeyRotation
expr: increase(euno_minter_key_rotation_total{reason="emergency"}[5m]) > 0
for: 0m
labels:
  severity: critical
annotations:
  summary: "Emergency minter key rotation for kid {{ $labels.kid }}"
  runbook: "https://docs.euno.example/runbooks/minter-key-rotation"
```

### Alert routing

All `critical` alerts page the on-call security engineer immediately (PagerDuty / OpsGenie
integration). `warning` alerts post to the `#security-alerts` Slack channel and are
reviewed at the next business-day stand-up. SRE runbooks for each alert are maintained at
`docs/runbooks/minter-*.md` (stub files created alongside this document; fully populated
before Stage 3 ships to the first paying customer).

---

## Sign-off

This document must be reviewed and signed by ≥ 2 engineers and ≥ 1 security reviewer who
did not author it before any minter code merges to `main`.

| Role | Name | Date | Notes |
|---|---|---|---|
| Author | _(name)_ | _(date)_ | |
| Engineer reviewer 1 | _(name)_ | _(date)_ | |
| Engineer reviewer 2 | _(name)_ | _(date)_ | |
| Security reviewer | _(name)_ | _(date)_ | |

Until all four rows are filled, the minter is **blocked from merging**. The CI gate
enforcing this is tracked in the Stage 3 task checklist in `docs/mvp.md`.

---

## Cross-references

| Document | Relevant section |
|---|---|
| [`docs/mvp.md`](../mvp.md) | §"Minter threat model" (lines 660–691), §"Critical Risks" (lines 877–885) |
| [`docs/stage3executionplan.md`](../stage3executionplan.md) | Task 1 (this document), Task 10–12 (minter implementation) |
| [`docs/enforcement.md`](../enforcement.md) | Cryptographic-token invariant |
| [`docs/capability-model.md`](../capability-model.md) | §6 — unknown types are denied by default |
| [`euno-platform/packages/common-infra/src/ledger-signer.ts`](../../euno-platform/packages/common-infra/src/ledger-signer.ts) | Per-row HMAC ledger pattern reused for mint-audit |
| [`euno-platform/packages/tool-gateway/src/revocation-store.ts`](../../euno-platform/packages/tool-gateway/src/revocation-store.ts) | Token revocation used in key rotation (§3) |
| [`euno-platform/packages/capability-issuer/src/azure-signer.ts`](../../euno-platform/packages/capability-issuer/src/azure-signer.ts) | Azure Key Vault signing driver |
| [`euno-platform/packages/capability-issuer/src/aws-kms-signer.ts`](../../euno-platform/packages/capability-issuer/src/aws-kms-signer.ts) | AWS KMS signing driver |
| [`euno-platform/packages/capability-issuer/src/gcp-cloudkms-signer.ts`](../../euno-platform/packages/capability-issuer/src/gcp-cloudkms-signer.ts) | GCP Cloud KMS signing driver |

# API-Key Minter Threat Model

> **Status:** Pending sign-off (requires ≥ 2 engineers + 1 security reviewer outside the
> implementer before minter code merges to `main` — see [stage3executionplan.md §Task 1](../stage3executionplan.md).
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

The minter holds the platform's managed signing authority. In the hosted design that
authority is implemented as per-tenant non-exportable HSM keys, not as one online
platform-wide private key. A compromise of the minter service could still request HSM
signatures for many tenants, so it remains the highest-value service in the system —
equivalent in sensitivity to a managed certificate authority or an OAuth authorization
server whose tokens directly authorize real-world actions.

This document answers the seven questions required by
[mvp.md §"Minter threat model"](../mvp.md#minter-threat-model-required-before-stage-3-ships)
(required before Stage 3 ships) before the minter may ship to a paying customer.

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
Vault), with per-tenant EC P-256 (`EC-HSM`, `ES256`) signing keys. Self-hosters may
use AWS CloudHSM or GCP Cloud HSM (HSM protection level). The reasoning:

| Dimension | Azure Managed HSM | AWS CloudHSM | GCP Cloud HSM |
|---|---|---|---|
| FIPS 140-2 Level 3 | ✓ (dedicated HSM cluster) | ✓ (dedicated cluster) | ✓ (HSM protection level on Cloud KMS) |
| Key non-exportability enforced at HSM | ✓ — `keyOps` excludes `export`; HSM firmware refuses export regardless of IAM | ✓ — CMK with `Origin=AWS_CLOUDHSM` cannot be exported by any IAM action | ✓ — `protectionLevel=HSM` keys have no `ExportCryptoKey` permission at all |
| Per-tenant key isolation | ✓ — one Managed HSM key per tenant selected by `policyHash:audience` | ✓ — one CMK ARN per tenant | ✓ — one CryptoKey per tenant key ring |
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
  `verify` permissions on tenant keys — it cannot create, delete, update, export, or
  change access policy on keys.
- All HSM admin operations (key create, key rotate, access-policy changes) are logged to
  the cloud provider's audit trail (Azure Monitor Activity Log / AWS CloudTrail / GCP
  Cloud Audit Logs) and to the separate minter audit store described in §6.
- Key material is stored exclusively in the HSM. No key material is ever logged,
  transmitted, or persisted to any other store. The platform bootstrap/admin identity
  may create or disable tenant keys, but it does not expose an online key that signs
  tenant capability tokens.

---

## 2. Blast Radius per Key Compromise

### Threat

The damage depends on which credential is compromised:

1. **API key compromise:** attacker can mint short-lived tokens only for the tenant,
   policy, scopes, and agent IDs bound to that API key.
2. **Tenant HSM key/sign-oracle compromise:** attacker can forge valid JWTs for that
   tenant's `aud`/`kid` until rotation removes the key from JWKS and revokes observed
   JTIs.
3. **Minter service compromise:** attacker may request HSM signatures across tenants
   that the service identity can reach and can attempt to bypass API-key policy lookup.
   This is the worst realistic online compromise and drives the controls below.
4. **HSM admin/root compromise:** attacker may provision or re-permission keys. This is
   mitigated by split admin identity, two-person approval, provider audit logs, and
   tenant-key rotation.

### Blast-radius containment design

| Layer | Mechanism |
|---|---|
| **Short TTL** | Minted tokens expire in ≤ 5 minutes (configurable per tenant down to 1 minute). An attacker with a compromised key can only mint tokens during the window between key compromise and key rotation. The `@euno/mcp` remote-enforcer client refreshes transparently before expiry. |
| **Per-issuance audit trail** | Every mint call writes an immutable row to the mint-audit store (see §6). On key or service compromise, the audit trail provides a complete enumeration of every token minted through the legitimate minter path: tenant, agent, jti, policy fingerprint, `iat`, and `exp`. Missing audit rows are treated as evidence of direct HSM-sign-oracle abuse and trigger emergency tenant-key rotation plus kill switch. |
| **Revocation list** | The gateway's existing `RevocationStore` (Redis-backed with Redis-circuit-breaker fail-closed) covers the unexpired window. On key compromise, the rotation procedure (§3) bulk-revokes all JTIs issued after the estimated compromise time and before the new key becomes active. The kill-switch manager (Redis + Postgres dual-write, §3 step 5a) provides a broader emergency stop if the compromise window is unclear. |
| **Per-tenant key isolation** | Per-tenant signing keys (§4) bound the blast radius to a single tenant's token population if a tenant-scoped key is compromised, not the entire platform. A compromise of the minter service identity is broader, so the service identity is segmented by tenant shard where operationally possible and all tenant key use is audited by the HSM provider. |
| **JWKS rotation window** | The gateway verifier respects `kid`. The compromised key's `kid` is removed from the JWKS endpoint immediately on rotation (§3), causing all in-flight tokens signed by the old key to fail verification within their remaining TTL (≤ 5 minutes). |

### Enumeration procedure on compromise

1. Query the mint-audit store: `SELECT * FROM mint_audit WHERE kid = $compromised_kid ORDER BY minted_at`.
2. Cross-check HSM provider sign-operation logs for the same `kid`; any HSM sign event
   without a matching mint-audit row is treated as direct sign-oracle abuse.
3. For each audited row, post the `jti` to the revocation store (the gateway's
   revocation API accepts bulk JTI lists).
4. Issue a tenant-scoped kill switch for known tenant-key compromise, or a platform-wide
   kill switch if the compromise window or tenant set is unclear (§3, step 5).

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
   a. Invoke the tenant-scoped kill switch immediately when the affected tenant is known;
      invoke the platform-wide kill switch (`POST /admin/kill-switch/global`) only when
      the compromise window or tenant set is unclear. This blocks token validations within
      the kill-switch propagation window (pub/sub propagation: single-digit milliseconds
      intra-DC; worst case bounded by `refreshIntervalMs = 30 s`).
   b. Bulk-revoke all JTIs in the mint-audit store signed with the compromised `kid`
      (per §2 enumeration procedure).
   c. Notify affected tenants with the list of potentially-forged JTIs from the audit log.
   d. Lift the kill switch after the new key is active and old-key JTIs are revoked.

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

Without tenant-scoped signing keys, a compromised minter or signing credential could
issue tokens for **any tenant** at maximum privilege, not just the attacker's own tenant.

### Design — per-tenant signing keys behind a single root

**Recommendation: per-tenant keys, single HSM root.**

Each tenant is assigned a dedicated signing key in the HSM. The tenant's tokens carry a
`kid` that maps to their key and an `aud`/issuer tuple bound to that tenant. The JWKS
endpoint returns only keys valid for the tenant/gateway audience being verified. The
platform root/admin identity is used only to bootstrap or disable tenant key creation
(a brief admin operation) and is otherwise outside the runtime signing path.

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

A compromised **tenant HSM signing path** can forge tokens for that tenant, so the
gateway must enforce the tenant/audience binding in addition to normal signature
verification. A compromised **minter service** is broader because it can perform policy
lookups and request signatures for tenants reachable by its workload identity; that risk
is mitigated by per-tenant HSM keys, tenant-sharded service identities where practical,
short TTLs, mint-audit/HSM-log reconciliation, and emergency kill-switch rotation.

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
[CDN / load balancer] — WAF rules: rate-limit per API-key prefix; only POST /mint and hosted /api/v1/enforce are routed — all other methods and paths are rejected at the load balancer
    ↓  Internal mTLS
[Minter service]
    ├─ SDK-authenticated KMS sign call (IAM role, no long-lived credential) → [HSM]
    └─ Internal mTLS with short-lived tenant JWT (hosted /api/v1/enforce only) → [Tool gateway]
```

- The minter service is not reachable from the public internet except through the CDN/LB.
  Internal traffic uses mTLS with a short-lived certificate rotated by the service mesh
  (e.g., Istio / AWS ACM / GCP Certificate Authority Service).
- The minter has **no inbound admin port**. Configuration changes (policy updates, key
  rotation triggers) arrive via a separate admin API that is network-isolated to the
  operator's management VLAN / VPN.
- API-key validation is rate-limited per `sk-` prefix at the CDN layer (N attempts/minute
  configurable per tenant) before the request reaches the minter process.
- In hosted remote-enforcer mode, the external API key terminates at the minter façade.
  The internal tool gateway receives only the short-lived capability JWT; it never accepts
  an `sk-...` API key as an authorization token.

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
- The internal tool gateway is separately network-isolated; only the minter façade and
  approved self-host/BYO ingress paths can reach its enforcement route.

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
Postgres role is: `GRANT INSERT ON mint_audit TO audit_writer` and
`GRANT USAGE ON SEQUENCE mint_audit_id_seq TO audit_writer`. No `SELECT`, `UPDATE`, or
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
  kms_request_id TEXT,                   -- provider request/correlation id when exposed
  exp           BIGINT NOT NULL,         -- unix seconds: token expiry
  result        TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
  denial_reason TEXT,                    -- populated when result != 'ok'
  previous_hash TEXT NOT NULL,           -- SHA-256 of previous canonical row
  row_hash      TEXT NOT NULL,           -- SHA-256 of this canonical row
  row_hmac      BYTEA NOT NULL           -- HMAC-SHA256(sidecar secret, row_hash)
);

CREATE INDEX ON mint_audit (tenant_id, minted_at DESC);
CREATE INDEX ON mint_audit (kid, minted_at DESC);  -- for key-compromise blast-radius query
CREATE INDEX ON mint_audit (jti);                  -- for per-token lookup on revocation
```

#### Tamper evidence

Each row is protected by a per-row HMAC-SHA-256 over the canonical JSON of the row
fields, computed with a secret held only by the audit sidecar (not the minter process and
not the DBA). Canonicalization uses RFC 8785 JSON Canonicalization Scheme over the
following exact field sequence: `minted_at`, `caller_ip`, `caller_ua`, `api_key_prefix`,
`tenant_id`, `agent_id`, `session_id`, `policy_id`, `policy_fingerprint`, `jti`, `kid`,
`kms_request_id`, `exp`, `result`, `denial_reason`, `previous_hash`. Nullable fields
such as `caller_ua`, `kms_request_id`, and `denial_reason` are encoded as JSON `null`
when absent. The excluded fields are `id`, `row_hash`, and `row_hmac`; `previous_hash`
is included so deletion or reordering breaks the chain. The sidecar supplies `minted_at`
explicitly before hashing rather than relying on the database default. Timestamps are UTC
ISO-8601 strings with millisecond precision, and binary `row_hmac` is encoded as
base64url for verification exports. This is the same pattern used by
`LedgerAuditEvidenceSigner` in
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

A **low-activity tenant** is defined as one with fewer than 10 successful mints in the
previous 7 days. The following rules are defined in the minter's alert configuration and
are tested against a synthetic test tenant before Stage 3 ships.

#### Rule 1 — Mint-rate spike per tenant

```yaml
# Fires when a single tenant's mint rate exceeds 10× its 1-hour rolling average.
alert: MinterRateSpike
expr: |
  sum by (tenant) (rate(euno_minter_mint_total{result="ok"}[5m]))
  > 10 * sum by (tenant) (avg_over_time(rate(euno_minter_mint_total{result="ok"}[5m])[1h:5m]))
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
    sum by (tenant) (increase(euno_minter_mint_total{result="ok"}[5m])) > 0
    and on(tenant) (
      sum by (tenant) (increase(euno_minter_mint_total{result="ok"}[7d])) < 10
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
# Fires when more than 5 KMS errors occur in 1 minute summed across all providers.
alert: MinterKmsErrorCluster
expr: sum(rate(euno_minter_kms_error_total[1m])) > 5
for: 1m
labels:
  severity: critical
annotations:
  summary: "KMS error rate spike across all providers"
  runbook: "https://docs.euno.example/runbooks/minter-kms-errors"
```

#### Rule 4 — Mint failure spike

```yaml
# Fires when the error/denied rate for any tenant exceeds 50% over 5 minutes,
# which may indicate a credential stuffing or API-key enumeration attack.
alert: MinterHighFailureRate
expr: |
  sum by (tenant) (rate(euno_minter_mint_total{result=~"denied|error"}[5m]))
  /
  sum by (tenant) (rate(euno_minter_mint_total[5m]))
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

#### Rule 6 — HSM sign/audit mismatch

The security telemetry job compares provider HSM sign-operation logs against
`mint_audit` rows by `kid`, service identity, and time bucket. Where the provider exposes
a request/correlation identifier to the SDK or audit log, the minter records it in
`mint_audit.kms_request_id` and the job performs exact matching. Where the provider does
not expose a stable application-visible request ID, the job falls back to exact count
matching per `(kid, service_identity, minute)` using the provider event timestamp truncated
to the minute after normalizing all timestamps to UTC. Minter nodes and audit ingestion
workers must be NTP-synchronized with drift under 30 seconds; if measured drift exceeds
that bound, the telemetry job pages separately because reconciliation is degraded.
Concurrent signs are handled by comparing aggregate counts over the affected minute plus
adjacent minutes covered by the 30-second drift tolerance. If provider logs are batched or
throughput is high enough that minute-level clustering makes bucket attribution ambiguous,
the job widens the comparison to a rolling 5-minute UTC window and compares cumulative
counts for the same `(kid, service_identity)`. No ±1 tolerance is accepted after the
two-minute ingestion-lag allowance; if the widened window still mismatches, the job pages
security as a potential direct sign-oracle compromise. Tenants whose normal volume makes
5-minute count matching too noisy must enable provider request-ID capture before their
rate limit is raised.

### Alert routing

All `critical` alerts page the on-call security engineer immediately (PagerDuty / OpsGenie
integration). `warning` alerts post to the `#security-alerts` Slack channel and are
reviewed at the next business-day stand-up. SRE runbooks for each alert are maintained at
`docs/runbooks/minter-*.md` (see stub files created alongside this document; fully
populated before Stage 3 ships to the first paying customer).

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
| [`docs/mvp.md`](../mvp.md) | [§"Minter threat model"](../mvp.md#minter-threat-model-required-before-stage-3-ships), [§"Critical risks"](../mvp.md#critical-risks) |
| [`docs/stage3executionplan.md`](../stage3executionplan.md) | Task 1 (this document), Task 10–12 (minter implementation) |
| [`docs/enforcement.md`](../enforcement.md) | Cryptographic-token invariant |
| [`docs/capability-model.md`](../capability-model.md) | §6 — unknown types are denied by default |
| [`euno-platform/packages/common-infra/src/ledger-signer.ts`](../../euno-platform/packages/common-infra/src/ledger-signer.ts) | Per-row HMAC ledger pattern reused for mint-audit |
| [`euno-platform/packages/tool-gateway/src/revocation-store.ts`](../../euno-platform/packages/tool-gateway/src/revocation-store.ts) | Token revocation used in key rotation (§3) |
| [`euno-platform/packages/capability-issuer/src/azure-signer.ts`](../../euno-platform/packages/capability-issuer/src/azure-signer.ts) | Azure Key Vault signing driver |
| [`euno-platform/packages/capability-issuer/src/aws-kms-signer.ts`](../../euno-platform/packages/capability-issuer/src/aws-kms-signer.ts) | AWS KMS signing driver |
| [`euno-platform/packages/capability-issuer/src/gcp-cloudkms-signer.ts`](../../euno-platform/packages/capability-issuer/src/gcp-cloudkms-signer.ts) | GCP Cloud KMS signing driver |

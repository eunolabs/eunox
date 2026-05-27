# Enterprise Federation Threat Model Addendum

> **Status:** Approved (2026-05-19) — signed off as part of the
> enterprise pre-flight review.
>
> **Last updated:** 2026-05-19
>
> **Authors:** Platform Security squad
>
> **Reviewers:**
>
> - Engineer 1: Platform Engineering Lead — 2026-05-19
> - Engineer 2: Backend Infrastructure Engineer — 2026-05-19
> - Security Reviewer: Principal Security Architect — 2026-05-19

---

## Background

The eunox enterprise deployment extends the platform to a full cross-organizational
trust ecosystem. Four capabilities introduce materially new attack surfaces:

1. **Partner-DID federation** — a remote organization issues capability tokens
   from their own DID-backed signing key, and the eunox gateway must accept and
   verify them without sharing key material.
2. **SCIM 2.0 provisioning** — an enterprise identity team can push users and
   group memberships from Okta, Entra ID, or Ping Identity, which are then
   reflected in capability issuance.
3. **SOC2 audit-trail export** — a `GET /api/v1/audit/export` endpoint exposes
   the entire signed audit record set to authorized operators.
4. **DB credential issuance** (`db-token-service`) — the platform now issues
   short-lived database IAM credentials scoped to a capability token, extending
   the blast radius of a stolen token to include live database access.

This document addresses the following threat model questions before partner-federation
code, SCIM code, or SOC2 export code may merge to `main`.

---

## 1. Partner DID Compromise

**Question:** _If a partner's signing key is compromised, what
capability tokens can an attacker mint? What is the blast radius across
partner-issued sessions? What is the detection path (circuit breaker fires,
Prometheus alert fires, admin is notified) and the revocation path (remove
partner DID from registry → circuit breaker forces re-evaluation on next
request)?_

### 1.1 What tokens can an attacker mint?

When a partner's signing key is compromised, an attacker can mint capability
JWTs that:

- Set `iss` to the partner's DID (which is trusted by the gateway).
- Set `sub`, `capabilities`, `agentId`, `tenantId`, and `exp` to arbitrary
  values — the gateway verifies the JWT signature against the partner's DID
  document but does not constrain what claims the partner may assert (the
  trust model is declarative, not capability-bounded: if the partner is trusted,
  their signed assertions are accepted).

The attacker **cannot**:

- Mint tokens whose `iss` is the eunox's own DID — that requires the
  platform's KMS signing key, which is a separate key entirely.
- Exceed the gateway's per-token TTL enforcement (`exp` ≤ `iat` + configured
  max TTL; the gateway rejects tokens whose remaining lifetime exceeds the
  configured maximum, regardless of the `exp` claim value). This limits how
  long each forged token is valid.
- Bypass gateway-side policy constraints that are independent of token content
  (IP allowlists, per-`sub` rate limits, gateway-level capability restrictions).
- Forge KMS-signed audit records — `SignedAuditEvidence` records are signed by
  the platform's KMS key, not by the partner's key. A partner key compromise
  does not affect the integrity of the audit trail.

### 1.2 Blast radius

The blast radius is bounded to:

- **Scope:** all agents and tenants whose `agentId`/`tenantId` values the
  attacker knows and that would be accepted in a token with the compromised
  partner's `iss`. The gateway does not maintain a per-partner list of
  allowable `agentId`/`tenantId` values — if the partner is trusted, any
  `(agentId, tenantId)` combination in their token is accepted.
- **Time window:** each forged token is valid until its `exp`. After the
  partner's key is rotated and their DID document is updated to remove the
  compromised key, the gateway's positive key cache (default 5 minutes,
  tunable via `PARTNER_DID_CACHE_TTL_SECONDS`) means existing cached keys
  remain valid for up to one cache TTL after the DID document is updated.
  During an active incident, call `POST /admin/partner-dids/:did/refresh`
  (with `X-Admin-Api-Key` and `X-Admin-Operator` headers) to flush the
  positive key cache for the compromised partner immediately.
  `PARTNER_DID_CACHE_TTL_SECONDS` accepts only positive integers and cannot
  be set to 0 to force immediate re-resolution.
- **Tenancy containment:** the blast radius is limited to partner-issued
  tokens. Platform-issued tokens (from the platform's own capability issuer)
  are not affected. Other registered partners are not affected.

| Compromised entity                                     | Blast radius                                                                                                                                                                                                                            |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Partner signing key (private JWKS)                     | Attacker can mint tokens with `iss = <partner DID>` for any `(agentId, tenantId)`. Bounded by gateway token TTL and positive cache TTL (max 5 min by default).                                                                          |
| Partner DID document hosting (domain/registry)         | See §2 (DID document spoofing).                                                                                                                                                                                                         |
| Gateway's `TRUSTED_PARTNER_DIDS` env var (legacy path) | An attacker who can write this env var can add an untrusted DID to the trust set without the two-eyes approval workflow. Mitigation: use the `PartnerDidRegistry` admin API (not the env var) for all production partner registrations. |

### 1.3 Detection path

| Signal                                                                                        | Source                                                                        | Alert threshold                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `eunox_partner_did_circuit_breaker_state{did="...", state="open"}`                            | Prometheus gauge (Task 3: `onCircuitStateChange` callback → Prometheus gauge) | Circuit opens after `PARTNER_DID_CB_FAILURE_THRESHOLD` failures within `PARTNER_DID_CB_WINDOW_MS`; transitions are logged at `warn` level and exported as a gauge. Alert threshold: state = `open` for > 1 minute. |
| Abnormal issuance volume for partner `iss`                                                    | Gateway audit log `ENFORCEMENT_DECISION` events, filter `iss = <partner DID>` | >2× 1-hour moving average per partner DID → PagerDuty.                                                                                                                                                             |
| `eunox_gateway_token_verify_error_total{reason="AUTHENTICATION_FAILED", iss="<partner DID>"}` | Prometheus counter                                                            | Spike in verification errors from a specific partner DID suggests token replay or key rotation without cache invalidation. Alert on sudden increase.                                                               |
| Partner DID re-resolve cache miss rate                                                        | Structured log `partner_did_cache_miss` events                                | High miss rate (> expected re-resolution frequency) may indicate forced cache invalidation attacks.                                                                                                                |
| Admin API partner-registry mutation events                                                    | Audit log `PARTNER_DID_APPROVED`, `PARTNER_DID_REVOKED`                       | Any registry change outside a change-management window triggers an operator alert.                                                                                                                                 |

### 1.4 Revocation path

1. **Immediate:** an on-call operator calls the gateway admin API:

   ```
   DELETE /admin/partner-dids/:did
   X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>
   X-Admin-Operator: <operator-identity>
   ```

   The `PartnerDidRegistry.revoke()` method transitions the entry to
   `revoked` status immediately. Subsequent `trusts(did)` calls return
   `false`, and `getKey()` throws `AUTHENTICATION_FAILED` without a
   network call.

2. **Cache flush:** tokens from the partner are no longer accepted
   immediately for new requests because `trustsAsync()` checks the
   registry before cache lookup — a revoked entry fails the trust check
   before the key cache is consulted.

3. **In-flight sessions:** sessions whose tokens were issued before
   revocation continue to be accepted by the gateway until the token's
   `exp`. This is unavoidable given the stateless JWT model. To minimize
   the in-flight window, operators should:
   - Set `DEFAULT_TOKEN_TTL` to 15 minutes or less (already the
     platform default).
   - Call the gateway's revocation endpoint (`POST /admin/revoke` with
     the `jti` of known forged tokens) for specific tokens whose
     `jti` is identified in the audit log.

4. **Key rotation:** the partner rotates their signing key and updates
   their DID document. The gateway's positive key cache (default 5
   minutes) expires naturally, and subsequent resolution fetches the
   new DID document with the new verification method.

---

## 2. DID Document Spoofing

**Question:** _A `did:web` document is served over HTTPS. What
happens if the partner's TLS certificate is MiTM'd or the domain is
hijacked? Document the pin-attestation workflow (`verifyPinAttestation`)
and mandate its use for production partner
registrations._

### 2.1 Threat model

For `did:web` DIDs (e.g., `did:web:partner.example.com`), the DID document
is hosted at `https://partner.example.com/.well-known/did.json`. The
security of the DID document depends on the security of that HTTPS endpoint.

If an attacker:

- **MiTMs the TLS connection**: obtains a fraudulently issued TLS certificate
  (via a rogue CA or CA compromise) and intercepts the HTTPS response to serve
  a forged DID document containing an attacker-controlled public key.
- **Hijacks the domain**: gains control of the partner's domain (DNS hijack,
  expired domain, registrar compromise) and hosts a fraudulent DID document.

In either case, without pin-attestation, the `PartnerIssuerResolver` would
accept the forged DID document and the attacker's key, allowing them to mint
tokens on behalf of the partner DID.

### 2.2 Pin-attestation workflow

The `PartnerDidRegistry` provides a cryptographic pin mechanism that prevents
acceptance of a substituted DID document. Pin-attestation is **mandatory for
all production partner registrations** (see §2.4 below).

**Step 1: proposal.** An operator submits a partner DID proposal via:

```
POST /admin/partner-dids/proposals
X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>
X-Admin-Operator: <proposer-identity>
Body: { "did": "did:web:partner.example.com", ... }
```

At proposal time, the gateway resolves the current DID document and computes
`pinnedDocSha256 = jcsSha256(didDocument)` (JCS-SHA-256 via
`jcsSerialize()` + SHA-256 over the deterministic JSON). This hash is stored
in the `PartnerDidEntry`.

**Step 2: two-eyes approval.** A _different_ operator (different identity from
the proposer — enforced by `approver !== entry.proposer`; the
`TwoEyesViolationError` is thrown and logged if violated) approves the entry:

```
POST /admin/partner-dids/proposals/:did/approve
X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>
X-Admin-Operator: <approver-identity>   ← must differ from proposer
```

At approval time, the gateway:

1. Re-fetches the live DID document and recomputes its JCS-SHA-256.
2. Verifies the hash matches the one recorded at proposal time.
3. If `PARTNER_DID_PIN_SECRET` is configured, produces a
   `PinAttestation` via `createPinAttestation()`:
   ```
   HMAC-SHA-256(PARTNER_DID_PIN_SECRET, jcsSerialize({
     did, pinnedDocSha256, approver, activatedAt
   }))
   ```
   This HMAC binds the pin hash to the specific approver identity and
   timestamp, preventing tampered Redis entries from substituting a
   different hash.

**Step 3: runtime enforcement.** On every DID document resolution
(`PartnerIssuerResolver._doResolve()`):

1. The live DID document is fetched over HTTPS.
2. `jcsSha256(liveDocument)` is computed and compared against
   `pinnedDocSha256` from the registry entry.
3. If `PARTNER_DID_PIN_SECRET` is set and the entry has a
   `pinAttestation`, `verifyPinAttestation()` is called first —
   a present-but-invalid attestation causes a fail-closed rejection
   (treated as a tampering signal):
   ```
   // entry has pin AND invalid attestation → fail closed
   if (attestation && !verifyPinAttestation(attestation, secret)) {
     throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, ...);
   }
   ```
4. Hash mismatch (live document differs from the pinned hash) →
   `CapabilityError(AUTHENTICATION_FAILED, ...)` — the partner token
   is denied even if the TLS connection succeeded.

Pin-mismatch and key-validation errors do **not** count as circuit-breaker
failures — only network resolution failures do. This prevents an attacker
with a malformed DID document from forcing the circuit open by design.

### 2.3 `did:ion` additional protection

For `did:ion` DIDs, the DID document is anchored on the ION ledger (backed
by Bitcoin) and resolved via a configured ION resolver endpoint
(`ION_RESOLVER_URL`). Domain hijack attacks do not apply to `did:ion`
because the DID document integrity is cryptographically anchored, not
dependent on DNS. However:

- Compromise of the `ION_RESOLVER_URL` endpoint (if self-hosted) could
  serve a forged resolution response.
- Task 2 adds a `RedisCircuitBreaker` around `resolveDidIon()` so that
  resolver outages do not crash the issuance path. The pin-attestation
  mechanism applies to `did:ion` as well when enabled.

### 2.4 Production mandate

**All production partner registrations MUST use pin-attestation.** Specifically:

1. `PARTNER_DID_PIN_SECRET` MUST be configured (minimum 32 bytes of entropy,
   stored in the secret manager, not in an env file).
2. `pinnedDocSha256` MUST be set at proposal time and re-verified at
   approval time.
3. The two-eyes approval workflow (different proposer and approver
   identities) is not optional — `TwoEyesViolationError` is a hard gate
   in the `approve()` implementation.
4. Env-var-seeded entries (from `TRUSTED_PARTNER_DIDS`) are treated as
   unpinned and generate a warning log at every resolution. They are
   acceptable only for development and evaluation environments — never
   for production.

---

## 3. SCIM Bearer Token Exposure

**Question:** _The `ISSUER_SCIM_BEARER_TOKEN` is a long-lived static
secret. Document its required rotation cadence, storage (secret manager, not
env file), and the consequence of exposure (all provisioned users/groups must
be considered attacker-controlled until token is rotated)._

### 3.1 Nature of the secret

`ISSUER_SCIM_BEARER_TOKEN` is the outbound credential that an enterprise IdP
(Okta, Entra ID, Ping Identity) presents when making SCIM API calls to the
capability issuer. Unlike the `ISSUER_ADMIN_API_KEY` (which is operator-only),
this token is held by the enterprise IdP and is therefore transmitted over the
network on every SCIM provisioning request.

The secret is verified using constant-time comparison (`crypto.timingSafeEqual`)
against every incoming `Authorization: Bearer <token>` header on the SCIM
endpoints.

### 3.2 Required rotation cadence

| Event                                                                        | Action                                                                                 |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Scheduled rotation                                                           | Every **90 days** — aligned with the platform's standard secret rotation policy.       |
| Suspected exposure (any of the below)                                        | **Immediate rotation** — within 1 hour of detection.                                   |
| SCIM IdP credential store compromise                                         | Immediate rotation.                                                                    |
| Any outbound SCIM client secret rotation at the IdP side                     | Rotate and update the issuer simultaneously in a single change window.                 |
| SCIM endpoint anomaly (unexpected provisioning events, unknown users/groups) | Immediate rotation + audit review of all SCIM-provisioned changes since last rotation. |

### 3.3 Storage requirements

1. **Secret manager only.** `ISSUER_SCIM_BEARER_TOKEN` must be stored
   in a managed secret store (Azure Key Vault, AWS Secrets Manager, GCP
   Secret Manager, or HashiCorp Vault). It must never appear in:
   - `.env` files in the repository or on disk.
   - Kubernetes ConfigMaps (use a Secret object backed by an external secrets
     manager, e.g., External Secrets Operator or Sealed Secrets).
   - Container image environment files.
   - Shell history.

2. **Minimum entropy.** The token must be at least 32 bytes of cryptographically
   random data, encoded as a URL-safe base64 or hex string:

   ```bash
   openssl rand -base64 48  # generates a 64-character base64 token
   ```

3. **Separate from admin credentials.** `ISSUER_SCIM_BEARER_TOKEN` must be
   a different value from `ISSUER_ADMIN_API_KEY` and all operator JWTs.
   The SCIM bearer token is held by the IdP; the admin API key is held
   by the operator. These must be rotated independently.

### 3.4 Consequence of exposure

**If `ISSUER_SCIM_BEARER_TOKEN` is exposed, the operator must assume:**

- All SCIM-provisioned users and groups are **attacker-controlled** until
  the token is rotated and all SCIM records are audited.
- An attacker with the SCIM bearer token can:
  - Provision arbitrary users with arbitrary group memberships.
  - Assign any user to any group, including groups mapped to elevated
    roles (`admin`, `operator`) if the `ISSUER_SCIM_GROUP_ROLE_MAP`
    allows this (see §4 for the approval gate on elevated-role mappings).
  - Delete legitimate users (soft-delete via SCIM `DELETE`) and groups.
  - Modify users' `active` status to deprovision real users.
- **New capability tokens issued after the exposure** to SCIM-provisioned
  users will reflect the attacker-controlled group memberships.
- **Tokens issued before the exposure** are not affected unless the
  attacker deprovisioned or modified the user record in a way that
  changes capability derivation (capability issuance uses SCIM group
  membership at issuance time, not at token validation time).

**Incident response steps:**

1. Rotate `ISSUER_SCIM_BEARER_TOKEN` immediately (this invalidates all
   future SCIM calls using the old token).
2. Audit the SCIM provisioning log for all events since the last known
   good state (or since the last scheduled rotation).
3. Review all users and groups provisioned via SCIM. Mark any suspicious
   entries for deletion or manual re-verification.
4. Revoke all in-flight capability tokens issued to SCIM-provisioned
   users whose memberships cannot be verified (use the gateway's
   `POST /admin/revoke` endpoint with the `jti` values from the audit
   log).
5. Re-provision legitimate users through the IdP side after rotating
   the token and updating the IdP's SCIM outbound configuration.

---

## 4. SCIM Privilege Escalation

**Question:** _A SCIM push can assign a user to an admin group.
Document the approval workflow required before a SCIM group is mapped to
an elevated role (`admin`, `operator`). The `ISSUER_SCIM_GROUP_ROLE_MAP`
must not permit mapping a SCIM group to `operator` without explicit
operator-JWT authorization for that mapping._

### 4.1 Group-to-role mapping architecture

The `ISSUER_SCIM_GROUP_ROLE_MAP` is a JSON configuration (supplied as an
env var or a mounted config file) that maps SCIM group names to issuer
role keys defined in `RoleCapabilityPolicy`. Example:

```json
{
  "EunoxViewers": "viewer",
  "EunoxDevelopers": "developer",
  "EunoxOperators": "operator"
}
```

When `IssueController.handleFromUserContext()` processes a user's capability
request, SCIM group memberships are fetched and merged with IdP-provided
roles. SCIM groups take precedence on conflict (the SCIM group membership is
the authoritative authorization model; IdP claims are the authentication
signal).

### 4.2 Elevated-role mapping gate

**Roles classified as "elevated" for this purpose:**

| Role key    | Classification                                                  |
| ----------- | --------------------------------------------------------------- |
| `viewer`    | Standard — no additional gate                                   |
| `developer` | Standard — no additional gate                                   |
| `admin`     | Elevated — approval required                                    |
| `operator`  | Elevated (highest privilege) — approval + operator-JWT required |

**Requirements for mapping a SCIM group to an elevated role:**

1. **The `ISSUER_SCIM_GROUP_ROLE_MAP` entry for any group mapped to
   `admin` or `operator` MUST be set or modified exclusively via an
   authenticated admin API call with a valid operator JWT** — not via
   a plain env-var edit or file system change without the operator-JWT
   authorization step. The administrative workflow is:

   ```
   POST /api/v1/admin/scim/group-role-map
   Authorization: Bearer <operator-JWT>
   X-Admin-Api-Key: <ISSUER_ADMIN_API_KEY>
   Body: { "groupName": "EunoxOperators", "role": "operator" }
   ```

   This request is recorded in the issuer audit log with the operator
   identity from the JWT.

2. **Two-eyes sign-off.** Any mapping of a SCIM group to `admin` or
   `operator` requires a second operator's approval (a separate API
   call from a different identity) before it becomes effective. This
   mirrors the partner-DID two-eyes approval workflow.

3. **The SCIM bearer token alone cannot modify group-to-role mappings.**
   The SCIM bearer token authorizes the `/scim/v2/` endpoints only. It
   does not authorize the `/api/v1/admin/scim/group-role-map` endpoint.
   An attacker with only the SCIM bearer token can add users to SCIM
   groups but cannot change which role a SCIM group maps to.

4. **Audit trail.** Every change to `ISSUER_SCIM_GROUP_ROLE_MAP` (add,
   update, delete) is recorded as an `ADMIN_CONFIG_CHANGE` audit event
   with the operator identity, the old value, the new value, and the
   timestamp.

### 4.3 Defense-in-depth: capability derivation is additive, not escalating

Even if an attacker successfully provisions a SCIM group mapped to `operator`
and adds a user to it, the user's effective capabilities are still bounded
by the `RoleCapabilityPolicy` configured for that role. The capability issuer
does not issue capabilities outside the policy definition regardless of group
membership. An `operator` role can only grant the capabilities defined in the
policy for `operator` — it cannot self-grant capabilities that are not in the
policy.

### 4.4 SCIM group removal

When a user is removed from a SCIM group (`PATCH /scim/v2/Groups/:id` with a
membership delta, or `PUT /scim/v2/Groups/:id` with the user absent from the
`members` list), the change takes effect on the **next capability issuance
request** for that user. Because capability tokens are short-lived (default
15-minute TTL), this means the user's effective capabilities are reduced within
at most one TTL window after group removal.

---

## 5. Cross-Chain Audit Anchor Tampering

**Question:** _The cross-chain anchor's HMAC secret is already
documented in `docs/runbooks/ledger-hmac-rotation.md`. Document
what an attacker who obtains the HMAC secret can do (forge
commitments, not forge individual signed evidence records — the evidence is
separately KMS-signed), and the impact of the Azure Confidential Ledger
backend versus the per-replica-postgres backend._

### 5.1 What the HMAC secret protects

Every row in the audit ledger includes:

```
row_hmac = HMAC-SHA256(AUDIT_LEDGER_HMAC_SECRET,
  seq || ":" || previousHash || ":" || recordHash || ":" || replicaId)
```

This per-row HMAC enables tamper detection: any modification to a ledger row
(changing `seq`, `previousHash`, `recordHash`, or `replicaId`) without the
secret will produce a detectable HMAC mismatch.

The cross-chain anchor (`CrossChainAnchor`) additionally computes hash-chain
commitments across ledger replicas, producing `SignedCrossChainCommitment`
objects whose integrity depends on the same HMAC secret.

### 5.2 What an attacker with the HMAC secret CAN do

An attacker who obtains `AUDIT_LEDGER_HMAC_SECRET` AND has write access to
the Postgres database can:

- **Forge `row_hmac` values** for modified or fabricated rows, making them
  pass `verifyRowHmac()` verification. This allows the attacker to alter
  or delete audit entries without detection by the HMAC integrity check.
- **Forge cross-chain anchor commitments** — recompute `SignedCrossChainCommitment`
  hash-chain values to match a modified ledger state.

An attacker with the HMAC secret alone (but no database write access) cannot
alter the audit ledger.

### 5.3 What an attacker with the HMAC secret CANNOT do

The HMAC secret does **not** protect individual `SignedAuditEvidence` records.
Those are separately signed by the platform's KMS key (Azure Key Vault,
AWS KMS, or GCP Cloud KMS) during audit pipeline processing. Specifically:

- Each `SignedAuditEvidence` record carries a JWS signature over the evidence
  payload, signed by the platform's non-exportable HSM/KMS key.
- Forging a `SignedAuditEvidence` record requires the platform's KMS private
  key, not the HMAC secret.
- Therefore, even if the attacker can alter the Postgres `row_hmac` chain,
  auditors verifying evidence records against the platform's JWKS endpoint
  (`/.well-known/jwks.json`) can still detect forged evidence records —
  the JWS signature will fail to verify.

**The two-layer model is intentional:**

- Row-level HMAC (AUDIT_LEDGER_HMAC_SECRET): protects ledger row integrity
  and chain linkage.
- KMS-based JWS signature: protects the semantic content of each audit
  evidence record.
  An attacker who compromises only one layer is limited: HMAC-only compromise
  enables chain manipulation but not evidence forgery; KMS compromise would
  allow evidence forgery but not chain manipulation (without also having
  database write access and the HMAC secret).

### 5.4 Per-replica-postgres backend versus Azure Confidential Ledger

| Property                 | `per-replica-postgres`                                                                                                                       | Azure Confidential Ledger (ACL)                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Tamper protection        | Row-level HMAC-SHA-256 (software-enforced; requires `AUDIT_LEDGER_HMAC_SECRET`). DB admin with write access + HMAC secret can forge records. | Hardware-attested append-only ledger; entries cannot be modified or deleted by anyone, including Azure employees. No HMAC secret required. |
| HMAC secret risk         | Present — secret exposure + DB write access = undetected ledger tampering.                                                                   | Not applicable — ACL enforces immutability at the hardware level.                                                                          |
| Availability             | Depends on Postgres replication health.                                                                                                      | Managed SLA by Microsoft Azure.                                                                                                            |
| Air-gap support          | Yes (self-hosted Postgres).                                                                                                                  | No (requires Azure connectivity).                                                                                                          |
| SOC2 audit defensibility | Row-level HMACs can be verified offline; auditors must trust the HMAC secret chain of custody.                                               | ACL's hardware attestation provides a stronger guarantee for external auditors.                                                            |

**Recommendation:** For environments where SOC2 or external audit defensibility
is the primary goal, use `AUDIT_LEDGER_BACKEND=acl` (Azure Confidential
Ledger). For air-gapped or on-prem deployments, use
`AUDIT_LEDGER_BACKEND=per-replica-postgres` with strict secret management for
`AUDIT_LEDGER_HMAC_SECRET` per `docs/runbooks/ledger-hmac-rotation.md`.

### 5.5 HMAC secret management requirements

The `AUDIT_LEDGER_HMAC_SECRET` must be treated at the same sensitivity level
as the platform's KMS signing key:

- Stored in a secret manager (never in an env file or source control).
- Rotated following the three strategies in `docs/runbooks/ledger-hmac-rotation.md`
  (Strategy A — new table — is recommended for production).
- Access restricted to the gateway's workload identity — human operators
  should not have direct access to the secret.
- Any suspected exposure triggers immediate incident response: rotation
  (Strategy A), re-import of historical records with the new secret for
  the Strategy B window, and audit review of all cross-chain commitments.

---

## 6. SOC2 Export Endpoint Exposure

**Question:** _The `GET /api/v1/audit/export` endpoint returns all
signed audit evidence. Document the authorization model (admin operator-JWT,
not user token), the rate limit, the cursor expiry (24 h), and the
data-residency implications (no audit data leaves the on-prem deployment
unless the operator explicitly calls the endpoint)._

### 6.1 Authorization model

The `GET /api/v1/audit/export` endpoint is protected exclusively by the
gateway's admin API key (`GATEWAY_ADMIN_API_KEY`), using the same
timing-safe constant-time comparison (`crypto.timingSafeEqual`) already
used by all other admin routes in the gateway admin handlers. The authorization
requirements are:

- **Header:** `X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>`
- **NOT** a user capability token — capability tokens are for agent
  authorization, not admin operations.
- **NOT** a SCIM bearer token — the SCIM token only authorizes SCIM
  provisioning endpoints.

The endpoint is **not publicly documented** and is not included in the
`/.well-known/capability-issuer` discovery document for unauthenticated
consumers. It is described only in the operator runbook and this threat model.

**Access control:** only operators with the `GATEWAY_ADMIN_API_KEY` can
call this endpoint. This key must be issued to the minimum number of
operator identities required and should be rotated on the same cadence
as other admin secrets (90 days or on suspected exposure).

### 6.2 Rate limit

The export endpoint is subject to a per-IP rate limit of **10 requests
per 60-second window** (shared with other admin routes unless overridden
by `ADMIN_RATE_LIMIT_MAX`). In addition:

- The page size is capped at **1 000 records per response**. Exporters
  must use cursor-based pagination to retrieve large audit sets.
- An export cursor expires after **24 hours**. An expired cursor returns
  a 400 with `cursor_expired`. This prevents unbounded long-running
  export sessions that hold server-side state indefinitely.

### 6.3 Cursor security

The export cursor is an opaque, base64-encoded JSON object:

```json
{ "lastRowId": 12345, "expiresAt": 1716220000 }
```

Cursors are not signed — an attacker who obtains a cursor value can
enumerate records from the corresponding position without re-authenticating
for the cursor's 24-hour lifetime. However:

- Obtaining a cursor requires already knowing the `GATEWAY_ADMIN_API_KEY`
  (the endpoint requires it on every request, including cursor-based
  subsequent pages).
- The cursor's 24-hour expiry limits the window of exposure.
- Operators should treat cursor values as secrets during active export
  sessions (do not log cursor values; do not pass them in URLs where
  they would appear in access logs).

### 6.4 Data-residency implications

**No audit data leaves the on-prem deployment unless the operator
explicitly calls the export endpoint.** Specifically:

- The platform does not push, replicate, or stream audit evidence to
  any external service by default, including the eunox telemetry API
  (which collects only aggregate usage counters, not signed evidence
  records).
- The `DurablePostureEmitter` (`posture-emitter` package) queues evidence
  records locally (WAL-mode SQLite) and delivers them to configured
  downstream plugins asynchronously. No plugin ships with an external
  destination pre-configured — operators must explicitly add a plugin
  that transmits records outside the deployment.
- In air-gapped on-prem deployments, the `posture-emitter` queue can
  only deliver records to locally reachable endpoints (the SQLite WAL
  file is local to the gateway pod).

**Operators are responsible for ensuring that any export operation
(manual or automated) complies with their data-residency and data-privacy
requirements before transmitting evidence records outside the deployment.**

---

## 7. DB Credential Blast Radius

**Question:** _If a `db-token-service`-issued credential is stolen,
what DB access does the attacker have? Document the minimum-privilege DB role
provisioned by the service, the credential TTL (must be ≤ capability token
TTL), and the connection-level audit trail at the DB layer._

### 7.1 What DB access does the attacker have?

A `db-token-service`-issued credential grants access to the specific
database and schema objects that the capability token's `db://` capabilities
name. The `POST /api/v1/db-tokens` endpoint:

1. Verifies the capability JWT (signature, `iss`, `aud`, expiry, algorithm
   allow-list) using the issuer's JWKS.
2. Extracts all capabilities whose `resource` starts with `db://`.
3. Resolves the DB username from the token's `authorizedBy.roles` claim
   via the `dbUsernamesByRole` policy (separate from the capability-issuer's
   policy — per-customer DB-cred policy changes do not require restarting
   the capability issuer).
4. Mints short-lived IAM credentials (Azure SQL AAD token, AWS RDS IAM
   auth token, or GCP Cloud SQL IAM token) scoped to the resolved DB
   username.

If the minted credential is stolen, the attacker has:

- **Read/write access** to the DB objects granted to the resolved DB username
  — bounded by the minimum-privilege DB role (see §7.2).
- **No access** to DB objects outside the capability token's `db://` scope.
- **No ability** to forge capability JWTs — the `db-token-service` holds no
  KMS signing credentials.
- **No access** to other tenants' databases — each `db://` capability names
  a specific database and schema; the DB username policy does not grant
  cross-tenant database access.

### 7.2 Minimum-privilege DB role

The `dbUsernamesByRole` policy maps issuer roles to pre-provisioned,
minimum-privilege DB principals. These principals must be provisioned by
the operator according to the following constraints:

| Issuer role | Required DB permission level                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------- |
| `viewer`    | `SELECT` on approved tables only; no `INSERT`, `UPDATE`, `DELETE`, `CREATE`.                      |
| `developer` | `SELECT`, `INSERT`, `UPDATE` on approved tables; no `DELETE` on audit tables; no DDL.             |
| `operator`  | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on approved tables; no DDL; no direct schema modification. |

**Prohibited at all levels:**

- `SUPERUSER`, `CREATEDB`, `CREATEROLE` (Postgres) or equivalent on other
  DB platforms.
- Access to system tables (`pg_catalog`, `information_schema`) beyond
  what is needed for query execution.
- Ability to create or modify stored procedures or functions that execute
  with elevated privileges (`SECURITY DEFINER`).

Operators MUST verify that DB principals provisioned for the
`db-token-service` follow these constraints during service setup and after
any DB schema change.

### 7.3 Credential TTL

The `db-token-service` derives the credential TTL from the capability
token's remaining lifetime:

```
const capabilityTtlSeconds = Math.max(0, payload.exp - now);
```

The minted credential is valid for `capabilityTtlSeconds` only —
**the credential TTL is always ≤ the capability token TTL**. This
is enforced in code; there is no configuration option to extend the
credential TTL beyond the token's remaining lifetime. When the
capability token expires, the DB credential also expires.

The default capability token TTL is **15 minutes** (`DEFAULT_TOKEN_TTL=900`).
Operators should not increase this beyond what is needed for their agent
workload. Shorter TTLs reduce the blast radius of a stolen credential.

### 7.4 Connection-level audit trail

The platform's `db-token-service` logs each credential-minting request to
the structured log at `info` level, including `agentId`, `userId`, and
`capCount`. These events also flow through the gateway's audit pipeline when
the `DurablePostureEmitter` plugin is wired (Task 4).

At the **database layer**, operators are required to enable connection-level
auditing appropriate for their platform:

| Platform         | Required auditing                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Azure SQL        | Auditing to Azure Monitor / Storage account (`AUDIT_ACTION_GROUP = SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, DATABASE_OPERATION_GROUP`) |
| AWS RDS / Aurora | CloudTrail for IAM auth events; DB audit log (e.g., `pgaudit` for Postgres) with `pgaudit.log = 'write'` at minimum                     |
| GCP Cloud SQL    | Cloud SQL audit logs (Data Access audit logs enabled for the database instance)                                                         |

**Operators are responsible for enabling database-layer auditing.** The
`db-token-service` cannot enforce database-side logging; it can only
record the credential issuance event in its own audit log.

---

## 8. In-Process Guard Bypass

**Question:** _The AGT guard is a soft guard. Document explicitly
that an attacker who can modify the agent's in-process state can bypass the
guard, and that the outer gateway is the only hard enforcement boundary. The
threat model must not imply that the in-process guard is a security boundary._

### 8.1 The AGT guard is NOT a security boundary

**This section is explicit and non-negotiable. It must not be softened in any
documentation, marketing material, or customer-facing description.**

The `agentruntime.Runtime` (from `internal/agentruntime`) implements an
**in-process policy check** that evaluates tool calls against an
`AgentCapabilityManifest` before forwarding them to the outer gateway.

The guard is a **defense-in-depth, observability, and fail-early mechanism.
It is not a security boundary.** Specifically:

1. **An attacker who can modify the agent's in-process state can bypass the
   guard.** The guard runs in the same process as the agent. Any attacker
   who has achieved code execution in the agent process — through prompt
   injection, deserialization of malicious tool responses, or any other
   in-process attack vector — can:
   - Replace the `IdentityTokenProvider` function to return a token with different
     capabilities.
   - Manipulate the runtime's internal state to return `Allowed: true` unconditionally.
   - Call the underlying HTTP transport directly, bypassing the
     runtime entirely.
   - Craft a tool call that the runtime would deny but deliver it directly to
     the transport layer.

2. **The outer gateway is the only hard enforcement boundary.** The gateway
   verifies the capability JWT on every request (signature, expiry, scope)
   and enforces policy independently of the agent's in-process state. An
   attacker who bypasses the AGT guard still faces the gateway's verification
   at the network boundary. The gateway's verification cannot be bypassed by
   in-process state manipulation.

3. **If the runtime allows but the outer gateway denies:** the gateway's denial is the
   authoritative enforcement outcome. The runtime's allow is not logged as an
   authorization decision — only the gateway's deny appears in the audit
   trail as a `CAPABILITY_DENIED` event.

4. **Runtime denials are not audit trail entries.** A runtime denial
   is a diagnostic signal only — it does not replace the
   gateway's enforcement audit record. An attacker who bypasses the runtime
   and reaches the gateway will still be denied and audited if they lack the
   required capability.

### 8.2 When to use the AGT guard

The AGT guard is appropriate for:

- **Fail-early optimization:** preventing tool calls that would be denied
  by the gateway from making a network round-trip, reducing latency for
  agents with a complex capability manifest.
- **Developer visibility:** surfacing capability constraint violations in
  the agent developer's local environment before they reach production.
- **Defense-in-depth observability:** the `onDeny` callback can emit
  application-level telemetry (Prometheus counters, log events) that
  provides earlier signal than the gateway's audit log.

The AGT guard is **not appropriate** for:

- Enforcing any security boundary that would be violated if the guard
  were absent.
- Replacing or reducing the capability surface enforced by the gateway.
- Justifying a relaxation of the gateway's policy configuration.

### 8.3 Documentation and marketing constraints

Any documentation or communications that describe the AGT guard must include
the following statement:

> _The AGT in-process guard is a defense-in-depth observability layer, not
> a security boundary. The eunox gateway is the authoritative, hard
> enforcement boundary for all capability decisions. Compliance and security
> teams evaluating the layered enforcement architecture should base their
> assessment on the gateway's enforcement guarantees, not on the in-process
> guard._

---

## 9. Air-Gapped Key Management

**Question:** _In an air-gapped on-prem deployment without an HSM,
operators may use file-based EC keys. Document the required file permissions
(`0400`), the key derivation procedure, the offline backup requirements, and
the explicit statement that file-based keys are not supported for multi-tenant
cloud deployments._

### 9.1 File-based keys are NOT supported for multi-tenant cloud deployments

**This is an explicit, non-negotiable restriction.**

File-based EC keys (configured via `SIGNING_PROVIDER=file`, if applicable,
or EC private key files mounted into the service) are supported **only**
for single-tenant, air-gapped, on-prem deployments where no HSM is
available. They must not be used for:

- Any hosted or cloud deployment that serves more than one tenant.
- Any deployment where the key file is accessible to more than one
  process or operator identity.
- Any deployment where the key file is stored on a network-attached
  filesystem, shared volume, or block storage that is accessible to
  multiple hosts.

For multi-tenant cloud deployments, the only supported signing providers
are `azure-keyvault`, `aws-kms`, and `gcp-cloudkms` (per the
`capability-issuer` `SIGNING_PROVIDER` config in
`pkg/config/issuer.go`). These providers use
non-exportable HSM/KMS keys with per-workload-identity access control.
File-based keys have no equivalent access isolation guarantee.

### 9.2 Required file permissions

EC private key files must be protected with the most restrictive file
permissions available on the host:

```bash
# Set owner-read-only (no write, no execute, no group/other access)
chmod 0400 /etc/eunox/signing-key.pem

# Verify
ls -la /etc/eunox/signing-key.pem
# Expected: -r-------- 1 eunox-svc eunox-svc 227 2026-05-19 signing-key.pem
```

The key file must be:

- Owned by the service account that runs the capability issuer process
  (`eunox-svc` or equivalent).
- **Not** group-readable or world-readable.
- Stored on a filesystem that does not allow `sudo`-accessible modification
  by operators (e.g., mounted from a Kubernetes Secret object, not from a
  ConfigMap or hostPath volume).
- **Not** stored in the container image layer — mount the key at runtime
  from a Kubernetes Secret backed by an external secrets manager.

### 9.3 Key derivation procedure

For air-gapped deployments generating a new EC P-256 signing key:

```bash
# Step 1: Generate EC P-256 private key (PEM format)
openssl ecparam -genkey -name prime256v1 -noout -out /secure-media/signing-key.pem

# Step 2: Extract the public key (for JWKS publication)
openssl ec -in /secure-media/signing-key.pem -pubout -out /secure-media/signing-key-pub.pem

# Step 3: Compute the key thumbprint (RFC 7638, for JWKS kid)
# Use a JWK thumbprint tool such as the `jose` CLI:
# jose jwk thp -i /secure-media/signing-key.pem

# Step 4: Set permissions before copying to the service
chmod 0400 /secure-media/signing-key.pem

# Step 5: Transfer to the deployment location
install -m 0400 -o eunox-svc -g eunox-svc /secure-media/signing-key.pem /etc/eunox/signing-key.pem
```

Key generation must be performed on a trusted, isolated machine (preferably
the air-gapped host itself or an offline key-ceremony machine) — never on a
shared build server or developer workstation.

### 9.4 Offline backup requirements

A file-based signing key that is lost cannot be recovered; a lost signing
key means all previously issued tokens remain valid until they expire, but
new tokens cannot be issued until a new key is generated (requiring a JWKS
rotation and re-distribution of the new public key to all verifiers).

Backup requirements:

1. **Encrypted offline backup.** The private key file must be backed up to
   at least two independent offline media (e.g., hardware-encrypted USB
   drives, offline tape) using a symmetric encryption key stored separately
   from the private key:
   ```bash
   # Encrypt the private key for offline backup
   openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
     -in /etc/eunox/signing-key.pem \
     -out /backup-media/signing-key.pem.enc
   # Store the passphrase in a separate physical location (e.g., sealed envelope)
   ```
2. **Separate storage locations.** The two backup copies must be stored in
   physically separate locations (e.g., two different secure rooms, two
   different sites) to protect against localized physical loss events.
3. **Access control on backups.** Backup media access requires two-person
   authorization (key-ceremony model). The passphrase/recovery key must
   be stored separately from the backup media (split knowledge).
4. **Annual recovery test.** Restore the key from backup annually in a
   controlled environment to verify the backup is usable.
5. **Backup inventory.** Maintain a written log of all backup copies,
   their locations, and their creation and last-verified dates.

### 9.5 Key rotation in air-gapped deployments

When rotating the signing key in an air-gapped deployment:

1. Generate the new key following §9.3.
2. Add the new key's public component to the JWKS endpoint (both old and
   new public keys must be present during the rotation window so existing
   tokens continue to verify).
3. Update the service configuration to sign new tokens with the new key.
4. Wait for all tokens signed with the old key to expire (one max-TTL
   window — 15 minutes by default).
5. Remove the old public key from the JWKS endpoint.
6. Securely destroy the old private key file (cryptographic erasure or
   physical destruction of the storage medium).

---

## Sign-off (required before Tasks 3 / 6 / 10 merge)

| Reviewer                                        | Role     | Date       | Notes                                                                                                                         |
| ----------------------------------------------- | -------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Engineer 1: Platform Engineering Lead           | Engineer | 2026-05-19 | Reviewed §1–§4, §8–§9; no blocking issues                                                                                     |
| Engineer 2: Backend Infrastructure Engineer     | Engineer | 2026-05-19 | Reviewed §5–§7; confirmed cross-chain model; no blocking issues                                                               |
| Security Reviewer: Principal Security Architect | Security | 2026-05-19 | Full review of all sections; SCIM escalation gate (§4.2) and in-process guard statement (§8.1) confirmed as required controls |

---

## References

- [`docs/architecture.md`](../architecture.md) — architecture overview
- [`internal/gateway/partner_did_redis.go`](../../internal/gateway/partner_did_redis.go) — partner DID pin storage and retrieval
- [`internal/gateway/partner_verifier.go`](../../internal/gateway/partner_verifier.go) — partner issuer verification and cache behavior
- [`internal/dbtokensvc/app.go`](../../internal/dbtokensvc/app.go) — DB credential issuance and request validation
- [`docs/runbooks/ledger-hmac-rotation.md`](../runbooks/ledger-hmac-rotation.md) — HMAC secret rotation strategies
- [`docs/security/issuer-identity-threat-model.md`](./issuer-identity-threat-model.md) — issuer identity threat model
- [`internal/agentruntime/tool_invoker.go`](../../internal/agentruntime/tool_invoker.go) — in-process tool invocation and guard points
- [`pkg/config/issuer.go`](../../pkg/config/issuer.go) and [`pkg/config/gateway.go`](../../pkg/config/gateway.go) — issuer and gateway config structs

# Federation Trust Lifecycle

> **Audience:** Security engineers and operators managing cross-organization
> trust relationships in eunox partner federation.

---

## Table of Contents

1. [Overview](#overview)
2. [Trust Model](#trust-model)
3. [Lifecycle Stages](#lifecycle-stages)
   - [Stage 1: Discovery](#stage-1-discovery)
   - [Stage 2: Registration](#stage-2-registration)
   - [Stage 3: Approval](#stage-3-approval)
   - [Stage 4: Active Trust](#stage-4-active-trust)
   - [Stage 5: Key Rotation](#stage-5-key-rotation)
   - [Stage 6: Revocation](#stage-6-revocation)
4. [DID Resolution](#did-resolution)
5. [Token Verification Flow](#token-verification-flow)
6. [Capability Attenuation](#capability-attenuation)
7. [Circuit Breaker Protection](#circuit-breaker-protection)
8. [Security Controls](#security-controls)
9. [Operational Procedures](#operational-procedures)
10. [Monitoring and Alerting](#monitoring-and-alerting)

---

## Overview

Eunox supports cross-organization capability delegation via **partner
federation**. Organizations can issue capability tokens that are recognized
by other organizations' gateways, enabling secure inter-company API access
without shared secrets.

Federation is built on [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
as the trust anchor. Each partner organization publishes a DID document
containing their public signing keys. The gateway resolves these documents
to verify tokens issued by partners.

---

## Trust Model

### Trust Anchors

| Component          | Trust Basis       | Verification                               |
| ------------------ | ----------------- | ------------------------------------------ |
| Partner identity   | DID document      | DID resolution (did:web, did:key, did:ion) |
| Token authenticity | Digital signature | Public key from DID document               |
| Capability scope   | Attenuation rules | Parent ⊇ child validation                  |
| Availability       | Circuit breaker   | Per-method isolation                       |

### Trust Assumptions

1. **DID document integrity:** The resolution endpoint (HTTPS for did:web,
   ION network for did:ion) is not compromised
2. **Key custody:** Partner organizations protect their private signing keys
   (ideally in HSM/KMS)
3. **Honest issuance:** Partners issue tokens only to their authorized users
4. **Bounded delegation:** Cross-org tokens cannot exceed the parent token's
   capability scope (attenuation rule)

### Non-Goals

- **Identity federation:** Eunox does not federate user identities — only
  capability tokens
- **Policy synchronization:** Partners maintain independent policies;
  coordination is via capability subset rules
- **Bilateral trust:** Trust relationships are unidirectional; mutual trust
  requires two independent registrations

---

## Lifecycle Stages

### Stage 1: Discovery

Partners exchange DID URIs out-of-band (email, contract, API directory):

```
Partner A DID: did:web:partner-a.example.com
Partner B DID: did:ion:EiC9R5...
```

**Supported DID Methods:**

| Method    | Resolution                        | Latency | Trust Level      |
| --------- | --------------------------------- | ------- | ---------------- |
| `did:key` | Embedded in URI (no network call) | 0 ms    | Self-certifying  |
| `did:web` | HTTPS GET `/.well-known/did.json` | ~100 ms | DNS + TLS        |
| `did:ion` | ION network query                 | ~500 ms | Bitcoin anchored |

### Stage 2: Registration

An operator registers the partner DID via the admin API:

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/ \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:web:partner-a.example.com",
    "name": "Partner A",
    "description": "Cross-org API access for joint project"
  }'
```

**Response:**

```json
{
  "status": "registered",
  "did": "did:web:partner-a.example.com",
  "name": "Partner A"
}
```

**State:** `pending` — The DID is recorded but **not yet trusted** for token
verification.

**Storage:** Partner DID entries are persisted in Redis
(`RedisPartnerDIDStore`) as JSON in the `partner_dids` hash for
multi-replica consistency.

### Stage 3: Approval

A separate operator (ideally with elevated privileges) approves the partner:

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:partner-a.example.com/approve \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

**Response:**

```json
{
  "did": "did:web:partner-a.example.com",
  "status": "approved"
}
```

**State:** `approved` — The DID is now trusted. Tokens signed by keys in
this DID document will be accepted.

**Audit event:** `partner-did.approve` emitted to the audit ledger.

### Stage 4: Active Trust

Once approved, the partner can issue tokens that the gateway accepts:

1. Partner A issues a capability token signed with their private key
2. Token includes `iss: "did:web:partner-a.example.com"` in claims
3. Gateway extracts issuer DID from the unverified token
4. Gateway checks partner registry → status must be `approved`
5. Gateway resolves DID document → extracts public keys
6. Gateway verifies JWT signature against extracted keys
7. Standard claim validation (exp, iat, aud)
8. Token accepted with `CrossOrg: true` flag in verify result

### Stage 5: Key Rotation

Partners rotate keys by updating their DID document. The gateway
automatically picks up new keys on the next cache miss:

**For did:web partners:**

1. Partner updates `/.well-known/did.json` with new verification method
2. Gateway's DID cache expires (default TTL: 5 minutes)
3. Next token verification triggers fresh resolution
4. New key is discovered and used for verification

**For did:ion partners:**

1. Partner publishes a DID update operation to the ION network
2. ION network processes the update (may take minutes)
3. Gateway resolves updated document on next cache miss

**Manual cache invalidation** (for urgent rotations):

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:partner-a.example.com/refresh \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

This invalidates the DID cache entry, forcing immediate re-resolution.
Status changes to `refreshed` until an explicit status update occurs.

### Stage 6: Revocation

When trust must be withdrawn (compromise, contract termination, policy
violation):

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:partner-a.example.com/revoke \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

**Effect:**

- Status changes to `revoked`
- All subsequent token verification attempts for this DID fail with
  `ErrPartnerNotApproved`
- Tokens already in-flight continue to work until they hit the gateway
  (real-time enforcement, no pre-issued token grace period)
- DID cache entry is invalidated

**Audit event:** `partner-did.revoke` emitted to the audit ledger.

**Recovery:** A revoked partner can be re-approved if the underlying issue is
resolved. The admin must explicitly call the approve endpoint again.

---

## DID Resolution

### Resolution Architecture

```
┌─────────────────────────────┐
│     PartnerIssuerResolver    │
│  ┌───────────────────────┐  │
│  │   PartnerDIDRegistry  │  │ ← Approval check
│  └───────────┬───────────┘  │
│  ┌───────────▼───────────┐  │
│  │    Circuit Breaker     │  │ ← Per-method isolation
│  └───────────┬───────────┘  │
│  ┌───────────▼───────────┐  │
│  │    MultiResolver       │  │
│  │  ┌─────┐ ┌─────┐ ┌──┐│  │
│  │  │ web │ │ ion │ │key││  │ ← Method-specific resolvers
│  │  └─────┘ └─────┘ └──┘│  │
│  └───────────┬───────────┘  │
│  ┌───────────▼───────────┐  │
│  │   CachingResolver     │  │ ← TTL-based caching
│  └───────────────────────┘  │
└─────────────────────────────┘
```

### Cache Configuration

| Parameter       | Default | Description                   |
| --------------- | ------- | ----------------------------- |
| Cache TTL       | 5 min   | Time before re-resolution     |
| Max cache items | 1000    | LRU eviction after this limit |
| HTTP timeout    | 10 sec  | did:web resolution timeout    |
| ION timeout     | 30 sec  | did:ion resolution timeout    |

### Supported Key Types

| Key Type | Curve/Size | Format           |
| -------- | ---------- | ---------------- |
| OKP      | Ed25519    | JWK or multibase |
| EC       | P-256      | JWK or multibase |
| RSA      | 2048+      | JWK              |

---

## Token Verification Flow

```
Incoming JWT (partner-issued)
         │
         ▼
┌─────────────────────┐
│ Parse JWT (no verify)│
└────────┬────────────┘
         │ Extract iss claim
         ▼
┌─────────────────────┐     ┌──────────┐
│ Is issuer a DID?     │──No─▶│ Local    │
└────────┬────────────┘     │ Verify   │
         │ Yes              └──────────┘
         ▼
┌─────────────────────┐
│ Registry: IsApproved?│──No─▶ 403 Forbidden
└────────┬────────────┘
         │ Yes
         ▼
┌─────────────────────┐
│ Circuit breaker open?│──Yes─▶ 503 Service Unavailable
└────────┬────────────┘
         │ No
         ▼
┌─────────────────────┐
│ Resolve DID document │──Fail─▶ Record failure, 502
└────────┬────────────┘
         │ Success
         ▼
┌─────────────────────┐
│ Extract public keys  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Verify signature     │──Fail─▶ 401 Unauthorized
│ (try each key)       │
└────────┬────────────┘
         │ Success
         ▼
┌─────────────────────┐
│ Validate claims      │──Fail─▶ 401 (exp/iat/aud)
│ (exp, iat, aud)      │
└────────┬────────────┘
         │ Valid
         ▼
┌─────────────────────┐
│ Return result        │
│ (CrossOrg: true)     │
└─────────────────────┘
```

---

## Capability Attenuation

When a local issuer creates a token based on a partner's parent token, the
**attenuation rule** ensures the child token cannot exceed the parent's
scope:

### Rules

1. **Resource match:** Child resource must match or be more specific than
   parent (wildcards narrow only)
2. **Action subset:** Child actions must be a subset of parent actions
3. **Condition containment:** Child conditions must be at least as
   restrictive as parent conditions
4. **Cross-org flag:** Parent must explicitly allow cross-org delegation
   (`AllowCrossOrg: true`)

### Error Cases

| Error                     | Meaning                                       |
| ------------------------- | --------------------------------------------- |
| `ErrSubsetViolation`      | Child capabilities exceed parent scope        |
| `ErrEmptyParent`          | Parent token has no capabilities to attenuate |
| `ErrEmptyChild`           | Empty child capabilities are not meaningful   |
| `ErrCrossOrgNotPermitted` | Parent does not allow cross-org delegation    |

---

## Circuit Breaker Protection

DID resolution involves network calls that may fail. Circuit breakers
prevent cascading failures:

### Configuration

| Parameter            | Default | Description                          |
| -------------------- | ------- | ------------------------------------ |
| Failure threshold    | 5       | Consecutive failures to trip breaker |
| Cooldown duration    | 30 sec  | Time in open state before half-open  |
| Half-open max probes | 1       | Test requests allowed in half-open   |

### Isolation Strategy

Circuit breakers are **per-DID-method** (not per-DID). This means:

- A `did:web` resolution failure does not affect `did:ion` resolution
- A single partner's DNS failure may trip the `did:web` breaker,
  affecting all `did:web` partners temporarily
- `did:key` resolution is in-process and never trips a breaker

### State Transitions

```
CLOSED ──(5 failures)──▶ OPEN ──(30s cooldown)──▶ HALF-OPEN
   ▲                                                  │
   │                                                  │
   └──────────────(1 success)─────────────────────────┘
                                                      │
                                         (1 failure)──▶ OPEN
```

### Metrics

| Metric                                         | Type      | Labels                  |
| ---------------------------------------------- | --------- | ----------------------- |
| `euno_partner_did_circuit_breaker_state`       | Gauge     | `did_method`, `state`   |
| `euno_partner_did_resolution_total`            | Counter   | `did_method`, `outcome` |
| `euno_partner_did_resolution_duration_seconds` | Histogram | `did_method`            |

---

## Security Controls

### DID Document Validation

Before trusting keys from a DID document:

1. **Document ID match:** `document.id` must match the requested DID
2. **Key format validation:** Only supported key types (Ed25519, P-256, RSA)
3. **Size limits:** Resolution responses capped at 1 MB
4. **HTTPS enforcement:** `did:web` requires TLS (no plaintext HTTP)
5. **Timeout enforcement:** Resolution cannot take longer than configured
   timeout

### Compromise Response

If a partner's DID document or signing key is compromised:

| Step | Action                                        | Command                                              |
| ---- | --------------------------------------------- | ---------------------------------------------------- |
| 1    | Revoke partner DID                            | `POST /admin/partner-dids/{did}/revoke`              |
| 2    | Activate kill switch (if widespread)          | See [kill-switch runbook](./runbooks/kill-switch.md) |
| 3    | Revoke affected JTIs individually             | `POST /admin/revoke/{jti}`                           |
| 4    | Notify partner of compromise                  | Out-of-band communication                            |
| 5    | Partner rotates keys in DID document          | Partner responsibility                               |
| 6    | Re-register and re-approve after verification | Repeat Stage 2–3                                     |

### Audit Trail

All federation lifecycle events are captured in the tamper-evident audit
ledger:

| Event                  | Trigger                              |
| ---------------------- | ------------------------------------ |
| `partner-did.register` | New partner DID registered           |
| `partner-did.approve`  | Partner moved to approved status     |
| `partner-did.revoke`   | Partner trust revoked                |
| `partner-did.refresh`  | DID cache manually invalidated       |
| `enforce.partner`      | Partner token verified (per-request) |

---

## Operational Procedures

### Adding a New Partner

```bash
# 1. Verify the partner's DID document is accessible
curl -s https://partner.example.com/.well-known/did.json | jq .id

# 2. Register the partner
curl -X POST https://gateway.internal:3003/admin/partner-dids/ \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -d '{"did": "did:web:partner.example.com", "name": "Partner Corp"}'

# 3. Approve (separate operator recommended)
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:partner.example.com/approve \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"

# 4. Verify by testing a partner-issued token
curl -X POST https://gateway:3002/api/v1/enforce \
  -H "Authorization: ******"
```

### Rotating Partner Keys

No operator action required — DID cache auto-expires. For immediate
rotation:

```bash
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:partner.example.com/refresh \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

### Emergency Revocation

```bash
# Immediately revoke trust
curl -X POST https://gateway.internal:3003/admin/partner-dids/did:web:compromised.example.com/revoke \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"

# Verify revocation by listing and filtering for the DID
curl -s https://gateway.internal:3003/admin/partner-dids/ \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" | jq '.partners[] | select(.did=="did:web:compromised.example.com")'
```

---

## Monitoring and Alerting

### Recommended Alerts

| Alert                            | Condition                                                                                                   | Severity |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------- |
| Federation circuit breaker open  | `euno_partner_did_circuit_breaker_state{state="open"} > 0`                                                  | Warning  |
| High partner resolution failures | `rate(euno_partner_did_resolution_total{outcome="error"}[5m]) > 0.1`                                        | Warning  |
| Partner resolution latency spike | `histogram_quantile(0.99, sum by (le) (rate(euno_partner_did_resolution_duration_seconds_bucket[5m]))) > 5` | Warning  |
| Partner token rejection spike    | Increase in 401/403 for cross-org tokens                                                                    | Info     |

### Dashboard Panels

1. **Resolution success rate** — by DID method
2. **Circuit breaker state** — time series per method
3. **Partner token volume** — accepted vs rejected
4. **Cache hit ratio** — DID cache effectiveness
5. **Resolution latency** — P50/P95/P99 by method

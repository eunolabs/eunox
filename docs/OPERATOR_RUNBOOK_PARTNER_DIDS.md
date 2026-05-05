# Operator Runbook — Partner-DID Trust Registry

> **Audience**: Gateway operators and SREs  
> **Scope**: Managing the cross-org partner-DID trust registry via the admin API  
> **See also**: `docs/cross-organizations.md` for architecture context

---

## Overview

The **partner-DID registry** manages which external organisations' capability
issuers this gateway will accept tokens from.  Each partner is identified by a
[W3C DID](https://www.w3.org/TR/did-core/) and follows a lifecycle:

```
proposed  →  active  →  revoked
```

Activation requires a **two-eyes** (four-eyes) approval step: the operator
who proposes a DID cannot also approve it.  This prevents a single compromised
admin credential from silently adding a trusted issuer.

---

## Prerequisites

All calls must include:

| Header | Description |
|---|---|
| `X-Admin-Api-Key: <key>` | Admin API key (set via `ADMIN_API_KEY`) |
| `X-Admin-Operator: <id>` | Operator identity label for audit trail |

The `X-Admin-Operator` header is **not** a separate authentication boundary —
it is an opaque label recorded in the audit trail.  Security relies on
`X-Admin-Api-Key`.

---

## Lifecycle

### Step 1: Propose

Operator A submits the proposal.  The entry is created in `proposed` state and
is **not yet trusted**.

```bash
curl -X POST https://gateway-admin.internal/admin/partner-dids/proposals \
  -H "X-Admin-Api-Key: $ADMIN_KEY" \
  -H "X-Admin-Operator: alice@acmecorp.com" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:web:issuer.partner.example.com",
    "pinnedDocSha256": "a1b2c3...",
    "notes": "Acme Corp integration — ticket INC-4421"
  }'
```

**Response (201)**:
```json
{
  "entry": {
    "did": "did:web:issuer.partner.example.com",
    "status": "proposed",
    "proposer": "alice@acmecorp.com",
    "proposedAt": 1715000000000,
    "pinnedDocSha256": "a1b2c3...",
    "notes": "Acme Corp integration — ticket INC-4421"
  }
}
```

### Step 2: Approve (second operator)

Operator B (a **different** operator) approves.  The approver identity must
differ from the proposer — the gateway returns `HTTP 403 TWO_EYES_VIOLATION`
if the same identity approves their own proposal.

```bash
curl -X POST \
  "https://gateway-admin.internal/admin/partner-dids/proposals/did%3Aweb%3Aissuer.partner.example.com/approve" \
  -H "X-Admin-Api-Key: $ADMIN_KEY" \
  -H "X-Admin-Operator: bob@acmecorp.com"
```

**Response (200)**:
```json
{
  "entry": {
    "did": "did:web:issuer.partner.example.com",
    "status": "active",
    "proposer": "alice@acmecorp.com",
    "approver": "bob@acmecorp.com",
    "activatedAt": 1715000300000
  }
}
```

After this point the gateway will accept JWT capability tokens issued by
`did:web:issuer.partner.example.com`.

### Step 3: Revoke (incident response)

Revocation is a single-operator action (speed matters in an incident).

```bash
curl -X DELETE \
  "https://gateway-admin.internal/admin/partner-dids/did%3Aweb%3Aissuer.partner.example.com" \
  -H "X-Admin-Api-Key: $ADMIN_KEY" \
  -H "X-Admin-Operator: alice@acmecorp.com" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Key compromise suspected — INC-4499"}'
```

**Response (200)**:
```json
{
  "entry": {
    "did": "did:web:issuer.partner.example.com",
    "status": "revoked",
    "revokedAt": 1715000900000
  }
}
```

Existing JWTs are immediately rejected on the next request (the resolver cache
is flushed).

---

## Additional Operations

### List registry entries

```bash
# All entries
curl https://gateway-admin.internal/admin/partner-dids \
  -H "X-Admin-Api-Key: $ADMIN_KEY"

# Filter by status
curl "https://gateway-admin.internal/admin/partner-dids?status=active" \
  -H "X-Admin-Api-Key: $ADMIN_KEY"
```

Valid `status` values: `proposed`, `active`, `revoked`.

### Refresh resolver cache (key rotation)

When a partner rotates their signing key out-of-band without a corresponding
DID document update, or when a transient resolver outage has pinned a stale
negative-cache entry:

```bash
curl -X POST \
  "https://gateway-admin.internal/admin/partner-dids/did%3Aweb%3Aissuer.partner.example.com/refresh" \
  -H "X-Admin-Api-Key: $ADMIN_KEY" \
  -H "X-Admin-Operator: alice@acmecorp.com"
```

This is equivalent to the legacy `/admin/partner-did/refresh/:encodedDid`
endpoint (which is preserved for backwards compatibility).

---

## Pin Enforcement

### `pinnedDocSha256`

A JCS-SHA-256 (hex) fingerprint of the partner's DID document.  When set,
the resolver verifies that the live DID document matches the pin before
trusting any key from it.  Prevents MITM of the DID document endpoint.

Compute the pin:

```bash
# Fetch and fingerprint
curl -s https://issuer.partner.example.com/.well-known/did.json \
  | python3 -c "
import sys, json, hashlib
doc = json.load(sys.stdin)
canonical = json.dumps(doc, sort_keys=True, separators=(',',':'))
print(hashlib.sha256(canonical.encode()).hexdigest())
"
```

> **Note**: The gateway uses JCS (RFC 8785) key ordering, which is equivalent
> to `json.dumps(…, sort_keys=True)` for standard JSON objects.

### `pinnedVerificationKeys`

Per-VM JWK thumbprint pins (RFC 7638 SHA-256, base64url), keyed by `kid`.
When set, the resolver verifies the thumbprint of each verification method
before importing the key.

### `secondaryResolver`

Provides a second-source cross-check: the gateway fetches the DID document
from a separate URL (e.g. a ledger anchor) and verifies that both documents
agree.  Use when the primary DID resolver is not authoritative or is a
potential single point of compromise.

```json
{
  "secondaryResolver": {
    "method": "web",
    "url": "https://ledger.example.com/did/issuer.partner.example.com",
    "expectedSha256": "d4e5f6..."
  }
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PARTNER_DID_REQUIRE_PIN` | `false` | Require `pinnedDocSha256` on all proposals |
| `PARTNER_DID_REGISTRY_REQUIRED` | `false` | Reject `TRUSTED_PARTNER_DIDS` env-var (force registry workflow) |
| `PARTNER_DID_REGISTRY_KEY_PREFIX` | `euno:gateway:partner-did` | Redis key prefix for registry entries |
| `PARTNER_DID_CACHE_TTL_SECONDS` | `300` | Positive cache TTL |
| `PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS` | `30` | Negative cache TTL |

---

## Migrating from `TRUSTED_PARTNER_DIDS`

The legacy `TRUSTED_PARTNER_DIDS` env-var is preserved for backwards
compatibility but has no pin, no two-eyes approval, and no audit trail.

**Migration path**:

1. For each DID in `TRUSTED_PARTNER_DIDS`, add it to the registry via the
   proposal/approval workflow above (optionally with a pin).
2. Remove `TRUSTED_PARTNER_DIDS` from your configuration.
3. Set `PARTNER_DID_REGISTRY_REQUIRED=true` to prevent future regressions.

Until `TRUSTED_PARTNER_DIDS` is removed the gateway will emit a `WARN` log
at startup (escalated to `ERROR` in production non-single-replica deployments).

---

## Audit Trail

Every registry operation emits a structured audit event (log level in the
`audit` category):

| Event type | Level | When |
|---|---|---|
| `partner_did_proposed` | info | Proposal created |
| `partner_did_approved` | info | Entry activated |
| `partner_did_two_eyes_violation` | warn | Approver === proposer |
| `partner_did_revoked` | warn | Entry revoked |
| `partner_did_refreshed` | info | Cache flushed via admin API |
| `partner_did_pin_violation` | warn | DID document hash mismatch |
| `partner_did_kid_pin_violation` | warn | JWK thumbprint mismatch |
| `partner_did_secondary_resolver_mismatch` | warn | Secondary resolver disagreement |
| `partner_did_cache_miss` | info | DID document fetched |
| `partner_did_cache_refresh` | info | DID document cached successfully |

All events include `did` and the acting `operator` or `proposer`/`approver`
fields for correlation.

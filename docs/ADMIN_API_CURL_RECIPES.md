# Admin API curl recipes

Quick-reference for the tool-gateway admin API (served on `ADMIN_PORT`, default 3003).

Set these shell variables before running any command:

```bash
ADMIN_HOST=http://localhost:3003
ADMIN_KEY=your-admin-api-key          # omit if ADMIN_API_KEY is unset
TENANT=your-tenant-id                 # omit if ADMIN_TENANT_ID is unset
```

---

## Authentication

All mutating endpoints require `X-Admin-API-Key` when `ADMIN_API_KEY` is configured:

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/session/sess-123/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

---

## Idempotency keys

Add `Idempotency-Key` to any mutating request so safe retries return the original response
without re-executing the operation:

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/agent/agent-abc/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{}'
```

The same `Idempotency-Key` value MUST NOT be reused for a different endpoint.
The server caches responses for 24 hours and returns HTTP 422 if the key is reused
against a different path.

---

## Tenant scoping

When `ADMIN_TENANT_ID` is set on the gateway every mutating request MUST include a
`tenantId` field in the JSON body whose value matches the configured tenant. A
mismatch returns HTTP 403 `TENANT_MISMATCH`.

Per-entity kill/revive:

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/session/sess-123/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"
```

Global kill (cross-tenant impact — requires explicit acknowledgement):

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/global/activate" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\", \"acknowledgesCrossTenantImpact\": true}"
```

---

## Kill switch

### Status

```bash
curl "$ADMIN_HOST/admin/kill-switch/status" \
  -H "X-Admin-API-Key: $ADMIN_KEY"
```

### Activate global kill (blocks ALL traffic on this gateway instance)

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/global/activate" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: sre-on-call@example.com" \
  -H "Content-Type: application/json" \
  -d '{}'
```

With tenant scoping:

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/global/activate" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\", \"acknowledgesCrossTenantImpact\": true}"
```

### Deactivate global kill

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/global/deactivate" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Kill a specific session

```bash
SESSION_ID=sess-abc-123

curl -X POST "$ADMIN_HOST/admin/kill-switch/session/$SESSION_ID/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"   # omit tenantId if not tenant-scoped
```

### Revive a session

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/session/$SESSION_ID/revive" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"
```

### Kill a specific agent

```bash
AGENT_ID=agent-xyz-456

curl -X POST "$ADMIN_HOST/admin/kill-switch/agent/$AGENT_ID/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"
```

### Revive an agent

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/agent/$AGENT_ID/revive" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"
```

### Reset all kill switches

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/reset" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\", \"acknowledgesCrossTenantImpact\": true}"
```

---

## Token revocation

Revoke a specific capability token by JTI. `expiresAt` is optional (defaults to now+24h).

```bash
TOKEN_ID=jti-value-from-token

curl -X POST "$ADMIN_HOST/admin/revoke" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{
    \"tokenId\": \"$TOKEN_ID\",
    \"expiresAt\": $(date -d '+1 hour' +%s),
    \"tenantId\": \"$TENANT\"
  }"
```

---

## Revocation epoch (bulk revocation by issuance time)

Blocks all tokens from a given issuer whose `iat` is strictly before `issuedBefore`.
Use this for incident response when a signing key is believed compromised.

```bash
ISSUER="did:web:issuer.example.com"
# Block all tokens issued before right now:
CUTOFF=$(date +%s)

curl -X POST "$ADMIN_HOST/admin/revocation/epoch" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{
    \"issuer\": \"$ISSUER\",
    \"issuedBefore\": $CUTOFF,
    \"tenantId\": \"$TENANT\"
  }"
```

---

## Partner DID cache refresh

Force a fresh resolution of a partner DID's document (drops positive and negative
cache entries):

```bash
DID="did:web:partner.example.com"
ENCODED_DID=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DID")

curl -X POST "$ADMIN_HOST/admin/partner-dids/$ENCODED_DID/refresh" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

---

## Operator attribution

Attach `X-Admin-Operator` to any request so the executing operator's identity is
recorded in both the Winston audit chain and the OCSF Authorization events emitted
to the configured SIEM transport:

```bash
curl -X POST "$ADMIN_HOST/admin/kill-switch/agent/$AGENT_ID/kill" \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "X-Admin-Operator: alice@example.com" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d "{\"tenantId\": \"$TENANT\"}"
```

---

## OCSF audit events

When `AUDIT_OCSF_*` environment variables are configured the gateway emits OCSF
Authorization events (class_uid 3003) for every mutating admin action:

| Action                   | activity_id | severity_id |
|--------------------------|-------------|-------------|
| Kill session / agent     | 2 (Revoke)  | 4 (High)    |
| Revive session / agent   | 1 (Assign)  | 2 (Low)     |
| Global kill activate     | 2 (Revoke)  | 5 (Critical)|
| Global kill deactivate   | 1 (Assign)  | 2 (Low)     |
| Reset all                | 99 (Other)  | 5 (Critical)|
| Revoke token             | 2 (Revoke)  | 4 (High)    |
| Set revocation epoch     | 2 (Revoke)  | 4 (High)    |
| Cross-tenant rejection   | 2 (Revoke)  | 4 (High, Failure) |

The `unmapped.tenantId` field is populated in every OCSF event when
`ADMIN_TENANT_ID` is set so SIEM queries can filter by tenant without parsing
the `message` field.

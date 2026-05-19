# SOC2 Audit-Trail Export — OCSF Mapping and Auditor Procedure

> **Audience:** Security engineers preparing a SOC2 Type II audit package and
> auditors verifying euno gateway evidence records.
>
> **Related documents:**
> - [`docs/self-host.md`](../self-host.md) §12.5 — SOC2 audit-trail export configuration
> - [`docs/security/enterprise-federation-threat-model.md`](./enterprise-federation-threat-model.md) §"SOC2 export endpoint exposure"
> - [`docs/runbooks/ledger-hmac-rotation.md`](../runbooks/ledger-hmac-rotation.md) — HMAC secret rotation runbook

---

## 1. OCSF `class_uid` to SOC2 control mapping

Euno emits all audit evidence in the
[OCSF v1.1](https://schema.ocsf.io/1.1.0/) format. Every record returned
by `GET /api/v1/audit/export` is one of two OCSF event classes:

| OCSF class | `class_uid` | `category_uid` | Euno usage | Relevant SOC2 controls |
|---|---|---|---|---|
| **Authorization** | `3003` | `3` (IAM) | Capability token issuance, renewal, attenuation, revocation | CC6.1, CC6.2, CC6.3 |
| **API Activity** | `6003` | `6` (Application Activity) | Gateway tool-call enforcement (allow / deny) | CC6.6, CC7.1, CC7.2 |

### 1.1 Authorization events (class_uid 3003)

Emitted whenever the capability issuer grants or revokes a principal's right
to act. Maps to the SOC2 **CC6 — Logical and Physical Access Controls**
trust service criteria.

| `type_uid` | Activity | Example trigger | CC control |
|---|---|---|---|
| `300301` | Issuance allowed | OIDC token exchange succeeds; capability token minted | CC6.2 — provisions access |
| `300302` | Issuance denied | Rate limit exceeded or SCIM lookup blocked the request | CC6.2 — access requests logged |
| `300303` | Renewal allowed | `POST /api/v1/tokens/renew` succeeds | CC6.2 |
| `300304` | Renewal denied | Renewal blocked by kill-switch or expiry | CC6.2 |
| `300305` | Revocation | `POST /admin/revoke` processed | CC6.2 — access revocations logged |
| `300306` | Attenuation | Token attenuated to narrower scope | CC6.3 — least-privilege enforcement |

### 1.2 API Activity events (class_uid 6003)

Emitted by the gateway for every enforcement decision. Maps to the SOC2
**CC6** and **CC7 — System Operations** trust service criteria.

| `type_uid` | Activity | Example trigger | CC control |
|---|---|---|---|
| `600301` | Enforcement allowed | Tool call passes capability + policy check | CC6.6 |
| `600302` | Enforcement denied | Tool call blocked (missing capability, constraint violated, kill-switch) | CC6.6 |
| `600303` | Validation | Credential structure check (schema, signature, expiry) | CC7.1 |
| `600304` | Denial detail | Structured denial with `denialCode` and `conditionType` | CC7.2 |

### 1.3 Admin action events (class_uid 3003, subtype)

Mutating admin API calls (policy updates, partner DID registration, kill-switch
activation) also emit `Authorization (3003)` events with the actor set to the
admin credential. These map directly to CC6.1 (access policies) and CC6.3
(privilege controls).

---

## 2. Signed evidence record schema

Each record in the export bundle is a `SignedAuditEvidence` object:

```typescript
interface SignedAuditEvidence {
  // OCSF envelope
  class_uid:    3003 | 6003;
  category_uid: 3 | 6;
  type_uid:     number;            // class_uid * 100 + activity_id
  time:         number;            // Unix ms
  severity_id:  number;            // OCSF severity (0=Unknown, 1=Informational, …)
  status:       'Success' | 'Failure';
  metadata: {
    version: '1.1.0';
    product: { name: 'euno'; vendor_name: 'euno'; version: string };
    uid: string;                   // UUID, stable per event
  };

  // Euno extensions
  evidenceJwt:  string;            // JWT signed by gateway KMS key
  replicaId:    string;            // Gateway replica that wrote the record
  seq:          number;            // Monotonic per-replica sequence
  previousHash: string;            // SHA-256 hex of previous record in chain
  recordHash:   string;            // SHA-256 hex of this record's canonical JSON
}
```

The `evidenceJwt` payload contains the full OCSF record plus the
`previousHash`/`seq`/`replicaId` chain fields, signed with the gateway's
KMS key (same key pair as `SIGNING_PROVIDER`). The signature can be
verified offline using the issuer's published JWKS endpoint.

---

## 3. Export endpoint reference

### Request

```
GET /api/v1/audit/export
X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>
```

| Query parameter | Type | Description |
|---|---|---|
| `scope` | `soc2-cc6` \| `soc2-cc7` \| `all` | **`soc2-cc6`** returns only Authorization (3003) events. **`soc2-cc7`** returns only API Activity (6003) events. **`all`** returns both. Default `all`. |
| `cursor` | opaque string | Continuation cursor from previous response. Expires 24 h after issue. |
| `pageSize` | integer 1–1000 | Max records per page. Default 100. |
| `since` | ISO 8601 | Include records at or after this timestamp (only on the first page). |
| `until` | ISO 8601 | Include records before this timestamp (only on the first page). |

### Response

```json
{
  "cursor": "<opaque-base64>",
  "hasMore": true,
  "records": [ /* SignedAuditEvidence[] */ ],
  "verificationUri": "/.well-known/jwks.json"
}
```

`cursor` is `null` on the last page. `verificationUri` is the issuer JWKS
endpoint to use for offline signature verification (informational only —
use the JWKS URL you control, not the value returned by the API).

---

## 4. Offline evidence verification procedure

The following steps allow an auditor to verify evidence records without
trusting the live API:

### 4.1 Obtain the verification JWKS

```bash
# Fetch the issuer JWKS at the time of the audit period
curl -s https://issuer.example.com/.well-known/jwks.json -o jwks.json
```

For the most trustworthy verification, retrieve the JWKS from your own
artifact store if it was snapshotted at the time of signing.

### 4.2 Export evidence records

```bash
# Export CC6 records for Q1 2026
curl -s "https://gateway.example.com/api/v1/audit/export" \
  "?scope=soc2-cc6&since=2026-01-01T00:00:00Z&until=2026-04-01T00:00:00Z" \
  -H "X-Admin-Api-Key: <key>" \
  > records-page1.json

# Continue to next page if hasMore=true
CURSOR=$(jq -r .cursor records-page1.json)
curl -s "https://gateway.example.com/api/v1/audit/export?cursor=${CURSOR}" \
  -H "X-Admin-Api-Key: <key>" \
  > records-page2.json
```

### 4.3 Verify each `evidenceJwt` signature

```javascript
// verify-evidence.mjs
import { createLocalJWKSet, jwtVerify } from 'jose';
import { readFileSync } from 'fs';

const jwks = createLocalJWKSet(JSON.parse(readFileSync('jwks.json', 'utf8')));
const records = JSON.parse(readFileSync('records-page1.json', 'utf8')).records;

for (const record of records) {
  try {
    const { payload } = await jwtVerify(record.evidenceJwt, jwks);
    console.log('VALID', record.metadata?.uid, payload.seq);
  } catch (e) {
    console.error('INVALID', record.metadata?.uid, e.message);
    process.exitCode = 1;
  }
}
```

### 4.4 Verify chain continuity

Each record's `previousHash` must equal the SHA-256 of the previous
record's canonical JSON at the same `(replicaId, seq - 1)` position.
A gap or hash mismatch indicates a missing or forged record.

```javascript
import { createHash } from 'crypto';

// Sort records by (replicaId, seq) before verifying
const byReplica = {};
for (const r of records) {
  (byReplica[r.replicaId] ??= []).push(r);
}
for (const [rid, chain] of Object.entries(byReplica)) {
  chain.sort((a, b) => a.seq - b.seq);
  for (let i = 1; i < chain.length; i++) {
    const expectedPrev = createHash('sha256')
      .update(chain[i - 1].recordHash)
      .digest('hex');
    if (chain[i].previousHash !== expectedPrev) {
      console.error(`Chain break at replica=${rid} seq=${chain[i].seq}`);
      process.exitCode = 1;
    }
  }
}
console.log('Chain continuity verified for', Object.keys(byReplica).length, 'replicas');
```

### 4.5 Verify S3 Object-Lock anchors (cross-chain commitments)

If `AUDIT_LEDGER_S3_BUCKET` was configured, the cross-chain anchor has
periodically written Merkle-root commitments to S3. Retrieve the anchor
objects and verify that the Merkle root matches the computed root of the
exported records:

```bash
# List anchor objects for the audit period
aws s3 ls s3://my-audit-anchor-bucket/audit-anchor/ --recursive \
  | grep "2026-01\|2026-02\|2026-03"
```

See `docs/runbooks/ledger-hmac-rotation.md` for the cross-chain anchor
verification procedure and HMAC secret rotation instructions.

---

## 5. Auditor checklist

Provide this checklist to the external auditor along with the export bundle.

**For each `Authorization (3003)` record (CC6):**

- [ ] `evidenceJwt` signature verifies against the JWKS in the audit
      evidence package.
- [ ] `status` field is `Success` for every token that was issued to a
      principal still within your expected access roster.
- [ ] `status` is `Failure` for every token that was explicitly denied
      (rate limit, kill-switch, SCIM block). Failure records do not
      indicate a security event — they are the control working as intended.
- [ ] `seq` values are monotonically increasing per `replicaId`.
- [ ] No `seq` gaps exist within a `replicaId` sequence.

**For each `API Activity (6003)` record (CC7):**

- [ ] `evidenceJwt` signature verifies.
- [ ] `status: 'Failure'` records for enforcement denials include a
      `denialCode` and `conditionType` in the JWT payload. Review
      `denied` outcomes for any unexpected pattern (e.g. a single agent
      repeatedly denied on the same tool).
- [ ] Cross-chain anchor hashes in S3 match the Merkle roots computed
      from exported records (see §4.5 above).

**For the full period:**

- [ ] First and last `time` values in the export span the entire audit
      period without gaps (verify by re-running the export with the same
      `since`/`until` values and confirming equal record counts).
- [ ] `replicaId` values match the expected set of gateway replicas
      (cross-check with your infrastructure inventory).
- [ ] `AUDIT_LEDGER_RETENTION_DAYS` was set to at least 365 for SOC2
      Type II (verify via `GET /admin/usage` → `retentionDays`).

---

## 6. OCSF to SOC2 TSC quick reference

| SOC2 Trust Service Criteria | OCSF class(es) | `class_uid` |
|---|---|---|
| CC6.1 — Logical access security software | Authorization (admin policy changes) | 3003 |
| CC6.2 — Access provisioning and de-provisioning | Authorization (issuance / revocation) | 3003 |
| CC6.3 — Role-based access control | Authorization (attenuation, SCIM group enrichment) | 3003 |
| CC6.6 — Logical access restrictions for changes | API Activity (enforcement allow/deny) | 6003 |
| CC7.1 — Monitoring infrastructure | API Activity (validation) | 6003 |
| CC7.2 — Evaluation of security events | API Activity (denial detail, conditionType) | 6003 |

For the full OCSF v1.1 schema see <https://schema.ocsf.io/1.1.0/>.

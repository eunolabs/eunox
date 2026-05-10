# Stage 3 Design RFC — "The Gateway as Managed Boundary"

> **Status:** Ready for committee sign-off. The authoring work (Task 0) is complete.
> The gate condition — approved by ≥2 engineers + 1 security reviewer — must be
> met before any Task 2+ implementation begins. See §9 Review Checklist.
>
> **MVP anchors satisfied:** All decisions below cross-link to
> `docs/mvp.md` sections where they are required. The anchor tag and line
> range appear after each decision header.

---

## 0. Purpose and Scope

This document is the Stage 3 design freeze for `euno-platform`. It captures
every architectural decision that Tasks 2–12 must implement — and nothing else.
The goal is to make implementation choices explicit, reviewable, and traceable
before code is written, not discovered during code review.

**What this document decides:**

1. KMS provider selection for the managed minter signing key.
2. Postgres deployment shape (audit ledger + revocation list).
3. Redis deployment shape (kill-switch, call counters, revocation).
4. Hosted-vs-self-host feature matrix.
5. API-key format and storage scheme.
6. Enforcer wire protocol — the exact HTTP contract between `@euno/mcp` in
   `enforcer:"https://..."` mode and the gateway.

**What this document does not decide:**

- Implementation details covered by individual task specs in
  `docs/stage3executionplan.md`.
- UI design (Stage 3 is API-first; see §4 self-host matrix).
- Pricing (the sketch in `docs/mvp.md` §"Pricing & business model" stands as a
  guide, not a commitment).
- Stage 4 capability issuer integration (out of scope for this RFC).

---

## 1. KMS Provider — Minter Signing Key

> **MVP anchor:** `docs/mvp.md` §"Minter threat model" (lines 660–691) and
> §"Policy and audit schema parity" table row "Audit signer" (line 525).

### 1.1 Decision

**Primary (hosted service):** Azure Managed HSM, using the
[Azure Key Vault Managed HSM REST API][az-mhsm] with per-tenant EC P-256
(`EC-HSM`, `ES256`) non-exportable keys.

**Supported (self-host and hosted fallback):**

| Backend              | Protection level          | Config type in `@euno/common-core` (`public/packages/common/src/runtime.ts`) |
|----------------------|---------------------------|-------------------------------------------------------------------------------|
| Azure Managed HSM    | FIPS 140-2 Level 3 (HSM)  | `AzureKeyVaultConfig`                                                         |
| AWS CloudHSM via KMS | FIPS 140-2 Level 3 (HSM)  | `AWSKMSConfig`                                                                |
| GCP Cloud KMS (HSM)  | FIPS 140-2 Level 3 (HSM)  | `GCPCloudKMSConfig`                                                           |

All three config types already exist in
`public/packages/common/src/runtime.ts` and are implemented as signing
backends in the capability issuer. The minter's `KmsEvidenceSigner`
(stage3executionplan.md §Task 5) reuses the same abstractions.

The hosted service does **not** keep an online platform-wide signing key.
Each tenant receives a dedicated HSM signing key selected through the existing
`policyHash:audience` lookup for Azure (`AzureKeyVaultConfig.keysByPolicyHash`).
AWS fallback deployments must bind each tenant to a distinct configured KMS key
or a separate signer config per tenant; `AWSKMSConfig.grantTokensByPolicyHash` scopes sign
authorization but does not select a different key. GCP deployments currently lack
per-tenant key isolation through a shared signer config; hosted GCP fallback is
blocked until the Stage 3 execution plan's Task 11 adds context-keyed
`CryptoKeyVersion` selection, while self-hosters can run a separate signer
config per tenant. Platform-level credentials may provision or disable tenant
keys, but they do not sign capability tokens.

### 1.2 Justification

**Why Azure Managed HSM as the primary:**

The existing Kubernetes deployment (`k8s/README.md`) targets Azure Container
Registry and Azure Key Vault. Azure Managed HSM provides:

- **Non-exportability enforced at the HSM boundary**: keys are created as
  `EC-HSM` P-256 keys with `key_ops` limited to `sign` and `verify`. Managed
  HSM does not expose private key material for HSM-protected keys, and download
  attempts fail with `KeyNotExportable` regardless of caller RBAC. This is
  enforced by the Managed HSM boundary, not merely by minter IAM policy. This
  satisfies the MVP's requirement: "verify
  non-exportability is enforced at the HSM level, not just by policy
  configuration" (`docs/mvp.md` §["Minter threat model"](mvp.md#minter-threat-model-required-before-stage-3-ships)).
- **Per-tenant key isolation**: Azure MHSM supports per-tenant key assignment
  via key names and role-based access control. The
  `AzureKeyVaultConfig.keysByPolicyHash` map (already wired in `runtime.ts`
  lines 456–490) enables composite `(policyHash, audience)` key selection
  without additional infrastructure.
- **Audit log**: every HSM operation (sign, decrypt, key creation) is written to
  Azure Monitor / Log Analytics. This is the external witness independent of the
  minter's own audit trail.

**Why not a single cloud:**

The three KMS backends are already implemented identically against the
`TokenSigner` / `EvidenceSigner` seams. Self-hosters running AWS or GCP should
not be blocked by a cloud-specific choice in the hosted service. The
`KmsEvidenceSigner` (Task 5) selects the backend from a `KMS_PROVIDER`
environment variable (`azure` | `aws` | `gcp`).

### 1.3 Non-exportability verification procedure

During provisioning, the operator MUST verify that the key is HSM-backed,
restricted to signing operations, and non-exportable:

```bash
az keyvault key create \
  --hsm-name <mhsm-name> \
  --name euno-minter-tenant-<tenant-id> \
  --kty EC-HSM \
  --curve P-256 \
  --ops sign verify \
  --protection hsm

az keyvault key show \
  --hsm-name <mhsm-name> \
  --name euno-minter-tenant-<tenant-id> \
  --query "{kty:key.kty, crv:key.crv, ops:key.keyOps}"
# Expected: kty=EC-HSM, crv=P-256, ops=[sign, verify] with no export/wrap operation.

# Azure Managed HSM — HSM key is non-exportable iff this returns KeyNotExportable.
az keyvault key download \
  --hsm-name <mhsm-name> \
  --name euno-minter-tenant-<tenant-id> \
  --file /tmp/export-test.pem \
  --encoding PEM
# Expected: "(KeyNotExportable) Key is not exportable"
```

This check is part of the provisioning runbook (`docs/runbooks/provision-mhsm.md`,
to be created in Task 5) and is also asserted by the `scripts/verify-kms-posture.ts`
script (to be created in Task 5).

### 1.4 Key rotation

Key rotation is addressed in the minter threat model
(`docs/security/minter-threat-model.md`, Task 1). The design seam here is that
the `JWTTokenVerifier` in `tool-gateway/src/verifier.ts` already resolves keys
by `kid` from a JWKS endpoint (`JwksKeySource`, `runtime.ts:JwksKeySource`).
Key rotation therefore requires:

1. Generate a new tenant key version in the HSM.
2. Publish the new `kid` → public key mapping to the JWKS endpoint.
3. Update the minter to use the new `kid` for new tokens.
4. Existing tokens are valid until their `exp`; if rotation is due to
   compromise, the existing revocation list covers invalidation by `jti`, and
   the tenant-scoped kill switch is activated until revocation replay completes.
5. Old key version is disabled in the HSM (not deleted — needed for signature
   verification during the token TTL window).

---

## 2. Postgres Deployment Shape

> **MVP anchor:** `docs/mvp.md` §"Stage 3: What ships" (lines 641–658),
> specifically "Persistent audit log" (line 648) and the distributed state
> requirement (lines 653–658).

### 2.1 Audit Ledger

**Implementation:** `PostgresLedgerBackend` (or the lock-free
`PerReplicaPostgresLedgerBackend` recommended in `docs/mvp.md` line 648) — both
implemented in `euno-platform/packages/common-infra/src/ledger-signer.ts`.

Stage 3 uses the **existing table schema** managed by
`PostgresLedgerBackend.migrate()` (see `ledger-signer.ts` lines 730–742 for
the authoritative `CREATE TABLE` statement). The schema is reproduced here for
reference; if the implementation diverges, `ledger-signer.ts` is the source of
truth:

```sql
-- Table: euno_audit_ledger  (default; configurable via PostgresLedgerOptions.table)
-- Managed by PostgresLedgerBackend.migrate() in ledger-signer.ts lines 730–742
CREATE TABLE euno_audit_ledger (
  seq           BIGINT PRIMARY KEY,       -- application-assigned under advisory lock
  record_id     TEXT NOT NULL UNIQUE,     -- UUID from AuditEvidence.id
  replica_id    TEXT NOT NULL,            -- pod / process identity
  previous_hash TEXT NOT NULL,            -- SHA-256 hex of the preceding record
  record_hash   TEXT NOT NULL,            -- SHA-256 hex of this record's payload
  payload       JSONB NOT NULL,           -- full SignedAuditEvidence (OCSF API Activity)
  row_hmac      BYTEA NOT NULL,           -- HMAC-SHA256(hmacSecret, seq||":"||…)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_euno_audit_ledger_created_at ON euno_audit_ledger (created_at);
```

The `PerReplicaPostgresLedgerBackend` uses `euno_audit_ledger_v2` (configurable
via `PerReplicaPostgresLedgerOptions.table`) with an additional `local_seq`
column for per-replica sequence tracking — no change in Stage 3.

**Task 7 query index:** For the audit query API, add a derived index on the
tenant and agent identifiers embedded in the payload:

```sql
-- Added by the Stage 3 bootstrap migration (not created by the existing backend)
CREATE INDEX IF NOT EXISTS idx_euno_audit_ledger_tenant_agent
  ON euno_audit_ledger ((payload->>'tenantId'), (payload->>'agentId'));
```

**Multi-replica serialization:** Already implemented. `PostgresLedgerBackend`
acquires `pg_advisory_xact_lock($1)` (PostgreSQL advisory lock function) where
the lock ID is the TypeScript `BigInt` value `BigInt('0x455534004C454447')` —
the hex encoding of "EU4LEDG" in ASCII. This is the default configured at
`ledger-signer.ts` line 683 (`options.advisoryLockId ?? BigInt('0x455534004C454447')`).
The `BigInt` is converted to a `string` when passed to the pg driver, which
maps it to PostgreSQL `bigint`. This is stable across deploys and does not
require any Stage-3 change.

**Retention:** 90-day default for Cloud Team tier; configurable via
`AUDIT_RETENTION_DAYS` env var. A background job (cron, or pg-cron) trims rows
older than the retention window. Rows are append-only until the trim job; the
trim job is itself audited.

**External witness (optional):** `PostgresLedgerBackend` already supports
putting a Merkle root of every N rows to an S3 Object-Lock bucket via
`PostgresLedgerOptions.s3` (constructed in code; there is no automatic env-var
wiring for the S3 config). This is off by default in Stage 3; the seam remains
in place per `docs/mvp.md` line 649.

### 2.2 Revocation Store

**Implementation:** `RedisRevocationStore` (primary, low-latency) +
`PostgresRevocationBackend` (durable truth, dual-write).

The Redis store (`tool-gateway/src/revocation-store.ts`) already handles
in-memory TTL pruning and Redis-backed persistence. Stage 3 adds a
Postgres backend for durability across Redis flushes:

```sql
CREATE TABLE revoked_tokens (
  jti          TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  expires_at   BIGINT NOT NULL,   -- unix seconds (natural token expiry)
  revoked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_by   TEXT              -- admin identity (audit)
);

CREATE INDEX revoked_tokens_expires_at_idx ON revoked_tokens (expires_at);
```

**Sync strategy (best-effort dual-write):**
- Every `revoke(jti, expiresAt)` call writes to Redis first, then to Postgres.
  These are two independent writes; there is no distributed transaction between
  them. The consistency guarantee is:
  - **Redis write succeeds, Postgres write fails:** The revocation is immediately
    effective in Redis (all replicas see it within pub/sub delivery time). A
    background reconciler re-drives the Postgres write from Redis at startup and
    on a periodic timer (every 30 s by default). After Redis connectivity is
    restored and the client becomes ready again following a connection loss, the
    implementation may also trigger an immediate reconciler run as an optimization.
    The 30-second bound comes from the periodic reconciler timer, so a
    Postgres-write failure is durably captured within one reconciler interval.
    Risk window: if Redis is flushed AND the reconciler has not yet written the
    row to Postgres, the revocation is lost. Mitigated by `redis-kill-switch.ts`'s
    periodic Postgres refresh and the 30-second reconciler bound.
  - **Postgres write succeeds, Redis write fails:** The revocation is durable.
    The next periodic Redis refresh (every 30 s by default) loads the Postgres
    row, so the revocation takes effect within one refresh interval.
- On Redis cold-start (flush or new replica), `PostgresRevocationBackend`
  replays all non-expired rows into Redis via `SETEX` calls in batches of 1000.
- TTL-expired rows in Postgres are pruned weekly by a trim job.

### 2.3 Kill-Switch Persistence

**Implementation:** `PostgresKillSwitchBackend` — already implemented in
`euno-platform/packages/common-infra/src/redis-kill-switch.ts` via the
`KillSwitchPersistenceBackend` seam.

The existing table schema is preserved unchanged in Stage 3. Row *presence* is
the kill state — revive/reset deletes the row, keeping reads simple:

```sql
-- Table: euno_kill_switch_entries  (default; configurable via constructor options.table)
-- Managed by PostgresKillSwitchBackend.migrate() in redis-kill-switch.ts
CREATE TABLE euno_kill_switch_entries (
  entry_type TEXT NOT NULL,  -- 'global' | 'session' | 'agent'
  entry_id   TEXT NOT NULL,  -- '' for global; session/agent ID otherwise
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (entry_type, entry_id)
);
```

- **Active kill** → row is present.
- **Revived / reset** → row is deleted (`DELETE FROM … WHERE entry_type = $1 AND entry_id = $2`).

The table deliberately has no `revived_at` or `tenant_id` columns. Tenancy
isolation at the kill-switch level is enforced by gateway-layer routing (each
tenant's gateway pods share a single Redis cluster and Postgres schema, but the
admin API is auth-scoped per tenant). If per-tenant audit trails for kill
operations are needed, the admin API logs each activation in the main audit
table (§2.1) — not in `euno_kill_switch_entries`.

**Sync strategy (per `redis-kill-switch.ts` design):** Redis is the read path
(synchronous, in-process cache). Postgres is the write-through durability layer.
On Redis cold-start, `load()` replays all rows from Postgres into the in-process
cache, and the manager seeds the Redis keys from there. This satisfies
`docs/stage3executionplan.md` §Task 6: "Redis cold-start, replay from Postgres."

### 2.4 Deployment topology

| Component                     | Instance count  | HA mechanism           |
|-------------------------------|-----------------|------------------------|
| Postgres (audit, revocation)  | 1 primary       | Cloud-managed HA replica (Azure Flexible Server / Cloud SQL / RDS) |
| Postgres (kill-switch)        | Same cluster    | Shared with audit DB, separate schema |
| Connection pool               | PgBouncer sidecar | One per gateway pod |

**Credentials:** Postgres credentials are separate from the gateway's own
API-key database (different Postgres user with minimal grants). The minter's
mint-audit table uses a third credential (per MVP §"Audit trail" line 679:
"separate credentials from the minter itself").

---

## 3. Redis Deployment Shape

> **MVP anchor:** `docs/mvp.md` §"Stage 3: What ships" (line 653–654):
> "Redis-backed distributed state for multi-process deployments."
> `docs/stage3executionplan.md` §Task 4 (call counters) and §Task 6
> (kill-switch).

### 3.1 Topology

**Single Redis Cluster** shared by all gateway replicas. Each store owns its
own key namespace, configurable via a dedicated environment variable:

| Purpose                 | Key pattern (default prefix)                        | Env var override             | TTL behaviour         |
|-------------------------|-----------------------------------------------------|------------------------------|-----------------------|
| Kill-switch global      | `killswitch:global` (default `killswitch:`)         | `KILL_SWITCH_KEY_PREFIX`     | No TTL (operator-revive) |
| Kill-switch sessions    | `killswitch:killed_sessions` (SET)                  | `KILL_SWITCH_KEY_PREFIX`     | No TTL                |
| Kill-switch agents      | `killswitch:killed_agents` (SET)                    | `KILL_SWITCH_KEY_PREFIX`     | No TTL                |
| Kill-switch pub/sub     | `killswitch:events` (channel)                       | `KILL_SWITCH_KEY_PREFIX`     | N/A                   |
| Call counters           | `capcall:<key>` (default `capcall:`)                | `CALL_COUNTER_KEY_PREFIX`    | Set to window boundary |
| Revocation list         | `revoked:<jti>` (default `revoked:`)                | `REVOCATION_KEY_PREFIX`      | Token `exp` − now     |
| Revocation epoch        | `epoch:<issuerId>` (default `epoch:`)               | `REVOCATION_EPOCH_KEY_PREFIX`| No TTL                |
| DPoP replay             | `dpopjti:<jti>` (default `dpopjti:`)                | `DPOP_REPLAY_KEY_PREFIX`     | DPoP proof `exp` + clock skew |

Each prefix default is defined in the corresponding module (see
`common-infra/src/redis-kill-switch.ts`, `common-infra/src/call-counter-store.ts`,
`tool-gateway/src/revocation-store.ts`, `public/packages/common/src/dpop.ts`).
There is **no global `REDIS_KEY_PREFIX`** environment variable — each store's
prefix is independently configurable to allow sharing a Redis instance across
multiple environments without key collisions.

### 3.2 Circuit-breaker policy

The `RedisCircuitBreaker` (`common-infra/src/redis-circuit-breaker.ts`) is
wired to all three Redis-dependent stores. Per `docs/stage3executionplan.md`
§Task 4, the circuit-open behaviour must be explicit — not silently defaulted:

| Store                | `REDIS_CIRCUIT_OPEN_MODE` value | Effect when open                |
|----------------------|---------------------------------|---------------------------------|
| CallCounterStore     | `fail-closed`                   | Treat counter as exceeded → deny |
| CallCounterStore     | `fail-open`                     | Allow (local fallback counter used) |
| RevocationStore      | `fail-closed`                   | Treat token as revoked → 401   |
| RevocationStore      | `fail-open-503`                 | Return 503 (caller retries)     |
| KillSwitchManager    | n/a                             | Reads always from local cache; writes surface Redis error to admin API |

**Default behaviour:** The hosted service hard-codes `fail-closed` and does not
expose `REDIS_CIRCUIT_OPEN_MODE` to tenants — a degraded Redis must not silently
widen the enforcement posture. Self-hosters MUST explicitly set
`REDIS_CIRCUIT_OPEN_MODE` in their deployment config; the gateway logs an
error-level warning on startup when the variable is absent and defaults to
`fail-closed` so a misconfigured self-host does not accidentally fail open.
Self-hosters who want `fail-open` (e.g. to accept per-replica counter
inaccuracy during Redis maintenance windows) must explicitly set the value.

### 3.3 Redis credentials

Redis is reached via `REDIS_URL` (`redis://` or `rediss://`). For the hosted
service, TLS (`rediss://`) is mandatory. The URL is injected at runtime from the
cloud secret manager (Azure Key Vault secret / AWS Secrets Manager / GCP Secret
Manager) — not baked into the container image.

---

## 4. Hosted-vs-Self-Host Feature Matrix

> **MVP anchor:** `docs/mvp.md` §"Pricing & business model sketch" (lines
> 791–808) and §"Stage 3: What ships" (lines 643–658).

The matrix below maps the pricing tiers from `docs/mvp.md` to concrete
technical features that gate the tier. It is the definitive reference for which
capabilities land in which tier.

| Feature                                  | OSS (`@euno/mcp` only) | Self-Host (BSL image) | Cloud Free | Cloud Team | Cloud Enterprise |
|------------------------------------------|:------:|:------:|:------:|:------:|:------:|
| Local enforcement (in-process PDP)       | ✅ | ✅ | ✅ | ✅ | ✅ |
| stdio + HTTP proxy transports            | ✅ | ✅ | ✅ | ✅ | ✅ |
| All condition types (Stage 1–2)          | ✅ | ✅ | ✅ | ✅ | ✅ |
| Local HMAC audit log                     | ✅ | ✅ | ✅ | ✅ | ✅ |
| `euno-mcp validate-token` / `stats`      | ✅ | ✅ | ✅ | ✅ | ✅ |
| Remote enforcer mode (`enforcer: url`)   | — | ✅ | ✅ | ✅ | ✅ |
| KMS-backed audit signer                  | — | ✅ (BYO KMS) | ✅ | ✅ | ✅ |
| Redis call-counter store                 | — | ✅ (BYO Redis) | ✅ | ✅ | ✅ |
| Redis kill-switch manager                | — | ✅ (BYO Redis) | ✅ | ✅ | ✅ |
| Postgres audit ledger                    | — | ✅ (BYO Postgres) | ✅ | ✅ | ✅ |
| Audit query API (Task 7)                 | — | ✅ | 7-day | 90-day | Configurable |
| Kill-switch admin API                    | — | ✅ | Session-scoped | ✅ | ✅ |
| API-key minter façade                    | — | — | ✅ | ✅ | ✅ |
| SSO via OIDC                             | — | — | — | ✅ | ✅ |
| Evidence export (signed OCSF)            | — | — | — | — | ✅ |
| On-prem signing key (BYO HSM)            | — | ✅ | — | — | ✅ |
| SOC2 attestation docs                    | — | — | — | — | ✅ |
| Cross-chain audit anchor (Stage 5)       | — | — | — | — | ✅ |

**Self-host bundle boundary:** The self-host Docker image ships all gateway
code (BSL 1.1). The API-key minter is **not** in the self-host bundle initially
(per `docs/mvp.md` line 646: "not part of the self-host bundle initially —
that decision can flip later based on demand"). Self-hosters must issue their
own JWT capability tokens via `euno-platform/packages/capability-issuer` or a
compatible issuer.

---

## 5. API-Key Format and Storage Scheme

> **MVP anchor:** `docs/mvp.md` §"Stage 3: The Stage 3 upgrade bridge" (lines
> 609–638) and `docs/stage3executionplan.md` §Task 0 (api-key format and
> storage scheme), §Task 10 (minter service skeleton).

### 5.1 Key format

```
sk-<prefix8>.<secret48>
│    │         │
│    │         └── 48 chars ≈ 285 bits of random, base58 encoded
│    │                        Provides > 2^284 guessing resistance
│    └── 8 random base58 chars, unique per key
│         Stored in plaintext in api_keys.prefix and indexed for O(1) DB lookup
│         without scanning digests
└── Literal prefix — identifies the token type in logs and error messages
```

**Concrete example:**

```
sk-x7Kp9mRq.bL3nYv2wQsT6dFhG8jZcAiUeR1oP4mKxN5yW7uE0tBpV9gC
```

**Character set:** Bitcoin-style Base58 (`[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]` —
the standard Bitcoin Base58 alphabet, which excludes `0`, `O`, `I`, `l` to
eliminate visually ambiguous characters). Total length: 3 (`sk-`) + 8 + 1
(`.`) + 48 = 60 characters. Fits in a single HTTP header field without line
wrapping.

**Why not UUID format:** UUIDs expose 122 bits of entropy. The `sk-<p8>.<s48>`
scheme exposes ~285 bits in base58 (log₂(58^48) ≈ 285), making brute-force
impractical even against the stored verifier. The 8-character prefix is random
lookup metadata, not part of the secret; it is stored and logged in plaintext.
Uniqueness is enforced by the `api_keys.prefix` unique constraint. If generation
collides, issuance discards the key and generates a new prefix/secret pair.

### 5.2 Storage schema

```sql
-- Table: api_keys
-- One row per issued key. Raw credentials are returned once and never stored.
CREATE TABLE api_keys (
  id           BIGSERIAL PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  prefix       TEXT NOT NULL UNIQUE,        -- 8-char base58 prefix (plaintext)
  key_digest   TEXT NOT NULL,               -- base64url(HMAC-SHA256 keyed by pepper over secret)
  hmac_key_version TEXT NOT NULL,           -- pepper version used for key_digest
  policy_id    TEXT NOT NULL,               -- FK → capability_policies.id
  scopes       TEXT[] NOT NULL DEFAULT '{}', -- ['enforce', 'admin', 'audit']
  label        TEXT,                        -- human-readable name set by admin
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX api_keys_prefix_idx ON api_keys (prefix);
CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id) WHERE revoked_at IS NULL;

-- Issuance audit (separate credentials from the minter, per MVP line 679)
CREATE TABLE api_key_issuance_log (
  id           BIGSERIAL PRIMARY KEY,
  key_prefix   TEXT NOT NULL,
  tenant_id    TEXT NOT NULL,
  issued_by    TEXT NOT NULL,               -- admin user or service identity
  policy_id    TEXT NOT NULL,
  policy_hash  TEXT NOT NULL,               -- SHA-256 of policy at issuance time
  issued_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 5.3 Key derivation and verification

**Verifier algorithm:** HMAC-SHA-256 over the 48-character secret, keyed by a
pepper stored outside the API-key database (cloud KMS/secret manager, never in
the DB). Store `base64url(HMAC-SHA256(pepper, secret))` in `key_digest` plus the
pepper `hmac_key_version` used to compute it.

**Rationale:** API keys are high-entropy random bearer credentials, not
human-memorable passwords. A memory-hard password KDF adds material online DoS
risk while providing little additional protection against offline guessing of a
~285-bit secret. A keyed digest means a DB-only compromise cannot validate
candidate keys; an attacker needs both the DB and the external pepper. The
digest comparison is performed with `crypto.timingSafeEqual` over decoded
32-byte digests. The process initializes one fixed 32-byte random dummy digest
at startup. If the stored digest is malformed or the decoded length is not
32 bytes, the verifier compares against that dummy digest and then rejects; it
must not pad attacker-controlled values or skip comparison in a way that creates
a timing oracle.

**Pepper storage and rotation:** Pepper material is stored in the cloud secret
manager or KMS-backed configuration store, not in Postgres and not in the
container image. The verifier keeps a small allowlist of active
`hmac_key_version` values during rotation. New keys are written with the newest
version; existing keys continue to verify with their recorded version until
they are reissued or the old pepper is retired. Retiring a pepper requires
revoking or reissuing every API key whose row still references that version.
At most two pepper versions may be active concurrently (`current` and
`previous`); an emergency overlap of three versions is allowed for no more than
24 hours.

**Verification flow:**

1. Split incoming key at `.` → `(prefix, secret)`.
2. PostgreSQL parameterized query fetches both the requested prefix and one reserved
   dummy row (constant `API_KEY_DUMMY_PREFIX = '__dummy__'`, outside the Base58 key
   format because `_` is not in the Base58 alphabet) so every lookup performs a real heap
   fetch even on requested-prefix misses. In PostgreSQL, `(prefix = $1)` evaluates to a
   boolean; `DESC` sorts `true` before `false`, returning the real row when it exists and
   falling back to the dummy row otherwise:
   `SELECT prefix, key_digest, hmac_key_version, tenant_id, policy_id, scopes, revoked_at, expires_at
   FROM api_keys WHERE prefix IN ($1, $2) ORDER BY (prefix = $1) DESC LIMIT 1`,
   where `$2` is `API_KEY_DUMMY_PREFIX`.
3. Run HMAC computation and constant-time comparison before any rejection is
   returned, including for missing, revoked, or expired rows. If the requested
   prefix did not select a real row, use the returned dummy row and fixed dummy
   digest so prefix enumeration does not get a cheaper timing path. During
   pepper rotation, both real-row and dummy-row paths iterate over all active
   pepper versions; only the digest for the row's recorded `hmac_key_version`
   can pass.
4. If no row, mismatch, inactive pepper version, `revoked_at IS NOT NULL`, or
   `expires_at < now()`: return 401.
5. Update `last_used_at` asynchronously (fire-and-forget; do not add latency to
   enforcement path).
6. Return `(tenant_id, policy_id, scopes)` to the caller.

**Key issuance:** POST `/admin/v1/keys` (admin scope required). The raw secret
is returned once in the response body and never stored. The caller MUST treat
the response as a one-time credential delivery.

---

## 6. Enforcer Wire Protocol

> **MVP anchor:** `docs/mvp.md` §"Stage 3: The Stage 3 upgrade bridge" (lines
> 609–638): "the upgrade really is one config change" and the `enforcer:
> "https://..."` config shape.
> `docs/stage3executionplan.md` §Task 2 (enforcer mode dispatch) and §Task 9
> (hosted enforcement HTTP contract).

This section defines the exact request/response contract between `@euno/mcp`
running in remote-enforcer mode and the hosted enforcement endpoint.

For Cloud, that public endpoint is the API-key minter façade in front of the
internal `tool-gateway`. The façade verifies the API key, mints a short-lived
tenant-scoped capability JWT, forwards the enforcement request to the internal
gateway using that JWT, and returns the gateway's decision. The internal
gateway never treats API keys as capability tokens. Self-host/BYO gateway
operators that do not run the managed minter may expose the same request shape
but authenticate it with their own issuer's JWT instead of an `sk-...` key.

### 6.1 Configuration

The `@euno/mcp` config uses the flat form promised in `docs/mvp.md` (line 633)
as the canonical user-facing shape. `@euno/mcp` also accepts the equivalent
nested-object form as an alternative for operators who prefer explicit
field grouping. Both forms are equivalent; the flat form is the one shown in
user-facing documentation.

```jsonc
// Stage 1–2: local enforcement (default — no change required)
{ "enforcer": "local" }

// Stage 3: remote gateway — flat form (MVP doc canonical shape, docs/mvp.md line 633)
{
  "enforcer": "https://gateway.euno.example",
  "apiKey": "sk-x7Kp9mRq.bL3nYv2wQsT6dFhG8jZcAiUeR1oP4mKxN5yW7uE0tBpV9gC",
  "enforcerTimeoutMs": 5000
}

// Stage 3: remote gateway — nested-object form (equivalent, optional)
{
  "enforcer": {
    "url": "https://gateway.euno.example",
    "apiKey": "sk-x7Kp9mRq.bL3nYv2wQsT6dFhG8jZcAiUeR1oP4mKxN5yW7uE0tBpV9gC",
    "timeoutMs": 5000
  }
}
```

**Parsing rule:** When `enforcer` is a `string` and the string is not `"local"`,
it is treated as the gateway URL (flat form); `apiKey` is read from the sibling
field. When `enforcer` is an `object`, it is the nested form. The `local` string
triggers the existing in-process path unchanged.

When the remote form is active, the proxy skips constructing
`FilePolicySource`, `LocalHmacSigner`, `InMemoryCallCounterStore`, and the
in-process kill-switch manager (per `stage3executionplan.md` §Task 2). The
gateway enforcer returns both the allow/deny decision and any obligations
(redaction, annotation); the proxy applies obligations locally.

### 6.2 Endpoint

```
POST /api/v1/enforce
Host: gateway.euno.example
Authorization: Bearer sk-<prefix8>.<secret48>
Content-Type: application/json
Accept: application/json
X-Euno-Protocol-Version: 1
X-Request-Id: <uuid>   (optional; reflected in response)
```

### 6.3 Request body

```typescript
interface EnforceRequest {
  /**
   * Opaque session identifier from the MCP initialize handshake.
   * For stdio: the proxy process lifetime ID.
   * For HTTP: the initialize→shutdown cycle ID.
   * Used by the gateway to apply session-scoped kill-switch checks.
   */
  sessionId: string;

  /**
   * The MCP tool name exactly as sent in tools/call.
   * Matched against the policy's requiredCapabilities[].resource
   * using the same matchesResource() logic as the local PDP.
   */
  toolName: string;

  /**
   * The raw arguments object from the tools/call request.
   * The gateway runs argumentSchema validation (if present in the policy)
   * and extracts recipients / operations for condition evaluation.
   * MUST be JSON-serialisable; binary values should be base64-encoded strings.
   */
  arguments: Record<string, unknown>;

  /** Per-request context for condition evaluation. */
  context: EnforceRequestContext;
}

interface EnforceRequestContext {
  /**
   * Source IP of the MCP client, stripped of IPv4-mapped prefix.
   * In Cloud, this value is overwritten by the edge/minter from the observed
   * connection or trusted forwarding headers; caller-supplied sourceIp is not
   * trusted for ipRange decisions. Self-hosters may accept this field only from
   * trusted in-network proxies. Omit for stdio-transport requests (ipRange
   * conditions will deny with MISSING_CONTEXT).
   */
  sourceIp?: string;

  /**
   * Recipients extracted from the tool arguments (to/recipients/cc/bcc fields).
   * The gateway uses the same extraction logic as the local recipientDomain handler.
   * MAY be omitted if the tool call has no recipient semantics.
   */
  recipients?: string[];

  /**
   * Wall-clock time of the request in ISO-8601 format.
   * When omitted, the gateway uses its own clock.
   * Providing this allows the gateway to record the client's observed time
   * for audit purposes. It is NOT used to evaluate `timeWindow` conditions
   * on the hosted (Cloud) service — the gateway always uses its own
   * authoritative clock for policy enforcement to prevent clients from
   * manipulating time-based access decisions. Self-hosters MAY choose to
   * honour this field for `timeWindow` evaluation, but MUST document the
   * trust assumption explicitly.
   * Difference > 60 s is rejected (clock-skew guard).
   */
  now?: string;
}
```

**Request size limit:** 512 KiB. Arguments exceeding this limit receive a 413
response with error code `REQUEST_TOO_LARGE`.

### 6.4 Response body

```typescript
interface EnforceResponse {
  /**
   * Echoes X-Request-Id if provided by the caller, or a gateway-generated UUID.
   * Included in the gateway's own audit log for correlation.
   */
  requestId: string;

  /** The enforcement decision. */
  decision: 'allow' | 'deny';

  /**
   * Obligations the caller MUST apply before returning the upstream response
   * to the MCP client. An empty array means no post-processing required.
   * Obligations are applied in order.
   * Only present when decision is 'allow'.
   */
  obligations?: Obligation[];

  /**
   * Denial details. Only present when decision is 'deny'.
   */
  denial?: DenialInfo;

  /**
   * ISO-8601 timestamp of this decision, from the gateway's clock.
   * Callers may use this to populate the audit log's activity time.
   */
  decidedAt: string;
}

type Obligation =
  | { type: 'redactFields'; paths: string[] }   // strip dotted-path fields from upstream response
  | { type: 'annotate'; key: string; value: string }; // add metadata to the audit event

interface DenialInfo {
  /**
   * Machine-readable denial code, drawn from the ErrorCode enum in
   * @euno/common-core. Examples: 'PATH_PATTERN', 'MAX_CALLS_EXCEEDED',
   * 'IP_RANGE_DENIED', 'KILL_SWITCH_ACTIVE'.
   */
  code: string;

  /**
   * The condition type that triggered the denial, or 'killSwitch' / 'policy'
   * for non-condition denials.
   */
  conditionType: string;

  /** Human-readable denial message. Suitable for logging; NOT for display to end users. */
  message: string;

  /**
   * Structured details specific to the denial type.
   * For argumentSchema failures: { schemaErrors: ValidationError[] }.
   * For ipRange denials: { sourceIp: string, allowedRanges: string[] }.
   * For maxCalls denials: { currentCount: number, maxCalls: number, windowSeconds: number }.
   * May be omitted for simple denials.
   */
  details?: Record<string, unknown>;
}
```

### 6.5 HTTP status codes

| Situation                                        | Status | Error code in body      |
|--------------------------------------------------|--------|-------------------------|
| Decision returned (allow or deny)                | 200    | — (use `decision` field) |
| Invalid or missing API key                       | 401    | `AUTHENTICATION_FAILED` |
| Valid key but insufficient scope                 | 403    | `PERMISSION_DENIED`     |
| Request body malformed / missing required fields | 400    | `INVALID_REQUEST`       |
| Request body too large (> 512 KiB)               | 413    | `REQUEST_TOO_LARGE`     |
| Gateway circuit open / temporary overload        | 503    | `GATEWAY_UNAVAILABLE`   |
| Protocol version not supported                   | 400    | `UNSUPPORTED_PROTOCOL_VERSION` |

All error responses use the same JSON envelope:

```typescript
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    requestId?: string;
  };
}
```

### 6.6 Protocol versioning

The `X-Euno-Protocol-Version` request header carries a monotonic integer
(currently `1`). The gateway echoes the negotiated version in the
`X-Euno-Protocol-Version` response header.

**Compatibility rules:**

- The gateway MUST accept all versions it has ever supported.
- When the client sends a version the gateway does not support, the gateway
  returns 400 with `UNSUPPORTED_PROTOCOL_VERSION` and a `supportedVersions`
  array in the error body.
- A protocol version increment requires a **deprecation window of ≥1 minor
  `@euno/mcp` release** during which the gateway serves both versions and the
  old version is announced as deprecated in the `X-Euno-Deprecation` response
  header.
- `@euno/mcp` sends the highest version it supports. The gateway responds on
  the negotiated version. This avoids the need for explicit negotiation round-trips.

**Current version 1 capabilities:** all fields described in §6.3–6.4.

### 6.7 Authentication and session lifecycle

1. `@euno/mcp` starts with an `enforcer` config containing the gateway URL and
   API key.
2. On each `tools/call` interception, the proxy constructs an `EnforceRequest`
   and sends it to `POST /api/v1/enforce` with the API key in `Authorization`.
3. The hosted minter façade verifies the API key (§5.3), loads the stored
   `(tenant_id, policy_id, policy_hash)`, signs a ≤5 minute capability JWT with
   the tenant's HSM key, and writes the mint-audit row required by the threat
   model.
4. The façade forwards the request to the internal gateway with the capability
   JWT. The gateway verifies the JWT through the existing verifier path, loads or
   caches the policy, and runs the PDP.
5. The proxy applies obligations from the response before forwarding to upstream
    (for `allow`) or returns a denial to the MCP client (for `deny`).
6. The gateway writes its own OCSF audit event. When running in remote-enforcer
    mode, the proxy does **not** write a duplicate local audit record for the same
    tool call (to avoid double-counting in the dashboard). This is an accepted
    tradeoff: the gateway's audit trail is the authoritative record. Compensating
    controls are: (a) the OCSF audit event is written by the gateway before the
    enforcement response is returned, so an unanswered proxy request still
    produces an audit row; (b) the `requestId` in the response is recorded by the
    proxy in its own structured log for correlation; (c) the KMS mint-audit sidecar
    records each token issuance independently of the gateway's enforcement log.
    Operators who require an independent proxy-side audit trail for compliance
    reasons MUST deploy their own `LocalHmacSigner`-backed audit sink alongside
    the remote enforcer and accept that dual-write introduces duplicate rows that
    the query API must de-duplicate on `requestId`.

**Latency target:** The gateway MUST return a response within `timeoutMs`
(default 5000 ms). If the timeout elapses, `@euno/mcp` falls back to
**deny-by-default** and surfaces the 503 to the MCP client as a structured
`GATEWAY_UNAVAILABLE` denial. There is no fail-open fallback on timeout.

### 6.8 Policy caching on the gateway

The gateway caches the resolved `AgentCapabilityManifest` keyed by
`(tenant_id, policy_id, policy_hash)` with a TTL of 60 seconds. This avoids a
Postgres round-trip on every tool call. Cache invalidation is triggered by:

- TTL expiry (every 60 s).
- Admin API call `POST /admin/v1/policies/:id/invalidate`.
- Kill-switch activation (the kill-switch already propagates within milliseconds
  via Redis pub/sub; the policy cache is a separate concern).

---

## 7. MVP Anchor Cross-Reference

This table maps every decision above to the `docs/mvp.md` section that requires
it. Reviewers should verify each cross-link before approving.

| Decision | This document § | `docs/mvp.md` anchor |
|---|---|---|
| KMS provider: Azure Managed HSM primary | §1.1 | `docs/mvp.md` §["Minter threat model"](mvp.md#minter-threat-model-required-before-stage-3-ships) |
| Config types in `@euno/common-core` | §1.1 | `public/packages/common/src/runtime.ts` |
| Non-exportability verification procedure | §1.3 | `docs/mvp.md` §["Minter threat model"](mvp.md#minter-threat-model-required-before-stage-3-ships) |
| Key rotation via JWKS kid | §1.4 | `docs/mvp.md` §["Minter threat model"](mvp.md#minter-threat-model-required-before-stage-3-ships) |
| Audit signer: KMS-backed → OCSF | §1 | Line 525 (parity table row "Audit signer") |
| Postgres ledger: existing `euno_audit_ledger` table + per-row HMAC `BYTEA` | §2.1 | Lines 648–650 (persistent audit log) |
| Advisory lock ID: `0x455534004C454447` (not hashtext) | §2.1 | `ledger-signer.ts` line 683 |
| S3 anchor: `PostgresLedgerOptions.s3` (code-configured, no env var) | §2.1 | `ledger-signer.ts` lines 548–560 |
| Audit retention 90-day default | §2.1 | Lines 791–798 (pricing tiers) |
| Revocation: Redis + Postgres best-effort dual-write | §2.2 | Lines 524, 527 (parity table "Kill switch") |
| Kill-switch: existing `euno_kill_switch_entries` table (row-presence = active) | §2.3 | `redis-kill-switch.ts` lines 165–179 |
| Kill-switch: Redis pub/sub + Postgres `load()` replay on cold-start | §2.3 | Line 527 + stage3plan §Task 6 |
| Redis key prefixes: per-store env vars (no global prefix) | §3.1 | `redis-kill-switch.ts`, `call-counter-store.ts`, `revocation-store.ts`, `dpop.ts` |
| Redis circuit-breaker: hosted hard-codes fail-closed; self-hosters must set `REDIS_CIRCUIT_OPEN_MODE` | §3.2 | stage3plan §Task 4 (no silent default) |
| Self-host bundle excludes minter | §4 | Line 646 (hosted-only initially) |
| API-key format: `sk-<p8>.<s48>` base58 | §5.1 | stage3plan §Task 10 |
| API-key verifier: HMAC-SHA256 with external pepper | §5.3 | `docs/mvp.md` §["Stage 3 upgrade bridge"](mvp.md#the-stage-3-upgrade-bridge--the-part-the-prior-plan-skipped) and §["Minter threat model"](mvp.md#minter-threat-model-required-before-stage-3-ships) |
| API-key issuance audit log (separate credentials) | §5.2 | Line 679 |
| Enforcer config: flat form canonical (mvp.md line 633); nested form also accepted | §6.1 | Lines 628–633 |
| Enforcer endpoint POST /api/v1/enforce | §6.2 | stage3plan §Task 9 |
| Remote enforcer timeout → deny-by-default | §6.7 | Lines 613–615 (cryptographic-token invariant must not be relaxed) |
| Policy cache 60-s TTL + invalidation | §6.8 | Line 638 (drop-in replacement, no schema change) |
| Protocol version deprecation window | §6.6 | stage3plan §Task 9 (backward-compat plan) |
| Hosted-vs-self-host matrix | §4 | Lines 643–658 |

---

## 8. Resolved Review Decisions

These items were reviewed as pre-signoff blockers and are resolved inline so
Tasks 2+ have no deferred architectural decisions.

1. **Per-tenant vs platform-wide minter key:** Resolved to per-tenant HSM keys
   for the hosted service. The existing `policyHash:audience` lookup in
   `AzureKeyVaultConfig.keysByPolicyHash` names the selection mechanism. No
   online platform-wide key signs capability tokens.

2. **Argon2id vs HMAC-SHA256 for API-key verification:** Resolved to
   HMAC-SHA256 with a secret pepper stored outside the API-key database. The API
   key secret is ~285 bits of random entropy, so the security boundary is pepper
   separation and rate limiting rather than password-style memory hardness.

3. **Postgres instance: shared vs separate for mint-audit:** The MVP requires
   the mint-audit log to use "separate credentials from the minter" (line 679).
   Resolved to a separate audit-sidecar write identity and a separate Postgres
   schema/user on the hosted database cluster by default. Enterprise deployments
   may place the schema on a separate instance, but the minimum accepted control
   is separate credentials and append-only grants held outside the minter
   process.

4. **`@euno/langchain` remote enforcer support:** Stage 3 introduces remote
   enforcement for `@euno/mcp`. The `@euno/langchain` companion package
   (`stage2executionplan.md` Task 9) uses the same `CapabilityRuntime` seam
   locally. Should `@euno/langchain` support `enforcer: { url, apiKey }` in
   Stage 3? Resolved to no for Stage 3. LangChain.js users who want shared
   state should route through the MCP transport or adopt the gateway directly
   after Stage 3; the initial remote-enforcer client surface remains
   `@euno/mcp` only.

---

## 9. Review Checklist

- [ ] KMS provider decision reviewed and signed off by ≥2 engineers.
- [ ] Minter threat model (Task 1) approved; §8 resolved decisions remain aligned
      with `docs/security/minter-threat-model.md`.
- [ ] Postgres schema reviewed by a DBA or engineer familiar with pg advisory
      locks and append-only audit credentials.
- [ ] Redis circuit-breaker defaults reviewed by on-call operations lead.
- [ ] API-key format reviewed by at least 1 security reviewer (entropy,
      pepper storage, rate limiting, constant-time comparison).
- [ ] Wire protocol reviewed by the `@euno/mcp` implementer (Task 2) and the
      gateway implementer (Task 9) — they must agree on the same spec.
- [x] All §8 review decisions resolved inline.
- [ ] This document approved (PR approved by ≥2 engineers + 1 security
      reviewer) before any Task 2+ code is merged to `main`.

[az-mhsm]: https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview

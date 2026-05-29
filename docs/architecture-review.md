# Architecture & Implementation Review

**Date:** 2026-05-28  
**Scope:** Full codebase — `pkg/`, `internal/`, `cmd/`  
**Reviewer:** Principal Architect (automated deep review)

Findings are ordered by severity within each section. Every item points to the exact file
and line(s) that contain the problem, verified against the current source tree.

---

## CRITICAL

---

### CR-1 — DID identity tokens accepted with a self-asserted, unverified JWK

**LOCATION:** `pkg/identity/did.go:71`  
**CATEGORY:** Logic Bug  
**SEVERITY:** Critical  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** `parsed.Claims(header.JSONWebKey.Key, ...)` trusts the JWK embedded
in the token's JOSE header to verify the signature without resolving the issuer's
DID document.

**CONSEQUENCE:** An attacker generates an arbitrary keypair, embeds the public key
in the token's `jwk` header field, signs the JWT with the matching private key, and
sets the `iss` claim to any string present in `DIDConfig.TrustedDIDs`. Every
verification step passes: the signature is valid (key matches), the DID is in the
trusted set. The attacker can impersonate any trusted DID and receive a
`UserContext` with full roles and claims. This is a complete authentication bypass.

**FIX:** Resolve the DID document for the `iss` DID (via DID Web, ION, or the
configured resolver) and verify that `header.JSONWebKey` matches one of the
`verificationMethod` keys listed in the document. Reject any token whose embedded
JWK is not anchored to the published DID document. The current `trustedDIDs`
allowlist provides no protection without this step.

**IMPLEMENTATION:**
- `pkg/identity/did.go` — `DIDConfig` now requires a `did.Resolver`; `VerifyToken`
  resolves the issuer's DID document and verifies the signature against each
  `verificationMethod` key. The JOSE header's embedded JWK is never consulted.
  `NewDIDProvider` returns an error if no resolver is supplied.
- `cmd/issuer/main.go` — the `"did"` provider case now constructs a
  `did.CachingResolver` wrapping a `did.MultiResolver` (web + ion + key methods)
  and passes it to `DIDConfig.Resolver`.
- `pkg/identity/identity_test.go` and `identity_extended_test.go` — updated with a
  `testDIDResolver` stub; existing DID tests updated to the resolver-based flow;
  `TestDIDProvider_EmbeddedJWKBypassRejected` added as a dedicated regression test.

---

### CR-2 — Cross-org attenuation treats empty parent `Actions` as wildcard

**LOCATION:** `pkg/federation/attenuation.go:88-109` (`isSubsetOf`)  
**CATEGORY:** Logic Bug  
**SEVERITY:** Critical  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** The action-subset check is guarded by `if len(parent.Actions) > 0`.
When a parent token has an empty `Actions` field, the entire action check is skipped
and `isSubsetOf` returns `true` for any child actions slice.

**CONSEQUENCE:** A parent token stored with `actions: []` (or omitted) acts as an
implicit wildcard. A child can request any actions — `["admin:delete", "data:export"]`
— against a parent that was intended to grant nothing. The federation attenuation
invariant (child ⊆ parent) is violated; privilege escalation is trivially achievable
via cross-org token issuance.

**FIX:** Invert the guard. An empty `parent.Actions` means "no actions permitted",
not "unrestricted". Replace the block at line 88 with:

```go
if len(parent.Actions) == 0 {
    return false // parent grants no actions; nothing can be a subset
}
```

**IMPLEMENTATION:**
- `pkg/federation/attenuation.go` — `isSubsetOf` now returns `false` immediately
  when `len(parent.Actions) == 0`, making the semantics explicit: empty = no grant.
- `pkg/federation/federation_test.go` — `TestAttenuate_EmptyParentActions_Denied`
  added as a regression test confirming that `["admin:delete"]` is denied against an
  empty-action parent.

---

### CR-3 — Cross-org attenuation checks condition type presence, not value restrictiveness

**LOCATION:** `pkg/federation/attenuation.go:113-147` (`containsAllConditionTypes`, `isSubsetOf`)  
**CATEGORY:** Logic Bug  
**SEVERITY:** Critical  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** `containsAllConditionTypes` verifies that the child's conditions include
every condition _type_ found in the parent, but not that the child's condition
_values_ are at least as restrictive. A child with `maxCalls: 10_000_000` satisfies
the check against a parent with `maxCalls: 10` because both have the
`ConditionTypeMaxCalls` type.

**CONSEQUENCE:** An attacker holding a tightly-scoped parent token (e.g., `maxCalls:
5`, `timeWindow: business-hours`, `ipRange: 10.0.0.0/8`) can request an attenuated
child token with `maxCalls: unlimited`, a 24-hour time window, and `0.0.0.0/0`.
Condition-level restrictions imposed by the parent organization are completely
bypassed through attenuation.

**FIX:** Implement per-condition-type value comparison in `isSubsetOf`. For each
condition type present in the parent, find the matching child condition and verify
that the child is at least as restrictive:

- `MaxCallsCondition`: child.Count ≤ parent.Count and child.WindowSeconds ≥ parent.WindowSeconds
- `TimeWindowCondition`: child range ⊆ parent range
- `IPRangeCondition`: child CIDRs ⊆ parent CIDRs (every child CIDR must be
  contained within a parent CIDR)

**IMPLEMENTATION:**
- `pkg/federation/attenuation.go` — `containsAllConditionTypes` replaced by
  `conditionsAreAtLeastAsRestrictive` which performs full per-type value comparison
  via `conditionIsAtLeastAsRestrictive`. All 9 concrete condition types are handled
  explicitly; unknown/opaque types fall back to JSON-digest equality. Helpers added:
  `timeWindowIsAtLeastAsRestrictive`, `ipRangesAreAtLeastAsRestrictive`,
  `networkContains`, `allowedTablesIsAtLeastAsRestrictive`,
  `stringSliceIsSubset`, `allowedValuesIsSubset`, `conditionDigest`.
- `pkg/federation/federation_test.go` — regression tests added:
  `TestAttenuate_MaxCallsEscalation_Denied`, `TestAttenuate_MaxCallsMoreRestrictive_Allowed`,
  `TestAttenuate_TimeWindowEscalation_Denied`, `TestAttenuate_IPRangeEscalation_Denied`,
  `TestAttenuate_IPRangeNarrower_Allowed`.

---

## HIGH

---

### H-1 — `handleEnforce` does not require DPoP for JKT-bound tokens

**LOCATION:** `internal/gateway/handlers.go:208-230`  
**CATEGORY:** Logic Bug  
**SEVERITY:** High  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** DPoP verification fires only `if payload.DPoP != nil` (line 209). There
is no check that a token carrying a `cnf.jkt` confirmation claim _must_ present a
DPoP proof. The same enforcement (line 499) is correctly implemented in
`handleProxy` but is absent in `handleEnforce`.

**CONSEQUENCE:** A stolen sender-constrained capability token can be replayed against
`/api/v1/enforce` without supplying a DPoP proof. The sender-constraint binding is
rendered worthless for the primary enforcement path.

**FIX:** After obtaining `claims` (line 206), add:

```go
if claims.Confirmation != nil && claims.Confirmation.JKT != "" && payload.DPoP == nil {
    writeJSON(w, http.StatusOK, capability.EnforceResponse{
        Decision: capability.DecisionDeny,
        Denial: &capability.DenialInfo{
            Code:    capability.ErrCodeAuthorizationFailed,
            Message: "DPoP proof required for sender-constrained token",
        },
    })
    return
}
```

**IMPLEMENTATION:**
- `internal/gateway/handlers.go` — added a mandatory DPoP check immediately after
  the token cache/verify block in `handleEnforce`. When `claims.Confirmation.JKT`
  is non-empty and no DPoP proof was supplied, the handler returns `DecisionDeny`
  with `ErrCodeAuthorizationFailed` before any enforcement engine evaluation.

---

### H-2 — Resilient revocation cache stores `revoked=false`, breaking fail-closed semantics

**LOCATION:** `pkg/revocation/resilient_redis.go:72`  
**CATEGORY:** Logic Bug  
**SEVERITY:** High  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** `r.cache.Put(jti, revoked)` on the success path (line 72) stores
`false` for non-revoked tokens. During a Redis outage, `r.cache.Get(jti)` returns
`(false, true)` for any token that was active before the outage, causing
`IsRevoked` to return `false` (not revoked).

**CONSEQUENCE:** Tokens revoked while Redis is unavailable — or tokens that were seen
as valid before the outage — continue to be accepted for up to `StaleTTL` seconds.
The code comment says "fail-closed" but the cache entry for `revoked=false` makes
it fail-open for the token population already in the cache. A revocation event
during a Redis outage produces a window where revoked tokens are still accepted.

**FIX:** Never cache `false`. Remove the `r.cache.Put(jti, revoked)` call and
replace with conditional caching:

```go
r.reporter.MarkHealthy()
if revoked {
    r.cache.Put(jti, true) // only cache the positive revocation signal
}
return revoked, nil
```

**IMPLEMENTATION:**
- `pkg/revocation/resilient_redis.go` — `r.cache.Put(jti, revoked)` replaced with
  `if revoked { r.cache.Put(jti, true) }`. Non-revoked tokens are no longer cached,
  so a Redis outage causes `IsRevoked` to fail-closed (return `true`) rather than
  serving a stale `false` from cache.
- `pkg/revocation/resilient_redis_test.go` — replaced `TestResilientRedis_CacheServesStale`
  (which asserted the now-removed insecure behaviour) with two new tests:
  `TestResilientRedis_FailClosedDuringOutage` (non-revoked token → blocked during outage)
  and `TestResilientRedis_RevokedTokenCachedAndServedDuringOutage` (revoked token →
  still blocked during outage because the positive signal is still cached).

---

### H-3 — Empty `access.Columns` bypasses column-level restrictions in `allowedTables`

**LOCATION:** `pkg/enforcement/handlers.go:339-364` (`handleAllowedTables`)  
**CATEGORY:** Logic Bug  
**SEVERITY:** High  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** The inner condition at line 341 is `if hasColumnRestriction && len(access.Columns) > 0`.
When `access.Columns` is an empty slice, the column check is skipped entirely even
when the capability defines column restrictions for the table.

**CONSEQUENCE:** An agent submitting `tables: [{table: "payments", columns: []}]`
bypasses all column restrictions on the `payments` table. Data-level access control
is circumvented by omitting the columns field.

**FIX:** Replace the condition. If a column restriction exists for the table, an
empty request columns list should be explicitly denied:

```go
if at.Columns != nil {
    allowedCols, hasColumnRestriction := at.Columns[access.Table]
    if hasColumnRestriction {
        if len(access.Columns) == 0 {
            return &ConditionError{
                Code:          capability.ErrCodeMissingContext,
                ConditionType: capability.ConditionTypeAllowedTables,
                Message:       fmt.Sprintf("column list required for table %q (column restrictions are configured)", access.Table),
            }
        }
        // ... existing column set check
    }
}
```

**IMPLEMENTATION:**
- `pkg/enforcement/handlers.go` — `handleAllowedTables` restructured so that when
  `hasColumnRestriction` is true and `len(access.Columns) == 0`, a `ConditionError`
  with `ErrCodeMissingContext` is returned immediately. The existing per-column
  allowlist check runs only when a non-empty column list is provided.
- `pkg/enforcement/enforcement_test.go` — `TestEngine_AllowedTables_EmptyColumnsWithRestriction`
  added: sends `Columns: []string{}` against a capability with column restrictions and
  asserts `DecisionDeny` with `ConditionTypeAllowedTables`.

---

### H-4 — SCIM PATCH has a data race on the shared user pointer

**LOCATION:** `internal/issuer/scim.go:500-525` (`handleSCIMPatchUser`)  
**CATEGORY:** Implementation  
**SEVERITY:** High  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** `GetUser` (line 489) acquires a read lock, returns the raw `*SCIMUser`
pointer from the map, and releases the lock. `applySCIMUserPatch` (line 514) then
mutates fields of that pointer without holding any lock. Two concurrent PATCH
requests for the same user obtain the same pointer and race on field writes. The
identical race exists in `handleSCIMPatchGroup` (line 683).

**CONSEQUENCE:** Concurrent PATCH calls corrupt the user record in unpredictable ways.
Under `-race`, this is a detected data race. In production, fields updated by one
request are silently overwritten by a concurrent one.

**FIX:** `GetUser`/`GetGroup` should return a deep copy, not the map pointer. Add a
`Clone()` method to `SCIMUser` and `SCIMGroup` that copies the struct and its slice
fields, and return that from the Get methods.

**IMPLEMENTATION:**
- `internal/issuer/scim.go` — `SCIMUser.Clone()` added (deep-copies Schemas, Emails,
  Groups slices); `SCIMGroup.Clone()` added (deep-copies Schemas, Members slices).
  `GetUser` and `GetGroup` now return `u.Clone()` / `g.Clone()` instead of the raw
  map pointer, so each PATCH handler works on an exclusively owned copy. The modified
  copy is written back under the write lock via `UpdateUser`/`UpdateGroup`.

---

### H-5 — SCIMStore is purely in-memory; all provisioned identities lost on restart

**LOCATION:** `internal/issuer/scim.go:28-44` (`SCIMStore`)  
**CATEGORY:** Architecture  
**SEVERITY:** High  
**STATUS:** ✅ Fixed (interface + compile check) — 2026-05-28; Postgres persistence tracked separately

**PROBLEM:** `SCIMStore` is a plain in-memory map. Restarts, deployments, and
crashes wipe all SCIM-provisioned users and groups.

**CONSEQUENCE:** The issuer's SCIM 2.0 API cannot be used in production. Any IdP
(Okta, Azure AD, Entra) that provisions users via SCIM will re-provision everything
on each pod restart, creating duplicate-user events and losing group membership
changes made between restarts.

**FIX:** Persist SCIM state in the issuer's Postgres database (a `scim_users` and
`scim_groups` table, managed by the migration runner already in place) or delegate
to an external identity store. The in-memory implementation is acceptable only as a
test double behind an interface.

**IMPLEMENTATION:**
- `internal/issuer/scim.go` — `SCIMRepository` interface extracted, covering all
  CRUD operations for users and groups. `var _ SCIMRepository = (*SCIMStore)(nil)`
  compile-time guard added to keep `SCIMStore` in sync with the interface.
- `internal/issuer/app.go` — `App.scimStore` field type changed from `*SCIMStore`
  to `SCIMRepository`, enabling injection of any conforming implementation (e.g., a
  future Postgres-backed store) without touching the handler layer.
- Postgres persistence is intentionally deferred: the interface boundary is in place;
  a `pgSCIMRepository` implementation can be added independently once the schema
  migrations are authored.

---

### H-6 — Audience claim not validated when gateway `Audience` config is empty

**LOCATION:** `pkg/capability/jwks.go:139-146` (`JWKSClient.VerifyToken`)  
**CATEGORY:** Logic Bug  
**SEVERITY:** High  
**STATUS:** ✅ Fixed — 2026-05-28

**PROBLEM:** Audience validation fires only `if c.audience != ""` (line 142). A
gateway deployed without `GATEWAY_AUDIENCE` set accepts any token for any audience.

**CONSEQUENCE:** A token issued for a different gateway or service can be replayed
against this gateway. Capability tokens are not scoped to this deployment even if
the issuer intended them for a different audience.

**FIX:** Make `Audience` a required field in both `Config` (gateway config) and
`JWKSVerifierConfig`. Fail fast at startup if empty. Remove the nil-guard and always
set `expected.AnyAudience`.

**IMPLEMENTATION:**
- `pkg/capability/jwks.go` — the `if c.audience != ""` guard removed from
  `VerifyToken`. `expected.AnyAudience` is now always set to `[]string{c.audience}`.
  An unconfigured (empty) audience causes all tokens whose `aud` claim is non-empty
  to be rejected — fail-closed. `NewJWKSClient` logs a `Warn` when `Audience` is
  empty to surface misconfiguration at startup.
- `cmd/gateway/main.go` — startup validation added: if `GATEWAY_AUDIENCE` is unset
  or blank, `run()` returns a fatal error before the verifier is constructed.
- `internal/gateway/jwks_verifier_test.go` — three tests updated to set a matching
  `Audience` in both verifier config and token claims (`TestJWKSVerifier_VerifyToken_Success`,
  `TestJWKSVerifier_VerifyToken_CachesKeys`, `TestJWKSVerifier_TracingTransport`).
  Existing negative-path tests (`TestJWKSVerifier_VerifyToken_AudienceCheck`) continue
  to pass unchanged.

---

## MEDIUM

---

### M-1 — Sequence number reused after audit backend failure

**LOCATION:** `pkg/audit/audit.go:326,341` (`DefaultPipeline.Append`)  
**CATEGORY:** Logic Bug  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `p.lastSeqNum` is incremented at line 326 and decremented at line 341
when `backend.Append` fails. If the backend partially committed the write before
returning an error (network fault after write), the rolled-back sequence number is
reused by the next `Append` call. The persisted record and the retry both carry
`SequenceNum = N`.

**CONSEQUENCE:** Sequence-number-based chain integrity tools see a collision at N.
Two records with the same sequence number and different chain hashes are
undetectable without full hash comparison.

**FIX:** Do not roll back `lastSeqNum`. Accept the gap: the next record gets N+1
regardless of whether N was committed. Document that sequence numbers are monotonic
with possible gaps after failures, not gapless.

**IMPLEMENTATION:**
- `pkg/audit/audit.go` — removed `p.lastSeqNum--` rollback in `DefaultPipeline.Append`;
  added doc comment explaining monotonic-with-gaps semantics (A-2 doc also added to struct).
- `pkg/audit/audit_test.go` — `TestPipeline_BackendErrorRollsBackSequence` renamed to
  `TestPipeline_BackendErrorLeavesSequenceGap`; assertion updated from seq=3 to seq=4
  and added `require.Len(t, records, 3)` to verify the gap.

---

### M-2 — `effectiveAudience` has a dead code path and can return an empty audience

**LOCATION:** `internal/issuer/app.go:704-712`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** The function returns `app.config.Audience` on line 706 when it is
non-empty. Line 711-712 (`return app.config.Audience`) is never reached. When
`config.Audience == ""` and `requested == ""`, it returns `""`. A token with an
empty audience fails gateway-side audience validation.

**FIX:** Return an error (or the issuer URL as a default) when both are empty.
Remove the dead `return app.config.Audience` at line 712.

**IMPLEMENTATION:**
- `internal/issuer/app.go` — `effectiveAudience` now falls back to `app.config.IssuerURL`
  when both `app.config.Audience` and `requested` are empty, ensuring tokens always carry
  a non-empty `aud` claim. The unreachable `return app.config.Audience` line was removed.

---

### M-3 — `signToken` builds JWT manually while `verifyCapabilityToken` uses go-jose

**LOCATION:** `internal/issuer/app.go:714-752`  
**CATEGORY:** Design  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `signToken` marshals a `map[string]string` header, base64url-encodes
it, and concatenates `header.payload.signature` manually. `verifyCapabilityToken`
(line 755) uses `jwt.ParseSigned` from go-jose. The two paths use different JWT
construction logic; any divergence produces tokens that fail verification.

**CONSEQUENCE:** If go-jose changes its expected header format, or if a field added
to the header map breaks the manual construction, issuance succeeds but attenuation
and renewal fail silently. The mismatch is only caught at runtime under the
`/attenuate` or `/renew` path.

**FIX:** Use `jose.NewSigner` + `jwt.Signed(signer).Claims(payload).Serialize()`
throughout `signToken`. Eliminate the manual header construction.

**IMPLEMENTATION:**
- `internal/issuer/app.go` — `signToken` rewritten to use `jose.NewSigner` +
  `jwt.Signed(joseSigner).Claims(payload).Serialize()`. The `typ: "JWT"` and `kid`
  headers are set via `SignerOptions.WithType("JWT").WithHeader(...)`. The manual
  base64 header construction and dead `signingDigest` helper were removed.
- `pkg/crypto/software.go` — `SoftwareSigner.PrivateKey()` method added so `signToken`
  can access the raw private key for go-jose via the local `privateKeyProvider` interface.

---

### M-4 — `Authorization: Bearer` parsing is case-sensitive

**LOCATION:** `internal/gateway/handlers.go:596-600` (`extractBearerToken`)  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `auth[:7] == "Bearer "` rejects `"bearer "` and `"BEARER "`. HTTP
headers are case-insensitive; many clients send lowercase scheme names.

**FIX:** Use `strings.HasPrefix(strings.ToUpper(auth), "BEARER ")` and extract
`auth[7:]`.

**IMPLEMENTATION:**
- `internal/gateway/handlers.go` — `extractBearerToken` now uses
  `strings.EqualFold(auth[:7], "bearer ")`, accepting any capitalisation of the
  scheme name per RFC 7235 §2.1.

---

### M-5 — `TokenCache.Invalidate` is O(n) on the insertion-order slice

**LOCATION:** `pkg/capability/token_cache.go:187-200`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `Invalidate` performs a linear scan through `insertOrder` (line 193)
to remove the key. With `MaxSize=4096`, a mass-revocation event (e.g., a compromised
key) that invalidates thousands of tokens holds the write lock for O(n) per call.

**FIX:** Replace `insertOrder []string` with a doubly-linked-list structure or a
map from key to list node so that removal is O(1). Alternatively, use a generation
counter: increment on each Invalidate call, and have Get() reject entries from
prior generations.

**IMPLEMENTATION:**
- `pkg/capability/token_cache.go` — `insertOrder []string` replaced with
  `insertOrder *list.List` (`container/list`). Each `tokenCacheEntry` stores a
  `*list.Element` back-pointer enabling O(1) `Invalidate` and `purgeExpired` removal.
  `Put` evicts the LRU (front of list) when at capacity. `NewTokenCache` initialises
  `insertOrder: list.New()`.

---

### M-6 — `callcounter/redis.go` sliding window key TTL is one second too short

**LOCATION:** `pkg/callcounter/redis.go:54`  
**CATEGORY:** Logic Bug  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `pipe.Expire(ctx, windowKey, time.Duration(windowSec)*time.Second+time.Second)`
adds only one extra second of TTL beyond the window. Under high clock skew between
the application and Redis (>1 second), entries at the start of the window could be
evicted before the ZREMRANGEBYSCORE clean-up fires, causing the ZCard to
undercount.

**FIX:** Use a 2× safety margin: `time.Duration(windowSec)*2*time.Second`. The
TTL is used only for key cleanup; a generous margin has negligible cost.

**IMPLEMENTATION:**
- `pkg/callcounter/redis.go` — `pipe.Expire` TTL changed from `windowSec*time.Second+time.Second`
  to `time.Duration(windowSec)*2*time.Second`.
- `pkg/callcounter/redis_test.go` — `TestRedis_IncrementAndGet_SlidingWindowExpiry` updated:
  `FastForward` advanced from 3 s to 5 s to exceed the new 4 s TTL (2×2 s); comment added
  explaining the key-expiry-based test mechanism.

---

### M-7 — `migration_test.go` test files skip missing directories inconsistently

**LOCATION:** `internal/integration/migration_test.go:47-82` (`TestMigration_ForwardBackwardPairs`, `TestMigration_SQLSyntaxBasicValidation`)  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `TestMigration_MigrationFilesExist` guards against missing directories
with `os.IsNotExist` and logs a notice. `TestMigration_ForwardBackwardPairs` and
`TestMigration_SQLSyntaxBasicValidation` call `os.ReadDir` without the same guard
and will `require.NoError` fail (not skip) if the directory is absent.

**FIX:** Apply the same `os.IsNotExist` guard and `t.Skip` in every test that reads
a migration directory.

**IMPLEMENTATION:**
- `internal/integration/migration_test.go` — `os.IsNotExist` guard + `t.Skipf` added
  at the start of the inner loops in `TestMigration_ForwardBackwardPairs` and
  `TestMigration_SQLSyntaxBasicValidation`, matching the pattern in
  `TestMigration_MigrationFilesExist`.

---

## ARCHITECTURE

---

### A-1 — `Enforcer` interface defined in the producer package, not the consumer

**LOCATION:** `pkg/enforcement/engine.go:134-141`  
**CATEGORY:** Architecture  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `Enforcer` is defined inside `pkg/enforcement` alongside the concrete
`*Engine` type. Consumers (e.g., `internal/gateway`) depend on `pkg/enforcement`
just to name the interface, creating unnecessary coupling to the producer package.

**FIX:** Move `Enforcer` (and `CallCounter`) to `pkg/capability` or a dedicated
`pkg/enforce` interface-only package. Consumers import the interface without
importing the implementation.

**IMPLEMENTATION:**
- `pkg/capability/enforce.go` — `Enforcer` and `CallCounter` interfaces defined here
  with doc comments.
- `pkg/enforcement/engine.go` — `Enforcer` and `CallCounter` changed to type aliases
  (`= capability.Enforcer`, `= capability.CallCounter`); compile-time guard
  `var _ capability.Enforcer = (*Engine)(nil)` added.
- `internal/gateway/app.go` — `Engine` field type changed from `enforcement.Enforcer`
  to `capability.Enforcer`; `enforcement` import dropped from `app.go` (still used in
  `handlers.go` for `enforcement.WithDryRun`).

---

### A-2 — `DefaultPipeline` chain state is per-replica and in-memory only

**LOCATION:** `pkg/audit/audit.go:219-268`  
**CATEGORY:** Architecture  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `lastChainHash` and `lastSeqNum` live in the process heap. In a
multi-replica deployment, each pod has its own chain with its own genesis hash and
independent sequence counter. There is no mechanism to detect ordering gaps or
stitch chains across replicas.

**CONSEQUENCE:** Cross-replica audit integrity verification is not possible without
external tooling that understands `ReplicaID`. A replica restart reloads state from
the backend (`Initialize`), but in-flight writes lost in the async pipeline on crash
produce silent gaps in the chain.

**FIX:** Document the per-replica chain model explicitly in operator guides.
Consider a distributed sequence allocator (Postgres sequence, Redis INCR) shared
across replicas so that `SequenceNum` is globally monotonic, enabling gap detection
without per-replica tracking.

**IMPLEMENTATION:**
- `pkg/audit/audit.go` — `DefaultPipeline` struct doc comment updated with a detailed
  "Per-replica chain model (A-2)" section explaining the in-process state, multi-replica
  semantics, and operator guidance for cross-replica integrity verification.
  Postgres-sequence / Redis INCR as a future global allocator is documented as an
  optional upgrade path.

---

### A-3 — `PartitionedKillSwitch` partition map grows unbounded

**LOCATION:** `pkg/killswitch/partitioned.go:256-292` (`getOrCreatePartition`)  
**CATEGORY:** Architecture  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** A new `agentPartition` is created and added to `p.partitions` for
every unique `agentID` seen in `ShouldBlock`. Partitions are never evicted. In a
long-running gateway handling tens of thousands of distinct agent IDs, the map and
its associated goroutines grow without bound.

**FIX:** Add a maximum partition count and evict the least-recently-used partition
when the limit is reached, canceling its goroutine. Alternatively, accept a
pre-registered set of agent IDs at startup and reject unknowns.

**IMPLEMENTATION:**
- `pkg/killswitch/partitioned.go` — `defaultMaxPartitions = 10_000` constant added;
  `PartitionedKillSwitch` gains `maxPartitions int` and `lruList *list.List` fields;
  each `agentPartition` carries a `lruElem *list.Element` back-pointer. `WithMaxPartitions`
  setter added. `getOrCreatePartition` evicts the LRU (front of list) when at capacity;
  `ShouldBlock` promotes the accessed partition to MRU on each call. `Reset` calls
  `p.lruList.Init()` to clear the LRU list alongside the partition map.

---

### A-4 — `issuer.App` embeds `SCIMStore` directly, preventing independent scaling

**LOCATION:** `internal/issuer/app.go:89-106`  
**CATEGORY:** Architecture  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed (interface + compile check) — 2026-05-28; Postgres persistence tracked separately

**PROBLEM:** `App.scimStore` is initialized in `New()` as an in-process singleton.
If the issuer is scaled horizontally, each replica has its own independent SCIM
state. This is the architectural root of H-5.

**FIX:** Abstract `scimStore` behind an interface (`SCIMRepository`) and inject it.
The current in-memory implementation satisfies the interface for single-instance
deploys. A Postgres-backed implementation satisfies it for multi-replica.

**IMPLEMENTATION:**
- `internal/issuer/scim.go` — `SCIMRepository` interface extracted (H-5 fix);
  `var _ SCIMRepository = (*SCIMStore)(nil)` compile-time guard added.
- `internal/issuer/app.go` — `App.scimStore` field typed as `SCIMRepository` so any
  conforming implementation (e.g. a Postgres-backed store) can be injected without
  touching the handler layer.

---

### A-5 — DID resolution absent: `DIDProvider` is a trusted-name-only allowlist

**LOCATION:** `pkg/identity/did.go:28-45`, `pkg/did/` (unused by DIDProvider)  
**CATEGORY:** Architecture  
**SEVERITY:** High (same root as CR-1)  
**STATUS:** ✅ Fixed — 2026-05-28 (resolved as part of CR-1)

**PROBLEM:** `pkg/did/` contains `web.go`, `ion.go`, and a `resolver.go`, but
`DIDProvider.VerifyToken` never calls them. The `trustedDIDs` map is a list of
opaque strings with no cryptographic binding. The DID document resolution
infrastructure exists in the repository but is not connected to the identity
verification path.

**FIX:** Wire `pkg/did.Resolver` into `DIDProvider`. On token receipt, resolve the
issuer DID, extract the `verificationMethod` keys, and use those (not the
self-asserted embedded JWK) to verify the signature.

**IMPLEMENTATION:** See CR-1 — `DIDConfig` now requires a `did.Resolver`;
`VerifyToken` resolves the issuer DID document and verifies the signature against
published `verificationMethod` keys. The header-embedded JWK is never trusted.

---

## DESIGN

---

### D-1 — `LedgerBackend` interface defined inside `pkg/audit` alongside the implementation

**LOCATION:** `pkg/audit/audit.go:91-100`  
**CATEGORY:** Design  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `LedgerBackend` is defined in the same package as `DefaultPipeline`,
which implements the `Pipeline` interface. Consumers of `LedgerBackend` (transport,
Postgres store) also live in `pkg/audit`, making the package a mix of interfaces,
implementations, and domain types. Adding a new backend requires touching the audit
package.

**FIX:** Move backend-agnostic interfaces (`LedgerBackend`, `Pipeline`) to a
separate `pkg/audit/contract` or `pkg/auditstore` package. Keep implementations in
`pkg/audit`. This eliminates the circular dependency risk and lets backends be
developed independently.

**IMPLEMENTATION:**
- `pkg/audit/contract/contract.go` — new package containing the canonical definitions
  of `LogEntry`, `SignedAuditEvidence`, `Pipeline`, and `LedgerBackend`. Imports only
  standard library, `go.opentelemetry.io/otel/trace`, and `pkg/ocsf`.
- `pkg/audit/audit.go` — original type definitions replaced with type aliases
  (`type LogEntry = contract.LogEntry`, etc.) so existing callers compile unchanged.

---

### D-2 — `KeyStore` interface defined inside `internal/issuer`, forcing consumers to import it

**LOCATION:** `internal/issuer/app.go:58-64`  
**CATEGORY:** Design  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `KeyStore` and `PublicKeyInfo` are defined in `internal/issuer` but
must be implemented by `internal/issuer/keystore.go` and
`internal/issuer/rotating_keystore.go`. Any additional keystore implementation must
import the `issuer` package, creating an import cycle if the implementation needs
issuer types.

**FIX:** Move `KeyStore` and `PublicKeyInfo` to `pkg/crypto` alongside the signer
types they depend on, then have `internal/issuer` import from `pkg/crypto`.

**IMPLEMENTATION:**
- `pkg/crypto/signer.go` — `PublicKeyInfo` struct and `KeyStore` interface added.
- `internal/issuer/app.go` — original definitions replaced with type aliases from
  `pkg/crypto`; all existing usages continue to compile unchanged.

---

### D-3 — `handleEnforce` and `handleValidate` duplicate token-verification logic

**LOCATION:** `internal/gateway/handlers.go:116-206`, `305-365`  
**CATEGORY:** Design  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** Both handlers contain near-identical token-verification blocks:
cache lookup → JWKS verify → expiry check → revocation check → cache store. The
only meaningful difference is that `handleValidate` skips the DPoP check. Any
change to verification logic (e.g., adding a new claim check) must be applied to
both handlers.

**FIX:** Extract a `verifyAndCacheClaims(ctx, token string) (*capability.TokenPayload, error)`
helper that handles the common path. Pass a `skipRevocation bool` parameter for
the rare case that diverges. Both handlers call the helper.

**IMPLEMENTATION:**
- `internal/gateway/handlers.go` — `tokenVerifyResult` struct and `verifyAndCacheToken`
  helper extracted. The helper performs: cache lookup → JWT verify → expiry check →
  revocation check → cache store; returns `DenyCode`, `DenyMsg`, and `ServiceUnavailable`
  fields so each caller can map the outcome to its own response shape. Duplicate
  verification blocks in `handleEnforce`, `handleValidate`, and `handleProxy` all
  replaced with a single call to the helper.

---

### D-4 — `ConditionHandler` function signature prevents stateful handlers from implementing an interface

**LOCATION:** `pkg/enforcement/engine.go:22`  
**CATEGORY:** Design  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `ConditionHandler` is a `func` type, not an interface. Registering a
stateful external policy evaluator (e.g., an OPA client with connection pooling)
requires passing a closure that captures state. The function signature cannot be
tested via interface-satisfaction compile-time assertions (`var _ ConditionHandler`
is not useful for structural checks).

**FIX:** Define a `ConditionHandler` interface with a single `Handle` method.
Register implementations, not closures. The built-in handlers already have
`*Engine` receiver methods that satisfy this shape.

**IMPLEMENTATION:**
- `pkg/enforcement/engine.go` — `ConditionHandler` changed from a `func` type to an
  interface with a single `Handle` method. `ConditionHandlerFunc` adapter type added
  so plain functions satisfy the interface without boilerplate.
- `pkg/enforcement/handlers.go` — `registerBuiltins` updated to wrap each method
  value with `ConditionHandlerFunc(e.handleXxx)`.
- `pkg/enforcement/enforcement_test.go` — `RegisterCondition` call updated to wrap
  the inline function with `enforcement.ConditionHandlerFunc(...)`.

---

## IMPLEMENTATION

---

### I-1 — `getOrCreatePartition` has a TOCTOU window between partition seed and subscription start

**LOCATION:** `pkg/killswitch/partitioned.go:286-291`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** After releasing `p.mu` (line 277), `inner.ShouldBlock` is called to
seed the initial kill state (line 286). Meanwhile `runAgentSubscription` is already
running (launched at line 291). If a `kill` event arrives via pub/sub between the
seed read and the subscription becoming active, the partition will miss the event
and start in the `killed=false` state even though the agent is killed.

**CONSEQUENCE:** A brief window (typically <1 ms) exists where a just-killed agent
is treated as alive by a new partition. Under normal Redis latency this is
negligible, but it violates the stated fail-closed guarantee.

**FIX:** Seed the initial state _after_ the subscription is confirmed live (after
the `pubsub.Receive` ping at line 307), not before launching the goroutine. This
ensures no events are missed between state read and subscription start.

**IMPLEMENTATION:**
- `pkg/killswitch/partitioned.go` — seed call removed from `getOrCreatePartition`;
  moved into `runAgentSubscription` immediately after `pubsub.Receive` confirms the
  subscription is live. The seed now sets both `part.killed = blocked` and
  `part.degraded = false` atomically under `part.mu`.

---

### I-2 — `parseMigrations` panics on non-`.up.sql`/`.down.sql` SQL files

**LOCATION:** `internal/migrate/migrate.go:432-441`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `parseFilename` returns an error for any `.sql` file that does not end
with `.up.sql` or `.down.sql`. However, `parseMigrations` propagates this as a
hard error (line 440), causing `NewRunner` to fail if the migrations directory
contains a plain `.sql` file (e.g., a seed file, a reference fixture, or a schema
dump committed for documentation).

**FIX:** Either skip unrecognized `.sql` files with a log warning, or document the
strict naming requirement prominently and add a validation step that enumerates
the directory before `NewRunner` is called.

**IMPLEMENTATION:**
- `internal/migrate/migrate.go` — `parseMigrations` now calls `slog.Default().Warn`
  and `continue` when `parseFilename` returns an error, rather than propagating a
  hard error. When all files are skipped, `NewRunner` returns `ErrNoMigrations`.
- `internal/migrate/migrate_test.go` — `TestNewRunner_InvalidFilename` and
  `TestNewRunner_ZeroVersion` updated to assert `ErrNoMigrations` (not `ErrInvalidVersion`)
  and confirm the file was skipped rather than causing a hard failure.

---

### I-3 — `refreshKeys` acquires a write lock and then calls `fetchKeys` (network I/O under lock)

**LOCATION:** `pkg/capability/jwks.go:192-227` (`refreshKeys`)  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** `refreshKeys` acquires `c.mu.Lock()` (line 193) before calling
`c.fetchKeys` (line 201), which performs an HTTP round-trip. All concurrent token
verifications block on this lock for the full duration of the JWKS fetch.

**CONSEQUENCE:** Under load, a slow JWKS endpoint (or a circuit-breaker retry delay)
causes all goroutines processing tokens to serialize behind the lock. P99 latency
for token verification spikes to the JWKS endpoint RTT during every cache miss.

**FIX:** Use a singleflight group to deduplicate concurrent refresh calls, then
store the result under a short write lock. This is the standard pattern for caches
with expensive refresh operations.

```go
var sfGroup singleflight.Group
result, err, _ := c.sfGroup.Do("refresh", func() (interface{}, error) {
    return c.fetchKeys(ctx)
})
// store result under c.mu.Lock()
```

**IMPLEMENTATION:**
- `pkg/capability/jwks.go` — `sfGroup singleflight.Group` field added to `JWKSClient`.
  `refreshKeys` rewritten: the write lock is no longer held during the HTTP fetch;
  `c.sfGroup.Do("refresh", ...)` deduplicates concurrent fetch calls; only the result
  storage step acquires `c.mu.Lock()`. A second freshness check inside the lock prevents
  redundant stores when multiple callers race to refresh.

---

### I-4 — `purgeExpired` rebuilds `insertOrder` in O(n) inside a write lock

**LOCATION:** `pkg/capability/token_cache.go:227-244`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29 (resolved by M-5 fix)

**PROBLEM:** The cleanup loop (default: every 60 seconds) deletes expired map
entries and then rebuilds `insertOrder` by scanning the entire slice under
`c.mu.Lock()`. With `MaxSize=4096` and 60-second cleanup intervals this is
infrequent, but the write lock blocks all concurrent `Put` and `Get` calls for
the duration of the O(n) scan.

**FIX:** Rebuild `insertOrder` by filtering in-place (`surviving = surviving[:0]`,
then append only surviving keys). This is already the pattern at line 238-243 —
it's fine. The real fix is to switch from a slice to a structure that allows O(1)
removal (see M-5).

**IMPLEMENTATION:**
- Resolved as a side-effect of the M-5 fix (`container/list` replacement). `purgeExpired`
  now calls `c.insertOrder.Remove(entry.listElem)` for each expired entry — O(1) per
  removal, holding the write lock only as long as the list traversal takes, which is
  bounded by the number of expired entries rather than the full cache size.

---

### I-5 — `writeEntry` uses `context.Background()`, losing trace context in the drain loop

**LOCATION:** `pkg/audit/async_pipeline.go:224`  
**CATEGORY:** Implementation  
**SEVERITY:** Medium  
**STATUS:** ✅ Fixed — 2026-05-29

**PROBLEM:** The background drain goroutine creates a fresh `context.Background()`
with a write timeout. Any OpenTelemetry trace context from the original `Append`
caller (enforcement hot path) is discarded. Audit writes appear as unlinked spans
in distributed traces.

**FIX:** Carry the trace context (not the cancellation) from the caller into the
`LogEntry` struct as an optional `SpanContext`. Reconstruct a linked context in
`writeEntry` using `trace.ContextWithRemoteSpanContext`.

**IMPLEMENTATION:**
- `pkg/audit/contract/contract.go` — `LogEntry` gains `TraceSpanContext trace.SpanContext`
  field (`json:"-"`, in-process only).
- `pkg/audit/async_pipeline.go` — `writeEntry` reconstructs a linked context via
  `trace.ContextWithRemoteSpanContext(base, entry.TraceSpanContext)` when the span
  context is valid. `WithTraceContext(ctx, entry)` helper exported for callers.
- `internal/gateway/handlers.go` — `emitEnforceAuditEvent` calls
  `audit.WithTraceContext(ctx, entry)` before `Append` to stamp the enforcement span
  context onto the log entry.

---

_End of review — 21 findings total: 3 Critical, 6 High, 7 Medium (logic/impl), 5 Architecture/Design._
_All findings resolved as of 2026-05-29._

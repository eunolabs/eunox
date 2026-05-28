# Architecture & Implementation Review

**Date:** 2026-05-28  
**Scope:** `pkg/`, `internal/agentruntime/`, `internal/gateway/`, `internal/minter/`  
**Reviewer:** Deep automated review

---

## How to read this document

Each finding lists:

| Field | Meaning |
|-------|---------|
| **Location** | File(s) and line numbers |
| **Category** | ARCHITECTURE · DESIGN · IMPLEMENTATION · LOGIC BUG |
| **Severity** | CRITICAL · HIGH · MEDIUM · LOW |
| **Problem** | What is wrong |
| **Consequence** | Worst-case observable impact |
| **Fix** | Recommended remediation |

Findings are ordered by severity within each category.

---

## CRITICAL

---

### C-1 — `PolicyCondition` silently allows every request

**Location:** `pkg/enforcement/handlers.go` lines 441–454  
**Category:** LOGIC BUG / SECURITY  
**Severity:** CRITICAL

**Problem:**  
`handlePolicy` builds a `PolicyCondition` from config and calls `evaluateCondition`, but `evaluateCondition` always returns `(true, nil)` — i.e. "allow" — because there is no concrete evaluation logic wired up. The condition object is constructed but its result is never tied to actual policy evaluation.

**Consequence:**  
Any `policy` condition in an enforcement rule is silently bypassed. An operator who believes policy-based rules are enforced is actually running with no enforcement at all for those rules. This is a full security bypass for the most general-purpose condition type.

**Fix:**  
Implement `evaluateCondition` to call the policy engine (OPA or equivalent). Add a test that demonstrates a policy returning "deny" actually causes `handlePolicy` to return a deny verdict.

---

### C-2 — `CustomCondition` silently allows by default

**Location:** `pkg/enforcement/handlers.go` lines 456–468  
**Category:** LOGIC BUG / SECURITY  
**Severity:** CRITICAL

**Problem:**  
`handleCustom` constructs the custom condition handler lookup but falls through to `return nil` (allow) for every case where the handler is absent or returns nil. There is no "deny-by-default" for unresolvable custom conditions.

**Consequence:**  
If an operator configures a `custom` condition whose handler is not registered (typo in handler name, handler not wired in DI, etc.), enforcement silently allows the request instead of failing safe. Attackers who can influence handler registration (e.g., via a plugin system) can neutralise custom conditions entirely.

**Fix:**  
If the handler name is configured but not found in the registry, return an explicit deny with an error: `"custom condition handler %q not found"`. Document the deny-by-default contract.

---

### C-3 — Condition bypass via absent context fields

**Location:**  
- `pkg/enforcement/handlers.go` lines 246–250 (`handleAllowedExtensions`)  
- `pkg/enforcement/handlers.go` lines 357–359 (`handleRecipientDomain`)  
- `pkg/enforcement/handlers.go` lines 296–298 (`handleAllowedTables`)  

**Category:** LOGIC BUG / SECURITY  
**Severity:** CRITICAL

**Problem:**  
Each of these condition handlers returns `nil` (allow) when the corresponding context field is absent from the request:

```go
// handleAllowedExtensions
if filePath == "" {
    return nil   // ← bypasses extension check entirely
}

// handleRecipientDomain
if len(req.Context.Recipients) == 0 {
    return nil   // ← bypasses domain check entirely
}

// handleAllowedTables
if len(req.Context.Tables) == 0 {
    return nil   // ← bypasses table check entirely
}
```

**Consequence:**  
A caller that omits `filePath`, `recipients`, or `tables` from its request bypasses the corresponding enforcement condition. This enables privilege escalation: a tool that is supposed to be restricted to `.py` files can operate on any file by omitting the filePath field; an email tool can send to any domain by omitting recipients; a DB tool can query any table by omitting tables.

**Fix:**  
Decide on a clear policy and enforce it:
- **Option A (deny when field absent):** Return a deny verdict — the condition cannot be evaluated without the field.
- **Option B (allow when field absent is valid):** Document explicitly that the condition only applies when the field is present, and audit all callers.

At minimum, log a warning when a configured condition is skipped due to absent context, so operators can detect misbehaving clients.

---

## HIGH

---

### H-1 — `ResilientRedis.started` data race in security-critical path

**Location:** `pkg/killswitch/resilient_redis.go` line 24 (field), line 38 (`Start`), line 59 (`ShouldBlock`)  
**Category:** IMPLEMENTATION  
**Severity:** HIGH

**Problem:**  
`started bool` is written by `Start()` and read by `ShouldBlock()` with no synchronisation (no mutex, no `sync/atomic`).

```go
type ResilientRedis struct {
    ...
    started bool   // ← no sync
}

func (r *ResilientRedis) Start(ctx context.Context) {
    r.started = true   // ← unsynchronised write
}

func (r *ResilientRedis) ShouldBlock(...) (bool, error) {
    if !r.started {    // ← unsynchronised read
        return true, nil
    }
    ...
}
```

**Consequence:**  
The Go memory model does not guarantee that the write in `Start()` is visible in `ShouldBlock()` on another goroutine. The Go race detector will flag this. In practice the race can cause `ShouldBlock` to see `started=false` after `Start()` has returned, causing all requests to be fail-closed (blocked) spuriously. Conversely it could be seen as `started=true` before initialisation completes, exposing unloaded state.

**Fix:**  
Use `sync/atomic` (`atomic.Bool`) or protect both the read and write with the existing mutex.

---

### H-2 — `AsyncPipeline.Close` double-calls `inner.Close()`

**Location:** `pkg/audit/async_pipeline.go` lines 151–160  
**Category:** IMPLEMENTATION  
**Severity:** HIGH

**Problem:**  
`Close()` drains the write-ahead channel and then calls `p.inner.Close()`, but this call is outside `p.once.Do`. If two goroutines call `Close()` concurrently, after the first `once.Do` completes (which closes the channel and signals the drain goroutine), both goroutines proceed to `p.wg.Wait()` and eventually both call `p.inner.Close()`.

```go
func (p *AsyncPipeline) Close() error {
    p.once.Do(func() {
        close(p.writeCh)
    })
    p.wg.Wait()
    return p.inner.Close()   // ← called by every concurrent closer
}
```

**Consequence:**  
Double-close of the inner pipeline. For `DefaultPipeline`, this closes the backend twice and may corrupt the HMAC chain state or cause a panic if the underlying backend does not tolerate double-close (e.g., a file handle or network connection).

**Fix:**  
Move `p.inner.Close()` inside `p.once.Do` (or use a separate `closeOnce`) so it executes exactly once. Return the inner close error from `once.Do` via a stored field.

---

### H-3 — `killswitch.Redis.Reset` ignores `deleteByPrefix` errors

**Location:** `pkg/killswitch/redis.go` lines 190–210 (`Reset`), lines 296–314 (`deleteByPrefix`)  
**Category:** IMPLEMENTATION  
**Severity:** HIGH

**Problem:**  
`deleteByPrefix` silently breaks on the first `SCAN` error, leaving keys undeleted. `Reset` calls it for agent and session key prefixes and ignores the returned error entirely. It then publishes "reset" and clears in-memory state regardless.

```go
func (r *Redis) Reset(ctx context.Context) error {
    _ = r.deleteByPrefix(ctx, agentKeyPrefix)    // ← error discarded
    _ = r.deleteByPrefix(ctx, sessionKeyPrefix)  // ← error discarded
    ...
    r.mu.Lock()
    r.killedAgents = make(map[string]struct{})
    r.killedSessions = make(map[string]struct{})
    r.mu.Unlock()
    return nil  // ← always succeeds from caller's perspective
}
```

**Consequence:**  
After a failed `Reset`, in-memory state reports "all clear" but Redis retains kill-switch keys. On the next service restart (or when the cache is refreshed from Redis), previously killed agents or sessions reappear as killed — a ghost kill-switch re-application. Operators will see inconsistent state with no indication that `Reset` partially failed.

**Fix:**  
Return the error from `deleteByPrefix`. Roll back in-memory state (or do not clear it) if the Redis deletion failed. At minimum surface the error so the caller can retry or alarm.

---

## MEDIUM

---

### M-1 — `TokenCache.Put` integer truncation causes stale token serving

**Location:** `pkg/capability/token_cache.go` (TTL computation in `Put`)  
**Category:** LOGIC BUG  
**Severity:** MEDIUM

**Problem:**  
TTL is computed using integer seconds:

```go
tokenRemaining := time.Duration(payload.ExpiresAt - now.Unix()) * time.Second
```

`now.Unix()` truncates sub-second time. If `ExpiresAt = now.Unix()` (token expires within the current second), `tokenRemaining` rounds to 0 or even negative, but `ExpiresAt - now.Unix()` is at worst 0. More importantly, a token with 0.9s remaining is cached with `tokenRemaining = 0`, which causes it to be inserted with TTL=0 — it is immediately eligible for purge but may still be returned by `Get` before `purgeExpired` runs.

In the gateway, `handleEnforce` and `handleProxy` serve tokens from cache without re-checking expiry after retrieval. This means a token that was valid at `Put` time but expired between `Put` and `Get` can be served.

**Consequence:**  
Capability tokens can be served up to ~1 second after their actual expiry. For most use cases this is acceptable, but for high-security deployments with short-lived tokens (TTL < 10s) this represents a meaningful window for replay of a revoked token.

**Fix:**  
- Use sub-second precision: `time.Until(time.Unix(payload.ExpiresAt, 0))`.
- In the gateway, re-validate token expiry after cache retrieval before serving.

---

### M-2 — `callcounter.Redis.IncrementAndGet` duplicate ZADD members undercount

**Location:** `pkg/callcounter/redis.go` line 32  
**Category:** LOGIC BUG  
**Severity:** MEDIUM

**Problem:**  
The sorted-set member is `fmt.Sprintf("%d", now.UnixNano())`. ZADD with an existing member updates its score rather than inserting a new entry. Under concurrent load, two calls in the same nanosecond (common on multicore systems) produce the same member string and the second ZADD overwrites the first.

Compare with `pkg/ratelimit/redis.go` which correctly uses:
```go
member = fmt.Sprintf("%d-%d", now.UnixNano(), l.seq.Add(1))
```

**Consequence:**  
The per-agent/per-tool call counter undercounts calls. This allows a tool to be invoked more times than the configured `MaxCalls` limit without triggering enforcement.

**Fix:**  
Add a monotonic sequence counter (e.g., `atomic.Int64`) and embed it in the member string, identical to the pattern in `ratelimit/redis.go`.

---

### M-3 — Empty `sessionID` creates cross-session shared `MaxCalls` counter

**Location:** `pkg/enforcement/engine.go` — `handleMaxCalls` key construction  
**Category:** LOGIC BUG  
**Severity:** MEDIUM

**Problem:**  
The counter key is:

```go
key := fmt.Sprintf("maxcalls:%s:%s", req.SessionID, req.ToolName)
```

When `req.SessionID` is empty, the key becomes `"maxcalls::toolname"`, a single counter shared across all sessions that omit the session ID. Any call from any session without a session ID increments the same counter.

**Consequence:**  
In multi-tenant deployments where session ID is optional or not yet assigned (e.g., during tool discovery or pre-authentication flows), calls from different tenants share the same `MaxCalls` budget. One tenant's calls exhaust another tenant's allowance (denial of service), or the check is completely ineffective because the counter is bounded per tool across all anonymous callers.

**Fix:**  
Validate that `req.SessionID` is non-empty before evaluating `MaxCalls` conditions. If empty, either deny with a clear error or skip `MaxCalls` enforcement and log a warning.

---

### M-4 — `DefaultPipeline.Append` sequence desync on ambiguous backend error

**Location:** `pkg/audit/audit.go` lines 305–312 (`DefaultPipeline.Append`)  
**Category:** LOGIC BUG  
**Severity:** MEDIUM

**Problem:**  
`Append` assigns an auto-incremented sequence number, calls `backend.Append`, and on error rolls back `lastSeqNum`. However, if `backend.Append` succeeds partially (network timeout after write commits, "write succeeded but acknowledgment lost"), the record exists in the backend with `seqNum = N`, but `lastSeqNum` is rolled back to `N-1`. The next call assigns `seqNum = N` again, creating a duplicate sequence number in the audit log.

Additionally, `Append` mutates the caller's `*LogEntry` in place (assigns `ID` and `Timestamp`), which violates the principle of least surprise for callers that re-use or log the same struct.

**Consequence:**  
- Duplicate sequence numbers break the HMAC chain integrity guarantees. The log can no longer be verified end-to-end.
- Callers that retain a reference to the `*LogEntry` see their struct mutated after `Append` returns.

**Fix:**  
- Use a two-phase commit pattern or an idempotency key to distinguish "write failed before persistence" from "write succeeded but ack lost". Consider using the entry's content hash as an idempotency key.
- Do not mutate the caller's struct; assign a copy or require the caller to pass a value type.

---

### M-5 — Production code imports test utility `pkg/testutil`

**Location:** `pkg/enforcement/engine.go` (import of `pkg/testutil`)  
**Category:** ARCHITECTURE  
**Severity:** MEDIUM

**Problem:**  
`pkg/enforcement/engine.go` imports `github.com/eunolabs/eunox/pkg/testutil` to use `testutil.Clock`. This creates a hard dependency from production enforcement logic on a package whose intended consumers are tests.

**Consequence:**  
- `pkg/testutil` is now compiled into every binary that includes `pkg/enforcement`. If `testutil` ever introduces test-only dependencies (e.g., `testing.T` helpers, mock frameworks), those will leak into production binaries.
- It signals unclear package boundaries: developers may add more test utilities to `testutil` without realising they are being pulled into production.
- Breaks the convention that `_test.go` files and `testutil` packages are excluded from production builds.

**Fix:**  
Move the `Clock` interface (and its real-clock implementation) to a production package, e.g., `pkg/clock`. Keep `testutil` for mock/fake implementations only. `pkg/enforcement` should depend on `pkg/clock`, and tests inject `testutil.MockClock`.

---

## LOW / DESIGN

---

### D-1 — `killswitch.Manager` interface violates Interface Segregation Principle

**Location:** `pkg/killswitch/manager.go` (Manager interface definition)  
**Category:** DESIGN  
**Severity:** LOW

**Problem:**  
The `Manager` interface combines read operations (`ShouldBlock`, `Status`) with write/admin operations (`ActivateGlobal`, `DeactivateGlobal`, `KillAgent`, `ReviveAgent`, `KillSession`, `ReviveSession`, `Reset`). Every consumer of the interface must accept all nine methods.

**Consequence:**  
- Components that only need to check `ShouldBlock` (e.g., the gateway hot path) are forced to depend on the full admin interface, making mocking harder and coupling higher.
- It is impossible to express "read-only access to the kill switch" in the type system.

**Fix:**  
Split into at least two interfaces:
```go
type Checker interface {
    ShouldBlock(ctx context.Context, agentID, sessionID string) (bool, error)
}

type Admin interface {
    Checker
    ActivateGlobal(ctx context.Context) error
    DeactivateGlobal(ctx context.Context) error
    KillAgent(ctx context.Context, agentID string) error
    ReviveAgent(ctx context.Context, agentID string) error
    KillSession(ctx context.Context, sessionID string) error
    ReviveSession(ctx context.Context, sessionID string) error
    Reset(ctx context.Context) error
    Status(ctx context.Context) (*Status, error)
}
```

---

### D-2 — `Dependencies.Engine` is a concrete type, not an interface

**Location:** `internal/gateway/app.go` — `Dependencies` struct  
**Category:** DESIGN  
**Severity:** LOW

**Problem:**  
`Dependencies.Engine` is `*enforcement.Engine` (a concrete pointer type) rather than an interface. The gateway is coupled to the exact implementation.

**Consequence:**  
- Testing the gateway requires constructing a real `enforcement.Engine` with all its dependencies, or monkey-patching.
- Substituting a different enforcement implementation (e.g., a remote enforcement service) requires changing the `Dependencies` struct and all call sites.

**Fix:**  
Define an `enforcement.Enforcer` interface with the methods the gateway actually calls (e.g., `Evaluate(ctx, req) (*Decision, error)`), and type `Dependencies.Engine` as `enforcement.Enforcer`.

---

### D-3 — `getOrCreatePartition` holds write lock while calling inner `ShouldBlock`

**Location:** `pkg/killswitch/partitioned.go` lines 264–283 (`getOrCreatePartition`)  
**Category:** DESIGN  
**Severity:** LOW

**Problem:**  
While holding `p.mu` (write lock), `getOrCreatePartition` calls `p.inner.ShouldBlock` to seed the initial kill state. This call is safe (inner uses a separate mutex), but it means all concurrent `ShouldBlock` callers on `PartitionedKillSwitch` are blocked for the duration of the inner call.

**Consequence:**  
Under high concurrency, the first `ShouldBlock` call for a new agent ID serialises all other callers behind an inner Redis or in-memory read. For the in-memory implementation this is negligible; for the Redis implementation this can add tens of milliseconds of latency to every concurrent request during a "new agent" partition creation event.

**Fix:**  
Create the `agentPartition` struct and insert it into the map under the write lock (as now), but seed the initial kill state outside the lock using a separate "loading" pattern (e.g., an `initialised chan struct{}` on `agentPartition` that `runAgentSubscription` closes after seeding state).

---

## Summary Table

| ID | Severity | Category | Location | One-line description |
|----|----------|----------|----------|----------------------|
| C-1 | CRITICAL | Logic Bug | `pkg/enforcement/handlers.go:441` | `PolicyCondition` silently allows all requests |
| C-2 | CRITICAL | Logic Bug | `pkg/enforcement/handlers.go:456` | `CustomCondition` silently allows when handler absent |
| C-3 | CRITICAL | Logic Bug | `pkg/enforcement/handlers.go:246,357,296` | Extension/domain/table conditions bypass via absent field |
| H-1 | HIGH | Implementation | `pkg/killswitch/resilient_redis.go:24` | `started` bool data race in `ShouldBlock` |
| H-2 | HIGH | Implementation | `pkg/audit/async_pipeline.go:151` | `inner.Close()` called outside `once.Do` → double-close |
| H-3 | HIGH | Implementation | `pkg/killswitch/redis.go:190` | `Reset` ignores `deleteByPrefix` errors, diverges state |
| M-1 | MEDIUM | Logic Bug | `pkg/capability/token_cache.go` | Integer truncation serves tokens ~1s past expiry |
| M-2 | MEDIUM | Logic Bug | `pkg/callcounter/redis.go:32` | Nanosecond ZADD member collision undercounts calls |
| M-3 | MEDIUM | Logic Bug | `pkg/enforcement/engine.go` | Empty `sessionID` creates cross-session shared counter |
| M-4 | MEDIUM | Logic Bug | `pkg/audit/audit.go:305` | Sequence desync on ambiguous backend error; entry mutation |
| M-5 | MEDIUM | Architecture | `pkg/enforcement/engine.go` | Production code imports `pkg/testutil` |
| D-1 | LOW | Design | `pkg/killswitch/manager.go` | `Manager` interface too large; violates ISP |
| D-2 | LOW | Design | `internal/gateway/app.go` | `Dependencies.Engine` is concrete type, not interface |
| D-3 | LOW | Design | `pkg/killswitch/partitioned.go:264` | Write lock held across inner `ShouldBlock` seed call |

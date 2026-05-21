# Change-Risk Report — euno-platform

> **Reviewer role:** Principal Software Architect  
> **Date:** May 2026  
> **Scope:** Highest change-risk ("fragile") areas in the euno-platform monorepo — code that is hard to modify without breaking something else.  
> **Artefacts reviewed:** `euno-platform/packages/tool-gateway/src/bootstrap.ts`, `src/app-factory.ts`, `src/admin-api.ts`, `src/enforcement.ts`, `public/packages/common/src/config/schema.ts`, `public/packages/mcp/src/cli.ts`, `src/policy/source.ts`, `src/transport/obligations.ts`

---

## Summary

| Area | File(s) | Blast Radius | Primary Issue | Priority |
|------|---------|--------------|---------------|----------|
| `GatewayDependencies` god-object | `bootstrap.ts`, `app-factory.ts` | **Critical** — all routes + tests | 40+ optional fields; silent 404 on missing wiring | P0 |
| `initializeServices()` monolith | `bootstrap.ts` | **Critical** — startup correctness | 13 mixed concerns; load-bearing ordering; unsafe cast | P0 |
| `admin-api.ts` god-module | `admin-api.ts` | **High** — all admin tests | 1 725-line file; hardcoded string→enum filter | P1 |
| `config/schema.ts` monolith | `common/src/config/schema.ts` | **Critical** — all config tests | 3 289-line single file for every service's schema | P1 |
| `enforcement.ts` string dispatch | `enforcement.ts` | **High** — security regression | No exhaustiveness on condition-type dispatch | P2 |
| `cli.ts` boolean-flag PDP mode | `mcp/src/cli.ts` | **Medium** — extensibility | `isRemoteMode` boolean; adding a 3rd mode rewrites block | P2 |
| `obligations.ts` implicit contract | `transport/obligations.ts` | **Medium** — data-leak risk | No type guard preventing calls with error results | P3 |

---

## P0 — Critical

### CR-R1 — `GatewayDependencies` is a god-object with 40+ fields ✅ FIXED

**Files:** `bootstrap.ts` (interface definition), `app-factory.ts` (consumers),  
`tests/app-factory.test.ts`, `tests/proxy.test.ts`, `tests/audit-route.test.ts`, `tests/audit-export.test.ts`, `tests/chain-proof.test.ts`, `tests/audit-signing-keys.test.ts`, `packages/integration-tests/tests/soc2-audit-export.test.ts`

**Why fragile:**  
`GatewayDependencies` is a single interface with ~40 fields spanning four distinct
responsibility groups: public-HTTP wiring (`metricsRegistry`, `rateLimitWindowMs`, …),
audit-chain state (`auditPipeline`, `ledgerPgPool`, `crossChainAnchor`, …), admin-route
wiring (`killSwitchManager`, `partnerRegistry`, `ocsfTransport`, …), and lifecycle/shutdown
bookkeeping (`config`, `adminPort`, `dpopReplayStore`, …).

Because all four groups are merged into one flat interface:

1. **`createApp()` advertises a superset of what it needs.** It doesn't use
   `killSwitchManager`, `adminPort`, or `partnerRegistry`, yet callers must populate
   those fields because the parameter type requires them.
2. **Routes are conditionally mounted based on field presence with no compile-time
   enforcement** (e.g. `if (auditQueryStore) app.use(createAuditRouter(…))`).  A missing
   field silently produces a 404 instead of a startup error.
3. **Every test that builds a minimal `deps` bag must reason about the entire interface**,
   even when the test exercises only one route family.
4. **Adding any new field cascades through every file** that constructs the bag
   (currently 7+ test files + the entrypoint + integration tests).

**Fix:** Split `GatewayDependencies` into four cohesive sub-interfaces and express the
full bag as their intersection:

```typescript
// Fields shared by createApp() and createAdminApp()
export interface CoreGatewayDeps { logger, verifier, trustProxy?, adminApiKey? }

// Fields used only by the public-facing Express app (createApp)
export interface PublicAppDeps { enforcementEngine, metricsRegistry, decisionsCounter,
  backendServiceUrl, allowedOrigins, rateLimitWindowMs, rateLimitMax, isReady?,
  region?, actionResolver, gatewayTelemetry?, sourceIpMode?,
  auditQueryStore?, auditLedgerBackend?, crossChainCommitmentStore?,
  auditSigningPublicKeyPem?, auditSigningKeyId?, auditSigningAlgorithm?,
  responseRedactionMaxBytes }

// Fields used only by the internal admin Express app (createAdminApp)
export interface AdminAppDeps { killSwitchManager, epochStore?, partnerResolver?,
  partnerRegistry?, requirePin?, pinAttestationSecret?, partnerDidAutoFetchPin?,
  adminTenantId?, ocsfTransport?, usageMeter?, auditRetentionDays?,
  killSwitchFailOpenOnWrite? }

// Fields used only by the entrypoint (index.ts) for lifecycle/shutdown
export interface LifecycleGatewayDeps { config, adminPort, adminHost?,
  auditPipelineDrainTimeoutMs, revocationStore?, callCounterStore?,
  evidenceSigner?, auditPipeline?, dpopReplayStore?, ledgerPgPool?,
  crossChainAnchor?, ledgerAclClient?, durablePostureEmitter? }

// Backward-compatible full bag (intersection of all four)
export type GatewayDependencies =
  CoreGatewayDeps & PublicAppDeps & AdminAppDeps & LifecycleGatewayDeps;
```

Update the factory signatures:
- `createApp(deps: CoreGatewayDeps & PublicAppDeps): Express`
- `createAdminApp(deps: CoreGatewayDeps & AdminAppDeps): Express`

All existing callers that pass `GatewayDependencies` continue to work because the
intersection satisfies both narrower types.

---

### CR-R2 — `initializeServices()` mixes 13 concerns and has implicit ordering ✅ FIXED

**File:** `bootstrap.ts` lines 857–1409

**Why fragile:**  
The single 550-line async function performs (in strict order):
config validation, logger creation, OCSF transport, metrics registry, 5 counters,
DPoP store, revocation/kill-switch/call-counter stores, 8 Prometheus gauges,
JWKS client pre-warm, action resolver + hash parity, JWT verifier, replica identity,
posture emitter, audit pipeline, gateway quota engine, enforcement engine, telemetry
collector, idempotency warning, security checks (CR-3/CR-4), and final bag assembly.

The ordering is **load-bearing**: the `redisErrorsCounter` created in Step 3 is captured by
a closure passed to `buildDpopModule()` in Step 4. Moving Step 4 before Step 3 silently
breaks the callback. There is no type-level or structural hint that Step 3 must precede
Step 4.

Two additional issues compound the fragility:

1. **Unsafe type cast** (line 1195):
   ```typescript
   const replicaIdFromEnv = (validated as { AUDIT_REPLICA_ID?: string }).AUDIT_REPLICA_ID;
   ```
   `AUDIT_REPLICA_ID` is already a declared field on `GatewayConfig` (added to the Zod schema); the cast is unnecessary and suppresses TypeScript's ability to catch renames.

2. **`partnerDidCircuitTransitionsCounter` pre-declare/late-assign** (lines 947, 979):
   A `let counter: Counter | undefined` is declared before `buildRevocationModule()`, then
   conditionally assigned inside the `if (partnerResolver)` block after the module returns.
   The counter callback passed into `buildRevocationModule` captures the `let` variable by
   reference — so the callback is wired before the counter exists. This works because JS
   closures capture by reference, but the pattern is invisible to readers and breaks if
   someone changes the declaration to `const`.

3. **Dynamic `require('os')`** (line 1199): `require('os')` with a cast instead of a top-level `import os from 'os'`.

**Fix (implemented):**
- Add `import os from 'os'` at the top of the file.
- Remove the unsafe cast; access `validated.AUDIT_REPLICA_ID` directly.
- Replace the pre-declare/late-assign pattern with an explicit mutable ref object.
- Extract `buildGatewayCounters(metricsRegistry, shardCount)` — a named function that
  creates all Counter objects and returns a typed record. Callers pass the record into
  store builders; the ordering contract is expressed by the function's return value rather
  than by positional proximity in a 550-line body.

**Concrete extract:**
```typescript
// Named helper — ordering is now expressed structurally, not by line proximity
function buildGatewayCounters(
  metricsRegistry: Registry,
  shardCount: number,
): GatewayCounters {
  const decisions = new Counter({ name: 'euno_gateway_decisions_total', … });
  const redisErrors = new Counter({ name: 'euno_gateway_redis_errors_total', … });
  const revocationUnavailable = new Counter({ … });
  const counterFallback = new Counter({ … });
  const usageMeterErrors = new Counter({ … });
  const shardMisrouted = shardCount > 1
    ? new Counter({ name: 'euno_gateway_shard_misrouted_total', … })
    : undefined;
  return { decisions, redisErrors, revocationUnavailable, counterFallback,
           usageMeterErrors, shardMisrouted };
}
```

---

## P1 — High

### H-R1 — `admin-api.ts` is a 1 725-line god-module

**File:** `euno-platform/packages/tool-gateway/src/admin-api.ts`

**Why fragile:**  
All seven admin endpoint groups (kill-switch, revocation, epochs, partner-DIDs, usage,
idempotency, OCSF) live in a single file with ~500 lines of duplicated error-handling
patterns. A hardcoded string-to-enum filter is the most fragile symptom:

```typescript
// line ~1424
const filter = (['proposed', 'active', 'revoked'].includes(statusParam ?? ''))
  ? statusParam as PartnerDidStatus : undefined;
```

Adding a new `PartnerDidStatus` value does **not** cause a compile error — the literal
array silently misses the new value and the filter silently drops it.

**Fix:** Replace the hardcoded literal array with `Object.values(PartnerDidStatus)` so
it auto-tracks the enum. Then split into per-group router files:
`admin-api/kill-switch.ts`, `admin-api/revocation.ts`, `admin-api/partner-dids.ts`,
`admin-api/usage.ts`. The root `admin-api.ts` becomes a thin assembler (~50 lines).

---

### H-R2 — `config/schema.ts` is a 3 289-line monolith

**File:** `public/packages/common/src/config/schema.ts`

**Why fragile:**  
Every service's env-var schema (issuer, gateway, minter, agent-runtime, future services)
is defined in one file. `superRefine` cross-field validators are interspersed throughout.
A merge conflict here touches every service simultaneously.

**Fix:** Split into `issuer-schema.ts`, `gateway-schema.ts`, `minter-schema.ts`, each
importing a shared `base-schema.ts`. The main `schema.ts` becomes a re-export barrel.

---

## P2 — Medium-High

### MH-R1 — `enforcement.ts` string-dispatches on condition types with no exhaustiveness check

**File:** `euno-platform/packages/tool-gateway/src/enforcement.ts`

Adding a new `CapabilityCondition` subtype produces no compiler error in the dispatch
logic. The failure mode is a silently unenforced policy condition — a security regression,
not just a bug.

**Fix:** `switch (condition.type)` with a `default: assertNever(condition)` exhaustiveness
helper, or a `Map<ConditionType, ConditionStrategy>` registry that validates at startup
that every registered condition type has a handler.

---

### MH-R2 — `cli.ts` uses a boolean flag for PDP mode selection

**File:** `public/packages/mcp/src/cli.ts`

```typescript
const isRemoteMode = enforcerUrl !== undefined;
if (isRemoteMode) { pdp = new RemoteEnforcerPDP(…); }
else if (options.policy) { pdp = new ConditionEnforcerPDP(…); }
else { pdp = new AlwaysAllowPDP(); }
```

Adding a third enforcement mode requires rewriting the entire conditional ladder.

**Fix:** Discriminated union `type EnforcementMode = { mode: 'local', … } | { mode: 'remote', … }`,
plus a pure `buildPdp(mode: EnforcementMode): PolicyDecisionPoint` factory.

---

## P3 — Medium

### M-R1 — `transport/obligations.ts` has an implicit pre-condition

**File:** `public/packages/mcp/src/transport/obligations.ts`

`applyRedactObligations()` silently no-ops when called with an error result; callers must
know to guard on `!result.isError` before calling. The type system does not enforce this.

**Fix:** Narrow the parameter type to `ToolCallResult & { isError?: false }` so the
compiler rejects calls that pass an error result.

---

## Recommended Execution Order

1. **CR-R1 + CR-R2** (this PR) — Highest leverage; removes the load-bearing ordering and the 40-field blast radius.
2. **H-R1** (next) — Enum filter hardening + file split.
3. **H-R2** — Schema split (large change; do as a dedicated PR with full config test suite run).
4. **MH-R1** — Exhaustiveness check (small change; add `assertNever` helper).
5. **MH-R2** — CLI discriminated union (medium; requires CLI test updates).
6. **M-R1** — Type narrowing for obligations (tiny; no test changes).

# Closing Capability Model Gaps: Analysis and Recommendations

> **Implementation note (April 2026):** The recommendations from this
> document have landed in code. See:
>
> - **Typed conditions:** `CapabilityCondition` discriminated union in
>   `euno-mcp/packages/common-core/src/types.ts` and the shared validate / enforce
>   pipeline in `euno-mcp/packages/common-core/src/condition-registry.ts`.
> - **Issuance-time validation:** `CapabilityIssuerService.issueCapability`
>   and `attenuateCapability` reject malformed or unknown conditions
>   before signing (`euno-platform/packages/capability-issuer/src/issuer-service.ts`).
> - **Gateway enforcement:** `EnforcementEngine.validateAction` in
>   `euno-platform/packages/tool-gateway/src/enforcement.ts` runs every typed
>   condition; unknown types deny by default.
> - **Distributed `maxCalls`:** `CallCounterStore` with in-memory and
>   Redis-backed implementations in
>   `euno-mcp/packages/common-core/src/call-counter-store.ts`, wired into the gateway
>   entrypoint via `createCallCounterStoreFromEnv` (reuses the same
>   `REDIS_URL` as the kill-switch / revocation-store wiring).
> - **Wildcard fix:** segment-aware `matchesResource` with scheme
>   equality enforcement in `euno-mcp/packages/common-core/src/utils.ts`.
> - **Action widening:** `Action = string` (legacy verbs preserved as
>   `LEGACY_ACTIONS`) so resource-specific verbs (`db:select`,
>   `s3:putObject`) are first-class.
>
> The project is pre-v1 with no production deployments; rather than
> introducing a `v2` tokens / migration window, the schema converged on
> a single strict format. Tokens issued before this change predate any
> deployment and do not need a compatibility shim.

## Problem Summary

The capability model in the current codebase declares fine-grained, conditional authorization but delivers shallow enforcement. Six interconnected gaps undermine the security guarantees the system is designed to provide:

1.  **Action granularity is too shallow.** The `Action` type is a fixed union of five generic strings (`read | write | execute | delete | admin`). Real authorization requires resource-specific verbs (`db.query`, `s3.PutObject`, `kafka.publish`). Forcing all backend operations into five categories either under-constrains ("everything is `execute`") or pushes semantic disambiguation outside the token, where the gateway cannot enforce it.

2.  **Conditions exist in the schema but are ignored at enforcement time.** `CapabilityConstraint.conditions?: Record<string, unknown>` is carried through token signing and issuance but the gateway's `isActionAllowed` function performs only resource-prefix + verb matching and completely skips condition evaluation. This is a **fail-open posture** for a security-critical field: the issuer can mint constraints the gateway has never heard of, and they will be silently dropped.

3.  **Wildcard semantics are simplistic.** Only trailing `/*` and `/**` are supported, both implemented identically as `startsWith(prefix)`. There is no path-segment distinction (a `/*` matches nested subdirectories the same as `/**`), no exclusion support, and no scheme or host validation at match time.

4.  **Structured validators are disconnected from the type system.** `capability-validators.ts` already implements semantic checks (allowed extensions, table/column allowlists, resource-pattern rules), but these are hard-coded and not reflected in the `conditions` type. The result is two parallel constraint systems — one explicit but inert (the `conditions` field), one implicit but enforced (the validators) — with no connection between them.

5.  **No issuance-time validation.** There is no schema check when a token is minted. Typos (`rate_limt`), wrong value types (`maxBytes: "10mb"` as a string), and unknown keys round-trip through signing into production tokens without error.

6.  **Forward-compatibility vs. safety tension.** `Record<string, unknown>` was likely chosen for extensibility, but the current system treats unrecognized conditions as no-ops. This is the opposite of safe: vendor extensions or future condition types will be silently ignored rather than triggering a denial.

These gaps collectively mean that the system gives the **appearance** of supporting conditional, fine-grained capabilities while actually enforcing only resource-prefix + verb matching. The single most dangerous consequence: a token issuer who believes they have restricted an agent's access (via conditions) has not actually done so.

***

## 1. Enriching the Action Model

### Current State

The five-action enum forces every backend operation into a generic category. A database `SELECT` and a database `DROP TABLE` both map to `execute`. An S3 `GetObject` and an S3 `DeleteBucket` both map to either `read` or `delete` depending on interpretation. This ambiguity defeats the purpose of least-privilege tokens.

### Existing Precedent in the Codebase

The Fine-grained Role claim Proposal already addresses this problem for a related system. It defines **"The Actions Scope — aka System Capability"** as actions powered by micro-services, describing action scopes at different granularity levels to enable the authorization model to express required action scopes precisely. The proposal includes a **Titan Capability JSON Schema** using a component-level bitmap approach — each microservice maps to a bit position, and the capability descriptor is the bitwise OR of all permitted component bits. This demonstrates that the engineering team has already recognized the need for finer-grained action modeling and built a working prototype in an adjacent system. [\[The Fine-g...m Proposal \| Word\]](https://microsoft.sharepoint.com/teams/AZCompute/_layouts/15/Doc.aspx?sourcedoc=%7B011E5192-E3D8-4F71-8DC7-02AA1C5F8CD7%7D&file=The%20Fine-grained%20Role%20claim%20Proposal.docx&action=default&mobileredirect=true&DefaultItemOpen=1)

### Recommended Approaches

| **Option**                          | **Mechanism**                                                                                                | **Pros**                                                         | **Cons**                                                                               | **Migration Risk**                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **A: Namespaced free-form strings** | Change `Action` from a union to `string`. Use `service:verb` convention (e.g., `db:select`, `s3:putObject`). | Maximum flexibility; aligns with cloud IAM patterns.             | Loses compile-time checking; typos become runtime failures unless validated.           | Medium — requires updating every package that switches on Action values. |
| **B: Sub-operation conditions**     | Keep the five generic actions but add an `allowedOperations` condition carrying resource-specific verbs.     | Minimal schema change; backward-compatible with existing tokens. | Mixes two concepts; `execute + allowedOps=[SELECT]` is less readable than `db:select`. | Low — existing code untouched; new logic added alongside.                |
| **C: Resource-type-aware actions**  | Add a `resourceType` field; validate actions against a registry of permitted verbs per resource type.        | Explicit, validatable, prevents misuse of generic actions.       | Requires defining and maintaining a resource-type registry; new field in every token.  | Medium — new field requires issuer and gateway changes.                  |

### Recommendation: Phase B → C

**Short-term (Option B):** Use the existing `conditions` field to carry `allowedOperations` arrays for resources that need sub-action specificity. This requires no schema changes — only enforcement logic in the gateway. Example:

```json
{
  "resource": "db://analytics/Customers",
  "actions": ["execute"],
  "conditions": { "type": "allowedOperations", "operations": ["SELECT", "UPDATE"] }
}
```

The gateway checks the agent's actual API call against `operations`. If the operation is not listed, the request is denied.

**Long-term (Option C):** Introduce a versioned `CapabilityConstraintV2` with explicit `resourceType` and a registry of permitted verbs per type. Resource URIs already use scheme prefixes (`file://`, `db://`, `s3://`), which can be parsed to infer resource type. The gateway maintains a map of valid actions per type, rejecting unknown combinations at both issuance and enforcement time.

**Acceptance Criteria:**

*   A token cannot authorize an operation not explicitly listed in its action set or `allowedOperations` condition.
*   The issuer rejects tokens with action/operation combinations that are invalid for the declared resource type.
*   Existing tokens using the five generic actions continue to function during the transition period.

***

## 2. Making Conditions Enforceable End-to-End

### The Core Problem

The gap between declared and enforced conditions is the most critical security deficiency. The signed-payload model from the Ghost Options Comparison establishes the architectural principle that should govern condition enforcement: **"user intent, scope, and parameters"** must be **"cryptographically bound into a signed request that downstream components can trust"** — and critically, **"a compromised agent cannot mint new requests or impersonate users, since it lacks signing material"**【5002†L854-L877】. Conditions in the capability token are exactly this kind of bound constraint. Ignoring them at enforcement time violates the core security property the system is built to provide.

### Recommended Changes

**Step 1 — Replace `Record<string, unknown>` with a discriminated union:**

Define a registry of supported condition types with explicit TypeScript interfaces:

```typescript
type CapabilityCondition =
  | { type: 'timeWindow'; notBefore?: string; notAfter?: string }
  | { type: 'ipRange'; cidrs: string[] }
  | { type: 'allowedOperations'; operations: string[] }
  | { type: 'allowedExtensions'; extensions: string[] }
  | { type: 'allowedTables'; tables: string[]; columns?: Record<string, string[]> }
  | { type: 'maxCalls'; count: number; windowSeconds: number }
  | { type: 'recipientDomain'; domains: string[] }
  | { type: 'redactFields'; fields: string[] }
```

Each type has a known structure the issuer can validate and the gateway can enforce. Unknown types cause **denial by default** in strict mode.

**Step 2 — Implement a `ConditionEvaluator` module in the gateway:**

For each supported condition type, implement an evaluation function:

| **Condition Type**  | **Evaluation Logic**                                     | **Required Context**                        |
| ------------------- | -------------------------------------------------------- | ------------------------------------------- |
| `timeWindow`        | Compare current timestamp against `notBefore`/`notAfter` | System clock                                |
| `ipRange`           | Check request source IP against CIDR list                | Request metadata                            |
| `allowedOperations` | Match requested operation against permitted list         | Tool call parameters                        |
| `allowedExtensions` | Check target file extension against list                 | File path from request                      |
| `allowedTables`     | Match query target against permitted tables/columns      | SQL parse or tool metadata                  |
| `maxCalls`          | Decrement counter; deny when exhausted                   | Per-capability counter (in-memory or Redis) |
| `recipientDomain`   | Check email recipient domain against allowlist           | Email tool parameters                       |
| `redactFields`      | Apply redaction to response before returning             | Response content                            |

In `isActionAllowed`, after the basic action/resource match passes, iterate through all conditions and require **every condition** to pass. If any condition fails or is unrecognized, deny the request.

**Step 3 — Add issuance-time validation:**

The Capability Issuer must validate conditions before signing:

*   Verify condition structure matches the expected schema for its declared type.
*   Reject unknown condition types (preventing round-tripping of unenforceable constraints).
*   Check logical consistency (e.g., `notAfter` must be after `notBefore`; `maxCalls` must be > 0).

This prevents the scenario where a typo or misconfiguration produces a token that *looks* restricted but is actually unconstrained.

**Step 4 — Consolidate existing validators:**

Audit `capability-validators.ts` and extract all implicitly supported constraints. Map each to a formal condition type:

| **Existing Validator**                        | **Proposed Condition Type**                        |
| --------------------------------------------- | -------------------------------------------------- |
| `validateFileExtension(capability, fileName)` | `allowedExtensions`                                |
| Table/column allowlist logic                  | `allowedTables`                                    |
| Resource pattern rules                        | Subsumed by improved wildcard matching (Section 3) |

Once migrated, remove the ad-hoc validators and route all constraint checking through the unified `ConditionEvaluator`.

**Step 5 — Handle the fail-open → fail-closed transition:**

Introduce a token version field to manage backward compatibility:

| **Token Version** | **Unknown Condition Behavior**      | **Use Case**                      |
| ----------------- | ----------------------------------- | --------------------------------- |
| `v1` (legacy)     | Silently ignored (current behavior) | Existing tokens during transition |
| `v2` (strict)     | Request denied; error logged        | All new tokens after migration    |

The issuer begins producing `v2` tokens once the gateway supports the corresponding conditions. During the transition period, both versions coexist. After a grace period, `v1` support is deprecated.

**Acceptance Criteria:**

*   A token with condition `{ type: 'timeWindow', notAfter: '2026-01-01T00:00:00Z' }` causes the gateway to deny requests after that timestamp.
*   A token with an unrecognized condition type (e.g., `{ type: 'foobar' }`) causes the gateway to deny the request in strict mode (`v2` tokens).
*   The issuer rejects a token mint request containing a condition with invalid structure (e.g., `maxCalls: "ten"` instead of a number).
*   Unit tests cover both permit and deny paths for each supported condition type.

***

## 3. Improving Wildcard and Resource Matching

### Current Behavior

Both `/*` and `/**` are implemented as `startsWith(prefix)`, which means:

*   `folder/*` matches `folder/file.txt` (intended) **and** `folder/sub/deep/file.txt` (unintended).
*   `folder/**` behaves identically to `folder/*`.
*   No path-segment boundary awareness exists — `folder/a` would match `folder/abc` if `folder/a` were used as a prefix.

### Recommended Semantics

| **Pattern** | **Current Behavior**                      | **Recommended Behavior**                                               |
| ----------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| `folder/*`  | Matches any path starting with `folder/`  | Matches exactly one path segment after `folder/` (no nested `/`)       |
| `folder/**` | Same as `folder/*`                        | Matches any depth of nesting under `folder/`                           |
| `folder/a*` | Matches any path starting with `folder/a` | Matches files in `folder/` whose names start with `a` (single segment) |
| No wildcard | Exact prefix match                        | Exact string match (the resource must match precisely)                 |

**Implementation:** Replace the `startsWith` check with a segment-aware matcher that splits resource strings on `/` and applies glob logic:

*   `*` matches any single segment (no `/` characters).
*   `**` matches zero or more segments.
*   The matcher should validate that the capability resource and the requested resource share the same URI scheme (e.g., `file://` vs `db://`) before comparing paths.

**Backward compatibility:** Existing tokens using `/*` or `/**` were created under prefix-match assumptions. If any existing tokens rely on the old (broader) behavior, treat them as `/**` (recursive) for `v1` tokens, and apply the new segment-aware semantics only to `v2` tokens.

**Acceptance Criteria:**

*   `resource = "folder/*"` authorizes `folder/file.txt` but **not** `folder/sub/file.txt`.
*   `resource = "folder/**"` authorizes both `folder/file.txt` and `folder/sub/deep/file.txt`.
*   `resource = "file://data/reports/*"` does not match `db://data/reports/table1` (scheme mismatch).

***

## 4. Unifying Validators with the Condition Registry

### Problem

The split between free-form `conditions` (declared but inert) and hard-coded validators (enforced but invisible in tokens) creates two problems:

*   **For auditors:** The token does not reflect the actual constraints applied. An auditor reading a token cannot know what restrictions are really in effect because some are enforced by code rather than by token content.
*   **For developers:** Adding a new constraint requires finding the right validator file and adding custom code, rather than declaring a condition in the token schema and having the gateway enforce it automatically.

### Recommendation

Create a **Condition Registry** — a single mapping from condition type names to their validation logic:

```typescript
const conditionRegistry: Map<string, ConditionHandler> = new Map([
  ['timeWindow', { validate: validateTimeWindow, enforce: enforceTimeWindow }],
  ['allowedExtensions', { validate: validateExtensions, enforce: enforceExtensions }],
  ['allowedTables', { validate: validateTables, enforce: enforceTables }],
  ['maxCalls', { validate: validateMaxCalls, enforce: enforceMaxCalls }],
  // ... additional types
]);
```

The **issuer** calls `validate` at mint time to confirm structure and logical consistency. The **gateway** calls `enforce` at request time, passing the condition data and the request context. Both components share the same registry, ensuring they agree on what conditions exist and what they mean.

The Capability Interface Isolation design already mandates that **"ALL sandbox interactions with external systems go ONLY through a controlled abstraction layer"** and **"are explicitly allowed, validated, and logged"** and **"cannot be bypassed by sandbox code"**【5003†L35-L39】. The condition registry is the mechanism that makes this mandate concrete for capability constraints: every constraint must be explicitly declared (in the token), validated (at issuance), logged (at enforcement), and non-bypassable (unknown conditions cause denial).

**For forward compatibility:** The registry supports a `custom` condition type for vendor extensions:

```typescript
| { type: 'custom'; name: string; config: unknown }
```

Custom conditions are treated as **deny by default** unless a corresponding handler is registered. This preserves extensibility while maintaining fail-closed safety — the exact inversion of the current `Record<string, unknown>` approach where unknown keys are silently ignored.

***

## 5. Migration Strategy and Token Versioning

### Phased Rollout

| **Phase**                    | **Timeline** | **Changes**                                                                                                                                                            | **Risk Controls**                                                                                 |
| ---------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **1: Instrumentation**       | Weeks 1–2    | Add logging to the gateway that reports when conditions are present but ignored. No behavioral changes.                                                                | Zero risk — purely observational. Reveals how many existing tokens carry unused conditions.       |
| **2: Strict Mode (opt-in)**  | Weeks 3–4    | Implement condition enforcement behind a `v2` token version flag. The issuer can produce `v2` tokens on request; the gateway enforces conditions for `v2` tokens only. | Low risk — `v1` tokens unchanged. Only explicitly opted-in agents use `v2`.                       |
| **3: Strict Mode (default)** | Weeks 5–8    | Switch the issuer's default to `v2` for new tokens. Existing `v1` tokens continue to work until they expire.                                                           | Medium risk — mitigated by short TTLs (tokens expire in minutes). Monitor for unexpected denials. |
| **4: Deprecation**           | Weeks 9–12   | Remove `v1` support. All tokens are `v2` with strict condition enforcement.                                                                                            | Low residual risk if Phase 3 has been stable.                                                     |

### Action Enum Migration

The `Action` type change (from a five-value union to an open string or richer structure) should follow the same phasing:

*   **Phase 1:** Widen the TypeScript type from `'read' | 'write' | 'execute' | 'delete' | 'admin'` to `string`, preserving the original five as named constants for backward compatibility.
*   **Phase 2:** Introduce resource-specific actions (e.g., `db:select`, `s3:putObject`) in `v2` tokens. The gateway validates these against a resource-type registry.
*   **Phase 3:** Deprecate the generic `execute` action for resources where specific verbs are available. Issue deprecation warnings when the issuer mints an `execute` token for a resource type that has a defined verb set.

### Rollback Plan

If condition enforcement causes unexpected failures:

*   The issuer can revert to `v1` tokens by configuration flag (no code deployment required).
*   The gateway can be switched to `v1`-only mode, restoring the current (ignore conditions) behavior.
*   Rollback telemetry: track the ratio of `v1` vs `v2` token issuance and the deny rate per condition type to detect regressions early.

***

## 6. Trade-off Analysis: Typed Conditions vs. Policy DSLs

| **Approach**                                                 | **Expressiveness**                                  | **Safety**                                                   | **Performance**                                                   | **Operational Complexity**                           | **Recommendation**                              |
| ------------------------------------------------------------ | --------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------- |
| **Typed discriminated union** (proposed)                     | Moderate — limited to predefined condition types    | High — unknown types cause denial; compile-time checking     | Excellent — simple data matching                                  | Low — no external dependencies                       | **Default choice**                              |
| **OPA/Rego sidecar**                                         | Very high — arbitrary policy logic                  | Medium — policy correctness depends on author                | Good — adds \~1–5ms per evaluation depending on policy complexity | High — requires deploying and managing OPA instances | Consider for future complex conditions          |
| **Cedar policy engine**                                      | High — attribute-based access with formal semantics | High — designed for authorization with formal analysis tools | Good — sub-millisecond for typical policies                       | Medium — requires Cedar runtime integration          | Consider if AWS alignment is strategic          |
| **External policy store** (conditions reference a policy ID) | Very high — any expressiveness the store supports   | Variable — depends on store implementation                   | Variable — adds network round-trip to policy store                | High — introduces a new critical dependency          | Avoid unless already operating a policy service |

**Recommendation:** Start with the typed discriminated union. It covers the identified use cases (time windows, data filters, rate limits, operation allowlists) with minimal complexity and maximum safety. If genuinely novel condition types emerge that cannot be expressed as structured data, add a `type: 'policyRef'` condition that references an external policy engine — but treat this as an escape hatch, not the default path.

The Ghost Options Comparison evaluation framework provides a useful lens for this decision. It assesses proposals across five dimensions: trust boundary strength, blast radius, replay resistance, autonomous enforcement authority, and audit quality【5002†L100-L157】. The typed union approach scores well on all five:

*   **Trust boundary:** High — conditions are cryptographically bound in the signed token.
*   **Blast radius:** Minimal — each condition narrows the scope of permitted actions.
*   **Replay resistance:** Strong — time-bound conditions expire automatically.
*   **Enforcement authority:** High — the gateway enforces conditions independently without consulting external services.
*   **Audit quality:** High — conditions are visible in the token and logged at enforcement time.

An external policy engine (OPA/Cedar) would score higher on expressiveness but lower on enforcement authority and audit quality, since policy evaluation becomes dependent on an external service and the token alone no longer contains the full authorization context.

***

## 7. Alignment with Internal Authorization Patterns

The GHOST Scenario Auth Design already implements a pattern that directly addresses several of the identified gaps. It introduces **structured authorization with a clear migration path from legacy role-based access to fine-grained claim-based authorization**【5001†L216-L218】. The design uses XML-based scenario definitions with explicit authorization claims and JIT role mappings:

```xml
<scenario scenarioname="GhostProcList">
  <authz>
    <claim type="role" value="ghost.executor"/>
  </authz>
  <jitrole>RdmOperator</jitrole>
</scenario>
```

【5001†L206-L210】

This pattern demonstrates that the team's adjacent systems already model authorization at a finer granularity than the capability model's five-action enum. The GHOST Authorization Model vNext provides **"deterministic authorization, supports both legacy and GHOST scenarios, and enables transition to RdmDiagnostics roles"**【5001†L199-L202】, with explicit guidance to **"log authorization paths, track fallback usage, monitor denylist hits, and identify scenarios missing authz"**【5001†L199-L200】.

The capability model should adopt the same patterns:

*   **Named, scenario-specific actions** (like `ghost.executor`) rather than generic verbs.
*   **Explicit authorization claim requirements** per capability rather than open-ended conditions.
*   **Migration support** with fallback tracking, so teams can identify capabilities that are still using legacy (generic) actions and migrate them incrementally.
*   **Operational logging** that distinguishes between "authorized via fine-grained condition" and "authorized via legacy broad action" to track migration progress.

***

## 8. Test Strategy

### Unit Tests

| **Test Category**              | **Example Test Case**                                                                                                        | **Expected Result**                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **Action granularity**         | Token: `actions: ["execute"], conditions: [{ type: "allowedOperations", operations: ["SELECT"] }]`. Agent attempts `INSERT`. | Gateway denies with `OperationNotPermitted`.                             |
| **Condition enforcement**      | Token: `conditions: [{ type: "timeWindow", notAfter: "2026-01-01T00:00:00Z" }]`. Request at `2026-01-02`.                    | Gateway denies with `ConditionNotSatisfied: timeWindow expired`.         |
| **Unknown condition**          | Token (`v2`): `conditions: [{ type: "unknownFuture", config: {} }]`.                                                         | Gateway denies with `UnrecognizedConditionType`.                         |
| **Unknown condition (legacy)** | Token (`v1`): `conditions: [{ type: "unknownFuture", config: {} }]`.                                                         | Gateway allows (backward-compatible ignore). Deprecation warning logged. |
| **Wildcard segment**           | Token: `resource: "folder/*"`. Agent requests `folder/sub/file.txt`.                                                         | Gateway denies (single-segment wildcard does not match nested path).     |
| **Wildcard recursive**         | Token: `resource: "folder/**"`. Agent requests `folder/sub/deep/file.txt`.                                                   | Gateway allows (recursive wildcard matches any depth).                   |
| **Issuance validation**        | Mint request: `conditions: [{ type: "maxCalls", count: "ten" }]`.                                                            | Issuer rejects with `InvalidConditionSchema: count must be number`.      |
| **Cross-scheme mismatch**      | Token: `resource: "file://data/*"`. Agent requests `db://data/table1`.                                                       | Gateway denies (scheme mismatch).                                        |

### Integration Tests

*   **End-to-end issuance and enforcement:** Issue a `v2` token with multiple conditions (time window + allowed operations + max calls). Simulate an agent making requests that satisfy all conditions (expect allow), then requests that violate each condition individually (expect deny for each).
*   **Delegation with conditions:** Parent token has `maxCalls: 100`. Attenuated child token has `maxCalls: 50`. Verify the child is denied after 50 calls even though the parent allows 100.
*   **Upgrade path:** Issue a `v1` token with conditions. Verify the gateway logs a deprecation warning but allows the request. Then switch the gateway to `v2`-only mode and verify the same conditions are now enforced.

### Security Tests

*   **Condition injection:** Attempt to add a condition to a signed token without re-signing. Verify the gateway rejects the token (signature invalid).
*   **Condition removal:** Attempt to strip conditions from a signed token. Verify the signature check fails.
*   **Race condition on maxCalls:** Simulate concurrent requests to verify the counter is atomic and does not allow over-limit usage.

***

## 9. Summary: Recommended Minimal-Change Plan vs. High-Assurance Plan

| **Dimension**              | **Minimal-Change Plan**                                                                | **High-Assurance Plan**                                                                                                                         |
| -------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Action model**           | Keep five-action enum; add `allowedOperations` condition for sub-actions               | Introduce `resourceType` field and resource-type-specific verb registries; deprecate generic `execute`                                          |
| **Condition enforcement**  | Implement `ConditionEvaluator` for 5–6 core condition types; add `v2` token versioning | Full discriminated union with compile-time exhaustiveness checking; JSON Schema validation at issuance; external policy engine integration path |
| **Wildcard semantics**     | Implement segment-aware `*` vs `**` distinction                                        | Add scheme validation, path-boundary enforcement, and optional mid-path wildcards                                                               |
| **Issuance validation**    | Add structural schema checks for known condition types                                 | Full JSON Schema validation with machine-readable error reporting; automated manifest generation from agent code analysis                       |
| **Backward compatibility** | `v1`/`v2` token versioning with configurable strict mode                               | Same, plus automated token migration tooling and deprecation dashboards                                                                         |
| **Timeline**               | 4–6 weeks                                                                              | 10–12 weeks                                                                                                                                     |

The **minimal-change plan** closes the most dangerous gap (conditions ignored at enforcement) with the least disruption. The **high-assurance plan** builds a sustainable, extensible capability model suitable for cross-organizational use and formal security analysis.

Both plans share the same foundational principle, established in the Ghost Options Comparison's key promises: **"User intent must be bound (what scenario, what scope, what time)"** and **"All actions must be auditable and attributable"**【5002†L60-L65】. The current implementation satisfies neither promise for conditional constraints. These plans close that gap.

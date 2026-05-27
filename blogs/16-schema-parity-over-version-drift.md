# Schema Parity Over Version Drift: Keeping the YAML Format Honest

_Second post in the "Design principles" series. [Post 15](./15-fail-closed-not-fail-open.md) covered the fail-closed principle that shapes every layer of the system. This post covers a different principle: why the policy contract is defined exactly once and shared everywhere, and what the BSL-1.1 licensing model has to do with it. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

I want to tell you about a bug I haven't had, and explain why I haven't had it.

The bug would go like this: you're running `eunox-mcp` locally. You write a policy YAML, it validates cleanly, the agent works. Then your organization migrates to the hosted gateway. You upload the same YAML, and the gateway interprets one of the fields slightly differently than the local proxy did — maybe a condition type name, maybe the semantics of a field that one implementation treats as optional but the other treats as required. The agent starts behaving differently in production than it did in development. You spend a week debugging before realizing the two environments have diverged.

This is the version drift problem. I've seen it destroy trust in multi-tier systems. Once you've experienced it, you spend real engineering effort preventing it.

The design choice that prevents it in eunox is deliberately boring: the entire capability manifest schema — every field, every condition type, every validation rule — is defined in exactly one place, shared by every component that processes it.

---

## The single source of truth

The `AgentCapabilityManifest` type, the `CapabilityCondition` union, the `ArgumentSchema` definition, and the capability-token claims all live in shared Go packages under `pkg/`. That's it. One set of packages, one module, one definition.

Every consumer of the schema imports from there:

- `eunox-mcp` — the local CLI proxy
- `cmd/gateway` — the hosted enforcement engine
- `cmd/issuer` — the token minting service
- Runtime adapters and enforcement helpers under `internal/`
- Other binaries under `cmd/` that need to parse or validate the manifest

None of them define their own version of the manifest type. None of them have a "compatibility shim" that translates between slightly different field names. They all import the shared Go types from `pkg/` and use them directly.

The consequence: when you write a policy YAML against `eunox-mcp` and that YAML validates against the shared manifest types, you know it will be interpreted identically by any other component built from the same Go module version. The gateway doesn't have its own interpretation of `allowedOperations`. The issuer doesn't have a slightly different read on what `maxCalls.windowSeconds` means. They all use the same code.

---

## Why this is harder than it sounds

"Just share the types" sounds like a trivial recommendation. In practice, it requires conscious ongoing effort to resist three pressures that push toward divergence.

**Pressure 1: performance optimizations.** The hosted gateway processes thousands of tokens per second. There's always a temptation to replace the shared schema validation with a hand-written fast path in the gateway code that checks only the fields the gateway cares about and skips the rest. This produces a gateway that's slightly faster but validates slightly differently from the issuer. Now you have two implementations that agree in the happy path and disagree on edge cases.

The answer in eunox is to keep the shared validator on the critical path and optimize it rather than replace it. The manifest and argument validation helpers in `pkg/` are exactly the modules that have received the most optimization attention — they're not slow because they're the bottleneck.

**Pressure 2: incremental feature additions.** You add a new condition type. You add it to the shared packages under `pkg/`, and then... need to rebuild and redeploy every consumer before the new condition type is useful. That deployment coordination is friction. The temptation is to "temporarily" add the new condition type handling directly to the gateway, deploy, test it in production, and then "later" promote it into the shared Go packages.

Later rarely comes. The "temporary" gateway addition becomes permanent. Now the gateway handles a condition that the local proxy doesn't validate correctly, and you've created the exact class of divergence you were trying to prevent.

The answer: new condition types go to `pkg/` first, always. The module version is bumped. All consumers are updated in coordination. This is a discipline, not a process you can automate around.

**Pressure 3: schema evolution in production.** The token schema version (`CAPABILITY_TOKEN_SCHEMA_VERSION`) exists precisely to manage breaking changes to the manifest shape. When a new field is added with breaking semantics, you bump the version, add the new version to `SUPPORTED_SCHEMA_VERSIONS`, and deploy in a coordinated window. The fail-closed schema version check (from [post 15](./15-fail-closed-not-fail-open.md)) means that tokens with an unknown schema version are rejected, which forces coordination.

But there's a more subtle category: non-breaking additions. Adding an optional field to `CapabilityConstraint` doesn't change the schema version. It doesn't break any existing token. But it does change the shape that the validator knows about. An old local proxy that pre-dates the new field will still validate tokens correctly for the fields it knows about — it just won't validate the new optional field. That's a gray area.

The rule I've settled on: anything that has semantic enforcement implications must be reflected in the shared schema with a corresponding validator test, not just added as an undocumented field. If the gateway would evaluate it differently from the local proxy, it's a breaking change even if it's additive.

---

## What lives in `pkg/`

Let me be specific about what the package contains, because it's the right scope for this discussion.

The shared Go packages under `pkg/` contain:

- **Manifest and token types**: The capability manifest structs, condition structs, argument-schema definitions, capability-token claims, and the schema-version constants.

- **Runtime interfaces**: The condition-registry interfaces, token-verifier interfaces, request context, and audit entry contracts that implementation code fulfills.

- **The condition registry**: The shared registry mapping condition type strings to handler implementations, plus the built-in condition handlers. This is the same code the local proxy and the gateway both use.

- **The argument validator**: The `ValidateArguments()` helper that checks tool-call arguments against an `ArgumentSchema`. Same function, same behavior, in every consumer.

- **The manifest validator**: The `ValidateManifest()` helper that checks a raw YAML-parsed object against the capability-manifest shape.

Those last three are the critical ones. The type definitions catch programmer errors at compile time, but the registry and validators are the executable logic. Sharing those means sharing not just the shape of the data but the semantics of the evaluation.

---

## The argument schema is a contract, not documentation

One thing I want to emphasize about `ArgumentSchema`: it's not documentation of what the tool expects. It's a contract that the gateway enforces.

When you write:

```yaml
capabilities:
  - resource: "api://db/query"
    actions: ["execute"]
    argumentSchema:
      type: object
      properties:
        query:
          type: string
          maxLength: 4096
        parameters:
          type: array
          maxItems: 20
      required: [query]
      additionalProperties: false
```

...you're not just documenting that the `query_db` tool takes a `query` string. You're specifying a constraint that the gateway will evaluate and enforce. If the agent passes a `query` that's 5000 characters, the gateway rejects the call. If the agent passes an extra field not in `properties`, the gateway rejects the call (because `additionalProperties` defaults to `false`).

The enforcement is done by `ValidateArguments()` from the shared Go packages under `pkg/`. The same function runs in:

- The `eunox-mcp validate` CLI command, when you're testing your policy locally before deployment
- The issuer service, which validates the schema at token mint time
- The gateway enforcement engine, which validates arguments at call time

This means a schema that passes `eunox-mcp validate` locally is the same schema the gateway will evaluate. There's no "local mode" vs "production mode" interpretation. The evaluation is identical because the evaluator is identical.

This property is what makes `eunox-mcp validate` a meaningful development tool rather than a linter that approximates what production does.

---

## The license model

Here's where the architecture intersects with the business model.

The Go-first implementation lives in one module — `github.com/edgeobs/eunox` — and the server-side components ship under BSL-1.1. That includes the gateway, issuer, minter, and the shared enforcement code they depend on. The practical boundary isn't an npm package split anymore; it's that every binary imports the same shared packages from `pkg/`.

The reason that matters for schema parity is straightforward: the manifest contract is compiled from one place. An operator writing policy YAML, a developer integrating `eunox-mcp`, and the hosted services under `cmd/` are all using the same Go types and validators. If you change the contract, you change it once in `pkg/`, and every consumer picks it up through the same module version.

The practical benefit: security teams can audit the actual enforcement contract in the repository. They can inspect the shared types, the condition registry, and the manifest validator that every binary uses. They're not trusting a separate SDK view of the system that might drift from production.

---

## The `eunox-mcp validate` CLI as a schema contract test

One of the things I'm most glad exists is the `eunox-mcp validate` command. On the surface it looks like a linter — you point it at a policy YAML and it tells you if the policy is valid. But the value isn't the linting. It's the _guarantee_ that the same validator runs in development and production.

Before I had `eunox-mcp validate`, policy authors had two paths to find out whether their policy was valid: test it locally with `eunox-mcp` (which might have a slightly different implementation from the gateway) or deploy to staging and wait for errors. Neither was great.

With `eunox-mcp validate` calling the same `ValidateManifest()` helper from the shared Go packages that the gateway uses:

```bash
$ eunox-mcp validate ./policy.yaml
✓ Manifest schema: valid
✓ Conditions: 4 conditions, all types recognized
✓ Argument schemas: 3 capabilities with explicit argument schemas
✓ Schema version: 1.0 (supported)

No issues found.
```

...the developer gets a deterministic answer. Not "this looks probably fine based on local tests" but "this is what the gateway will do with this policy." That changes the development loop. You can write policies locally, validate them, be confident they'll behave identically in staging and production.

The `eunox-mcp validate` command has a `--explain` flag that shows the full evaluation path — which conditions were checked, what the condition handler received, what it returned. That flag is specifically designed for debugging condition violations during development, before the policy ever sees a real tool call.

---

## Schema evolution in practice: the `schemaVersion` story

Let me walk through a concrete example of how schema evolution works to illustrate why the schema version check matters.

When the first version of the capability token format shipped, the `conditions` field on `CapabilityConstraint` didn't exist. There were no typed conditions — capabilities had `resource`, `actions`, and an optional `metadata` blob. The enforcement engine checked resource and action and either allowed or denied. Simple, but limited.

When typed conditions were introduced (the current architecture), we had to add `conditions` to `CapabilityConstraint` and add the `ConditionRegistry` to the enforcement path. This was a schema change with enforcement implications: a gateway running the old code couldn't correctly enforce a token with typed conditions. It would either ignore the conditions (fail-open) or fail to parse the token entirely.

The answer was `schemaVersion: "1.0"` — the first version that included typed conditions — and an explicit allowlist in `SUPPORTED_SCHEMA_VERSIONS`. Old gateways (pre-typed-condition) would see `schemaVersion: "1.0"` and reject the token because they only supported the original schema. New gateways process it correctly.

This created a migration requirement: before minting tokens with typed conditions, you need all gateways in the fleet to be updated to support schema version 1.0. The fail-closed schema version check enforces this: mixed fleets fail closed on the tokens they can't handle, which makes the upgrade requirement visible immediately rather than silently processing tokens incorrectly.

The lesson from this migration: **schema versioning is not just for humans**. The `schemaVersion` field is machine-enforced. You can't accidentally deploy a mixed fleet and have it quietly work wrong. The enforcement boundary rejects what it can't handle.

---

## What happens when you add a custom condition

The condition registry (`ConditionRegistry`) supports runtime registration of custom handlers:

```go
registry.Register("my-data-classification", func(condition CustomCondition, context RequestContext) Decision {
    classification := context.RequestMetadata["dataClassification"]
    if slices.Contains(condition.AllowedClassifications, classification) {
        return Decision{Allowed: true}
    }
    return Decision{Allowed: false, DenialCode: "classification_denied"}
})
```

When you do this, you're extending the shared registry. The local proxy, the in-process runtime guards, and the gateway will all use the registered handler if they've loaded the same registration code. The key constraint: you have to register the handler in every consumer that processes tokens with your custom condition. If you register it in the gateway but not in the local proxy, `eunox-mcp validate` will correctly reject policies that use your custom condition (because the registry doesn't know about it at validate time). That failure is intentional — it surfaces the registration gap before you deploy.

The `CustomCondition` type lives in the shared Go packages under `pkg/`, alongside the rest of the manifest contract. That means your custom condition definitions and the registry that evaluates them stay attached to the same module version every binary uses.

---

## The practical test: try to make the two implementations disagree

One of the tests I run mentally when making changes to `pkg/` is: can I construct a YAML policy that behaves differently under `eunox-mcp validate` vs. the gateway? If the answer is yes, there's a divergence to fix.

The test suites around `pkg/` and `cmd/gateway` have explicit parity tests for this: take a set of policy fixtures, run `ValidateManifest()` on each, and then run the same fixtures through the gateway enforcement engine as test requests and verify the outcomes match. If a policy fails validation, the corresponding request should be denied at the gateway. If it passes validation, the request should be allowed (assuming a valid token and the right resource/action match).

These aren't 100% comprehensive — there are enforcement decisions that involve distributed state (call counters, kill switch) that the unit validator can't replicate. But for the static structure of the policy, they provide a regression test that would catch a divergence before it reached production.

---

## Looking back at the Go integrations

One concrete example of where schema parity mattered: when the Go runtime integrations under `internal/` were wired up, we needed manifest validation to be exactly the same as what the local proxy and gateway do. The fix wasn't to maintain adapter-specific validation logic. It was to replace those checks with the shared `ValidateManifest()` helper from `pkg/`.

Before that helper was shared everywhere, integration code could make slightly different assumptions about optional fields. The fix wasn't to tweak every adapter one by one. It was to route them all through the shared function. One call, same behavior, no divergence.

That's the design principle in miniature: when you find yourself writing a second implementation of something that already exists in `pkg/`, stop and ask whether you can use the existing implementation instead.

Usually you can. The times when you can't are usually signals that `pkg/` is missing an abstraction that should be promoted from the consumer code to the shared package. Those promotions are how the package has grown over time — not by accumulating bloat, but by accumulating the semantics that genuinely need to be shared.

---

_Previous: [post 15 — Fail closed, not fail open: the most important decision in security software](./15-fail-closed-not-fail-open.md). Next: [post 17 — Declarative, not transitive: the partner federation trust model](./17-declarative-not-transitive.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

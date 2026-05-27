---
title: "Fail Closed, Not Fail Open: The Most Important Decision in Security Software"
description: 'First post in the "Design principles" series. The previous series — "Architecture deep-dives" — ended with [post 14 on AGT](./14-agt-defense-in-depth.md), the in-process guard that sits inside the agent. This post zooms out from implementation details and examines the single design principle that shapes every layer of eunox: when something unexpected happens, what should the system do? See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.'
pubDate: "2026-06-03"
---

_First post in the "Design principles" series. The previous series — "Architecture deep-dives" — ended with [post 14 on AGT](./14-agt-defense-in-depth.md), the in-process guard that sits inside the agent. This post zooms out from implementation details and examines the single design principle that shapes every layer of eunox: when something unexpected happens, what should the system do? See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

There's a moment in every security system's history where someone asks the question: "What happens when this breaks?" And the answer to that question tells you more about the security properties of the system than almost anything else in the design.

I want to talk about that question in the context of eunox, because fail-closed vs fail-open is not a choice you make once and move on. It's a philosophy that has to be re-applied at every layer, at every point where the system can encounter an unexpected state. And I've seen this go wrong — in other systems, in early versions of this one — in ways that were both subtle and catastrophic.

Let me start with some history before I get into the specifics of how eunox handles it.

---

## The classic failure

In 2012, a widely-deployed web application firewall had a behavior that didn't make headlines until years later: when the WAF's rule database failed to load at startup, the WAF entered a "degraded" mode that still accepted traffic. It just didn't apply any rules. The application behind it kept running. Users didn't notice anything. The operations team didn't notice anything — the health check still returned 200. The WAF was there. It was just not doing anything.

This is the canonical fail-open failure mode. The system exists, responds, reports itself as healthy, and silently does nothing useful.

I'm not singling out WAFs. The same pattern shows up in certificate validation code that returns `true` when the certificate check throws an exception ("fail-open, just log the error"). It shows up in authorization middleware that permits the request when the policy store is unreachable ("fail-open, the store might be a transient blip"). It shows up in rate-limiting infrastructure that falls back to unlimited when Redis is unavailable ("fail-open, don't break the user experience").

Each of these decisions has a justification. Each is, in some sense, a reasonable product choice. And each of them, when exploited, produces an incident that the security team has to explain to a regulator with a straight face.

---

## The choice eunox makes everywhere

Every place in eunox where something can go wrong — an unexpected input, an unavailable dependency, an unknown extension point, a malformed token — has the same default answer: **deny**.

This isn't a policy you configure. It's baked into the enforcement architecture at multiple levels. Let me walk through the specific cases because the categories are different and they're each worth understanding.

---

## Unknown conditions fail closed

This is the one I'm most proud of because it's the easiest to get wrong. [Post 10 covered the enforcement engine](../../blogs/10-tool-gateway-reference-monitor.md) in detail, but the key point for this discussion is how the condition registry handles a condition type it doesn't recognize.

When the gateway evaluates a capability token, it iterates over the token's conditions and evaluates each one against the incoming request. The conditions are typed: `allowedOperations`, `maxCalls`, `allowedTables`, `timeWindow`, `ipRange`, and so on. The registry maps each type string to a handler function that performs the evaluation.

What happens when the token contains a condition type that the gateway's registry doesn't recognize? The tempting answer is "skip it and continue" — maybe it's a new condition type from a future version of the platform that this older gateway doesn't know how to evaluate. Skipping unknown conditions lets the rest of the evaluation proceed; the call might be allowed.

The correct answer is: **reject the token immediately**.

```typescript
// From condition-registry.ts
if (!this.handlers.has(condition.type)) {
  return {
    allowed: false,
    denialCode: "unknown_condition_type",
    reason: `Condition type '${condition.type}' is not registered in this enforcement engine`,
  };
}
```

An unknown condition is not a benign unknown. It's a constraint that this gateway cannot evaluate. If the token was issued with that constraint, the issuer intended it to be enforced. Running the token without enforcing all of its conditions is silently weakening the policy. The safe behavior — the only secure behavior — is to deny the call and let the operator know that there's a schema mismatch between the issuer and the gateway.

In practice, this catches a specific attack scenario: a token where the attacker has modified the condition type string to something that looks like a real condition but isn't recognized, hoping to bypass the evaluation. With fail-closed unknown-condition handling, that attempt produces a hard denial rather than a silent pass-through.

It also means that when you deploy a new condition type across a fleet of gateways, you need to ensure all gateways have the updated registry before minting tokens with that condition type. That's a minor operational constraint. It's much better than the alternative.

---

## Malformed tokens fail closed

A JWT that fails signature verification is an obvious denial. But there are more subtle failure modes in JWT processing that some implementations handle... optimistically.

A few categories eunox specifically handles as hard failures:

**Clock skew beyond tolerance.** If the token's `nbf` (not-before) or `exp` (expiration) claims put it outside the validity window plus the configured clock-skew tolerance, the token is rejected. There's no "just a few extra minutes, probably fine" tolerance beyond the configured window. The default tolerance is five minutes; operators can narrow it but not widen it beyond fifteen minutes. A token that's expired is expired.

**Missing required claims.** The `AgentCapabilityManifest` JWT format has required fields: `sub`, `iss`, `aud`, `jti`, `iat`, `exp`, `capabilities`, `schemaVersion`. If any of those are absent or malformed, the token is rejected. We don't try to "fill in defaults" for missing claims or treat `null` as equivalent to some expected value. The token is malformed; deny.

**Unknown schema versions.** This one is worth calling out specifically. The token payload carries a `schemaVersion` field, and the gateway maintains an explicit set of supported versions (`SUPPORTED_SCHEMA_VERSIONS` in the `pkg/manifest` Go package). A token with a schema version outside that set is rejected — even if everything else looks valid.

```typescript
export const SUPPORTED_SCHEMA_VERSIONS: ReadonlySet<string> = new Set([
  CAPABILITY_TOKEN_SCHEMA_VERSION, // currently "1.0"
]);

// At enforcement time:
if (!SUPPORTED_SCHEMA_VERSIONS.has(payload.schemaVersion)) {
  return deny("unsupported_schema_version");
}
```

This means you cannot accidentally run a v1.0 gateway against v2.0 tokens and have enforcement silently proceed as if the token were fine. The gateway rejects it explicitly, the operator gets a clear error, and the version mismatch is surfaced before it can cause a policy gap.

The flip side of this is operational: rolling out a new schema version requires coordinating the gateway upgrade before minting tokens with the new version. That coordination cost is real. I'd rather have that coordination cost than have a fail-open path where a token the gateway doesn't understand gets treated as if it were trusted.

---

## Gateway unavailability fails closed

This is the one that generates the most pushback from product teams. The conversation goes something like: "If the gateway goes down, the agents stop working. That's bad for the user experience. Surely we can have a fallback mode?"

No. No fallback mode.

When the tool gateway is unreachable, tool calls fail. Full stop. This is not a bug; it's the intended behavior and it follows directly from the security architecture.

The gateway is the enforcement boundary. Every tool call is a request that has not yet been authorized. The gateway is the thing that authorizes it. Without the gateway, you don't have "no authorization check" — you have "no authorization at all." Those are different states. "No authorization" means _nothing checked the call_. That's a security failure, not a availability trade-off.

I've thought hard about whether there's a principled way to build a "local policy cache" fallback — where the agent retains a copy of the most recently evaluated policy and uses it when the gateway is unreachable. The problem is that "most recently evaluated policy" is stale the moment the gateway goes down. The gateway might have been going down _because_ an operator was activating a kill switch. The most recent policy might be the thing you most urgently need to stop enforcing.

There's also the revocation problem. The gateway checks the revocation list on every call (through the in-memory `RevocationStore` backed by Redis). A local fallback has no way to check revocation in real time. A token that was revoked thirty seconds before the gateway went down would be treated as valid by the local fallback. That's unacceptable.

The right operational answer to gateway availability is: run the gateway at high availability. The deployment documentation (see `docs/deployment.md`) covers the HA configuration — Redis cluster for shared state, multiple gateway replicas behind a load balancer, readiness probes that prevent a misconfigured instance from receiving traffic. If you've set up HA correctly, the gateway should not have downtime.

But even in a worst case — a rolling deployment, a rack-level failure, a botched Kubernetes upgrade — the correct behavior is for tool calls to fail until the gateway recovers, not to proceed without enforcement.

---

## Token refresh failures fail closed

This is a case I covered briefly in [post 14 on the AGT guard](./14-agt-defense-in-depth.md), but it deserves a full treatment here because it's a specific pattern I've seen other systems get wrong.

Token refresh involves making a network call to the capability issuer. That call can fail — temporary network partition, issuer restart, a race condition during a rolling deploy. When it fails, the agent's current token is about to expire (or has already expired). What should happen?

The correct behavior is: **no calls proceed until a valid, non-expired token is available**.

```typescript
// From AGT guard's token supplier:
const token = await options.tokenSupplier();
if (!token) {
  return {
    guardResult: "deny",
    denyReason: "policy_evaluation_error",
    message: "tokenSupplier returned null/undefined — token not available",
  };
}
```

The guard returns `deny` when the token supplier returns nothing. It does not forward the call with whatever stale token it might have cached. It does not skip the guard check entirely because "the token will probably be refreshed shortly." It fails closed.

This is important because the token represents a recent authorization decision. The issuer knows, at token mint time, the current state of the policy, the current revocation list, the current scoped permissions. A stale token might represent a permission that has since been revoked, a condition that has since been tightened, or a role that has since been removed. Using a stale token is using outdated policy — which, depending on the use case, could be exactly what an attacker is waiting for.

---

## Network errors fail closed

Related to gateway unavailability, but at a finer granularity: what happens when a specific request to the gateway times out, or gets a network-level error?

Same answer. The call fails. The error propagates up to the agent framework as a tool call failure.

There's a common temptation here to add retry logic with "optimistic" fallback — "if we've retried three times and it's still failing, just let it through." Absolutely not. Retry logic is appropriate for transient infrastructure failures where you expect eventual success. "Just let it through" is never appropriate for an authorization check.

The gateway itself uses a similar principle when calls to its upstream dependencies fail. If the Redis call counter store is unreachable and the token includes a `maxCalls` condition, the gateway denies the call rather than assuming "probably not at the limit." If the kill-switch Redis lookup fails, the gateway... well, this one is nuanced and worth its own paragraph.

---

## The kill-switch edge case

The global kill switch (`POST /admin/kill-switch`) stops all tool calls immediately for a tenant. It's backed by a Redis key that the gateway checks on every request. What happens when the Redis lookup fails?

The kill switch has an asymmetry that's different from call counters. The kill switch is an emergency action — someone pressed it because something bad is happening right now. If you're checking the kill switch and you can't reach Redis, you have two options:

1. Assume the kill switch is NOT active (fail-open) — let calls through in case it's just a Redis blip
2. Assume the kill switch IS active (fail-closed) — block all calls until you can confirm the state

Option 1 is dangerous. If someone pressed the kill switch because of an active breach or a runaway agent, the Redis failure becomes a way to defeat the emergency stop.

Option 2 causes false positives — benign Redis blips temporarily block legitimate tool calls. That's operationally disruptive.

eunox uses option 2. A kill-switch Redis lookup failure causes the request to be denied with a specific `kill_switch_check_failed` code. This appears in the audit log. An alert fires if it persists. The operator can investigate. But the tool calls don't go through.

This feels severe until you consider the threat model: the kill switch exists for scenarios where urgency matters more than availability. In those scenarios, the conservative failure is the right one.

---

## The `argumentSchemaRequired` mode

Post 10 covered the argument validator briefly, but there's a configuration option that deserves explicit treatment in a fail-closed discussion: `argumentSchemaRequired`.

By default, a capability that doesn't declare an `argumentSchema` imposes no argument-level constraints. The tool call can pass any arguments it wants, and the gateway only enforces the token-level conditions (`allowedOperations`, etc.) but not argument-level schema validation.

With `argumentSchemaRequired: true`, a capability that _doesn't_ declare an `argumentSchema` is denied outright:

```typescript
if (options.argumentSchemaRequired && !capability.argumentSchema) {
  return deny("argument_schema_required_but_missing");
}
```

This is a stricter fail-closed mode designed for deployments where the security team wants to ensure every capability has been explicitly locked down to a validated argument shape. It's not the default because it requires every capability definition to be updated before you can enable it — that's a migration cost that depends on where you are in your deployment lifecycle. But once you've done that migration, it gives you a stronger posture: no capability can accidentally receive unconstrained arguments because someone forgot to write an `argumentSchema`.

The migration path is: enable it in staging, discover which capabilities lack schemas, add schemas, then enable in production. The deny code tells you exactly which capability was missing the schema, which makes the migration mechanical.

---

## Contrasting with systems that chose differently

I want to be concrete about real failure modes I've encountered, without naming the specific systems involved.

**Certificate validation fall-through.** A certificate validation library in a popular programming language had a multi-year bug where, if the certificate chain couldn't be built — because an intermediate CA was missing, because the root store was empty, because the system time was wrong — the validation function returned `true` rather than `false`. Every TLS connection was "valid." The fix was straightforward. The exposure window was years.

**Rate limiter degraded mode.** A widely-used API gateway had a configuration option called `fail_open_on_service_unavailable` for its rate limiter. The default was `false` (fail closed). A popular deployment guide recommended setting it to `true` to "improve availability." The guide was read by thousands of teams. Many of them are running unprotected under degraded conditions right now without knowing it.

**WAF emergency bypass.** A web application firewall product had an "emergency bypass" mechanism — a special header value that, when present, caused the WAF to skip all inspection. This header was supposed to be secret. It was documented in the product manual. It was found in a git repository by a security researcher. It became a universal bypass for anyone who'd read the docs.

The common thread: someone decided that availability was more important than security in the edge case. That decision, replicated across thousands of deployments, produces a category of vulnerability where the "security feature is present but not effective under conditions that an attacker can create."

---

## What fail-closed costs you

I want to be honest about the trade-offs, because this is not a free decision.

Fail-closed makes debugging harder. When something goes wrong and tool calls start failing, the failure is sometimes opaque — you need to read the denial code, correlate with the audit log, check the gateway metrics, figure out whether it's a token expiry, a Redis hiccup, an unknown condition, or a killed token. A fail-open system would have let the call through and you might not have known anything was wrong.

Fail-closed requires higher availability from your dependencies. If the gateway fails closed on Redis unavailability, you need Redis to be highly available. That's an operational cost. The [post on Redis HA in the deployment docs](../deployment.md) covers the specific configuration — Redis cluster mode, Sentinel, etc. — but there's no getting around the fact that you're adding operational complexity to achieve the availability you need.

Fail-closed can create user-visible disruptions from infrastructure blips. A five-second Redis restart causes tool call failures during those five seconds. In a local development setup, that's annoying. In a production deployment where an AI agent is processing a user's request, it can mean an error response that the user sees.

These are real costs. I don't want to wave them away. But they're manageable costs — HA configuration, good alerting, clear error messages that let users retry. The alternative — fail-open — produces failures that are silent, delayed, and potentially undetectable until an auditor or a security researcher finds them.

---

## The cumulative property

Here's the thing about defense in depth: the value of fail-closed at any individual layer is modest. The value of fail-closed at _every_ layer is qualitatively different.

If the gateway fails closed on unknown conditions, and also on malformed tokens, and also on Redis unavailability, and also on token refresh failures, and also on kill-switch check failures — then an attacker needs to simultaneously defeat all of those defenses to get a tool call through without authorization. That's not four times harder than defeating one. It's _multiplicatively_ harder, because each layer is independently correct and would have to fail independently.

The [AGT guard in post 14](./14-agt-defense-in-depth.md) is another layer that fails closed. The network policy that restricts the agent's egress to only the gateway URL is another. The read-only database credentials for the audit ledger are another.

None of these individual layers is perfect. All of them together create a system where "fail open" is not a path that an attacker or a failure mode can easily walk through. That's the point.

---

## A note on the `eunox-mcp` local mode

Everything I've described above is about the hosted gateway. The local `eunox-mcp` proxy has a different failure surface because it runs in the agent's own process — but it makes the same fundamental choices.

If the YAML policy file fails to load (corrupted, missing, permissions error), `eunox-mcp` refuses to start. It doesn't start in a "no policy" mode where all calls are allowed. If the policy file loads but fails validation (schema error, unrecognized condition type), same thing: no start.

If the audit log rotation fails, the proxy logs the error and continues — because in the local case, the audit log is best-effort observability rather than the primary enforcement mechanism. (The gateway is the enforcement mechanism, even in hybrid deployments.) But the policy enforcement itself doesn't depend on the audit log's health.

The local mode is the first stage of what might become a fully hosted deployment. Keeping it fail-closed from day one means that the behavior change when you migrate to hosted is: the enforcement boundary moves to the network, not the policy strictness. The policy semantics stay the same.

---

_This post is the first in the "Design principles" series. Next: [post 16 — Schema parity over version drift: keeping the YAML format honest](./16-schema-parity-over-version-drift.md), which covers why `eunox-mcp`, the Go runtime SDK, and the gateway share a single `AgentCapabilityManifest` type and why that Apache-2.0 contract is public. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

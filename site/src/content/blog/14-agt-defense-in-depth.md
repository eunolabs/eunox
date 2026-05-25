---
title: "AGT: Defense in Depth Inside the Agent Process"
description: "The final post in the \"Architecture deep-dives\" series. The previous posts covered capability tokens (post 9, \"Capability tokens: a cryptographic contract between agent and operator\") and the enforcement pipeline (post 10, \"The Tool Gateway as a reference monitor\"). Both describe defenses at the gateway — the external reference monitor. This post covers the other enforcement layer: the one that runs inside the agent process, before any tool call reaches the network. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index."
pubDate: "2026-06-02"
---

*The final post in the "Architecture deep-dives" series. The previous posts covered capability tokens (post 9, "Capability tokens: a cryptographic contract between agent and operator") and the enforcement pipeline (post 10, "The Tool Gateway as a reference monitor"). Both describe defenses at the gateway — the external reference monitor. This post covers the other enforcement layer: the one that runs inside the agent process, before any tool call reaches the network. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

One of the architectural tensions I've wrestled with throughout building euno is this: the gateway is the correct enforcement boundary. It's cryptographic, audited, and impossible for the agent to bypass as long as network controls are in place. It is, in the security architecture sense, the right place to enforce policy.

But "the gateway will catch it" is not the same as "we checked it." There's a real gap between a system where the agent tries to call a tool, the call hits the network, the gateway rejects it, the rejection propagates back to the agent, and the agent recovers — and a system where the agent checks whether a call is permitted *before* invoking any of that machinery. Both enforce the policy. They have different latency, cost, and observability properties.

The in-process guard (`createAgtGuard()`, part of `@euno/agent-runtime`) is the answer to that gap. It's not a replacement for the gateway. It's an additional layer that runs earlier, cheaper, and with different failure modes.

---

## Why bother with in-process checking at all?

Let me start with the practical argument before the security one.

A gateway round-trip costs 5-30ms depending on network topology, gateway load, and whether you're running in-cluster or cross-region. For an agent that makes 50 tool calls in a session, that's 250ms to 1.5 seconds just in gateway latency. Most of those calls are going to be allowed. The enforcement engine does real work on every call — token verification, condition evaluation, revocation check — but for a well-behaved agent running within its declared policy, that work is always going to reach the same conclusion.

The in-process guard short-circuits the obvious failures. If the agent tries to call a tool that isn't in its capability manifest at all, the guard blocks it instantly — no network call, no gateway processing, no audit event generated for a call that was never going to be allowed. For agents in agent-loop scenarios where a model occasionally tries to invoke tools outside its declared scope (a common pattern when the model is extrapolating from context rather than strictly following its system prompt), this saves real latency and reduces gateway load.

The security argument is different: it's about defense in depth, not about replacing the gateway. The model I keep coming back to from the `sandboxing.md` doc is the three-layer stack:

1. **Outer layer:** sandbox isolation (network policies, seccomp, microVM boundaries)
2. **Middle layer:** the gateway reference monitor (cryptographic, audited, hard enforcement)
3. **Inner layer:** in-process policy checking (fast, declarative, soft enforcement)

The inner layer can fail — a bug in the guard implementation, a null dereference in the policy evaluation, anything — and the gateway still catches it. But if the inner layer works correctly, it catches things that the gateway would have caught anyway, earlier and more cheaply.

---

## The guard is a soft guard

This is the most important thing to understand about `createAgtGuard()`, and it's stated explicitly in the code and documentation: **the guard is a soft guard**. Passing the in-process check does not guarantee the outer gateway will also allow the call.

The gateway performs:
- Cryptographic JWT signature verification
- Token expiry check
- Revocation list lookup
- Independent condition evaluation with the full condition registry
- Kill-switch check

The guard performs:
- A lookup of the tool name against the capability manifest's `requiredCapabilities` and `optionalCapabilities` arrays

That's it. The guard doesn't verify JWT signatures (the token comes from a `tokenSupplier` callback that the caller is responsible for refreshing). It doesn't check revocation. It doesn't evaluate conditions — it doesn't know whether the specific SQL query in the `query_db` call passes the `allowedOperations` condition; it only knows whether `query_db` appears in the manifest at all.

This distinction matters for threat modelling. If you're thinking "does the guard prevent prompt injection?" — it helps, but not completely. A prompt injection attack that causes the agent to call a tool that's declared in the manifest but with arguments that violate a condition will pass the guard and be caught by the gateway. A prompt injection attack that causes the agent to call a tool that's *not* in the manifest at all will be caught by the guard.

The guard is a first line of defense against the most obvious violations, optimized for the common case.

---

## The API

```typescript
import { createAgtGuard, HttpToolTransport } from '@euno/agent-runtime';

const guard = createAgtGuard(
  {
    tokenSupplier: () => tokenStore.currentToken(),
    policy: manifest,
    onDeny: (tool, reason) => logger.warn('guard deny', { tool, reason }),
    onGatewayDeny: (tool, code) => metrics.increment('gateway_deny', { tool, code }),
  },
  new HttpToolTransport(gatewayUrl),
);

const response = await guard.invokeTool({ tool: 'db:read', args: { table: 'users' } });
```

The returned `AgtGuardInvokeResponse` has two fields beyond the standard transport response:
- `guardResult: 'allow' | 'deny'` — the guard's own verdict
- `denyReason?: AgtGuardDenyReason` — set when the guard itself blocked the call

If the guard allowed the call but the gateway denied it, `guardResult` is `'allow'` and `success` is `false`. The distinction matters for observability: a guard deny means the agent violated its declared manifest; a gateway deny after a guard allow means the agent had a valid manifest entry but the gateway found a condition violation, revoked token, or other enforcement failure. These are different operational situations and you want to track them separately.

---

## The deny reasons

There are two meaningful deny reasons from the guard:

**`capability_not_found`** — the tool name doesn't appear in either `requiredCapabilities` or `optionalCapabilities` in the manifest. This is the most common guard deny in practice. It fires when the model attempts to call a tool that the operator never granted access to.

**`policy_evaluation_error`** — an unexpected error during the in-process policy check, or a failure from the `tokenSupplier`. The guard fails closed on evaluation errors. If the `tokenSupplier` throws (perhaps because the token refresh failed due to a network issue), the guard returns a deny rather than forwarding the call without a token.

There is no `condition_violation` deny reason at the guard layer. As noted above, the guard doesn't evaluate conditions — that's the gateway's job.

---

## The `onDeny` and `onGatewayDeny` callbacks

Both callbacks are optional but worth wiring up in production.

`onDeny` fires for guard-layer denials. This is your signal that the agent is attempting to use tools outside its manifest. In a well-behaved deployment, this should be rare to nonexistent. A spike in `onDeny` events is a signal worth investigating — it might indicate a prompt injection attack, a model change that widened the tool-use behavior, or a misconfigured manifest.

`onGatewayDeny` fires for gateway-layer denials that the guard allowed to pass. This is your signal that the agent is within its manifest but hitting a condition, revocation, or kill-switch boundary at the gateway. Distinguishing these two callbacks in your metrics is the key to understanding what kind of enforcement is happening.

Both callbacks are wrapped in a `safeInvoke()` — if your callback throws, the exception is swallowed rather than propagating into the guard evaluation path. This is intentional: a malfunctioning observability hook should not turn into a DoS vector by causing every tool call to fail.

---

## The single-audit-entry invariant

One constraint the guard is designed to maintain: **for every tool call, exactly one audit entry is written, by the gateway**.

This sounds obvious but has a subtle implication. When the guard blocks a call (`guardResult: 'deny'`), no network call is made and no audit event is written. The audit log does not contain guard-layer denials.

This is a deliberate design decision, and it's occasionally surprising to people who expect the audit log to be a complete record of every policy evaluation. The reasoning:

The audit log is the source of truth for SOC 2 evidence. It records what the gateway decided about what the agent actually tried to do at the enforcement boundary. Guard denials are *not* enforcement decisions — they're pre-screening that happened before the enforcement boundary was reached. Including them in the OCSF audit log would muddy the evidence record.

More practically: the guard runs in the agent process, which is inside the agent's trust domain. If you want tamper-evident audit evidence, you want it from the enforcement boundary, not from the agent process. An agent process can, in principle, be compromised. The gateway cannot be trivially compromised from inside the agent's sandbox (network policies prevent direct agent-to-backend communication; the gateway is the only egress path).

The `onDeny` callback is where guard denials land — in your application's logging and metrics, not in the OCSF ledger. For compliance purposes, what matters is that the gateway saw and decided on every action the agent actually attempted to take. Guard denials represent actions that were caught before reaching the enforcement boundary; they're useful for operational monitoring but they're not evidence of enforcement.

---

## The transport abstraction

`createAgtGuard()` takes a `ToolTransport` as its second argument. In production, this is an `HttpToolTransport` configured with the gateway URL. In tests, it's an `InProcessToolTransport` backed by a mock handler — this means you can write unit tests for your agent's tool-calling behavior, including guard behavior, without a live gateway instance.

```typescript
import { createAgtGuard, HttpToolTransport, InProcessToolTransport } from '@euno/agent-runtime';

// In production
const guard = createAgtGuard(options, new HttpToolTransport('https://gateway.example.com'));

// In tests
const guard = createAgtGuard(options, new InProcessToolTransport(mockHandler));
```

The `InProcessToolTransport` was one of those features that seemed like a testing nicety when I added it but turned out to matter for the real test suite. Integration tests that need a live gateway are valuable but slow and require infrastructure. Unit tests that use `InProcessToolTransport` run in milliseconds and need no external dependencies. Having both paths — and having them be the same guard code — is what lets the test pyramid work correctly for agent-runtime tests.

---

## Where the guard fits in the deployment topology

The guard lives inside `@euno/agent-runtime`, which is the BUSL-licensed library that wraps your AI agent framework code. The typical deployment looks like:

```
Agent process (sandboxed runtime)
├── Agent framework (LangChain / CrewAI / MAF)
│   └── Tool transport
│       └── createAgtGuard()         ← inner layer, in-process
│           └── HttpToolTransport
│               └── Tool Gateway     ← middle layer, network boundary
│                   └── Protected backends
```

The agent framework calls `createAgtGuard().invokeTool()` for every tool invocation. The guard checks the manifest, acquires the current token from `tokenSupplier`, and forwards to the `HttpToolTransport` if the tool is in scope. The transport makes the HTTPS call to the gateway. The gateway does the full enforcement check and either forwards to the backend or returns a denial.

In the sandboxing model, the outer layer (OS/VM isolation) prevents the agent from making any network connections except to the gateway. This means that even if the guard is bypassed — say, by a bug in the guard implementation or by an agent that manages to make direct HTTP calls through an imported library — the network layer prevents those calls from reaching backends directly. The gateway is the only reachable destination.

Defense in depth means that every layer assumes the layers inside it might fail. The guard assumes the network controls might be circumvented and checks policy anyway. The gateway assumes the guard might have been bypassed and enforces cryptographically. The network controls assume the gateway might be misconfigured and enforce at the packet level.

---

## What the guard doesn't do

I want to be specific about the limits because I've seen architectural diagrams where the guard is presented as equivalent to the gateway, which it's not.

The guard **does not**:
- Verify JWT signatures
- Check token expiry
- Consult the revocation list
- Evaluate typed conditions (`allowedOperations`, `allowedTables`, `maxCalls`, etc.)
- Produce tamper-evident audit evidence
- Enforce kill-switch state
- Do anything with DPoP proof verification

All of those are gateway responsibilities. The guard's role is narrow and intentional: check that the tool name appears in the declared manifest and that a token is available, then forward.

If the gateway is unreachable (network partition, gateway restart, misconfigured service discovery), the guard cannot substitute for it. Tool calls will fail at the transport layer. This is fail-closed: a broken gateway causes tool calls to fail, not to succeed without enforcement.

---

## The `optionalCapabilities` subtlety

The manifest has two capability arrays: `requiredCapabilities` and `optionalCapabilities`. Both are checked by the guard — if a tool is listed in either array, the guard allows it. The distinction between required and optional is semantic at the manifest level (required capabilities must be present in the token for the agent to start; optional ones may or may not be present) but at the guard level, both arrays are treated as the allowable tool set.

This means the guard's check is: *is this tool listed in the manifest at all?* Not: *does the current token include this capability?* Token coverage is the gateway's job. The guard trusts that the token from `tokenSupplier` is the agent's current valid token; what capabilities it actually contains is verified by the gateway's cryptographic check.

---

## Operational guidance

A few things I've learned from running the guard in production:

**Wire `onDeny` to a metric with a low-alert threshold.** Guard denials should be rare. If you're seeing more than a handful per hour in a stable deployment, something is wrong — either the manifest is too restrictive for what the model is actually trying to do, or the model's behavior has drifted, or you're under a prompt injection campaign.

**Separate guard denials from gateway denials in your dashboards.** They have different root causes. Guard denials are usually manifest coverage issues. Gateway denials after guard allows are usually condition violations (the model is calling the right tool with the wrong arguments).

**Use `InProcessToolTransport` in your agent's integration tests.** Testing your agent against a mock transport is much faster than testing against a live gateway, and it catches manifest coverage issues early. The live gateway tests are valuable for end-to-end validation but shouldn't be your primary feedback loop during development.

**Don't treat guard allows as evidence of permitted actions.** The audit log is the evidence of what the gateway decided. Guard allows are implementation details of the agent process. For compliance purposes, only gateway decisions matter.

---

## Looking ahead

The guard as implemented is a structural manifest check — "is this tool in the manifest?" There's a potential future extension that I've thought about but not built: pre-screening condition evaluation. If the guard could check `allowedOperations` before forwarding to the gateway, it could catch SQL mutation attempts in-process, without a network round-trip.

The challenge is that conditions are evaluated against the actual arguments at call time, and some conditions (like `maxCalls`) require distributed state (call counter in Redis) that the guard, running in the agent process, shouldn't be directly accessing. The guard is designed to be lightweight and in-process; adding Redis access to it would change its operational profile significantly.

The better path, if latency is a real concern for condition evaluation, is probably gateway co-location: running the gateway as a sidecar in the same pod as the agent, rather than as a separate service, to minimize the network round-trip. Same enforcement semantics, lower latency.

---

*This post concludes the "Architecture deep-dives" series. If you're building an enterprise AI governance platform and want to understand the design choices that led here, I'd suggest reading them in order: post 9 (capability tokens) → post 10 (enforcement pipeline) → [post 11 (audit logs)](./11-tamper-evident-audit-logs.md) → [post 12 (pluggable adapters)](./12-pluggable-adapters.md) → [post 13 (partner federation)](./13-partner-did-federation.md) → this post. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

*The next series covers design principles: why the system fails closed, how the YAML policy format stays honest across deployment tiers, and how we think about defense in depth for SQL injection through an LLM.*

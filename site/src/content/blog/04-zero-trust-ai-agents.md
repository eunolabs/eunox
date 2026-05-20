---
title: "Zero trust for AI agents: a practitioner's guide"
description: "How to apply zero-trust principles — verify explicitly, least privilege, assume breach — to AI agent infrastructure in practice."
pubDate: "2024-12-01"
audience: "security architects and platform engineers deploying AI agent infrastructure"
---

*Audience: security architects and platform engineers deploying AI agent infrastructure*

---

"Zero trust" has been through the corporate buzzword lifecycle at this point. You've seen the slide decks. You've sat through the vendor presentations where someone draws a castle-and-moat diagram, says "that's the old way," and then shows a new diagram that looks almost identical except the perimeter is now called "identity." If you're sceptical, that's reasonable. A lot of what gets sold as zero trust is just TLS plus a VPN replacement plus a dashboard showing you which employees clicked the phishing simulation.

But the underlying idea — the actual idea that John Kindervag articulated at Forrester back in 2010 — is genuinely simple and genuinely right: stop assuming that anything on your network can be trusted. Verify every access, every time, at the point of the resource. Not at the edge. Not once at login. At the resource, every time.

That idea was designed for humans and service accounts. Applying it to AI agents turns out to be harder than it looks, but also more necessary than most teams realise until something goes wrong.

---

## Why AI agents break the assumptions classical zero trust was built on

Classical zero trust assumes a few things that aren't true for AI agents.

It assumes predictable access patterns. You can write a policy for a service account because the service account does roughly the same things every day — it queries these tables, calls these APIs, on this schedule. You can verify that pattern over time and alert when it deviates. An AI agent's access patterns are determined at runtime by a language model choosing a sequence of tool calls. Two invocations with the same high-level intent can result in completely different sequences of tool calls. You can't write a static policy for something that chooses its own path.

It assumes the principal can't be manipulated through its inputs. A service account doesn't read documents. It doesn't process emails. It doesn't have a context window that a malicious actor can stuff with instructions. A language model does all of those things, and anything in that context window is potentially an instruction. This is prompt injection, and it means an attacker who can get content in front of your agent has a vector to manipulate what actions that agent takes — without touching your auth stack, your network, or your database. There's a longer exploration of this in [the prompt injection post](./01-prompt-injection-policy-layer.md), but the point here is that classical zero trust has no model for a principal that can be socially engineered.

It assumes stable identity. A service account is itself — the same identity, the same credentials, making the same kind of requests. An AI agent runs tasks. Different tasks need different capabilities. An agent doing a read-only research task should have completely different access than the same agent executing a file modification. But most deployments handle this by giving the agent maximum credentials and letting the system prompt limit what it does. Which is trust at the wrong layer, as we've seen. You can read about the failure modes that produces in [the governance failure modes post](./03-agent-governance-failure-modes.md).

So classical zero trust is necessary but not sufficient. You need the same properties — continuous verification, least-privilege access, fail-closed defaults — but applied in ways that account for what's different about agents.

---

## The NIST 800-207 tenets, translated

NIST 800-207 lays out the seven tenets of zero trust. You can look them up, and they're worth reading, but I'll spare you the government-document prose and focus on the four that matter most here.

**Every resource is protected, regardless of network location.** For agents, this means your tools, databases, and APIs should require authentication and authorisation regardless of whether the call originates from your internal network or not. "Internal" is not a trust boundary. An agent calling an internal API with a stolen or overly-broad credential is still a problem. This sounds obvious but a lot of deployments have internal tools that trust any call from the company network, because they predate agents and were never built for a world where something on the network would make arbitrary API calls on behalf of users.

**Access is granted per-session, per-task, with minimum necessary privilege.** This is the capability token idea. Instead of long-lived credentials that grant broad access, you issue short-lived tokens at the start of a session that encode exactly what this agent invocation is allowed to do — which tools, which operations, which data, with which constraints, until when. The token expires. When the task is done, the access goes away. [There's a full walkthrough of how to structure capability tokens](./02-least-privilege-agent-era.md) for agent deployments — the short version is that a token should encode identity, capability set, session scope, time bounds, and any numerical limits on consequential operations.

**Policy is dynamic and includes posture data.** Static policies — "this service account can query these tables" — aren't enough when the thing making the request is context-sensitive. A well-implemented policy pipeline evaluates conditions at call time: what is the agent doing, what has it already done this session, does the current request match the stated capability, are there anomalies in the call pattern. The policy is a function evaluated per call, not a fixed rule checked at provisioning time.

**Everything is monitored and logged.** This one is easy to nod at and hard to implement well. The key properties for agent deployments: every tool call gets a log entry before and after execution (not just on failure), the log is tamper-evident so an agent that could compromise the logging path can't cover its tracks, and the log format is structured enough to be queryable. You need to be able to answer "which sessions accessed this data in the last 30 days" and "how many times did this agent invoke the send_email tool last week" without writing a log parser.

---

## Fail closed. This is not optional.

Before getting into architecture: the most important decision in designing any enforcement point for AI agents is this one, and it's a cultural and engineering decision as much as a technical one.

When the enforcement point can't make a confident decision — the token is missing, the policy store is unreachable, the condition type isn't recognised, the Redis instance that backs your rate counters is temporarily unavailable — what happens?

The natural engineering instinct is to add a fallback. Don't break the user's experience. If the policy store is down, maybe permit with reduced confidence and flag for review. If the condition type is unrecognised, maybe skip that check and apply the rest. Fallbacks are good engineering practice in almost every other context.

For a security enforcement point, a fallback that permits is not a fallback. It's a hole. Every time the enforcement point falls back to permit, you have a moment where ungoverned actions can happen. Attackers who understand your system will deliberately trigger those moments. Even without adversarial intent, the failure scenario is "security was down, agent ran unconstrained, something we didn't expect happened."

Fail closed means: unknown condition type? Deny. Policy store down? Deny. Token missing? Deny. Can't evaluate a condition? Deny. This will occasionally deny legitimate requests. That's the trade-off, and it's the right one. A transient deny is annoying. An ungoverned action might not be recoverable.

The teams that have the hardest time accepting this are the ones who've optimised hard for availability and uptime. It feels backwards to make a security component that fails harder than everything else. But that's the property you want. Your load balancer should fail open — you'd rather some traffic get through than all traffic drop. Your security enforcement point should fail closed — you'd rather deny a few legitimate calls than permit ungoverned ones.

---

## What the enforcement pipeline actually looks like

When an agent makes a tool call, here's what happens in a properly implemented zero trust pipeline before that call reaches the upstream tool:

**Token verification.** Is there a valid JWT capability token? Is the signature valid against the issuer's key? Is it expired? Has it been tampered with? If any of these fail, deny. Don't log "suspicious activity," just deny — a missing or invalid token is not an anomaly to investigate later, it's a hard stop.

**Revocation check.** Even a valid, unexpired token might have been revoked — because the user's session was terminated, because a security event triggered revocation, because an admin killed a runaway agent. The revocation check should be fast (Redis lookup is fine) and fail closed — if the revocation store is unreachable, assume the token might be revoked.

**Kill-switch check.** A coarser control than revocation: is there an active kill-switch that applies to this agent type, this tool, this capability class? Kill-switches let you stop a class of actions across all active sessions in seconds — useful when you discover an exploit and need to prevent any agent from calling a specific tool while you patch it.

**Capability match.** Does the token's capability set include permission to call this tool with these arguments? A token that grants `read_document` doesn't grant `send_email`. A token that grants `query_database` for table X doesn't grant it for table Y. This is the structural heart of the zero trust model — the token is the artefact that encodes what the agent is actually authorised to do, and this check enforces that.

**Condition evaluation.** This is where it gets interesting. Conditions are dynamic constraints attached to capabilities: rate limits (no more than N calls per session), time windows (only callable between 09:00 and 17:00), argument patterns (email recipient must match this regex). These are evaluated per call against current state. This is also where unknown condition types fail closed — the enforcement point should only approve a capability when it can positively verify all conditions are satisfied.

**Obligation application.** Some policies require side effects rather than just allow/deny. Rate counters get incremented. Arguments might get sanitised (strip PII before logging). The response might need to be filtered. These aren't gates — the call proceeds — but they need to happen before the call is forwarded.

**Audit write.** Before the call is forwarded to the upstream tool, the decision and context are written to the tamper-evident audit log. Not after. If you write the audit entry after the call returns and the call hangs or errors, you lose the record. Every call gets an entry regardless of outcome — denials matter too, sometimes more than approvals.

**Forward or deny.** If everything above passes, the call goes through. If anything failed, it doesn't. The upstream tool never sees the call.

Eight steps. Each one independently important. Each one failing closed.

---

## The tamper-evident audit log

The audit log is worth a separate paragraph because teams often underinvest in it until they need it and then realise they don't have what they need.

Tamper-evident means the log entries are chained — each entry includes a hash of the previous entry, so you can verify that nothing has been deleted or modified without invalidating the chain. An agent that compromised the logging path could still add false entries, but it can't retroactively remove or modify entries without detection. Pair this with a KMS-signed export at the end of a session and you have a log that satisfies most SOC 2 and regulatory audit requirements.

OCSF (Open Cybersecurity Schema Framework) format for the entries means your log is queryable with standard security tooling. An API Activity event in OCSF gives you: actor identity, target resource, action taken, outcome, timestamp, metadata. For agent tool calls you have all of this: the token identity is the actor, the tool name is the target, the arguments are the request, the decision is the outcome. This is the right data model. Don't invent your own log schema when OCSF already maps cleanly.

---

## A maturity model, briefly

You don't have to implement all of this at once. Here's a rough progression:

**Phase 1 — Basic auth.** Agents authenticate to tools with API keys. No session scoping, no capability constraints. This is where most teams start. Better than nothing. Not meaningfully zero trust.

**Phase 2 — Token-based auth with expiry.** Short-lived JWTs instead of API keys. Tokens expire. Rotation is automated. Still no capability scoping — the token proves identity but doesn't constrain what the identity can do.

**Phase 3 — Capability tokens with per-task scoping.** This is the meaningful step. Tokens encode capability sets. Different tasks get different tokens. Per-session rate limits. Revocation. This is where zero trust principles actually start applying.

**Phase 4 — Full enforcement pipeline with dynamic conditions.** Condition evaluation per call. Audit logging with tamper-evidence. Kill-switches. Fail-closed defaults. Obligation application. This is production-grade.

**Phase 5 — Federated cross-org trust.** When your agents need to call tools hosted by partner organisations, or when partner agents need to call your tools. DID-based identity verification. Federated policy. Cross-org audit trails. This is where enterprise deployments of any real complexity eventually end up.

Most teams should be aiming for Phase 3 or 4 as their steady state. Phase 1 and 2 are transient steps, not destinations.

---

The thing about zero trust is that it's demanding to implement well and the payoff isn't visible when it's working — it's only visible when something tries to go wrong and can't. That's a hard sell in an environment where you're under pressure to ship capability. But the agents you're deploying have real access to real systems with real consequences, and the blast radius when they misbehave is proportional to what you've given them access to.

Build the enforcement pipeline. Fail closed. Log everything. The work pays off in the scenarios you don't have to explain to your security team.

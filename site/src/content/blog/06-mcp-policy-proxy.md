---
title: "Building a policy proxy for MCP: design choices and trade-offs"
description: "The key design decisions behind a transparent MCP policy proxy: where to intercept, how to evaluate conditions, and what fail-closed means in practice."
pubDate: "2025-01-15"
audience: "platform engineers and security architects building MCP infrastructure"
---

*Audience: platform engineers and security architects building MCP infrastructure*

---

You've read [the MCP post](./05-mcp-explained.md). You're convinced the protocol is the right abstraction — one server works with any client, the integration matrix collapses, your tools are composable. So you start wiring things up, and somewhere around the point where your agent successfully queries your production database and emails the results to a user, you notice something uncomfortable: there's nothing between the model and the backend except a JSON-RPC message.

The model decides what to call. The protocol delivers the call. The tool executes it. No authentication at the call level, no policy evaluation, no rate limiting, no audit log. The agent that just retrieved a customer record and formatted it into an email — could it have retrieved *any* customer record? Could it send the email to *any* address? How would you know if it did? How would you stop it if it tried?

This is the governance gap that MCP doesn't close. The protocol is plumbing. Governance is a different layer, and if you're running agents with any kind of real access, you need to build it.

---

## Three options, two of them wrong

When you decide to add governance, you have three places to put it.

You can instrument the model side — intercept before the model produces a tool call, or modify the model's context to influence what it decides to do. This sounds appealing because it's early in the chain. The problem is that you're working with natural language and model behaviour, not structured data. You can add instructions to the system prompt: "only call send_email with addresses from the approved list." You can add a validation pass before tool calls. But as we've explored in detail in [the prompt injection post](./01-prompt-injection-policy-layer.md), system prompt instructions are suggestions to a language model. A sufficiently motivated instruction in the model's context can override them. You can't write a robust policy against natural language — it's the wrong data type.

You can instrument the server side — add auth and policy logic to each MCP Server. This is more principled because you're working closer to the actual execution. The problem is scaling. If you have twenty MCP servers — GitHub, Slack, your database, your CRM, your document store, your deployment pipeline — you have to implement the same auth and policy logic twenty times. Each server ends up with its own interpretation of what "rate limiting" means, its own token validation code, its own audit log format. Consistency is hard to maintain, security reviews become sprawling, and when you need to update your policy — new token format, new condition type, new revocation mechanism — you update twenty places or you don't update them all.

The right answer is to sit in the middle as a proxy. Every tool call passes through the proxy. The proxy speaks MCP on both sides — it looks like an MCP Server to the client, and it looks like an MCP Client to the upstream servers. It enforces policy on the structured JSON arguments that MCP gives you. The upstream servers never see an unauthorised call. You write your governance logic once.

This is the right architecture. Let's talk about how to build it.

---

## The proxy architecture

The MCP client connects to the proxy, not to the upstream servers directly. The proxy registers itself as an MCP Server during the handshake, advertises the union of tools from all upstream servers it fronts, and handles tool calls by evaluating policy and forwarding authorised calls to the appropriate upstream server.

This means the proxy needs to know which upstream server handles which tool. For STDIO transport, where each server is a subprocess, the proxy wraps those processes and routes based on tool name. For HTTP transport, the proxy maintains connections to each upstream server's endpoint and routes accordingly. In both cases, the forwarding logic is straightforward once the policy evaluation is done.

The proxy also needs to handle discovery correctly — when the client asks what tools are available, the proxy queries all upstream servers, aggregates their capability lists, and returns the union. If an upstream server is unavailable, the proxy can return its last-known capability list or exclude that server's tools from the list. Fail closed means excluding them.

One important design question: does the proxy strip tool descriptions before passing them to the client? You might consider this because, as discussed in the MCP post, tool descriptions from upstream servers are a trust surface — a malicious server could provide misleading descriptions. A strict implementation has the proxy maintain its own canonical descriptions for trusted tools and rewrite anything from upstream. This is more work but meaningfully improves the security posture.

---

## STDIO vs HTTP transport, and why it matters for deployment

These two transport modes have different operational implications for the proxy.

STDIO is subprocess-based. The proxy spawns each MCP server as a child process, communicates over stdin/stdout. This is clean and simple — no network port, no TLS configuration, no service discovery. For local development (Claude Desktop, Cursor, a developer's personal agent setup), it works great. The proxy is typically bundled with the client and manages its server processes internally.

The limitation: one proxy instance per server process, because subprocess ownership is not shareable. For single-user local dev, that's fine. For multi-user production, you want multiple agent sessions sharing governance infrastructure — shared rate counter state, shared revocation lists, shared audit log. You can't do that with STDIO.

HTTP transport is the production model. The proxy is a hosted service. MCP Servers are separate hosted services. Multiple clients connect to the proxy; the proxy maintains connections to upstream servers over the network. This requires proper TLS, service discovery, and handling of connection failures. It also enables the shared state you need for multi-user deployments: a Redis-backed rate counter that works across all active sessions, a centralised revocation list, a durable audit log.

In practice: STDIO proxy for local dev, HTTP proxy for production. The critical thing is that the policy format is identical. Your policy YAML from local dev should deploy unchanged to production. You shouldn't have to rewrite your capability definitions because you moved from a subprocess proxy to a hosted gateway.

---

## The enforcement pipeline

This is where the actual work happens. Every tool call — every single one — passes through this sequence before it reaches an upstream server.

**Token verification.** The call must carry a valid JWT capability token. Valid means signed by the right key, not expired, not tampered with. The token is the zero-trust artefact: it encodes identity, the capability set this session is allowed to exercise, and the conditions under which those capabilities are available. If the token is missing or invalid, deny. No meaningful error message to the caller — that leaks information. Just deny.

**Revocation check.** A valid token can be revoked. This happens when a session is terminated, when a security event is detected, when an admin kills a specific agent mid-run. The revocation check is a fast lookup — Redis by token ID is fine. If the revocation store is unreachable, assume the token might be revoked and deny. Fail closed.

**Kill-switch check.** Coarser than revocation — applies to capability classes or specific tools rather than individual sessions. A kill-switch lets you prevent any session from calling, say, `send_email` while you're investigating an incident, without individually revoking thousands of tokens. Kill-switch state should be checked per call, not cached for the session lifetime.

**Capability match.** Does the token's capability set include this tool with these operations? A capability that grants `read_document` doesn't grant `delete_document`. A capability that grants access to database table X doesn't grant access to table Y. This is structural enforcement — it doesn't depend on the model's good behaviour or the system prompt's instructions. It's enforced on the structured data in the token and the structured data in the tool call.

**Condition evaluation.** This is the interesting one. Conditions are dynamic constraints on capabilities:

- Rate limits: no more than N calls to `send_email` per session, or per hour, or per day
- Time windows: `deploy_service` is only callable during business hours
- Argument pattern matching: `send_email.recipient` must match an allowlisted domain regex
- Call budget: total tool calls across all tools this session cannot exceed M

Conditions are evaluated against current state — which means your rate counters need to be consistent across the proxy instances in a multi-node deployment. Redis is the right backing store for this. The counters need to be atomic (Redis INCR, not read-then-write), and they need to expire so you're not accumulating state forever.

The fail-closed rule is especially important here: **if the proxy encounters a condition type it doesn't recognise, it denies.** This sounds annoying but it's the right call. Policy evolves. If you add a new condition type to your policy language and the proxy doesn't recognise it yet, you want that to be a loud failure you notice and fix, not a silent skip that means the new condition is never enforced. An enforcement point that silently skips unknown conditions is a time bomb — it'll work fine until you actually need the condition. The broader fail-closed principle — including what happens when Redis is down, when the policy store is unreachable, when any infrastructure component fails — is covered in depth in [the zero trust guide](./04-zero-trust-ai-agents.md).

**Obligation application.** Some policies have side effects rather than just allow/deny. Rate counters need to be incremented after a successful approval. Arguments might need sanitisation — strip PII from log payloads, normalise values. The response from upstream might need to be filtered before being returned to the client. This step handles all of that.

**Audit write.** Before forwarding the call, write an initial decision record to the audit log. Not after — if you wait and the call hangs, you lose the fact that the call was approved and forwarded. Then, when the upstream call completes (success or error), write or update a completion record with the response outcome and latency. The initial record contains call timestamp, token identity, tool name, sanitised arguments, policy decision, and conditions evaluated. Completion adds execution outcome details. Structured enough to be queryable. Written to a tamper-evident log (see below). Both approved and denied calls get logged — denials are often more interesting than approvals.

**Forward or deny.** Everything passed. The call goes to the upstream server. The result comes back and is returned to the client. Or something failed, and the call is denied.

---

## Audit logging that's actually useful

MCP tool calls are structurally ideal for audit logging. You have: the tool name, the typed arguments, the caller identity (from the token), the timestamp, the outcome. That's most of an OCSF API Activity event already. Use OCSF — don't invent your own schema when there's an industry standard that your security tooling already knows how to query.

Tamper-evidence is not optional if you're running anything with compliance requirements. Chain the log entries — each entry includes an HMAC of the previous entry, so deletion or modification of any entry breaks the chain. At session end, export a KMS-signed log bundle. If an auditor asks "show me all tool calls made by agent sessions with access to customer data last month," you can produce a verifiable record.

The [governance failure modes post](./03-agent-governance-failure-modes.md) has a scenario where an agent exfiltrates data via email with no visible trace in conventional logs. Structured argument logging at the proxy layer is what would have caught it — the `send_email` call with its recipient and content would have been in the audit log before it executed. That's the record you want.

---

## Single-process vs hosted proxy

The deployment model affects what you can do.

A single-process proxy bundled with the client works well for local development. It manages its server subprocesses, enforces policy from a local config file, writes audit logs to disk. Low operational overhead. Good for individual developers who want governance without infrastructure.

For production — multi-user, multi-tenant, high throughput — you need a hosted gateway. Stateful rate counters require a shared backing store. Revocation needs to work across all active sessions instantly. The audit log needs to be durable and centralised. The gateway itself needs to be highly available, which means horizontal scaling and session affinity for stateful checks.

The most important design decision for this transition: keep the policy format identical between environments. A developer who writes capability policies on their laptop should be able to deploy those policies to production without reformatting them. If the policy format is environment-specific, policies will drift between environments and you'll have governance surprises in production that didn't appear in dev.

---

## When your agents need to call tools at partner organisations

This comes up more than you'd think in B2B contexts. Your agent needs to trigger a workflow in a partner's system. Their agent needs to call your tools as part of a shared workflow. You need cross-org trust without sharing credentials.

DID-based federation is the right architecture here. Both organisations maintain a DID (decentralised identifier) — `did:web` is the simplest approach, just a well-known JSON document at a known URL — that maps to their public keys. When your agent's token is presented to a partner's proxy, the partner can verify the signature using your published DID document without any shared secret. Same in reverse.

The operational concern is DID resolution reliability. If your partner has a temporary infrastructure issue and their DID document is unreachable, DID resolution fails. The proxy needs a circuit breaker: a cached version of the DID document for a defined TTL, with fail-closed behaviour when the cache is stale and resolution is failing. You'd rather pause cross-org tool calls during a partner outage than either fail all your agents or silently bypass verification.

---

## Governance isn't an add-on

There's a framing that treats governance as something you bolt on after you've shipped the capability — something for the security team to worry about, something to add to the backlog, something for v2. This framing is understandable but it's backwards.

An MCP-connected agent without governance is a language model with unrestricted access to your production systems, mediated only by the model's good judgement and your system prompt's persuasiveness. You wouldn't give a new contractor unrestricted access to your production systems on the grounds that they seem trustworthy. The agent deserves the same thinking.

The proxy is the layer that makes MCP actually usable in production. The protocol gives you the plumbing. The proxy gives you the safety. Both of them together give you something you can actually put in front of real workloads and defend to your security team.

---
title: "Least-privilege for AI: translating a 50-year-old principle to the agent era"
description: "RBAC and OAuth scopes were designed for humans. Here is what least-privilege actually means for AI agents that call tools autonomously."
pubDate: "2024-11-01"
audience: "security architects and developers building multi-tool agent systems"
---

*Audience: security architects and developers building multi-tool agent systems*

---

Least privilege is one of those principles that everyone agrees with and almost nobody implements properly. Give every process and user only the access they need, no more. Saltzer and Schroeder wrote it down in 1975. It's held up perfectly for fifty years. Nobody's arguing against it.

The problem isn't the principle. It's that the tools we've built to implement it — RBAC, OAuth scopes, cloud IAM — were designed around a set of assumptions that AI agents violate in almost every direction. Not slightly. Fundamentally.

This post is about the gap between those assumptions and the reality of how agents work, and what a model that actually fits looks like.

---

## Why the old tools don't fit

To understand the mismatch, it helps to understand what the classic tools were built for.

RBAC was formalised in the 1990s. The problem it was solving: enterprise organisations have hundreds or thousands of employees, each needing access to a defined set of systems. Managing permissions user-by-user doesn't scale. Managing them role-by-role does. The model works because the cast of principals is relatively stable, the set of resources is known, and the operations on those resources are bounded. Someone in "Finance" can read the billing tables. Someone in "Engineering" can access the code repositories. These assignments are made at provisioning time and reviewed periodically.

OAuth 2.0 solved a different problem: a user delegating access to a third-party application without sharing their credentials. The scope mechanism — `repo:read`, `calendar:write`, `email:send` — gives users something readable to approve or reject. The granularity is intentionally coarse, because the value here is legibility, not precision. You review it once, click allow, and move on.

Cloud IAM extended RBAC to infrastructure. An EC2 instance gets an IAM role. The role lets it read from a specific S3 bucket and write to a specific DynamoDB table. The principal is stable (the instance identity), the resources are known (the specific bucket and table), the permissions are set at deployment time.

All three of these assume: a stable principal doing predictable things, with permissions set in advance.

An AI agent violates all of that.

---

## What's actually different about agents

The same agent deployment might, for one task, call `read_file`, then `execute_sql`, then `send_email`. For a different task, it might call `list_calendar_events`, `create_meeting`, and `update_crm_contact`. The tool sequence is determined at runtime by a language model's reasoning process, responding to an open-ended natural language task. You can't predict it at provisioning time. You can't write a meaningful IAM policy for it — either it's so broad it covers everything the agent might ever do, or it's so narrow the agent can't function, or it's a sprawling mess of hyper-specific roles that nobody can maintain.

The other problem is that agents don't just call tools — they chain them. The output of step N feeds into step N+1. Which means the arguments to step N+1 are influenced by whatever was in the data the agent retrieved in step N. Including, potentially, adversarial content in that data.

Here's a concrete version: an agent summarises supplier contracts and emails the summaries to the legal team. Step one: query the supplier directory for the latest contract ID. Step two: fetch the contract document. Step three: summarise. Step four: email. An OAuth scope of `email:send` says the agent can send email. It says nothing about to whom. If a malicious instruction in the contract document (step two) redirects the email destination from `legal@corp.example.com` to `attacker@external.com`, the scope check passes. The attacker gets the document. Nothing in the OAuth model caught this.

That's the gap between "authorises the capability class" and "authorises this specific exercise of the capability". For agents, the gap is exploitable. This is discussed in more detail in [the prompt injection post](./01-prompt-injection-policy-layer.md), but the core point here is: an access control model that doesn't constrain arguments can't actually enforce least privilege for agents.

There's also the lifetime problem. An employee's IAM role persists for years. A microservice's service account persists for the lifetime of the app. That stability makes sense for those principals. An agent task is ephemeral — it runs, it completes, it's done. Giving the agent a long-lived credential with all the permissions it might ever need means those permissions persist across tasks, accumulating into exactly the kind of over-provisioned access that least privilege is designed to prevent. An injection attack that exploits permissions granted for task 1 but not needed for task 47 is a direct consequence of not scoping access per-task.

And finally: there's no human in the loop at enforcement time. OAuth has a consent screen — the user sees what's being requested and approves it. Agent tool calls happen autonomously, at machine speed, potentially dozens per session. The policy has to be precise enough that the enforcement layer can make correct allow/deny decisions without a human reviewing individual calls. That's a much harder bar than "show the user a scope list and let them click OK."

---

## The capability token model

The solution that fits these constraints has a name with a long history — capability-based security, dating to Dennis and Van Horn's work in the 1960s — but the specific shape for agents is worth spelling out.

Instead of a long-lived role assignment, each agent task gets a short-lived JWT capability token. The token is issued by a capability issuer that has authenticated the agent's identity and compiled the operator's policy into a cryptographically signed grant. It encodes, precisely, what this agent is allowed to do during this task — not as opaque scope strings, but as machine-evaluable conditions over actual argument values.

Here's what a token payload looks like for a supplier analytics agent:

```json
{
  "iss": "https://capability-issuer.corp.example.com",
  "aud": "https://tool-gateway.corp.example.com",
  "sub": "did:web:supplier-analytics-agent.corp.example.com",
  "jti": "01J3K7M2N8P4Q6R0S5T9V2W1X",
  "iat": 1718200000,
  "exp": 1718203600,
  "tools": {
    "execute_sql": {
      "allowedOperations": ["SELECT"],
      "argumentSchema": {
        "query": { "pattern": "^SELECT\\s", "maxLength": 8192 },
        "database": { "enum": ["supplier_db", "analytics_db"] }
      },
      "maxCalls": 100
    },
    "read_file": {
      "allowedPaths": ["/data/contracts/**", "/data/invoices/**"],
      "maxCalls": 200
    },
    "send_email": {
      "allowedRecipientDomains": ["corp.example.com"],
      "maxCalls": 5
    }
  }
}
```

Every condition in there is evaluable against a concrete call. `allowedOperations: ["SELECT"]` means the proxy extracts the first keyword from the SQL query and checks it against that list — not against the model's stated intent, against the actual argument value. `allowedRecipientDomains` means that email to `attacker@external.com` gets blocked, regardless of what injection produced the call. `maxCalls: 5` means after five emails, the tool is exhausted for the lifetime of this token.

The token expires in an hour. When the task is done, access is gone. A subsequent task gets a new token scoped to what that task requires. There's no residual access to exploit.

---

## Per-call enforcement is what makes this real

The token is only useful if it's enforced at the right level of granularity. A session-level check — "does this agent have a valid token?" — misses the point. The enforcement has to happen on every individual call, against the actual arguments.

For `execute_sql`, that means: pull the first keyword out of the query. Check it against `allowedOperations`. Match the query against the `pattern`. Verify the `database` argument is in the enum. Check the Redis rate counter and decrement it. All five checks run on the actual values in the actual call. An injection attack that produces `DELETE FROM users` as the query argument fails the operation check and the pattern check, regardless of how it was phrased to the model.

The enforcement layer that does all this is the tool gateway — the proxy that sits between the agent runtime and the upstream tools. Every call goes through it. The upstream servers never see an unauthorised call because the only path to them is through the gateway. This is explained in more detail in [the policy proxy post](./06-mcp-policy-proxy.md), but the architectural principle is simple: you can only enforce least privilege if you can intercept the call.

---

## Emergency controls that work at runtime

Here's something classical access control doesn't do well: stopping an agent mid-run.

If you have a long-lived IAM role assigned to an agent process and the agent starts doing something unexpected, your options are limited. You can kill the process. You can revoke the role. Both of those have latency — they require changes that propagate.

The token model gives you two much faster levers.

**Token revocation.** Every capability token has a JTI (JWT ID). Push that ID to a Redis revocation list and every subsequent call from that agent using that token is denied within milliseconds. No redeploy. No config change. One write to Redis.

**Kill-switch.** One flag in Redis that suspends all agent activity for a deployment instantly. Set it and every call fails until it's cleared, regardless of which tokens are in flight. That's your emergency stop when something is actively wrong and you need agents to stop *now*.

These are operational controls that matter more than they might sound. Agents operate at machine speed. Between "we see something wrong in the audit log" and "we need this to stop," there might be seconds. The difference between a control that takes effect in milliseconds and one that takes minutes can be the difference between an incident and a significant breach.

---

## Delegation without escalation

Modern agent deployments increasingly involve chains of agents. An orchestrator breaks down a complex task and delegates sub-tasks to specialist agents. Each sub-agent has its own token, its own identity, its own policy.

The problem: the orchestrator needs to give the sub-agent enough access to do its job, but shouldn't be able to give it more than the orchestrator itself has. Classical access control handles this poorly — OAuth token exchange exists but requires specific infrastructure support; IAM role chaining has limits.

The capability token model handles it with an attenuation property: when the orchestrator derives a token for a sub-agent, the issuer verifies that every permission in the derived token is a subset of the parent. The orchestrator is limited to `SELECT` on `supplier_db`? The sub-agent's derived token can't grant `INSERT` on `orders_db`. It can only narrow, never widen.

This preserves least privilege through arbitrarily deep delegation chains without any special configuration per-chain. The math is simple: you can give away a subset of what you have, but you can't give away what you don't have.

---

## DPoP and the token theft problem

There's one more wrinkle worth mentioning. A signed JWT can be stolen. If an attacker intercepts a valid capability token, can they use it from a different process?

DPoP (Demonstrating Proof-of-Possession, RFC 9449) closes this gap. With DPoP, the agent generates a key pair and includes the public key in its token request. Each subsequent call includes a short-lived signed proof that the caller holds the corresponding private key. A stolen token is useless without the private key, which never leaves the legitimate agent process.

For most deployments this is an additional layer rather than a baseline requirement. But for high-sensitivity deployments where token interception is a real concern, it's the right mechanism.

---

## What changes operationally

Adopting this model changes some workflows in ways that are worth flagging.

**Provisioning** becomes authoring a YAML manifest and merging it through normal code review. No cloud console, no IAM UI. The manifest is version-controlled, diffable, reviewable by security engineers who don't have cloud admin access. Policy changes are pull requests.

**Onboarding a new agent type** means writing a new manifest. The capability issuer serves it to authenticated agents with the right identity. No cross-team tickets for cloud role assignments.

**Responding to an incident**: identify the token JTI from the audit log, push it to the revocation list (takes effect in milliseconds), review the full session call sequence, tighten the manifest. The agent and model don't need to be redeployed to update policy.

**Multi-tenant deployments**: each tenant's agent session gets a token with tenant-scoped conditions. An agent serving tenant A literally cannot be made to query tenant B's database, even by a prompt injection that tries to redirect it. The token conditions are scoped and the gateway enforces them on the actual arguments.

---

## Honest about what it doesn't solve

The capability token model is not a complete solution to AI security problems, and it's worth being straight about that.

It doesn't prevent the model from producing bad outputs that don't involve tool calls. Content safety is a separate problem.

It doesn't prevent all prompt injection. If an injection causes the agent to call a permitted tool with permitted arguments — within the scope defined in the token — the call will go through. The blast radius is bounded by the token conditions, but it isn't zero. Defence in depth (narrow tool schemas, read-only database credentials, human confirmation triggers for high-impact actions) is still necessary.

It requires well-written manifests. A token that permits `allowedOperations: [SELECT, INSERT, UPDATE, DELETE]` is far weaker than one that permits only `SELECT`. The enforcement gives effect to the policy you write. Writing tight policies requires the same careful thinking as writing secure code.

And it requires the gateway to be the only path to tools. If the agent can reach the SQL database directly — bypassing the gateway — capability token enforcement is meaningless. The architecture has to ensure every tool call goes through the enforcement point.

---

## The principle is old. The mechanism is new.

Least privilege for AI agents isn't a solved problem you implement once and move on from. It's an ongoing practice. New tools get added. New attack techniques get discovered. Your understanding of what "minimum necessary access" means for each agent type deepens over time.

What the capability token model gives you is the right foundation: precise, evaluable, version-controlled, cryptographically enforced conditions, checked at the only moment that matters — when the action is about to happen.

For the full picture of how the token interacts with the gateway's enforcement pipeline, see [Building a policy proxy for MCP: design choices and trade-offs](./06-mcp-policy-proxy.md). For the zero trust architecture these tokens sit inside, see [Zero trust for AI agents](./04-zero-trust-ai-agents.md).

---

*Previous: [The prompt injection problem: why every AI agent needs a policy layer](./01-prompt-injection-policy-layer.md)*

# Least-privilege for AI: translating a 20-year-old principle to the agent era

*Audience: security architects and developers building multi-tool agent systems*

---

## The principle has not changed. The problem has.

Least privilege is one of the oldest ideas in computer security. Give every process, user, and service only the permissions it needs to do its job — no more. The formulation dates to Saltzer and Schroeder's 1975 paper on the protection of information in computer systems, and it has been a cornerstone of security design ever since.

Nothing about the principle itself needs updating for the AI agent era. The problem is that the mechanisms we have used to implement it for the past two decades — RBAC, OAuth scopes, and IAM roles — do not translate cleanly to multi-tool, multi-step agent workflows. Using them directly leaves significant gaps. Understanding why requires looking at what is structurally different about agents.

---

## What classical access control was designed for

RBAC (Role-Based Access Control) was designed for human users and long-lived service identities. A developer gets read access to the code repository. A billing service gets write access to the invoices table. Roles are assigned once, checked at authentication time, and rarely change mid-session. The principal is stable, the resource is known in advance, and the action set is bounded.

OAuth 2.0 scopes added a layer of delegation: a user can grant a third-party application a subset of their permissions. Scopes like `read:email` or `repo:write` are coarse-grained claims attached to an access token. The token is issued for a specific client and a specific user, and its validity period is measured in hours.

Both models assume a relatively static relationship between a principal, a set of resources, and a set of allowed operations. You define the policy at provisioning time, and enforcement is a simple membership check: does this principal have role X? Does this token include scope Y?

---

## What is structurally different about agents

An AI agent is a different kind of principal. Several properties distinguish it from the identities classical access control was designed to govern.

### Dynamic tool selection

A human user who logs into a system knows which actions they intend to take. An agent, by design, selects tools dynamically based on the task it is given and the state of the conversation. The same agent instance might call `read_file`, then `execute_sql`, then `send_email` in a single task — each with different argument shapes, each against a different backend, each with a different risk profile.

An OAuth scope like `tools:invoke` tells you nothing useful about which tools can be called, with what arguments, at what rate, or under what conditions. A role like `agent-operator` is equally opaque. The access control decision needs to happen per-tool-call, not per-session.

### Multi-step chaining

Agents plan and execute sequences of steps. Step 3 depends on the output of step 2, which shaped the arguments to step 1. A classical access control check at session establishment cannot account for the data that flows between steps. An attacker who can influence step 2's output can potentially manipulate the arguments that step 3 will pass to a sensitive tool — which is the mechanics of prompt injection.

Effective least privilege here means constraining not just *which* tools an agent can call, but *what arguments* it can pass to each tool, evaluated at call time against actual argument values.

### Short-lived, task-scoped execution

Agents are not long-lived service accounts. A useful mental model is that each task is a mini-session with its own permission budget. The agent should be able to do exactly what this task requires: query these tables with these operations, read files in this directory, send messages in this channel. Once the task is complete, the permission budget should be exhausted or expired.

Assigning a broad IAM role or a long-lived OAuth token to an agent process grants it far more access than any individual task needs — and leaves that access available for an attacker who finds a way to influence the agent's behaviour.

### No stable human-in-the-loop

When an OAuth flow prompts a human to approve access, there is a conscious decision point. Agents, by design, act autonomously. There is no human to review each tool call before it executes. The policy must encode the operator's intent in advance, precisely enough that the enforcement layer can make correct decisions without human review of every call.

---

## Why the capability-token model fits

The capability-token model addresses each of these structural differences.

A capability token is a short-lived, signed JWT issued by a capability issuer to a specific agent identity for a specific task scope. It carries structured conditions that constrain exactly what the bearer may do with each tool:

```yaml
# Policy YAML — authored by the operator, version-controlled
tools:
  execute_sql:
    allowedOperations:
      - SELECT
    argumentSchema:
      query:
        pattern: "^SELECT \\S"
        maxLength: 4096
    maxCalls: 50
  read_file:
    allowedPaths:
      - "/data/reports/**"
    maxCalls: 100
  send_email:
    allowedRecipientDomains:
      - "corp.example.com"
    maxCalls: 5
```

This policy is compiled into a signed JWT. At enforcement time, every tool call is checked against the token's conditions. There is no need to consult a central policy service for each call — the signed token is the authorisation decision, already made and cryptographically bound.

### Per-call, per-argument enforcement

The enforcement engine evaluates conditions against actual call arguments at the moment of the call. `allowedOperations: ["SELECT"]` extracts the first word of the `query` argument and checks it. `argumentSchema.query.pattern` matches the full query string. These checks happen on real data, not on an abstract scope claim.

### Short expiry with revocation

Tokens have short lifetimes — measured in minutes or hours, not days. The issuer can also push a token to the revocation list or activate a global kill-switch at any time. The agent's access is not just scoped; it is actively manageable during execution.

### Attenuation chains

A downstream component can further restrict a capability token without being able to widen it. If agent A delegates to agent B for a sub-task, B's token can only have a subset of A's permissions. This preserves least privilege across multi-agent pipelines.

### Cryptographic binding to agent identity

The token is bound to the agent's DID or client ID. A token issued for agent `did:web:billing-agent.corp.example.com` cannot be used by a different agent identity. If the token is stolen and replayed, DPoP (Demonstrating Proof-of-Possession) binding prevents it from being used from a different client instance.

---

## Mapping old concepts to new ones

| Classical model | Agent equivalent |
|---|---|
| IAM role | Capability token with tool-scoped conditions |
| OAuth scope | `tools` map in the capability manifest |
| Session permission check | Per-call condition evaluation |
| Scope grant approval | Operator-authored YAML policy, version-controlled |
| Role assignment | Token issuance (short-lived, task-scoped) |
| Role revocation | Kill-switch or token revocation list |

The concepts translate — but the granularity and the timing of enforcement must shift from session-level to call-level.

---

## What this looks like in practice

An operator authors a YAML capability manifest that describes what a specific agent role may do. That manifest is checked into version control, reviewed like any security-sensitive configuration, and validated against the shared schema before deployment.

When an agent needs to start a task, it requests a token from the capability issuer. The issuer authenticates the agent identity (via IdP, DID federation, or SCIM-provisioned role mapping), compiles the relevant manifest into a JWT, signs it, and returns it. The agent includes the token in every tool call.

The policy proxy (the tool gateway) receives each call, verifies the token, evaluates its conditions against the call arguments, applies any obligations, records the decision in the audit ledger, and either forwards the call or returns a denial. The agent never has direct access to the backend — only the gateway does.

The result is a system where every tool call is governed by an explicit, reviewable, version-controlled policy, evaluated against real arguments, producing a tamper-evident record. That is least privilege applied to the agent era: not a broad scope granted at session time, but a precise, short-lived authorisation evaluated at the only moment that matters — when the action is about to happen.

---

*Previous: [The prompt injection problem: why every AI agent needs a policy layer](./01-prompt-injection-policy-layer.md)*

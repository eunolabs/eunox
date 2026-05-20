# Least-privilege for AI: translating a 50-year-old principle to the agent era

*Audience: security architects and developers building multi-tool agent systems*

---

## The principle has not changed. The problem has.

Least privilege is one of the oldest and most durable ideas in computer security. Give every process, user, and service only the permissions it needs to do its job — no more, no less. The formulation dates to Jerome Saltzer and Michael Schroeder's 1975 paper, *The Protection of Information in Computer Systems*, which articulated eight design principles for building secure systems. Fifty years of subsequent practice has not invalidated a single one of them.

Nothing about the principle itself needs updating for the AI agent era. What does need updating is the set of mechanisms we use to implement it. For the past two decades, least privilege in software systems has been implemented primarily through three mechanisms: Role-Based Access Control (RBAC), OAuth 2.0 scopes, and cloud IAM roles. These are mature, well-understood, and well-tooled. They are also structurally ill-suited to multi-tool, multi-step agentic workflows.

Using them directly to govern AI agents leaves significant, exploitable gaps. This post explains why — and what a more appropriate model looks like.

---

## A brief history of how we got here

Understanding why classical access control doesn't fit agents requires understanding what problems it was designed to solve and the assumptions it bakes in.

### The origins of RBAC

Role-Based Access Control emerged from work done in the 1970s and formalised in NIST publications in the mid-1990s. The core insight was that managing permissions for individual users in large organisations was operationally intractable. Assigning permissions to roles — and then assigning users to roles — made large-scale permission management feasible.

RBAC assumes a relatively stable cast of principals (employees, contractors, service accounts), a known set of resources (files, databases, applications), and a bounded set of operations (read, write, admin). Permission assignments are made at provisioning time and reviewed periodically. The enforcement question — "is this principal allowed to perform this action?" — is answered by a membership check: does this user have a role that grants this permission?

This works well for human users interacting with defined systems. It was extended to service accounts — background processes with stable identities that need consistent access to specific resources — with similar success.

### OAuth 2.0 and the delegation layer

OAuth 2.0, standardised in RFC 6749 in 2012, addressed a different problem: how to allow a user to grant a third-party application access to their resources without sharing their credentials. The scope mechanism — a set of string claims in an access token that describes what the bearer is permitted to do — enabled coarse-grained delegation.

Scopes like `repo:read`, `calendar:write`, or `email:send` are human-readable labels that a user can review when approving an OAuth authorisation request. The granularity is intentionally coarse: the value of the scope mechanism is its legibility to humans who need to make approval decisions, not its precision as a policy language.

OAuth tokens typically have multi-hour lifetimes. They are issued to a specific client application for a specific user. Revocation exists but is rarely used in practice because the expectation is that tokens are short enough to expire naturally.

### Cloud IAM: RBAC at infrastructure scale

Cloud IAM (AWS IAM, Azure RBAC, GCP IAM) extended the RBAC model to infrastructure resources. An IAM role might grant an EC2 instance the ability to read from an S3 bucket or write to a DynamoDB table. The principal is stable (the instance's IAM role), the resources are known (the specific bucket or table), and the policy is set at deployment time.

Cloud IAM is sophisticated in many ways — it supports resource-level conditions, tag-based access control, and cross-account delegation. But its foundational model is still: a stable principal, a known resource, a bounded action set, policy set at configuration time.

---

## What is structurally different about agents

An AI agent is a fundamentally different kind of principal. The structural differences are not superficial — they go to the assumptions that RBAC, OAuth, and IAM were built on.

### Difference 1: Dynamic, runtime tool selection

A human user who logs into a system generally knows what they are going to do. They open the email client to read email. They connect to the database to run a report. Their actions are predictable enough that access control policies set at provisioning time are adequate.

An AI agent's tool usage is determined at runtime by the model's reasoning process, based on the task description and the evolving state of the conversation. The same agent deployment might, for a given task, call `read_file`, `execute_sql`, and `send_email` in sequence — and for a different task, call `list_calendar_events`, `create_meeting`, and `update_contact`. The tools used, the arguments passed, and the sequence of operations are all emergent from the model's reasoning. They cannot be fully predicted at provisioning time.

An OAuth scope of `tools:invoke` or an IAM role of `agent-service-role` says nothing useful about which specific tools can be called, with what arguments, against which data, at what rate. It is either too broad (every tool, any argument, unlimited rate) or requires an impractical proliferation of hyper-specific roles (one IAM role per tool per agent type per environment).

The access control decision for an agent must happen *per-call*, not *per-session*. The relevant policy question is not "is this agent authenticated?" but "is this specific call, with these specific arguments, to this specific tool, permitted under this agent's current task scope?"

### Difference 2: Multi-step chaining and data provenance

Agents plan and execute sequences of steps. The output of step N becomes part of the input to step N+1. A classical access control check at session establishment has no visibility into the data flowing through the agent's reasoning process during execution.

Consider an agent tasked with "summarise the latest contract from our supplier directory and send it to the legal team." The agent might:

1. Query the supplier directory database to get the latest contract ID
2. Fetch the contract document using the ID
3. Call a summarisation tool
4. Send the summary by email

A prompt injection attack embedded in the contract document (step 2) could attempt to redirect step 4: instead of emailing `legal@corp.example.com`, the injected instruction might cause the agent to send the full document to `attacker@external.com`. 

An OAuth token with `email:send` scope would not prevent this. The scope says the agent can send email — it says nothing about to whom, or under what circumstances. Effective least privilege here requires constraining the recipient to `corp.example.com` domains, and that constraint must be evaluated at the moment step 4 executes, against the actual recipient argument, not at session establishment.

This is the core limitation of coarse-grained scope-based access control in agentic systems: it authorises the capability class (`email:send`) but not the specific exercise of that capability (`email:send to legal@corp.example.com only`). In a world where adversarial content can influence the arguments the agent passes to its tools, the gap between "can send email" and "can send email only to these recipients" is an exploitable attack surface.

### Difference 3: Short-lived, task-scoped execution contexts

Human users and service accounts are long-lived principals. An employee's IAM role persists for the duration of their employment. A microservice's service account persists for the lifetime of the application. This stability is appropriate for their use cases.

An AI agent task is inherently ephemeral. A useful mental model is that each task is a bounded execution context with its own permission budget. The billing-summary agent handling a particular user's request should have access to exactly the data and tools it needs for that request — and when the request is complete, those permissions should expire. There should be no residual access from previous tasks that a later injection attack could exploit.

Assigning a broad, long-lived IAM role to the agent process means that the agent's permissions persist indefinitely, across tasks, regardless of what the current task actually requires. An injection attack that occurs during task 47 can exploit permissions that were granted (but not needed) during task 1.

Short-lived, task-scoped tokens are the right granularity. Each task gets a fresh token with exactly the permissions that task requires. When the task ends, the token expires. There is no residual access to exploit.

### Difference 4: No human-in-the-loop at enforcement time

OAuth authorisation flows have a human decision point built in. The user sees a consent screen: "This application is requesting access to your email and calendar. Allow?" They can review the scope and make a judgement.

Agents operate autonomously. When the agent calls `execute_sql` with a dynamically constructed query, there is no human reviewing the specific query before it executes. The policy must encode the operator's intent with enough precision that the enforcement layer can make correct allow/deny decisions automatically — without human review of individual calls — across a space of possible arguments that the operator cannot fully enumerate in advance.

This changes the nature of the policy problem. Classical access control policies describe what a principal can do in terms of static role memberships and resource-level permissions. Agent policies must describe what a principal can do in terms of runtime conditions over actual argument values. The policy language must be expressive enough to cover the cases the operator cares about — and the enforcement must be precise enough to give effect to that expression.

### Difference 5: Composable, multi-agent pipelines

Modern AI deployments increasingly involve multiple cooperating agents. An orchestrator agent breaks a complex task into sub-tasks and delegates them to specialist agents. A coding agent spawns sub-agents to run tests or perform code review. A research agent delegates fact-checking to a verification agent.

In these pipelines, each agent has its own identity, its own tool access, and its own policy. The orchestrator must be able to delegate a subset of its permissions to downstream agents — but it must not be able to grant permissions it does not itself possess, and it must not be able to escalate a downstream agent's permissions beyond its own.

Classical access control has limited support for constrained delegation of this kind. OAuth's token exchange (RFC 8693) allows delegation but requires explicit support from the authorisation server. IAM role chaining has limits and does not support fine-grained constraint attenuation. Neither model was designed for the case where permissions need to be progressively narrowed through a chain of delegating agents.

---

## Why the capability-token model fits

The capability-token model addresses each of these structural differences. It was not invented for AI agents — the concept of capability-based security dates to the 1960s work of Dennis and Van Horn — but the properties it provides map well to the agentic problem space.

In the capability-token model, a capability token is a signed, self-contained authorisation grant that specifies exactly what its bearer may do. The token is:

- **Issued** by a trusted capability issuer that has authenticated the agent's identity and compiled the operator's policy manifest into a signed JWT
- **Short-lived**, with an expiry measured in minutes to hours
- **Task-scoped**, carrying only the permissions the current task requires
- **Condition-bearing**, containing structured rules that constrain tool usage to specific argument patterns
- **Cryptographically bound** to the agent's identity, preventing it from being used by a different agent

Here is an example token payload for a supplier analytics agent:

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

This token encodes, in machine-evaluable form, exactly what this agent is permitted to do during this task. The policy is precise. Every condition is evaluable against actual call arguments. The token expires in one hour. It is signed by the capability issuer's private key — the agent cannot modify it, and a forged token will fail signature verification.

### Per-call, per-argument enforcement in detail

When the agent sends a tool call, the policy proxy extracts the token and evaluates each applicable condition against the actual arguments. This is not a membership check — it is not "does this agent have role X?" — it is an evaluation of structured predicates over concrete values.

For `execute_sql`:
- Extract the first keyword from `args.query`. If it is not in `allowedOperations`, deny.
- Match `args.query` against the pattern `^SELECT\s`. If it does not match, deny.
- Check `len(args.query) <= 8192`. If not, deny.
- Check `args.database` is one of `["supplier_db", "analytics_db"]`. If not, deny.
- Decrement the call counter in Redis. If the counter is at zero, deny.

These checks happen on the actual values in the actual call, not on abstract claims. An injection attack that causes the agent to pass `DROP TABLE users` as the `query` argument fails the `allowedOperations` check and the pattern check — regardless of how that string got into the agent's reasoning process.

### Short expiry and active revocation

Tokens expire after at most one hour. But operators do not always have an hour. An agent that appears to be behaving unexpectedly — making unusual queries, accessing unusual files, sending emails to unusual recipients — can be stopped immediately:

- **Token revocation:** Push the token's JTI to the Redis revocation list. Subsequent calls from the agent with that token are denied. Takes effect in milliseconds.
- **Kill-switch:** Set a kill-switch flag in Redis for the deployment. All agent activity stops immediately, regardless of which tokens are in flight. Takes effect before the next call to the proxy.

These controls do not require redeploying the agent, updating the model, or modifying any configuration files. They are operational controls available to whoever has write access to the Redis instance.

### Attenuation without amplification

When agent A needs to delegate a sub-task to agent B, A's token can be used to derive B's token — but only with equal or lesser permissions. The attenuation property is enforced by the capability issuer: it checks that every permission in the derived token is a subset of the parent token's permissions. If A is limited to `SELECT` on `supplier_db`, B's derived token cannot grant `INSERT` on `orders_db`.

This preserves least privilege through arbitrarily deep delegation chains. An orchestrator agent cannot escalate its sub-agents' permissions beyond its own. A compromised sub-agent cannot use a derived token to access resources the orchestrator was not permitted to access.

### Cryptographic identity binding and DPoP

Each token is issued to a specific agent identity — a DID (Decentralised Identifier) or client ID that the capability issuer authenticated before issuing the token. The `sub` claim binds the token to that identity.

To prevent token theft and replay, the gateway supports DPoP (Demonstrating Proof-of-Possession, RFC 9449). With DPoP, the agent includes a signed proof-of-possession token with each request, demonstrating that it holds the private key corresponding to the public key in its identity. A token stolen from one agent instance cannot be used by a different agent instance, because the different instance does not have the private key needed to generate a valid DPoP proof.

---

## The full authorisation flow: from policy to enforcement

Walking through the complete flow makes the architecture concrete.

### 1. Operator authors the policy manifest

An operator — a security engineer, a platform team member, or a developer with the appropriate responsibility — authors a YAML capability manifest:

```yaml
# manifests/supplier-analytics-agent.yaml
agentId: supplier-analytics-agent
version: "1.0"
tools:
  execute_sql:
    allowedOperations:
      - SELECT
    argumentSchema:
      query:
        pattern: "^SELECT\\s"
        maxLength: 8192
      database:
        enum:
          - supplier_db
          - analytics_db
    maxCalls: 100
  read_file:
    allowedPaths:
      - "/data/contracts/**"
      - "/data/invoices/**"
    maxCalls: 200
  send_email:
    allowedRecipientDomains:
      - corp.example.com
    maxCalls: 5
```

This manifest is committed to the version control system. Changes go through the same review process as any security-sensitive configuration — pull request, approval from a designated reviewer, automated schema validation in CI.

The shared `AgentCapabilityManifest` schema is public (Apache 2.0 licensed). The policy format is the same whether you are running the local proxy for development or the full gateway in production. There is no format migration when you move between environments.

### 2. Agent requests a capability token

When the agent process starts a new task, it requests a capability token from the capability issuer. The request includes:

- The agent's identity credential (an OIDC token from the IdP, or a signed DID assertion for partner-federated agents)
- The task scope (which manifest to use)
- The DPoP public key (for possession binding)

The capability issuer authenticates the agent identity — checking the OIDC token with the IdP, or resolving and verifying the DID for federated partners. It looks up the applicable manifest for this agent identity and task scope. It compiles the manifest into a JWT payload, signs it with its private key (RS256 or EdDSA), and returns the signed token.

For enterprise deployments, the signing key lives in a KMS (Azure Key Vault, AWS KMS, or GCP Cloud KMS), never in the issuer process's memory. The KMS enforces HSM-backed key custody, key rotation, and access logging.

### 3. Agent includes the token in every tool call

The agent runtime attaches the capability token to every outgoing MCP tool call — in the `Authorization` header or as an MCP protocol extension, depending on the transport. The agent does not interpret the token's contents. It is simply a credential that the gateway will validate.

### 4. Gateway enforces the policy

The tool gateway receives the call. It:

1. Extracts and verifies the capability token (signature, expiry, issuer, audience, revocation, kill-switch)
2. Identifies the tool being called and locates the applicable conditions in the token
3. Evaluates each condition against the actual call arguments
4. Applies any obligation conditions (rate limit, parameter injection)
5. Records the decision in the signed hash-chained audit ledger
6. Forwards the call (ALLOW) or returns an error (DENY)

Steps 1–5 all happen before the call reaches the upstream MCP server. If any step fails, the call is denied and the upstream server is never contacted.

### 5. Operator reviews the audit trail

The audit ledger records every decision — allowed and denied calls, the arguments, the token JTI, the agent identity, and the decision rationale. The records are exportable via the `/api/v1/audit/export` endpoint in OCSF format, suitable for ingestion into any SIEM.

The signed hash chain makes the ledger tamper-evident: if any record is deleted or modified, the chain breaks, and the break is detectable by any party that can verify the signing keys. This is the property that makes the audit trail useful for compliance and incident response, not just operational monitoring.

---

## Mapping old concepts to new ones

The concepts from classical access control all have analogues in the capability-token model. The differences are in granularity and timing.

| Classical concept | Classical mechanism | Agent equivalent | Key difference |
|---|---|---|---|
| Principal identity | Username, service account | Agent DID or client ID | Ephemeral per-task, DPoP-bound |
| Permission assignment | Role membership | Capability token issuance | Short-lived, task-scoped |
| Access check | Role membership lookup | Per-call condition evaluation | Evaluated against actual arguments |
| Policy definition | RBAC role config, IAM policy JSON | YAML capability manifest | Per-tool, per-argument conditions |
| Scope | OAuth scope string | `tools` map in token | Machine-evaluable conditions, not opaque strings |
| Revocation | Account disable, role removal | Token JTI revocation, kill-switch | Takes effect in milliseconds, no redeploy |
| Delegation | Role assumption, OAuth token exchange | Token attenuation chain | Permissions can only narrow, never widen |
| Audit | IAM access logs, OAuth grant records | Signed hash-chained OCSF events | Tamper-evident, argument-level detail |

The core principle is the same — grant only what is needed. The mechanism is different — because what "only what is needed" means for an agent is per-tool, per-argument conditions evaluated at call time, not a role assigned at provisioning time.

---

## What this means operationally

Adopting the capability-token model changes how several operational functions work.

**Provisioning** now means authoring a YAML manifest and checking it into version control, rather than assigning IAM roles through a cloud console. The manifest is the source of truth. It is reviewable, diffable, and auditable.

**Onboarding a new agent type** means writing a new manifest file, having it reviewed, and merging it. The capability issuer can be configured to serve the new manifest to authenticated agents with the corresponding identity. No cloud console access required.

**Responding to an incident** means: identify the token JTI from the audit records, push it to the revocation list (takes effect immediately), review the full call sequence in the audit ledger, tighten the manifest, and redeploy the manifest (not the agent or the model).

**Compliance evidence** is produced automatically. Every call, with its full argument payload and decision rationale, is recorded in a signed OCSF event that can be exported for SOC 2, ISO 27001, or any other framework's audit evidence requirements.

**Multi-tenant deployments** are handled by issuing separate capability tokens per tenant, with tenant-scoped conditions (e.g., `database: { enum: ["tenant_a_db"] }`). An agent serving tenant A cannot be made to query tenant B's database, even if a prompt injection attack attempts to redirect it — the token's conditions are tenant-scoped and the gateway enforces them.

---

## The limits of the model

The capability-token model is not a complete solution to all AI security problems. It is important to be honest about what it does and does not address.

**It does not prevent the model from producing incorrect or harmful outputs** that do not involve tool calls. Content policy and output safety are separate concerns.

**It does not prevent all prompt injection.** If an injection successfully causes the agent to call a tool with arguments that are within its permitted scope, the call will be allowed. The blast radius is bounded by the token's conditions — but it is not zero. Defence in depth (input sanitisation, narrow tool schemas, human-in-the-loop for high-impact actions) remains necessary.

**It requires well-written manifests.** A manifest that permits `allowedOperations: [SELECT, INSERT, UPDATE, DELETE]` provides much weaker protection than one that permits only `SELECT`. The model enforces the policy you write. Writing narrow, correct policies requires the same discipline as writing secure code.

**It requires the gateway to be the only path to tools.** If the agent can reach the SQL database directly (without going through the gateway), the capability-token enforcement is bypassed entirely. The architecture must ensure that every tool call goes through the gateway.

---

## A foundation, not a destination

Least privilege for AI agents is not a solved problem that you implement once and move on from. It is a practice — one that requires ongoing attention as your agent deployment evolves, as new tools are added, as new attack techniques are discovered, and as your understanding of what "only what is needed" means for each agent type deepens.

The capability-token model provides the right foundation for that practice: a precise, evaluable, version-controlled, cryptographically enforced expression of what each agent may do, evaluated at the only moment that matters — when the action is about to happen. The principle is fifty years old. The mechanisms are new. The work of applying them carefully is yours to do.

---

*Previous: [The prompt injection problem: why every AI agent needs a policy layer](./01-prompt-injection-policy-layer.md)*

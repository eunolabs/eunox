# Zero trust for AI agents: a practitioner's guide

*Audience: security architects and platform engineers deploying AI agent infrastructure*

---

## From buzzword to engineering discipline

Zero trust has been one of the most discussed — and most misunderstood — concepts in enterprise security over the past decade. In its original, precise formulation by John Kindervag at Forrester Research in 2010, zero trust is a simple and powerful idea: stop assuming that anything inside your network perimeter can be trusted, and start verifying every access request, every time, regardless of where it originates.

The perimeter model that zero trust replaced had a clear problem: once an attacker breached the perimeter — through a phishing attack, a compromised VPN credential, a misconfigured firewall rule — they found a network that largely trusted its own inhabitants. Lateral movement was easy. Resources that were supposed to be internal-only were accessible from anywhere inside. The perimeter was supposed to be the hard shell protecting the soft interior, but once the shell cracked, the interior was defenceless.

Zero trust's answer: move the enforcement point from the perimeter to the resource. Every request to every resource must be authenticated, authorised, and verified — regardless of whether it comes from inside or outside the traditional perimeter. Trust nothing implicitly. Verify everything explicitly. Enforce at the point of access.

The practical implementation of this principle has evolved significantly since 2010. NIST's 800-207 guidance, published in 2020, articulated zero trust as a set of tenets rather than a specific technology: verify explicitly, use least-privilege access, assume breach. BeyondCorp at Google, Zero Trust Architecture from NIST, and numerous vendor implementations have translated these tenets into concrete engineering patterns: identity-based access control, software-defined perimeters, continuous validation, micro-segmentation.

What none of this literature anticipated was the emergence of AI agents as principals in enterprise systems — autonomous processes that make API calls, access data, and take actions on behalf of users, with a level of autonomy and a breadth of capability that no previous category of software had. This post applies zero trust principles to AI agents concretely, using euno's architecture as a worked example.

---

## Why AI agents break classical zero trust implementations

Before getting to the solution, it is worth being precise about why the problem is different for AI agents than for the conventional workloads that existing zero trust implementations were designed to handle.

### Unpredictable access patterns

A conventional workload — a microservice, a batch job, an API server — has a known access pattern. It makes predictable calls to a defined set of resources. The access control policy for it can be written in advance: service A can read from database table B, service C can write to message queue D. Deviations from the expected pattern are rare and usually indicate a bug or an attack.

An AI agent's access pattern is determined at runtime by a language model's reasoning process, in response to an open-ended natural language task. The same agent deployment might, for a given user task, call `read_file`, then `execute_sql`, then `send_email`. For a different task, it might call `list_calendar`, then `create_event`, then `update_crm_contact`. The tools used, the arguments passed, the sequence and combination of operations — all emerge from the model's reasoning. They cannot be fully predicted at deployment time.

This creates a challenge for access control systems designed around predictable access patterns. A network segmentation rule that allows service A to reach resource B works when the relevant requests come in predictable forms. A policy for an AI agent must work across the full space of possible tool calls the agent might make, many of which were not anticipated when the policy was written.

### Natural language as an attack surface

Classical zero trust deals with principals that present cryptographic credentials — certificates, tokens, HMAC signatures. The control flow of those principals is determined by code, which behaves deterministically given the same inputs. If an access control check fails, the code handles the error; it does not decide to try a different approach.

An AI agent's control flow is determined by a language model, which interprets natural language instructions and produces natural language outputs. Natural language can be manipulated in ways that binary code cannot. An attacker who can influence the text the agent reads — through a malicious document, a crafted web page, an adversarial database record — can potentially influence the actions the agent takes.

This means that for AI agents, the principal is not fully in control of its own behaviour. The credentials are valid, the token is legitimate, the agent is authenticated — but the specific actions it takes can be influenced by external adversarial content. Classical zero trust verifies the identity of the principal; it does not and cannot verify that the principal's behaviour at any given moment is free from adversarial influence.

### Ephemeral, task-scoped execution contexts

Zero trust implementations typically deal with long-lived principals: user identities that persist for years, service accounts that persist for the lifetime of an application, machine identities tied to specific infrastructure. The assumption of relatively stable principals makes certain verification approaches practical: certificate-based identity, periodic re-authentication, session-level risk scoring.

AI agent tasks are inherently ephemeral. A useful customer service agent might complete hundreds of tasks per day, each lasting seconds to minutes. Each task represents a distinct execution context with potentially different data access requirements. The agent handling a billing question should have access to billing data; the same agent handling a technical support question should have access to the knowledge base. These are not the same access requirements.

This mismatch — a persistent principal with task-varying access requirements — creates pressure toward over-provisioning. If you cannot easily grant access per-task, you grant access per-deployment, and the deployment gets everything any task might ever need. Which is exactly the over-privileged credential pattern that produces failure modes 3 and 4 from our earlier analysis.

---

## The zero trust tenets applied to AI agents

NIST 800-207 articulates zero trust as seven tenets. Applying each to AI agents specifically:

### Tenet 1: All data sources and computing services are resources

*Standard interpretation*: every system component — databases, APIs, file systems, microservices — is a resource that requires access control, regardless of where it runs.

*Agent-specific implication*: every tool the agent can call is a resource. The email service, the SQL database, the file system, the external API — these are all resources that should have explicit access policies. "The agent can call any tool it has been configured with" is the perimeter model in disguise. Zero trust requires explicit per-resource policy.

### Tenet 2: All communication is secured regardless of network location

*Standard interpretation*: TLS everywhere, no unencrypted communication even on internal networks.

*Agent-specific implication*: this tenet is relatively straightforward to implement for agents and is widely implemented. All agent-to-tool-gateway communication should be over TLS. The tool gateway-to-backend communication should also be encrypted. This is table stakes and rarely the source of agent security failures.

### Tenet 3: Access to individual enterprise resources is granted on a per-session basis

*Standard interpretation*: access grants should be specific to a session, not persistent across sessions. Each access request is evaluated fresh.

*Agent-specific implication*: this is one of the most important tenets for agents. Access should be granted per-task, not per-deployment. A capability token issued for a specific task — with a bounded set of tools, specific argument constraints, and a short expiry — implements this tenet. The same agent deployment can be issued different tokens for different tasks, each with the specific access the task requires and no more.

This is the architecture of euno's capability-token model: a JWT `AgentCapabilityManifest` issued by the capability issuer for a specific agent, task, and scope, with a short expiry. The token is not "this agent can do X, Y, and Z always." It is "this agent can do X with these constraints, Y with these constraints, and Z with these constraints, for the next fifteen minutes, for this specific task context."

### Tenet 4: Access to resources is determined by dynamic policy

*Standard interpretation*: access decisions should not be purely based on static, pre-configured policies. They should incorporate real-time data: the requester's identity, the requested resource, the requester's current security posture, environmental context.

*Agent-specific implication*: static policies are a starting point, but agent access control benefits from dynamic evaluation. Is this agent in a known-good state? Has its posture been verified recently? Have there been anomalous behaviour signals? Is the requested tool call consistent with the task context?

euno's posture emitter pattern addresses this: continuous reporting of agent runtime state (what capabilities are active, when they were last used, what the agent's current operational context is) to a centralised inventory. A zero trust policy engine can incorporate posture signals: if this agent has not been seen in the posture inventory for the past hour, treat its token with elevated scrutiny. If this agent's recent tool call pattern deviates significantly from baseline, apply additional verification.

### Tenet 5: The enterprise monitors and measures the integrity and security posture of all owned and associated assets

*Standard interpretation*: continuous monitoring of all devices, services, and endpoints. Compliance with security policy is an ongoing check, not a one-time certification.

*Agent-specific implication*: agent audit logging is not optional — it is the implementation of this tenet for the agent fleet. Every tool call, with its full argument payload, result, and identity context, must be logged to a tamper-evident audit ledger. The HMAC-chained, OCSF-formatted audit log in euno's architecture implements this for the tool gateway layer.

Continuous monitoring also means continuous anomaly detection: statistical baselines for each agent deployment's tool call patterns, alerts when an agent's behaviour deviates from baseline, automated responses (capability suspension, kill-switch) when anomalies exceed thresholds.

### Tenet 6: All resource authentication and authorisation is dynamic and strictly enforced

*Standard interpretation*: authentication is not a one-time check at session establishment. Authorisation is not a simple lookup in an access control list. Both are continuous, strictly enforced at every access attempt.

*Agent-specific implication*: for agents, this means that every tool call is authenticated and authorised at the policy enforcement point, not just at session establishment. The tool gateway verifies the capability token on every call — not just the first time the agent connects. Token expiry is enforced strictly; an expired token is rejected even if the underlying identity is valid. Capability revocation takes effect immediately: a revoked token is rejected on the next call, not just on the next re-authentication.

This is fundamentally different from the session-based model where an authenticated connection persists until it times out. An agent that is performing a long-running task should be re-verifying its authorisation on every tool call. If the operator revokes the agent's capability mid-task — because they see something wrong in the audit log, or because a kill-switch has been activated — the revocation should take effect on the next call, within seconds.

### Tenet 7: The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture

*Standard interpretation*: comprehensive telemetry feeds a continuous improvement loop. Data collected about security incidents, near-misses, and normal operations is used to refine policies and detect threats earlier.

*Agent-specific implication*: the audit data collected by the tool gateway is not just compliance evidence — it is a rich signal for improving agent governance. Aggregating across agent deployments: which tools are called most frequently? Which argument patterns are most common? Which calls fail policy checks and why? This data informs policy refinement, anomaly detection calibration, and capacity planning.

---

## The policy enforcement architecture

Applying these tenets concretely to an AI agent deployment requires three components: a policy decision point, a policy enforcement point, and a policy information point.

### Policy Decision Point (PDP)

The PDP is where access decisions are made. For AI agents, this is the system that evaluates a proposed tool call against the applicable policy and returns a decision: permit, deny, or permit-with-obligations.

In euno's architecture, the capability issuer serves as the PDP at token-issuance time: it evaluates the requesting agent's identity, the requested capabilities, and the current policy configuration, and issues a token that encodes the decision. The tool gateway serves as the runtime PDP: on every incoming tool call, it verifies the token, evaluates any runtime conditions (rate limits, time windows, contextual conditions), and makes the permit/deny decision.

The separation of issuance-time and runtime decisions is important. Some policy decisions can be made at token issuance: this agent is permitted to call these tools, with these static constraints. Others must be made at runtime: has this agent exceeded its call limit? Is the current time within the permitted window? Is the specific argument within the permitted range?

### Policy Enforcement Point (PEP)

The PEP sits between the agent and the backend resources, enforcing the decisions made by the PDP. In a well-designed zero trust architecture, the PEP is as close to the resource as possible — the further from the resource, the more surface area exists for bypass.

For AI agents, the natural PEP is the tool gateway: the proxy through which all tool calls are routed before reaching backend systems. The tool gateway intercepts every call, verifies the capability token, evaluates runtime policy, enforces obligations (rate limiting, argument sanitisation, audit logging), and either forwards the call to the backend or rejects it.

The key property of the PEP is that it is **mandatory**: the agent cannot reach the backend resource without going through it. An architecture where the PEP is optional — where the agent could, in principle, call the backend directly — is not zero trust. It is a monitoring system that can be bypassed.

euno achieves this through a combination of the tool proxy pattern (all tool calls are routed through `@euno/mcp` or the tool gateway) and credential management (backend service credentials are held by the gateway, not by the agent). The agent cannot call the database directly because it does not have database credentials; the only path to database access is through the gateway, which enforces policy.

### Policy Information Point (PIP)

The PIP provides the contextual information that the PDP needs to make access decisions. For conventional zero trust, this includes device posture data, threat intelligence feeds, user behaviour analytics, and identity attributes.

For AI agents, the PIP should include:

- **Agent posture data**: is this agent deployment healthy? When was it last attested? What is its current operational context?
- **Capability inventory**: what capabilities is this agent currently operating under? What has it done recently?
- **Behavioural baselines**: what is normal for this agent? How does its current call pattern compare?
- **Threat intelligence**: are there active campaigns targeting the tools this agent uses? Have similar agent deployments been compromised recently?
- **User context**: what is the authenticated user's risk profile? Are there anomalous signals from their recent activity?

euno's posture emitter provides the agent posture and capability inventory data. The audit log provides the behavioural history. Integration with enterprise threat intelligence and identity management systems rounds out the picture.

---

## Practical implementation: the euno architecture as zero trust reference

Translating the abstract tenets into a concrete architecture for an euno deployment:

### Authentication layer

Every agent deployment has a unique identity, encoded in the `sub` claim of its capability token. Tokens are issued by the capability issuer after verification of the agent's OAuth 2.0 client credentials (or PKCE flow for interactive deployments). The issuer uses a signing key backed by a hardware security module (HSM) — Azure Key Vault, AWS KMS, or GCP Cloud KMS — ensuring that token signing keys are protected at the highest available level.

DPoP (Demonstrating Proof of Possession) binding associates tokens with a specific key pair held by the agent, preventing token relay attacks: even if an attacker intercepts a valid capability token, they cannot use it without the corresponding private key.

For multi-organisation deployments, the partner DID federation layer extends authentication across organisational boundaries: an agent from a partner organisation can present a token issued by the partner's capability issuer, which is verified against the partner's DID document. The verification includes circuit breaker logic to handle DID resolution infrastructure failures without failing open.

### Per-call authorisation at the gateway

The tool gateway implements the runtime PDP and PEP. The enforcement pipeline on every tool call:

1. **Token verification**: verify JWT signature, check expiry, validate issuer against trust store, check DPoP binding
2. **Revocation check**: verify the token's JTI is not in the revocation list (Redis-backed for low latency)
3. **Kill-switch check**: verify the global kill-switch is not active for this agent or tenant
4. **Capability matching**: verify the requested tool is listed in the token's capability manifest
5. **Condition evaluation**: evaluate any conditions on the capability (rate limits, time windows, argument patterns, contextual conditions)
6. **Obligation application**: apply any obligations on the capability (rate counter increment, argument sanitisation, required audit fields)
7. **Audit logging**: write a signed OCSF-formatted audit record to the tamper-evident ledger
8. **Forward or reject**: forward the call to the backend tool, or return a 403 with a structured error

This pipeline executes on every single tool call, not just at session establishment. An agent that has been operating normally for an hour and then receives an injected instruction that attempts to exfiltrate data will hit the per-call authorisation check for that exfiltration attempt — regardless of whether all previous calls were legitimate.

### Capability tokens as zero trust artefacts

The JWT `AgentCapabilityManifest` is the central zero trust artefact in euno's architecture. It encodes, in a cryptographically verifiable form:

- **Who**: the agent's identity (`sub`), the issuer (`iss`), the audience (`aud`)
- **What**: the specific tools the agent is permitted to use, with argument constraints for each
- **When**: token expiry (`exp`), not-before time (`nbf`), and optional time-window conditions
- **How much**: rate limit conditions (`maxCalls` per tool, `maxCalls` per session)
- **Under what circumstances**: contextual conditions that must be satisfied at call time

This is a richer representation of authorisation than an OAuth scope. A scope of `tools:invoke` says nothing about which tools, under what constraints, at what rate. A capability manifest says exactly which tools, with exactly what argument constraints, at exactly what rate, for exactly how long.

The token is issued for a specific task context and has a short expiry — typically fifteen minutes to one hour, depending on the expected task duration. When the task is complete, or when the token expires, the agent must obtain a new token for a new task. This implements the per-session access grant tenet in a concrete, enforceable way.

### Tamper-evident audit logging

The HMAC-chained audit ledger in euno's tool gateway implements the continuous monitoring tenet with a specific additional property: **tamper evidence**. Each audit record includes an HMAC computed over its content and the HMAC of the previous record, forming a chain. If any record is modified or deleted, the chain breaks at that point. If records are inserted out of order, the chain is invalid.

This is important for AI governance specifically because agents operate rapidly and autonomously. A security incident might involve an agent taking dozens of actions in minutes. By the time a human investigator is looking at the audit log, the agent has long since completed its task (or been stopped). The audit log is the primary evidence for reconstructing what happened.

If the audit log is mutable — if an attacker who has compromised the agent or the gateway can also modify the log — the evidence trail can be covered. HMAC chaining prevents this: the chain provides cryptographic proof that the log has not been tampered with after the fact.

For SOC 2 compliance, euno's `GET /api/v1/audit/export` endpoint produces signed evidence bundles that can be submitted to auditors as proof of control operation. The signature is produced by a KMS-backed signing key, providing hardware-level assurance of the evidence's integrity.

---

## Fail closed: the most important zero trust property for AI agents

Across all of the tenets and all of the architectural patterns, the single most important property of a zero trust implementation for AI agents is: **fail closed**.

When the policy enforcement point cannot make a confident permit decision — because the token is missing, because the token cannot be verified, because the condition evaluation produces an error, because the policy store is unavailable — the correct answer is to deny the request.

This is the opposite of the behaviour that comes naturally to systems designed for reliability and user experience. When a network request fails, the natural engineering response is to implement a fallback. When a cache misses, serve from the origin. When an authentication service is unavailable, grant a grace period. These are reasonable choices for many failure modes in many systems.

For a security enforcement point, they are wrong. A policy enforcement point that fails open — that permits requests when it cannot verify authorisation — is not a security control. It is a monitoring system with an availability-dependent security guarantee, which is no security guarantee at all.

In euno's architecture, every failure mode at the enforcement layer defaults to deny:
- Token verification failure: deny
- Redis (revocation check) unavailable: deny
- Condition evaluation error: deny
- Policy store unavailable: deny
- Capability manifest malformed: deny
- Unknown condition type: deny

The last item is particularly important: **unknown conditions fail closed**. A future version of the policy engine might introduce a new condition type. An agent with a capability token that contains an unrecognised condition is not permitted to operate as if the condition is satisfied. The enforcement point denies the request until it is updated to understand the new condition type. This prevents future policy extensions from inadvertently creating gaps where new conditions are silently ignored.

---

## Complementing perimeter controls, not replacing them

Zero trust for AI agents does not mean abandoning perimeter security. It means not *depending* on it. Network segmentation, VPC boundaries, private subnets — these are still valuable as defence-in-depth layers. If an agent is compromised, network segmentation that prevents it from reaching resources outside its expected communication pattern adds friction for an attacker.

But the lesson of zero trust is that perimeter controls are not sufficient. They can be breached. The tool gateway must enforce policy assuming that a breach has occurred: that the network request arriving at the gateway might come from a compromised agent, a replayed token, or a lateral movement attack rather than the legitimate agent. The per-call verification at the PEP is the control that holds regardless of the network origin of the request.

This is also the correct framing for internal agent deployments. An agent that runs entirely inside your private network, calling internal microservices, is not exempt from zero trust principles. The prompt injection attack surface exists regardless of network topology. An adversarial document that causes an agent to exfiltrate data to an internal attacker-controlled endpoint is just as dangerous as one that exfiltrates to an external endpoint. The enforcement must be at the tool call layer, not at the network boundary.

---

## Getting started: a zero trust maturity model for AI agents

Organisations typically implement zero trust in phases, starting with the highest-value controls and expanding over time. The same approach applies to AI agent deployments:

**Phase 1: Authentication and basic authorisation**
- All agent-to-gateway communication uses verifiable identity (capability tokens, not shared API keys)
- Per-call token verification at the gateway
- Token expiry strictly enforced

**Phase 2: Fine-grained capability scoping**
- Capability tokens specify per-tool permissions with argument constraints
- No agent operates with more permissions than its current task requires
- Different tasks receive different tokens with task-appropriate scoping

**Phase 3: Continuous monitoring and audit**
- All tool calls logged to a tamper-evident audit ledger
- Anomaly detection on tool call patterns
- Real-time alerting on policy violations

**Phase 4: Dynamic policy evaluation**
- Posture data incorporated into access decisions
- Behavioural baselines established and monitored
- Risk-based policy adjustment (elevated scrutiny for anomalous agents)

**Phase 5: Cross-organisation federation**
- Partner DID federation for multi-organisation deployments
- Federated audit evidence for cross-organisational accountability
- Consistent policy enforcement across organisational boundaries

Organisations that have reached Phase 3 or beyond are well-positioned to defend against the full range of AI agent failure modes and attack vectors. The investment is not primarily in exotic technology — it is in the engineering discipline of applying well-understood security principles consistently to a new category of software principal.

The agents are here. The threat surface is real. The zero trust framework for addressing it is available. The work is in the implementation.

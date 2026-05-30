Let me check my memory for context from our previous conversation, and look at the eunox codebase to ground my reasoning.

Now I have a thorough picture. Let me reason through this carefully.

Good enough context. Let me now write the full analysis.

---

## Where MCP, Anthropic, and the Agentic Ecosystem are Heading — and How eunox Differs

I'll work through this in layers: what each player will likely build, the underlying security model they're adopting, and where eunox sits in structural contrast to all of them.

---

### 1. The Convergence Point: OAuth 2.0 + Scoped Tokens + Policy-as-Code

Every major player — Anthropic (MCP), Google (ADK / Gemini), Microsoft (AutoGen / Copilot Studio), AWS (Bedrock Agents) — is converging on the same stack:

- **OAuth 2.0 with PKCE** for agent authentication to tools (MCP already has this in its auth spec as of late 2025)
- **Scoped access tokens** at the MCP server level (not per-call, but per-connection or per-session)
- **OPA/Rego or CEL** as the policy engine sitting in front of tool registries
- **OpenTelemetry traces** as the audit mechanism

The reason everyone is converging here is obvious: this is what enterprise security teams already know. It reuses existing identity infrastructure (Azure AD, Okta, AWS IAM). Procurement is easier. The security review is faster.

**The critical limitation:** OAuth scopes are coarse. When an MCP server grants `files:write`, that token lets any tool call on that server write any file. There is no mechanism in OAuth for the scope to encode "write only to paths under `/data/`" in a way that is cryptographically enforceable at the call site without application-level code in the tool itself. The enforcement is **connection-level**, not **call-level**.

---

### 2. Anthropic's Specific Bet: Model-Native Policy + MCP-Level OAuth

Anthropic's architectural instinct will be to make **Claude itself the enforcement point**. This shows up in several ways:

- **Operator system prompts** encode what the model is allowed to do. If you tell Claude "you may not write to paths outside `/data/`", Claude is supposed to refuse.
- **Tooling-level scopes in MCP** mean when Claude connects to an MCP server, it negotiates what resource types it has access to — but this is at OAuth handshake time, not at tool-call time.
- **Constitutional AI / RLHF alignment** is intended to make the model reluctant to circumvent operator intent even if technically capable.

This is a fundamentally different trust model from eunox. Anthropic's model is:

> **"The model is the policy enforcement point. External enforcement is secondary."**

The security problem with this: the model can be jailbroken, tricked through prompt injection, or simply make an error in judgment. The model is not a reference monitor in the formal computer science sense — it has no invariant guarantee of enforcement. There is no cryptographic proof that what the model was instructed matches what actually governed a specific tool call. The audit trail depends on the model and the surrounding system honestly recording what happened.

Anthropic knows this, which is why MCP has OAuth. But OAuth at the server level doesn't close the gap.

---

### 3. Google / Microsoft / AWS: RBAC-Wrapped Agents

Google ADK, AutoGen, CrewAI, LangGraph all take a similar approach: **role-based access control on the agent object itself**.

- An agent is created with a set of allowed tools
- A registry enforces which tools a given agent identity can invoke
- Human-in-the-loop checkpoints for "dangerous" operations
- Rate limiting at the framework/router level

The model is:

> **"Who is this agent (identity)? What role does it have? What tools does that role permit?"**

This is standard RBAC, just applied to agents instead of users. It has all the known RBAC failure modes:

- **Confused deputy**: An orchestrator agent has broad permissions. A sub-agent manipulates the orchestrator into using its permissions on the sub-agent's behalf. RBAC doesn't prevent this because the orchestrator's role is valid.
- **Ambient authority**: The agent holds permissions it doesn't need for this specific task. If the agent is compromised or makes an error, those ambient permissions are available to be exploited.
- **No attenuation in delegation**: When an orchestrator spawns a sub-agent, the sub-agent can be granted any subset of the orchestrator's permissions by policy, but there's no cryptographic guarantee that the sub-agent *can't* claim permissions it wasn't supposed to receive.

---

### 4. The Structural Difference: ACL/RBAC vs. the Capability Model

This is the crux. eunox is built on the **capability security model**, not ACL or RBAC. The distinction is not cosmetic.

**ACL/RBAC (everyone else):**
- Identity is the anchor. "Who are you?" determines what you can do.
- Permissions are ambient: once you have a role, all permissions that role implies are available in every context.
- The authority to call a tool is checked by looking up whether your identity has been granted that authority.

**Capability model (eunox):**
- The token IS the permission. You possess an unforgeable, cryptographically signed bearer proof that authorizes exactly one scoped action or set of actions.
- There is no ambient authority. If you don't hold a token for `write_file on /data/`, you literally cannot call it — the gateway rejects without consulting any external identity store.
- Delegation is **attenuating**: when an orchestrator delegates to a sub-agent, it can only issue a capability token that is strictly weaker than its own. There is no mechanism to escalate.

Looking at eunox's code: the `ManifestPDP` in [cmd/mcp/pdp.go](cmd/mcp/pdp.go) enforces at the argument level — it validates not just whether the tool is permitted, but whether the specific file path, SQL operation, recipients list, and table names in this call fall within the constraint's conditions. The `DPoPProofGenerator` in [internal/agentruntime/dpop.go](internal/agentruntime/dpop.go) binds tokens to the specific key pair of the requester, preventing token theft replay.

No OAuth-based system does this at call-evaluation time with cryptographic binding. OAuth tokens are bearer tokens; eunox's capability tokens with DPoP are proof-of-possession.

---

### 5. Audit: Structural Difference in Non-Repudiation

MCP/Anthropic's likely audit path: OpenTelemetry → SIEM. Each span records what happened.

The problem: OpenTelemetry logs are **mutable**. A compromised system can retroactively edit or delete log entries. There is no cryptographic proof that the log has not been tampered with.

eunox's audit log is an **HMAC-SHA256 chain** in OCSF format. Each entry is signed with the previous entry's hash as input. Deletion or modification of any entry breaks the chain and is detectable. This is the difference between a notebook and a blockchain-style ledger.

For regulated industries (financial services, healthcare, government), this distinction matters enormously in an audit or incident investigation. "The log says the agent called this tool" is different from "it is cryptographically provable that this log record has not been altered since the moment the call was made."

---

### 6. Kill Switch: Nobody Else Has This

The `eunox-mcp kill --session <id>` command immediately blocks a running session. This is a real-time revocation primitive.

The OAuth world handles revocation by revoking tokens, but:
- Token revocation requires the resource server to check a revocation endpoint or wait for token expiry
- Long-lived tokens (which are common for agent sessions) may not be checked frequently
- There is no semantic of "stop this agent *right now*, block every call it makes from this point forward, even if it currently holds a valid token"

eunox's kill switch is checked on *every* `tools/call` as the first step (line 82 in `pdp.go`). There is zero propagation delay.

---

### 7. The Platform Boundary: Where eunox is Structurally Distinct

| Property | MCP + OAuth | RBAC frameworks | eunox |
|---|---|---|---|
| Enforcement granularity | Connection-level | Agent-level | Per-call, per-argument |
| Security model | ACL / RBAC | RBAC | Capability model |
| Token binding | Bearer (OAuth JWT) | Bearer (API keys) | DPoP (proof-of-possession) |
| Delegation attenuation | No cryptographic guarantee | No | Yes — sub-tokens can only restrict |
| Confused deputy protection | No | No | Yes — ambient authority doesn't exist |
| Audit tamper-evidence | No | No | HMAC chain |
| Real-time kill switch | Token expiry-bound | Session termination | Sub-second, per-call checked |
| Agent-framework agnostic | MCP-specific | Framework-specific | Yes — any MCP host or HTTP agent |

---

### 8. Where eunox is Vulnerable

This is the honest part.

**Commoditization risk from cloud providers.** AWS, Azure, and GCP will eventually offer AI-native IAM policies that work at the tool invocation level. When AWS says "you can write an IAM policy that restricts Bedrock agents to specific S3 path prefixes, checked cryptographically on every call," eunox's gateway story gets harder to differentiate for AWS-native workloads.

**MCP native capability extensions.** If the MCP spec itself evolves to include per-call capability scoping (not just OAuth at connection time), the protocol-level solution will commoditize eunox's proxy value for MCP-native deployments. Anthropic controls the spec and has every incentive to build governance in rather than letting third parties own it.

**Operational complexity.** The capability model is harder to reason about than RBAC for most security engineers. If the industry lands on "OAuth + OPA is good enough for 95% of enterprise agent use cases," eunox faces a buyer education problem even where it's technically superior.

**Distribution.** Palo Alto, Zscaler, and CrowdStrike are already moving to AI-aware proxy products. They have existing sales motion into enterprise security teams. They will commoditize the "proxy in front of MCP servers" story. eunox's differentiation then has to rest entirely on the capability model's cryptographic depth — which requires a buyer who understands why that matters.

---

### 9. The Core Thesis eunox Has to Win On

The capability model solves **confused deputy and ambient authority** — the two most fundamental vulnerabilities in agentic systems — in a way that no OAuth/RBAC approach can address without fundamental rearchitecture.

As agents do more consequential things (financial transactions, infrastructure changes, data exfiltration-adjacent operations), the argument that "the model won't misuse its ambient permissions" becomes indefensible to a security team. The liability question changes. Regulators will eventually require cryptographic proof that an agent could only have done what it did because it held explicit, time-limited, attenuated authorization — not because a role in a policy database said so.

That's the moment eunox's architectural bet pays off. The question is whether the market gets there before the hyperscalers build capability-model primitives into their own IAM systems.

The differentiation eunox needs to protect is:
1. **Cross-framework portability** — it works in front of *any* agent, not just Claude or LangChain
2. **Cryptographic non-repudiation of the audit chain** — the HMAC chain is a genuine moat that cloud logging does not have
3. **Attenuation in delegation chains** — this is deep in the capability security literature and genuinely hard to retrofit onto RBAC systems
4. **Real-time kill switch** — sub-second, per-call checked, no token expiry dependency

The biggest strategic risk is that Anthropic builds model-level governance so trusted by the market that external enforcement is seen as redundant. eunox's counter-argument has to be: the model is not a reference monitor. Formal security properties require external, cryptographic enforcement. And that argument becomes stronger every time a jailbreak makes headlines.

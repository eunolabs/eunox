# Capability tokens: a cryptographic contract between agent and operator

*Audience: security architects and developers who want to understand the trust model at euno's core*

---

Every serious question about agent security eventually comes back to the same thing: how does the enforcement layer know what a given agent session is allowed to do? Not what the system prompt says. Not what the model's training suggests. Not what the API key's associated service account technically has permission to in the cloud IAM config. What the agent is actually, specifically, verifiably authorised to do — right now, in this session, for this task.

This is the capability token's job. It's the artefact that carries the answer to that question in a form that an enforcement point can verify without talking to anyone, without trusting the agent's claims about itself, and without being fooled by anything the agent has encountered since it started running.

I've touched on capability tokens in several earlier posts — [the least-privilege post](./02-least-privilege-agent-era.md) explains why classical RBAC doesn't work for agents, [the prompt injection post](./01-prompt-injection-policy-layer.md) shows how tokens encode the conditions that block injection attacks, and [the policy proxy post](./06-mcp-policy-proxy.md) covers the enforcement pipeline they flow through. This post goes deeper on the token itself: what's in it, why it's structured this way, and why a short-lived signed JWT is the right foundation for per-session agent authorisation.

---

## Why a shared API key isn't enough

Let me start with the comparison because it comes up constantly. Most teams deploying agents start with an API key — one secret that identifies the agent to the tool, grants whatever the key was set up with, and persists until someone rotates it. This works in the sense that calls get made and results come back. It's just not security.

The problems with API keys as the sole authorisation mechanism for agents:

**They're identity, not capability.** An API key says "this is agent X." It doesn't say "agent X is allowed to do Y but not Z in this session." The permissions associated with a key are set at provisioning time and apply to everything that uses the key. If the key has read access to table A and you need the agent to read table A for one task, the key also has read access to table A for every other task the agent ever runs — including ones where table A access is irrelevant and represents unnecessary exposure.

**They're long-lived.** A key provisioned for an agent deployment stays valid until someone remembers to rotate it. That's often a long time. Months. Sometimes years. A key that's valid for months is a key that, if stolen, grants months of access. The blast radius of a compromised API key is proportional to its lifetime.

**They can't be narrowed per-task.** An orchestrator that delegates to a sub-agent can't give the sub-agent "a limited version" of its API key. Either the sub-agent has the same key (with full permissions) or it has a different key (set up separately, probably with similarly broad permissions). There's no mechanism to grant exactly the permissions needed for this sub-task and no more.

**They have no conditions.** A `send_email` permission granted to an API key applies unconditionally. The key can send email to anyone. You can't say "this key can only send email to internal addresses" at the key layer — you have to add that check somewhere else, probably in the application logic, where it's reviewable only by people who read code rather than everyone who can read a policy document.

**There's no tamper-evident record of their use.** API key calls might show up in server logs, but there's no per-call audit record with the caller's identity, the arguments, the decision rationale, and a cryptographic chain tying the records together. Reconstructing what a key was used for from server logs is possible in theory and painful in practice.

A JWT capability token addresses every one of these. Let me show you what's inside one.

---

## The token anatomy

Here's a decoded capability token payload from an analytics agent session:

```json
{
  "iss": "https://capability-issuer.corp.example.com",
  "aud": "https://tool-gateway.corp.example.com",
  "sub": "did:web:analytics-agent.corp.example.com",
  "jti": "01J3K7M2N8P4Q6R0S5T9V2W1X",
  "iat": 1718200000,
  "exp": 1718203600,
  "schemaVersion": "1.0",
  "capabilities": [
    {
      "resource": "db://analytics/**",
      "actions": ["read"],
      "conditions": [
        {
          "type": "allowedOperations",
          "operations": ["SELECT"]
        },
        {
          "type": "maxCalls",
          "count": 100,
          "windowSeconds": 3600
        }
      ]
    },
    {
      "resource": "storage://reports/**",
      "actions": ["read", "write"],
      "conditions": [
        {
          "type": "allowedExtensions",
          "extensions": [".csv", ".json", ".pdf"]
        },
        {
          "type": "maxCalls",
          "count": 50,
          "windowSeconds": 3600
        }
      ]
    }
  ]
}
```

Let me go through each piece.

**`iss` (issuer).** The URL of the capability issuer service that signed this token. The gateway verifies the token signature against the issuer's published JWKS (JSON Web Key Set) endpoint. If `iss` points somewhere the gateway doesn't trust, the token is rejected immediately. This is the anchor that prevents an agent from presenting a self-signed token claiming whatever permissions it wants.

**`aud` (audience).** The URL of the tool gateway this token is valid for. A token issued for gateway A cannot be replayed at gateway B — the audience check fails. This prevents stolen tokens from being used across deployment boundaries. In a multi-environment setup (staging gateway, production gateway), a staging token can't be used in production.

**`sub` (subject).** The agent's identity — here, a DID (decentralised identifier). This is who is being authorised. The gateway uses this for audit attribution — every audit record carries the subject of the token that approved the call. In a multi-agent workflow, you can trace every action back to the specific agent identity that was authorised to take it.

**`jti` (JWT ID).** A unique identifier for this token issuance. This is what revocation operates on. Push this JTI to the revocation list in Redis and every subsequent call using this token fails within milliseconds. The JTI is also what connects the enforcement audit records to the issuance event — the capability issuer logs every token it mints with the JTI, and the gateway logs every decision with the JTI, so the full chain from issuance to enforcement is traceable.

**`iat` / `exp` (issued at / expiry).** The token's lifetime. This one expires in one hour (3600 seconds from `iat` to `exp`). After expiry, the token is dead regardless of what the revocation list says. Short token lifetimes limit the window of exposure if a token is intercepted. If a token expires in fifteen minutes, a stolen token is at most fifteen minutes of risk. For sensitive operations — anything touching money, PII, or irreversible changes — tokens should be short: five to fifteen minutes, renewable per action if the session needs to continue.

**`schemaVersion`.** The version of the capability token schema this token uses. The gateway rejects tokens with unrecognised schema versions. This is the fail-closed behaviour for schema evolution: when you publish a new condition type or capability format in schema version 2.0, gateways that haven't been updated to understand 2.0 will refuse to evaluate those tokens rather than silently treating the new fields as unknown and skipping them. A schema version mismatch is a loud failure you notice and fix, not a silent bypass.

**`capabilities`.** The actual authorisation grant. An array of `CapabilityConstraint` objects — each one a resource pattern, a set of actions, and an optional array of conditions. This is the heart of the token. Let me spend some time here.

---

## Capabilities and conditions: the actual policy

The `capabilities` array is where the policy lives, encoded into the cryptographically signed token. Once the token is issued, the agent cannot modify it — the signature would break. The operator who authored the manifest can't be overridden by a prompt injection that lands in the agent's context. The conditions are what they are.

Each capability entry has:

**`resource`**: A URI pattern. `db://analytics/**` matches any resource in the analytics database namespace. `storage://reports/**` matches any file path under reports. The scheme is equality-checked — `api://` never matches `storage://`. Single-level wildcards (`/*`) match exactly one path segment. Multi-level wildcards (`/**`) match one or more. `api://*` (bare star at the root) is rejected — it's too broad to be meaningful policy.

**`actions`**: An array of action types. `["read"]` is read-only. `["read", "write"]` allows both. The gateway checks that the tool call's implied action is in the allowed set. An agent with a `read`-only capability on a resource cannot be made to write to it by any instruction, because the token's `actions` array doesn't include `write`.

**`conditions`**: The interesting part. These are typed constraints on top of the action grant. They narrow what an allowed action can actually do:

- `allowedOperations: ["SELECT"]` — The gateway extracts the first keyword from any SQL query argument and checks it against this list. `DROP`, `DELETE`, `INSERT`, `UPDATE`, `ALTER`, `TRUNCATE` all fail this check if only `SELECT` is listed. The check runs on the actual argument value, not on what the model said it was doing. An injection that produces `DROP TABLE orders` as the query argument fails here regardless of how convincingly the model was asked to run it.

- `maxCalls: { count: 100, windowSeconds: 3600 }` — A distributed rate counter. After 100 calls to resources matching this capability in a rolling hour window, further calls are denied until the window expires. This counter is stored in Redis, not in-memory — so it's shared across all agent instances and all sessions using this token (or, in the hosted gateway, all sessions with this capability scoped). The counter increments atomically and the gateway denies once it exceeds the configured limit, so two simultaneous calls at the boundary can't both get approved due to a stale read.

- `allowedExtensions: [".csv", ".json", ".pdf"]` — File calls (read or write) are checked against the extension of the file path argument. A write to `output.exe` fails this check.

- `recipientDomain: ["corp.example.com"]` — Email calls check the recipient address domain. An instruction to send email to `attacker@external.com` fails here, regardless of what produced the instruction. This is the control that would have blocked the law firm exfiltration scenario from [the failure modes post](./03-agent-governance-failure-modes.md).

- `timeWindow: { notBefore: "...", notAfter: "..." }` — The capability is only usable during a specified time range. A deployment capability gated to business hours won't fire at 2am even if the agent is running.

- `allowedTables / columns` — Database-specific constraint. Restricts which tables (and optionally which columns within those tables) the agent can query. An agent permitted to query only `sales` and `customers` cannot be redirected to the `employees` or `compensation` tables.

What's not in the `conditions` array doesn't get evaluated. Unknown condition types — conditions the gateway's `ConditionRegistry` hasn't been told how to evaluate — cause the entire call to be denied. This is the crucial asymmetry: the gateway only approves when it can positively verify all conditions. It doesn't approve when some conditions are unrecognisable and it decides to skip them.

This property matters for policy evolution. When a new condition type ships in a future schema version, old gateways that haven't been updated will reject tokens that include the new condition type. That's the right behaviour — it surfaces the need for a gateway update, rather than silently running the token without enforcing the new condition.

---

## The lifecycle: from manifest to token to decision

The token starts life as a capability manifest — the YAML file I've shown throughout this series. An operator writes the manifest and commits it through code review. The capability issuer service reads the manifest, authenticates the requesting agent, and issues a signed JWT.

More precisely:

1. An agent begins a session. It authenticates with the capability issuer using its identity credential (typically backed by the platform's identity provider — Azure AD, Cognito, whatever is configured).

2. The issuer looks up the agent's registered manifest. It validates the manifest against the `AgentCapabilityManifest` schema — checking that all condition types are known, all resource patterns are syntactically valid, no forbidden patterns like bare `api://*` are present.

3. The issuer compiles the manifest into a JWT payload, sets the `iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `schemaVersion`, and `capabilities` fields, and signs it using the tenant's KMS-backed private key.

4. The token is returned to the agent. For the rest of the session, the agent includes this token in every tool call.

5. At each tool call, the gateway verifies the token signature, checks the standard JWT claims (expiry, audience, issuer), checks the JTI against the revocation list, and evaluates the conditions in the relevant capability. Decision — allow or deny — plus any obligations — obligation application (rate counter increment, argument sanitisation, etc.) — and audit record write.

6. When the session ends or the token expires, the grant is gone. The next session gets a new token, potentially with different conditions if the operator has updated the manifest in the meantime.

The token is the moment where "what the policy says" becomes "what was cryptographically committed to at issuance time for this session." Policy changes in the manifest take effect at the next token issuance, not mid-session. This is intentional — you don't want a policy change during an active session to retroactively change the terms of decisions that were already made. The policy at issuance time is what matters for any given session's audit record.

---

## Attenuation: giving a sub-agent a subset of your permissions

Modern agentic workflows often involve delegation chains. An orchestrator agent breaks a complex task into sub-tasks and delegates them to specialist agents. The orchestrator has a token granting certain capabilities. Each sub-agent needs a token too — but ideally, a narrower token scoped to exactly what that sub-task requires.

This is what attenuation is for. The orchestrator calls `POST /api/v1/attenuate` on the capability issuer with its own token and a requested capability set that is a strict subset of what its token grants.

```json
{
  "requestedCapabilities": [
    {
      "resource": "db://analytics/sales",
      "actions": ["read"],
      "conditions": [
        { "type": "allowedOperations", "operations": ["SELECT"] },
        { "type": "maxCalls", "count": 10, "windowSeconds": 600 }
      ]
    }
  ],
  "ttl": 120
}
```

The issuer enforces two hard rules on this request:

**Subset property.** Every resource and action in `requestedCapabilities` must be a subset of what the parent token grants. If the orchestrator's token doesn't grant write access to any analytics resource, it can't produce a sub-agent token that does. The issuer checks this at issuance time — it's not an honour system. An attenuated token can only narrow what the parent token grants. It can't widen it.

**TTL ceiling.** The requested `ttl` can't exceed the parent token's remaining lifetime. If the orchestrator's token expires in 90 seconds, the sub-agent's token can be at most 90 seconds. This prevents a sub-agent token from outliving the session that spawned it.

The attenuated token carries a `parentCapabilityId` claim linking it to the parent token. The audit log traces both: the sub-agent's actions are attributed to its token, and the token is linked to the orchestrator session that created it. In a complex multi-agent workflow, this audit chain is what lets you trace any action back to the human-level request that started the task.

---

## DPoP: making stolen tokens useless

A valid signed JWT is transportable. If an attacker intercepts a token in transit, they have a credential they can replay from any machine until it expires. Short token lifetimes reduce the window, but don't close it.

DPoP (Demonstrating Proof-of-Possession, RFC 9449) closes it. When DPoP is enabled:

1. At session start, the agent generates an ephemeral key pair. The public key is included in the token request.
2. The capability issuer includes the public key hash as a `cnf` (confirmation) claim in the issued JWT.
3. On every tool call, the agent includes a DPoP proof: a short-lived JWT signed with the corresponding private key, containing the method, endpoint, and a timestamp.
4. The gateway verifies the DPoP proof signature against the `cnf` public key in the capability token. A call that includes the capability token but lacks a valid DPoP proof is rejected.

A stolen token is useless without the private key. The private key lives in the agent process and never leaves it. An attacker with the token but not the private key can't produce valid DPoP proofs. The capability token and the DPoP proof together prove identity at the moment of each call.

For most deployments, DPoP is an optional additional layer rather than a baseline requirement. The call is still TLS-protected, the token is short-lived, and revocation is instant. But for deployments where the token transport path is considered high-risk — or where regulatory requirements specify proof-of-possession — DPoP is the mechanism.

---

## What the token doesn't protect

I want to be honest about the limits.

The token enforces the conditions that were authored into it. A condition that was not authored offers no protection. An agent with `allowedOperations: ["SELECT", "INSERT", "UPDATE", "DELETE"]` will have those operations approved. Writing tight conditions is the operator's responsibility, and the token's enforcement is only as strong as the policy that produced it.

The token doesn't prevent the model from being convinced to call a permitted tool with permitted arguments in a way the operator didn't intend. If the manifest allows sending email to internal addresses and a prompt injection convinces the model to send a sensitive summary to a legitimate-looking internal address that routes to an attacker, the token won't catch that — the recipient domain check passes. The token is a lower bound on safety. It's not a guarantee that every approved call was a good call.

And the token only matters if the gateway is the only path to the tools. If there's a direct connection from the agent to the database that bypasses the gateway entirely, capability token enforcement is moot for that path. The architecture has to ensure that every call goes through the enforcement point.

These aren't reasons to not use tokens. They're reasons to think carefully about the policy you write and to use multiple layers of defence. The token is the hardest enforcement point — it works on structured data at the moment of action, without relying on model behaviour or system prompt instructions. Everything else is defence around it.

---

## The token as a paper trail

One thing I don't talk about enough: the token is not just an enforcement mechanism. It's a paper trail.

Every token minting event is logged by the capability issuer — who requested it, what identity was authenticated, what policy hash was in effect. Every enforcement decision is logged by the gateway with the `jti` that links back to the minting event. Every decision carries the full capability and condition context: what was checked, what was the outcome, what were the arguments.

That chain — manifest commit → issuance event → enforcement decision — is what makes an incident investigation tractable. You can answer: what policy was in effect for this session? Which conditions were evaluated? Which calls were approved and which were denied? Was the token revoked and if so when? What was in the arguments of the calls that triggered the incident?

You can also answer the forward-looking question: what would change if I update this condition? The manifest history is in version control. The issuance log shows which policy hash was active. The enforcement records show which conditions were most frequently evaluated. This is the operational data that lets you tighten policy intelligently rather than guessing.

The token is the contract. But a contract is only as useful as the paper trail that proves what terms were agreed to, when, and by whom.

---

*Previous: [From local YAML to hosted policy store: euno's migration story](./08-local-yaml-to-hosted-gateway.md)*

*Next: [The Tool Gateway as a reference monitor: implementing PDP in practice](./10-tool-gateway-reference-monitor.md)*

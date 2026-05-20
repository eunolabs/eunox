# The Tool Gateway as a reference monitor: implementing PDP in practice

*Audience: security engineers and platform architects who want to understand how enforcement is actually implemented*

---

The "reference monitor" concept has been in computer security literature since James Anderson's 1972 report on computer security planning for the US Air Force. The idea is simple and still holds up perfectly: there must be a component that mediates every access to every protected resource, that cannot be tampered with, and that is small enough to be subject to analysis and testing. A complete, always-active, verifiable enforcement mechanism between subjects and objects.

For decades this was implemented at the OS level — the kernel's access control layer, SELinux, mandatory access control. When we talk about a tool gateway for AI agents, we're implementing exactly the same concept at the application layer, with AI agent sessions as subjects and tool calls as the requests to be mediated.

This post is about what that mediation actually looks like in code — the enforcement pipeline that every tool call runs through before it reaches an upstream tool, and why each step is designed the way it is. If you've read [the capability tokens post](./09-capability-tokens.md) and want to understand what happens to those tokens once they arrive at the gateway, this is the continuation.

---

## Why the gateway is the right policy decision point

There's been a lot of discussion in the AI safety space about where to put enforcement: in the model itself, in the system prompt, in the application logic, in the tool. I've addressed parts of this in earlier posts — the prompt injection post explains why model-layer enforcement is insufficient, the least privilege post explains why application-layer policy isn't enough. But it's worth saying clearly what makes the gateway the right PDP (Policy Decision Point).

The gateway sees structured data at the only moment that matters. When the model decides to call a tool, it produces a structured JSON-RPC message — `{ name: "execute_sql", args: { query: "...", database: "..." } }`. That message exists as a typed data structure with no ambiguity. The query string is `"DROP TABLE users"` or it isn't. The recipient is `attacker@external.com` or it isn't. There's no natural language interpretation to get wrong.

Compare this to the alternatives:

- **Model-layer enforcement** works on tokens in a context window. The distinction between "instruction from the operator" and "adversarial instruction in retrieved content" is learned, not enforced. Any sufficiently creative phrasing can blur the distinction. You're fighting natural language.
- **System prompt instructions** are input to the model, not constraints on its output. "Don't call execute_sql with DELETE statements" is a request, not an enforcement mechanism.
- **Tool-side enforcement** is principled but doesn't scale — you'd implement the same auth and policy logic N times for N tools, with N different interpretations and N separate audit logs.
- **The gateway** intercepts every call at the typed data layer, implements policy once, and is the only path to the upstream tools. It's the reference monitor by definition.

This is the architecture the rest of this post assumes: the gateway is the mandatory interception point, and every tool call goes through it.

---

## The enforcement pipeline, step by step

I'm going to walk through the actual pipeline — the sequence of operations that every tool call passes through. I'll explain what each step does, why it's in that position, and what "fail closed" means for that specific step.

### Step 1: Token extraction and structure validation

Before anything else, the gateway needs a JWT capability token. The token should arrive in the `Authorization: Bearer <token>` header of the enforce request.

If the header is absent, malformed, or contains something that doesn't parse as a JWT: deny. Immediately. No helpful error message that tells the caller what format to use — that leaks information about what the gateway expects. Just deny with a generic error.

The token is base64-decoded and the payload is inspected for mandatory claims: `iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `schemaVersion`, `capabilities`. If any required claim is missing or has the wrong type: deny. The `schemaVersion` is checked against the set of versions this gateway supports. A token with `schemaVersion: "2.0"` on a gateway that only knows `"1.0"` is rejected — fail closed on schema evolution, as I explained in the tokens post.

This step is deliberately cheap and doesn't require any external state. It's pure structural validation on the token bytes. The cost is a few milliseconds. The alternative — accepting structurally incomplete tokens and trying to work with partial data — creates an attack surface. You want to reject garbage early.

### Step 2: Signature verification

The issuer claim (`iss`) in the JWT points to the capability issuer service that signed the token. The gateway fetches that issuer's public keys from its JWKS endpoint (with caching — you don't make an HTTP request on every single call; the JWKS is cached with a reasonable TTL) and verifies the token signature.

If the signature fails to verify: deny. The token has been tampered with, was never valid, or was signed by a key the gateway doesn't trust. No partial credit. A token with a broken signature is not "almost valid."

If the JWKS endpoint is unreachable and the cached keys are stale: deny. You could fall back to "accept the token anyway" when you can't reach the key source — but that would mean an attacker who can block your JWKS endpoint can bypass signature verification. Fail closed.

The key rotation case is worth mentioning. When an issuer rotates its signing keys, there's a brief window where valid tokens signed with the new key might arrive before the gateway's JWKS cache has refreshed. The JWKS spec handles this via `kid` (key ID) claims — the token identifies which key signed it, and if the gateway doesn't find that key in its cache, it can force a JWKS refresh rather than failing immediately. This is the one case where the fail-closed rule has a short-circuit: an unrecognised `kid` triggers a cache refresh, and if the key is found after the refresh, the verification proceeds. If it's still not found after the refresh: deny.

### Step 3: Standard JWT claim validation

With a valid signature established, the standard JWT claims are checked:

**Expiry (`exp`).** If `exp` is in the past: deny. An expired token is a dead token. No grace period — the expiry was set at issuance time with the session's needs in mind. If you need more time, use `POST /api/v1/renew` before the token expires.

**Not-before (`nbf`).** If present and `nbf` is in the future: deny. Token is not yet valid.

**Audience (`aud`).** The token's audience must match this gateway's configured identifier. A token issued for the staging gateway is not valid at the production gateway.

**Issued-at (`iat`).** Sanity check — `iat` should not be in the future. A token that claims to have been issued in the future was produced by something that doesn't have an accurate clock, which is suspicious.

All of these are O(1) operations on the token claims. No external state, no database lookups, no Redis calls. Fast.

### Step 4: Revocation check

Now we make our first external call. The token's `jti` is checked against the revocation list — a Redis sorted set or hash that contains the JTIs of revoked tokens.

If the JTI is in the revocation list: deny. The token has been explicitly revoked — the session was terminated, a security event was detected, or an admin killed this specific session.

If Redis is unavailable: deny. We can't confirm the token hasn't been revoked, so we treat it as potentially revoked. This is exactly the kind of fail-closed decision that ops teams sometimes push back on ("but Redis has a hiccup once in a while, do we really have to deny everything during a Redis blip?"). The answer is yes. Permitting during Redis unavailability means a deliberate Redis outage — something an attacker who understands your architecture could trigger — becomes a window where all revocations are bypassed. That's not a trade-off I'm willing to make.

The revocation list should only contain entries for tokens that haven't expired yet. There's no point keeping expired tokens in the revocation list — they fail the expiry check before you even get to the revocation check. Use a Redis TTL on revocation entries that matches the corresponding token's remaining lifetime.

### Step 5: Kill-switch check

Separate from per-token revocation, the kill-switch is a global (or capability-class-scoped) flag that suspends all agent activity instantly. It's the emergency stop.

The kill-switch state is a Redis key. The gateway checks it on every call. If active: deny with code `KILL_SWITCH_ACTIVE`. Clearing the kill-switch (setting it back to inactive) immediately resumes normal enforcement.

The kill-switch is coarser than revocation. Revocation targets a specific session's JTI. The kill-switch can be: all sessions, sessions for a specific agent type, sessions with a specific capability, sessions calling a specific tool. When you discover an exploit in a specific MCP server and need to prevent any agent from calling any tool on that server while you patch it, the kill-switch is the right lever. Revoking individual tokens would require enumerating every active session — slow and error-prone when you need to stop something in ten seconds.

### Step 6: Capability match

Now the gateway looks at the actual tool call. The call has a `toolName` and an `arguments` object. The token has a `capabilities` array. The gateway needs to find a capability entry that covers this call.

The matching logic:

1. Map the `toolName` to a resource URI. The gateway has a tool-to-resource mapping that says "`execute_sql` on the analytics database maps to `db://analytics/**`". (This mapping is configured per server; the gateway learns it from the tool's registration metadata.)

2. Find capability entries in the token whose `resource` pattern matches the mapped resource URI, using segment-aware glob matching. `db://analytics/**` matches `db://analytics/sales_data`.

3. Check that the capability's `actions` array includes the action implied by this call. A `read` tool call against a capability that only grants `write` fails this check.

4. If no matching capability is found: deny. The token doesn't grant permission for this tool call. The agent has no business calling this tool in this session.

5. If multiple capabilities match (this can happen when conditions on the narrower one would fail): use the most-specific match. This prevents a broader, less-constrained capability from being used when a narrower one was intended.

The resource URI mapping and pattern matching is the part that requires the most careful configuration — getting it wrong means either the agent can't do what it needs to do (false denials) or a capability ends up matching tools it shouldn't (false allows). For the built-in MCP servers that euno ships adapters for, the mapping is pre-configured. For custom tools, operators define the mapping as part of tool registration.

### Step 7: Condition evaluation

This is where the interesting work happens. For each condition in the matched capability entry, the gateway's `ConditionRegistry` looks up the handler for that condition type and invokes it with the call's arguments and context.

The `ConditionRegistry` is the extensibility point for conditions. The built-in types — `allowedOperations`, `maxCalls`, `timeWindow`, `allowedExtensions`, `allowedTables`, `recipientDomain`, `redactFields`, `ipRange` — all have registered handlers. Custom condition types can be registered by gateway operators who need domain-specific enforcement logic.

The critical property: **unknown condition types fail closed**. If the token contains a condition with `type: "newConditionType"` and the gateway's `ConditionRegistry` has no handler for `"newConditionType"`, the gateway does not skip that condition. It denies the call. A condition that can't be evaluated is a condition that might have denied the call, and we can't know which, so we deny.

This asymmetry is intentional and important. During policy evolution — when a new condition type is published and some gateways have been updated but others haven't — the updated gateways enforce the new condition while the unupdated gateways refuse to run tokens that include it. The unupdated gateways need to be updated. The failure mode is "agent calls fail until the gateway is updated," which is visible and fixable. The alternative — "unupdated gateways skip the new condition and allow calls that should have been denied" — is the silent security regression that you don't find out about until something goes wrong.

Some specific conditions and how they're evaluated:

**`allowedOperations`**: Extract the first non-whitespace keyword from the `query` argument (after stripping comments). Check it against the allowed list. This is case-insensitive and done on the raw argument string. An injection that produces `/* comment */ DROP TABLE users` would have `DROP` as the first keyword and fail. An injection that produces `SELECT /*; DROP TABLE users; --*/` from legitimate_table would pass — the first keyword is `SELECT` — but the multi-statement guard (if configured) would catch the embedded `DROP`.

**`maxCalls`**: Fetch-and-increment the rate counter in Redis, scoped to the `(jti, resource, condition-hash)` tuple. If the counter exceeds the limit: deny. If Redis is unavailable: deny. The increment is atomic (Redis `INCR` command) so two concurrent calls both at the limit can't both get approved by reading a stale counter.

**`timeWindow`**: Check `now` against `notBefore` and `notAfter`. Pure in-process check, no external state.

**`recipientDomain`**: Extract the domain from each email address in the `recipients` argument. Check each domain against the allowed list. Any address with a non-allowed domain: deny. This is evaluated against the actual argument values, not the model's stated intent.

**`redactFields`**: Unlike the others, this is not an allow/deny condition — it's a pre-flight obligation. The gateway marks the specified fields for redaction before they're logged to the audit record. The call is allowed; the obligation is recorded and applied at the audit write step.

If any condition fails: deny the whole call. All conditions are and-ed together. Satisfying nine of ten conditions is the same as satisfying zero of ten. Partial compliance is not compliance.

### Step 8: Obligation application

Some conditions generate obligations — side effects that must happen on an allowed call. Obligations are distinct from conditions in that they don't gate the decision; they're applied after the decision is confirmed as allow.

The main obligations:

**Rate counter increment.** For `maxCalls` conditions that allowed the call, the counter needs to be incremented. This happens here rather than during the evaluation step to avoid a scenario where the evaluation increments the counter but the call is later denied by a different condition. (All conditions are evaluated before any counter increments happen.)

**Argument sanitisation.** `redactFields` obligations mark specific argument fields for scrubbing before audit logging. The gateway creates a sanitised copy of the arguments for the audit record, with the redacted fields replaced by a placeholder.

**Context injection.** Some policies require headers or metadata to be injected into the upstream call. For example, stamping an audit correlation ID onto upstream requests so the backend's own logs can be correlated with the gateway's audit records. This happens at obligation application time, before forwarding.

Obligations cannot change a deny to an allow. They're applied only when the decision is already allow. And if any obligation fails (Redis counter increment fails because Redis is unavailable during the obligation step): the call is treated as denied. Fail closed.

### Step 9: Audit write

Before forwarding the approved call to the upstream tool, the gateway writes an audit record to the Postgres ledger. Before, not after.

Why before? If you write the audit record after the upstream call returns and the upstream call hangs or errors, you have a call you can't account for. The initial audit record is written with the decision, the token identity, the tool name, the sanitised arguments, and the conditions that were evaluated. When the upstream call completes (or fails), a completion record is written with the response outcome and latency.

The audit records are OCSF (Open Cybersecurity Schema Framework) API Activity events. The schema maps cleanly to agent tool calls: `actor` is the token subject (the agent's DID), `target.name` is the tool name, `api.request.body` is the sanitised arguments hash, `status_id` is the decision (allow/deny), `metadata` carries the `jti`, condition results, and denial reasons if applicable.

HMAC chaining ties the audit records together. Each record includes an HMAC of the previous record's content, keyed by a secret that the gateway operator holds. Deletion or modification of any record breaks the chain at that point, and the chain break is detectable by anyone who verifies the record sequence. The chain is verified by `GET /api/v1/audit/verify-chain` and is part of the evidence bundle exported for SOC 2 audits.

Every call gets an audit record — allowed and denied. Denied calls are often the most interesting ones. An anomalous spike in denied calls for a specific condition type tells you something is happening that your policy was designed to prevent. That's signal worth having.

### Step 10: Forward or deny

If everything above passed: the call is forwarded to the upstream MCP server. The result comes back through the gateway and is returned to the agent. The gateway can apply response-level obligations here if any are configured — filtering out fields from the response before returning them to the agent.

If anything failed: deny. The upstream server never sees the call. The agent receives an error response with a code that tells it the call was denied and, if policy permits surfacing this information, a reason. The agent can log this, surface it to a user, or continue with its task without the tool result.

---

## The single-audit-entry invariant

One property worth calling out explicitly because it comes up in multi-agent architectures: when a call is mediated by both an in-process guard (the AGT guard, used in agent runtimes that embed euno directly) and the gateway, there should be exactly one audit record for that call, not two.

The in-process guard checks policy before the network even sees the tool call. If it denies, it writes its own audit record and the gateway never sees the call — one record. If it allows, it forwards to the gateway. The gateway writes the authoritative audit record. One record. The in-process guard does not write a separate record for calls it allows and forwards.

This matters because audit inflation — multiple records for a single logical operation — makes audit analysis harder and can make counting-based queries (how many times was tool X called?) produce incorrect numbers. The invariant is maintained by having the in-process guard suppress its own allow-record when a gateway is configured.

---

## Testing the pipeline

The reference monitor property — that every access is mediated, without exception — is only meaningful if it's testable. We've built a comprehensive test suite for the enforcement pipeline, but the architecture-level testing approach is worth describing.

The tests that matter most for the reference monitor property:

**Path coverage.** Every code path that could bypass the enforcement steps (network error handling, timeout handling, condition evaluation exceptions) must be tested to verify it produces a deny, not a permit. Integration tests for all nine steps, including the failure paths.

**Condition registry exhaustiveness.** Every built-in condition type must have tests for: (a) a call that satisfies the condition, (b) a call that violates the condition, (c) an edge case (empty list, boundary values). And there's a test that verifies an unknown condition type produces a deny.

**Concurrency for rate counters.** The `maxCalls` counter test includes a concurrent call test: N goroutines simultaneously call the same rate-limited capability. The total approved calls must equal exactly the configured limit, not "approximately the limit" or "the limit per goroutine."

**Audit completeness.** After running a set of calls through the pipeline, the test verifies that the audit record count equals the call count, not a subset. Every call got an audit record.

The reference monitor concept is demanding not just about the design but about the testing. "It should deny" is only a useful property if you've verified that it actually does.

---

## Why this isn't overkill for AI agents

When I explain this pipeline to teams that are new to agent governance, the reaction is sometimes: "that's a lot for a chat tool." And I understand the reaction — this is enterprise security infrastructure, not something you throw together in an afternoon.

But consider what we're actually protecting against. An agent with database access, file system access, and email access has the capability to:
- Read any database table the service account can access
- Read any file the OS allows the process to read
- Email anything to anyone

An agent that's been exposed to adversarial content — a malicious document, a prompt injection in a web page, an attacker-controlled API response — can be directed to exercise any of those capabilities in ways the operator didn't intend. The attack surface isn't hypothetical. Researchers have demonstrated real exploits against real systems deployed by real companies.

The reference monitor doesn't make agents safe. Nothing makes them safe in an absolute sense. What it does is enforce a ceiling — a set of conditions that must be satisfied for any action to proceed, regardless of what convinced the model to take the action. The ceiling is authored by humans, reviewed like any other security-sensitive configuration, and cryptographically committed to at issuance time.

That's the right architecture for a system where the principal doing the requesting is a language model: enforce not on the model's stated intent, not on system prompt instructions, but on the actual structured arguments at the moment of action. That's the only layer where enforcement is rigorous. Everything else is defence in depth around it.

---

*Previous: [Capability tokens: a cryptographic contract between agent and operator](./09-capability-tokens.md)*

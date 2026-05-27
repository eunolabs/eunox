# From local YAML to hosted policy store: eunox's migration story

_Audience: developers and platform engineers scaling agent governance beyond a single machine_

---

Every system that goes through serious adoption has a moment where the early design runs out of runway. Not because the early design was wrong — it was right for what it was. But the assumptions it was built on stop holding, and you have to evolve. With euno, that moment arrived predictably: the day an agent deployment went from "one developer, one machine" to "multiple agents, multiple users, shared infrastructure."

This post is about that transition — what breaks, what stays the same, and the specific decisions we made about how to bridge the gap without requiring everyone to rewrite their policies or relearn the system. If you've read [the drop-in governance tutorial](./07-drop-in-governance-claude-desktop.md), this is the follow-up: what happens when that setup grows up.

---

## The local mode design and its assumptions

When you run `eunox-mcp proxy --policy ./euno.policy.yaml` in local mode, the whole governance stack is in one process. The policy YAML is loaded at startup. Conditions are evaluated in-memory. Call counters live in-memory. The audit log goes to a local file — `~/.euno/audit.jsonl`.

This design was deliberate. For a single developer using Claude Desktop, it's exactly right. There's no infrastructure to run, no services to keep up, no distributed state to worry about. You change a YAML file and restart. The feedback loop is tight. Onboarding takes five minutes, as [the previous post](./07-drop-in-governance-claude-desktop.md) demonstrates.

But several of the assumptions behind local mode break the moment you scale:

**Assumption 1: there is one agent and one user.** In-memory call counters work when a single process is doing all the enforcement. When you have multiple agent instances running concurrently — which happens immediately when you move from a developer's laptop to any kind of shared deployment — the counters are per-process and independent. A `maxCalls: 100` limit on a `send_email` tool means 100 calls per process, not 100 calls in total. In practice it means the limit doesn't work.

**Assumption 2: the audit log is local and that's fine.** A local JSONL file is fine for a developer who wants to see what Claude did today. It's not fine for a security team that needs to ask "how many calls to the billing database did any agent make this quarter" or for a compliance team that needs a tamper-evident record they didn't produce themselves.

**Assumption 3: kill-switch and revocation are per-process.** Local mode has an in-memory kill-switch. It works for the process it lives in. If an agent is misbehaving and you need to stop it — and you have four instances running — you need to reach four processes. Ideally you'd push one flag and all of them stop within milliseconds. You can't do that without shared state.

**Assumption 4: token signing is implicit.** Local mode works without a cryptographic token issuer. The policy is evaluated from the YAML directly. This is fine as a developer convenience. But the full security model — the one where tokens are signed by a KMS-backed key, carry an expiry, have an unforgeable JTI, and can be individually revoked — requires a real capability issuer service. The local mode shortcuts this, which is fine until you need the properties the shortcuts removed.

None of these are surprises. The local design was always intended as a stepping stone, not a destination. The critical thing was making the transition to hosted mode as close to zero-friction as possible.

---

## What the hosted gateway adds

The hosted gateway is a different architecture, not a replacement philosophy. The same concepts apply — capability manifests, conditions, fail-closed enforcement, tamper-evident audit. What changes is where the state lives and how it's shared.

Here's the side-by-side:

| Concern         | Local mode                           | Hosted mode                                     |
| --------------- | ------------------------------------ | ----------------------------------------------- |
| Policy storage  | YAML file on disk                    | Gateway policy store (versioned, hash-verified) |
| Call counters   | In-memory, per-process               | Redis, shared across all agent instances        |
| Kill-switch     | In-memory, per-process               | Redis global flag, instant effect everywhere    |
| Revocation list | In-memory, per-process               | Redis, checked per call across all sessions     |
| Audit log       | `~/.euno/audit.jsonl` (HMAC-chained) | Postgres ledger (KMS-signed, durable)           |
| Token signing   | Simplified / skipped                 | Full JWT signed by HSM-backed tenant key        |
| Multi-user      | Not designed for it                  | Native multi-tenancy with per-tenant isolation  |

The policy format is identical. That's the single most important architectural decision in the whole migration story, and I'll explain why it was hard to maintain and why we held the line on it.

---

## The one-config-change promise

When we designed the migration path, we had a strong requirement: the change from local to hosted mode should be a single config change. Not a policy rewrite, not a new YAML format, not a learning exercise. You change one thing in your MCP config — swap `--policy ./euno.policy.yaml` for `--enforcer-url https://gateway.example --enforcer-api-key sk-...` — and everything else is the same.

This turns out to be a surprisingly hard thing to commit to, because the two modes have different underlying security architectures. Local mode evaluates policy directly from a YAML file. Hosted mode requires a signed JWT capability token — a cryptographic artefact that the enforcement pipeline verifies before looking at anything else. These are not the same thing. You can't just swap one for the other without bridging the gap somewhere.

The bridge is the minter façade.

---

## The minter façade: the seam that makes it work

When `eunox-mcp` in hosted mode sends a tool call to the gateway, it sends its `sk-...` API key as the bearer token. That API key is a long-lived bearer secret — essentially a password. It's not a JWT. It doesn't have a signature. It doesn't have an expiry. It can't pass through the gateway's JWT verification step.

The minter façade sits between the proxy and the enforcement endpoint. It receives the API key, looks up the tenant and policy associated with it, and mints a short-lived signed JWT — TTL of five minutes or less — using the tenant's HSM-backed signing key. That JWT goes to the enforcement endpoint, which verifies it like any other capability token.

The flow looks like this:

```
eunox-mcp (proxy)
      │
      │  POST /api/v1/enforce
      │  Authorization: Bearer sk-x7Kp9mRq...
      │  Body: { toolName, arguments, sessionId }
      ▼
Minter façade
      │  1. Validate sk-... API key
      │  2. Look up tenant ID, policy ID, policy hash
      │  3. Mint JWT using HSM key (TTL ≤ 5 min)
      │  4. Write mint-audit record (jti, tenant, policy hash)
      │
      │  JWT (signed by HSM)
      ▼
POST /api/v1/enforce (internal)
      │  1. Verify JWT signature against JWKS
      │  2. Check expiry, schema version
      │  3. Check JTI against revocation list
      │  4. Evaluate conditions
      │  5. Write audit record (Postgres)
      ▼
EnforceResponse { decision, obligations }
```

The key insight here is that the JWT minted by the façade contains the policy hash as a claim. So every enforcement decision in the audit log carries a cryptographic fingerprint of the exact policy that was in effect when the token was issued. If you need to prove to an auditor that agent sessions this quarter were governed by policy version X, you pull the audit records and they all carry the policy hash for version X. There's no "trust me, the right policy was active" — it's in the record.

A few other properties this buys you:

**Revocability with bounded blast radius.** If an API key is compromised, you revoke it in the gateway. Any JWTs minted from it before revocation have a maximum TTL of five minutes. An active running session's JTI can be added to the revocation list immediately via the admin API, closing the window to zero. At most five minutes of exposure per key compromise, and you can make that window zero if you have the admin API wired up.

**Key isolation.** Each tenant's JWTs are signed by their own HSM key. Compromise of one tenant's key doesn't affect any other tenant's tokens. The HSM key itself can't be exported — the HSM boundary enforces this regardless of what access the caller has. An attacker who compromises minter credentials can trigger signatures but can't exfiltrate the private key material.

**Non-repudiation.** The minted JWT is not just a session credential — it's a commitment. The minter's own audit record says "at time T, from API key K, I issued JWT J for policy P." The JWT itself carries `policy_hash`, `jti`, `iss`, `aud`, and standard claims. The enforcement record in Postgres carries the `jti`. You can trace any enforcement decision back to its minting event and from there to the policy that was in effect.

---

## Keeping the policy format identical — and why it was hard

I said the policy format is identical between local and hosted mode. This is a strong statement that took engineering effort to maintain, and it's worth explaining why.

The hosted gateway internally represents policies in a slightly different shape than the YAML you write. It needs to version them, hash them, associate them with tenants. There's a temptation to expose that internal shape — let you upload a "gateway-native" policy format that has the versioning and tenant fields baked in. It's a natural evolution.

We didn't do it. The shared manifest types live in Go packages under `pkg/`. The same Go structs, conditions, resource-pattern parsing, and validation code are used by `eunox-mcp` for local mode evaluation, by the issuer service for JWT generation, and by the hosted gateway in `cmd/gateway` for enforcement. The gateway wraps the manifest in internal metadata, but the manifest itself is the same thing you write locally.

The reason this matters practically: a developer who writes a manifest on their laptop, validates it with `eunox-mcp validate`, runs it locally for a week, and then uploads it to the gateway should have no surprises. The policy they tested locally is the policy being enforced remotely. There's no "that works locally but not in the gateway" class of problem if the schema is genuinely shared.

The shared schema also means that `eunox-mcp validate` — which runs the same validation logic as both the local evaluator and the gateway — is a trustworthy pre-flight check in CI. If the validation passes, the gateway will accept it. If the gateway rejects it, the validation would have caught it. This makes the policy authoring loop genuinely usable, which is something that falls apart quickly if the local and remote validation rules diverge.

---

## The migration in practice

We built `eunox-mcp upgrade-to-hosted` to make the mechanics as smooth as the conceptual story. The command does four things:

1. Validates the API key against the gateway (catches auth problems before you're half-migrated)
2. Uploads your policy YAML to the gateway's policy store
3. Prints the policy ID so you can reference it later
4. Optionally patches your MCP config to swap `--policy` for `--enforcer-url` + `--enforcer-api-key`, with a `.bak` backup of your old config

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.euno.example \
  --api-key sk-x7Kp9mRq.bL3nYv2wQs... \
  --admin-key sk-adminKey... \
  --policy ./euno.policy.yaml
```

There's also a `--dry-run` flag that shows you what it would do without writing anything. Use it before the real run.

The recommended approach is to run both modes in parallel briefly before committing to the switch. Your MCP config can have two entries for the same server — one local, one hosted — and you can compare decision logs from both to confirm parity before removing the local entry.

```jsonc
{
  "mcpServers": {
    "database-local": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "/path/to/euno.policy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://localhost:5432/analytics",
      ],
    },
    "database-hosted": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--enforcer-url",
        "https://gateway.euno.example",
        "--enforcer-api-key",
        "sk-x7Kp9mRq...",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://localhost:5432/analytics",
      ],
    },
  },
}
```

A day or two of parallel running tells you quickly if there are any policy edge cases that behave differently. In practice, if `eunox-mcp validate` passes on your local file, the hosted gateway will behave identically — the validation is shared code. But the parallel run catches any environmental differences.

---

## The data boundary question

Moving to hosted mode means tool call arguments leave your network on their way to the gateway's policy evaluation engine. This is worth being explicit about for anyone doing a SOC 2 review or GDPR analysis.

What goes to the gateway on every tool call:

- Tool name
- Tool arguments (raw — these are evaluated for policy conditions like `allowedOperations`, `argumentSchema`, `recipientDomain`)
- Session identifier
- Source IP (for stdio transports, this is omitted)
- Timestamp

What stays on your network:

- The upstream MCP server's response — the gateway never sees it
- Raw tool arguments after evaluation — only a SHA-256 hash (`argsHash`) is written to the audit ledger, not the raw arguments
- Your policy YAML content — uploaded once at setup, not re-transmitted per call
- HSM signing key material — never leaves the HSM boundary

The audit record stores `argsHash` rather than raw arguments for exactly the reasons you'd expect: arguments frequently contain personal data, credentials, PII, confidential query values. Storing a hash preserves the ability to verify argument integrity (you can re-hash a known argument and compare) without retaining the raw data in a long-lived store.

If you need tool arguments to stay on your network entirely, the self-hosted path is the answer. You run the gateway stack yourself — Redis, Postgres, the capability issuer, the gateway service — and nothing leaves your infrastructure. The trade-off is operational overhead. See `docs/self-host.md` for the full guide.

---

## Rollback, because rollback should be easy

One thing I insisted on early: rollback to local mode should be instant and require no data migration.

It is. If you need to roll back from hosted to local: restore the `--policy` flag, remove `--enforcer-url` and `--enforcer-api-key`, restart your MCP host. Done. Local enforcement is active again.

The gateway doesn't delete anything. Audit records written during the hosted period remain in the Postgres ledger and are queryable via the audit API even after you switch back. The local HMAC audit log file is untouched — records from before the migration are still there for `eunox-mcp stats` and local analysis. The two audit trails — local HMAC and hosted Postgres — coexist independently.

This wasn't an accident. Systems where rollback is a major operation discourage rollback, which means teams are stuck with a bad upgrade longer than they should be. Making rollback trivial changes the risk calculus of migrating in the first place.

---

## What the hosted gateway unlocks

Beyond the engineering properties, there are a few operational capabilities that simply don't exist in local mode and become available in hosted mode.

**Cross-session analytics.** The Postgres audit ledger is queryable. You can ask: "which agent sessions accessed the billing database last month?" or "what was the total call volume for the GitHub integration this week?" or "show me all sessions where the `send_email` tool was called more than 10 times." These queries are either impossible or very slow against a JSONL file.

**Live kill-switch.** One Redis write suspends all agent activity for your deployment instantly. From the admin API: `POST /api/v1/kill-switch { "active": true }`. Every subsequent tool call from every session returns a deny with code `KILL_SWITCH_ACTIVE`. This is the emergency stop you want in your back pocket when something is actively wrong.

**Per-token revocation.** An individual session's JWT JTI can be added to the revocation list via the admin API. The session's next tool call fails immediately. This is useful when you've identified a specific session behaving oddly but don't want to kill everything.

**SOC 2 evidence export.** The audit ledger supports a signed export endpoint — `GET /api/v1/audit/export` — that produces a bundle covering a time range, signed by the gateway's signing key. A SOC 2 auditor can verify the signature against the published JWKS and confirm the audit records are authentic and unmodified. This is not something you can produce from a local JSONL file without a lot of additional work.

**SCIM provisioning.** For enterprise deployments, SCIM 2.0 lets you provision agents from your identity provider — Okta, Azure AD, Entra ID. New agents get capability manifests derived from their group memberships. Removed users' tokens are revoked automatically. This is the operational layer that makes large-scale agent deployments manageable.

---

## The migration is a gradient, not a cliff

One thing worth saying directly: you don't have to migrate everything at once. The hosted and local modes are composable. You might migrate your production database server to hosted enforcement today and keep your local filesystem server in local mode for now. The different entries in your MCP config can use different enforcement modes independently.

The right approach is incremental: start with the servers where shared state matters most — the ones that have rate limiting you actually need to enforce across sessions, or where audit durability is a genuine requirement — and leave the lower-stakes ones in local mode until you're ready.

The policy YAML for both entries comes from the same source. You're not maintaining two separate sets of policies; you're just choosing, per server, where the enforcement engine runs.

That flexibility is what makes the architecture useful in practice. Not everyone needs a hosted gateway on day one. But the path to it should never require throwing away the work you've already done.

---

_Previous: [Drop-in governance: adding eunox-mcp to Claude Desktop in 5 minutes](./07-drop-in-governance-claude-desktop.md)_

_Next: [Capability tokens: a cryptographic contract between agent and operator](./09-capability-tokens.md)_

# From Dev to Prod: The euno CLI Experience

*Second post in the "User experience and developer ergonomics" series. [Post 19](./19-one-yaml-file.md) covered the YAML manifest format itself — the artifact you're authoring when you use these commands. [Post 8](./08-local-to-hosted.md) covers the architectural story of the migration from local to hosted enforcement; this post is about the CLI experience of living through that journey day-to-day. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

I believe that tools shape the habits of the people who use them. A security tool with a painful developer experience produces workarounds — people do just enough to clear the gate and then find ways to avoid the tool afterwards. A security tool that fits into the existing developer loop gets used, gets iterated on, and ends up producing better security posture than the "better" tool that nobody wanted to open.

That conviction drove a lot of the euno CLI design. Every command is something you'd want to run as a natural part of developing or operating an AI agent, not something you'd run grudgingly before a deployment gate.

This post walks through the full CLI experience from first write to production operation.

---

## Getting started: `euno-mcp proxy`

Everything begins with `euno-mcp proxy`. This is the command that puts euno in front of your upstream MCP server. For the stdio transport — which is what Claude Desktop, Cursor, and most MCP-capable hosts expect — it looks like this:

```bash
euno-mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

That `--` separator is important: everything after it is the upstream server command, including its arguments. The `euno-mcp proxy` command spawns that upstream process and starts intercepting MCP messages between the host and the upstream server.

In the absence of a `--policy` flag, the proxy runs in passthrough mode: all tool calls are allowed, none are blocked. This is intentional for the first few minutes with a new agent — you want to see the tools work before you start adding constraints. The audit log still runs in passthrough mode, which means you can see exactly what tools the agent called and with what arguments, even before you write a policy.

Once you have a policy file:

```bash
euno-mcp proxy --policy ./euno.policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

The proxy validates the manifest at startup. If validation fails, the proxy exits immediately with a human-readable error — it won't start in an ambiguous state. Once it starts, every tool call is checked against the policy before the upstream ever sees it.

The startup validation is doing something important: it's running the same `validateManifest()` function from `@euno/common-core` that the hosted gateway runs at enforcement time. Not a "close enough" check — the exact same code. This means if the policy validates at startup, you know it will be processed identically in production. There are no "local vs. production" surprises with the schema. [Post 16](./16-schema-parity-over-version-drift.md) explains why this property is worth the engineering effort it takes to maintain.

---

## Transport options: stdio vs HTTP

The default transport is stdio, which is what you need when configuring Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "euno-mcp",
      "args": [
        "proxy",
        "--policy", "/path/to/euno.policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

The `claude_desktop_config.json` pattern puts `euno-mcp proxy` as the outer command. Claude Desktop spawns `euno-mcp proxy`, which in turn spawns the upstream server. All of Claude Desktop's MCP traffic for this server flows through euno's proxy transparently.

The HTTP transport is for when you're running the proxy as a service that multiple agent processes connect to:

```bash
euno-mcp proxy \
  --transport http \
  --port 3000 \
  --auth-token $(openssl rand -hex 32) \
  --policy ./euno.policy.yaml \
  -- node ./my-mcp-server.js
```

The `--auth-token` flag is worth calling out explicitly. Without it, the proxy will start and print a warning that any process on the machine can call the `/mcp` endpoint. You almost certainly want to set it, especially if you're binding to anything other than localhost. Generate a strong random token and inject it into your agent processes' environment.

The `--bind` flag (default `127.0.0.1`) controls what address the HTTP server listens on. If you need to accept connections from other hosts, use `--unsafe-bind-all` (which binds to `0.0.0.0`). The flag name is deliberately alarming — binding to all interfaces when running behind a reverse proxy is fine, but the operator should consciously accept the implications.

The `--upstream-timeout` flag is one I always recommend setting in production. By default there's no timeout on the upstream server. If your upstream hangs, the proxy will hang waiting for it — indefinitely. Setting `--upstream-timeout 30000` means slow upstream calls fail with a clear error rather than blocking the connection forever. The call is logged in the audit trail with a timeout error, which is actionable. A silent hang is not.

---

## Validating a policy: `euno-mcp validate`

You don't need to start the proxy to validate a policy file. The `validate` command does exactly that:

```bash
euno-mcp validate ./euno.policy.yaml
```

On success:

```
✓ Manifest is valid
  Agent: Sales Research Bot (sales-research-bot)
  Version: 0.2.0
  Required capabilities: 4
```

On failure:

```
✗ Validation failed: Capability at index 1: condition at index 0 has unknown type "allowedOpetations". Did you mean "allowedOperations"?
```

The error messages try to be helpful. When we detect a string that's close to a valid condition type name (edit distance one or two), we include a "did you mean" suggestion. It's a small thing but it's the difference between a developer spending two minutes staring at a YAML field versus spending ten seconds reading the error.

`euno-mcp validate` integrates naturally into CI. Add it as a pre-commit hook or a CI step:

```yaml
# .github/workflows/validate-policy.yml
- name: Validate euno policy
  run: npx -y @euno/mcp validate ./euno.policy.yaml
```

The command exits with code 0 on success, non-zero on failure, so it works cleanly as a CI gate. We've seen teams add this to their PR checks so policy changes get validated before merge, not after deploy.

---

## The local kill switch: `euno-mcp kill`

The kill switch is primarily an operator concern (covered in depth in [post 21](./21-operator-tooling.md)), but the local CLI exposes it for development and testing purposes via the HTTP transport.

When you're running the proxy in HTTP mode, you can activate the kill switch from another terminal:

```bash
# Kill a specific session
euno-mcp kill sess-abc-123 --port 3000

# Kill all active sessions
euno-mcp kill all --port 3000
```

This sends a POST to the proxy's `/control/kill` endpoint. The proxy responds by denying all subsequent tool calls from the affected session(s) — they receive a `KILL_SWITCH_ACTIVE` error code rather than a tool result.

The kill switch tests something important: your agent code's error handling. When a tool call is denied with `KILL_SWITCH_ACTIVE`, what does your agent do? Does it surface the error gracefully to the user? Does it loop and retry? Does it crash? You want to know the answer to these questions in development, not in an incident.

The kill target `all` is especially useful for chaos testing: start the proxy, run your agent through a workflow, hit `euno-mcp kill all` partway through, and observe what happens. If the agent handles the kill switch correctly, you'll see clean error propagation. If not, you've found a reliability gap before it matters.

---

## Inspecting audit records: `euno-mcp validate-token`

Every tool call that goes through the local proxy is recorded as an OCSF API Activity event in `~/.euno/audit.jsonl`, signed with an HMAC using a key stored at `~/.euno/key`. [Post 11](./11-tamper-evident-audit-logs.md) covers the audit log design in detail.

The `validate-token` command gives you two ways to inspect those records.

**Looking up a specific decision by request ID:**

```bash
euno-mcp validate-token --request-id a1b2c3d4-1234-5678-abcd-ef0123456789
```

This finds the audit record with that `metadata.uid`, re-computes the HMAC signature, and reports whether it matches. The output looks like:

```
Request ID: a1b2c3d4-1234-5678-abcd-ef0123456789
  Decision:  ALLOW
  Tool:      query
  Agent:     sales-research-bot (v0.2.0)
  Time:      2026-05-15T14:23:11.456Z
  HMAC:      ✓ signature verified
```

Or if the record has been tampered with:

```
Request ID: a1b2c3d4-1234-5678-abcd-ef0123456789
  HMAC:      ✗ signature mismatch — record may have been modified
```

This command is useful for two audiences. For developers, it's a way to understand exactly what the enforcement engine saw and decided for a specific tool call. For compliance work, it's a way to produce evidence that a specific tool call's audit record is intact.

**Listing decisions since a timestamp:**

```bash
euno-mcp validate-token --since 2026-05-15T00:00:00Z
```

This streams all audit records from today onward to stdout. Useful for ad-hoc review when you want to see recent decisions. Combine with `jq` for structured inspection:

```bash
euno-mcp validate-token --since 2026-05-15T00:00:00Z | jq 'select(.activity_id == 2)' # denied calls only
```

The `--request-id` and `--since` flags are mutually exclusive — you're doing one of two things: verifying a specific record's integrity, or browsing a time range.

---

## Aggregated denial analysis: `euno-mcp stats`

Once you've been running the proxy for a while and have an audit log with some content, `euno-mcp stats` gives you a high-level summary of what the enforcement engine has been doing:

```bash
euno-mcp stats --since 2026-05-01
```

The output is an ASCII histogram of denial events grouped by condition type and denial code:

```
Denial summary (2026-05-01T00:00:00Z – now)
────────────────────────────────────────────────────────────
allowedOperations / OPERATION_NOT_ALLOWED    ████████████  48
maxCalls          / RATE_LIMIT_EXCEEDED      ████           16
allowedExtensions / EXTENSION_NOT_ALLOWED    ██              8
────────────────────────────────────────────────────────────
Total denials: 72  |  Unique sessions: 3
```

The histogram is designed to be readable at a glance and to answer the question: "Is my policy working as intended?" If you see zero denials, either the policy isn't being triggered (the agent isn't hitting the constrained tools), or the policy is too permissive. If you see unexpected denial categories at high volume, that's a signal to investigate.

The `--since` flag is relative to the current time if you use a relative format like `2026-05-01`, or an absolute ISO-8601 timestamp. The command reads all audit log files including rotated ones (named `~/.euno/audit.jsonl.<ISO-timestamp>`), so you can analyze over a long time window even if the log has been rotated multiple times.

I've started recommending that teams run `euno-mcp stats` as part of their weekly agent review. Not as a deep audit — that's what the full JSONL is for — but as a five-second sanity check: what's being denied, at what rate, and is that what we expect?

---

## Remote enforcer mode

Once you're comfortable with local enforcement and ready to migrate to the hosted gateway, the proxy mode changes. Instead of a local policy file, you point to the hosted gateway:

```bash
euno-mcp proxy \
  --enforcer-url https://gateway.euno.example \
  --enforcer-api-key sk-x7Kp9.abc123... \
  -- node ./my-mcp-server.js
```

In this mode, the proxy doesn't load a local policy file — the flag `--policy` is mutually exclusive with `--enforcer-url`. Instead, every tool call triggers a POST to the gateway's `/api/v1/enforce` endpoint. The gateway evaluates the policy stored in its own policy store and returns an allow/deny decision plus any obligations.

The proxy can't enforce locally in this mode — that's the point. All enforcement decisions are made centrally by the gateway, which means policy updates take effect immediately without restarting the proxy processes. One policy change touches every agent session using that policy.

If the enforcer URL is set but the API key is missing (or vice versa), the proxy refuses to start with a clear error. If the gateway is unreachable during a tool call, the proxy returns a denial with `REMOTE_ENFORCER_UNAVAILABLE` — fail closed, per [post 15](./15-fail-closed-not-fail-open.md). The enforcer timeout (`--enforcer-timeout`) controls how long the proxy waits for a response before denying — default 10 seconds, adjustable for gateways with higher latency.

---

## Automated migration: `euno-mcp upgrade-to-hosted`

The migration from local to hosted enforcement isn't just a config change — there are a few steps involved: validate that your API key works, discover your `claude_desktop_config.json` and patch it to use `--enforcer-url` instead of `--policy`, optionally upload your local policy to the hosted policy store. The `upgrade-to-hosted` command automates all of this:

```bash
euno-mcp upgrade-to-hosted \
  --gateway-url https://gateway.euno.example \
  --api-key sk-x7Kp9.abc123...
```

The command walks through the steps interactively:

1. Pings the gateway health endpoint to verify connectivity.
2. Calls `GET /api/v1/ping` with your API key to verify the key and print your tenant ID, policy ID, and scopes.
3. Discovers your `claude_desktop_config.json` (at the platform-standard path) and any additional config files you pass with `--config`.
4. Shows you the proposed diff and asks for confirmation before making any changes.
5. Makes a timestamped backup of any file it modifies.
6. Applies the patches.

The fact that it asks for confirmation before making changes — and shows the diff — is intentional. Migration is a one-way door in terms of the config file state. The backup means you can roll back, but it's better to see the change before it's made.

You can also pass `--dry-run` to see the proposed changes without applying them. This is useful when you want to review the upgrade in a PR rather than applying it interactively.

---

## The feedback loop in practice

The workflow I recommend for developing a new agent policy looks like this:

1. **Write the initial manifest.** Start from one of the reference policies ([post 22](./22-reference-policies.md)) and adapt it. Don't over-constrain on the first draft.

2. **Run the proxy in passthrough mode first.** No `--policy` flag. Run the agent through a few realistic workflows. Watch the audit log with `euno-mcp validate-token --since <now>`. Note what tools it calls and with what arguments.

3. **Write the policy based on what you observed.** The audit log gives you exactly the resources, actions, and argument shapes the agent actually uses. You're constraining the real behavior, not a guess about it.

4. **Validate the policy.** `euno-mcp validate ./euno.policy.yaml`. Fix any schema errors.

5. **Start the proxy with the policy.** Run the same workflows again. Check that nothing is blocked that should be allowed. Check that the things you intended to block are blocked.

6. **Check `euno-mcp stats`.** Make sure the denial count is what you expect.

7. **Add the policy to your git repo and submit a PR.** Add `euno-mcp validate ./euno.policy.yaml` as a CI step. Request security team review.

8. **Upgrade to hosted when ready.** `euno-mcp upgrade-to-hosted` handles the config transition.

The whole loop from "blank policy" to "reviewed and deployed" is designed to take hours, not days. The constraints are reviewable and the CLI gives you immediate feedback on whether they're correct.

---

## A note on the audit log key

The local HMAC audit log uses a signing key at `~/.euno/key`. This key is created automatically on first use with secure random bytes. The file permissions are set to `0600` — readable only by the current user.

If you're running the proxy in an automated context (CI, a container, a server), make sure the key path is consistent across invocations. If the key is regenerated for every run, you lose the ability to verify signatures from previous runs (the signature uses the key that existed when the record was written). The `--audit-log` flag lets you specify a custom log path; the signing key always remains at `~/.euno/key` regardless of where the log is written.

For production deployments, the hosted gateway uses KMS-backed signing, which addresses the key management complexity. But for local development, the file-based key is deliberately simple. The critical property is that you don't lose it between runs of the proxy.

---

*Previous: [post 19 — One YAML file: the design philosophy behind euno's policy format](./19-one-yaml-file.md). Next: [post 21 — Operator tooling: kill switches, revocation, and SCIM provisioning](./21-operator-tooling.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

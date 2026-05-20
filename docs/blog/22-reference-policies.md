# Reference Policies: Copy-Paste Guardrails for Common MCP Servers

*Fourth and final post in the "User experience and developer ergonomics" series. [Post 19](./19-one-yaml-file.md) covered the YAML format itself. [Post 18](./18-defense-in-depth-sql-injection.md) explains the defense-in-depth rationale behind several of the constraints in the Postgres policy. [Post 10](./10-tool-gateway-pdp.md) covers the enforcement engine that evaluates these policies at runtime. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

One of the things I spent a lot of time on before shipping euno was the set of reference policies that ship with the package. Not because they're technically complex — the YAML isn't complicated. Because getting the constraints *right* requires thinking carefully about what each MCP server can do, what can go wrong, and what reasonable defaults look like for an operator who hasn't thought deeply about AI agent security for their specific tool.

The five policies that ship with `@euno/mcp` under `public/packages/mcp/policies/` cover the MCP servers we see deployed most often: filesystem, Postgres, GitHub, Slack, and fetch. This post walks through each one with detailed commentary on why specific constraints were chosen, what they protect against, and where the gaps are.

I want to be honest about the gaps. A reference policy is a starting point, not a final answer. The right policy for your deployment depends on your specific threat model, your trust model for the LLM, and the business logic of the agent. Copy the reference policy, then think about what to change.

---

## The default-allow caveat

Before diving in: the euno-mcp PDP has a **default allow** behavior for tool calls that don't match any constraint in the manifest. This is worth internalizing before you read the individual policies.

If your manifest lists a `query` tool but not a `list_tables` tool, and the agent calls `list_tables`, that call is allowed. There's no implicit block for unlisted tools. The policy is a list of constraints on specific tools, not a whitelist that blocks everything else.

This design choice was deliberate. An overly restrictive default would mean that the first time a new MCP server adds a read-only introspection tool, every existing policy would start denying calls that were previously allowed and innocuous. It would also make writing first drafts of policies much harder — you'd need to enumerate every tool before you could start at all.

The tradeoff is that reference policies need to be explicit about which unlisted tools are being intentionally left unconstrained. Every policy in this set has a comment explaining exactly that.

---

## The filesystem policy

**File**: `public/packages/mcp/policies/filesystem.policy.yaml`
**Upstream**: `@modelcontextprotocol/server-filesystem`

The filesystem MCP server is the most widely deployed server in the ecosystem and, by some margin, the most dangerous without guardrails. It exposes tools that can read, write, delete, and move files on the host filesystem. An unguarded filesystem agent is essentially a remote code execution surface.

The reference policy enforces three layers of protection:

**Layer 1: Path confinement for write operations.** All write, delete, and move tools require that the `path` argument matches `/data/.*`. Read tools are unrestricted — the rationale is that if an agent can read the filesystem, path-confining reads doesn't meaningfully limit the information available to it (the LLM will find creative ways to read what it needs). Write confinement is where it matters.

```yaml
- resource: write_file
  actions: [call]
  argumentSchema:
    type: object
    properties:
      path:
        type: string
        pattern: "/data/.*"
    required: [path, content]
    additionalProperties: false
```

The `additionalProperties: false` is doing quiet but important work here. If a prompt injection attack embeds additional fields in the argument object (a technique sometimes used to bypass validators that only check expected fields), the `additionalProperties: false` clause rejects those arguments entirely.

**Layer 2: Extension allowlist on write and delete.** Even within `/data/`, writes and deletes are restricted to text-safe extensions: `.txt`, `.md`, `.json`, `.csv`, `.yaml`, `.yml`. Binary formats, executables, scripts — none of these can be written through the policy.

```yaml
conditions:
  - type: allowedExtensions
    extensions: [.txt, .md, .json, .csv, .yaml, .yml]
```

The extension check on reads is more permissive (also includes `.log`, `.xml`, `.html`, `.toml`, `.ini`) because reading a binary file is significantly less dangerous than writing one. You can read a `.so` file; you should never be able to write one through an AI agent.

**Layer 3: Burst guards on destructive operations.** `delete_file` is limited to 5 calls per minute. This is a behavioral guardrail against a looping agent that repeatedly calls `delete_file` — a failure mode that can happen when the agent gets confused and enters a retry loop. `write_file` is limited to 100 calls per minute, which is generous for legitimate use but will catch runaway write loops.

**The `move_file` edge case.** One nuance worth highlighting: the `move_file` tool takes `source` and `destination` arguments, not a `path` argument. The euno enforcement engine's `extractFilePath()` function recognizes common argument key names (`filePath`, `path`, `file`, `filename`) but not `source` and `destination`. This means the `allowedExtensions` condition can't be applied to `move_file` — the engine doesn't know which argument to check.

The workaround is to encode the path confinement and extension restriction directly in the `argumentSchema` patterns:

```yaml
- resource: move_file
  actions: [call]
  argumentSchema:
    type: object
    properties:
      source:
        type: string
        pattern: "/data/.*\\.(?:txt|md|json|csv|yaml|yml)"
      destination:
        type: string
        pattern: "/data/.*\\.(?:txt|md|json|csv|yaml|yml)"
    required: [source, destination]
    additionalProperties: false
```

This is a good example of why you need to understand your MCP server's argument shape, not just its tool names. The reference policies have been written with knowledge of how each server structures its arguments. If you're adapting a policy for a different server, check its argument schema.

**What the filesystem policy doesn't protect against**: It doesn't protect against reading sensitive files like `~/.ssh/id_rsa`, `/etc/passwd`, or environment files. If you need to restrict read access, you'll need to add path confinement to the read tools as well. The default decision to leave reads unrestricted was a judgment call — restricting writes is the higher-priority protection against irreversible harm.

---

## The Postgres policy

**File**: `public/packages/mcp/policies/postgres.policy.yaml`
**Upstream**: `@modelcontextprotocol/server-postgres`

The Postgres policy is the most directly connected to the SQL injection defense described in [post 18](./18-defense-in-depth-sql-injection.md). It implements two of the five defense layers: `allowedOperations` (layer 1) and `allowedTables` (layer 2, with the table allowlist being the logical complement).

```yaml
- resource: query
  actions: [call]
  conditions:
    - type: allowedOperations
      operations: [SELECT, EXPLAIN, SHOW]
    - type: allowedTables
      tables: [orders, products, customers, inventory, catalog]
    - type: maxCalls
      count: 100
      windowSeconds: 60
```

**Why `allowedOperations`?** The first-word extraction blocks the most obvious injection vectors: `DROP TABLE`, `INSERT INTO`, `DELETE FROM`, `UPDATE`, `ALTER TABLE`, `TRUNCATE`, `CREATE`, `GRANT`, `REVOKE`. A model that has been manipulated into generating DDL or DML simply cannot execute it if the first word isn't `SELECT`, `EXPLAIN`, or `SHOW`.

[Post 18](./18-defense-in-depth-sql-injection.md) is honest about what this doesn't catch: it doesn't catch `SELECT ... INTO OUTFILE`, creative uses of CTEs with side effects (if your database supports them), or SQL procedures invoked via SELECT. The `allowedOperations` check is a first line of defense against the obvious cases, not a complete SQL parser.

**Why `allowedTables`?** Even with `SELECT`-only enforcement, an unrestricted table allowlist means the agent can read anything in the schema. The table allowlist is the defense against a compromised agent reading credential tables, session tables, audit logs, or anything else it shouldn't access. The reference policy lists five example business tables; your actual deployment should list exactly the tables the agent needs and no more.

The reference policy is silent on tables like `users`, `auth_tokens`, `secrets`, `audit_log`, `sessions`. This is intentional — those tables are excluded by omission. The allowlist is a positive list: only tables in the list can appear in the FROM clause. If the agent tries to query a table not in the list, the enforcement engine returns `TABLE_NOT_ALLOWED`.

**Why `maxCalls`?** A SELECT-only agent that can issue 10,000 queries per minute can still exfiltrate the entire database faster than most organizations can detect it. The rate limit isn't primarily a security control — it's a cost and availability control. 100 queries per minute is generous for most reporting use cases. If your agent needs higher throughput, bump it deliberately and note why.

**What the Postgres policy doesn't protect against**: It doesn't apply parameterization. The enforcement engine checks the SQL string, not the parameterized query. If your MCP server passes the LLM-generated SQL directly to the database without parameterization, you're relying entirely on the first-word check. The reference policy comment includes this explicit warning. Read [post 18](./18-defense-in-depth-sql-injection.md) for the full picture.

**Schema introspection.** The `list_tables` and `describe_table` tools are left unconstrained. This was a deliberate ergonomics decision: blocking schema introspection makes it very hard for the agent to formulate correct queries. The information accessible through schema introspection (table names, column names, types) is usually not secret. If your database schema contains sensitive table names, add constraints to the introspection tools as well.

---

## The GitHub policy

**File**: `public/packages/mcp/policies/github.policy.yaml`
**Upstream**: `@modelcontextprotocol/server-github`

The GitHub policy reflects the threat model for an AI agent with access to your organization's codebase: runaway write operations (too many issues, too many PR comments, automated code commits) and excessive API usage (GitHub has rate limits and overage costs).

Read tools are unrestricted:

```yaml
- resource: get_file_contents
  actions: [call]

- resource: list_branches
  actions: [call]

# ... and so on for all read tools
```

This is another default-allow ergonomic decision. Read tools on a code repository are low-risk — the agent can read what it needs to do its job. The interesting constraints are on write tools and search tools.

**Write tools: conservative hourly budgets.** The write tools have `maxCalls` conditions with generous-but-bounded hourly windows:

```yaml
- resource: create_issue
  actions: [call]
  conditions:
    - type: maxCalls
      count: 10
      windowSeconds: 3600

- resource: create_pull_request
  actions: [call]
  conditions:
    - type: maxCalls
      count: 5
      windowSeconds: 3600

- resource: create_or_update_file
  actions: [call]
  conditions:
    - type: maxCalls
      count: 20
      windowSeconds: 3600
```

The 3600-second (one-hour) window is chosen because GitHub rate limits are enforced hourly. The call counts are set conservatively — 5 PRs per hour is more than enough for any legitimate agent workflow but will stop a runaway automation that's creating a PR on every iteration of a loop.

The numbers here are starting points. A release automation agent might legitimately need more `create_or_update_file` calls. A code review agent might never need `create_issue`. Adjust to match your agent's actual usage pattern.

**Search tools: cost and API limit protection.**

```yaml
- resource: search_code
  actions: [call]
  conditions:
    - type: maxCalls
      count: 30
      windowSeconds: 60
```

Code and repository search are the most expensive GitHub API operations (both in terms of rate limits and in terms of the response sizes). The 30-per-minute limit provides reasonable throughput for a search-heavy agent while preventing a loop from exhausting your GitHub API rate limit and affecting other systems that depend on it.

**The important caveat about unlisted tools.** The GitHub policy comment includes an explicit warning that I want to repeat here: branch deletion, repository deletion, secrets management, and organization admin tools are all exposed by the GitHub MCP server and are **not** covered by this policy. They'll be allowed by default.

If your agent has any possibility of calling these tools — even accidentally through a clever prompt injection — you need to add explicit constraints. The cleanest way to block a specific dangerous tool while leaving everything else alone is to add a `timeWindow` condition in the distant future (so the condition always evaluates to "before the allowed window starts"), which will deny any call to that tool:

```yaml
- resource: delete_branch
  actions: [call]
  conditions:
    - type: timeWindow
      notBefore: "2099-01-01T00:00:00Z"  # intentionally unreachable — always denied
```

This is a somewhat unusual use of the `timeWindow` condition, but it produces the desired effect: the tool is listed in the policy with a condition that never passes, so calls to it are always denied.

---

## The Slack policy

**File**: `public/packages/mcp/policies/slack.policy.yaml`
**Upstream**: `@modelcontextprotocol/server-slack`

The Slack policy demonstrates two things that don't come up in the other policies: the `recipientDomain` condition and the limitations of what euno can enforce for addressing that uses non-email identifiers.

**Direct message restriction:**

```yaml
- resource: send_dm
  actions: [call]
  conditions:
    - type: recipientDomain
      domains: [company.com]
    - type: maxCalls
      count: 20
      windowSeconds: 3600
```

The `recipientDomain` condition checks the `to`, `recipients`, `cc`, and `bcc` argument fields (each can be a string or an array of strings). For `send_dm`, the target is typically an email address or a Slack user ID. When it's an email address, the domain check works as expected — it blocks direct messages to external addresses (potential data exfiltration via "send this sensitive document to attacker@external.com").

This is one of the primary threat vectors for AI agents with communication capabilities: an attacker embeds a hidden instruction in a document the agent processes, telling it to forward the document's contents to an external email. The `recipientDomain` condition is the policy-level defense against this. Without it, the only protection is the model's own judgment — which is explicitly not a security guarantee.

**Channel posting limitation:**

```yaml
- resource: post_message
  actions: [call]
  conditions:
    - type: maxCalls
      count: 50
      windowSeconds: 3600
```

`post_message` uses a Slack channel ID (e.g., `C12345678`) rather than an email address as its target. There's no domain concept for Slack channel IDs. This means `recipientDomain` is not applicable — euno can't tell from the channel ID whether the channel is internal or external.

This is a genuine limitation that the policy comment is explicit about: "Channel access control should be handled at the Slack workspace level or via a custom condition." If you need to restrict which channels the agent can post to, you'd need to write a custom condition that checks the channel ID against an allowlist, or configure Slack permissions to restrict the bot's access at the workspace level.

The 50-per-hour rate limit on `post_message` is a cost and noise guard, not a security control. It prevents an agent that's malfunctioned from flooding a channel with messages.

**Read tools:** `list_channels` is unrestricted. `get_channel_history` is limited to 100 calls per hour — mostly to prevent the agent from bulk-downloading the entire channel history of your workspace. `list_users` is unrestricted.

**What's not covered:** File uploads, channel creation and deletion, workspace admin operations, and user management are not listed in the policy. They're allowed by default. If your bot has admin-level permissions in your Slack workspace (a common mistake — many bots are over-provisioned), you should add explicit constraints for the admin tools.

---

## The fetch policy

**File**: `public/packages/mcp/policies/fetch.policy.yaml`
**Upstream**: `mcp-server-fetch` / `@modelcontextprotocol/server-fetch`

The fetch policy is the most technically interesting in the set, because the threat it's defending against — Server-Side Request Forgery (SSRF) — is inherently asymmetric with lexical policy enforcement.

The threat: an agent calls the `fetch` tool with a URL that reaches your cloud provider's metadata endpoint. On AWS, that's `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. A successful fetch returns your EC2 instance's IAM credentials. The attacker now has your cloud credentials. This is a real attack that has been used against real AI systems.

The reference policy's SSRF defense is lexical — it checks the URL string using a regex pattern:

```yaml
- resource: fetch
  actions: [call]
  argumentSchema:
    type: object
    properties:
      url:
        type: string
        pattern: "https://(?!(?:[^/]*@|localhost|127\\.|10\\.|192\\.168\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.)).*"
      method:
        type: string
        enum: [GET, HEAD, OPTIONS]
    required: [url]
    additionalProperties: false
  conditions:
    - type: maxCalls
      count: 60
      windowSeconds: 60
```

Let me break down what the regex is doing:

- `https://` — requires HTTPS. HTTP is rejected entirely. This is both a security measure (HTTPS provides confidentiality) and a practical one (the metadata endpoint uses HTTP, so HTTPS-only already blocks it).

- `(?!(?:[^/]*@|...))` — a negative lookahead that blocks several categories:
  - `[^/]*@` — blocks URLs with userinfo in the authority (e.g., `https://evil.com@169.254.169.254/`). This is a classic SSRF bypass technique: the browser/client parses the URL as having host `169.254.169.254` with userinfo `evil.com`, but an insecure parser treats the entire `evil.com@169.254.169.254` as the host. The regex blocks any URL with an `@` before the path separator.
  - `localhost` — blocks the literal hostname `localhost`.
  - `127\.` — blocks `127.x.x.x` (IPv4 loopback range).
  - `10\.` — blocks `10.x.x.x` (RFC 1918 Class A private range).
  - `192\.168\.` — blocks `192.168.x.x` (RFC 1918 Class C private range).
  - `172\.(?:1[6-9]|2[0-9]|3[01])\.` — blocks `172.16.x.x` through `172.31.x.x` (RFC 1918 Class B private range). The regex is careful about the second octet bounds.
  - `169\.254\.` — blocks `169.254.x.x` (link-local, including the cloud metadata endpoint `169.254.169.254`).

- **What else it blocks:** The method enum (`GET`, `HEAD`, `OPTIONS`) limits the agent to safe HTTP methods. POST, PUT, DELETE, PATCH are all rejected.

**The critical limitation to understand.** The policy comment is explicit about this and I want to repeat it clearly: this protection is **lexical**, not network-level. It matches the URL string. It does not perform DNS resolution.

This means DNS rebinding attacks bypass it. A hostname like `internal.legit-company.com` passes the regex check — it doesn't match any of the blocked patterns. But if `internal.legit-company.com` is configured in DNS to resolve to `169.254.169.254` (which an attacker can do if they control the DNS for `legit-company.com`), the fetch will succeed and reach the metadata endpoint.

For complete SSRF protection, combine this policy with network-level egress controls:
- Run the fetch MCP server in a container or VM that has firewall rules blocking outbound connections to the RFC 1918 ranges and `169.254.169.254`.
- Use a forward proxy that enforces these rules at the network level, not the application level.

The reference policy is the application-level defense. Network-level defense is a deployment concern, not a policy concern. Both layers are needed for meaningful SSRF protection.

---

## Common patterns across the reference policies

Having walked through all five, I want to highlight the patterns that appear across multiple policies and the reasoning behind them.

**`maxCalls` on write operations, never on read operations (mostly).** Every write tool has a rate limit. Most read tools don't. The asymmetry reflects the asymmetry of the harm: a runaway read loop is annoying (API costs, performance), but a runaway write loop is damaging (data corruption, spam, committed code). Rate-limit the operations that cause irreversible harm.

**`additionalProperties: false` on all `argumentSchema` objects.** Rejecting unexpected fields prevents certain bypass techniques and makes the policy behavior predictable. If you know exactly which fields the tool accepts, listing them explicitly with `additionalProperties: false` is cheap and makes the policy easier to audit.

**Conservative hourly windows for write tools on external services.** GitHub, Slack — any tool that affects an external service uses hourly windows rather than per-minute windows. This matches the rate-limit granularity of the external service and provides protection against patterns that would exhaust your quota over a session.

**Explicit comments on unlisted tools.** Every reference policy has a comment explaining which tools are intentionally left unconstrained. This is documentation for the operator who is adapting the policy — they should read those comments and decide whether the unlisted tools need constraints for their deployment.

---

## Adapting the reference policies

A few things to always do when adapting a reference policy:

1. **Change the `agentId`.** The reference policies use generic IDs like `postgres-read-agent`. Your deployment should have a specific, meaningful ID that will appear in every audit record.

2. **Bump the version.** Start at `0.1.0` and increment meaningfully when you change the policy.

3. **Update the `metadata.owner`.** Point to the team or individual who owns this agent's policy. When something goes wrong, you want to know who to call.

4. **Review every comment about unlisted tools.** For each MCP server, there are tools that the reference policy intentionally doesn't constrain. Decide whether those need constraints in your context.

5. **Run `euno-mcp validate` on your adapted policy.** Don't skip this step. The validator catches typos in condition type names, invalid regex patterns in `argumentSchema`, and structural errors. It's a cheap check that saves real debugging time.

6. **Run the agent in passthrough mode first.** As described in [post 20](./20-from-dev-to-prod-cli.md), start without a policy file and observe what tools the agent actually calls. Adapt the reference policy to reflect actual behavior, not assumed behavior. Agents often call tools that you wouldn't predict.

---

## A note on default-deny manifests

The five reference policies all use euno's default-allow model: unlisted tools are permitted. But for high-assurance deployments — a privileged agent with access to sensitive infrastructure, for instance — you might want default-deny behavior: only explicitly listed tools are allowed.

You can achieve this by adding a catch-all constraint that blocks everything not specifically listed. The cleanest way is a capability entry with a `timeWindow` condition set in the past:

```yaml
# Catch-all deny for unlisted tools — add this entry last in requiredCapabilities
# The resource wildcard is not supported; you'd need to enumerate each tool.
```

Actually, there's a design limitation here: the euno policy model doesn't have a catch-all wildcard at the resource level. If you need default-deny behavior for a specific set of tools, you need to enumerate them. This is intentional — catch-all wildcards are how policies become permissive over time ("just add `*`") without anyone noticing.

For default-deny, the pattern is: list every tool the server exposes in your manifest, with deny-by-condition constraints for the ones you don't want to allow, and permissive constraints for the ones you do. More verbose, but explicit.

---

## Keeping policies current as MCP servers update

MCP servers add new tools. When a server you're using ships a new version with new tools, those tools are unconstrained by your existing policy until you explicitly add entries for them.

Whether this matters depends on the tool. A new read-only introspection tool is probably fine to leave unconstrained. A new `delete_repository` tool in the GitHub server is not.

My recommendation: treat MCP server version updates the same way you'd treat dependency updates in your security posture — review the changelog, identify new tools, and update the policy before upgrading to production. The reference policies in the repo are updated to track the upstream server versions, so checking for policy updates alongside server updates is a reasonable workflow.

The `version` field in the policy manifest is there precisely for this kind of tracking. When you review and confirm that the server update doesn't require policy changes, bump the policy version anyway with a comment. That creates a clear audit trail showing that the update was reviewed.

---

*Previous: [post 21 — Operator tooling: kill switches, revocation, and SCIM provisioning](./21-operator-tooling.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

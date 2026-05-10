# euno Promotion Content

Promotion copy for the `@euno/mcp` launch. All copy is anchored to the
Stage 1 pitch: *"Add guardrails to any MCP server in 5 minutes. No
infrastructure required."* Tone is direct, developer-first. Avoid
capability-theory jargon in grassroots channels — lead with the concrete
failure mode the tool prevents.

---

## Hacker News

### Show HN

**Title:**
> Show HN: euno – stop your AI agent from dropping your database (MCP proxy, 5-min setup)

**Body:**

```
I built a proxy MCP server that sits between any MCP client (Claude Desktop,
Cursor, LangChain.js) and any upstream MCP server and blocks tool calls that
violate a policy you define. No backend, no cloud account — one npx command
and a YAML file.

The problem it solves: agents running against a filesystem or database MCP
server have no runtime enforcement. LangSmith and similar tools give you
observability *after* the call executes. euno stops the call *before* it
reaches the upstream server.

The install path for Claude Desktop or Cursor is literally replacing one line
in mcpServers config:

    // before
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/data"] }

    // after — same filesystem server, now with a policy wrapper
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@euno/mcp", "proxy", "--policy", "./euno.policy.yaml",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/data"]
    }

Example policy (YAML):

    tools:
      - name: query_db
        conditions:
          - type: allowedOperations
            operations: [SELECT]
      - name: write_file
        conditions:
          - type: allowedExtensions
            extensions: [.md, .txt]
          - type: maxCalls
            limit: 20
            window: 3600

One thing worth saying upfront: enforcement is on the arguments the agent
sent — not on what the upstream server does with them. If you own the
upstream server you can get stronger guarantees than a proxy alone provides.
The README says this plainly.

The audit log is jsonl, written to ~/.euno/audit.jsonl, OCSF-shaped, locally
HMAC-signed. Same format the enterprise gateway writes to SIEM — same schema,
different signer — so policies and records are portable if you ever move to the
hosted version.

Repo: https://github.com/edgeobs/euno
Package: @euno/mcp on GitHub Packages
```

---

### Ask HN (engagement / research)

**Title:**
> Ask HN: How are you enforcing guardrails on AI agent tool calls today?

**Body:**

```
Agents calling tools (file reads, SQL queries, API calls) in production is
becoming common, and I keep running into teams who've discovered the hard way
that agents will do exactly what you didn't intend if you let them.

Curious what people are actually doing: prompt engineering, LangSmith
tracing after the fact, sandboxed environments, something else? Is anyone
doing runtime enforcement — blocking the call before it reaches the backend?

I'm building something in this space (an MCP proxy that enforces typed
conditions before forwarding tool calls) and would love to understand what's
actually being used before I write more code.
```

---

### HN comment (drop into relevant threads)

*Use when threads appear about: MCP servers, Claude tool use, agent safety, LangChain.js, AI agent mistakes.*

```
We ran into this too. The solution we've been using is a proxy MCP server
(https://github.com/edgeobs/euno) — it intercepts tools/call before the
upstream server sees it and evaluates a typed policy (SELECT-only SQL, file
extension allowlists, per-session call limits, time windows). No backend
required; installs with npx and a YAML file.

It's not a perfect safety net — enforcement is on the arguments the agent
sent, not on what the DB does with them — but it's caught several cases where
the agent tried to run a mutation during a session that was supposed to be
read-only.
```

---

## Blog Posts

### Post 1 — Developer tutorial (primary distribution piece)

**Title:** How I stopped my LangChain agent from destroying my dev database

**Intended outlets:** personal blog / dev.to / Hashnode / Medium

---

Last week my LangChain.js agent, helpfully trying to "clean up old records
before running the analysis," issued a `DELETE FROM sessions WHERE
created_at < NOW() - INTERVAL '90 days'`. Against production. I had not told
it to do that.

I had told it to "summarize usage patterns from the sessions table."

Agents are not careful. They are literal. If the tool can do a thing, the
agent will eventually do that thing — usually at the worst possible time.

**The standard answer is wrong**

The go-to response is: add to the prompt. "Never run destructive queries."
"Only use SELECT." I've been adding these instructions for months. They work
until they don't. Prompt-level restrictions are soft constraints — the model
interprets them, and interpretation fails under the right conditions.

The right answer is to enforce at the boundary, not in the language model.

**What I'm using now**

[`@euno/mcp`](https://github.com/edgeobs/euno) is a proxy MCP server. It
sits between your MCP client and your upstream MCP server, intercepts every
`tools/call`, evaluates a policy file, and either forwards the call or returns
a structured denial — before the upstream server is ever contacted.

Setup is one `npx` command and a YAML file. No cloud account, no Redis, no
signing keys.

**Install**

```bash
npm config set @euno:registry https://npm.pkg.github.com
npm login --registry=https://npm.pkg.github.com
npm install -g @euno/mcp
# or use npx inline after the scoped registry is configured
```

**Policy file** (`euno.policy.yaml`):

```yaml
tools:
  - name: query_db
    conditions:
      - type: allowedOperations
        operations: [SELECT]
  - name: execute_query
    conditions:
      - type: allowedOperations
        operations: [SELECT]
      - type: allowedTables
        tables: [sessions, events, users]
      - type: maxCalls
        limit: 50
        window: 3600   # per hour
```

**For Claude Desktop or Cursor** — replace the upstream server command with
the proxy in `claude_desktop_config.json` (or Cursor's equivalent):

```jsonc
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--policy", "/home/you/euno.policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-postgres",
        "postgresql://localhost/mydb"
      ]
    }
  }
}
```

That's it. Restart the client. Every `tools/call` to the `postgres` server
now goes through the policy before the database sees it. The agent receives a
structured `CapabilityDenied` response if it tries to run a mutation.

**For LangChain.js** (HTTP mode):

```bash
npx -y @euno/mcp proxy \
  --transport http --port 7391 \
  --policy ./euno.policy.yaml \
  -- node ./my-mcp-server.js
```

Then point your LangChain `MultiServerMCPClient` at `http://localhost:7391`.

**Validating the policy**

```bash
npx @euno/mcp validate ./euno.policy.yaml
# exits 0 if valid, exits 1 with structured errors if not
```

**What it doesn't do**

Worth being clear about this: enforcement is on the arguments the agent
sends — not on what the database does with them. If you tell the agent to use
the `query_db` tool and it tries to run `DROP TABLE users`, the proxy blocks
it. But if your database has triggers or stored procedures that perform
mutations when a `SELECT` is run, those are outside the proxy's view.

For an upstream server you control, wrapping is a stronger guarantee than
proxying. The proxy is the right tool for upstream servers you don't own or
don't want to modify.

**The audit log**

Every call — allowed or denied — goes to `~/.euno/audit.jsonl`. OCSF-shaped,
locally HMAC-signed. You can `tail -f` it while your agent runs to watch
exactly what it's trying to do.

```jsonc
{
  "time": 1746590400,
  "activity_id": 6001,
  "tool": "query_db",
  "outcome": "denied",
  "denial_reason": "allowedOperations: DELETE not in [SELECT]",
  "session_id": "sess_abc123",
  "raw_args": { "query": "DELETE FROM sessions WHERE ..." }
}
```

**Why not just sandbox the database?**

You should do that too. Defense in depth. But sandbox setup is
infrastructure work; this is a five-minute policy file. Both have a place.

**Repo:** https://github.com/edgeobs/euno

---

### Post 2 — Explainer (MCP ecosystem / security audience)

**Title:** Runtime enforcement for MCP tool calls: how the proxy model works

**Intended outlets:** dev.to, personal blog, the modelcontextprotocol community

---

The Model Context Protocol (MCP) has become the dominant tool interface for
AI agents: Claude Desktop, Cursor, Windsurf, and most serious agent frameworks
support it. As MCP adoption grows, the question of *what happens when an agent
calls a tool it shouldn't* becomes an engineering problem, not just a prompt
engineering problem.

**The enforcement gap**

MCP defines a clean RPC interface: `tools/list` to discover tools,
`tools/call` to invoke them. It says nothing about authorisation. The
upstream server trusts whatever the client sends.

Today's common mitigations:

- **Prompt-level restrictions.** "Only use SELECT." Works until the model
  interprets the instruction differently than intended.
- **Post-hoc observability.** LangSmith, Helicone, and similar tools record
  what happened. Useful for debugging; not a guardrail.
- **Sandboxed infrastructure.** Run the upstream server against a read-only
  replica, a restricted DB user. Correct but requires infrastructure work per
  tool.

None of these intercepts the call *before* it executes.

**The proxy model**

A proxy MCP server implements the full MCP server interface, forwards
`tools/list` verbatim, but intercepts every `tools/call`:

```
Client → tools/call → Proxy (policy check) → Upstream MCP Server
                                ↓ denied
                       Client ← CapabilityDenied
                       (upstream never contacted)
```

The proxy is invisible to the client — it advertises the same tool schemas
as the upstream server. It is invisible to the upstream server — it forwards
calls with the original arguments. The policy evaluation happens entirely
within the proxy process.

**Transport: why stdio matters**

Most discussions of MCP proxy assume HTTP. But Claude Desktop and Cursor —
the most-used MCP clients — spawn MCP servers as **stdio child processes**.
A proxy that only speaks HTTP cannot intercept those calls. A useful MCP
proxy must support stdio-as-transport: the proxy is the command in
`mcpServers`, it spawns the real upstream as a child process, and pipes
JSON-RPC frames through itself.

**Condition types that matter at Stage 1**

Not every condition type is equally valuable at the local-proxy stage. The
ones that address the most common failures:

- `allowedOperations` — SQL verb allowlist. The single most important one.
  Stops mutations on a read-only session.
- `allowedTables` / `allowedExtensions` — structural argument validation.
  Prevents reads from tables or paths outside the agent's scope.
- `maxCalls` — per-session or per-window call count. Rate-limits runaway
  agents and agentic loops.
- `timeWindow` — `notBefore` / `notAfter`. Limits when a capability is valid.
  Useful for scheduled jobs.
- `argumentSchema` — a JSON Schema applied to the raw arguments. The most
  general form of structural validation.

**The audit log as a forward-compatible artifact**

If you're using a local proxy today and moving to a hosted gateway later,
the audit records should be the same shape. `@euno/mcp` writes OCSF-shaped
jsonl, locally HMAC-signed — the same format the enterprise gateway writes
to SIEM. The only thing that changes at the hosted tier is the signer and
the sink.

**References**

- `@euno/mcp`: https://github.com/edgeobs/euno
- MCP spec: https://spec.modelcontextprotocol.io
- OCSF: https://schema.ocsf.io

---

### Post 3 — Opinion piece (security / engineering leadership)

**Title:** Your AI agents need a reference monitor, not a bigger prompt

**Intended outlets:** blog, LinkedIn article, The New Stack / InfoQ style

---

Every few months I talk to an engineering team that has deployed an AI agent
to production and is now describing, in increasingly alarmed terms, something
the agent did that it definitely should not have done.

The pattern is consistent: the team added guardrails via prompting ("only
read, never write"), added logging after the fact, and assumed the model would
respect the instructions. It didn't — or it did, until the right input arrived.

**The fundamental problem with prompt-level enforcement**

Language models are not rule-following systems. They are next-token prediction
engines that, most of the time, produce outputs that look like they're
following rules. That's different from actually following rules. Under
adversarial prompts, sufficiently long context, unusual input patterns, or
a model update, the soft constraint fails.

Computer security resolved this class of problem decades ago: *enforce at the
boundary, not in the trust domain you're trying to protect*. The principle is
called a reference monitor. A reference monitor sits at the boundary of a
protected resource and enforces policy before any operation is permitted.
The model cannot bypass it because the monitor is not part of the model's
context.

**What a reference monitor looks like for MCP agents**

The Model Context Protocol gives us a clean boundary: `tools/call` is the
RPC that invokes a tool. A proxy MCP server that intercepts `tools/call` and
enforces a policy before forwarding to the upstream server is a reference
monitor for agent tool use.

The policy is code, not text. *"SELECT only"* is not a prompt instruction —
it is a typed condition (`allowedOperations: [SELECT]`) evaluated by a
deterministic enforcement function. The condition either passes or it doesn't.
There is no room for interpretation.

**The operational case**

Beyond the security argument, runtime enforcement is an operational control.
- You can kill a runaway agent mid-session without redeploying.
- You have a signed audit trail of every tool call, allowed or denied.
- You can enforce rate limits per agent without modifying the tool servers.
- You can constrain a new agent to a conservative capability set and expand
  it as you gain confidence — the same way you'd manage a new database user.

These are things you would want whether or not you were worried about security.

**Where to start**

[`@euno/mcp`](https://github.com/edgeobs/euno) is an open-source proxy MCP
server. `npx @euno/mcp proxy --policy ./euno.policy.yaml -- <your-mcp-server-command>`.
No infrastructure. Five minutes. One policy file.

It won't solve every agent safety problem. It will solve the class of problem
where the agent calls a tool with arguments that your policy explicitly
disallows. That's a large and important class.

---

## Social Media

### Twitter / X

**Launch thread:**

```
1/ I got tired of my AI agents doing things they definitely shouldn't be doing.
   Introducing @euno/mcp — a proxy MCP server that stops tool calls before
   they reach the upstream. 5-min setup. No infrastructure required. 🧵

2/ The problem: your agent running against a DB or filesystem MCP server will
   eventually run a query or write to a path it shouldn't. Prompting it not to
   is a soft constraint. Enforcement at the boundary is a hard one.

3/ @euno/mcp intercepts every tools/call and evaluates a typed policy:
   • allowedOperations: [SELECT]  ← no mutations, ever
   • allowedTables: [sessions, users]
   • maxCalls: 50 per hour
   • allowedExtensions: [.md, .txt]

4/ Works with stdio (Claude Desktop, Cursor) and HTTP (LangChain.js).
   For Claude Desktop: replace the upstream command in claude_desktop_config.json
   with the proxy. That's the full migration.

5/ Every call — allowed or denied — goes to ~/.euno/audit.jsonl.
   OCSF-shaped, locally HMAC-signed. Same format an enterprise SIEM expects;
   different signer.

6/ One thing to be honest about: enforcement is on arguments the agent sends,
   not on what the upstream does with them. If you own the upstream, wrapping
   gives stronger guarantees. The README says this upfront.

7/ Open source, Apache-2.0.
   npm: npx @euno/mcp proxy --policy ./euno.policy.yaml -- <your-mcp-server>
   Repo: https://github.com/edgeobs/euno
```

---

**Standalone tweet (high-signal, brief):**

```
Stop your AI agent from running DROP TABLE.

npx @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  -- npx @modelcontextprotocol/server-postgres $DATABASE_URL

5 minutes. No backend. Works with Claude Desktop, Cursor, LangChain.js.
https://github.com/edgeobs/euno
```

---

**Reply to "agent ate my database" stories:**

```
Classic. If you're using MCP, @euno/mcp is a proxy that evaluates
allowedOperations: [SELECT] before the DB server sees the call.
Not foolproof but stops the obvious cases: https://github.com/edgeobs/euno
```

---

### LinkedIn

**Article-style post:**

```
AI agents are going to production. Runtime enforcement isn't keeping pace.

Three weeks ago an agent I was testing — given a read-only analysis task —
issued a DELETE statement against a table with 90 days of session data. It
was trying to be helpful. The prompt said "summarize usage patterns." It
decided cleaning up old data was part of that.

I had told it not to run destructive queries. In the prompt.

Prompt-level restrictions are soft constraints. The model interprets them.
Interpretation fails. This is not a new problem — computer security has a
well-understood answer: enforce at the boundary, not inside the thing you're
trying to constrain.

For AI agents using the Model Context Protocol, the boundary is tools/call.

I've been building a proxy MCP server (@euno/mcp) that sits at that boundary:
it intercepts every tool call, evaluates a policy you define (SQL verb
allowlists, file extension restrictions, per-session call limits, argument
schemas), and either forwards the call or returns a structured denial —
before the upstream server is ever contacted.

Setup is one command and a YAML file. It works with Claude Desktop, Cursor,
and LangChain.js out of the box. Every call — allowed or denied — is logged
to a local audit file.

It's open source: https://github.com/edgeobs/euno

If you're deploying agents against databases, filesystems, or APIs and relying
on prompting to keep them in lane — I'd suggest adding a hard enforcement
layer before you find out the prompt wasn't enough.
```

---

### Reddit

**r/LocalLLaMA post:**

**Title:** Built a proxy MCP server that enforces typed guardrails on tool calls — stops the agent before it reaches the upstream

**Body:**

```
Background: I kept running into the same problem — agents with legitimate
access to a database MCP server eventually run something they shouldn't. "Only
use SELECT" in the system prompt works most of the time. It doesn't work all
of the time.

What I built: a proxy MCP server (npx @euno/mcp) that sits between any MCP
client (Claude Desktop, Cursor, LangChain.js) and any upstream MCP server. It
intercepts tools/call and evaluates a typed policy before forwarding:

    tools:
      - name: query_db
        conditions:
          - type: allowedOperations
            operations: [SELECT]
          - type: allowedTables
            tables: [sessions, events, users]
          - type: maxCalls
            limit: 50
            window: 3600

If the call doesn't match the policy, the agent gets a structured denial and
the upstream never sees the request.

For Claude Desktop: replace the upstream in claude_desktop_config.json with
the proxy command. Restart Claude. Done.

One honest caveat: this enforces on arguments the agent sent — not on what the
upstream does with them. If your DB has side-effecting triggers on SELECT that
shouldn't run, that's outside the proxy's view. For things you own, wrapping
is a stronger option.

Audit log: ~/.euno/audit.jsonl. Every call, allowed or denied, OCSF-shaped,
locally HMAC-signed.

Repo: https://github.com/edgeobs/euno
GitHub Packages: @euno/mcp (Apache-2.0, no cloud account needed)

Happy to answer questions about how the enforcement model works.
```

---

**r/MachineLearning comment (drop into relevant threads):**

```
For anyone running MCP-based agents against real data: npx @euno/mcp wraps
any MCP server and enforces typed conditions (SQL allowlists, path
restrictions, call rate limits) on tools/call before forwarding. Local, no
backend, Apache-2.0. https://github.com/edgeobs/euno
```

---

### Discord / Slack

*Drop into: LangChain Discord #tools-and-integrations, MCP community Discord, relevant Slack workspaces*

**Short drop:**

```
For folks running agents against MCP servers — just published @euno/mcp, a
proxy that enforces typed policy (allowedOperations, allowedTables,
allowedExtensions, maxCalls) on tools/call before forwarding to upstream.
Works as a stdio wrapper for Claude Desktop/Cursor or in HTTP mode for
LangChain.js. No backend needed. https://github.com/edgeobs/euno
```

**Longer drop with context:**

```
Hey — wanted to share something I've been building that might be useful here.

@euno/mcp is a proxy MCP server. You put it between your client
(Claude Desktop, Cursor, LangChain) and your upstream MCP server. It
intercepts every tools/call, evaluates a policy file you write in YAML, and
either forwards or returns a denial — before the upstream sees anything.

Policy looks like:

    tools:
      - name: query_db
        conditions:
          - type: allowedOperations
            operations: [SELECT]

For Claude Desktop it's replacing one line in claude_desktop_config.json.
For LangChain it's running it in --transport http mode and pointing your
client at localhost.

Honest about the limits: enforcement is on what the agent sent, not on what
the DB does with it. But for the "agent ran a mutation during what was supposed
to be a read-only session" class of problem, it works well.

Open source (Apache-2.0): https://github.com/edgeobs/euno
```

---

## Community Placement

### modelcontextprotocol/servers README PR

Add to the "Proxy / gateway" section of the MCP servers list:

```markdown
- **[euno MCP Proxy](https://github.com/edgeobs/euno)** (`@euno/mcp`) —
  Policy-enforcing proxy. Intercepts `tools/call`, evaluates typed conditions
  (SQL verb allowlists, path restrictions, call rate limits, argument schemas),
  and returns a structured denial before the upstream server is contacted.
  Stdio and HTTP transports. Apache-2.0.
```

### awesome-mcp-servers (if it exists)

```markdown
- [edgeobs/euno](https://github.com/edgeobs/euno) — Runtime enforcement
  proxy for MCP tool calls. Typed policy engine (allowedOperations, allowedTables,
  maxCalls, argumentSchema), local audit log, stdio + HTTP transports.
```

---

## Messaging Consistency Reference

Use these consistently across all channels. Do not deviate into architecture
language in grassroots channels.

| Do say | Don't say |
|---|---|
| "stop your agent from dropping your database" | "capability-based zero-trust governance" |
| "typed conditions enforced before the upstream sees the call" | "CapabilityCondition discriminated union" |
| "policy file" | "AgentCapabilityManifest" |
| "guardrails" / "enforcement" | "reference monitor" (fine in long-form; too jargon-y elsewhere) |
| "works with Claude Desktop, Cursor, LangChain.js" | "MCP-compatible client runtime" |
| "no cloud account needed" | "local in-memory backend" |
| "audit log at ~/.euno/audit.jsonl" | "OCSF-shaped jsonl evidence stream" |
| "5-minute setup" | "sub-millisecond enforcement overhead" |

**The one sentence that opens every piece:** *"Add guardrails to any MCP
server in 5 minutes. No infrastructure required."*

**The one honest caveat that must appear in every technical piece:** enforcement
is on the arguments the agent sends — not on what the upstream server does with
them.

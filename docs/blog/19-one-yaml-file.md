# One YAML File: The Design Philosophy Behind euno's Policy Format

*First post in the "User experience and developer ergonomics" series. [Post 16](./16-schema-parity-over-version-drift.md) in the "Design principles" series explains why the schema behind this YAML is defined exactly once and shared by every component that processes it. [Post 10](./10-tool-gateway-pdp.md) covers the enforcement engine that reads these files at runtime. This post is about the deliberate design choices in the format itself — why it looks the way it does, and what that makes possible for the teams writing and reviewing it. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

Every time I demo euno to a new team, the thing that gets the most comments is not the gateway, not the cryptographic audit chain, not the DID federation. It's the YAML file.

Not because it's clever. Because it's boring. It's just a YAML file. You open it in VS Code. You can read it without a decoder ring. You can diff two versions. You can put it in pull request review. You can copy it into a Confluence doc and your security team will understand what it says.

That boringness is the design. This post is about the choices that went into it.

---

## The problem with "policy as code"

When we first started thinking about how operators would express what an AI agent is allowed to do, the obvious solution was policy as code. You write a TypeScript or Python function that takes a tool call as input and returns allow/deny. It's flexible. It's testable. It's familiar to the developers who'll be writing it.

We built a prototype along those lines and demoed it internally. The reaction from the security team was immediate and not in our favour: "So I need to run a code review on every policy change?" One of our security architects put it well: "The whole point of separating policy from code is so the policy doesn't need to be in a code review."

That exchange clarified something important. The audience for an AI agent's policy is not just the developer who wrote the agent. It's the security team that approved the agent for production. It's the compliance team auditing what the agent was permitted to do. It's the incident responder trying to understand what happened in a specific session three months ago. These people have different skills, different tools, and different tolerances for abstraction.

A YAML file that says `allowedOperations: [SELECT, EXPLAIN, SHOW]` communicates something to all of those audiences. A TypeScript function that implements the same check communicates it clearly only to the first audience.

---

## The manifest structure

The capability manifest is a YAML (or JSON) document that validates against the `AgentCapabilityManifest` type in `@euno/common-core`. The required fields at the top level are:

```yaml
agentId: "sales-research-bot"       # stable, kebab-case, machine-readable identifier
name: "Sales Research Bot"          # human-readable display name
version: "0.1.0"                    # semver — bump this when the manifest changes
requiredCapabilities: []            # the actual policy — what this agent can do
```

Then the optional fields:

```yaml
optionalCapabilities: []            # capabilities the agent will use if available
metadata:
  description: "Synthesizes account-research briefings."
  owner: "revops-oncall@example.com"
  tags: ["revops", "research"]
  runtime: "node:20"
```

The `agentId` field is worth pausing on. It's a stable, machine-readable identifier for the agent, not a human display name. It's the identifier that appears in every audit record for sessions running under this manifest. When something goes wrong, your incident response team will be correlating `agentId` values across the audit trail. Make it meaningful but also stable — changing it mid-deployment breaks that audit correlation.

The `version` field solves a subtle problem: if you change the policy and forget to bump the version, you can't tell from the audit record which policy was in effect for a given session. We enforce that deployed tokens carry the manifest's `version` in their JWT payload. If you need to know "what policy was this session running under?", the answer is in the token and in the audit record — a specific version string that maps to a specific commit in your git history.

---

## One capability entry is one enforcement unit

The `requiredCapabilities` array is a list of capability constraints. Each entry says: "for this resource, these actions are permitted, subject to these conditions."

```yaml
requiredCapabilities:
  - resource: "api://crm/customers/*"
    actions: ["read"]
    conditions:
      - type: maxCalls
        count: 200
        windowSeconds: 60
```

The `resource` field is a URI pattern with segment-aware wildcard semantics. `api://crm/customers/*` matches any single-segment child of `customers` — customer IDs like `123`, `abc` — but not paths with additional depth like `customers/123/notes`. If you need recursive depth, use `/**`. If you specify the exact path, use it exactly. The validator will reject patterns that are obviously too broad (bare `*` with no scheme).

The `actions` field is a list of action types. The built-in vocabulary is `read`, `write`, `execute`, `delete`, `admin`, but the system supports resource-specific verbs like `db:select` or `s3:putObject` if you need finer granularity. In the MCP server context, where tools don't naturally map to these verbs, the common pattern is simply `["call"]` — this tool is callable.

The `conditions` array narrows what an otherwise-permitted action is allowed to do. Conditions are a typed discriminated union — every entry has a `type` discriminator that tells the enforcement engine which handler to invoke. There's no "untyped" or "custom" condition that silently passes; unknown condition types are rejected at both policy validation and enforcement time.

---

## The eight built-in condition types

The conditions that ship with euno cover the situations that come up repeatedly across real deployments. I'll describe each one with the concrete scenario it solves.

**`maxCalls`** — rate limiting. This is the most widely used condition. An agent with `count: 100, windowSeconds: 60` can make at most 100 calls to this resource in any 60-second window. The window is sliding, not fixed. The counter is per-session in local mode, or per-tenant across all sessions in hosted mode (backed by a distributed Redis counter). See [post 26](./26-redis-enforcement-substrate.md) for how that distributed counter works.

```yaml
- type: maxCalls
  count: 100
  windowSeconds: 60
```

**`timeWindow`** — temporal constraints. Good for project-scoped agents that should only operate during a specific sprint, or campaign-scoped agents that should expire at the end of the campaign. The token itself also has a TTL; the `timeWindow` condition provides an additional declarative constraint that's visible in the manifest rather than buried in the issuer configuration.

```yaml
- type: timeWindow
  notBefore: "2026-04-01T00:00:00Z"
  notAfter:  "2026-12-31T23:59:59Z"
```

**`ipRange`** — source IP allowlist. Useful when your agent runs from a known infrastructure range. In HTTP proxy mode, works with `--trust-forwarded-for` when a reverse proxy sits in front of euno. In production, this should be a backup defense, not your primary access control — but it adds meaningful defense in depth.

```yaml
- type: ipRange
  cidrs: ["10.0.0.0/8", "192.168.1.0/24"]
```

**`allowedOperations`** — command verb restriction. Designed for database tools but applicable to any resource where the model passes a command as an argument. The enforcement engine extracts the first whitespace-delimited token from the `sql`, `query`, or `statement` field, uppercases it, and checks it against the list. [Post 18](./18-defense-in-depth-sql-injection.md) covers why this is necessary and what it can and can't catch.

```yaml
- type: allowedOperations
  operations: [SELECT, EXPLAIN, SHOW]
```

**`allowedExtensions`** — file extension allowlist. Applies to any tool call that includes a file path argument. The enforcement engine recognizes common argument key names (`path`, `filename`, `file`, `filepath`) and extracts the extension using standard path semantics. Use this to prevent an agent from writing `.sh`, `.exe`, `.so`, or any other executable format.

```yaml
- type: allowedExtensions
  extensions: [.txt, .md, .json, .csv, .yaml, .yml]
```

**`allowedTables`** — table-level SQL restriction. Works alongside `allowedOperations` to narrow database access to specific tables. The enforcement engine parses simple FROM clauses and table references from the SQL. It's not a full SQL parser — multi-table joins with complex aliases will degrade gracefully to `unknown table` and be denied. That's the correct failure mode for the ambiguous case.

```yaml
- type: allowedTables
  tables: [orders, products, customers, inventory, catalog]
```

**`recipientDomain`** — outbound communication domain allowlist. Applies when an agent can send messages or emails. Prevents an agent from exfiltrating data by sending it to an external address that isn't in your approved list. The field under examination is the `to`, `recipient`, `email`, or `address` argument key.

```yaml
- type: recipientDomain
  domains: ["company.com"]
```

**`redactFields`** — field-level redaction obligations. Rather than denying the call, this condition tells the enforcement engine to record a redaction obligation in the audit entry. The obligation is carried through to the gateway's response envelope and to the audit log. It's the mechanism for implementing "the agent can query customer data but the PII fields must be masked before the LLM receives them." [Post 10](./10-tool-gateway-pdp.md) explains how obligations flow through the enforcement pipeline.

```yaml
- type: redactFields
  fields: ["customers.email", "customers.ssn"]
```

---

## The `argumentSchema` field

Beyond conditions, each capability entry supports an `argumentSchema` field. This is a subset of JSON Schema applied to the raw argument object of the tool call. It gives you structural validation of the arguments themselves.

The most common use case is path confinement:

```yaml
- resource: write_file
  actions: [call]
  argumentSchema:
    type: object
    properties:
      path:
        type: string
        pattern: "/data/.*"
      content:
        type: string
    required: [path, content]
    additionalProperties: false
```

This says: the `write_file` tool call must have `path` and `content` fields, `path` must match the `/data/.*` pattern, and no additional fields are allowed. The `additionalProperties: false` is significant — it means the enforcement engine rejects calls with unexpected argument shapes, which prevents certain prompt-injection bypass patterns that rely on overloading argument keys.

The `pattern` field uses JavaScript regex semantics. The argument validator wraps the pattern with `^(?:...)$` so it always tests the entire field value, not just a substring. This means `/data/.*` will match `/data/foo.txt` but not `/etc/passwd` (which doesn't start with `/data/`).

The combination of `argumentSchema` path confinement and `allowedExtensions` conditions gives you layered protection: path confinement ensures the location, extension allowlist ensures the file type. Both must pass for the call to proceed.

---

## What "shareable between developers and security teams" actually means

The promise I made at the start — that this format is shareable between the agent developer and the security team — requires a bit of elaboration, because the two audiences read the same YAML very differently.

The agent developer reads it as a specification of the tools their agent can use. "I need `read` on the CRM customer records with a 200 calls-per-minute limit." They write the manifest to describe what the agent needs to work. The conditions are constraints they accept in order to get production access.

The security team reads it as a description of what the agent is permitted to do. "This agent can read customer records but can't write them. It's rate-limited to prevent bulk extraction. The `redactFields` condition means the audit log will record when it accessed PII." They approve or deny the manifest based on whether the described capabilities are appropriate.

The critical thing is that both audiences are reading the same document and their readings of it correspond. There's no "implementation detail" layer that the security team is trusting the developer to get right — the YAML is the policy, and the enforcement engine implements exactly what the YAML describes, using the shared code from `@euno/common-core` ([post 16](./16-schema-parity-over-version-drift.md)).

This also means the YAML can live in source control alongside the agent code, with the same review processes. Security teams can review manifest changes in pull requests. Compliance teams can audit the git history of the manifest to understand what the agent was permitted to do at any point in time. The answer to "what was this agent allowed to do on March 15th?" is the commit in git that was deployed on March 15th.

---

## Version controlling your policy is non-optional

I want to be direct about this: if your policy manifest isn't in version control, your governance story has a hole in it.

The audit log (covered in [post 11](./11-tamper-evident-audit-logs.md)) records which `agentId` and manifest `version` was in effect for each session. That's useful for forensics and compliance. But it's only useful if you can look up version `0.3.1` in your git history and see exactly what that version permitted. If the YAML is living in a shared S3 bucket or in a database without change tracking, you've lost the ability to answer "what was this agent allowed to do?" with any confidence.

The intended workflow is:
1. Developer writes or modifies `euno.policy.yaml` in the agent's repo.
2. PR is submitted. Security team reviews the diff.
3. On merge and deploy, the manifest is loaded by `euno-mcp proxy --policy ./euno.policy.yaml` (local mode) or uploaded to the hosted policy store (hosted mode). Either way, the `version` field in the file records which commit this corresponds to.

This is different from the traditional "policy database" approach where policies are rows in a table updated by an admin console. Tables are hard to diff and review. The YAML-in-git approach makes the policy as reviewable and auditable as the code itself.

---

## The authoring guide and common patterns

The [`CAPABILITY_MANIFEST_GUIDE.md`](../CAPABILITY_MANIFEST_GUIDE.md) in the docs is the canonical authoring reference, and it's worth reading if you're writing your first manifest. But here are the patterns I see most often in real deployments:

**Pattern A: read-only research agent.** Just `read` actions, resources scoped to specific paths with `/*`, no write capabilities. The most common type. The security approval conversation is usually: "yes, this agent can read these resources."

**Pattern B: workflow agent with narrow write.** Reads broadly but writes back to exactly one specific path. The write resource is usually a strict child path of the read resource. The security conversation focuses on the write path: "why does this agent need to write here? What's the blast radius if it writes garbage?"

**Pattern C: tool-specialist agent.** Calls one internal RPC endpoint heavily. The interesting part is the conditions layer — you'd typically have `maxCalls` to prevent runaway loops, possibly `allowedOperations` if the tool takes a command argument.

**Pattern D: delegated child agent.** A parent agent spins up a child with a strictly smaller capability set via the `/api/v1/attenuate` endpoint. The child token's capabilities are guaranteed to be a subset of the parent's by the issuer — it's not a convention, it's a cryptographic guarantee. [Post 9](./09-capability-tokens.md) covers the attenuation chain mechanics.

---

## What happens when the YAML is wrong

I want to address the failure modes because understanding them makes you a better policy author.

If the YAML fails schema validation, `euno-mcp proxy` exits immediately with a clear error message — it will not start in an unknown state. The error messages from the validator are designed to be human-readable: "Required field 'actions' missing from capability at index 2" rather than a raw Zod error.

If a condition type is unrecognized, the manifest validation fails. There's no "soft ignore" path. If you spell `allowedOpetations` (note the typo), the validator tells you `"allowedOpetations" is not a recognized condition type` and exits. The fail-closed principle from [post 15](./15-fail-closed-not-fail-open.md) applies to policy authoring as well as runtime enforcement: a malformed policy doesn't produce a permissive agent, it produces a non-starting agent.

If the `argumentSchema` pattern is invalid regex, validation fails at startup. If the `cidrs` in an `ipRange` condition contains an invalid CIDR notation, validation fails at startup. The goal is that every error that can be caught at policy load time is caught at policy load time, not discovered when an agent hits a specific tool call in production.

---

## The thing I hear most often

When I talk to teams that have deployed euno, the feedback I hear most consistently is: "we were surprised how quickly the security team got comfortable reviewing it."

That's what the format was designed to produce. Not a document that security teams rubber-stamp because they can't read it. A document they can actually reason about. One that makes the approval conversation productive rather than ceremonial.

The YAML file is boring on purpose. Boring is what scales.

---

*Previous: [post 18 — Defense-in-depth for SQL injection through an LLM](./18-defense-in-depth-sql-injection.md). Next: [post 20 — From dev to prod: the euno CLI experience](./20-from-dev-to-prod-cli.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

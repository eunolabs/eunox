# Capability Manifest Guide

> Patterns for writing capability manifests that work the first time
> and age well. This guide is the canonical companion to
> `eunox-mcp validate` in `cmd/mcp/`.

A **capability manifest** is the YAML file you pass to the proxy via
`--policy manifest.yaml`. The proxy loads it at startup and checks
every `tools/call` against it before forwarding.
The manifest is therefore the **single source of authority** for what
an agent can do — get it right and the rest of the system enforces it
mechanically.

## 1. Required structure

The required top-level fields are `name`, `version`, and `capabilities`.
Optional fields are `description`, `defaultTtl`, and `audience`.
Anything missing or shaped differently is rejected by `eunox-mcp validate`.

```yaml
name: "Sales Research Bot" # human-readable, unique per logical agent
version: "0.1.0"           # semver; recorded in every audit log entry
capabilities: []           # see § 2 — each entry is a capability constraint
description: "Synthesizes account-research briefings." # optional
defaultTtl: 600            # informational only — not enforced by the proxy
audience: "eunox"          # optional; used in JWT-intersection mode
```

The `defaultTtl` and `audience` fields are informational in the proxy —
JWT expiry is enforced by your IdP, not by eunox-mcp. See § 5 for TTL
guidance.

## 2. How enforcement works

Before writing a manifest, understand what the proxy actually checks.

**Resource** — matched against the MCP tool name.

Every `tools/call` request carries a `name` field (e.g. `read_file`,
`query_db`, `get_customer`). The proxy matches that string against each
capability entry's `resource` field using `path.Match` glob semantics.
There are no resource URIs, paths, or URLs in the MCP protocol — only
tool names. `resource: "get_*"` matches any tool whose name starts with
`get_`; `resource: read_file` matches only the tool named `read_file`
exactly.

**Actions** — use `[call]`.

Once a matching capability is found, the proxy checks whether the call
is permitted by the `actions` list.

```yaml
actions: [call]   # ← use this
```

`[call]` permits any `tools/call` for the matched resource, regardless
of tool name. It is explicit, deterministic, and what all the examples
in this guide use.

**Avoid semantic action categories (`[read]`, `[write]`, …).**

The proxy also supports semantic action categories that are matched by
classifying the tool name using a prefix heuristic (`get_*` → read,
`create_*` → write, etc.). This sounds convenient but has the same
failure mode as over-broad resource globs: a new tool added to the
server that happens to match a prefix is silently permitted without
any operator review. For example:

```yaml
# FRAGILE: any new tool whose name starts with "get_" is permitted,
# including a future "get_admin_credentials" tool you never reviewed.
- resource: "get_*"
  actions: [read]   # ← heuristic; avoid
```

If you genuinely need to restrict a group of tools to a specific verb
category, use a **static action map** (an explicit `tool → category`
file loaded via `--action-map`) rather than relying on the name-prefix
heuristic. The heuristic is documented in `cmd/mcp/resolver.go` for
reference; do not rely on it in production policy.

## 3. The capability list — four common patterns

### Pattern A — Single-purpose read agent

> _"This agent looks things up and reports. It never writes anywhere."_

```yaml
capabilities:
  - resource: "get_*"       # matches get_customer, get_invoice, get_report …
    actions: [call]
  - resource: "list_*"      # matches list_customers, list_orders …
    actions: [call]
  - resource: "search_*"    # matches search_products, search_tickets …
    actions: [call]
```

- Use `actions: [call]` — it is unconditional for any matched tool.
- Scope each resource glob to one verb prefix. Do not write
  `resource: "*"` (rejected by `eunox-mcp validate`) or
  `resource: "get_or_list_*"` (not how glob patterns work).
- If the agent should only call a small fixed set of tools, list them
  individually rather than using a prefix glob — narrow is always safer.

  ```yaml
  capabilities:
    - resource: get_customer
      actions: [call]
    - resource: list_orders
      actions: [call]
  ```

### Pattern B — Workflow agent (read-many, narrow write)

> _"This agent reads broadly but writes to exactly one tool."_

```yaml
capabilities:
  - resource: "get_*"           # reads — broad
    actions: [call]
  - resource: "list_*"          # reads — broad
    actions: [call]
  - resource: add_customer_note # single permitted write tool — explicit
    actions: [call]
  # create_*, update_*, delete_* are absent → denied by default
```

- There are no resource paths in MCP — you control access by
  **naming the write tools explicitly**, not by restricting to a path prefix.
- Never add a write tool "just in case it's needed later".
  Every write capability you add is blast radius.
- If the agent genuinely needs several write tools, list each one
  individually rather than widening to `"create_*"` or `"*"`.

### Pattern C — Tool-specialist agent

> _"This agent calls one specific tool many times, with argument constraints."_

```yaml
capabilities:
  - resource: run_forecast      # exact tool name
    actions: [call]
    conditions:
      - type: maxCalls           # at most 30 calls per minute
        count: 30
        windowSeconds: 60
      - type: allowedOperations  # narrow the operation verb further
        operations: ["predict"]
```

- Use the exact tool name, not a glob — you want this constraint to
  apply to precisely one tool.
- Apply typed conditions to constrain arguments and rate. Each condition
  is one of the typed shapes in `pkg/capability/condition.go`.
- See § 4 for the full condition type reference.

### Pattern D — JWT-scoped agent (manifest + IdP intersection)

> _"A per-task JWT narrows what this invocation can do within the
> broader manifest."_

```yaml
# manifest.yaml — broadest policy the system ever permits
capabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*"]
  - resource: query_db
    actions: [call]
```

The IdP then issues a JWT carrying a narrower `eunox.capabilities` claim:

```json
{
  "eunox.capabilities": ["read_file:/reports/q3.pdf"],
  "eunox.agent_id": "summariser-run-42",
  "eunox.task_id": "briefing-2026-05-31"
}
```

The proxy takes the **intersection**: the JWT can only restrict, never
expand beyond what the manifest permits. `query_db` is denied for this
invocation even though the manifest allows it.

- Start the proxy in JWT mode: `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox --policy manifest.yaml`
- The audit log records `agent_id` and `task_id` from the JWT automatically.

## 4. Resource pattern reference

The `resource` field is matched against the MCP **tool name** using
`path.Match`. Because tool names rarely contain `/`, the `*` wildcard
effectively matches any suffix within a single naming segment.

| Pattern | Matches | Does **not** match |
|---|---|---|
| `get_customer` | `get_customer` only | `get_customers`, `get_customer_by_id` |
| `get_*` | `get_customer`, `get_invoice`, `get_report` | `list_customers`, `create_customer` |
| `*_report` | `get_report`, `create_report`, `delete_report` | `report_get`, `reports` |
| `read_file` | `read_file` only | `read_files`, `read_file_metadata` |
| `*` | (rejected by `eunox-mcp validate`) | — |

Rules:

- **Match is against the tool name string.** There are no resource URIs,
  HTTP paths, or URL schemes in the MCP protocol.
- **`*` matches any characters except `/`.** Since most tool names do not
  contain `/`, this is effectively a substring wildcard, but it will not
  span a `/` if one appears.
- **Multi-segment wildcards (`**`) are not supported.** `path.Match`
  treats `**` identically to `*`.
- **Bare `*` is rejected** by `eunox-mcp validate`. Use named tools or
  specific prefix globs instead.
- **Most-specific match wins.** If two entries both match a tool name,
  the one with the higher specificity score (exact > no-wildcard prefix >
  shorter wildcard) is used.

## 5. Conditions cookbook

`conditions` is an array of typed shapes from
`pkg/capability/condition.go`. Every entry has a `type` discriminator.
Unknown types are denied at the proxy, so spelling matters.

```yaml
# Rate-limit, time-window, and IP-allowlist on a reporting tool
- resource: get_invoice
  actions: [call]
  conditions:
    - type: maxCalls        # at most 60 calls per minute
      count: 60
      windowSeconds: 60
    - type: timeWindow      # restrict to a fiscal-year window
      notBefore: "2026-04-01T00:00:00Z"
      notAfter: "2026-12-31T23:59:59Z"
    - type: ipRange         # internal network only
      cidrs: ["10.0.0.0/8"]

# Restrict file exports to safe types
- resource: export_data
  actions: [call]
  conditions:
    - type: allowedExtensions
      extensions: [".csv", ".json"]

# Database query tool: restrict tables and redact a column
- resource: query_sales
  actions: [call]
  conditions:
    - type: allowedTables
      tables: ["sales"]
      columns:
        sales: ["customer_id", "amount", "ts"]
    - type: redactFields       # proxy strips this field from the result
      fields: ["sales.customer_email"]

# Email tool: allowlist recipient domains
- resource: send_email
  actions: [call]
  conditions:
    - type: recipientDomain
      domains: ["example.com"]
```

The full list of shipped condition types: `timeWindow`, `ipRange`,
`allowedOperations`, `allowedExtensions`, `allowedTables`, `maxCalls`,
`recipientDomain`, `redactFields`, `allowedValues`, `policy`,
and the `custom` escape hatch (requires the named handler to be
registered via `RegisterCondition`).

**`allowedValues`** — restricts a named tool argument to a set of allowed
literal values or glob patterns:

```yaml
- resource: read_file
  actions: [call]
  conditions:
    - type: allowedValues   # restrict the path argument
      argument: path
      values: ["/reports/*", "/public/*"]
```

The `argument` field names the tool parameter to check; `values` is a
list of exact strings or `*`-glob patterns (e.g. `/reports/*` matches
`/reports/q3.pdf`).

**`allowedOperations`** — restricts the SQL verb or operation keyword
extracted from a tool argument named `sql`, `query`, or `statement`:

```yaml
- resource: query_db
  actions: [call]
  conditions:
    - type: allowedOperations
      operations: ["SELECT"]   # blocks INSERT, UPDATE, DELETE, DROP, …
```

**`policy`** — delegates the allow/deny decision to an external policy
decision point (e.g. OPA, Cedar) registered via `WithPolicyEvaluator`:

```yaml
- resource: query_db
  actions: [call]
  conditions:
    - type: policy
      backend: opa          # name passed to your registered PolicyEvaluator
      config:               # optional backend-specific config
        query: "data.authz.allow"
      input:                # optional extra input merged with the request
        env: production
```

The proxy calls `PolicyEvaluator.Evaluate(ctx, backend, config, input, req)`.
When no evaluator is wired (the default), any `policy` condition is
denied fail-closed. Use this for logic that cannot be expressed with
the other typed conditions.

> If a condition type you need does not exist, **add a new typed shape
> to `pkg/capability/condition.go` first**, register its handler in
> `pkg/enforcement/handlers.go`, and ship a test.
> Unknown condition types are denied at the proxy — that is the correct
> behaviour, but a regression for the manifest author if they forget to
> register the handler.

## 6. TTL guidance

In JWT mode, token lifetime is controlled by the `exp` claim your IdP
stamps on the JWT — eunox-mcp validates and rejects expired tokens but
does not issue them. The `defaultTtl` manifest field is informational
and available for your tooling to read; the proxy does not enforce it.

| Scenario                                | Recommended JWT TTL (seconds) |
| --------------------------------------- | ----------------------------- |
| Interactive chat / tool call            | 900 (15 min)                  |
| Long-running batch (ETL, embedding job) | 1800–3600                     |
| Task-scoped sub-invocation              | 60–300                        |
| Anything that touches money or PII      | 300                           |

Configure short TTLs in your IdP client settings; request a fresh
token per task rather than re-using a long-lived one.

## 7. Anti-patterns to avoid

These all _work_ (token issued, proxy happy) but each one silently
degrades the security posture.

1. **Manifest copied between agents** with `name` not changed.
   Audit logs lose attribution clarity. Use a unique manifest `name` per logical
   agent, not per pod / replica.
2. **Over-broad resource globs** "for development". Configure dev
   manifests with realistic scopes from day one — a manifest that is
   too wide in development tends to stay that way in production.
3. **Adding tools the agent doesn't currently need.** List only what
   the agent actually calls. Over-broad manifests silently widen the
   blast radius of a prompt-injection or supply-chain compromise.
4. **One manifest shared across every environment.** Use a separate
   manifest per environment (`dev`, `staging`, `prod`) with
   progressively tighter conditions — the `name`/`version` fields make
   this traceable in the audit log.
5. **Long-lived JWTs re-used across tasks.** Request a fresh token
   per task and keep TTLs short; the audit log records `task_id` from
   the JWT so attribution is preserved without needing long-lived tokens.

## 8. Tooling

| Step                                          | CLI command                                          |
| --------------------------------------------- | ---------------------------------------------------- |
| Validate a manifest file                      | `eunox-mcp validate ./manifest.yaml`                 |
| Validate multiple manifests at once           | `eunox-mcp validate ./a.yaml ./b.yaml`               |
| Start the proxy (manifest-only mode)          | `eunox-mcp proxy --policy manifest.yaml --transport http --upstream-url <url>` |
| Start the proxy (JWT + manifest intersection) | add `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox` |
| Start the proxy with drift enforcement        | add `--strict-drift` (aborts session on FM-1/FM-2)   |
| Verify HMAC signatures in the audit log       | `eunox-mcp validate-token --audit-log audit.jsonl --audit-key-path audit.key` |

Wire `eunox-mcp validate` into your CI pipeline for every manifest PR
to catch schema errors and over-broad globs before they reach production.

### Startup drift detection

Every time a session is established the proxy fetches `tools/list` from
the upstream and compares the live tool set against the manifest.
Findings are structured log lines emitted to stderr:

```
[eunox-mcp] WARN drift=fm1 tool="delete_all_records" resource="delete_*" — new upstream tool matched by manifest glob; verify this is intentional before deploying
[eunox-mcp] WARN drift=fm2 resource="query_db" — manifest entry matches no live upstream tool (tool removed or renamed?)
[eunox-mcp] WARN drift=fm3 resource="read_file" tool="read_file" argument="path" — condition argument not in live inputSchema; condition may not enforce if argument was renamed
[eunox-mcp] INFO drift=uncovered tool="summarise_text" — not covered by manifest; all calls will be denied
```

Add `--strict-drift` to abort session establishment (HTTP 500) when FM-1
or FM-2 drift is detected.  Appropriate for production deployments where
any policy gap must be resolved before traffic is admitted.

See [`mcp-contract-drift.md`](./mcp-contract-drift.md) for a full
description of each failure mode and recommended remediation.

## 9. Where this guide lives in the rest of the docs

- **Security properties and threat model**: [`threat-model-mcp.md`](./threat-model-mcp.md)
- **Performance baseline**: [`benchmarks.md`](./benchmarks.md)

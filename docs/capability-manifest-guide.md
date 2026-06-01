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

Every manifest must match `AgentCapabilityManifest` in
`internal/agentruntime/manifest.go`. The required top-level fields are
`name`, `version`, and `capabilities`. Optional fields are
`description`, `defaultTtl`, and `audience`. Anything missing or shaped
differently is rejected by `eunox validate`.

```yaml
name: "Sales Research Bot" # human-readable
version: "0.1.0" # agent version (semver)
capabilities: [] # see § 2 — every entry is a capability.Constraint
description: "Synthesizes account-research briefings."
defaultTtl: 600 # optional
audience: "eunox" # optional
```

The `defaultTtl` and `audience` fields are parsed and stored but are
informational in the proxy — JWT expiry is enforced by your IdP, not
by eunox-mcp. See § 5 for TTL guidance.

## 2. The capability list — the four common patterns

Most manifests fall into one of four shapes. Start from the closest
one and resist the urge to invent new shapes unless none of these fits.

### Pattern A — Single-purpose read agent

> _"This agent looks things up and reports. It never writes anywhere."_

```yaml
capabilities:
  - resource: "api://crm/customers/*"
    actions: ["read"]
  - resource: "api://reports/*"
    actions: ["read"]
```

- Only `read`.
- Resources scoped to a _segment_ with `/*`, never bare `*`.
- The Sentinel rule **"Write attempt from a read-only session"** will
  fire immediately if this agent ever attempts a write — that's the
  intended behaviour and it is **not** a false positive. Investigate
  before widening the manifest.

### Pattern B — Workflow agent (read-most, narrow write)

> _"This agent reads broadly but only writes back to one specific path."_

```yaml
capabilities:
  - resource: "api://crm/customers/*"
    actions: ["read"]
  - resource: "api://crm/customers/*/notes"
    actions: ["write"]
  - resource: "api://reports/*"
    actions: ["read"]
```

- Write resource is a **child path** of the read resource.
- Each write resource lists explicit actions; never use
  `["read", "write", "delete"]` "just in case".
- If the agent needs to write into N siblings, list them
  individually — don't widen to `api://crm/*`.

### Pattern C — Tool-specialist agent

> _"This agent calls a single internal tool a lot, with arguments."_

```yaml
capabilities:
  - resource: "api://forecasting/predict"
    actions: ["execute"]
    conditions:
      - type: maxCalls # MaxCallsCondition
        count: 30
        windowSeconds: 60
      - type: allowedOperations # AllowedOperationsCondition (narrows the verb)
        operations: ["predict"]
```

- Use `execute` for RPC-style endpoints.
- Apply typed conditions instead of relying on TTL alone.
- Each entry is one of the typed condition shapes in
  `pkg/capability/condition.go`; the proxy enforces them through the
  `ConditionRegistry` — no new validator code is needed if the type
  already exists.

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

The IdP then issues a JWT carrying a narrower `mcp.capabilities` claim:

```json
{
  "mcp": {
    "v": "0.1",
    "capabilities": ["read_file:/reports/q3.pdf"],
    "agent_id": "summariser-run-42",
    "task_id": "briefing-2026-05-31"
  }
}
```

The proxy takes the **intersection**: the JWT can only restrict, never
expand beyond what the manifest permits. `query_db` is denied for this
invocation even though the manifest allows it.

- Start the proxy in JWT mode: `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox --policy manifest.yaml`
- The audit log records `agent_id` and `task_id` from the JWT automatically.

## 3. Resource pattern do's and don'ts

The wildcard semantics are **segment-aware** (`pkg/enforcement/engine.go::matchesResource`).
Internalize the table below.

| Pattern                 | Matches                              | Does **not** match                     |
| ----------------------- | ------------------------------------ | -------------------------------------- |
| `api://crm/customers`   | `api://crm/customers` only           | `api://crm/customers/123`              |
| `api://crm/customers/*` | `api://crm/customers/123`, `.../abc` | `api://crm/customers`, `.../123/notes` |
| `storage://docs/team/*` | `storage://docs/team/file.pdf`       | `storage://docs/file.pdf`              |
| `api://*`               | (rejected by `eunox validate`)       | —                                      |

Rules:

- **Schemes are equality-checked.** `api://` and `storage://` never
  cross-match.
- **`*` matches one segment only.** `api://crm/customers/*` matches
  `api://crm/customers/123` but not `api://crm/customers/123/notes`.
  Multi-segment wildcards (`**`) are not supported — `path.Match`
  semantics are used and treat `**` identically to `*`.
- **Bare `*` is not allowed.** `eunox-mcp validate` rejects it.

## 4. Conditions cookbook

`conditions` is an array of typed shapes from
`pkg/capability/condition.go` and `pkg/capability/conditions.go`.
Every entry has a `type` discriminator and is enforced by the shared
`ConditionRegistry`. Unknown types are denied at both issuance and at
the proxy, so spelling matters.

```yaml
- resource: "api://billing/invoices/*"
  actions: ["read"]
  conditions:
    - type: maxCalls # rate-limit
      count: 60
      windowSeconds: 60
    - type: timeWindow # restrict to a window
      notBefore: "2026-04-01T00:00:00Z"
      notAfter: "2026-12-31T23:59:59Z"
    - type: ipRange # source-IP allowlist
      cidrs: ["10.0.0.0/8"]

- resource: "storage://exports/team-a/*"
  actions: ["write"]
  conditions:
    - type: allowedExtensions # restrict file types
      extensions: [".csv", ".json"]

- resource: "db://warehouse/sales"
  actions: ["read"]
  conditions:
    - type: allowedTables # restrict tables (and optionally columns)
      tables: ["sales"]
      columns:
        sales: ["customer_id", "amount", "ts"]
    - type: redactFields # proxy records the redaction obligation
      fields: ["sales.customer_email"]

- resource: "smtp://outbound/*"
  actions: ["execute"]
  conditions:
    - type: recipientDomain # outbound email allowlist
      domains: ["example.com"]
```

The full list of shipped condition types is `timeWindow`, `ipRange`,
`allowedOperations`, `allowedExtensions`, `allowedTables`, `maxCalls`,
`recipientDomain`, `redactFields`, `allowedValues`, `policy`,
and the `custom` escape hatch (which requires the named handler to be
registered in the `ConditionRegistry`).

**`allowedValues`** — restricts a named string argument to a set of allowed
literal values or glob patterns:

```yaml
- resource: read_file
  conditions:
    - type: allowedValues   # restrict the path argument
      argument: path
      values: ["/reports/*", "/public/*"]
```

The `argument` field names the tool parameter to check; `values` is a list
of exact strings or `*`-glob patterns (e.g. `/reports/*` matches
`/reports/q3.pdf`).

**`policy`** — delegates the allow/deny decision to an external policy
decision point (e.g. OPA, Cedar) registered via `WithPolicyEvaluator`:

```yaml
- resource: query_db
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

> If a condition you need is not in the union, **add a new typed
> shape to `pkg/capability/condition.go` first**, register its
> handler in `pkg/enforcement/handlers.go`, and ship a
> validator with tests under `pkg/capability/validate.go`.
> Free-form conditions are denied at the proxy, which is the correct
> behaviour but a policy regression for the manifest author.

## 5. TTL guidance

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

## 6. Anti-patterns to avoid

These all _work_ (token issued, proxy happy) but each one silently
degrades the security posture.

1. **Manifest copied between agents** with `name` not changed.
   Audit logs lose attribution clarity. Use a unique manifest `name` per logical
   agent, not per pod / replica.
2. **Over-broad resource globs** "for development". Configure dev
   manifests with realistic scopes from day one — a manifest that is
   too wide in development tends to stay that way in production.
3. **Adding actions the agent doesn't currently need.** List only what
   the agent actually calls. Over-broad manifests silently widen the
   blast radius of a prompt-injection or supply-chain compromise.
4. **One manifest shared across every environment.** Use a separate
   manifest per environment (`dev`, `staging`, `prod`) with
   progressively tighter conditions — the `name`/`version` fields make
   this traceable in the audit log.
5. **Long-lived JWTs re-used across tasks.** Request a fresh token
   per task and keep TTLs short; the audit log records `task_id` from
   the JWT so attribution is preserved without needing long-lived tokens.

## 7. Tooling

| Step                                          | CLI command                                          |
| --------------------------------------------- | ---------------------------------------------------- |
| Validate a manifest file                      | `eunox-mcp validate ./manifest.yaml`                 |
| Validate multiple manifests at once           | `eunox-mcp validate ./a.yaml ./b.yaml`               |
| Browse built-in server profiles               | `eunox-mcp profiles`                                 |
| Show tools for a specific profile             | `eunox-mcp profiles <name>`                          |
| Start the proxy (manifest-only mode)          | `eunox-mcp proxy --policy manifest.yaml --transport http --upstream-url <url>` |
| Start the proxy (JWT + manifest intersection) | add `--jwks-uri <url> --jwt-issuer <iss> --jwt-audience eunox` |
| Verify HMAC signatures in the audit log       | `eunox-mcp validate-token --audit-log audit.jsonl --audit-key-path audit.key` |

Wire `eunox-mcp validate` into your CI pipeline for every manifest PR
to catch schema errors and over-broad globs before they reach production.

## 8. Where this guide lives in the rest of the docs

- **Why the proxy is the policy decision point**: [`enforcement.md`](./enforcement.md)
- **Security properties and threat model**: [`threat-model-mcp.md`](./threat-model-mcp.md)
- **Performance baseline**: [`benchmarks.md`](./benchmarks.md)

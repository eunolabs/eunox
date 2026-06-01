# Capability Manifest Guide

> Patterns for writing capability manifests that work the first time,
> age well, and survive Sentinel scrutiny. This guide is the canonical
> companion to `eunox init` / `eunox validate` / `eunox plan` in
> `cmd/`.

A **capability manifest** is the YAML / JSON document that the
[`Capability Issuer`](../internal/issuer) consumes to
produce a signed JWT for an agent session. The token is what the
[`Tool Gateway`](../internal/gateway) verifies on every action.
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
audience: "eunox-gateway" # optional
```

Token-level concerns (TTL, the issuer DID, the JWT `schemaVersion`)
are **not** part of the manifest. They are configured on the
**Capability Issuer** (`DEFAULT_TOKEN_TTL`, `ISSUER_DID`) and stamped
onto the JWT at issuance time — see [`schema-versioning.md`](./schema-versioning.md)
and the issuer environment template in `internal/issuer/`.

## 2. The capability list — the four golden patterns

The pilot revealed that 90 % of real manifests fall into one of four
shapes. Use the closest one and resist the urge to invent new shapes
unless none of these fits.

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
  `pkg/capability/condition.go`; the gateway enforces them through the
  `ConditionRegistry` — no new validator code is needed if the type
  already exists.

### Pattern D — Delegated / attenuated child

> _"A parent agent spins up a child agent for a sub-task with a strictly
> smaller capability set."_

```yaml
# Body of POST /api/v1/attenuate using the parent token (the
# request payload uses the same CapabilityConstraint shape, just
# called requestedCapabilities at the wire layer).
requestedCapabilities:
  - resource: "api://crm/customers/12345" # exact ID, not wildcard
    actions: ["read"]
ttl: 120 # seconds; must be ≤ parent TTL
```

- Resource must be a **strict subset** of a parent capability (the
  issuer enforces this; see `internal/issuer`).
- TTL must be ≤ parent TTL (also enforced).
- The audit log will carry `parentCapabilityId` automatically; do not
  invent your own correlation field.

## 3. Resource pattern do's and don'ts

The wildcard semantics are **segment-aware** (`pkg/enforcement/engine.go::matchesResource`).
Internalize the table below.

| Pattern                  | Matches                                        | Does **not** match                         |
| ------------------------ | ---------------------------------------------- | ------------------------------------------ |
| `api://crm/customers`    | `api://crm/customers` only                     | `api://crm/customers/123`                  |
| `api://crm/customers/*`  | `api://crm/customers/123`, `.../abc`           | `api://crm/customers`, `.../123/notes`     |
| `api://crm/customers/**` | `api://crm/customers/123`, `.../123/notes/xyz` | `api://crm/customers`, `api://billing/...` |
| `storage://docs/team/*`  | `storage://docs/team/file.pdf`                 | `storage://docs/file.pdf`                  |
| `api://*`                | (rejected by `eunox validate` — too broad)     | —                                          |

Rules:

- **Schemes are equality-checked.** `api://` and `storage://` never
  cross-match, even if you use `**`.
- **A trailing `/*` matches one segment.** A trailing `/**` matches
  one or more segments.
- **Bare `*` is not allowed.** `eunox     validate` and the issuer both
  reject it.

## 4. Conditions cookbook

`conditions` is an array of typed shapes from
`pkg/capability/condition.go` and `pkg/capability/conditions.go`.
Every entry has a `type` discriminator and is enforced by the shared
`ConditionRegistry`. Unknown types are denied at both issuance and at
the gateway, so spelling matters.

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
    - type: redactFields # gateway records the redaction obligation
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
- name: read_file
  conditions:
    - type: allowedValues   # restrict the path argument
      argument: path
      values: ["/reports/*", "/public/*"]
```

The `argument` field names the tool parameter to check; `values` is a list
of exact strings or `*`-glob patterns (e.g. `/reports/*` matches
`/reports/q3.pdf`).

**`policy`** — delegates the allow/deny decision to an embedded OPA/Rego
policy string evaluated at call time:

```yaml
- name: query_db
  conditions:
    - type: policy
      rego: |
        default allow = false
        allow { input.arguments.query != "" }
```

The `rego` field is evaluated with `input.arguments` bound to the
tool's argument map; the policy must define `allow`.  Use this for
logic that cannot be expressed with the other typed conditions.

> If a condition you need is not in the union, **add a new typed
> shape to `pkg/capability/condition.go` first**, register its
> handler in `pkg/enforcement/handlers.go`, and ship a
> validator with tests under `pkg/capability/validate.go`.
> Free-form conditions are denied at the gateway, which is the correct
> behaviour but a policy regression for the manifest author.

## 5. TTL guidance

Token TTL is set on the **issuer** (via `DEFAULT_TOKEN_TTL` env var on
the Capability Issuer), not in the manifest. For attenuated child
tokens the caller passes `ttl` in the `/api/v1/attenuate` request
body and the issuer caps it at the parent's remaining TTL.

| Scenario                                | Recommended TTL (seconds)                 |
| --------------------------------------- | ----------------------------------------- |
| Interactive chat / tool call            | 900 (15 min — the default)                |
| Long-running batch (ETL, embedding job) | 1800–3600 (use `/renew` if you need more) |
| Delegated child for one sub-task        | 60–300                                    |
| Anything that touches money or PII      | 300 with mandatory `/renew` per action    |

Keep the issuer's `DEFAULT_TOKEN_TTL` ≤ 3600 in the pilot.

## 6. Anti-patterns we caught during the pilot

These all _worked_ (token issued, gateway happy) but each one degrades
the security posture and triggered tuning churn during hypercare.

1. **Manifest copied between agents** with `name` not changed.
   Audit logs lose attribution clarity. Use a unique manifest `name` per logical
   agent, not per pod / replica.
2. **`api://*` with `["read", "write"]`** "for development". This
   passes `validate` only when the strict mode is off. In production
   the issuer rejects it; configure your dev manifests with realistic
   scopes and a separate dev manifest identity (`name`/`version`).
3. **Adding `delete` "for cleanup"**. If the agent doesn't currently
   delete anything, do not list `delete`. The Sentinel "Write attempt
   from a read-only session" rule treats delete as write; over-broad
   manifests defeat the rule.
4. **Issuing one massive token** that covers every tool the agent
   _might_ need. Issue task-scoped tokens via `/issue` and chain via
   `/attenuate`; the token TTL is short for a reason.
5. **Hand-editing a JWT** to extend expiry during testing. Use
   `POST /api/v1/renew` — anything else invalidates the signature and
   is correctly rejected.

## 7. Tooling

| Step                                                        | CLI command                                              |
| ----------------------------------------------------------- | -------------------------------------------------------- |
| Scaffold a new manifest                                     | `eunox init --agent <name> --output ./manifest.yaml`     |
| Add a framework scaffold to it                              | `eunox init --framework langchain` (or `maf` / `crewai`) |
| Add a cloud-deployment scaffold                             | `eunox init --cloud aws` (or `azure` / `gcp`)            |
| Validate the file                                           | `eunox validate ./manifest.yaml`                         |
| Show the current and supported schema versions on an issuer | `eunox schema-version check --issuer <url>`              |
| Plan a schema-version migration                             | `eunox schema-version plan <from> <to>`                  |
| Inspect a token's `schemaVersion` claim                     | `eunox schema-version validate-token <jwt>`              |
| Show CLI configuration / env                                | `eunox config`                                           |
| Request a token (documentation helper)                      | `eunox request --agent <id> --token $AAD_ACCESS_TOKEN`   |

Wire `eunox validate` into your CI for every manifest PR; combine with
`eunox schema-version check` against your staging issuer if you want to
fail builds on schema-version drift before they reach production.

## 8. Where this guide lives in the rest of the docs

- **Token format and signing**: [`schema-versioning.md`](./schema-versioning.md)
- **Why the gateway is the policy decision point**: [`enforcement.md`](./enforcement.md)
- **Adapter pattern (custom identity / signers)**: [`adapters.md`](./adapters.md)

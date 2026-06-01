# RFC: MCP Capability Manifest

**Status:** Draft  
**Version:** 0.1  
**Authors:** Eunolabs  
**Repository:** https://github.com/eunolabs/eunox

---

## Abstract

This document specifies the **MCP Capability Manifest** — a vendor-neutral,
file-based format for declaring the tool-call authorizations an AI agent is
permitted to exercise against an MCP server. It also specifies the companion
**MCP JWT Capability Claim** schema for carrying per-invocation capability
assertions in IdP-issued bearer tokens.

The goal is to give the MCP ecosystem a single, interoperable authorization
vocabulary so that manifests written for one compliant enforcement proxy work
without modification in any other.

---

## 1. Introduction

The Model Context Protocol (MCP) defines a standard wire format for AI agents
to discover and invoke server-side tools. MCP itself is deliberately silent on
authorization: it specifies *how* tool calls are made, not *who is allowed to
make them* or *under what conditions*.

In practice every production deployment that exposes MCP tools needs answers to
questions such as:

- Which tools may this agent call?
- May it read `/reports/*` but not `/etc/shadow`?
- Is it rate-limited to 30 calls per minute?
- Is the capability scoped to a specific task or time window?

Without a shared vocabulary each deployment invents its own policy language.
Manifests are not portable between vendors, and there is no common surface for
audit, compliance tooling, or IdP integration.

This RFC proposes a minimal, extensible schema that answers those questions in a
way that any compliant enforcement proxy can implement.

### 1.1 Design Goals

1. **Vendor-neutral** — no proprietary fields; any MCP proxy can implement it.
2. **Declarative** — a manifest is a static YAML/JSON file; no code required.
3. **Composable** — a per-deployment manifest and a per-invocation JWT claim can
   be combined via intersection at enforcement time.
4. **Auditable** — every enforcement decision references a manifest entry and a
   condition type by name, giving compliance tooling a stable vocabulary.
5. **Minimal** — the required schema is five fields. Everything else is opt-in.

### 1.2 Relationship to MCP

This RFC is a companion to the MCP specification, not a revision of it. It
describes what lives *in front of* an MCP server, not inside it.

```
MCP Host → [enforcement proxy] → MCP Server
                 ↑
         reads manifest + JWT
```

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
| --- | --- |
| **Manifest** | The YAML or JSON file described by this RFC. |
| **Constraint** | One entry in the `capabilities` list — a (resource, actions, conditions) tuple. |
| **Condition** | A typed predicate evaluated at call time against the tool arguments, call context, or call history. |
| **Enforcement proxy** | The component that loads the manifest and evaluates it on every `tools/call`. |
| **Capability claim** | The `mcp` object in a bearer JWT issued by an IdP. |
| **Intersection model** | When both a manifest and a JWT claim are present, the proxy allows only what both independently permit. |

---

## 3. Capability Manifest Schema

### 3.1 Top-Level Fields

A manifest is a JSON object (or its YAML equivalent) with the following fields:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | **Yes** | Human-readable name for the agent or policy. Used for attribution in audit logs. |
| `version` | string | **Yes** | Semver string for the manifest itself (e.g. `"1.0.0"`). Enables diff-based policy reviews. |
| `capabilities` | array | **Yes** | List of `Constraint` objects (§ 3.2). An empty array denies all tool calls. |
| `description` | string | No | Free-text description of the agent's purpose. |
| `defaultTtl` | integer | No | Informational: recommended JWT TTL in seconds for tokens that reference this manifest. Not enforced by the proxy — JWT expiry is the IdP's responsibility. |
| `audience` | string | No | Informational: recommended value for the JWT `aud` claim. |

**Example:**

```yaml
name: "Sales Research Bot"
version: "1.0.0"
description: "Reads CRM data and generates briefings. Never writes."
capabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*"]
  - resource: query_db
    actions: [call]
    conditions:
      - type: allowedOperations
        operations: [SELECT]
      - type: maxCalls
        count: 30
        windowSeconds: 60
```

### 3.2 Constraint Object

Each entry in `capabilities` is a Constraint:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `resource` | string | **Yes** | The tool name or URI being authorized. For MCP tools this is the tool name (e.g. `read_file`). URI schemes (e.g. `api://`, `storage://`) are supported for richer resource hierarchies. |
| `actions` | array of strings | **Yes** | Permitted actions. For MCP tools use `["call"]`. Other values (`read`, `write`, `execute`) are available for non-MCP resource schemes. |
| `conditions` | array of Condition | No | Zero or more typed predicates that must all pass for the call to be allowed (logical AND). |
| `argumentSchema` | object | No | JSON Schema (subset) for validating tool arguments at the structural level, independent of conditions. |

A Constraint with no `conditions` allows the tool unconditionally (subject to
action matching). An absent `capabilities` entry for a tool MUST be treated as
a deny.

#### 3.2.1 Resource Wildcard Semantics

Resource strings support segment-aware wildcards:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `read_file` | `read_file` only | anything else |
| `api://crm/customers/*` | `api://crm/customers/123` | `api://crm/customers/123/notes` |
| `api://crm/customers/**` | `api://crm/customers/123`, `…/123/notes/xyz` | `api://crm/customers` |
| `api://*` | **MUST be rejected by validators** — too broad | — |

Rules:
- Scheme components (`api://`, `storage://`) are equality-checked; cross-scheme
  matching MUST NOT occur.
- `*` matches exactly one path segment.
- `**` matches one or more path segments.
- Bare `*` at the top level (no scheme, no path) MUST be rejected.

### 3.3 Condition Types

Every condition object MUST carry a `type` field (the discriminator). Unknown
types MUST be treated as a deny. The following types are defined by this RFC:

#### `allowedValues`
Restricts a named string argument to a set of allowed literal values or glob patterns.

```yaml
- type: allowedValues
  argument: path          # name of the tool argument to check
  values:
    - "/reports/*"        # glob — matches /reports/q3.pdf
    - "/public/index.html" # literal
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `argument` | string | Yes | Name of the tool argument to inspect. |
| `values` | array of strings | Yes | Allowed values. Each may be a literal or a `*`-glob. |

#### `allowedOperations`
Restricts a string argument (default: the first argument) to a set of allowed
operation verbs. Designed for SQL-style interfaces.

```yaml
- type: allowedOperations
  operations: [SELECT, SHOW]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `operations` | array of strings | Yes | Allowed operation strings. Case-sensitive. |

#### `maxCalls`
Rate-limits invocations within a sliding time window, per session.

```yaml
- type: maxCalls
  count: 30
  windowSeconds: 60
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | Yes | Maximum number of calls permitted in the window. |
| `windowSeconds` | integer | Yes | Length of the sliding window in seconds. |

#### `timeWindow`
Restricts the tool to a time range (UTC).

```yaml
- type: timeWindow
  notBefore: "2026-01-01T00:00:00Z"
  notAfter:  "2026-12-31T23:59:59Z"
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `notBefore` | RFC 3339 string | No | Call must occur after this time. |
| `notAfter` | RFC 3339 string | No | Call must occur before this time. |

#### `ipRange`
Restricts calls to requests originating from the listed CIDR blocks.

```yaml
- type: ipRange
  cidrs: ["10.0.0.0/8", "192.168.1.0/24"]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `cidrs` | array of strings | Yes | Allowed source IP ranges in CIDR notation. |

#### `allowedExtensions`
Restricts a file-path argument to the listed file extensions.

```yaml
- type: allowedExtensions
  extensions: [".csv", ".json", ".pdf"]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `extensions` | array of strings | Yes | Allowed extensions including the leading dot. |

#### `allowedTables`
Restricts a database-query argument to the listed tables and optional columns.

```yaml
- type: allowedTables
  tables: [reports, summaries]
  columns:
    reports: [id, title, created_at]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `tables` | array of strings | Yes | Allowed table names. |
| `columns` | map of string → array of strings | No | Per-table column allowlists. Absent means all columns in that table are permitted. |

#### `recipientDomain`
Restricts outbound communication tools (e.g. email, webhooks) to the listed
domain suffixes.

```yaml
- type: recipientDomain
  domains: ["example.com", "partner.org"]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `domains` | array of strings | Yes | Allowed recipient domain suffixes. |

#### `redactFields`
Marks fields in the tool response for redaction before returning to the caller.
This is an obligation on the enforcement proxy, not a deny condition.

```yaml
- type: redactFields
  fields: ["customer_email", "ssn"]
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `fields` | array of strings | Yes | Field names to redact from the tool response. |

#### `policy`
Delegates the allow/deny decision to an embedded OPA/Rego policy string.

```yaml
- type: policy
  rego: |
    default allow = false
    allow { input.arguments.query != "" }
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `rego` | string | Yes | Rego policy. Must define `allow`. `input.arguments` is bound to the tool argument map at evaluation time. |

#### `custom`
Escape hatch for implementation-specific conditions not yet covered by this RFC.
Implementations MUST document the handler name and its semantics. Manifests
using `custom` conditions are not portable between implementations.

```yaml
- type: custom
  handler: "my-vendor.ratelimit-by-user"
  config:
    maxPerUser: 10
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `handler` | string | Yes | Reverse-DNS handler identifier. |
| `config` | object | No | Handler-specific configuration. |

---

## 4. MCP JWT Capability Claim

When an IdP issues a bearer JWT for an agent invocation, it MAY include an
`mcp` claim object that narrows what the agent is permitted to do for that
specific invocation.

### 4.1 Claim Structure

```json
{
  "mcp": {
    "v": "0.1",
    "capabilities": ["read_file:/reports/*", "query_db:SELECT"],
    "agent_id": "research-agent-42",
    "task_id":  "briefing-2026-05-31"
  }
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `v` | string | **Yes** | Schema version. MUST be `"0.1"` for this revision of the RFC. Tokens with an absent or unrecognised `v` MUST be rejected. |
| `capabilities` | array of strings | Yes | Per-invocation capability assertions in shorthand format (§ 4.2). |
| `agent_id` | string | No | Stable identifier for the agent software. Recorded in the audit log. |
| `task_id` | string | No | Identifier for the specific task or session. Recorded in the audit log. |

### 4.2 Capability Shorthand Format

Each entry in `capabilities` is a string of the form:

```
<tool>[:<condition>]
```

The `<condition>` part is optional. When present it is interpreted by the
following heuristics (applied in order):

1. **SQL verb** — if `<condition>` is an uppercase SQL keyword (`SELECT`,
   `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`), it
   maps to an `allowedOperations` condition.

   `"query_db:SELECT"` → allow `query_db` where `operation` is `SELECT`.

2. **Path glob** — otherwise the condition is treated as an `allowedValues`
   condition on the argument named `path`.

   `"read_file:/reports/*"` → allow `read_file` where `path` matches `/reports/*`.

3. **No condition** — the tool is allowed unconditionally (still subject to the
   manifest intersection, see § 5).

   `"read_file"` → allow `read_file` with no argument restrictions from the JWT.

Implementations MAY extend the shorthand with additional heuristics, but MUST
document any extensions and MUST fall back to treating unrecognised condition
syntax as `allowedValues(path=<condition>)`.

### 4.3 Keycloak Mapper Configuration

The `mcp` claim object is produced by configuring individual
`oidc-hardcoded-claim-mapper` entries using dotted claim names. Keycloak (and
most IdPs that support dot-path claim names) will nest them automatically:

| Claim name | Value | JSON type |
| --- | --- | --- |
| `mcp.v` | `0.1` | String |
| `mcp.capabilities` | `["read_file:/reports/*","query_db:SELECT"]` | JSON |
| `mcp.agent_id` | `research-agent-42` | String |
| `mcp.task_id` | `briefing-2026-05-31` | String |

---

## 5. Enforcement Model

### 5.1 Manifest-Only Mode

When the proxy is configured with only a manifest (`--policy manifest.yaml`):

1. Look up the tool name in `capabilities`. If not found → **DENY** with
   `AUTHORIZATION_FAILED`.
2. Check that the requested action is in `actions`. If not → **DENY**.
3. Evaluate all `conditions` in the matching Constraint (logical AND). If any
   condition fails → **DENY** with `CONDITION_FAILED` (report the failing
   condition type and argument).
4. If all conditions pass → **ALLOW**.

### 5.2 JWT + Manifest Intersection Mode

When both a manifest and a `--jwks-uri` are configured:

1. Validate the JWT signature, expiry (`exp`), issuer (`iss`), and audience
   (`aud`). On failure → HTTP 401.
2. Validate `mcp.v`. On failure → HTTP 401.
3. Parse the `mcp.capabilities` shorthand claims into a set of in-memory
   Constraints (§ 4.2).
4. Evaluate the tool call against **both** the manifest Constraints and the JWT
   Constraints. The call is allowed only if it passes both independently.
5. The JWT can only **restrict** — it cannot expand what the manifest permits.

**Why intersection?** A manifest is an administrative policy set by the operator.
A JWT is a per-invocation scope set by the orchestration layer. Neither should
be able to override the other. This model preserves defence in depth: a
compromised IdP cannot grant more than the manifest permits, and a manifest
change cannot bypass per-task scoping.

### 5.3 Default Deny

Any tool not listed in `capabilities` MUST be denied, regardless of whether a
JWT is present. Manifests are allowlists, not blocklists.

### 5.4 Audit

Every enforcement decision MUST be written to a tamper-evident audit log. Each
record MUST include at minimum:

- A unique request ID.
- The MCP session ID.
- The tool name.
- The decision (`allow` or `deny`).
- The denial code if denied (`AUTHORIZATION_FAILED`, `CONDITION_FAILED`).
- The condition type and argument that triggered the denial (if applicable).
- The `agent_id` and `task_id` from the JWT (if present).
- A timestamp.

---

## 6. Versioning

### 6.1 Manifest Version

The `version` field in the manifest is the version of the *policy document*,
not the schema. It follows [Semantic Versioning](https://semver.org). Operators
SHOULD increment it on every policy change; audit records MAY reference it for
traceability.

### 6.2 Claim Schema Version

The `mcp.v` field in the JWT claim is the version of *this RFC's claim schema*.
The current value is `"0.1"`. Implementations:

- MUST reject tokens with an absent `v`.
- MUST reject tokens with an unrecognised `v`.
- SHOULD log a clear error message identifying the expected and received values.

Version `"0.1"` indicates the schema is pre-stable. Breaking changes prior to
`"1.0"` will increment the minor component (`"0.2"`, `"0.3"`, …). Once `"1.0"`
is declared, the major component increments for breaking changes (`"2.0"`).

### 6.3 RFC Version

This RFC is versioned independently of the claim schema. The RFC version
reflects the state of the specification document; the claim schema version
reflects what must be in the JWT.

---

## 7. Security Considerations

### 7.1 Manifest as the Ceiling

The manifest is the administrative ceiling. No JWT claim, user-supplied
argument, or runtime condition can expand what the manifest permits. This
property MUST be preserved by all compliant implementations.

### 7.2 Condition Evaluation Order

Conditions are evaluated in declaration order. Implementations SHOULD evaluate
cheaper conditions (e.g. `allowedValues`) before expensive ones (e.g. `policy`
with a Rego evaluation).

### 7.3 Argument Validation Scope

Conditions operate on the *declared* tool arguments. If a tool accepts free-form
input, `allowedValues` and `allowedOperations` conditions constrain that input
before it reaches the upstream server. Implementations MUST NOT pass tool
arguments to the upstream server before all conditions pass.

### 7.4 Audit Tamper-Evidence

Audit records MUST be signed with an HMAC or equivalent. A record with an
invalid signature MUST be flagged as invalid by any audit verification tool.
The signing key MUST be persisted alongside the log so that records can be
verified after the enforcement proxy restarts.

### 7.5 JWT Key Management

Implementations MUST validate JWT signatures against keys fetched from the
`--jwks-uri` endpoint. Symmetric signing algorithms (e.g. `HS256`) MUST NOT be
accepted. Implementations SHOULD cache the JWKS with a short TTL and support
key rotation by re-fetching when an unknown `kid` is encountered.

### 7.6 Denial Detail Sanitization

Error responses sent to callers MUST NOT echo raw user-supplied argument values.
Sensitive fields (e.g. the path that failed an `allowedValues` check) MUST be
redacted in client-facing error messages. The full argument value MAY appear in
the audit log (which is operator-controlled, not caller-visible).

---

## 8. Examples

### 8.1 Read-Only Research Agent

```yaml
name: "Research Agent"
version: "1.0.0"
capabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedValues
        argument: path
        values: ["/reports/*", "/public/*"]
  - resource: web_search
    actions: [call]
    conditions:
      - type: maxCalls
        count: 50
        windowSeconds: 3600
```

### 8.2 Narrow Database Agent with JWT Scoping

Manifest (operator-controlled ceiling):

```yaml
name: "Analytics Agent"
version: "1.0.0"
capabilities:
  - resource: query_db
    actions: [call]
    conditions:
      - type: allowedOperations
        operations: [SELECT]
      - type: allowedTables
        tables: [sales, inventory]
```

JWT claim (per-task, issued by IdP):

```json
{
  "mcp": {
    "v": "0.1",
    "capabilities": ["query_db:SELECT"],
    "agent_id": "analytics-v2",
    "task_id": "weekly-report-2026-W22"
  }
}
```

Result: `query_db` is allowed only for `SELECT` on `sales` or `inventory`
tables, scoped to the specific task. An agent with a JWT that omits `query_db`
entirely would be denied even though the manifest allows it.

### 8.3 Timed Window Agent

```yaml
name: "End-of-Quarter Closer"
version: "1.0.0"
capabilities:
  - resource: update_crm
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2026-06-28T00:00:00Z"
        notAfter:  "2026-06-30T23:59:59Z"
      - type: allowedValues
        argument: stage
        values: ["closed-won", "closed-lost"]
```

---

## 9. IANA Considerations

The `mcp` JWT claim name used in § 4 is not currently registered with IANA. If
this specification advances, registration of `mcp` as a JSON Web Token Claim
Name per [RFC 7519 § 10.1](https://www.rfc-editor.org/rfc/rfc7519#section-10.1)
will be sought.

---

## 10. Open Questions

The following design questions are deferred to a future revision:

1. **Claim schema negotiation** — should the proxy advertise the claim versions
   it accepts, e.g. via a well-known endpoint?
2. **Multi-value `v`** — should `v` be a string or an array to allow gradual
   migration periods?
3. **Capability shorthand extensibility** — should the shorthand grammar be
   formally specified (e.g. as a BNF) rather than described by heuristics?
4. **`argumentSchema` validation** — this RFC includes `argumentSchema` in the
   Constraint but does not specify when it takes precedence over conditions.
5. **Revocation** — this RFC has no mechanism for revoking an in-flight JWT. A
   kill-switch mechanism is out of scope for the manifest but referenced here for
   completeness.

---

## Appendix A — Schema Summary (JSON Schema)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://eunolabs.com/schemas/mcp-capability-manifest/0.1",
  "type": "object",
  "required": ["name", "version", "capabilities"],
  "properties": {
    "name":         { "type": "string", "minLength": 1 },
    "version":      { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+" },
    "description":  { "type": "string" },
    "defaultTtl":   { "type": "integer", "minimum": 1 },
    "audience":     { "type": "string" },
    "capabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["resource", "actions"],
        "properties": {
          "resource":   { "type": "string", "minLength": 1 },
          "actions":    { "type": "array", "items": { "type": "string" }, "minItems": 1 },
          "conditions": { "type": "array", "items": { "type": "object", "required": ["type"] } }
        }
      }
    }
  }
}
```

## Appendix B — JWT Claim Schema Summary

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://eunolabs.com/schemas/mcp-jwt-claim/0.1",
  "type": "object",
  "required": ["v", "capabilities"],
  "properties": {
    "v":            { "type": "string", "const": "0.1" },
    "capabilities": { "type": "array", "items": { "type": "string" } },
    "agent_id":     { "type": "string" },
    "task_id":      { "type": "string" }
  }
}
```

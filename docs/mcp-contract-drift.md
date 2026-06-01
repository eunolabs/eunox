# MCP Server Contract Drift

**Date:** 2026-05-31  
**Status:** Discovery / action items open  
**Related:** [`mcp-enforcement-gaps.md`](./mcp-enforcement-gaps.md)

---

## Problem statement

A capability manifest is authored against a snapshot of an MCP server's
tool contract at a point in time. The proxy has no mechanism to detect
when that contract changes. When it does, the manifest can silently
over-permit, silently under-permit, or silently mis-enforce — all
without producing any error.

This is distinct from the enforcement gaps in
[`mcp-enforcement-gaps.md`](./mcp-enforcement-gaps.md). Those gaps are
about MCP message types the proxy does not inspect at all. This problem
is about the manifest becoming stale relative to the tools the proxy
_does_ inspect.

---

## Failure modes

### FM-1 — Silent over-permission (highest severity)

A new tool is added to the server whose name matches an existing
manifest glob.

**Example.** The manifest contains:

```yaml
- resource: "delete_*"
  actions: [call]
```

The server ships `delete_all_records`. The proxy immediately permits it —
the policy author is never notified. No error, no warning, no audit
entry that looks unusual.

**Why it matters.** Glob-based manifests, which are the natural way to
avoid listing every tool individually, are the most exposed to this
failure. A glob that was safe when authored may become dangerous the
moment the server adds a new tool that matches it.

### FM-2 — Silent under-permission (medium severity)

A tool is renamed on the server. The manifest entry becomes a dead
reference. Every call the agent makes to the new tool name is denied
with `AUTHORIZATION_FAILED`. There is no startup warning; the failure
only surfaces at call time.

**Example.** `query_db` is renamed to `execute_query`. Manifest has
`resource: query_db`. Agent is broken until the manifest is updated.

### FM-3 — Silent condition bypass (high severity)

A tool's argument schema changes — a field is renamed, split, or
restructured. A condition that targeted the old field name silently
skips enforcement rather than failing closed.

**Example.** The manifest has:

```yaml
- resource: read_file
  conditions:
    - type: allowedValues
      argument: path          # ← targets this field name
      values: ["/reports/*"]
```

The server renames the argument from `path` to `file_path`. The
`allowedValues` condition finds no argument named `path` in the request
and the enforcement handler returns a
`MISSING_CONTEXT` error — but in the current implementation,
`allowedValues` with a missing argument returns a _deny_, not a
passthrough. However, a different argument name change — where the
schema field is restructured into a nested object — could cause the
condition to silently pass by never matching. The invariant to protect
is: a condition that was intended to restrict must not silently become a
no-op.

### FM-4 — Server version mismatch (detectable via version pin)

A tool retains its name and argument schema but its server-side
implementation changes. For example, `read_file` begins exfiltrating
file metadata to a telemetry endpoint after a server update. The proxy
cannot detect implementation changes directly, but it **can** detect
that the server version changed — provided the manifest declares a
`serverVersion` pin.

**Detected when `serverVersion` is set in the manifest.** The proxy
compares the version string from the upstream `initialize` response
against the pinned constraint and emits an FM-4 warning on mismatch.

```yaml
# manifest.yaml
name: "my-policy"
version: "1.0.0"
serverVersion: "1.2.*"   # allow any patch of 1.2; reject 1.3+
capabilities:
  - resource: read_file
    actions: [call]
```

Supported constraint forms:

| Constraint | Matches |
|---|---|
| `1.2.3` | exactly `1.2.3` |
| `1.2.*` | `1.2.x` for any patch `x` |
| `1.*`   | `1.x.y` for any minor and patch |
| `*`     | any version (effectively no pin) |

**Without `serverVersion` in the manifest:** FM-4 is never emitted —
existing manifests are unaffected.

**In `--strict-drift` mode:** FM-4 aborts session establishment (like
FM-1 and FM-2), preventing an agent from connecting to an unexpected
server version.

**Purely behavioral changes** (same version, changed implementation)
cannot be detected at the proxy layer and remain a supply-chain concern
addressed by deployment controls.

---

## Fixes

### Fix 1 — Startup drift detection ✅ **Implemented**

After the `initialize` handshake the proxy sends `tools/list` to the
upstream and compares the live tool set against the manifest.  Three
message types are emitted as structured `key=value` log lines to stderr:

**1a. New tool matches an existing glob (FM-1) — `WARN`**

```
[eunox-mcp] WARN drift=fm1 tool="delete_all_records" resource="delete_*" — new upstream tool matched by manifest glob; verify this is intentional before deploying
```

**1b. Manifest entry matches no upstream tool (FM-2) — `WARN`**

```
[eunox-mcp] WARN drift=fm2 resource="query_db" — manifest entry matches no live upstream tool (tool removed or renamed?)
```

**1c. Upstream tool not covered by manifest — `INFO`**

```
[eunox-mcp] INFO drift=uncovered tool="summarise_document" — not covered by manifest; all calls will be denied
```

The check runs in a background goroutine in non-strict mode (session
establishment is not blocked).

**`--strict-drift` flag** promotes FM-1 and FM-2 findings to startup
errors, aborting session establishment with HTTP 500.  FM-3 findings
and uncovered-tool infos remain advisory even in strict mode.

### Fix 2 — `eunox-mcp validate --live` subcommand ✅ **Implemented**

A new `validate` flag that connects to a live upstream, fetches
`tools/list`, and runs a complete diff against the manifest:

```
$ eunox-mcp validate manifest.yaml \
    --live \
    --transport http \
    --upstream-url https://mcp.example.com

Connecting to upstream...  ok (12 tools)

COVERED
  ✓ read_file          resource: read_file  (exact match)
  ✓ query_db           resource: query_db   (exact match)
  ✓ get_customer       resource: get_*      (glob match)
  ✓ get_invoice        resource: get_*      (glob match)

WARNINGS
  ⚠ delete_all_records resource: delete_*   (NEW tool matched by glob —
                                             confirm this is intended)

NOT COVERED (denied by default)
  - execute_query      no manifest entry
  - summarise_text     no manifest entry

STALE MANIFEST ENTRIES
  ✗ legacy_search      no matching upstream tool

Result: 1 warning, 1 stale entry. Exit code 1.
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | All manifest entries match live tools; no new glob-matched tools |
| 1 | Warnings or stale entries present (review required) |
| 2 | Connection or parse error |

Integrate into CI on every server release:

```yaml
# .github/workflows/manifest-drift.yml
- name: Check manifest drift
  run: |
    eunox-mcp validate manifest.yaml \
      --live \
      --upstream-url ${{ vars.MCP_STAGING_URL }}
```

The pipeline fails (exit 1) when any upstream tool is newly matched by
a glob or when any manifest entry becomes stale. Policy authors review
the diff and update the manifest explicitly before the server release
ships to production.

### Fix 3 — Argument schema drift detection ✅ **Implemented**

Startup drift detection (Fix 1) now also checks FM-3: for each manifest
entry that matches a live tool, the proxy compares each condition's
explicit `argument` field against the tool's live `inputSchema.properties`.
If the argument name is absent from the live schema the following warning
is emitted:

```
[eunox-mcp] WARN drift=fm3 resource="read_file" tool="read_file" argument="path" — condition argument not in live inputSchema; condition may not enforce if argument was renamed
```

FM-3 findings are advisory (not fatal even with `--strict-drift`) because
an absent argument name still causes the condition to fail closed (deny)
— the risk is a false-deny, not a silent pass-through.  The warning
prompts the operator to update the manifest `argument` field.

**Strengthening FM-3 with `argumentSchema` pinning:**

The `argumentSchema` field on a capability constraint is validated at
call time by `validateSchema` in `cmd/mcp/pdp.go`.  Pinning the schema
converts an argument rename from an FM-3 advisory into a hard
`ARGUMENT_VALIDATION_FAILED` error:

```yaml
- resource: read_file
  actions: [call]
  argumentSchema:           # pinned from tools/list at manifest authoring time
    type: object
    properties:
      path: { type: string }
    required: [path]
  conditions:
    - type: allowedValues
      argument: path
      values: ["/reports/*"]
```

When the server renames `path` to `file_path`, the proxy rejects every
call at schema validation rather than silently applying the condition
to a missing argument.

### Fix 4 — `eunox-mcp init` scaffold ✅ **Implemented**

A new `init` subcommand connects to a live upstream and generates a
starter manifest with one deny-all entry per tool:

```
$ eunox-mcp init \
    --transport http \
    --upstream-url https://mcp.example.com \
    --output manifest.yaml

Fetching tool list from upstream... 12 tools

Generated manifest.yaml
Review and uncomment the capabilities you want to permit.
```

Generated output:

```yaml
name: "generated-manifest"
version: "1.0.0"

capabilities:
  # REVIEW: uncomment and add conditions before enabling each tool.
  # - resource: read_file
  #   actions: [call]
  #   argumentSchema:
  #     type: object
  #     properties:
  #       path: { type: string }
  #     required: [path]

  # - resource: query_db
  #   actions: [call]
  #   argumentSchema:
  #     type: object
  #     properties:
  #       query: { type: string }
  #     required: [query]

  # ... (10 more tools commented out)
```

Every tool starts commented out — deny by default. Policy authors
uncomment and add conditions only for tools the agent genuinely needs.
Re-running `init` after a server update produces a new file; diffing
against the current manifest surfaces additions and removals.

---

## What cannot be fixed at the proxy layer

**FM-4 (behavior drift)** cannot be addressed by manifest policy.
A tool that changes its server-side implementation while keeping its
name and argument schema is indistinguishable from the proxy's
perspective. Mitigations are external:

- **Pin the server version.** Deploy via container image digest
  (`:sha256-abc123`) rather than a mutable tag (`:latest`). Any server
  update requires an explicit digest change, which is a reviewable event.
- **Sandbox the server.** Run the upstream MCP server in a network
  namespace or similar isolation so that even if it changes behavior,
  its egress surface is limited.
- **Treat the server as untrusted.** The threat model doc
  (`threat-model-mcp.md`) already models the MCP server as a potential
  adversary. The proxy's job is to limit what the _agent_ can do; the
  server's own behavior is a supply-chain concern.

---

## Priority

| Fix | Effort | Addresses | Status |
|---|---|---|---|
| Fix 1 — Startup drift warnings | Low | FM-1, FM-2 | ✅ **Shipped** (`cmd/mcp/drift.go`) |
| Fix 3 — Argument schema drift | Low | FM-3 | ✅ **Shipped** (Fix 1 extended; `argumentSchema` pinning documented) |
| Fix 2 — `validate --live` | Medium | FM-1, FM-2, FM-3, FM-4 | ✅ **Shipped** (`cmd/mcp/validate_live.go`; `--live` flag on `validate`) |
| Fix 4 — `init` scaffold | Medium | Authoring UX | ✅ **Shipped** (`cmd/mcp/init_manifest.go`; `init` subcommand) |
| FM-4 — Version pin | Low | FM-4 | ✅ **Shipped** (`serverVersion` manifest field; `cmd/mcp/drift.go`) |

---

## Impact on the MVP release checklist

The release checklist should include a **Stage 4** CI step:

```yaml
# .github/workflows/manifest-drift.yml
- name: Check manifest drift
  run: |
    eunox-mcp validate manifest.yaml \
      --live \
      --upstream-url ${{ vars.MCP_STAGING_URL }}
```

Exit code 1 (glob matches or stale entries detected) fails the pipeline;
policy authors review the diff and update the manifest before the server
release ships to production.

To bootstrap a manifest for a new server, run:

```
eunox-mcp init --upstream-url https://mcp.example.com --output manifest.yaml
```

Every tool starts commented out.  Uncomment and add conditions only for
tools the agent genuinely needs, then commit the result.

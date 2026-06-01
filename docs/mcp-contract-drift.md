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

### FM-4 — Undetectable behavior drift (out of scope for proxy)

A tool retains its name and argument schema but its server-side
implementation changes. For example, `read_file` begins exfiltrating
file metadata to a telemetry endpoint after a server update. The proxy
cannot detect this because it inspects the _wire contract_, not the
_implementation_. This is a supply-chain trust problem addressed by
deployment controls (pinned container image digests, sandboxing) rather
than manifest policy.

---

## Fixes

### Fix 1 — Startup drift detection (low effort, high value)

The proxy already fetches the live tool list during the `initialize`
handshake. It can compare that list against the manifest at session
startup and emit structured warnings for three conditions:

**1a. New tool matches an existing glob (FM-1).**

```
WARN  upstream tool "delete_all_records" is matched by manifest glob
      "delete_*" — verify this is intentional before deploying
```

Implementation: for each tool returned by `tools/list`, run
`findConstraint(toolName)` and log a warning when a _glob_ entry (one
containing `*`, `?`, or `[`) is the matching entry. Exact-name matches
are intentional by definition; glob matches for new tools require
operator review.

**1b. Manifest entry matches no upstream tool (FM-2).**

```
WARN  manifest entry "query_db" matches no tool in the upstream server
      (tool removed or renamed?) — entry is a dead reference
```

Implementation: for each manifest `resource` entry, check whether any
tool in the live list matches it. If not, log a warning.

**1c. Upstream tool matches no manifest entry.**

```
INFO  upstream tool "summarise_document" is not covered by the manifest
      — all calls will be denied (allowlist semantics)
```

This is informational, not a warning — deny-by-default is correct
behaviour. But surfacing uncovered tools helps policy authors know when
a server has grown new capabilities they should evaluate.

The startup check runs in the background; it does not block session
establishment. All three message types are structured (key=value or
JSON) so they can be ingested by log aggregators.

A `--strict-drift` flag promotes the glob-match warning (1a) and
dead-reference warning (1b) to startup errors, aborting the session.
Appropriate for production deployments where any policy drift must be
resolved before traffic is admitted.

### Fix 2 — `eunox-mcp validate --live` subcommand (medium effort)

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

### Fix 3 — Argument schema pinning via `argumentSchema` (low effort)

The `argumentSchema` field on a capability constraint already exists
and is already validated by the proxy (`validateSchema` in
`cmd/mcp/pdp.go`). Pinning the schema of each tool in the manifest
converts FM-3 from a silent bypass into an explicit startup failure.

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

When the server renames `path` to `file_path`, the proxy rejects the
call at schema validation with `ARGUMENT_VALIDATION_FAILED` rather than
silently skipping the `allowedValues` condition. The operator sees an
immediate, explicit error rather than a silent policy gap.

The `--live` validation mode (Fix 2) auto-generates the `argumentSchema`
block from `tools/list` and flags drift between the pinned schema and
the live schema:

```
⚠ read_file: argument "path" (pinned) not found in live schema
             live schema has: file_path (string), encoding (string)
             → update argumentSchema and allowedValues.argument
```

### Fix 4 — `eunox-mcp init` scaffold (medium effort)

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

| Fix | Effort | Addresses | Priority |
|---|---|---|---|
| Fix 1 — Startup drift warnings | Low | FM-1, FM-2 | **Before MVP** |
| Fix 3 — `argumentSchema` pinning | Low | FM-3 | **Before MVP** (field already exists; document the pattern) |
| Fix 2 — `validate --live` | Medium | FM-1, FM-2, FM-3 | **Post-MVP milestone** |
| Fix 4 — `init` scaffold | Medium | Authoring UX | **Post-MVP milestone** |
| FM-4 — Behavior drift | Not solvable at proxy | — | Supply-chain / deployment controls |

---

## Impact on the MVP release checklist

The release checklist should include a **Stage 4** documentation item:

> Confirm that the upstream MCP server version deployed in the demo
> matches the version used when the manifest was authored. If the
> server has been updated since the manifest was last reviewed, run
> `eunox-mcp validate` and inspect the tool list manually.

Until Fix 1 (startup warnings) ships, operators must verify manifest
currency manually on every server update.

# MCP Enforcement Gap Analysis

**Date:** 2026-05-31  
**Status:** Discovery / decision pending  
**Context:** eunox-mcp MVP (v0.1.0) enforces policy only on `tools/call`. The
MCP 2025-11-25 protocol defines a broader message surface. This report
catalogues the unguarded methods, assesses their risk, and recommends
what to address before the MVP ships vs. what to defer.

---

## Background

The proxy intercepts every JSON-RPC message that flows between the MCP
host (Claude Desktop, LangChain, etc.) and the upstream MCP server.
Its routing logic has three branches:

```
msg.Method == "initialize"  → proxy answers directly (no upstream call)
msg.Method == "tools/call"  → PDP enforcement → conditional upstream call
anything else               → forwarded verbatim to upstream
```

Everything in the third branch bypasses the capability manifest entirely.
The following sections audit that surface.

---

## Gap inventory

### Gap 1 — `resources/read` (Severity: **High**)

**What it is.** MCP servers can expose _resources_ — files, database rows,
API results, live data feeds — identified by a URI (e.g.
`file:///data/customers.csv`, `db://warehouse/orders`). A host reads a
resource by sending `resources/read` with that URI.

**What currently happens.** The request is forwarded verbatim. The manifest
is not consulted. An agent can read any resource the server exposes,
regardless of what the manifest permits.

**Risk.** This is the same class of problem that `tools/call` enforcement
solves, applied to the resource primitive. A manifest that carefully
restricts which _tools_ the agent can call silently permits unrestricted
_resource_ access. In practice, MCP servers that expose sensitive data
frequently do so via resources rather than tools (e.g. the filesystem
server, the database server, the GitHub server's repository contents).

**Exploitability.** Moderate to high. Requires the upstream server to
expose resources _and_ the agent or a prompt-injection payload to know
the resource URI. Discovery via `resources/list` (also unguarded — see
Gap 2) lowers this bar significantly.

**Effort to fix.** Low-to-medium. The enforcement engine already supports
glob-based resource patterns, `allowedValues` conditions (for URI
filtering), and the full condition set. The proxy needs to route
`resources/read` through `handleHTTPToolsCall`-equivalent logic, using
the resource URI as the tool name for matching. No new manifest syntax
is required — the existing `resource` field and `actions` vocabulary
apply directly:

```yaml
capabilities:
  - resource: "file:///data/reports/*"   # resource URI glob
    actions: [read]
```

---

### Gap 2 — `tools/list` (Severity: **Medium**)

**What it is.** `tools/list` returns the full catalogue of tools the
upstream server exposes. The host uses this list to know what it can
call; the LLM uses it to decide what to invoke.

**What currently happens.** The full tool list is returned to the host
unfiltered. The host and model see every tool the server exposes, even
tools that the manifest blocks from being called.

**Risk.** Two issues:

1. **Capability surface leakage.** An agent (or an attacker who has
   achieved prompt injection) can enumerate all available tools —
   including blocked ones — by issuing `tools/list`. This gives a
   detailed map of what to attempt.

2. **Model confusion.** The LLM receives descriptions for tools it
   cannot call. If it attempts them it gets a denial with an error
   message that reveals the manifest's structure. At scale, a
   manipulated model can use repeated denied calls to probe the
   policy boundary.

**Exploitability.** Low standalone risk — an attacker still cannot
_call_ a blocked tool — but it meaningfully aids other attacks.

**Effort to fix.** Low. The proxy already holds the manifest at the time
`tools/list` is received. Filtering the upstream response to only
include tools whose names match at least one manifest `resource` entry
is a straightforward post-processing step. No new manifest syntax needed.

---

### Gap 3 — `resources/list` and `resources/subscribe` (Severity: **Low–Medium**)

**What it is.** `resources/list` enumerates available resources.
`resources/subscribe` establishes a live update channel for a specific
resource URI.

**What currently happens.** Both are forwarded verbatim.

**Risk.** `resources/list` has the same discovery-aid problem as
`tools/list` (Gap 2) applied to resources. `resources/subscribe` is
more concerning: it opens an ongoing channel for data to flow to the
host without any per-read policy check. If Gap 1 is fixed
(`resources/read` enforcement) but `resources/subscribe` is left open,
a determined agent can use subscriptions to receive resource updates
continuously.

**Exploitability.** Low without Gap 1 also being exploited. Addressed
naturally once `resources/read` is enforced — subscriptions should be
subject to the same resource policy as reads.

**Effort to fix.** Medium (filtering `resources/list`); High
(`resources/subscribe` requires stateful tracking of subscriptions
against the manifest, plus enforcement on the async update stream).

---

### Gap 4 — `prompts/get` (Severity: **Medium**)

**What it is.** MCP servers can expose _prompts_ — named, parameterised
instruction templates that the host injects into the conversation. A
prompt is not static text; it is executable model instruction.

**What currently happens.** `prompts/get` is forwarded verbatim. Any
agent can retrieve any prompt the server exposes.

**Risk.** A prompt is a policy bypass vector. A manifest can block
`write_file` as a tool call, but a prompt retrieved via `prompts/get`
can instruct the model to call `write_file` as part of a multi-turn
plan. The proxy never sees the instruction in that form — it only sees
the resulting `tools/call`, which it does enforce. However, a malicious
prompt can construct chains that collectively circumvent individual
tool-call restrictions.

Additionally, prompt templates can themselves contain sensitive data
(system instructions, internal API schemas, operational runbooks) that
an agent should not be able to exfiltrate by reading them.

**Exploitability.** Moderate. Requires a server that exposes prompts _and_
a model that follows injected prompt instructions without resistance.

**Effort to fix.** Medium. Requires deciding on the manifest vocabulary
for prompts (prompt names vs. resource URIs) and adding a `prompts/get`
enforcement branch. No new condition types needed. Prompt _filtering_
(inspecting prompt content for policy violations) is a separate, much
harder problem (LLM-based) and is out of scope.

---

### Gap 5 — `sampling/createMessage` (Severity: **High**; direction: server→client)

**What it is.** MCP 2025-11-25 allows the _server_ to request that the
_host LLM_ generate a message — the reverse of the normal flow. The
server sends `sampling/createMessage` to the proxy, which forwards it
to the host, which calls the model and returns the result to the server.

**What currently happens.** The request is forwarded verbatim in both
directions. The manifest is not consulted.

**Risk.** This is the most structurally dangerous gap in the current
proxy architecture. A compromised, malicious, or prompt-injected
upstream server can:

- **Exfiltrate conversation history** by requesting a model completion
  that summarises or repeats it.
- **Invoke tool calls indirectly** by generating model output that
  contains tool invocations the host then executes.
- **Impersonate the user** by generating messages in the user's voice.
- **Escape the session context** by establishing a separate model
  dialogue the operator cannot see.

The current proxy enforces what the _agent_ requests. `sampling/createMessage`
is a channel the _server_ controls, which means any enforcement model
built only around agent behaviour is insufficient if this channel is
open.

**Exploitability.** Requires the host to support the `sampling` capability
(Claude Desktop does; not all hosts do). If supported, the risk is real
and requires no agent cooperation — the server acts alone.

**Effort to fix.** High. Requires:

1. A new enforcement direction (server→client) and a new manifest
   concept — the existing `resource`/`actions` model is agent→server
   only.
2. Deciding what "allow/deny sampling" means in policy terms
   (per-server allowlist? max tokens? allowed model parameters?).
3. Inspecting and potentially rejecting the _result_ of sampling before
   returning it to the server — currently there is no hook for this.

A minimal first step — **denying `sampling/createMessage` by default
unless the manifest explicitly allows it** — is low effort and
eliminates the most dangerous failure mode. Full parametric control is
a post-MVP workstream.

---

## Priority matrix

| Gap | Severity | Exploitability | Effort | MVP? |
|---|---|---|---|---|
| Gap 5 — `sampling/createMessage` | High | High (if host supports it) | Medium (deny-by-default) / High (full control) | **Yes — deny-by-default** |
| Gap 1 — `resources/read` | High | Moderate | Low–Medium | **Yes** |
| Gap 2 — `tools/list` filtering | Medium | Low | Low | **Yes** |
| Gap 4 — `prompts/get` | Medium | Moderate | Medium | **Borderline — see below** |
| Gap 3 — `resources/list` filtering | Low–Medium | Low | Low | No |
| Gap 3 — `resources/subscribe` | Low–Medium | Low | High | No |

---

## Recommendations

### Ship before MVP

**Gap 5 — deny `sampling/createMessage` by default.**
The implementation cost is minimal: add `"sampling/createMessage"` to
the enforced method set and return a JSON-RPC error unless the manifest
explicitly contains a `sampling` capability entry (or a new
`--allow-sampling` flag). This converts a high-severity open channel
into an explicit opt-in. Operators who need server-initiated sampling
can enable it; everyone else is protected without writing any new
manifest entries.

**Gap 1 — enforce `resources/read`.**
Extend the PDP routing to intercept `resources/read` and run it through
the same `findConstraint`/condition-evaluation path as `tools/call`,
using the resource URI as the match target. Manifests that do not
include resource entries deny all resource reads by default — consistent
with the existing allowlist semantics for tools. This closes the most
direct data-exfiltration path and is essential for servers that expose
sensitive data as resources (filesystem, database, GitHub content).

**Gap 2 — filter `tools/list` to permitted tools.**
The proxy holds the manifest; filtering the upstream `tools/list`
response to only the entries whose tool names match a manifest
`resource` pattern is a small post-processing step. This eliminates
the capability-surface leak and reduces the information available
to prompt-injection attacks.

### Defer to post-MVP

**Gap 4 — `prompts/get`.** The risk is real but the manifest vocabulary
for prompt-name matching is not designed yet, and the harder problem
(prompt _content_ inspection) is out of scope for any near-term release.
Defer, but document that `prompts/get` is unguarded so operators can
choose upstream servers that do not expose sensitive prompts.

**Gap 3 — `resources/list` and `resources/subscribe`.** List filtering
is low effort but low impact (Gap 2 is the more important discovery
gap). Subscribe is high effort. Both should wait until Gap 1 is shipped
and the resource policy model is established.

---

## Impact on the MVP release checklist

The checklist item **Stage 4 — Documentation review** should include a
note that `prompts/get`, `resources/list`, and `resources/subscribe`
are currently unguarded. Users who deploy eunox-mcp v0.1.0 against
servers that expose resources or prompts should be aware of these limits.

If Gap 5 and Gap 1 are resolved before tagging v0.1.0, the proxy's
security posture for the two highest-severity gaps is adequate for an
MVP. If they are not resolved, v0.1.0 should be released with an
explicit advisory in the README noting that resource access and
server-initiated sampling are not currently policy-controlled.

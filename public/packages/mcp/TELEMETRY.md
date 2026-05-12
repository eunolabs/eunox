# Telemetry

`@euno/mcp` collects **anonymous, aggregate usage counts** to help the team
understand how the tool is used and prioritize improvements.

No tool names, argument values, file paths, SQL fragments, or any payload
content is ever transmitted.  All telemetry is **opt-in** (default: **off**).

---

## How it works

On the first run that can reach an interactive terminal, `euno-mcp` shows a
one-time prompt:

```
[euno-mcp] Help improve euno-mcp with anonymous usage counts.
  What's collected: version, OS, Node.js major, session counts,
  and denial-type counts (e.g. "maxCalls: 2").  No tool names,
  argument values, file paths, or any payload content — ever.
  Full schema: https://github.com/edgeobs/euno/blob/main/public/packages/mcp/TELEMETRY.md
  Disable any time: EUNO_TELEMETRY=0
Enable anonymous telemetry? [y/N]
```

Your answer is persisted to `~/.euno/telemetry` and never asked again.  In
non-interactive environments (e.g. Claude Desktop's MCP config, CI pipelines)
the prompt is skipped and telemetry defaults to **off**.

---

## How to disable

Three ways to opt out:

| Method | Effect |
| --- | --- |
| Answer **N** (or press Enter) at the prompt | Persists `enabled: false` to `~/.euno/telemetry` |
| `EUNO_TELEMETRY=0` env var | Disables entirely — no prompt, no file, no network |
| Delete / edit `~/.euno/telemetry` | Set `"enabled": false` in the JSON |

`EUNO_TELEMETRY=0` always wins over the consent file.

---

## How to inspect what would be sent

Set `EUNO_TELEMETRY_LOCAL=1` to write each event to `~/.euno/telemetry.jsonl`
instead of sending it over the network.  This lets you verify the exact payload
before deciding whether to opt in:

```sh
EUNO_TELEMETRY=1 EUNO_TELEMETRY_LOCAL=1 euno-mcp validate ./policy.yaml
cat ~/.euno/telemetry.jsonl
```

---

## Event schema

One JSON event is emitted per CLI invocation.  Every field is documented below.

| Field | Type | Description |
| --- | --- | --- |
| `installId` | `string` | Anonymous UUID created on first run and persisted to `~/.euno/telemetry`.  Never regenerated once set.  No machine fingerprinting — this is a random UUID. |
| `version` | `string` | Installed package version (e.g. `"1.2.0"`). |
| `osFamily` | `string` | Broad OS family: `"linux"`, `"darwin"`, `"win32"`, or `"other"`.  No OS version or kernel info. |
| `nodeMajor` | `number` | Major Node.js version number (e.g. `20`).  No patch or minor. |
| `subcommand` | `string` | CLI subcommand invoked: `"proxy"`, `"validate"`, `"kill"`, `"validate-token"`, or `"stats"` for client-side events; `"hosted-enforce"` for server-side events emitted by the tool-gateway's `GatewayTelemetryCollector` (see §Hosted-mode server-side events below). |
| `sessionsStarted` | `number` | Number of MCP sessions started.  Always `1` for a stdio proxy run; may be higher for an HTTP proxy with multiple clients. |
| `sessionsWithEnforcement` | `number` | Number of those sessions that had at least one `tools/call` enforcement event (allow or deny). |
| `denialsByConditionType` | `object` | Map from condition type name to denial count.  Keys are the `CapabilityCondition.type` values (`"maxCalls"`, `"timeWindow"`, `"allowedOperations"`, etc.) plus `"argumentSchema"` and `"kill"` for the special denial paths.  **No tool names are included.** |
| `peakConcurrentSessions` | `number` | Peak number of MCP sessions that were active simultaneously during this invocation.  `0` when no session was established (e.g. upstream connection failed before `onSessionStart` ran).  `1` for a successful stdio proxy run.  May be higher for an HTTP proxy serving multiple clients concurrently, providing a privacy-preserving signal of shared team usage.  No user identifiers, IPs, or hostnames are captured — only the peak count. |
| `upstreamServerName` | `string` | The upstream MCP server name, sanitized against a known-OSS-package allow-list.  Reported verbatim for known packages (e.g. `"@modelcontextprotocol/server-filesystem"`); reported as `"custom"` for any other command.  Never includes file paths or arbitrary arguments. |
| `timestamp` | `number` | Unix epoch milliseconds when the event was emitted. |

### Example event

```json
{
  "installId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "version": "1.0.0",
  "osFamily": "darwin",
  "nodeMajor": 20,
  "subcommand": "proxy",
  "sessionsStarted": 1,
  "sessionsWithEnforcement": 1,
  "denialsByConditionType": { "maxCalls": 3 },
  "peakConcurrentSessions": 1,
  "upstreamServerName": "@modelcontextprotocol/server-filesystem",
  "timestamp": 1736000000000
}
```

---

## Where it goes

Events are sent via a single `POST` request to `https://telemetry.euno.dev/v1/events`
with a `Content-Type: application/json` body.  The request has a 5-second
timeout; if it fails (network error, non-2xx response, timeout) the error is
silently discarded — telemetry never affects proxy operation.

Override the endpoint with `EUNO_TELEMETRY_URL`:

```sh
EUNO_TELEMETRY_URL=https://your-collector.example.com/events euno-mcp proxy -- ...
```

---

## State file: `~/.euno/telemetry`

A small JSON file persisted to your home directory:

```json
{
  "installId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "enabled": true,
  "promptedAt": "2025-01-01T00:00:00.000Z"
}
```

Delete or set `"enabled": false` to opt out without touching env vars.

---

## Local-mode output: `~/.euno/telemetry.jsonl`

When `EUNO_TELEMETRY_LOCAL=1` is set, each event is appended to this file
instead of being sent over the network.  The file is in JSONL format (one JSON
object per line), so it can be inspected with standard tools:

```sh
cat ~/.euno/telemetry.jsonl | jq .
```

---

## Hosted-mode server-side events

When the **tool-gateway** is deployed in hosted mode (Stage 3), the
`GatewayTelemetryCollector` (added in Task 16) emits server-side analytics
events to the same `https://telemetry.euno.dev/v1/events` endpoint so
Stage 1–2 dashboards remain valid without schema changes.

### Key differences from client-side events

| Field | Client-side value | Server-side value |
| --- | --- | --- |
| `subcommand` | `"proxy"` / `"validate"` / etc. | `"hosted-enforce"` |
| `installId` | Random UUID (per install) | `"tenant:" + tenantId` (per tenant) |
| `upstreamServerName` | Upstream MCP command | `"gateway"` |
| `sessionsStarted` | Sessions in this process run | Unique session IDs in the 5-min window |
| `peakConcurrentSessions` | Peak for this process | Max sessions within any 60-s window |

All other field names and types are identical so a single dashboard query can
aggregate both event types.  Filter on `subcommand = 'hosted-enforce'` to
isolate server-side rows.

### Privacy model for hosted-mode events

- `installId = 'tenant:' + tenantId` — identifies the organisation (not any
  individual user or session).  No user IDs, IP addresses, or session IDs.
- `denialsByConditionType` keys are condition type names (`"maxCalls"`,
  `"timeWindow"`, etc.) — **no tool names or argument values**.
- `peakConcurrentSessions` is derived from counting unique session IDs in a
  60-second sliding window.  No session IDs leave the gateway.

### Opt-out (server-side)

Set `EUNO_TELEMETRY=0` on the gateway host to disable server-side telemetry
entirely.  Default: enabled (the operator controls the server; there is no
interactive prompt).

```sh
EUNO_TELEMETRY=0 docker run ... euno/tool-gateway
```

### Configuration (server-side)

| Env var | Default |
| --- | --- |
| `EUNO_TELEMETRY` | (unset = enabled; `0` = disabled) |
| `EUNO_TELEMETRY_URL` | `https://telemetry.euno.dev/v1/events` |
| `GATEWAY_TELEMETRY_FLUSH_MS` | `300000` (5 minutes) |

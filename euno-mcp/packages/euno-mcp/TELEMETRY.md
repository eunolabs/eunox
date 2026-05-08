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
  Full schema: https://github.com/edgeobs/euno/blob/main/euno-mcp/packages/euno-mcp/TELEMETRY.md
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
| `subcommand` | `string` | CLI subcommand invoked: `"proxy"`, `"validate"`, or `"kill"`. |
| `sessionsStarted` | `number` | Number of MCP sessions started.  Always `1` for a stdio proxy run; may be higher for an HTTP proxy with multiple clients. |
| `sessionsWithEnforcement` | `number` | Number of those sessions that had at least one `tools/call` enforcement event (allow or deny). |
| `denialsByConditionType` | `object` | Map from condition type name to denial count.  Keys are the `CapabilityCondition.type` values (`"maxCalls"`, `"timeWindow"`, `"allowedOperations"`, etc.) plus `"argumentSchema"` and `"kill"` for the special denial paths.  **No tool names are included.** |
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

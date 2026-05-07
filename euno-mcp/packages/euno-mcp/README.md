# @euno/mcp

> **Status:** Stage 1 — stdio proxy transport is live.

`@euno/mcp` is the [Model Context Protocol](https://spec.modelcontextprotocol.io/) bridge for [Euno](https://github.com/edgeobs/euno).  It lets MCP hosts (Claude Desktop, Cursor, Windsurf, …) talk to Euno-governed tool registries without any BUSL-licensed server-side components.

## Quick start

```sh
# Drop euno-mcp in front of the filesystem MCP server:
npx @euno/mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Or with a capability policy (Phase B):
npx @euno/mcp proxy --policy ./policy.yaml -- node ./my-mcp-server.js
```

Add it to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem-governed": {
      "command": "npx",
      "args": [
        "@euno/mcp", "proxy",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

## Commands

| Command | Description |
|---------|-------------|
| `euno-mcp proxy -- <upstream-cmd> [args...]` | Start the stdio proxy |
| `euno-mcp validate <policy-file>` | Validate a policy file (Phase B) |
| `euno-mcp --help` | Show all options |

## Protocol compatibility

`@euno/mcp` targets the `2025-11-25` MCP protocol revision and accepts connections from hosts advertising any revision within the support window.  See [docs/mcp-support.md](../../docs/mcp-support.md) for the full version policy, upgrade procedure, and the list of accepted revisions.

The pinned version constant is exported as `MCP_PROTOCOL_VERSION` from the package:

```ts
import { MCP_PROTOCOL_VERSION, MCP_SUPPORTED_PROTOCOL_VERSIONS } from '@euno/mcp';
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).

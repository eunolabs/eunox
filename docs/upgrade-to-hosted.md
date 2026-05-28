# Upgrading from Local to Hosted Enforcement

This guide explains how to migrate from local in-process enforcement
(`enforcer: "local"`) to the hosted eunox gateway (`enforcer: "https://…"`).

> **TL;DR** — For most users the quickest path is the interactive CLI command:
>
> ```bash
> eunox-mcp upgrade-to-hosted \
>   --gateway-url https://gateway.eunox.example \
>   --api-key sk-x7Kp9mRq.bL3nYv2w...
> ```
>
> See [§ Automated upgrade (recommended)](#automated-upgrade-recommended)
> for the full command reference.

---

## Why upgrade?

| Feature                      | Local (`enforcer: "local"`) | Hosted (`enforcer: "https://…"`)                      |
| ---------------------------- | --------------------------- | ----------------------------------------------------- |
| Enforcement location         | In each agent process       | Centralised gateway                                   |
| Policy updates               | Edit file, restart agent    | Update via admin API — all agents pick up immediately |
| Audit log                    | File on each laptop         | Centralised, queryable via API                        |
| Kill-switch                  | Local only                  | Gateway-wide (revoke all sessions instantly)          |
| Cryptographic audit evidence | Optional (HMAC)             | KMS-signed per-decision evidence                      |
| Multi-agent / team support   | Manual policy sync          | Single policy, all agents                             |

---

## Prerequisites

1. **An eunox API key** (`sk-<prefix>.<secret>`) from the eunox Cloud console or
   your self-hosted gateway admin. Your key needs at least the `enforce` scope.
2. **The gateway URL** — the base URL of your minter / gateway service.
3. **Optional — an admin API key** to upload your local policy file to the
   hosted store.

---

## Automated upgrade (recommended)

The `eunox-mcp upgrade-to-hosted` command performs the three migration steps
in sequence and backs up any config files it modifies.

### Step 1 — Validate your API key (connectivity check)

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.eunox.example \
  --api-key sk-x7Kp9mRq.bL3nYv2w...
```

The command:

1. Checks that `{gatewayUrl}/health` is reachable.
2. Calls `GET {gatewayUrl}/api/v1/ping` with your API key as a Bearer token
   and prints your tenant ID, policy ID, and scopes.
3. Discovers and patches `claude_desktop_config.json` (and any `--config`
   paths you supply) to replace `--policy <file>` with
   `--enforcer-url <url> --enforcer-api-key <key>`.

### Step 2 — Also upload your local policy (optional)

If you want to copy your existing local policy file to the hosted store so
that the gateway uses the same rules:

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.eunox.example \
  --api-key  sk-x7Kp9mRq.bL3nYv2w... \
  --admin-key <admin-key>  \
  --policy    ./eunox.policy.yaml
```

The command calls `POST {gatewayUrl}/admin/v1/policies` and updates the
`capabilities` array on every API key that shares the same `policyId`.

### Preview changes without writing anything

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.eunox.example \
  --api-key sk-x7Kp9mRq.bL3nYv2w... \
  --policy ./eunox.policy.yaml --admin-key <admin-key> \
  --dry-run
```

### Patch additional config files

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.eunox.example \
  --api-key sk-x7Kp9mRq.bL3nYv2w... \
  --config /path/to/custom/mcp.json
```

Config files are backed up before modification as
`<file>.bak.<YYYYMMDDHHmmss>`. To roll back:

```bash
cp claude_desktop_config.json.bak.20260512123045 claude_desktop_config.json
```

---

## Manual upgrade path

If you prefer to perform the migration yourself or the automated command is
not suitable for your environment, follow these steps.

### Step 1 — Validate your API key

```bash
curl -s \
  -H "Authorization: Bearer sk-x7Kp9mRq.bL3nYv2w..." \
  https://gateway.eunox.example/api/v1/ping | jq .
# Expected: { "valid": true, "tenantId": "…", "policyId": "…", "scopes": […] }
```

Note the `policyId` value — you will need it in Step 2.

### Step 2 — Upload your policy (optional)

If you want the hosted gateway to use your local policy's capabilities:

```bash
POLICY_ID="policy-1"          # from Step 1 output
GATEWAY_URL="https://gateway.eunox.example"
ADMIN_KEY="<admin-api-key>"   # issued by eunox console or your admin

curl -s -X POST "${GATEWAY_URL}/admin/v1/policies" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d "{
    \"policyId\": \"${POLICY_ID}\",
    \"manifest\": $(cat ./eunox.policy.yaml | python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)))')
  }" | jq .
# Expected: { "policyId": "…", "updatedKeys": 1, "capabilityCount": 3 }
```

> **Note:** The command above uses Python's `yaml` module to convert the YAML policy to JSON.
> You can also write the manifest directly as JSON.

### Step 3 — Update Claude Desktop config

Locate `claude_desktop_config.json`:

| Platform | Default path                                                      |
| -------- | ----------------------------------------------------------------- |
| macOS    | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows  | `%APPDATA%\Claude\claude_desktop_config.json`                     |
| Linux    | `~/.config/Claude/claude_desktop_config.json`                     |

Open the file and find your `eunox-mcp proxy` entry. Change:

```json
{
  "mcpServers": {
    "my-mcp-server": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "./eunox.policy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp"
      ]
    }
  }
}
```

to:

```json
{
  "mcpServers": {
    "my-mcp-server": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--enforcer-url",
        "https://gateway.eunox.example",
        "--enforcer-api-key",
        "sk-x7Kp9mRq.bL3nYv2w...",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp"
      ]
    }
  }
}
```

Save the file and restart Claude Desktop.

### Step 4 — Verify

Start an MCP session and perform a `tools/call`. The audit log on the
gateway should record the enforcement event. You can also check the local
audit file (`~/.eunox/audit.jsonl`) for any `GATEWAY_UNAVAILABLE` denials
that would indicate the gateway is unreachable.

---

## Rollback

To revert to local enforcement:

1. Restore your config backup:
   ```bash
   cp claude_desktop_config.json.bak.<timestamp> claude_desktop_config.json
   ```
2. Restart Claude Desktop.

Your local policy file is unchanged by the upgrade and will be used again
once the config points back to `--policy <file>`.

---

## Troubleshooting

| Error                          | Likely cause                     | Fix                                                     |
| ------------------------------ | -------------------------------- | ------------------------------------------------------- |
| `API key is not valid`         | Wrong `--api-key` or key revoked | Check the key in the eunox console                      |
| `HTTP 503 from /health`        | Gateway unreachable              | Check `--gateway-url` and network connectivity          |
| `Admin key rejected`           | Wrong `--admin-key`              | Verify the admin key in the eunox console               |
| `manifest validation failed`   | Policy file has schema errors    | Run `eunox-mcp validate --policy <file>` to see details |
| `GATEWAY_UNAVAILABLE` in audit | Gateway down during enforcement  | Gateway is unreachable; fail-closed deny was applied    |

# Reference Policies

Pre-built `euno.policy.yaml` files for the most common upstream MCP servers.
Drop one in your project, run `euno-mcp validate <file>`, and pass it to
`euno-mcp proxy --policy <file>` to enforce it immediately.

---

## Available policies

| File | Upstream server | One-line summary |
|------|-----------------|------------------|
| [`filesystem.policy.yaml`](./filesystem.policy.yaml) | `@modelcontextprotocol/server-filesystem` | Reads limited to safe extensions; writes confined to `/data/`; executables blocked |
| [`postgres.policy.yaml`](./postgres.policy.yaml) | `@modelcontextprotocol/server-postgres` | SELECT-only on approved business tables; DDL/DML writes blocked |
| [`github.policy.yaml`](./github.policy.yaml) | `@modelcontextprotocol/server-github` | Read tools unrestricted; write tools rate-limited to prevent runaway automation |
| [`slack.policy.yaml`](./slack.policy.yaml) | `@modelcontextprotocol/server-slack` | Direct messages restricted to `company.com` via recipientDomain; message bursts rate-limited |
| [`fetch.policy.yaml`](./fetch.policy.yaml) | `mcp-server-fetch` | HTTPS-only; userinfo authority blocked; private RFC-1918 ranges and metadata endpoint blocked (lexical SSRF guard — combine with network egress controls) |

---

## Quick start

```bash
# 1. Validate the policy file
npx -y @euno/mcp validate ./policies/postgres.policy.yaml

# 2. Run the proxy with the policy
npx -y @euno/mcp proxy \
  --policy ./policies/postgres.policy.yaml \
  -- npx -y @modelcontextprotocol/server-postgres postgres://localhost/mydb
```

---

## Adapting a policy for your setup

Each file is a plain YAML [AgentCapabilityManifest](https://github.com/edgeobs/euno/blob/main/public/packages/common/src/types.ts).
Copy the relevant file, adjust the `agentId`, extend the `allowedTables` / `domains`
lists, and re-validate. The `euno-mcp validate` command exits 0 on success and
prints a structured error on failure.

```bash
cp policies/slack.policy.yaml my-slack.policy.yaml
# Edit my-slack.policy.yaml — change company.com to your domain
npx -y @euno/mcp validate my-slack.policy.yaml
```

---

## CI validation

To assert that every policy in this directory validates cleanly in CI, run:

```bash
npx -y @euno/mcp validate policies/filesystem.policy.yaml
npx -y @euno/mcp validate policies/postgres.policy.yaml
npx -y @euno/mcp validate policies/github.policy.yaml
npx -y @euno/mcp validate policies/slack.policy.yaml
npx -y @euno/mcp validate policies/fetch.policy.yaml
```

Or use the Jest test suite:

```bash
npm run -w @euno/mcp test -- --testPathPattern=policies
```

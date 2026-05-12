# Migrating from Local Mode to Hosted Gateway

> **Audience:** Developers and platform engineers who have deployed `@euno/mcp`
> in local-enforcement mode and want to migrate to the hosted Euno gateway for
> shared state, persistent audit, and managed key infrastructure.
>
> **Related documents:**
> - [`docs/self-host.md`](./self-host.md) — BYO-GW path for teams who want to
>   run all infrastructure themselves
> - [`docs/stage-3-design.md`](./stage-3-design.md) — authoritative Stage-3
>   architecture decisions
> - [`docs/stage-3-gateway-protocol.md`](./stage-3-gateway-protocol.md) — wire
>   protocol reference for the `/api/v1/enforce` endpoint
> - [`docs/enforcement.md`](./enforcement.md) — cryptographic-token invariant
>   and security model

---

## 1. The before / after

### Local mode (Stage 1–2)

Policy lives in a YAML file on disk. All enforcement logic runs inside the
`@euno/mcp` process. State (call counters, kill-switch) is scoped to a single
process and lost on restart. The audit log is a local HMAC-signed JSONL file.

```jsonc
// claude_desktop_config.json — local enforcement (no change required)
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--policy", "/path/to/euno.policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

```bash
# Or on the CLI:
euno-mcp proxy --policy ./euno.policy.yaml -- node ./my-mcp-server.js
```

### Hosted mode (Stage 3)

Policy lives in the gateway's policy store. Enforcement runs on the hosted
gateway, which holds shared Redis state (call counters, kill-switch, revocation
list) and writes to a persistent Postgres audit ledger. The `@euno/mcp` proxy
becomes a thin forwarding layer: it intercepts `tools/call`, sends an
`EnforceRequest` to `POST /api/v1/enforce`, and applies the returned obligations
before forwarding the upstream response.

```jsonc
// claude_desktop_config.json — hosted enforcement (the one config change)
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--enforcer-url", "https://gateway.euno.example",
        "--enforcer-api-key", "sk-x7Kp9mRq.bL3nYv2wQs...",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

```bash
# Or on the CLI:
euno-mcp proxy \
  --enforcer-url https://gateway.euno.example \
  --enforcer-api-key sk-x7Kp9mRq.bL3nYv2wQs... \
  -- node ./my-mcp-server.js
```

`--enforcer-url` and `--policy` are mutually exclusive. No policy file is
needed in hosted mode — your policy is stored and managed in the gateway.

### What changes, what stays the same

| Aspect | Local mode | Hosted mode |
|---|---|---|
| Policy file on disk | Required | Not used |
| Enforcement engine | In-process PDP | Gateway PDP |
| Call counters | In-memory, per-process | Redis, shared across replicas |
| Kill-switch | In-memory, per-process | Gateway global, Redis-backed |
| Audit log | `~/.euno/audit.jsonl` (HMAC) | Postgres ledger (KMS-signed) |
| Custom conditions | `--custom-condition` flags | Registered on the gateway |
| Policy backends | `--policy-backend` flags | Registered on the gateway |
| `euno-mcp stats` | Works on local audit log | Not applicable — use the audit query API |
| `euno-mcp validate-token` | Verifies local HMAC | Not applicable in hosted mode |
| Fail behavior on infra error | Local PDP is always reachable | Network error → deny (fail-closed) |

---

## 2. The cryptographic story — why the API key is not a token

This is the most important thing to understand before migrating.

### The invariant

Every enforcement decision in euno must be backed by a **signed JWT capability
token** (see [`docs/enforcement.md`](./enforcement.md) and
[`docs/capability-model.md`](./capability-model.md)). The gateway's verifier
validates the JWT signature against a JWKS endpoint before running any policy.
This is non-negotiable: it is the cryptographic-token invariant the entire
system rests on.

### The API key's role

The `sk-...` API key you put in `--enforcer-api-key` is a **long-lived bearer
secret**, not a capability token. It has no cryptographic binding to any
specific capability, policy, or expiry. It is essentially a password.

The API key cannot pass through the gateway's JWT verifier directly. If it
could, the entire cryptographic-token invariant would be vacuous — any bearer
credential could claim any capability.

### The minter façade

To preserve the one-config-change upgrade promise without weakening the security
model, the hosted gateway includes an **API-key minter façade** between `@euno/mcp`
and the internal enforcement endpoint:

```
@euno/mcp
    │
    │  sk-... API key
    ▼
Minter façade  ←── HSM-backed tenant signing key
    │
    │  Looks up your tenant ID, policy ID, and policy hash from the key.
    │  Mints a short-lived signed JWT (TTL ≤ 5 min) using the tenant's
    │  Azure Managed HSM / AWS KMS / GCP Cloud KMS key.
    │  Writes a mint-audit row (caller identity + tenant + policy hash + JWT jti).
    │
    │  JWT capability token (signed by HSM key)
    ▼
POST /api/v1/enforce
    │
    │  Full PDP: JWT signature verification → kill-switch → condition evaluation
    ▼
EnforceResponse (allow/deny + obligations)
```

What this buys you:

1. **Auditability.** Every enforcement decision is backed by a minted JWT that
   was written to an immutable, append-only mint-audit store. Every token has a
   `jti` (JWT ID) and a `policy_hash` that prove what policy was in effect when
   the token was issued.

2. **Revocability.** If an API key is compromised, you revoke it in the gateway.
   Previously minted JWTs (TTL ≤ 5 min) can be individually revoked by `jti` via
   the revocation list. At most 5 minutes of blast radius per key compromise, and
   the gateway's kill-switch closes the window immediately for running sessions.

3. **Key isolation.** Signing uses a per-tenant HSM key, not a platform-wide
   shared secret. Compromise of one tenant's signing key does not affect any
   other tenant.

4. **Non-exportability.** The HSM key cannot be downloaded from the HSM
   regardless of caller RBAC — the HSM boundary enforces this, not policy
   configuration. An attacker who compromises minter credentials can trigger
   signs but cannot steal the private key material.

### Why not accept the API key directly at the gateway?

Directly accepting API keys at the enforcement endpoint would require the
gateway to understand two authentication modes (JWT and API key). The JWT path
is already the only correct path — it ensures every enforcement decision is
cryptographically attributable to a specific token issuance, with a specific
expiry and a specific policy fingerprint. The API key is a convenience layer
that sits in front of the cryptographic path, not a replacement for it.

---

## 3. Data that leaves your network in hosted mode

This section is the explicit data-boundary analysis for SOC2 / GDPR review.

### Data sent to the gateway on every `tools/call`

When `@euno/mcp` is configured with `--enforcer-url`, the following fields are
transmitted to the gateway's `POST /api/v1/enforce` endpoint on every
intercepted tool call:

| Field | What it is | Classification |
|---|---|---|
| `sessionId` | MCP session identifier from the `initialize` handshake | Session metadata |
| `toolName` | MCP tool name exactly as sent in `tools/call` | Tool metadata |
| `arguments` | Raw arguments object from the `tools/call` request | **Potentially sensitive — see below** |
| `context.sourceIp` | Source IP of the MCP client (omitted for stdio) | Network metadata |
| `context.recipients` | Recipient addresses extracted from arguments (for `recipientDomain` condition) | Potentially personal data |
| `context.now` | Wall-clock timestamp of the request (ISO-8601) | Timing metadata |
| Authorization header | Bearer token derived from the `sk-...` API key via the minter | Credential (short-lived JWT) |

**The `arguments` field is the critical data-privacy consideration.** Tool call
arguments can contain — and often do contain — confidential or personal data:
SQL queries, file paths, email addresses, user identifiers, or free-form text.
In hosted mode, every tool call argument is transmitted to the gateway for
policy evaluation.

> **GDPR / SOC2 teams:** The gateway processes `arguments` for policy evaluation
> (e.g., checking `allowedOperations`, `argumentSchema`, `allowedTables`). The
> gateway retains the full `arguments` object as part of the OCSF audit record
> written to the Postgres ledger. The audit record is retained for the duration
> configured for your plan (default 90 days for Cloud Team, configurable for
> Cloud Enterprise). If your tool arguments contain personal data as defined by
> GDPR Article 4(1), you have a data-processing relationship with the gateway
> operator. Review the DPA and privacy addendum available from
> [trust.euno.example](https://trust.euno.example) before deploying in production.

### Data that does NOT leave your network

| Item | Where it stays |
|---|---|
| Upstream tool call results (responses from your MCP server) | Your network only — the gateway never sees upstream responses |
| Your policy YAML content (after initial upload) | Stored on the gateway; not re-transmitted on every call |
| Raw `sk-...` API key material | Never forwarded beyond the minter façade |
| HSM signing key material | Never leaves the HSM boundary |
| `~/.euno/audit.jsonl` | Local file; not uploaded unless you use the audit-export API explicitly |
| `maxCalls` / `rateLimit` counter state | Gateway Redis; you can read it back via the admin API but it lives on the gateway |

### Network topology in hosted mode

```
Your machine / cloud                     Euno hosted service
─────────────────────                    ────────────────────
@euno/mcp (proxy)
    │
    │ EnforceRequest (TLS 1.3)
    │ · sessionId
    │ · toolName                ────────────────────────────►  Minter façade
    │ · arguments (raw)                                             │
    │ · context.sourceIp                                            │  JWT mint + audit
    │ · context.recipients                                          ▼
    │ · Authorization: Bearer sk-...                        POST /api/v1/enforce
    │                                                               │
    │                                                               │  PDP evaluation
    │                                                               │  Audit write (Postgres)
    │  EnforceResponse (TLS 1.3)                                    │
    │ · decision: allow | deny  ◄────────────────────────────       │
    │ · obligations[]
    │ · denial info
    │
    ▼ (if allow)
Your upstream MCP server — never contacted by the gateway
```

The gateway never establishes a network connection to your upstream MCP server.
The upstream server response never leaves your network (the proxy applies
obligations like `redactFields` locally before forwarding to the MCP host).

### Data residency

The hosted service currently runs in a single region. Data residency
guarantees and multi-region options are available on the Cloud Enterprise plan.
Contact [enterprise@euno.example](mailto:enterprise@euno.example) for a DPA
with explicit regional commitments.

---

## 4. Migration steps

### Step 1 — Upload your policy

Before switching to hosted mode, your policy must be registered in the gateway.
Use the admin API (see [`docs/ADMIN_API_CURL_RECIPES.md`](./ADMIN_API_CURL_RECIPES.md))
or the interactive upgrade command (available from Stage 3 onward):

```bash
euno-mcp upgrade-to-hosted \
  --api-key sk-x7Kp9mRq.bL3nYv2wQs... \
  --gateway-url https://gateway.euno.example \
  --policy ./euno.policy.yaml
```

This command:
1. Validates the API key against the gateway.
2. Round-trips your existing local policy file to the hosted policy store via
   the admin API.
3. Prints the policy ID assigned to your policy.
4. Optionally patches your `mcp.json` / `claude_desktop_config.json` to add
   `enforcer.url` and `apiKey`, with a `.bak` backup.

For the manual path, see the [manual migration recipe](#5-manual-migration-recipe) below.

### Step 2 — Smoke-test in parallel

Before removing the `--policy` flag, you can run both modes in parallel using
separate server entries in your config:

```jsonc
{
  "mcpServers": {
    "my-server-local": {
      "command": "npx",
      "args": ["-y", "@euno/mcp", "proxy",
               "--policy", "/path/to/euno.policy.yaml",
               "--", "node", "./my-mcp-server.js"]
    },
    "my-server-hosted": {
      "command": "npx",
      "args": ["-y", "@euno/mcp", "proxy",
               "--enforcer-url", "https://gateway.euno.example",
               "--enforcer-api-key", "sk-x7Kp9mRq.bL3nYv2wQs...",
               "--", "node", "./my-mcp-server.js"]
    }
  }
}
```

Compare decisions using the local `euno-mcp stats` and the hosted audit query
API (`GET /api/v1/audit/records`) to confirm parity before removing the local
entry.

### Step 3 — Switch over

Replace `--policy` with `--enforcer-url` / `--enforcer-api-key` in your MCP
config. Restart your MCP host (Claude Desktop / Cursor / Windsurf). Local
enforcement is now off; every tool call goes to the gateway.

### Step 4 — Verify the audit trail

After a few tool calls, confirm that audit records are appearing in the gateway:

```bash
# List recent audit records for your tenant
curl -s \
  -H "Authorization: Bearer sk-x7Kp9mRq.bL3nYv2wQs..." \
  "https://gateway.euno.example/api/v1/audit/records?limit=10" \
  | jq '.records[].decidedAt'
```

---

## 5. Manual migration recipe

If you prefer not to use the interactive upgrade command:

**5.1 Create the policy via the admin API:**

```bash
# Read the policy file and POST it to the gateway
POLICY_YAML=$(cat ./euno.policy.yaml)

curl -s -X POST \
  -H "Authorization: Bearer sk-x7Kp9mRq.bL3nYv2wQs..." \
  -H "Content-Type: application/json" \
  -d "{\"policyYaml\": $(printf '%s' "$POLICY_YAML" | jq -Rs .)}" \
  "https://gateway.euno.example/admin/v1/policies" \
  | jq '{policyId: .id, policyHash: .hash}'
```

Save the returned `policyId` — you may need it for API-key scoping.

**5.2 Update your MCP config:**

Replace the `--policy` flag with `--enforcer-url` + `--enforcer-api-key` in
your `claude_desktop_config.json`, `mcp.json`, or launch script.

**5.3 Confirm the API key is scoped correctly:**

Your `sk-...` API key must have the `enforce` scope (and optionally `audit` for
audit queries, `admin` for admin operations). Scopes are set at key-issuance
time. Contact your gateway administrator if you need scope adjustments.

---

## 6. Rollback

Hosted mode adds no new dependencies to `@euno/mcp` itself. Rollback is
instantaneous: restore the `--policy` flag and remove `--enforcer-url` /
`--enforcer-api-key`. Your local policy file and local HMAC audit log are
unchanged.

Audit records written during the hosted period remain in the gateway's Postgres
ledger and are accessible via the audit query API even after you roll back to
local mode. The two audit trails (local HMAC + hosted Postgres) are independent
and can coexist.

---

## 7. Self-host alternative

If you do not want tool call arguments to leave your network, or if you need
data-residency guarantees you can verify yourself, you can self-host the entire
gateway stack. See [`docs/self-host.md`](./self-host.md) for the full guide.

Key trade-offs versus the hosted cloud option:

| Trade-off | Hosted | Self-host |
|---|---|---|
| Data leaves your network | Yes — tool call arguments sent to gateway | No |
| Infrastructure to operate | None | Redis + Postgres + KMS + container runtime |
| API-key minter | Managed | Not included — issue JWTs directly via `capability-issuer` |
| Signing-key management | Managed by Euno | BYO (Azure KV, AWS KMS, GCP KMS) |
| Audit retention SLA | Per plan | You manage |
| SOC2 attestation | Cloud Enterprise plan | Self-managed |

---

## 8. Frequently asked questions

**Q: Do I need to rewrite my policy file?**

No. The policy YAML format is identical between local and hosted mode —
it is the same `AgentCapabilityManifest` schema from `@euno/common-core`.
The upgrade command uploads your existing file verbatim.

**Q: What happens if the gateway is unreachable?**

`@euno/mcp` is fail-closed. Any network error, HTTP error, or malformed
response causes a `deny` decision with code `GATEWAY_UNAVAILABLE`. The upstream
tool is never called. There is no fail-open path.

**Q: Can I use a self-issued JWT instead of an `sk-...` key?**

Yes, in a self-hosted deployment. Self-hosted gateways accept a pre-issued JWT
directly in the `Authorization` header, skipping the minter façade (see
[`docs/self-host.md`](./self-host.md) §2 "The key difference: no managed
minter"). The hosted cloud service requires an `sk-...` key; JWT issuance is
handled internally by the minter.

**Q: What happens to my local HMAC audit log?**

In hosted mode, `@euno/mcp` does not write duplicate local audit records for
tool calls that were evaluated by the gateway (the gateway writes the canonical
OCSF event). The local `~/.euno/audit.jsonl` file remains unchanged for any
events written before the switch (such as `euno-mcp proxy` startup/shutdown
lifecycle events). `euno-mcp stats` and `euno-mcp validate-token` still work on
the local file for pre-migration records.

**Q: Are custom conditions and policy backends supported in hosted mode?**

Custom conditions and policy backends are registered server-side on the hosted
gateway, not loaded via `--custom-condition` / `--policy-backend` CLI flags
(those flags are local-mode only). Contact your gateway administrator to
register custom handlers. The handler contract is the same as the local interface.

**Q: Is there a staging / sandbox environment?**

The hosted service provides a sandbox environment at
`https://sandbox.gateway.euno.example` for pre-production validation. Sandbox
audit records are not retained beyond 7 days. Request a sandbox API key from
your account dashboard.

# OPA / Envoy fails here — reproducible demo

This demo shows three concrete scenarios where Open Policy Agent (OPA) alone
**cannot** enforce a security requirement that eunox can.

The root cause is the same in every case: **OPA is stateless per evaluation**.
Each policy query is independent — OPA has no knowledge of what was called
before within the same session.

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Docker ≥ 27 with Compose v2 | Run the demo stack |
| `curl` + `bash` | Drive the scenario scripts |
| `jq` | Parse JSON responses in scenario scripts |
| `make` | Convenience wrapper (optional) |

No account or token needed. Everything runs locally.

---

## Quick start — all three scenarios

From the repository root:

```bash
make -C demo/opa-comparison scenario-1   # ~3 min (first run builds images)
make -C demo/opa-comparison scenario-2   # ~1 min
make -C demo/opa-comparison scenario-3   # ~1 min
```

Each target:
1. Builds the tool server and eunox-mcp images (cached after the first run).
2. Starts OPA, the tool server, and the eunox-mcp proxy.
3. Runs the corresponding scenario script and prints a comparison table.
4. Tears down the stack automatically.

Total cold-start time (including `docker build`): **< 10 minutes** on a
typical developer laptop with a local image cache.

---

## Scenarios

### Scenario 1 — Credential exfiltration

**Intent:** The agent is allowed to call `read_credentials` and
`write_external` *once* per session. A second call is a policy violation.

**What OPA does:** Its `scenario1.rego` maintains an allow-list of the two
tools. Every call to either tool is approved — OPA cannot count calls within a
session.

**What eunox does:** `manifests/scenario1.yaml` adds `maxCalls: 1` on both
tools. The second call is blocked immediately.

**Why this matters:** A compromised agent can call `read_credentials` in a
loop, harvesting every credential in the vault. OPA is powerless to stop it.

```
eunox manifest (8 lines total):
  capabilities:
    - resource: read_credentials
      actions: [call]
      conditions:
        - type: maxCalls
          count: 1
          windowSeconds: 3600
    - resource: write_external
      actions: [call]
      conditions:
        - type: maxCalls
          count: 1
          windowSeconds: 3600
```

---

### Scenario 2 — Path-gated file access (10 tools)

**Intent:** Ten file/config/secret tools are restricted to paths under
`/reports/*` and limited to 5 calls per tool per minute.

**What OPA does:** `scenario2.rego` checks `startswith(path, "/reports/")`.
It works for path filtering — but requires one explicit rule per tool (O(tools
× path-prefixes)), and the `maxCalls` requirement is simply not expressible.

**What eunox does:** A single 8-line YAML stanza with `resource: "*"` covers
all ten tools at once via wildcard matching, plus the `maxCalls` condition.

```
eunox manifest (8 lines covering ALL 10 tools):
  capabilities:
    - resource: "*"
      actions: [call]
      conditions:
        - type: allowedValues
          argument: path
          values: ["/reports/*"]
        - type: maxCalls
          count: 5
          windowSeconds: 60
```

OPA equivalent would require ~40 lines *and* still cannot rate-limit.

---

### Scenario 3 — Short-lived cloud token reuse

**Intent:** The agent is allowed to call `get_aws_token` and
`get_github_token` *once* per session. The returned tokens have TTLs of 900 s
(AWS STS) and 600 s (GitHub) respectively.

**What OPA does:** `scenario3.rego` allows both tools every time. An agent
polling `get_aws_token` every 895 seconds would accumulate an ever-growing pool
of valid 15-minute credentials — a classic sliding-window privilege-escalation.

**What eunox does:** `manifests/scenario3.yaml` sets `maxCalls: 1` on both
tools. The first call succeeds; any subsequent attempt is denied.

---

## Architecture

```
demo/opa-comparison/
├── Makefile                    # scenario-1/2/3 targets
├── README.md                   # this file
├── docker-compose.yml          # server (9090) + opa (8181) + eunox-mcp (3000)
├── audit/                      # eunox audit log (created at runtime)
├── manifests/
│   ├── scenario1.yaml
│   ├── scenario2.yaml
│   └── scenario3.yaml
├── opa-policies/
│   ├── scenario1.rego
│   ├── scenario2.rego
│   └── scenario3.rego
├── server/
│   ├── main.go                 # MCP tool server (all scenario tools)
│   ├── main_test.go
│   └── Dockerfile
└── scripts/
    ├── common.sh               # shared helpers (mcp_call, opa_check, …)
    ├── scenario1.sh
    ├── scenario2.sh
    └── scenario3.sh
```

### Service ports (all localhost)

| Port | Service |
|------|---------|
| 9090 | MCP tool server (direct, bypasses enforcement) |
| 8181 | OPA REST API |
| 3000 | eunox-mcp proxy (enforced, use this one) |

---

## Manual exploration

Start the stack manually (scenario 1 manifest):

```bash
cd demo/opa-comparison
EUNOX_MANIFEST=scenario1.yaml docker compose up --build -d --wait
```

Query OPA directly:

```bash
# OPA allows read_credentials unconditionally
curl -s http://localhost:8181/v1/data/scenario1/allow \
  -H 'Content-Type: application/json' \
  -d '{"input":{"tool":"read_credentials"}}' | jq .

# → {"result": true}
```

Initialize an eunox session and call the same tool twice:

```bash
# Init
RESP=$(curl -si -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
SID=$(echo "$RESP" | grep -i Mcp-Session-Id | awk '{print $2}' | tr -d '\r')

# Call 1 — allowed
curl -s -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_credentials","arguments":{"service":"aws"}}}' | jq .

# Call 2 — denied
curl -s -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_credentials","arguments":{"service":"aws"}}}' | jq .
```

Tear down:

```bash
docker compose down --remove-orphans
```

---

## Root cause analysis

OPA's data model for policy evaluation is:

```
(policy, input) → decision
```

There is no `session_state` term. Between two evaluations, OPA remembers
nothing. This is a deliberate design choice that makes OPA highly composable
and easy to reason about — but it means OPA is the wrong tool for stateful
enforcement requirements like rate limiting or single-use tokens.

Envoy's RBAC and ext_authz filters share the same limitation: each request is
evaluated in isolation against the current policy snapshot.

eunox's enforcement model is:

```
(policy, input, session_call_counters) → decision
```

The call counter is stored in a `callcounter.Store` (in-process for
single-node, Redis-backed for multi-node) and is incremented atomically on
every allow decision. The `maxCalls` condition fails closed — a counter store
failure results in a deny, not a bypass.

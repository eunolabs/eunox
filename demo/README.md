# eunox-mcp demo

Three Docker services. One manifest file. First enforced tool call in under 10 minutes.

## What this demo shows

- `eunox-mcp` sitting between a client and an MCP server, enforcing a YAML policy
- **Allow**: `read_file /reports/q3.pdf` — passes the `AllowedValues` path condition
- **Deny**: `write_file` — not in the manifest, blocked by default
- **Deny**: `read_file /etc/shadow` — path doesn't match `/reports/*`
- **Deny**: `query_db DELETE` — blocked by `AllowedOperations: [SELECT]`
- Tamper-evident OCSF audit log with HMAC-SHA256 per-record signing
- **JWT mode** (step 3): IdP-issued capability claims via Keycloak, intersected with the manifest

## Prerequisites

```
docker      >= 24.0
docker compose >= 2.20
jq          (for pretty-printed output; optional)
curl
```

---

## Step 1 — Start the stack

```
$ make -C demo up
```

Expected output:
```
[+] Building 12.4s (21/21) FINISHED
[+] Running 3/3
 ✔ Container demo-mock-mcp-server-1  Started
 ✔ Container demo-keycloak-1         Started
 ✔ Container demo-eunox-mcp-1        Started

  eunox-mcp proxy : http://localhost:3000/mcp
  mock-mcp-server : http://localhost:8080/mcp
  Keycloak        : http://localhost:8081 (admin / admin)

  Next: make -C demo allow   # allowed tool call
        make -C demo deny    # policy denial
        make -C demo audit   # live audit log
```

The proxy takes ~5 seconds to be ready. The healthcheck polls the mock server and
waits before starting eunox-mcp.

---

## Step 2a — Allowed tool call

`read_file /reports/q3.pdf` matches the `AllowedValues: ["/reports/*"]` condition in
`demo/manifest.yaml`. The proxy forwards the call to the mock server.

```
$ make -C demo allow
```

Expected output:
```
>>> read_file /reports/q3.pdf  [expect: ALLOWED]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[mock] Contents of /reports/q3.pdf:\n\nQ3 Financial Summary\nRevenue:  $12,400,000\nExpenses: $ 8,900,000\nEBITDA:   $ 3,500,000\n(end of mock file /reports/q3.pdf)"
      }
    ],
    "isError": false
  }
}
```

---

## Step 2b — Policy denial (tool not in manifest)

`write_file` is intentionally absent from the manifest. The proxy denies it before
the request reaches the mock server.

```
$ make -C demo deny
```

Expected output:
```
>>> write_file /etc/passwd  [expect: DENIED — not in manifest]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"AUTHORIZATION_FAILED\",\"error\":\"CapabilityDenied\",\"message\":\"tool \\\"write_file\\\" is not listed in the capability manifest\",\"tool\":\"write_file\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2c — Policy denial (wrong path)

`read_file /etc/shadow` is denied because `/etc/shadow` does not match `/reports/*`.

```
$ make -C demo deny-path
```

Expected output:
```
>>> read_file /etc/shadow  [expect: DENIED — path not in /reports/*]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"CONDITION_FAILED\",\"details\":{\"allowedValues\":[\"/reports/*\"],\"argument\":\"path\",\"value\":\"[redacted]\"},\"error\":\"CapabilityDenied\",\"message\":\"argument \\\"path\\\" value is not in the allowed set\",\"tool\":\"read_file\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2d — Policy denial (wrong SQL operation)

`query_db DELETE` is denied by `AllowedOperations: [SELECT]`.

```
$ make -C demo deny-op
```

Expected output:
```
>>> query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"code\":\"CONDITION_FAILED\",\"details\":{\"allowedOperations\":[\"SELECT\"],\"operation\":\"[redacted]\"},\"error\":\"CapabilityDenied\",\"message\":\"operation \\\"DELETE\\\" is not allowed\",\"tool\":\"query_db\"}"
      }
    ],
    "isError": true
  }
}
```

---

## Step 2e — Audit log

The proxy writes a tamper-evident OCSF audit record for every decision. Each record
has an HMAC-SHA256 signature.

```
$ make -C demo audit
```

Expected output (one record per tool call, streaming):
```json
{
  "class_uid": 6003,
  "time": "2026-05-29T12:00:00.123456789Z",
  "request_id": "a3f1e2b4-...",
  "session_id": "d7c8b9a0-...",
  "tool_name": "read_file",
  "decision": "allow",
  "hmac": "sha256:a1b2c3d4..."
}
{
  "class_uid": 6003,
  "time": "2026-05-29T12:00:01.456789012Z",
  "request_id": "b5e6f7a8-...",
  "session_id": "e9d0c1b2-...",
  "tool_name": "write_file",
  "decision": "deny",
  "hmac": "sha256:b2c3d4e5..."
}
```

Verify the HMAC chain:
```
$ docker run --rm -v "$(pwd)/demo/audit:/audit" \
    --entrypoint /usr/local/bin/mcp \
    eunolabs/eunox-mcp:latest \
    validate-token --audit-log /audit/audit.jsonl
Checked 4 record(s): 4 valid, 0 invalid, 0 skipped.
```

---

## Step 3 — JWT mode (manifest + IdP claims)

In JWT mode, every request must carry an IdP-issued Bearer JWT. The proxy
intersects the JWT's `eunox.capabilities` claims with the manifest: the JWT can
only restrict, never expand.

The Keycloak `demo-agent` client issues tokens with:
```json
{
  "eunox.capabilities": ["read_file:/reports/*", "query_db:SELECT"],
  "eunox.task_id": "demo-task-001",
  "eunox.agent_id": "demo-agent",
  "aud": "eunox"
}
```

### 3a — Restart with JWT mode enabled

```
$ make -C demo up-jwt
```

Expected output:
```
[+] Running 3/3
 ✔ Container demo-keycloak-1         Healthy
 ✔ Container demo-mock-mcp-server-1  Healthy
 ✔ Container demo-eunox-mcp-1        Started

  eunox-mcp (JWT mode) : http://localhost:3000/mcp
  Keycloak             : http://localhost:8081 (admin / admin)
```

### 3b — Get a test JWT

```
$ make -C demo jwt
```

Expected output (raw JWT, trimmed):
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii...
```

Decode at jwt.io to inspect the claims.

### 3c — JWT-authenticated allowed call

```
$ make -C demo jwt-allow
```

Expected output:
```
>>> [JWT mode] read_file /reports/q3.pdf  [expect: ALLOWED]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{ "type": "text", "text": "[mock] Contents of /reports/q3.pdf:..." }],
    "isError": false
  }
}
```

### 3d — JWT-authenticated denied call

`write_file` is absent from both the manifest and the JWT claims.

```
$ make -C demo jwt-deny
```

Expected output:
```
>>> [JWT mode] write_file /tmp/x.txt  [expect: DENIED — not in JWT capabilities]
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{ "type": "text", "text": "{\"code\":\"AUTHORIZATION_FAILED\",...}" }],
    "isError": true
  }
}
```

---

## Tear down

```
$ make -C demo down
```

---

## What's in this directory

```
demo/
├── docker-compose.yml       base stack: mock-mcp-server + keycloak + eunox-mcp (manifest mode)
├── docker-compose.jwt.yml   overlay: switches eunox-mcp to JWT + manifest intersection mode
├── manifest.yaml            capability policy for the demo
├── Makefile                 all demo targets
├── audit/                   audit log written here by eunox-mcp (bind-mounted into container)
├── mock-mcp-server/
│   ├── main.go              minimal MCP HTTP server (3 tools, fake responses)
│   ├── main_test.go         unit tests
│   └── Dockerfile           multi-stage Go build (shares root go.mod)
├── keycloak/
│   └── realm-export.json    eunox-demo realm with demo-agent client and capability mappers
└── scripts/
    ├── mcp-call.sh          initialize session + tool call
    └── get-jwt.sh           client-credentials token request to Keycloak
```

## Troubleshooting

**`make allow` fails with "connection refused"**
The proxy is not ready yet. Wait 10 seconds and retry. Or watch: `make -C demo logs`.

**`make jwt` fails with "failed to reach Keycloak"**
Keycloak takes up to 30 seconds to start. Check: `docker compose -f demo/docker-compose.yml logs keycloak | tail -20`

**Audit log is empty**
Make a call first (`make allow`), then re-run `make audit`.

**On Linux: audit log permission error**
The `make up` target runs `chmod 777 demo/audit/`. If you see permission errors,
run `sudo chmod 777 demo/audit && sudo chown -R 0:0 demo/audit` then `make up`.

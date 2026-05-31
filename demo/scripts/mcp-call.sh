#!/usr/bin/env bash
# demo/scripts/mcp-call.sh — initialize an MCP session then make a single tool call.
#
# Usage:
#   bash scripts/mcp-call.sh <call-body-json> [bearer-token]
#
# Arguments:
#   call-body-json   Full JSON-RPC tools/call request body.
#   bearer-token     Optional.  If set, passed as Authorization: Bearer <token>.
#
# The script:
#   1. POSTs initialize to http://localhost:3000/mcp to create a session.
#   2. Extracts the Mcp-Session-Id from the response headers.
#   3. POSTs the tool call with the session ID attached.
#   4. Prints the result through jq if available, otherwise raw.

set -eo pipefail

HOST="${MCP_HOST:-http://localhost:3000}"
CALL_BODY="${1:?usage: mcp-call.sh <call-body-json> [token]}"
BEARER="${2:-}"

# mcp_curl — wrapper that appends the Authorization header when a bearer token
# is present.  Using a function instead of an array avoids the bash 3.2 (macOS
# default) nounset error triggered by expanding an empty array with set -u.
mcp_curl() {
  if [[ -n "$BEARER" ]]; then
    curl "$@" -H "Authorization: Bearer $BEARER"
  else
    curl "$@"
  fi
}

# ── Step 1: initialize ────────────────────────────────────────────────────────
INIT_RESP=$(mcp_curl -si \
  -X POST "$HOST/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo-client","version":"1.0"}}}')

HTTP_STATUS=$(echo "$INIT_RESP" | head -1 | awk '{print $2}')
if [[ "$HTTP_STATUS" != "200" ]]; then
  echo "ERROR: initialize failed with HTTP $HTTP_STATUS" >&2
  echo "$INIT_RESP" >&2
  exit 1
fi

SESSION_ID=$(echo "$INIT_RESP" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
if [[ -z "$SESSION_ID" ]]; then
  echo "ERROR: no Mcp-Session-Id in initialize response" >&2
  echo "$INIT_RESP" >&2
  exit 1
fi

# ── Step 2: tool call ─────────────────────────────────────────────────────────
RESULT=$(mcp_curl -s \
  -X POST "$HOST/mcp" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d "$CALL_BODY")

if command -v jq &>/dev/null; then
  echo "$RESULT" | jq .
else
  echo "$RESULT"
fi

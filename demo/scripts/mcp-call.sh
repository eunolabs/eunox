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

set -euo pipefail

HOST="${MCP_HOST:-http://localhost:3000}"
CALL_BODY="${1:?usage: mcp-call.sh <call-body-json> [token]}"
BEARER="${2:-}"

auth_args=()
if [[ -n "$BEARER" ]]; then
  auth_args+=(-H "Authorization: Bearer $BEARER")
fi

# ── Step 1: initialize ────────────────────────────────────────────────────────
INIT_RESP=$(curl -si \
  -X POST "$HOST/mcp" \
  -H "Content-Type: application/json" \
  "${auth_args[@]}" \
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
RESULT=$(curl -s \
  -X POST "$HOST/mcp" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  "${auth_args[@]}" \
  -d "$CALL_BODY")

if command -v jq &>/dev/null; then
  echo "$RESULT" | jq .
else
  echo "$RESULT"
fi

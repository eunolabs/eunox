#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/opa-comparison/scripts/common.sh
# Shared helpers sourced by scenario scripts.

set -euo pipefail

EUNOX_HOST="${EUNOX_HOST:-http://localhost:3000}"
OPA_HOST="${OPA_HOST:-http://localhost:8181}"

# ── colour / formatting ───────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
BOLD='\033[1m'
RST='\033[0m'

print_header() {
  local title="$1"
  echo ""
  echo -e "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
  echo -e "${BOLD}${BLU}  ${title}${RST}"
  echo -e "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
}

print_step() {
  echo -e "\n${CYN}▶  $*${RST}"
}

print_ok() {
  echo -e "${GRN}✔  $*${RST}"
}

print_denied() {
  echo -e "${RED}✘  $*${RST}"
}

print_note() {
  echo -e "${YLW}ℹ  $*${RST}"
}

# ── OPA query ─────────────────────────────────────────────────────────────────
# opa_check <package> <tool> [extra-json-fields]
# Queries POST /v1/data/<package>/allow and prints the decision.
# extra-json-fields: additional key:value pairs to merge into input (comma-sep JSON).
# Returns 0 if OPA says allow=true, 1 otherwise.
opa_check() {
  local pkg="$1"
  local tool="$2"
  local extra="${3:-}"

  local input_json
  if [[ -n "$extra" ]]; then
    input_json="{\"tool\":\"${tool}\",${extra}}"
  else
    input_json="{\"tool\":\"${tool}\"}"
  fi

  local resp
  resp=$(curl -sf \
    -X POST "${OPA_HOST}/v1/data/${pkg}/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":${input_json}}" 2>&1) || {
    echo "ERROR: OPA unreachable at ${OPA_HOST}" >&2
    return 1
  }

  local decision
  decision=$(echo "$resp" | grep -o '"result":[^,}]*' | cut -d: -f2 | tr -d ' "')

  if [[ "$decision" == "true" ]]; then
    print_ok "OPA [${pkg}] tool=${tool} → ALLOW"
    return 0
  else
    print_denied "OPA [${pkg}] tool=${tool} → DENY (decision=${decision:-false})"
    return 1
  fi
}

# ── MCP session ───────────────────────────────────────────────────────────────
# mcp_init — initialise a session and export MCP_SESSION_ID.
mcp_init() {
  local resp
  resp=$(curl -si \
    -X POST "${EUNOX_HOST}/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"opa-cmp-demo","version":"1.0"}}}')

  local status
  status=$(echo "$resp" | head -1 | awk '{print $2}')
  if [[ "$status" != "200" ]]; then
    echo "ERROR: eunox initialize failed with HTTP ${status}" >&2
    echo "$resp" >&2
    exit 1
  fi

  MCP_SESSION_ID=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$MCP_SESSION_ID" ]]; then
    echo "ERROR: no Mcp-Session-Id in response" >&2
    exit 1
  fi
  export MCP_SESSION_ID
}

# mcp_call <tool> <args-json>
# Issues a tools/call and returns the result text.
# Prints eunox decision (ALLOW / DENY) based on HTTP + isError.
mcp_call() {
  local tool="$1"
  local args="$2"

  local body
  body=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}' \
    "$tool" "$args")

  local resp
  resp=$(curl -s \
    -X POST "${EUNOX_HOST}/mcp" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
    -d "$body")

  # Check for a JSON-RPC error (policy denial) vs success.
  if echo "$resp" | grep -q '"error"'; then
    local msg
    msg=$(echo "$resp" | grep -o '"message":"[^"]*"' | head -1 | cut -d'"' -f4)
    print_denied "eunox [tool=${tool}] → DENY: ${msg}"
    echo "$resp"
    return 1
  fi

  # Check isError flag from the MCP tool result.
  if echo "$resp" | grep -q '"isError":true'; then
    print_denied "eunox [tool=${tool}] → TOOL ERROR"
    echo "$resp"
    return 1
  fi

  local text
  text=$(echo "$resp" | grep -o '"text":"[^"]*"' | head -1 | cut -d'"' -f4)
  print_ok "eunox [tool=${tool}] → ALLOW: ${text:0:80}$([ ${#text} -gt 80 ] && echo '…')"
  echo "$resp"
  return 0
}

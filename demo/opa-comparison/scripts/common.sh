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
# Use $'...' ANSI-C quoting so the variables hold the actual ESC byte.
# Plain `echo` (no -e flag) then renders them correctly in any bash version.
# Colours are suppressed in CI (GitHub Actions sets CI=true), when stdout is
# not a terminal, or when TERM=dumb.
if [[ -z "${CI:-}" && -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  RED=$'\033[0;31m'
  GRN=$'\033[0;32m'
  YLW=$'\033[0;33m'
  BLU=$'\033[0;34m'
  CYN=$'\033[0;36m'
  BOLD=$'\033[1m'
  RST=$'\033[0m'
else
  RED='' GRN='' YLW='' BLU='' CYN='' BOLD='' RST=''
fi

print_header() {
  local title="$1"
  echo ""
  echo "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
  echo "${BOLD}${BLU}  ${title}${RST}"
  echo "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
}

print_step() {
  echo ""
  echo "${CYN}▶  $*${RST}"
}

print_ok() {
  echo "${GRN}✔  $*${RST}"
}

print_denied() {
  echo "${RED}✘  $*${RST}"
}

print_note() {
  echo "${YLW}ℹ  $*${RST}"
}

# ── prerequisites ─────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo "${RED}ERROR: jq is required but not installed.${RST}" >&2
  echo "       Install: https://jqlang.github.io/jq/download/" >&2
  exit 1
fi

# ── OPA query ─────────────────────────────────────────────────────────────────
# opa_check <package> <tool> [extra-json-fields]
# Queries POST /v1/data/<package>/allow and prints the decision.
# extra-json-fields: additional comma-separated JSON key:value pairs merged into input.
# Returns 0 if allow=true, 1 otherwise.
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
  decision=$(echo "$resp" | jq -r '.result // false')

  if [[ "$decision" == "true" ]]; then
    print_ok "OPA [${pkg}] tool=${tool} → ALLOW"
    return 0
  else
    print_denied "OPA [${pkg}] tool=${tool} → DENY (decision=${decision})"
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
# Issues a tools/call against eunox-mcp and prints the outcome.
# Prints ALLOW with a preview of the result text, or DENY with the reason.
# Returns 0 on allow, 1 on deny.
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

  # JSON-RPC protocol-level error (e.g. unknown session, parse error).
  local rpc_err
  rpc_err=$(echo "$resp" | jq -r '.error.message // empty' 2>/dev/null || true)
  if [[ -n "$rpc_err" ]]; then
    print_denied "eunox [tool=${tool}] → DENY: ${rpc_err}"
    return 1
  fi

  # eunox wraps policy denials as isError:true inside the MCP result envelope.
  local is_err
  is_err=$(echo "$resp" | jq -r '.result.isError // false' 2>/dev/null || echo "false")
  if [[ "$is_err" == "true" ]]; then
    # The content text is a JSON object with a "message" field.
    local inner msg
    inner=$(echo "$resp" | jq -r '.result.content[0].text // ""' 2>/dev/null || true)
    msg=$(echo "$inner" | jq -r '.message // "denied"' 2>/dev/null || echo "denied")
    print_denied "eunox [tool=${tool}] → DENY: ${msg}"
    return 1
  fi

  # Successful tool call — show a preview of the result text.
  local text preview
  text=$(echo "$resp" | jq -r '.result.content[0].text // ""' 2>/dev/null || true)
  preview="${text:0:80}"
  [[ ${#text} -gt 80 ]] && preview="${preview}…"
  print_ok "eunox [tool=${tool}] → ALLOW: ${preview}"
  return 0
}

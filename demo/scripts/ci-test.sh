#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test.sh — manifest-only integration test
#
# Asserts that eunox-mcp enforces demo/manifest.yaml correctly:
#   - read_file /reports/*       → ALLOW  (allowedValues glob)
#   - read_file outside /reports → DENY   (path not in allowed set)
#   - write_file                 → DENY   (tool absent from manifest)
#   - query_db SELECT            → ALLOW  (allowedOperations)
#   - query_db DELETE            → DENY   (operation not permitted)
#
# Exits 0 if all assertions pass, non-zero otherwise.
# Requires: curl, jq

set -euo pipefail

HOST="${EUNOX_HOST:-http://localhost:3000}"
pass=0
fail=0

# new_session — initialise a fresh MCP session, print the session ID.
new_session() {
  local resp
  resp=$(curl -si -X POST "$HOST/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
  local sid
  sid=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$sid" ]]; then
    echo "ERROR: failed to initialise MCP session (is eunox-mcp running at $HOST?)" >&2
    echo "$resp" >&2
    exit 1
  fi
  echo "$sid"
}

# check <description> <session-id> <tool-call-body> <want: allow|deny>
check() {
  local desc="$1" sid="$2" body="$3" want="$4"
  local resp is_err got

  resp=$(curl -s -X POST "$HOST/mcp" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $sid" \
    -d "$body")

  is_err=$(echo "$resp" | jq -r '.result.isError // false' 2>/dev/null || echo "false")

  if   [[ "$want" == "allow" && "$is_err" == "false" ]]; then
    printf 'PASS  %s\n' "$desc"
    ((pass++)) || true
  elif [[ "$want" == "deny"  && "$is_err" == "true"  ]]; then
    printf 'PASS  %s\n' "$desc"
    ((pass++)) || true
  else
    got="$([[ "$is_err" == "true" ]] && echo deny || echo allow)"
    printf 'FAIL  %s  (want=%s got=%s)\n' "$desc" "$want" "$got"
    printf '      response: %s\n' "$resp"
    ((fail++)) || true
  fi
}

# ── tests ─────────────────────────────────────────────────────────────────────

echo "==> eunox-mcp demo: manifest-only integration tests"
echo ""

SID=$(new_session)

check \
  "read_file /reports/q3.pdf → ALLOW (path matches /reports/* glob)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  allow

check \
  "read_file /reports/summary.csv → ALLOW (another path under /reports/)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/summary.csv"}}}' \
  allow

check \
  "read_file /etc/shadow → DENY (path outside /reports/*)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
  deny

check \
  "read_file /internal/secrets.txt → DENY (path outside /reports/*)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/internal/secrets.txt"}}}' \
  deny

check \
  "write_file /etc/passwd → DENY (tool absent from manifest)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"x"}}}' \
  deny

check \
  "query_db SELECT * FROM reports → ALLOW (SELECT in allowedOperations)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}' \
  allow

check \
  "query_db DELETE FROM reports → DENY (only SELECT permitted)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}' \
  deny

check \
  "query_db DROP TABLE reports → DENY (only SELECT permitted)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DROP TABLE reports"}}}' \
  deny

# ── results ───────────────────────────────────────────────────────────────────

echo ""
printf 'Results: %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]

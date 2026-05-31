#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 2 — Path-gated file access: OPA requires one rule per tool and
#              cannot express per-tool call-rate limits at all.
#
# Ten tools each restricted to /reports/* paths, plus maxCalls:5 per minute.
# OPA must enumerate every tool explicitly; eunox uses a single wildcard rule.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

print_header "Scenario 2 — Path-Gated File Access (10 tools)"
echo ""
echo "  Policy intent: all file tools restricted to /reports/* paths."
echo "  Rate limit: max 5 calls per tool per minute."
echo ""
echo "  OPA policy:   scenario2.rego — one startswith rule (no maxCalls)"
echo "  eunox policy: manifests/scenario2.yaml — wildcard resource + 2 conditions"

# ── OPA: allowed path ─────────────────────────────────────────────────────────
print_step "OPA: read_file /reports/q3.pdf (expect: ALLOW)"
opa_check "scenario2" "read_file" '"arguments":{"path":"/reports/q3.pdf"}'

print_step "OPA: write_file /reports/output.csv (expect: ALLOW)"
opa_check "scenario2" "write_file" '"arguments":{"path":"/reports/output.csv"}'

# ── OPA: denied path ─────────────────────────────────────────────────────────
print_step "OPA: read_file /etc/passwd (expect: DENY)"
opa_check "scenario2" "read_file" '"arguments":{"path":"/etc/passwd"}' || true

# ── OPA: cannot count ─────────────────────────────────────────────────────────
print_step "OPA: calling read_file 6 times (all 6 expect: ALLOW — OPA has no counter)"
for i in $(seq 1 6); do
  opa_check "scenario2" "read_file" '"arguments":{"path":"/reports/q3.pdf"}' || true
done
print_note "OPA allowed all 6 calls.  maxCalls enforcement is impossible without external state."

# ── eunox enforcement ─────────────────────────────────────────────────────────
print_step "Initialising eunox MCP session …"
mcp_init
echo "  Session ID: ${MCP_SESSION_ID}"

print_step "eunox: read_file /reports/q3.pdf (expect: ALLOW)"
mcp_call "read_file" '{"path":"/reports/q3.pdf"}' || true

print_step "eunox: read_file /etc/passwd (expect: DENY — path not in /reports/*)"
mcp_call "read_file" '{"path":"/etc/passwd"}' || true

print_step "eunox: calling read_file 5 more times to hit maxCalls:5 …"
for i in $(seq 2 5); do
  print_note "  call ${i}/5"
  mcp_call "read_file" '{"path":"/reports/q3.pdf"}' || true
done

print_step "eunox: call 6 of read_file (expect: DENY — maxCalls:5 exceeded)"
mcp_call "read_file" '{"path":"/reports/q3.pdf"}' || true

echo ""
print_header "Scenario 2 — Summary"
echo ""
echo "  eunox manifest (scenario2.yaml)  —  8 lines covering ALL 10 tools:"
echo ""
echo "    capabilities:"
echo "      - resource: \"*\"           # ← one rule, all tools"
echo "        actions: [call]"
echo "        conditions:"
echo "          - type: allowedValues"
echo "            argument: path"
echo "            values: [\"/reports/*\"]"
echo "          - type: maxCalls      # ← impossible in plain OPA"
echo "            count: 5"
echo "            windowSeconds: 60"
echo ""
echo "  OPA scenario2.rego requires one explicit rule per tool (O(tools))."
echo "  Adding maxCalls would require an external state store — i.e. a custom"
echo "  enforcement engine bolted onto OPA."
echo ""

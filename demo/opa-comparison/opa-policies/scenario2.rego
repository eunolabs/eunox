# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 2 — Path-gated file access: OPA policy
#
# Ten tools, each restricted to paths under /reports/.
# OPA can enforce path prefixes, but:
#   1. Each tool needs its own rule — this file would need to grow linearly.
#   2. There is still no way to enforce a per-tool call-rate limit.
#
# Query: POST /v1/data/scenario2/allow
# Input:
#   {"input": {"tool": "read_file", "arguments": {"path": "/reports/q3.pdf"}}}

package scenario2

import rego.v1

# Tools that accept a "path" argument.
path_gated_tools := {
	"read_file",
	"write_file",
	"read_config",
	"update_config",
	"read_log",
	"delete_file",
	"stat_file",
	"read_secret",
	"write_secret",
	"read_backup",
}

default allow := false

allow if {
	input.tool in path_gated_tools
	startswith(input.arguments.path, "/reports/")
}

# ── OPA line-count vs eunox ──────────────────────────────────────────────────
# The rule above is 4 lines.  If the allowed prefix was different per tool
# (e.g. write_file → /tmp/, read_config → /etc/app/) each tool needs its own
# rule, and the policy grows O(tools × prefixes).
#
# eunox expresses this for ALL ten tools in a single 4-line YAML stanza using
# a wildcard resource match:
#
#   capabilities:
#     - resource: "*"           # matches every tool
#       actions: [call]
#       conditions:
#         - type: allowedValues
#           argument: path
#           values: ["/reports/*"]
#
# Additionally, adding a rate limit in OPA is impossible without external state.
# eunox adds one extra condition line:
#   - type: maxCalls
#     count: 5
#     windowSeconds: 60

# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 1 — Credential exfiltration: OPA policy
#
# The agent is supposed to read credentials ONCE and write to an internal
# destination ONCE.  OPA can express the tool allow-list but it is stateless:
# it has no memory of how many times read_credentials or write_external have
# been called in this session.  An attacker can call them arbitrarily many
# times and OPA cannot stop it.
#
# Query: POST /v1/data/scenario1/allow
# Input:
#   {"input": {"tool": "read_credentials", "session_id": "abc123"}}

package scenario1

import rego.v1

# Allowed tool names — OPA can only check identity, not frequency.
allowed_tools := {"read_credentials", "write_external"}

default allow := false

allow if {
	input.tool in allowed_tools
}

# ── What OPA CANNOT do ──────────────────────────────────────────────────────
# OPA has no persistent state between policy evaluations.  There is no way to
# express "allow read_credentials at most once per session" in plain OPA
# without an external state store — at which point you are building a bespoke
# enforcement engine, not using OPA alone.
#
# eunox expresses this as:
#   conditions:
#     - type: maxCalls
#       count: 1
#       windowSeconds: 3600

// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import "go.opentelemetry.io/otel/attribute"

// Eunox-specific OpenTelemetry span attribute keys used across all services.
// Sharing constants here ensures traces can be joined on consistent attribute
// names regardless of which component emitted them.
var (
	// EunoxAttrAgentID identifies the agent (JWT subject) making the request.
	EunoxAttrAgentID = attribute.Key("eunox.agent_id")

	// EunoxAttrSessionID identifies the MCP session carrying the request.
	EunoxAttrSessionID = attribute.Key("eunox.session_id")

	// EunoxAttrTaskID identifies the task within a session.
	EunoxAttrTaskID = attribute.Key("eunox.task_id")

	// EunoxAttrCapabilityTokenID is the JWT ID (jti) of the capability token.
	EunoxAttrCapabilityTokenID = attribute.Key("eunox.capability_token_id")

	// EunoxAttrToolName is the MCP tool name being invoked or controlled.
	EunoxAttrToolName = attribute.Key("eunox.tool_name")

	// EunoxAttrPolicyDecision is the enforcement outcome: "allow" or "deny".
	EunoxAttrPolicyDecision = attribute.Key("eunox.policy_decision")

	// EunoxAttrTenantID identifies the tenant that issued the capability token.
	EunoxAttrTenantID = attribute.Key("eunox.tenant_id")

	// EunoxAttrDenialCode carries the denial code when the decision is "deny".
	EunoxAttrDenialCode = attribute.Key("eunox.denial_code")

	// EunoxAttrDBAdapter is the cloud database adapter used for credential minting.
	EunoxAttrDBAdapter = attribute.Key("eunox.db_adapter")
)

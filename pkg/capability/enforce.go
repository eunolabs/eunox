// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package capability

import "context"

// EnforceRequest is the input payload for runtime capability enforcement.
type EnforceRequest struct {
	SessionID string                 `json:"sessionId"`
	ToolName  string                 `json:"toolName"`
	Arguments map[string]interface{} `json:"arguments"`
	Context   EnforceRequestContext  `json:"context"`
}

// EnforceRequestContext carries request attributes used during enforcement.
type EnforceRequestContext struct {
	SourceIP   string        `json:"sourceIp,omitempty"`
	Recipients []string      `json:"recipients,omitempty"`
	Now        string        `json:"now,omitempty"`
	Operation  string        `json:"operation,omitempty"`
	FilePath   string        `json:"filePath,omitempty"`
	Tables     []TableAccess `json:"tables,omitempty"`
}

// TableAccess describes the table and columns accessed by a request.
type TableAccess struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns,omitempty"`
}

// EnforceResponse reports the decision and any obligations from enforcement.
type EnforceResponse struct {
	RequestID   string       `json:"requestId"`
	Decision    Decision     `json:"decision"`
	Obligations []Obligation `json:"obligations,omitempty"`
	Denial      *DenialInfo  `json:"denial,omitempty"`
	DecidedAt   string       `json:"decidedAt"`
}

// Decision identifies the enforcement outcome.
type Decision string

// Enforcement decision values.
const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// DenialInfo describes why enforcement denied a request.
type DenialInfo struct {
	Code          string                 `json:"code"`
	ConditionType string                 `json:"conditionType"`
	Message       string                 `json:"message"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// Enforcer is the minimal interface that enforcement consumers (e.g. the
// gateway) should depend on rather than the concrete *enforcement.Engine type.
// Accepting Enforcer instead of *Engine decouples the caller from the
// implementation, making it straightforward to substitute a remote enforcement
// backend or a test double without modifying call sites.
//
// A-1 fix: moved here from pkg/enforcement so that consumers can import the
// interface without importing the implementation package.
type Enforcer interface {
	// ValidateAction evaluates req against capabilities and returns a decision.
	ValidateAction(ctx context.Context, req *EnforceRequest, capabilities []Constraint) (EnforceResponse, error)
	// FindMatchingCapability returns the most specific matching constraint, or
	// nil if none match.
	FindMatchingCapability(req *EnforceRequest, capabilities []Constraint) *Constraint
}

// CallCounter tracks per-key invocation counts within a sliding time window.
// Implementations must be safe for concurrent use.
//
// A-1 fix: moved here from pkg/enforcement alongside Enforcer so that both
// consumer-facing interfaces live in pkg/capability rather than in the
// producer package.
type CallCounter interface {
	IncrementAndGet(ctx context.Context, key string, windowSec int) (int64, error)
}

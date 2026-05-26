// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

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

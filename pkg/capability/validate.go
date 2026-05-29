// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package capability

// ValidateActionRequest is the input payload for capability validation.
type ValidateActionRequest struct {
	Token    string                 `json:"token"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Context  map[string]interface{} `json:"context,omitempty"`
	DPoP     *DPoPProof             `json:"dpop,omitempty"`
}

// DPoPProof contains the proof-of-possession data sent with a validation request.
type DPoPProof struct {
	Proof      string `json:"proof"`
	HTTPMethod string `json:"httpMethod"`
	HTTPURL    string `json:"httpUrl"`
}

// ValidateActionResponse reports whether a requested action is allowed.
type ValidateActionResponse struct {
	Allowed           bool        `json:"allowed"`
	Reason            string      `json:"reason,omitempty"`
	MatchedCapability *Constraint `json:"matchedCapability,omitempty"`
}

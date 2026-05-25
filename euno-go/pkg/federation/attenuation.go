// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"errors"
	"fmt"

	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
)

// Errors for cross-org attenuation.
var (
	ErrSubsetViolation      = errors.New("child capabilities must be a subset of parent capabilities")
	ErrEmptyParent          = errors.New("parent token has no capabilities")
	ErrEmptyChild           = errors.New("child capabilities cannot be empty")
	ErrCrossOrgNotPermitted = errors.New("cross-org attenuation not permitted by parent token")
)

// AttenuationRequest represents a request to attenuate a parent token across org boundaries.
type AttenuationRequest struct {
	// ParentCapabilities are the capabilities from the partner's parent token.
	ParentCapabilities []capability.Constraint
	// RequestedCapabilities are the capabilities the local issuer wants to grant.
	RequestedCapabilities []capability.Constraint
	// ParentDID is the DID of the partner that issued the parent token.
	ParentDID string
	// AllowCrossOrg indicates whether the parent explicitly allows cross-org attenuation.
	AllowCrossOrg bool
}

// AttenuationResult is the result of a successful attenuation.
type AttenuationResult struct {
	// Capabilities are the attenuated capabilities (subset of parent).
	Capabilities []capability.Constraint
	// CrossOrg indicates this is a cross-organization attenuated token.
	CrossOrg bool
	// ParentDID is the originating partner DID.
	ParentDID string
}

// Attenuate validates and applies cross-org token attenuation.
// It enforces the subset invariant: child capabilities must be a subset of parent capabilities.
func Attenuate(req AttenuationRequest) (*AttenuationResult, error) {
	if len(req.ParentCapabilities) == 0 {
		return nil, ErrEmptyParent
	}
	if len(req.RequestedCapabilities) == 0 {
		return nil, ErrEmptyChild
	}
	if !req.AllowCrossOrg {
		return nil, ErrCrossOrgNotPermitted
	}

	// Verify subset invariant: every requested capability must be covered by a parent capability.
	for i, child := range req.RequestedCapabilities {
		if !isSubsetOfAny(child, req.ParentCapabilities) {
			return nil, fmt.Errorf("%w: capability[%d] resource=%q actions=%v not covered by parent",
				ErrSubsetViolation, i, child.Resource, child.Actions)
		}
	}

	return &AttenuationResult{
		Capabilities: req.RequestedCapabilities,
		CrossOrg:     true,
		ParentDID:    req.ParentDID,
	}, nil
}

// isSubsetOfAny checks if a child constraint is covered by any parent constraint.
func isSubsetOfAny(child capability.Constraint, parents []capability.Constraint) bool {
	for _, parent := range parents {
		if isSubsetOf(child, parent) {
			return true
		}
	}
	return false
}

// isSubsetOf checks if a child constraint is a subset of a parent constraint.
func isSubsetOf(child, parent capability.Constraint) bool {
	// Check resource match.
	if parent.Resource != "*" && parent.Resource != child.Resource {
		return false
	}

	// Check actions subset.
	if len(parent.Actions) > 0 {
		parentHasWildcard := false
		parentActions := make(map[string]bool, len(parent.Actions))
		for _, a := range parent.Actions {
			if a == "*" {
				parentHasWildcard = true
				break
			}
			parentActions[a] = true
		}
		if !parentHasWildcard {
			for _, childAction := range child.Actions {
				if childAction == "*" {
					// Child wants wildcard but parent doesn't have it.
					return false
				}
				if !parentActions[childAction] {
					return false
				}
			}
		}
	}

	// Check conditions: child conditions must be at least as restrictive.
	// If parent has conditions, child must include all of them.
	if len(parent.Conditions) > 0 && len(child.Conditions) == 0 {
		return false
	}
	if !containsAllConditionTypes(child.Conditions, parent.Conditions) {
		return false
	}

	return true
}

func containsAllConditionTypes(child, parent []capability.Condition) bool {
	if len(parent) == 0 {
		return true
	}

	childTypes := make(map[string]struct{}, len(child))
	for _, condition := range child {
		if condition == nil {
			continue
		}
		childTypes[condition.ConditionType()] = struct{}{}
	}

	for _, condition := range parent {
		if condition == nil {
			continue
		}
		if _, ok := childTypes[condition.ConditionType()]; !ok {
			return false
		}
	}

	return true
}

// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
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
	// Resource match: parent wildcard or exact equality.
	if parent.Resource != "*" && parent.Resource != child.Resource {
		return false
	}

	// CR-2 fix: an empty parent.Actions means "no actions permitted", not unrestricted.
	// Previously, the guard `if len(parent.Actions) > 0` skipped the action check when
	// parent.Actions was empty, effectively treating it as a wildcard. Any child action
	// set — including ["admin:delete"] — would pass unchecked.
	if len(parent.Actions) == 0 {
		return false
	}

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
				// Child requests wildcard but parent does not grant it.
				return false
			}
			if !parentActions[childAction] {
				return false
			}
		}
	}

	// CR-3 fix: conditions must be at least as restrictive at the value level, not
	// just present at the type level. Previously, containsAllConditionTypes only verified
	// that the child had each condition type present in the parent. A child with
	// maxCalls:10_000_000 satisfied a parent with maxCalls:5 because both carried the
	// ConditionTypeMaxCalls type. The new check compares condition values.
	if len(parent.Conditions) > 0 && len(child.Conditions) == 0 {
		return false
	}
	if !conditionsAreAtLeastAsRestrictive(child.Conditions, parent.Conditions) {
		return false
	}

	return true
}

// conditionsAreAtLeastAsRestrictive checks that for every condition in parent,
// the child has a matching condition of the same type whose values are at least
// as restrictive as the parent's values.
func conditionsAreAtLeastAsRestrictive(child, parent []capability.Condition) bool {
	if len(parent) == 0 {
		return true
	}

	// Index child conditions by type for O(1) lookup.
	childByType := make(map[string][]capability.Condition, len(child))
	for _, c := range child {
		if c == nil {
			continue
		}
		ct := c.ConditionType()
		childByType[ct] = append(childByType[ct], c)
	}

	for _, parentCond := range parent {
		if parentCond == nil {
			continue
		}
		ct := parentCond.ConditionType()
		childConds := childByType[ct]
		if len(childConds) == 0 {
			return false // child is missing a required condition type
		}
		// At least one child condition of this type must be at least as restrictive
		// as the parent condition.
		found := false
		for _, childCond := range childConds {
			if conditionIsAtLeastAsRestrictive(childCond, parentCond) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// conditionIsAtLeastAsRestrictive compares two conditions of the same type and
// reports whether child imposes constraints that are at least as tight as parent.
func conditionIsAtLeastAsRestrictive(child, parent capability.Condition) bool {
	switch p := parent.(type) {
	case *capability.MaxCallsCondition:
		c, ok := child.(*capability.MaxCallsCondition)
		if !ok {
			return false
		}
		// Fewer permitted calls is more restrictive.
		// A longer window spreads the quota over more time, making bursting harder,
		// so a longer window is also more restrictive.
		return c.Count <= p.Count && c.WindowSeconds >= p.WindowSeconds

	case *capability.TimeWindowCondition:
		c, ok := child.(*capability.TimeWindowCondition)
		if !ok {
			return false
		}
		return timeWindowIsAtLeastAsRestrictive(c, p)

	case *capability.IPRangeCondition:
		c, ok := child.(*capability.IPRangeCondition)
		if !ok {
			return false
		}
		return ipRangesAreAtLeastAsRestrictive(c.CIDRs, p.CIDRs)

	case *capability.AllowedOperationsCondition:
		c, ok := child.(*capability.AllowedOperationsCondition)
		if !ok {
			return false
		}
		// Fewer allowed operations = more restrictive.
		return stringSliceIsSubset(c.Operations, p.Operations)

	case *capability.AllowedExtensionsCondition:
		c, ok := child.(*capability.AllowedExtensionsCondition)
		if !ok {
			return false
		}
		return stringSliceIsSubset(c.Extensions, p.Extensions)

	case *capability.AllowedTablesCondition:
		c, ok := child.(*capability.AllowedTablesCondition)
		if !ok {
			return false
		}
		return allowedTablesIsAtLeastAsRestrictive(c, p)

	case *capability.RecipientDomainCondition:
		c, ok := child.(*capability.RecipientDomainCondition)
		if !ok {
			return false
		}
		return stringSliceIsSubset(c.Domains, p.Domains)

	case *capability.RedactFieldsCondition:
		c, ok := child.(*capability.RedactFieldsCondition)
		if !ok {
			return false
		}
		// More fields redacted = more restrictive: parent fields must be a subset of child fields.
		return stringSliceIsSubset(p.Fields, c.Fields)

	case *capability.AllowedValuesCondition:
		c, ok := child.(*capability.AllowedValuesCondition)
		if !ok {
			return false
		}
		if c.Argument != p.Argument {
			return false
		}
		// Fewer allowed values = more restrictive.
		return allowedValuesIsSubset(c.Values, p.Values)

	default:
		// For PolicyCondition, CustomCondition, and unknown types, require the child
		// condition to be byte-identical to the parent. We cannot determine
		// relative restrictiveness for opaque condition payloads.
		return conditionDigest(child) == conditionDigest(parent)
	}
}

// timeWindowIsAtLeastAsRestrictive checks that child's time window is no wider than parent's.
// An empty string means "no bound" (−∞ for NotBefore, +∞ for NotAfter).
func timeWindowIsAtLeastAsRestrictive(child, parent *capability.TimeWindowCondition) bool {
	// If parent enforces a lower bound, child must enforce an equal or later lower bound.
	if parent.NotBefore != "" {
		if child.NotBefore == "" {
			return false // child has no lower bound but parent does
		}
		parentT, err1 := time.Parse(time.RFC3339, parent.NotBefore)
		childT, err2 := time.Parse(time.RFC3339, child.NotBefore)
		if err1 != nil || err2 != nil {
			return false // unparseable time — cannot confirm restrictiveness
		}
		if childT.Before(parentT) {
			return false // child window starts earlier than parent (less restrictive)
		}
	}
	// If parent enforces an upper bound, child must enforce an equal or earlier upper bound.
	if parent.NotAfter != "" {
		if child.NotAfter == "" {
			return false // child has no upper bound but parent does
		}
		parentT, err1 := time.Parse(time.RFC3339, parent.NotAfter)
		childT, err2 := time.Parse(time.RFC3339, child.NotAfter)
		if err1 != nil || err2 != nil {
			return false
		}
		if childT.After(parentT) {
			return false // child window ends later than parent (less restrictive)
		}
	}
	return true
}

// ipRangesAreAtLeastAsRestrictive checks that every child CIDR is fully contained
// within at least one parent CIDR.
func ipRangesAreAtLeastAsRestrictive(childCIDRs, parentCIDRs []string) bool {
	parsedParents := make([]*net.IPNet, 0, len(parentCIDRs))
	for _, cidr := range parentCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedParents = append(parsedParents, network)
		}
	}
	for _, cidr := range childCIDRs {
		_, childNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return false // unparseable CIDR — cannot confirm restrictiveness
		}
		if !cidrContainedByAny(childNet, parsedParents) {
			return false
		}
	}
	return true
}

// cidrContainedByAny reports whether child is fully contained within any of the parent networks.
func cidrContainedByAny(child *net.IPNet, parents []*net.IPNet) bool {
	for _, parent := range parents {
		if networkContains(parent, child) {
			return true
		}
	}
	return false
}

// networkContains reports whether parent fully contains child.
// A parent contains child when the parent's prefix is equal or shorter (broader),
// and the child's network address falls within the parent.
func networkContains(parent, child *net.IPNet) bool {
	pOnes, _ := parent.Mask.Size()
	cOnes, _ := child.Mask.Size()
	// Parent must be at least as broad as child (fewer or equal prefix bits).
	if pOnes > cOnes {
		return false
	}
	// If the parent contains the child's first address, it contains all of the
	// child's addresses because the child is a more-specific sub-network.
	return parent.Contains(child.IP)
}

// allowedTablesIsAtLeastAsRestrictive checks that the child's table/column access
// is a subset of the parent's.
func allowedTablesIsAtLeastAsRestrictive(child, parent *capability.AllowedTablesCondition) bool {
	// Child's accessible tables must be a subset of parent's.
	if !stringSliceIsSubset(child.Tables, parent.Tables) {
		return false
	}
	// For each table with column restrictions in the parent, the child must also
	// restrict columns to a subset of the parent's allowed columns.
	for table, parentCols := range parent.Columns {
		childCols, ok := child.Columns[table]
		if !ok {
			return false // child has no column restriction where parent requires one
		}
		if !stringSliceIsSubset(childCols, parentCols) {
			return false
		}
	}
	return true
}

// stringSliceIsSubset reports whether every element of child appears in parent.
func stringSliceIsSubset(child, parent []string) bool {
	if len(child) == 0 {
		return true
	}
	parentSet := make(map[string]struct{}, len(parent))
	for _, s := range parent {
		parentSet[s] = struct{}{}
	}
	for _, s := range child {
		if _, ok := parentSet[s]; !ok {
			return false
		}
	}
	return true
}

// allowedValuesIsSubset reports whether every value in child appears in parent.
func allowedValuesIsSubset(child, parent []interface{}) bool {
	if len(child) == 0 {
		return true
	}
	// Use string-keyed set via JSON marshalling to handle mixed scalar types.
	parentSet := make(map[string]struct{}, len(parent))
	for _, v := range parent {
		if key, err := json.Marshal(v); err == nil {
			parentSet[string(key)] = struct{}{}
		}
	}
	for _, v := range child {
		key, err := json.Marshal(v)
		if err != nil {
			return false
		}
		if _, ok := parentSet[string(key)]; !ok {
			return false
		}
	}
	return true
}

// conditionDigest returns a stable JSON serialisation of a condition for equality comparison.
func conditionDigest(c capability.Condition) string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

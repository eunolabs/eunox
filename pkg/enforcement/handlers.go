// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// registerBuiltins registers all built-in condition handlers.
// D-4 fix: each method value is wrapped in ConditionHandlerFunc so that it
// satisfies the ConditionHandler interface.
func (e *Engine) registerBuiltins() {
	e.handlers[capability.ConditionTypeTimeWindow] = ConditionHandlerFunc(e.handleTimeWindow)
	e.handlers[capability.ConditionTypeIPRange] = ConditionHandlerFunc(e.handleIPRange)
	e.handlers[capability.ConditionTypeMaxCalls] = ConditionHandlerFunc(e.handleMaxCalls)
	e.handlers[capability.ConditionTypeAllowedOperations] = ConditionHandlerFunc(e.handleAllowedOperations)
	e.handlers[capability.ConditionTypeAllowedExtensions] = ConditionHandlerFunc(e.handleAllowedExtensions)
	e.handlers[capability.ConditionTypeAllowedTables] = ConditionHandlerFunc(e.handleAllowedTables)
	e.handlers[capability.ConditionTypeRecipientDomain] = ConditionHandlerFunc(e.handleRecipientDomain)
	e.handlers[capability.ConditionTypeAllowedValues] = ConditionHandlerFunc(e.handleAllowedValues)
	e.handlers[capability.ConditionTypePolicy] = ConditionHandlerFunc(e.handlePolicy)
	e.handlers[capability.ConditionTypeCustom] = ConditionHandlerFunc(e.handleCustom)
}

func (e *Engine) handleTimeWindow(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	tw, ok := asTimeWindow(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeTimeWindow,
			Message:       "invalid timeWindow condition type",
		}
	}

	now := e.clock.Now().UTC()

	if tw.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, tw.NotBefore)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       fmt.Sprintf("invalid notBefore time: %s", tw.NotBefore),
			}
		}
		if now.Before(notBefore.UTC()) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       "request is before the allowed time window",
				Details: map[string]interface{}{
					"notBefore": tw.NotBefore,
					"now":       now.Format(time.RFC3339),
				},
			}
		}
	}

	if tw.NotAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, tw.NotAfter)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       fmt.Sprintf("invalid notAfter time: %s", tw.NotAfter),
			}
		}
		if now.After(notAfter.UTC()) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       "request is after the allowed time window",
				Details: map[string]interface{}{
					"notAfter": tw.NotAfter,
					"now":      now.Format(time.RFC3339),
				},
			}
		}
	}

	return nil
}

func (e *Engine) handleIPRange(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ipr, ok := asIPRange(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeIPRange,
			Message:       "invalid ipRange condition type",
		}
	}

	if req.Context.SourceIP == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeIPRange,
			Message:       "sourceIp is required for ipRange condition",
		}
	}

	ip := net.ParseIP(req.Context.SourceIP)
	if ip == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeIPRange,
			Message:       fmt.Sprintf("invalid source IP: %s", req.Context.SourceIP),
		}
	}

	for _, cidr := range ipr.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeIPRange,
				Message:       fmt.Sprintf("invalid CIDR in condition: %s", cidr),
			}
		}
		if network.Contains(ip) {
			return nil
		}
	}

	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeIPRange,
		Message:       "source IP is not in allowed ranges",
		Details: map[string]interface{}{
			"sourceIp":     req.Context.SourceIP,
			"allowedCIDRs": ipr.CIDRs,
		},
	}
}

func (e *Engine) handleMaxCalls(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	mc, ok := asMaxCalls(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "invalid maxCalls condition type",
		}
	}

	// In dry-run mode (e.g. preflight /validate) skip the counter entirely so
	// that quota is not consumed.  The condition is treated as satisfied.
	if isDryRun(ctx) {
		return nil
	}

	if e.counter == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "call counter not configured",
		}
	}

	// A missing sessionID would make the key "maxcalls::<tool>", merging quota
	// across all anonymous callers (denial-of-service or quota bypass). Deny
	// rather than silently creating a cross-session shared bucket.
	if req.SessionID == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "sessionId is required for maxCalls condition",
		}
	}

	// Build a unique key from session + tool
	key := fmt.Sprintf("maxcalls:%s:%s", req.SessionID, req.ToolName)
	count, err := e.counter.IncrementAndGet(ctx, key, mc.WindowSeconds)
	if err != nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       fmt.Sprintf("call counter error: %v", err),
		}
	}

	if count > int64(mc.Count) {
		return &ConditionError{
			Code:          capability.ErrCodeRateLimited,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "call limit exceeded",
			Details: map[string]interface{}{
				"limit":   mc.Count,
				"current": count,
				"window":  mc.WindowSeconds,
			},
		}
	}

	return nil
}

func (e *Engine) handleAllowedOperations(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ao, ok := asAllowedOperations(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       "invalid allowedOperations condition type",
		}
	}

	operation := req.Context.Operation
	if operation == "" {
		operation = req.ToolName
	}

	for _, allowed := range ao.Operations {
		if allowed == operation || allowed == "*" {
			return nil
		}
	}

	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeAllowedOperations,
		Message:       fmt.Sprintf("operation %q is not allowed", operation),
		Details: map[string]interface{}{
			"operation":         operation,
			"allowedOperations": ao.Operations,
		},
	}
}

func (e *Engine) handleAllowedExtensions(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ae, ok := asAllowedExtensions(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedExtensions,
			Message:       "invalid allowedExtensions condition type",
		}
	}

	filePath := req.Context.FilePath
	if filePath == "" {
		// If no file path in context, check arguments
		if fp, ok := req.Arguments["filePath"]; ok {
			if s, ok := fp.(string); ok {
				filePath = s
			}
		}
	}

	if filePath == "" {
		// filePath is required: deny rather than silently skipping the check.
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedExtensions,
			Message:       "filePath is required for allowedExtensions condition",
		}
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedExtensions,
			Message:       "file has no extension",
			Details: map[string]interface{}{
				"filePath":          filePath,
				"allowedExtensions": ae.Extensions,
			},
		}
	}

	// Normalize: remove leading dot for comparison
	extNoDot := ext[1:]

	for _, allowed := range ae.Extensions {
		normalized := strings.TrimPrefix(strings.ToLower(allowed), ".")
		if normalized == extNoDot {
			return nil
		}
	}

	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeAllowedExtensions,
		Message:       fmt.Sprintf("file extension %q is not allowed", ext),
		Details: map[string]interface{}{
			"filePath":          filePath,
			"extension":         ext,
			"allowedExtensions": ae.Extensions,
		},
	}
}

func (e *Engine) handleAllowedTables(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	at, ok := asAllowedTables(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedTables,
			Message:       "invalid allowedTables condition type",
		}
	}

	if len(req.Context.Tables) == 0 {
		// tables is required: deny rather than silently skipping the check.
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedTables,
			Message:       "tables is required for allowedTables condition",
		}
	}

	allowedTableSet := make(map[string]bool, len(at.Tables))
	for _, t := range at.Tables {
		allowedTableSet[t] = true
	}

	for _, access := range req.Context.Tables {
		if !allowedTableSet[access.Table] {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedTables,
				Message:       fmt.Sprintf("table %q is not allowed", access.Table),
				Details: map[string]interface{}{
					"table":         access.Table,
					"allowedTables": at.Tables,
				},
			}
		}

		// Check column restrictions if specified.
		// H-3 fix: when the capability defines column restrictions for a table, an
		// empty access.Columns slice must be explicitly denied. Previously the guard
		// `if hasColumnRestriction && len(access.Columns) > 0` skipped the check
		// entirely for empty slices, allowing agents to bypass column-level ACLs by
		// omitting the columns field.
		if at.Columns != nil {
			allowedCols, hasColumnRestriction := at.Columns[access.Table]
			if hasColumnRestriction {
				if len(access.Columns) == 0 {
					return &ConditionError{
						Code:          capability.ErrCodeMissingContext,
						ConditionType: capability.ConditionTypeAllowedTables,
						Message:       fmt.Sprintf("column list required for table %q (column restrictions are configured)", access.Table),
						Details: map[string]interface{}{
							"table":          access.Table,
							"allowedColumns": allowedCols,
						},
					}
				}
				colSet := make(map[string]bool, len(allowedCols))
				for _, c := range allowedCols {
					colSet[c] = true
				}
				for _, col := range access.Columns {
					if !colSet[col] {
						return &ConditionError{
							Code:          capability.ErrCodeConditionFailed,
							ConditionType: capability.ConditionTypeAllowedTables,
							Message:       fmt.Sprintf("column %q on table %q is not allowed", col, access.Table),
							Details: map[string]interface{}{
								"table":          access.Table,
								"column":         col,
								"allowedColumns": allowedCols,
							},
						}
					}
				}
			}
		}
	}

	return nil
}

func (e *Engine) handleRecipientDomain(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	rd, ok := asRecipientDomain(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeRecipientDomain,
			Message:       "invalid recipientDomain condition type",
		}
	}

	if len(req.Context.Recipients) == 0 {
		// recipients is required: deny rather than silently skipping the check.
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeRecipientDomain,
			Message:       "recipients is required for recipientDomain condition",
		}
	}

	domainSet := make(map[string]bool, len(rd.Domains))
	for _, d := range rd.Domains {
		domainSet[strings.ToLower(d)] = true
	}

	for _, recipient := range req.Context.Recipients {
		parts := strings.SplitN(recipient, "@", 2)
		if len(parts) != 2 {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeRecipientDomain,
				Message:       fmt.Sprintf("invalid recipient email: %s", recipient),
			}
		}
		domain := strings.ToLower(parts[1])
		if !domainSet[domain] {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeRecipientDomain,
				Message:       fmt.Sprintf("recipient domain %q is not allowed", domain),
				Details: map[string]interface{}{
					"recipient":      recipient,
					"domain":         domain,
					"allowedDomains": rd.Domains,
				},
			}
		}
	}

	return nil
}

func (e *Engine) handleAllowedValues(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	av, ok := asAllowedValues(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       "invalid allowedValues condition type",
		}
	}

	if av.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       "allowedValues condition has empty argument name",
		}
	}

	argValue, present := req.Arguments[av.Argument]
	if !present {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       fmt.Sprintf("required argument %q is missing", av.Argument),
			Details: map[string]interface{}{
				"argument": av.Argument,
			},
		}
	}

	for _, allowed := range av.Values {
		// Exact match (handles non-string types: bool, number, nil).
		if reflect.DeepEqual(allowed, argValue) {
			return nil
		}
		// Glob match: when both the pattern and the argument value are strings,
		// apply path.Match so that values like "/reports/*" match "/reports/q3.pdf".
		// path.Match uses slash as the separator on all platforms, which is correct
		// for URL-style path arguments.  A malformed pattern (path.ErrBadPattern)
		// falls through to the next allowed value rather than causing an error.
		if pattern, patOK := allowed.(string); patOK {
			if str, strOK := argValue.(string); strOK {
				if matched, err := path.Match(pattern, str); err == nil && matched {
					return nil
				}
			}
		}
	}

	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeAllowedValues,
		Message:       fmt.Sprintf("argument %q value is not in the allowed set", av.Argument),
		Details: map[string]interface{}{
			"argument":      av.Argument,
			"value":         argValue,
			"allowedValues": av.Values,
		},
	}
}

func (e *Engine) handlePolicy(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	pc, ok := asPolicy(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypePolicy,
			Message:       "invalid policy condition type",
		}
	}

	// Fail closed: require an explicit policy evaluator. Capabilities that carry
	// a policy condition must not be silently allowed when no evaluator is wired
	// up — configure one via WithPolicyEvaluator.
	if e.policyEvaluator == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypePolicy,
			Message:       "no policy evaluator configured; register one via WithPolicyEvaluator",
			Details: map[string]interface{}{
				"backend": pc.Backend,
			},
		}
	}

	return e.policyEvaluator.Evaluate(ctx, pc.Backend, pc.Config, pc.Input, req)
}

func (e *Engine) handleCustom(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	cc, ok := asCustom(cond)
	if !ok {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeCustom,
			Message:       "invalid custom condition type",
		}
	}

	// Fail closed: no handler has been registered for custom conditions.
	// Call RegisterCondition(capability.ConditionTypeCustom, handler) to supply
	// a dispatcher that resolves conditions by their Name field.
	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeCustom,
		Message:       fmt.Sprintf("no handler registered for custom condition %q; register one via RegisterCondition", cc.Name),
		Details: map[string]interface{}{
			"name": cc.Name,
		},
	}
}

func asTimeWindow(cond capability.Condition) (*capability.TimeWindowCondition, bool) {
	if t, ok := cond.(*capability.TimeWindowCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.TimeWindowCondition); ok {
		return &t, true
	}
	return nil, false
}

func asIPRange(cond capability.Condition) (*capability.IPRangeCondition, bool) {
	if t, ok := cond.(*capability.IPRangeCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.IPRangeCondition); ok {
		return &t, true
	}
	return nil, false
}

func asMaxCalls(cond capability.Condition) (*capability.MaxCallsCondition, bool) {
	if t, ok := cond.(*capability.MaxCallsCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.MaxCallsCondition); ok {
		return &t, true
	}
	return nil, false
}

func asAllowedOperations(cond capability.Condition) (*capability.AllowedOperationsCondition, bool) {
	if t, ok := cond.(*capability.AllowedOperationsCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.AllowedOperationsCondition); ok {
		return &t, true
	}
	return nil, false
}

func asAllowedExtensions(cond capability.Condition) (*capability.AllowedExtensionsCondition, bool) {
	if t, ok := cond.(*capability.AllowedExtensionsCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.AllowedExtensionsCondition); ok {
		return &t, true
	}
	return nil, false
}

func asAllowedTables(cond capability.Condition) (*capability.AllowedTablesCondition, bool) {
	if t, ok := cond.(*capability.AllowedTablesCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.AllowedTablesCondition); ok {
		return &t, true
	}
	return nil, false
}

func asRecipientDomain(cond capability.Condition) (*capability.RecipientDomainCondition, bool) {
	if t, ok := cond.(*capability.RecipientDomainCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.RecipientDomainCondition); ok {
		return &t, true
	}
	return nil, false
}

func asPolicy(cond capability.Condition) (*capability.PolicyCondition, bool) {
	if t, ok := cond.(*capability.PolicyCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.PolicyCondition); ok {
		return &t, true
	}
	return nil, false
}

func asCustom(cond capability.Condition) (*capability.CustomCondition, bool) {
	if t, ok := cond.(*capability.CustomCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.CustomCondition); ok {
		return &t, true
	}
	return nil, false
}

func asAllowedValues(cond capability.Condition) (*capability.AllowedValuesCondition, bool) {
	if t, ok := cond.(*capability.AllowedValuesCondition); ok {
		return t, true
	}
	if t, ok := cond.(capability.AllowedValuesCondition); ok {
		return &t, true
	}
	return nil, false
}

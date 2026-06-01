// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct{ now time.Time }

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }
func (fc *fakeClock) Now() time.Time      { return fc.now }

func TestEngine_ValidateAction_NoMatchingCapability(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "unknown-tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "other-tool", Actions: []string{"read"}},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

func TestEngine_ValidateAction_AllowWildcard(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "any-tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "*", Actions: []string{"*"}},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.NotEmpty(t, resp.RequestID)
	assert.NotEmpty(t, resp.DecidedAt)
}

func TestEngine_ValidateAction_AllowExactMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:send", Actions: []string{"call"}},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_PrefixMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:read",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "file:*", Actions: []string{"*"}},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_Allow(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_DenyBefore(t *testing.T) {
	now := time.Date(2025, 6, 15, 9, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_TimeWindow_DenyAfter(t *testing.T) {
	now := time.Date(2025, 6, 15, 15, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotAfter: "2025-06-15T14:00:00Z",
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_IPRange_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context:   capability.EnforceRequestContext{SourceIP: "10.0.1.50"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_IPRange_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context:   capability.EnforceRequestContext{SourceIP: "192.168.1.1"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

func TestEngine_IPRange_MissingSourceIP(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_IPRange_InvalidCIDR(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			SourceIP: "10.0.0.1",
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"not-a-valid-cidr"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

func TestEngine_MaxCalls_Allow(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	caps := []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			},
		},
	}

	// First call should be allowed
	resp, err := engine.ValidateAction(ctx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MaxCalls_Deny(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	caps := []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 3, WindowSeconds: 60},
			},
		},
	}

	// Make 3 calls (all should be allowed)
	for i := 0; i < 3; i++ {
		resp, err := engine.ValidateAction(ctx, &req, caps)
		require.NoError(t, err)
		assert.Equal(t, capability.DecisionAllow, resp.Decision, "call %d should be allowed", i+1)
	}

	// 4th call should be denied
	resp, err := engine.ValidateAction(ctx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
}

func TestEngine_MaxCalls_EmptySessionIDDenies(t *testing.T) {
	// When SessionID is empty the maxCalls counter key would merge traffic from
	// every session, creating a shared global counter — a mis-accounting bug that
	// can also be abused to exhaust another tenant's quota.  The engine must
	// deny with ErrCodeMissingContext rather than silently increment the counter.
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		// SessionID intentionally blank.
		ToolName: "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 100, WindowSeconds: 60},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
}

func TestEngine_AllowedOperations_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file",
		Arguments: map[string]interface{}{"op": "read"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "list"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file",
		Arguments: map[string]interface{}{"op": "delete"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "list"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
}

func TestEngine_AllowedExtensions_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:read",
		Arguments: map[string]interface{}{"path": "/docs/report.pdf"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:read",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf", ".txt", ".md"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:read",
		Arguments: map[string]interface{}{"path": "/etc/passwords.sh"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:read",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf", ".txt", ".md"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
}

func TestEngine_AllowedTables_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []interface{}{"name", "email"},
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"users", "orders"},
					Columns:  map[string][]string{"users": {"name", "email", "id"}},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_DenyTable(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{"table": "secrets"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users", "orders"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
}

func TestEngine_AllowedTables_DenyColumn(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []interface{}{"password_hash"},
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"users"},
					Columns:  map[string][]string{"users": {"name", "email"}},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// TestEngine_AllowedTables_EmptyColumnsWithRestriction is the H-3 regression test.
//
// When a capability defines column restrictions for a table, an agent that sends
// an empty columns slice must be denied. Previously, `if hasColumnRestriction &&
// len(access.Columns) > 0` skipped the column check entirely for an empty slice,
// allowing full-column access to tables with configured restrictions.
func TestEngine_AllowedTables_EmptyColumnsWithRestriction(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-h3",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "payments",
				"columns": []interface{}{}, // empty — must be denied (H-3 regression)
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"payments"},
					Columns:  map[string][]string{"payments": {"amount", "currency"}},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision, "empty column list must be denied when column restrictions exist (H-3)")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
}

func TestEngine_RecipientDomain_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
		Arguments: map[string]interface{}{
			"to": []interface{}{"user@example.com", "admin@example.com"},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "email:send",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
		Arguments: map[string]interface{}{
			"to": []interface{}{"user@example.com", "evil@attacker.com"},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "email:send",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
}

func TestEngine_RedactFields_ProducesObligation(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.RedactFieldsCondition{Fields: []string{"$.ssn", "$.creditCard"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, "redactFields", resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.ssn", "$.creditCard"}, resp.Obligations[0].Paths)
}

func TestEngine_PolicyCondition_DenyWhenNoEvaluatorConfigured(t *testing.T) {
	// Without a PolicyEvaluator the engine must deny (fail-closed) so that a
	// misconfigured deployment cannot silently allow policy-gated requests.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa", Config: map[string]interface{}{"policy": "allow"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypePolicy, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "WithPolicyEvaluator")
}

func TestEngine_PolicyCondition_EvaluatorAllow(t *testing.T) {
	evaluator := &fakePolicyEvaluator{result: nil}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(evaluator))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.True(t, evaluator.called)
}

func TestEngine_PolicyCondition_EvaluatorDeny(t *testing.T) {
	evaluator := &fakePolicyEvaluator{
		result: &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypePolicy,
			Message:       "policy denies this action",
		},
	}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(evaluator))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "policy denies this action", resp.Denial.Message)
}

// fakePolicyEvaluator is a test double for enforcement.PolicyEvaluator.
type fakePolicyEvaluator struct {
	called bool
	result *enforcement.ConditionError
}

func (f *fakePolicyEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
	f.called = true
	return f.result
}

func TestEngine_CustomCondition_DenyWhenNoHandlerRegistered(t *testing.T) {
	// Without an explicit handler registered for ConditionTypeCustom the engine
	// must deny (fail-closed) so that unknown custom conditions cannot silently
	// allow requests.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.CustomCondition{Name: "my-check", Config: "data"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeCustom, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "my-check")
	assert.Contains(t, resp.Denial.Message, "RegisterCondition")
}

func TestEngine_AllowedExtensions_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	// The "argument" field is required — guessing argument names is not allowed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "file:write"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:write",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Extensions: []string{".pdf"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_AllowedExtensions_ArgumentValueMissing(t *testing.T) {
	// "argument" is set but the named argument is absent from the tool call.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:write",
		Arguments: map[string]interface{}{"other": "value"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:write",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
}

func TestEngine_AllowedTables_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "db:query"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Tables: []string{"users"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_AllowedTables_ArgumentValueMissing(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{"other": "irrelevant"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_RecipientDomain_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "email:send"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "email:send",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Domains: []string{"example.com"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_RecipientDomain_ArgumentValueMissing(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
		Arguments: map[string]interface{}{"subject": "hello"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "email:send",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_RegisterCustomCondition(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	// Override the custom handler to deny all.
	// D-4: wrap the plain func with enforcement.ConditionHandlerFunc.
	engine.RegisterCondition(capability.ConditionTypeCustom, enforcement.ConditionHandlerFunc(func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
		return &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeCustom,
			Message:       "custom condition denied",
		}
	}))

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.CustomCondition{Name: "deny-all"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, "custom condition denied", resp.Denial.Message)
}

func TestEngine_MultipleConditions_AllMustPass(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			SourceIP: "10.0.0.5",
		},
		Arguments: map[string]interface{}{"op": "read"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "write"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MultipleConditions_FirstFailureDenies(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			SourceIP:  "192.168.1.1", // Not in allowed range
	
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

func TestEngine_EmptyActions_MatchesAny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "tool", Actions: nil},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_FromNamedArgument(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:write",
		Arguments: map[string]interface{}{"filePath": "/tmp/data.csv"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:write",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "filePath", Extensions: []string{"csv", "json"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_IgnoresRequestContextNow(t *testing.T) {
	// req.Context.Now must be ignored; the server clock is always authoritative
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	engine := enforcement.New(enforcement.WithClock(newFakeClock(fixedTime)))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			// Client supplies a different "now" that falls outside the window —
			// the engine must not use it; it must use the server clock instead.
			Now: "2020-01-01T00:00:00Z",
		},
	}

	// Window is open at the fixed server time (12:00) — should allow
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)

	// Window is closed at the fixed server time (12:00) — should deny regardless of req.Context.Now
	req2 := capability.EnforceRequest{
		SessionID: "sess-2",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			// Client supplies a "now" inside the (future) window — must be ignored
			Now: "2025-06-15T16:00:00Z",
		},
	}
	resp2, err := engine.ValidateAction(ctx, &req2, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T15:00:00Z",
					NotAfter:  "2025-06-15T17:00:00Z",
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp2.Decision)
}

func TestEngine_AllowedValues_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	tests := []struct {
		name     string
		argument string
		values   []interface{}
		args     map[string]interface{}
	}{
		{
			name:     "string match",
			argument: "format",
			values:   []interface{}{"json", "csv"},
			args:     map[string]interface{}{"format": "json"},
		},
		{
			name:     "boolean match",
			argument: "strict",
			values:   []interface{}{true},
			args:     map[string]interface{}{"strict": true},
		},
		{
			name:     "nil value in allowed list",
			argument: "filter",
			values:   []interface{}{nil, "all"},
			args:     map[string]interface{}{"filter": nil},
		},
		// Glob patterns — path.Match semantics.
		{
			name:     "glob slash-star matches file under directory",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/reports/q3.pdf"},
		},
		{
			name:     "glob star-dot-ext matches extension",
			argument: "path",
			values:   []interface{}{"*.pdf"},
			args:     map[string]interface{}{"path": "report.pdf"},
		},
		{
			name:     "glob question-mark matches single char",
			argument: "env",
			values:   []interface{}{"prod-?"},
			args:     map[string]interface{}{"env": "prod-1"},
		},
		{
			name:     "glob mixed with exact: exact value wins before reaching glob",
			argument: "path",
			values:   []interface{}{"/reports/q3.pdf", "/reports/*"},
			args:     map[string]interface{}{"path": "/reports/q3.pdf"},
		},
		{
			name:     "glob with prefix wildcard",
			argument: "service",
			values:   []interface{}{"aws-*"},
			args:     map[string]interface{}{"service": "aws-prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				SessionID: "sess-1",
				ToolName:  "tool",
				Arguments: tt.args,
			}
			resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{
					Resource: "tool",
					Actions:  []string{"*"},
					Conditions: []capability.Condition{
						&capability.AllowedValuesCondition{
							Argument: tt.argument,
							Values:   tt.values,
						},
					},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, capability.DecisionAllow, resp.Decision, tt.name)
		})
	}
}

func TestEngine_AllowedValues_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Arguments: map[string]interface{}{"format": "xml"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "format",
					Values:   []interface{}{"json", "csv"},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_GlobDeny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	tests := []struct {
		name     string
		argument string
		values   []interface{}
		args     map[string]interface{}
	}{
		{
			name:     "glob no match: path outside directory",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/internal/secret.txt"},
		},
		{
			name:     "glob no match: subdirectory not matched by single star",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/reports/sub/file.txt"},
		},
		{
			name:     "glob no match: extension mismatch",
			argument: "path",
			values:   []interface{}{"*.pdf"},
			args:     map[string]interface{}{"path": "report.csv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				SessionID: "sess-1",
				ToolName:  "tool",
				Arguments: tt.args,
			}
			resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{
					Resource: "tool",
					Actions:  []string{"*"},
					Conditions: []capability.Condition{
						&capability.AllowedValuesCondition{
							Argument: tt.argument,
							Values:   tt.values,
						},
					},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, capability.DecisionDeny, resp.Decision, tt.name)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
		})
	}
}

func TestEngine_AllowedValues_MalformedGlobFallsThrough(t *testing.T) {
	// A malformed glob pattern (path.ErrBadPattern) must not cause an error —
	// it should fall through to the next value and ultimately deny.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Arguments: map[string]interface{}{"path": "/reports/q3.pdf"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"[bad-pattern"},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// path.Match glob semantics tests.

func TestEngine_ValidateAction_GlobQuestionMark(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:a",
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "file:?", Actions: []string{"*"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_GlobQuestionMark_NoMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:ab",
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "file:?", Actions: []string{"*"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_ValidateAction_GlobCharacterClass(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool:b",
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "tool:[abc]", Actions: []string{"*"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_MidStringWildcard(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file:data.csv",
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "file:*.csv", Actions: []string{"*"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestValidateResourcePattern_Valid(t *testing.T) {
	cases := []string{"*", "tool:*", "file:?.csv", "tool:[abc]", "email:send"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			assert.NoError(t, enforcement.ValidateResourcePattern(c))
		})
	}
}

func TestValidateResourcePattern_Invalid(t *testing.T) {
	// Unclosed character class is a malformed pattern.
	err := enforcement.ValidateResourcePattern("tool:[abc")
	assert.Error(t, err)
}

func TestEngine_MostSpecificMatch_NarrowCapabilityWins(t *testing.T) {
	// Exact resource beats glob: email:send is more specific than email:*
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "email:send"}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "email:send", Actions: []string{"call"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_ExactResourceBeatsWildcard(t *testing.T) {
	// Exact resource entry (no conditions) wins over glob with a deny condition.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "email:send"}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "email:send", Actions: []string{"call"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_LongerPrefixWins(t *testing.T) {
	// A longer literal prefix in a glob beats a shorter one.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "tool:mail"}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "tool:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "tool:mail", Actions: []string{"call"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_OrderingDoesNotMatter(t *testing.T) {
	// The most-specific constraint wins regardless of its position in the list.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "file:read"}
	constraints := []capability.Constraint{
		{Resource: "file:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "file:read", Actions: []string{"call"}},
	}

	respA, err := engine.ValidateAction(ctx, &req, constraints)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, respA.Decision)

	respB, err := engine.ValidateAction(ctx, &req, []capability.Constraint{constraints[1], constraints[0]})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, respB.Decision)
}

// ── ConditionError ──────────────────────────────────────────────────────────

func TestConditionError_Error(t *testing.T) {
	t.Parallel()
	ce := &enforcement.ConditionError{
		Code:          "TEST_CODE",
		ConditionType: "timeWindow",
		Message:       "something went wrong",
	}
	assert.Equal(t, "something went wrong", ce.Error())
}

// ── WithDryRun ──────────────────────────────────────────────────────────────

func TestEngine_WithDryRun_SkipsMaxCallsIncrement(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))

	// Normal context: MaxCalls=1 is consumed on the first call.
	ctx := context.Background()
	req := capability.EnforceRequest{
		SessionID: "sess-dry",
		ToolName:  "tool",
	}
	caps := []capability.Constraint{{
		Resource:   "tool",
		Actions:    []string{"*"},
		Conditions: []capability.Condition{&capability.MaxCallsCondition{Count: 1, WindowSeconds: 60}},
	}}

	resp, err := engine.ValidateAction(ctx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)

	// Second call on normal context is denied (quota exhausted).
	resp, err = engine.ValidateAction(ctx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)

	// Dry-run context: quota must NOT be consumed.
	freshCounter := callcounter.NewInMemory()
	engineDry := enforcement.New(enforcement.WithCallCounter(freshCounter))
	dryCtx := enforcement.WithDryRun(context.Background())

	resp, err = engineDry.ValidateAction(dryCtx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision, "dry-run must pass MaxCalls without consuming quota")

	// On a normal context after the dry-run the quota is still intact (count is zero).
	resp, err = engineDry.ValidateAction(ctx, &req, caps)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision, "quota must not have been consumed during dry-run")
}

// ── FindMatchingCapability ──────────────────────────────────────────────────

func TestEngine_FindMatchingCapability_ReturnsMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{ToolName: "read_file"}
	caps := []capability.Constraint{
		{Resource: "write_file", Actions: []string{"*"}},
		{Resource: "read_file", Actions: []string{"*"}},
	}

	matched := engine.FindMatchingCapability(req, caps)
	require.NotNil(t, matched)
	assert.Equal(t, "read_file", matched.Resource)
}

func TestEngine_FindMatchingCapability_ReturnsNilWhenNoMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{ToolName: "delete_file"}
	caps := []capability.Constraint{
		{Resource: "read_file", Actions: []string{"*"}},
	}

	matched := engine.FindMatchingCapability(req, caps)
	assert.Nil(t, matched)
}

// ── Value-form condition branch coverage ───────────────────────────────────
//
// Each `as*` helper in pkg/enforcement/handlers.go tries the pointer-form type
// assertion first and falls back to value-form. Existing tests always pass pointer
// conditions. The tests below pass value-form (non-pointer) conditions to exercise
// the second branch.

func TestEngine_TimeWindow_ValueForm(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	engine := enforcement.New(enforcement.WithClock(newFakeClock(now)))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "tool",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			// value form — not pointer
			capability.TimeWindowCondition{
				NotBefore: "2025-06-15T10:00:00Z",
				NotAfter:  "2025-06-15T14:00:00Z",
			},
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_IPRange_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "tool",
		Context:   capability.EnforceRequestContext{SourceIP: "192.168.1.50"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "tool",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.IPRangeCondition{CIDRs: []string{"192.168.0.0/16"}}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedOperations.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "db",
		Arguments: map[string]interface{}{"query": "SELECT 1"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "db",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedOperationsCondition{Argument: "query", Operations: []string{"SELECT"}}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedExtensions.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "file:read",
		Arguments: map[string]interface{}{"path": "/docs/report.pdf"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "file:read",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedTables.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "db:query",
		Arguments: map[string]interface{}{"table": "reports"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "db:query",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedTablesCondition{Argument: "table", Tables: []string{"reports"}}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MaxCalls_ValueForm(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-mc-val", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "tool",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "email:send",
		Arguments: map[string]interface{}{"to": "alice@example.com"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "email:send",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}}, // value form
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_Policy_ValueForm(t *testing.T) {
	t.Parallel()
	// A nil PolicyEvaluator with a policy condition is fail-closed (deny).
	// The important thing is that asPolicy's value-form branch is exercised.
	engine := enforcement.New() // no PolicyEvaluator wired
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "tool",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"}, // value form
		},
	}})

	require.NoError(t, err)
	// Fail-closed: no evaluator → deny.
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_Custom_ValueForm(t *testing.T) {
	t.Parallel()
	// The built-in custom handler always denies (fail-closed). This test verifies
	// that asCustom's value-form branch is exercised: a value-form CustomCondition
	// is correctly identified and the handler is reached (result is deny, as designed).
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "tool",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.CustomCondition{Name: "my-custom", Config: nil}, // value form
		},
	}})

	require.NoError(t, err)
	// Fail-closed: built-in handleCustom always denies.
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeCustom, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/reports/q3.pdf"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "read_file",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedValuesCondition{ // value form
				Argument: "path",
				Values:   []interface{}{"/reports/*"},
			},
		},
	}})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// ── Additional coverage tests ───────────────────────────────────────────────

func TestEngine_MatchesResource_BadGlobPattern(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{ToolName: "anything"}
	matched := engine.FindMatchingCapability(req, []capability.Constraint{
		{Resource: "[", Actions: []string{"*"}},
	})
	assert.Nil(t, matched, "bad glob pattern must produce no match")
}

func TestEngine_AllowedOperations_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	// The old heuristic fallback (guessing argument names, falling back to
	// tool name) is removed — deterministic enforcement requires an explicit
	// "argument" declaration.
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "myTool",
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "myTool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Operations: []string{"myTool"}},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_TimeWindow_InvalidNotBefore(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithClock(newFakeClock(time.Now())))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{NotBefore: "not-a-date"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_TimeWindow_InvalidNotAfter(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithClock(newFakeClock(time.Now())))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{NotAfter: "not-a-date"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_EmptyArgumentName(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "", Values: []interface{}{"x"}},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_MissingArgument(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Arguments: nil, // no arguments at all
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp"}},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_AllowedValues_ExactMatchNonString(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Arguments: map[string]interface{}{"count": float64(42)},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "count",
					Values:   []interface{}{float64(42)},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedValues_NoMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Arguments: map[string]interface{}{"color": "c"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "color",
					Values:   []interface{}{"a", "b"},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// errorCounter is a CallCounter that always returns an error.
type errorCounter struct{}

func (errorCounter) IncrementAndGet(_ context.Context, _ string, _ int) (int64, error) {
	return 0, errors.New("counter error")
}

func TestEngine_MaxCalls_CounterError(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(errorCounter{}))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 10, WindowSeconds: 60},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "call counter error")
}

// allowEvaluator is a PolicyEvaluator that always allows.
type allowEvaluator struct{}

func (allowEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
	return nil
}

func TestEngine_Policy_WithEvaluator_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithPolicyEvaluator(allowEvaluator{}))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", ToolName: "tool"}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "tool",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "test"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// ── Named-argument mode tests ───────────────────────────────────────────────
//
// Each condition type that previously relied on hardcoded heuristic argument
// name extraction now supports an explicit "argument" field.  The tests below
// verify that specifying the argument name takes precedence over the heuristic
// and works for non-standard argument names.

func TestEngine_AllowedOperations_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	// Tool uses "command" instead of "sql"/"query"/"statement".
	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "run_db",
		Arguments: map[string]interface{}{"command": "SELECT * FROM orders"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "run_db",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "run_db",
		Arguments: map[string]interface{}{"command": "DROP TABLE orders"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "run_db",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
}

func TestEngine_AllowedOperations_NamedArgument_Missing(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "run_db",
		Arguments: map[string]interface{}{"other": "value"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "run_db",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_AllowedExtensions_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "upload",
		Arguments: map[string]interface{}{"filename": "/data/report.csv"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "upload",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedExtensionsCondition{
				Argument:   "filename",
				Extensions: []string{".csv", ".json"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "upload",
		Arguments: map[string]interface{}{"filename": "/data/malware.exe"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "upload",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedExtensionsCondition{
				Argument:   "filename",
				Extensions: []string{".csv", ".json"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query",
		Arguments: map[string]interface{}{"target_table": "orders"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "query",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query",
		Arguments: map[string]interface{}{"target_table": "salaries"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "query",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_ArrayAllow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query",
		Arguments: map[string]interface{}{
			"target_table": []interface{}{"orders", "customers"},
		},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "query",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers", "products"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "send_notification",
		Arguments: map[string]interface{}{"dest_email": "alice@example.com"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "send_notification",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "send_notification",
		Arguments: map[string]interface{}{"dest_email": "attacker@evil.com"},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "send_notification",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_RecipientDomain_NamedArgument_ArrayAllow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "send_notification",
		Arguments: map[string]interface{}{
			"dest_email": []interface{}{"alice@example.com", "bob@example.com"},
		},
	}
	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Resource: "send_notification",
		Actions:  []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package enforcement_test

import (
	"context"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		Context:   capability.EnforceRequestContext{Operation: "email:send"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:send", Actions: []string{"email:send"}},
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
	clock := testutil.NewFakeClock(now)
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
	clock := testutil.NewFakeClock(now)
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
	clock := testutil.NewFakeClock(now)
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

func TestEngine_AllowedOperations_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "file",
		Context:   capability.EnforceRequestContext{Operation: "read"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Operations: []string{"read", "list"}},
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
		Context:   capability.EnforceRequestContext{Operation: "delete"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Operations: []string{"read", "list"}},
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
		Context:   capability.EnforceRequestContext{FilePath: "/docs/report.pdf"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:read",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Extensions: []string{".pdf", ".txt", ".md"}},
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
		Context:   capability.EnforceRequestContext{FilePath: "/etc/passwords.sh"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "file:read",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Extensions: []string{".pdf", ".txt", ".md"}},
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
		Context: capability.EnforceRequestContext{
			Tables: []capability.TableAccess{
				{Table: "users", Columns: []string{"name", "email"}},
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Tables:  []string{"users", "orders"},
					Columns: map[string][]string{"users": {"name", "email", "id"}},
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
		Context: capability.EnforceRequestContext{
			Tables: []capability.TableAccess{
				{Table: "secrets"},
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Tables: []string{"users", "orders"}},
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
		Context: capability.EnforceRequestContext{
			Tables: []capability.TableAccess{
				{Table: "users", Columns: []string{"password_hash"}},
			},
		},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Resource: "db:query",
			Actions:  []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Tables:  []string{"users"},
					Columns: map[string][]string{"users": {"name", "email"}},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_RecipientDomain_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
		Context: capability.EnforceRequestContext{
			Recipients: []string{"user@example.com", "admin@example.com"},
		},
	}

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
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "email:send",
		Context: capability.EnforceRequestContext{
			Recipients: []string{"user@example.com", "evil@attacker.com"},
		},
	}

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

func TestEngine_PolicyCondition_PassThrough(t *testing.T) {
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
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_CustomCondition_PassThrough(t *testing.T) {
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
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RegisterCustomCondition(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	// Override the custom handler to deny all
	engine.RegisterCondition(capability.ConditionTypeCustom, func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
		return &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeCustom,
			Message:       "custom condition denied",
		}
	})

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
	clock := testutil.NewFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			SourceIP:  "10.0.0.5",
			Operation: "read",
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
				&capability.AllowedOperationsCondition{Operations: []string{"read", "write"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MultipleConditions_FirstFailureDenies(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := testutil.NewFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID: "sess-1",
		ToolName:  "tool",
		Context: capability.EnforceRequestContext{
			SourceIP:  "192.168.1.1", // Not in allowed range
			Operation: "read",
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
		Context:   capability.EnforceRequestContext{Operation: "anything"},
	}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "tool", Actions: nil},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_FromArguments(t *testing.T) {
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
				&capability.AllowedExtensionsCondition{Extensions: []string{"csv", "json"}},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_IgnoresRequestContextNow(t *testing.T) {
	// req.Context.Now must be ignored; the server clock is always authoritative
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	engine := enforcement.New(enforcement.WithClock(testutil.NewFakeClock(fixedTime)))
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
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "email:send", Context: capability.EnforceRequestContext{Operation: "send"}}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:*", Actions: []string{"*"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "email:*", Actions: []string{"send"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_ExactResourceBeatsWildcard(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "email:send", Context: capability.EnforceRequestContext{Operation: "send"}}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "email:*", Actions: []string{"send"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "email:send", Actions: []string{"send"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_ActionSpecificityWins(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "tool:mail", Context: capability.EnforceRequestContext{Operation: "invoke"}}

	resp, err := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Resource: "tool:*", Actions: []string{"*"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "tool:*", Actions: []string{"invoke"}},
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_JWTOrderingDoesNotMatter(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{ToolName: "file:read", Context: capability.EnforceRequestContext{Operation: "read"}}
	constraints := []capability.Constraint{
		{Resource: "file:*", Actions: []string{"*"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Resource: "file:read", Actions: []string{"read"}},
	}

	respA, err := engine.ValidateAction(ctx, &req, constraints)
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, respA.Decision)

	respB, err := engine.ValidateAction(ctx, &req, []capability.Constraint{constraints[1], constraints[0]})
	require.NoError(t, err)
	assert.Equal(t, capability.DecisionAllow, respB.Decision)
}

// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/gateway"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/eunolabs/eunox/pkg/revocation"
	"github.com/eunolabs/eunox/pkg/testutil"
)

// staticClaimsVerifier always returns the configured claims.
type staticClaimsVerifier struct {
	claims *capability.TokenPayload
}

func (v *staticClaimsVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return v.claims, nil
}

// newConditionTestGateway creates a gateway wired with the given engine options and claims.
func newConditionTestGateway(t *testing.T, claims *capability.TokenPayload, opts ...enforcement.Option) http.Handler {
	t.Helper()
	engine := enforcement.New(opts...)
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	return app.Handler()
}

// enforceAndGetResponse sends an enforce request and returns the parsed response.
func enforceAndGetResponse(t *testing.T, handler http.Handler, payload map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	return resp
}

// TestCondition_TimeWindow_AllowWithinWindow verifies requests within the time window are allowed.
func TestCondition_TimeWindow_AllowWithinWindow(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	clock := testutil.NewFakeClock(now)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.TimeWindowCondition{
						NotBefore: now.Add(-1 * time.Hour).Format(time.RFC3339),
						NotAfter:  now.Add(1 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithClock(clock))

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_TimeWindow_DenyBeforeWindow verifies requests before the time window are denied.
func TestCondition_TimeWindow_DenyBeforeWindow(t *testing.T) {
	now := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	clock := testutil.NewFakeClock(now)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.TimeWindowCondition{
						NotBefore: now.Add(4 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithClock(clock))

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "timeWindow", denial["conditionType"])
}

// TestCondition_TimeWindow_DenyAfterWindow verifies requests after the time window are denied.
func TestCondition_TimeWindow_DenyAfterWindow(t *testing.T) {
	now := time.Date(2026, 6, 1, 20, 0, 0, 0, time.UTC)
	clock := testutil.NewFakeClock(now)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.TimeWindowCondition{
						NotAfter: now.Add(-2 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithClock(clock))

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_IPRange_AllowMatchingCIDR verifies allowed IP within CIDR.
func TestCondition_IPRange_AllowMatchingCIDR(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.5.3.7"},
		},
	})

	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_IPRange_DenyOutsideCIDR verifies denial when IP is outside allowed ranges.
func TestCondition_IPRange_DenyOutsideCIDR(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "172.16.0.1"},
		},
	})

	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "ipRange", denial["conditionType"])
}

// TestCondition_MaxCalls_AllowUnderLimit verifies calls within the max limit succeed.
func TestCondition_MaxCalls_AllowUnderLimit(t *testing.T) {
	counter := callcounter.NewInMemory()
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "file-read",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithCallCounter(counter))
	payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-max",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Make 5 calls - all should be allowed
	for i := 0; i < 5; i++ {
		resp := enforceAndGetResponse(t, handler, payload)
		assert.Equal(t, "allow", resp["decision"], "call %d should be allowed", i+1)
	}
}

// TestCondition_MaxCalls_DenyOverLimit verifies calls exceeding the max limit are denied.
func TestCondition_MaxCalls_DenyOverLimit(t *testing.T) {
	counter := callcounter.NewInMemory()
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "file-read",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.MaxCallsCondition{Count: 3, WindowSeconds: 60},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithCallCounter(counter))
	payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-over",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Use up limit
	for i := 0; i < 3; i++ {
		resp := enforceAndGetResponse(t, handler, payload)
		assert.Equal(t, "allow", resp["decision"])
	}

	// 4th call should be denied
	resp := enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "RATE_LIMITED", denial["code"])
}

// TestCondition_AllowedOperations_AllowListedOperation verifies listed operations pass.
func TestCondition_AllowedOperations_AllowListedOperation(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedOperationsCondition{Operations: []string{"read", "list"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "read"},
		},
	})
	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_AllowedOperations_DenyUnlistedOperation verifies unlisted operations are denied.
func TestCondition_AllowedOperations_DenyUnlistedOperation(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedOperationsCondition{Operations: []string{"read", "list"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "delete"},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "allowedOperations", denial["conditionType"])
}

// TestCondition_AllowedExtensions_AllowPermittedExtension verifies allowed file extensions pass.
func TestCondition_AllowedExtensions_AllowPermittedExtension(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedExtensionsCondition{Extensions: []string{".go", ".ts", ".md"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "filePath": "/src/main.go"},
		},
	})
	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_AllowedExtensions_DenyForbiddenExtension verifies disallowed extensions are denied.
func TestCondition_AllowedExtensions_DenyForbiddenExtension(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedExtensionsCondition{Extensions: []string{".go", ".ts"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "filePath": "/secrets/key.pem"},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_AllowedTables_AllowPermittedTable verifies allowed table access passes.
func TestCondition_AllowedTables_AllowPermittedTable(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "db-query",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedTablesCondition{
						Tables:  []string{"users", "orders"},
						Columns: map[string][]string{"users": {"id", "name", "email"}},
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "db-query",
			"context": map[string]any{
				"sourceIp": "10.0.0.1",
				"tables": []map[string]any{
					{"table": "users", "columns": []string{"id", "name"}},
				},
			},
		},
	})
	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_AllowedTables_DenyForbiddenTable verifies denied table access.
func TestCondition_AllowedTables_DenyForbiddenTable(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "db-query",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedTablesCondition{
						Tables: []string{"users", "orders"},
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "db-query",
			"context": map[string]any{
				"sourceIp": "10.0.0.1",
				"tables": []map[string]any{
					{"table": "admin_secrets", "columns": []string{"key"}},
				},
			},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_AllowedTables_DenyForbiddenColumn verifies denied column access.
func TestCondition_AllowedTables_DenyForbiddenColumn(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "db-query",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedTablesCondition{
						Tables:  []string{"users"},
						Columns: map[string][]string{"users": {"id", "name"}},
					},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "db-query",
			"context": map[string]any{
				"sourceIp": "10.0.0.1",
				"tables": []map[string]any{
					{"table": "users", "columns": []string{"id", "password_hash"}},
				},
			},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_RecipientDomain_AllowPermittedDomain verifies allowed email domains pass.
func TestCondition_RecipientDomain_AllowPermittedDomain(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "send-email",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.RecipientDomainCondition{Domains: []string{"example.com", "partner.org"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "send-email",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "recipients": []string{"alice@example.com"}},
		},
	})
	assert.Equal(t, "allow", resp["decision"])
}

// TestCondition_RecipientDomain_DenyForbiddenDomain verifies denied email domains.
func TestCondition_RecipientDomain_DenyForbiddenDomain(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "send-email",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.RecipientDomainCondition{Domains: []string{"example.com"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "send-email",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "recipients": []string{"evil@attacker.io"}},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_RedactFields_ProducesObligation verifies redactFields generates obligations.
func TestCondition_RedactFields_ProducesObligation(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "user-query",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.RedactFieldsCondition{Fields: []string{"$.password", "$.ssn", "$.credit_card"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "user-query",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	assert.Equal(t, "allow", resp["decision"])
	obligations, ok := resp["obligations"].([]any)
	require.True(t, ok, "obligations should be present")
	require.Len(t, obligations, 1)
	obl := obligations[0].(map[string]any)
	assert.Equal(t, "redactFields", obl["type"])
}

// TestCondition_MultipleConditions_AllMustPass verifies all conditions must pass.
func TestCondition_MultipleConditions_AllMustPass(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	clock := testutil.NewFakeClock(now)
	counter := callcounter.NewInMemory()

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "file-read",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.TimeWindowCondition{
						NotBefore: now.Add(-1 * time.Hour).Format(time.RFC3339),
						NotAfter:  now.Add(1 * time.Hour).Format(time.RFC3339),
					},
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
					&capability.MaxCallsCondition{Count: 10, WindowSeconds: 60},
					&capability.AllowedExtensionsCondition{Extensions: []string{".go", ".md"}},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims, enforcement.WithClock(clock), enforcement.WithCallCounter(counter))

	// All conditions satisfied
	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-multi",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "filePath": "/src/main.go"},
		},
	})
	assert.Equal(t, "allow", resp["decision"])

	// IP condition fails
	resp = enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-multi",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "172.16.0.1", "filePath": "/src/main.go"},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
}

// TestCondition_CustomCondition_DenyWhenNoHandlerRegistered verifies that a
// custom condition is denied (fail-closed) when no handler has been registered
// via RegisterCondition.  The old pass-through default was a security bypass.
func TestCondition_CustomCondition_DenyWhenNoHandlerRegistered(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.CustomCondition{Name: "unknown-future-condition", Config: nil},
				},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "any-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})
	// Custom conditions without a registered handler must be denied.
	assert.Equal(t, "deny", resp["decision"])
	denial, ok := resp["denial"].(map[string]any)
	require.True(t, ok, "expected denial object in response")
	assert.Equal(t, "CONDITION_FAILED", denial["code"])
	assert.Equal(t, "custom", denial["conditionType"])
}

// TestCondition_NoMatchingCapability_DeniesAction verifies no resource match produces denial.
func TestCondition_NoMatchingCapability_DeniesAction(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "file-read",
				Actions:  []string{"read"},
			},
		},
	}

	handler := newConditionTestGateway(t, claims)

	resp := enforceAndGetResponse(t, handler, map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "dangerous-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})
	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "AUTHORIZATION_FAILED", denial["code"])
}

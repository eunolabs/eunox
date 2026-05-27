// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// TestKillSwitch_GlobalActivation verifies the global kill switch blocks all requests.
func TestKillSwitch_GlobalActivation(t *testing.T) {
	ks := killswitch.NewInMemory()
	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	handler := app.Handler()

	payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-ks",
			"toolName":  "any-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Request allowed before kill switch activation
	resp := enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "allow", resp["decision"])

	// Activate global kill switch
	err = ks.ActivateGlobal(context.Background())
	require.NoError(t, err)

	// Request blocked after activation
	resp = enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "KILL_SWITCH_ACTIVE", denial["code"])

	// Deactivate
	err = ks.DeactivateGlobal(context.Background())
	require.NoError(t, err)

	// Request allowed again after deactivation
	resp = enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "allow", resp["decision"])
}

// TestKillSwitch_PerAgent verifies agent-specific kill switch blocks only targeted agent.
func TestKillSwitch_PerAgent(t *testing.T) {
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	claimsAgent1 := &capability.TokenPayload{
		Subject:   "agent-1",
		JWTID:     "jti-agent1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	claimsAgent2 := &capability.TokenPayload{
		Subject:   "agent-2",
		JWTID:     "jti-agent2",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	// Gateway that returns claims based on the token string
	verifier := &multiClaimsVerifier{
		tokens: map[string]*capability.TokenPayload{
			"token-agent-1": claimsAgent1,
			"token-agent-2": claimsAgent2,
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	handler := app.Handler()

	agent1Payload := map[string]any{
		"token": "token-agent-1",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "tool-a",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}
	agent2Payload := map[string]any{
		"token": "token-agent-2",
		"request": map[string]any{
			"sessionId": "sess-2",
			"toolName":  "tool-a",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Both agents allowed initially
	resp := enforceAndGetResponse(t, handler, agent1Payload)
	assert.Equal(t, "allow", resp["decision"])
	resp = enforceAndGetResponse(t, handler, agent2Payload)
	assert.Equal(t, "allow", resp["decision"])

	// Kill agent-1
	err = ks.KillAgent(context.Background(), "agent-1")
	require.NoError(t, err)

	// Agent-1 blocked, agent-2 still allowed
	resp = enforceAndGetResponse(t, handler, agent1Payload)
	assert.Equal(t, "deny", resp["decision"])
	resp = enforceAndGetResponse(t, handler, agent2Payload)
	assert.Equal(t, "allow", resp["decision"])

	// Revive agent-1
	err = ks.ReviveAgent(context.Background(), "agent-1")
	require.NoError(t, err)

	// Agent-1 allowed again
	resp = enforceAndGetResponse(t, handler, agent1Payload)
	assert.Equal(t, "allow", resp["decision"])
}

// TestKillSwitch_PerSession verifies session-specific kill switch blocks only targeted sessions.
func TestKillSwitch_PerSession(t *testing.T) {
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	handler := app.Handler()

	sess1Payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "session-good",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}
	sess2Payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "session-compromised",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Kill specific session
	err = ks.KillSession(context.Background(), "session-compromised")
	require.NoError(t, err)

	// Good session still works
	resp := enforceAndGetResponse(t, handler, sess1Payload)
	assert.Equal(t, "allow", resp["decision"])

	// Compromised session is blocked
	resp = enforceAndGetResponse(t, handler, sess2Payload)
	assert.Equal(t, "deny", resp["decision"])
}

// TestKillSwitch_StatusReport verifies kill switch status reporting.
func TestKillSwitch_StatusReport(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	// Initially clean
	status, err := ks.Status(ctx)
	require.NoError(t, err)
	assert.False(t, status.GlobalActive)
	assert.Empty(t, status.KilledAgents)
	assert.Empty(t, status.KilledSessions)

	// Activate various kills
	require.NoError(t, ks.ActivateGlobal(ctx))
	require.NoError(t, ks.KillAgent(ctx, "agent-x"))
	require.NoError(t, ks.KillAgent(ctx, "agent-y"))
	require.NoError(t, ks.KillSession(ctx, "sess-z"))

	status, err = ks.Status(ctx)
	require.NoError(t, err)
	assert.True(t, status.GlobalActive)
	assert.Len(t, status.KilledAgents, 2)
	assert.Len(t, status.KilledSessions, 1)
	assert.Contains(t, status.KilledAgents, "agent-x")
	assert.Contains(t, status.KilledAgents, "agent-y")
	assert.Contains(t, status.KilledSessions, "sess-z")

	// Reset clears all
	require.NoError(t, ks.Reset(ctx))
	status, err = ks.Status(ctx)
	require.NoError(t, err)
	assert.False(t, status.GlobalActive)
	assert.Empty(t, status.KilledAgents)
	assert.Empty(t, status.KilledSessions)
}

// TestRevocation_TokenLifecycle verifies the full revocation lifecycle.
func TestRevocation_TokenLifecycle(t *testing.T) {
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	claims := &capability.TokenPayload{
		Subject:   "user-revoke",
		JWTID:     "revokable-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revStore,
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	handler := app.Handler()

	payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-rev",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	// Token works before revocation
	resp := enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "allow", resp["decision"])

	// Revoke the token
	err = revStore.Revoke(context.Background(), "revokable-jti", 1*time.Hour)
	require.NoError(t, err)

	// Token is now rejected
	resp = enforceAndGetResponse(t, handler, payload)
	assert.Equal(t, "deny", resp["decision"])
	denial := resp["denial"].(map[string]any)
	assert.Equal(t, "TOKEN_REVOKED", denial["code"])
}

// TestRevocation_UnrevokedTokenStillWorks verifies non-revoked tokens remain functional.
func TestRevocation_UnrevokedTokenStillWorks(t *testing.T) {
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	// Revoke a different JTI
	err := revStore.Revoke(context.Background(), "other-jti", 1*time.Hour)
	require.NoError(t, err)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "my-good-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revStore,
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	payload := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	resp := enforceAndGetResponse(t, app.Handler(), payload)
	assert.Equal(t, "allow", resp["decision"])
}

// multiClaimsVerifier returns different claims based on the token string.
type multiClaimsVerifier struct {
	tokens map[string]*capability.TokenPayload
}

func (v *multiClaimsVerifier) VerifyToken(_ context.Context, tokenStr string) (*capability.TokenPayload, error) {
	if claims, ok := v.tokens[tokenStr]; ok {
		return claims, nil
	}
	return nil, fmt.Errorf("unknown token: %s", tokenStr)
}

// TestKillSwitch_AdminEndpoint_GlobalActivate tests admin kill switch activation via HTTP.
func TestKillSwitch_AdminEndpoint_GlobalActivate(t *testing.T) {
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	claims := &capability.TokenPayload{
		Subject:   "user-1",
		JWTID:     "jti-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "test-tenant",
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	adminHandler := app.AdminHandler()

	// Activate global kill switch via admin API (requires cross-tenant ack)
	activateBody, _ := json.Marshal(map[string]any{"acknowledgesCrossTenantImpact": true})
	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch/global/activate", bytes.NewReader(activateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	w := httptest.NewRecorder()
	adminHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify kill switch is active
	blocked, err := ks.ShouldBlock(context.Background(), "user-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)
}

// TestKillSwitch_AdminEndpoint_AgentKill tests per-agent kill switch via admin API.
func TestKillSwitch_AdminEndpoint_AgentKill(t *testing.T) {
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	claims := &capability.TokenPayload{
		Subject:   "target-agent",
		JWTID:     "jti-target",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "test-tenant",
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	require.NoError(t, err)

	adminHandler := app.AdminHandler()

	// Kill specific agent via admin API
	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch/agent/target-agent/kill", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	w := httptest.NewRecorder()
	adminHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify agent is killed
	blocked, err := ks.ShouldBlock(context.Background(), "target-agent", "any-session")
	require.NoError(t, err)
	assert.True(t, blocked)
}

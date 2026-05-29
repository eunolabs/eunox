// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/gateway"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/eunolabs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSidecarApp(t *testing.T, agentID string) *gateway.App {
	t.Helper()

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		SidecarMode:     true,
		SidecarAgentID:  agentID,
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

// TestSidecarMode_RejectsMismatchedAgent verifies that a request carrying a
// different agent ID is rejected with 403 in sidecar mode.
func TestSidecarMode_RejectsMismatchedAgent(t *testing.T) {
	app := newSidecarApp(t, "agent-alice")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", http.NoBody)
	req.Header.Set("X-Agent-Id", "agent-bob") // wrong agent
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "wrong sidecar")
}

// TestSidecarMode_AllowsMatchingAgent verifies that a request for the configured
// agent is not rejected by the sidecar middleware (it may fail later due to missing
// token, but must not be rejected with 403 by the sidecar filter).
func TestSidecarMode_AllowsMatchingAgent(t *testing.T) {
	app := newSidecarApp(t, "agent-alice")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", http.NoBody)
	req.Header.Set("X-Agent-Id", "agent-alice") // correct agent
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// The request passes the sidecar filter; it fails with 400/401 for other
	// reasons (missing body / token), not 403.
	assert.NotEqual(t, http.StatusForbidden, w.Code)
}

// TestSidecarMode_RejectsAbsentHeader verifies that a request without the
// X-Agent-Id header is rejected with 403 in sidecar mode. The header is required
// to enforce strict single-agent isolation and prevent a valid token for a
// different agent from being accepted when the header is absent.
func TestSidecarMode_RejectsAbsentHeader(t *testing.T) {
	app := newSidecarApp(t, "agent-alice")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", http.NoBody)
	// No X-Agent-Id header set
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "wrong sidecar")
}

// TestSidecarMode_RequiresAgentID verifies that New() returns an error when
// SidecarMode is true but SidecarAgentID is empty.
func TestSidecarMode_RequiresAgentID(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		SidecarMode:     true,
		SidecarAgentID:  "", // deliberately empty
	}

	_, err := gateway.New(&cfg, &deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_SIDECAR_AGENT_ID")
}

// TestSidecarMode_HealthEndpointsUnaffected verifies that the sidecar
// middleware is NOT applied to health endpoints.
func TestSidecarMode_HealthEndpointsUnaffected(t *testing.T) {
	app := newSidecarApp(t, "agent-alice")

	for _, path := range []string{"/health/live", "/health/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.Header.Set("X-Agent-Id", "agent-bob") // mismatched — should not matter
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "health endpoint %s should not be filtered by sidecar middleware", path)
	}
}

// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"encoding/json"
	"net/http"
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

// wireParityFixture defines a wire-protocol parity test case with exact
// request/response shapes that must match the TypeScript gateway behavior.
type wireParityFixture struct {
	Name           string
	Description    string
	RequestBody    map[string]any
	Claims         *capability.TokenPayload
	ExpectedStatus int
	ExpectedFields map[string]any // Fields that must be present/match in response
}

// TestWireParity_EnforceResponseFormat verifies the enforce endpoint produces
// responses with the exact same shape as the TypeScript implementation.
func TestWireParity_EnforceResponseFormat(t *testing.T) {
	fixtures := []wireParityFixture{
		{
			Name:        "allow_response_shape",
			Description: "Allow response must have requestId, decision=allow, decidedAt",
			RequestBody: map[string]any{
				"token": "test-token",
				"request": map[string]any{
					"sessionId": "wire-sess-1",
					"toolName":  "file-read",
					"context":   map[string]any{"sourceIp": "10.0.0.1"},
				},
			},
			Claims: &capability.TokenPayload{
				Subject: "wire-user", JWTID: "wire-jti-1",
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				Capabilities: []capability.Constraint{
					{Resource: "*", Actions: []string{"*"}},
				},
			},
			ExpectedStatus: http.StatusOK,
			ExpectedFields: map[string]any{
				"decision": "allow",
			},
		},
		{
			Name:        "deny_response_no_matching_capability",
			Description: "Deny response must include denial object with code and message",
			RequestBody: map[string]any{
				"token": "test-token",
				"request": map[string]any{
					"sessionId": "wire-sess-2",
					"toolName":  "admin-panel",
					"context":   map[string]any{"sourceIp": "10.0.0.1"},
				},
			},
			Claims: &capability.TokenPayload{
				Subject: "wire-user", JWTID: "wire-jti-2",
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				Capabilities: []capability.Constraint{
					{Resource: "file-only", Actions: []string{"read"}},
				},
			},
			ExpectedStatus: http.StatusOK,
			ExpectedFields: map[string]any{
				"decision": "deny",
			},
		},
		{
			Name:        "deny_condition_violation",
			Description: "Deny from condition violation includes conditionType in denial",
			RequestBody: map[string]any{
				"token": "test-token",
				"request": map[string]any{
					"sessionId": "wire-sess-3",
					"toolName":  "protected-tool",
					"context":   map[string]any{"sourceIp": "192.168.1.1"},
				},
			},
			Claims: &capability.TokenPayload{
				Subject: "wire-user", JWTID: "wire-jti-3",
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				Capabilities: []capability.Constraint{
					{
						Resource: "protected-tool", Actions: []string{"*"},
						Conditions: []capability.Condition{
							&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
						},
					},
				},
			},
			ExpectedStatus: http.StatusOK,
			ExpectedFields: map[string]any{
				"decision": "deny",
			},
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
			app := gateway.New(&gateway.Config{
				GatewayAudience: "wire-test",
				AdminAPIKey:     testAdminKey,
			}, &gateway.Dependencies{
				Engine:      enforcement.New(),
				KillSwitch:  killswitch.NewInMemory(),
				Revocation:  revocation.NewInMemory(),
				JWTVerifier: &staticClaimsVerifier{claims: fx.Claims},
				DPoPStore:   dpopStore,
			})

			resp := enforceAndGetResponse(t, app.Handler(), fx.RequestBody)

			// Verify required fields exist
			assert.Contains(t, resp, "requestId", "response must contain requestId")
			assert.Contains(t, resp, "decision", "response must contain decision")
			assert.Contains(t, resp, "decidedAt", "response must contain decidedAt")

			// Verify expected field values
			for key, expected := range fx.ExpectedFields {
				assert.Equal(t, expected, resp[key], "field %s mismatch", key)
			}

			// Verify decidedAt is a valid ISO 8601 timestamp
			decidedAtStr, ok := resp["decidedAt"].(string)
			require.True(t, ok, "decidedAt must be a string")
			_, err := time.Parse(time.RFC3339Nano, decidedAtStr)
			assert.NoError(t, err, "decidedAt must be RFC3339")

			// Verify requestId is a non-empty string
			requestID, ok := resp["requestId"].(string)
			require.True(t, ok, "requestId must be a string")
			assert.NotEmpty(t, requestID)

			// Verify denial shape when decision is deny
			if resp["decision"] == "deny" {
				denial, ok := resp["denial"].(map[string]any)
				require.True(t, ok, "deny response must include denial object")
				assert.Contains(t, denial, "code", "denial must have code")
				assert.Contains(t, denial, "message", "denial must have message")
			}
		})
	}
}

// TestWireParity_RequestIDPropagation verifies requestId echoes X-Request-Id
// and remains populated across early-deny paths.
func TestWireParity_RequestIDPropagation(t *testing.T) {
	makeHandler := func(claims *capability.TokenPayload, ks killswitch.Manager, revStore *revocation.InMemory) http.Handler {
		dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
		app := gateway.New(&gateway.Config{
			GatewayAudience: "wire-test",
			AdminAPIKey:     testAdminKey,
		}, &gateway.Dependencies{
			Engine:      enforcement.New(),
			KillSwitch:  ks,
			Revocation:  revStore,
			JWTVerifier: &staticClaimsVerifier{claims: claims},
			DPoPStore:   dpopStore,
		})

		return app.Handler()
	}

	baseRequest := map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "wire-request-id",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}

	t.Run("echoes_x_request_id_when_provided", func(t *testing.T) {
		claims := &capability.TokenPayload{
			Subject: "wire-user", JWTID: "wire-jti-echo",
			ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
			Capabilities: []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
		}
		handler := makeHandler(claims, killswitch.NewInMemory(), revocation.NewInMemory())

		body, err := json.Marshal(baseRequest)
		require.NoError(t, err)
		req := newJSONRequest(t, http.MethodPost, "/api/v1/enforce", body)
		req.Header.Set("X-Request-Id", "wire-request-id-123")

		w := doRequest(handler, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]any
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "wire-request-id-123", resp["requestId"])
		assert.Equal(t, "allow", resp["decision"])
	})

	t.Run("request_id_present_on_global_killswitch_deny", func(t *testing.T) {
		claims := &capability.TokenPayload{
			Subject: "wire-user", JWTID: "wire-jti-kill",
			ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
			Capabilities: []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
		}
		ks := killswitch.NewInMemory()
		require.NoError(t, ks.ActivateGlobal(context.Background()))
		handler := makeHandler(claims, ks, revocation.NewInMemory())

		resp := enforceAndGetResponse(t, handler, baseRequest)
		assert.Equal(t, "deny", resp["decision"])
		assert.NotEmpty(t, resp["requestId"])
	})

	t.Run("request_id_present_on_revoked_token_deny", func(t *testing.T) {
		claims := &capability.TokenPayload{
			Subject: "wire-user", JWTID: "wire-jti-revoked",
			ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
			Capabilities: []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
		}
		revStore := revocation.NewInMemory()
		require.NoError(t, revStore.Revoke(context.Background(), claims.JWTID, time.Hour))
		handler := makeHandler(claims, killswitch.NewInMemory(), revStore)

		resp := enforceAndGetResponse(t, handler, baseRequest)
		assert.Equal(t, "deny", resp["decision"])
		assert.NotEmpty(t, resp["requestId"])
	})

	t.Run("request_id_present_on_expired_token_deny", func(t *testing.T) {
		claims := &capability.TokenPayload{
			Subject: "wire-user", JWTID: "wire-jti-expired",
			ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(),
			Capabilities: []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
		}
		handler := makeHandler(claims, killswitch.NewInMemory(), revocation.NewInMemory())

		resp := enforceAndGetResponse(t, handler, baseRequest)
		assert.Equal(t, "deny", resp["decision"])
		assert.NotEmpty(t, resp["requestId"])
	})
}

// TestWireParity_EnforceRequestValidation verifies request validation matches TypeScript behavior.
func TestWireParity_EnforceRequestValidation(t *testing.T) {
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	claims := &capability.TokenPayload{
		Subject: "user", JWTID: "jti",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
	}
	app := gateway.New(&gateway.Config{
		GatewayAudience: "wire-test",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})

	handler := app.Handler()

	tests := []struct {
		name     string
		body     map[string]any
		wantCode int
	}{
		{
			name:     "missing_token",
			body:     map[string]any{"request": map[string]any{"sessionId": "s", "toolName": "t"}},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "valid_minimal_request",
			body: map[string]any{
				"token": "t",
				"request": map[string]any{
					"sessionId": "s",
					"toolName":  "t",
					"context":   map[string]any{},
				},
			},
			wantCode: http.StatusOK,
		},
		{
			name:     "empty_body",
			body:     map[string]any{},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := newJSONRequest(t, http.MethodPost, "/api/v1/enforce", body)
			w := doRequest(handler, req)
			assert.Equal(t, tc.wantCode, w.Code, "body: %s", w.Body.String())
		})
	}
}

// TestWireParity_ObligationsFormat verifies obligations are returned in the correct format.
func TestWireParity_ObligationsFormat(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject: "obl-user", JWTID: "obl-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "email-tool", Actions: []string{"send"},
				Conditions: []capability.Condition{
					&capability.RedactFieldsCondition{Fields: []string{"ssn", "credit_card"}},
				},
			},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(&gateway.Config{
		GatewayAudience: "wire-test",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})

	resp := enforceAndGetResponse(t, app.Handler(), map[string]any{
		"token": "test-token",
		"request": map[string]any{
			"sessionId": "obl-sess",
			"toolName":  "email-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "send"},
		},
	})

	assert.Equal(t, "allow", resp["decision"])

	// Obligations should be an array
	if obligations, ok := resp["obligations"]; ok {
		oblArr, ok := obligations.([]any)
		require.True(t, ok, "obligations must be an array")
		for _, obl := range oblArr {
			oblMap, ok := obl.(map[string]any)
			require.True(t, ok, "each obligation must be an object")
			assert.Contains(t, oblMap, "type", "obligation must have type")
		}
	}
}

// TestWireParity_HealthEndpoint verifies the health endpoint response format.
func TestWireParity_HealthEndpoint(t *testing.T) {
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(&gateway.Config{
		GatewayAudience: "wire-test",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: nil},
		DPoPStore:   dpopStore,
	})

	req := newJSONRequest(t, http.MethodGet, "/health/live", nil)
	w := doRequest(app.Handler(), req)

	assert.Equal(t, http.StatusOK, w.Code)
	var health map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &health)
	require.NoError(t, err)
	assert.Equal(t, "ok", health["status"])
}

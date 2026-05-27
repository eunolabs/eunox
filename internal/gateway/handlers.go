// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/google/uuid"
)

const defaultMaxBodySize int64 = 1 << 20 // 1 MB

// maxBodySizeFor returns the configured or default max body size.
func (app *App) maxBodySizeFor() int64 {
	if app.config.MaxRequestBodySize > 0 {
		return app.config.MaxRequestBodySize
	}
	return defaultMaxBodySize
}

// handleLive returns 200 if the service is alive.
func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleReady returns 200 if the service is ready to accept traffic, or 503
// during the lifecycle drain delay (when Config.IsReady returns false).
func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if app.config.IsReady != nil && !app.config.IsReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not_ready"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// enforceRequestPayload wraps the enforce request with token and optional DPoP.
type enforceRequestPayload struct {
	Token   string                    `json:"token"`
	Request capability.EnforceRequest `json:"request"`
	DPoP    *capability.DPoPProof     `json:"dpop,omitempty"`
}

// handleEnforce handles POST /api/v1/enforce.
func (app *App) handleEnforce(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if requestID == "" {
		requestID = uuid.NewString()
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, app.maxBodySizeFor()))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("failed to read request body"))
		return
	}

	var payload enforceRequestPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid JSON payload"))
		return
	}

	if payload.Token == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("token is required"))
		return
	}

	// Verify JWT
	claims, err := app.deps.JWTVerifier.VerifyToken(r.Context(), payload.Token)
	if err != nil {
		resp := capability.EnforceResponse{
			RequestID: requestID,
			Decision:  capability.DecisionDeny,
			DecidedAt: time.Now().UTC().Format(time.RFC3339),
			Denial: &capability.DenialInfo{
				Code:    capability.ErrCodeAuthorizationFailed,
				Message: fmt.Sprintf("token verification failed: %v", err),
			},
		}
		app.recordMetric("deny", start)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Check token expiry
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		resp := capability.EnforceResponse{
			RequestID: requestID,
			Decision:  capability.DecisionDeny,
			DecidedAt: time.Now().UTC().Format(time.RFC3339),
			Denial: &capability.DenialInfo{
				Code:    capability.ErrCodeExpired,
				Message: "token has expired",
			},
		}
		app.recordMetric("deny", start)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Check revocation
	if app.deps.Revocation != nil && claims.JWTID != "" {
		revoked, revErr := app.deps.Revocation.IsRevoked(r.Context(), claims.JWTID)
		if revErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
			app.recordMetric("deny", start)
			return
		}
		if revoked {
			resp := capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
				Denial: &capability.DenialInfo{
					Code:    capability.ErrCodeRevoked,
					Message: "token has been revoked",
				},
			}
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Check DPoP replay
	if payload.DPoP != nil {
		if err := app.verifyDPoP(r.Context(), payload.DPoP, claims); err != nil {
			resp := capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
				Denial: &capability.DenialInfo{
					Code:    capability.ErrCodeAuthorizationFailed,
					Message: fmt.Sprintf("DPoP verification failed: %v", err),
				},
			}
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Check kill switch
	if app.deps.KillSwitch != nil {
		blocked, ksErr := app.deps.KillSwitch.ShouldBlock(r.Context(), claims.Subject, payload.Request.SessionID)
		if ksErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch check unavailable"))
			app.recordMetric("deny", start)
			return
		}
		if blocked {
			resp := capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
				Denial: &capability.DenialInfo{
					Code:    capability.ErrCodeKillSwitch,
					Message: "kill switch is active",
				},
			}
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Fill in source IP from request if not provided
	if payload.Request.Context.SourceIP == "" {
		payload.Request.Context.SourceIP = app.extractClientIP(r)
	}

	// Run enforcement engine
	resp, engineErr := app.deps.Engine.ValidateAction(r.Context(), &payload.Request, claims.Capabilities)
	if engineErr != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("enforcement engine error"))
		return
	}
	resp.RequestID = requestID

	decision := string(resp.Decision)
	app.recordMetric(decision, start)
	writeJSON(w, http.StatusOK, resp)
}

// handleValidate handles POST /api/v1/validate.
func (app *App) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, app.maxBodySizeFor()))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("failed to read request body"))
		return
	}

	var req capability.ValidateActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid JSON payload"))
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("token is required"))
		return
	}

	// Verify JWT
	claims, err := app.deps.JWTVerifier.VerifyToken(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("token verification failed: %v", err),
		})
		return
	}

	// Check if any capability matches the requested action/resource
	for i := range claims.Capabilities {
		constraint := &claims.Capabilities[i]
		resourceMatch := constraint.Resource == "*" || constraint.Resource == req.Resource
		if !resourceMatch {
			continue
		}

		actionMatch := len(constraint.Actions) == 0
		for _, a := range constraint.Actions {
			if a == "*" || a == req.Action {
				actionMatch = true
				break
			}
		}
		if !actionMatch {
			continue
		}

		writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
			Allowed:           true,
			MatchedCapability: constraint,
		})
		return
	}

	writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
		Allowed: false,
		Reason:  "no matching capability for requested action",
	})
}

// handleProxy handles ANY /proxy/* — reverse proxies to backend after enforcement.
func (app *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	if app.proxy == nil {
		writeJSON(w, http.StatusBadGateway, errorResponse("no backend configured"))
		return
	}

	// Extract token from Authorization header
	token := extractBearerToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errorResponse("missing authorization token"))
		return
	}

	// Verify JWT
	claims, err := app.deps.JWTVerifier.VerifyToken(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse("invalid token"))
		return
	}

	// Check token expiry
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		writeJSON(w, http.StatusUnauthorized, errorResponse("token has expired"))
		return
	}

	// Check kill switch
	if app.deps.KillSwitch != nil {
		sessionID := r.Header.Get("X-Session-ID")
		blocked, ksErr := app.deps.KillSwitch.ShouldBlock(r.Context(), claims.Subject, sessionID)
		if ksErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch check unavailable"))
			return
		}
		if blocked {
			writeJSON(w, http.StatusForbidden, errorResponse("kill switch active"))
			return
		}
	}

	// Check revocation
	if app.deps.Revocation != nil && claims.JWTID != "" {
		revoked, revErr := app.deps.Revocation.IsRevoked(r.Context(), claims.JWTID)
		if revErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
			return
		}
		if revoked {
			writeJSON(w, http.StatusForbidden, errorResponse("token revoked"))
			return
		}
	}

	// Build enforce request from proxy context
	enforceReq := capability.EnforceRequest{
		SessionID: r.Header.Get("X-Session-ID"),
		ToolName:  r.Header.Get("X-Tool-Name"),
		Context: capability.EnforceRequestContext{
			SourceIP:  app.extractClientIP(r),
			Operation: r.Method,
		},
	}

	// Run enforcement
	resp, engineErr := app.deps.Engine.ValidateAction(r.Context(), &enforceReq, claims.Capabilities)
	if engineErr != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("enforcement error"))
		return
	}

	if resp.Decision == capability.DecisionDeny {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	// Proxy the request to backend
	app.proxy.ServeHTTP(w, r)
}

func (app *App) recordMetric(decision string, start time.Time) {
	if app.metrics == nil {
		return
	}
	duration := time.Since(start).Seconds()
	app.metrics.enforceDuration.WithLabelValues(decision).Observe(duration)
	app.metrics.enforceTotal.WithLabelValues(decision).Inc()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error string `json:"error"`
}

func errorResponse(msg string) apiError {
	return apiError{Error: msg}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// isTrustedProxy reports whether ip is within one of the configured trusted proxy CIDRs.
func (app *App) isTrustedProxy(ip net.IP) bool {
	for _, network := range app.trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP returns the real client IP address for enforcement.
//
// X-Forwarded-For is only trusted when the immediate peer (r.RemoteAddr) is
// within one of the configured TrustedProxyCIDRs.  When no trusted proxies are
// configured, or the peer is not trusted, RemoteAddr is used directly.
func (app *App) extractClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if len(app.trustedProxyNets) > 0 {
		if remoteIP := net.ParseIP(remoteHost); remoteIP != nil && app.isTrustedProxy(remoteIP) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Walk the XFF chain backwards (right to left), returning the
				// first IP that is not in the trusted proxy list.  This prevents
				// a client from spoofing the leftmost entry when a trusted proxy
				// appends to (rather than overwrites) an incoming XFF header.
				parts := strings.Split(xff, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					ip := net.ParseIP(strings.TrimSpace(parts[i]))
					if ip == nil {
						continue
					}
					if !app.isTrustedProxy(ip) {
						return ip.String()
					}
				}
			}
		}
	}

	return remoteHost
}

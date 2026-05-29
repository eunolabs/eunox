// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/eunolabs/eunox/pkg/audit"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/observability"
	"github.com/eunolabs/eunox/pkg/ocsf"
	"github.com/google/uuid"
)

// gatewayTracer is the OTel tracer used for enforcement sub-step spans (P2-4).
var gatewayTracer = otel.Tracer("github.com/eunolabs/eunox/internal/gateway")

// setDecision writes both the legacy "decision" attribute and the canonical
// eunox.policy_decision attribute in a single call, keeping every return path
// in handleEnforce consistent.
func setDecision(span trace.Span, decision string) {
	span.SetAttributes(
		attribute.String("decision", decision),
		observability.EunoxAttrPolicyDecision.String(decision),
	)
}

// validToolNameRE enforces an allowlist on the X-Tool-Name proxy header.
// Accepts 1–256 characters: letters, digits, underscores, hyphens, colons, dots.
var validToolNameRE = regexp.MustCompile(`^[a-zA-Z0-9_\-:.]{1,256}$`)

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

	// Start a child span for enforcement so that sub-steps (token verify,
	// revocation check, engine eval) can be observed independently (P2-4).
	ctx, span := gatewayTracer.Start(r.Context(), "gateway.enforce",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			attribute.String("request_id", requestID),
		),
	)
	defer span.End()

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

	// Set request-level span attributes from the parsed payload.
	span.SetAttributes(
		observability.EunoxAttrToolName.String(payload.Request.ToolName),
		observability.EunoxAttrSessionID.String(payload.Request.SessionID),
	)

	// --- Token verification: cache-hit path skips JWKS re-verify and
	// revocation check (P2-2). On a cache miss we fall through to full
	// verification and store the result on success. ---
	var claims *capability.TokenPayload
	cacheHit := false
	if app.tokenCache != nil {
		if cached, ok := app.tokenCache.Get(payload.Token); ok {
			claims = cached
			cacheHit = true
			span.SetAttributes(attribute.Bool("token_cache_hit", true))
		}
	}

	if !cacheHit {
		// Verify JWT signature and standard claims (JWKS round-trip).
		_, verifySpan := gatewayTracer.Start(ctx, "gateway.enforce.verify_token")
		var verifyErr error
		claims, verifyErr = app.deps.JWTVerifier.VerifyToken(ctx, payload.Token)
		if verifyErr != nil {
			verifySpan.RecordError(verifyErr)
			verifySpan.SetStatus(codes.Error, verifyErr.Error())
			verifySpan.End()
			resp := capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
				Denial: &capability.DenialInfo{
					Code:    capability.ErrCodeAuthorizationFailed,
					Message: fmt.Sprintf("token verification failed: %v", verifyErr),
				},
			}
			setDecision(span, "deny")
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		verifySpan.End()

		// Check token expiry.
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
			setDecision(span, "deny")
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// Check revocation (Redis round-trip — skipped on cache hits).
		if app.deps.Revocation != nil && claims.JWTID != "" {
			_, revSpan := gatewayTracer.Start(ctx, "gateway.enforce.revocation_check")
			revoked, revErr := app.deps.Revocation.IsRevoked(ctx, claims.JWTID)
			if revErr != nil {
				revSpan.RecordError(revErr)
				revSpan.SetStatus(codes.Error, revErr.Error())
				revSpan.End()
				writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
				app.recordMetric("deny", start)
				return
			}
			revSpan.End()
			if revoked {
				// Ensure we don't serve a revoked token from cache in the future.
				if app.tokenCache != nil {
					app.tokenCache.Invalidate(payload.Token)
				}
				resp := capability.EnforceResponse{
					RequestID: requestID,
					Decision:  capability.DecisionDeny,
					DecidedAt: time.Now().UTC().Format(time.RFC3339),
					Denial: &capability.DenialInfo{
						Code:    capability.ErrCodeRevoked,
						Message: "token has been revoked",
					},
				}
				setDecision(span, "deny")
				app.recordMetric("deny", start)
				writeJSON(w, http.StatusOK, resp)
				return
			}
		}

		// Cache the verified claims so subsequent requests in the same
		// pipeline run avoid the JWKS + revocation round-trips.
		if app.tokenCache != nil {
			app.tokenCache.Put(payload.Token, claims)
		}
	}

	// Set claims-level span attributes now that we have verified claims.
	{
		tenantID := ""
		if claims.AuthorizedBy != nil {
			tenantID = claims.AuthorizedBy.TenantID
		}
		span.SetAttributes(
			observability.EunoxAttrAgentID.String(claims.Subject),
			observability.EunoxAttrCapabilityTokenID.String(claims.JWTID),
			observability.EunoxAttrTenantID.String(tenantID),
		)
	}

	// H-1 fix: a sender-constrained token (cnf.jkt set) MUST present a DPoP
	// proof. Without this check, a stolen JKT-bound token can be replayed
	// against /api/v1/enforce without supplying any proof-of-possession.
	// handleProxy (line ~529) has the equivalent check; the two paths must
	// remain in sync.
	if claims.Confirmation != nil && claims.Confirmation.JKT != "" && payload.DPoP == nil {
		resp := capability.EnforceResponse{
			RequestID: requestID,
			Decision:  capability.DecisionDeny,
			DecidedAt: time.Now().UTC().Format(time.RFC3339),
			Denial: &capability.DenialInfo{
				Code:    capability.ErrCodeAuthorizationFailed,
				Message: "DPoP proof required for sender-constrained token",
			},
		}
		setDecision(span, "deny")
		app.recordMetric("deny", start)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Check DPoP replay
	if payload.DPoP != nil {
		_, dpopSpan := gatewayTracer.Start(ctx, "gateway.enforce.dpop_check")
		if err := app.verifyDPoP(ctx, payload.DPoP, claims); err != nil {
			dpopSpan.RecordError(err)
			dpopSpan.SetStatus(codes.Error, err.Error())
			dpopSpan.End()
			resp := capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
				Denial: &capability.DenialInfo{
					Code:    capability.ErrCodeAuthorizationFailed,
					Message: fmt.Sprintf("DPoP verification failed: %v", err),
				},
			}
			setDecision(span, "deny")
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		dpopSpan.End()
	}

	// Check kill switch
	if app.deps.KillSwitch != nil {
		_, ksSpan := gatewayTracer.Start(ctx, "gateway.enforce.kill_switch_check")
		blocked, ksErr := app.deps.KillSwitch.ShouldBlock(ctx, claims.Subject, payload.Request.SessionID)
		if ksErr != nil {
			ksSpan.RecordError(ksErr)
			ksSpan.SetStatus(codes.Error, ksErr.Error())
			ksSpan.End()
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch check unavailable"))
			app.recordMetric("deny", start)
			return
		}
		ksSpan.End()
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
			setDecision(span, "deny")
			app.recordMetric("deny", start)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Fill in source IP from request if not provided
	if payload.Request.Context.SourceIP == "" {
		payload.Request.Context.SourceIP = app.extractClientIP(r)
	}

	// Run enforcement engine.
	_, engineSpan := gatewayTracer.Start(ctx, "gateway.enforce.engine_eval")
	resp, engineErr := app.deps.Engine.ValidateAction(ctx, &payload.Request, claims.Capabilities)
	if engineErr != nil {
		engineSpan.RecordError(engineErr)
		engineSpan.SetStatus(codes.Error, engineErr.Error())
		engineSpan.End()
		writeJSON(w, http.StatusInternalServerError, errorResponse("enforcement engine error"))
		return
	}
	engineSpan.End()
	resp.RequestID = requestID

	decision := string(resp.Decision)
	setDecision(span, decision)

	// Emit an audit event for the enforcement decision (P2-3). The write is
	// non-blocking when the pipeline is wrapped in an AsyncPipeline; it does
	// not affect enforcement response latency.
	app.emitEnforceAuditEvent(ctx, claims, &payload.Request, &resp, requestID)

	app.recordMetric(decision, start)
	writeJSON(w, http.StatusOK, resp)
}

// handleValidate handles POST /api/v1/validate.
//
// Full condition evaluation is performed (time windows, IP ranges, allowed
// operations, etc.) using the same enforcement engine as /enforce.  The
// call-counter (MaxCalls) is explicitly skipped via enforcement.WithDryRun so
// that preflight checks do not consume quota.
//
// Revocation and kill-switch are checked so that the preflight result is
// consistent with /enforce.  DPoP replay protection is intentionally omitted —
// /validate is a read-only preflight and does not consume proof JTIs.
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

	// Token verification: check in-process cache first (P2-2).
	var claims *capability.TokenPayload
	cacheHit := false
	if app.tokenCache != nil {
		if cached, ok := app.tokenCache.Get(req.Token); ok {
			claims = cached
			cacheHit = true
		}
	}

	if !cacheHit {
		// Verify JWT
		claims, err = app.deps.JWTVerifier.VerifyToken(r.Context(), req.Token)
		if err != nil {
			writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("token verification failed: %v", err),
			})
			return
		}

		// Check revocation so that a revoked token is denied here, just as it
		// would be by /enforce.
		if app.deps.Revocation != nil && claims.JWTID != "" {
			revoked, revErr := app.deps.Revocation.IsRevoked(r.Context(), claims.JWTID)
			if revErr != nil {
				writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
				return
			}
			if revoked {
				if app.tokenCache != nil {
					app.tokenCache.Invalidate(req.Token)
				}
				writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
					Allowed: false,
					Reason:  "token has been revoked",
				})
				return
			}
		}

		// Cache the verified claims.
		if app.tokenCache != nil {
			app.tokenCache.Put(req.Token, claims)
		}
	}

	// Check kill switch so that a blocked subject is denied here, just as it
	// would be by /enforce.
	if app.deps.KillSwitch != nil {
		blocked, ksErr := app.deps.KillSwitch.ShouldBlock(r.Context(), claims.Subject, "")
		if ksErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch check unavailable"))
			return
		}
		if blocked {
			writeJSON(w, http.StatusOK, capability.ValidateActionResponse{
				Allowed: false,
				Reason:  "kill switch is active",
			})
			return
		}
	}

	// Build the enforcement request.  Propagate source IP from the request
	// context field (if provided by the caller) or fall back to the network
	// peer, so that IPRangeCondition evaluations are accurate.
	// "sourceIp" is the JSON key from capability.EnforceRequestContext (json:"sourceIp,omitempty").
	sourceIP := app.extractClientIP(r)
	if ip, ok := req.Context["sourceIp"].(string); ok && ip != "" {
		sourceIP = ip
	}

	enforceReq := &capability.EnforceRequest{
		ToolName: req.Resource,
		Context: capability.EnforceRequestContext{
			Operation: req.Action,
			SourceIP:  sourceIP,
		},
	}

	// Run the full enforcement engine with dry-run flag so that conditions
	// (time window, IP range, allowed operations, etc.) are evaluated but
	// MaxCalls counters are not incremented.
	engineResp, engineErr := app.deps.Engine.ValidateAction(enforcement.WithDryRun(r.Context()), enforceReq, claims.Capabilities)
	if engineErr != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("enforcement engine error"))
		return
	}

	allowed := engineResp.Decision == capability.DecisionAllow
	validateResp := capability.ValidateActionResponse{
		Allowed: allowed,
	}

	switch {
	case allowed:
		// Populate MatchedCapability for callers that use it to inspect obligations.
		validateResp.MatchedCapability = app.deps.Engine.FindMatchingCapability(enforceReq, claims.Capabilities)
	case engineResp.Denial != nil:
		validateResp.Reason = engineResp.Denial.Message
	default:
		validateResp.Reason = "no matching capability for requested action"
	}

	writeJSON(w, http.StatusOK, validateResp)
}

// handleProxy handles ANY /proxy/* — reverse proxies to backend after enforcement.
func (app *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	if app.proxy == nil {
		writeJSON(w, http.StatusBadGateway, errorResponse("no backend configured"))
		return
	}

	// Extract and validate X-Request-Id for distributed tracing.
	requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if requestID == "" {
		requestID = uuid.NewString()
	}

	// Extract token from Authorization header
	token := extractBearerToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errorResponse("missing authorization token"))
		return
	}

	// Token verification: check in-process cache first (P2-2).
	var claims *capability.TokenPayload
	cacheHit := false
	if app.tokenCache != nil {
		if cached, ok := app.tokenCache.Get(token); ok {
			claims = cached
			cacheHit = true
		}
	}

	if !cacheHit {
		// Verify JWT
		var err error
		claims, err = app.deps.JWTVerifier.VerifyToken(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errorResponse("invalid token"))
			return
		}

		// Check token expiry
		if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
			writeJSON(w, http.StatusUnauthorized, errorResponse("token has expired"))
			return
		}

		// Check revocation before DPoP (aligns with handleEnforce order, B-3 fix).
		if app.deps.Revocation != nil && claims.JWTID != "" {
			revoked, revErr := app.deps.Revocation.IsRevoked(r.Context(), claims.JWTID)
			if revErr != nil {
				writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
				return
			}
			if revoked {
				if app.tokenCache != nil {
					app.tokenCache.Invalidate(token)
				}
				writeJSON(w, http.StatusForbidden, errorResponse("token revoked"))
				return
			}
		}

		// Cache the verified claims.
		if app.tokenCache != nil {
			app.tokenCache.Put(token, claims)
		}
	}

	// DPoP sender-constraint enforcement (F-2 fix).
	// When the capability token carries a cnf.jkt binding, a valid DPoP proof
	// from the DPoP header is required so stolen tokens cannot be replayed.
	// Placed after revocation and before kill-switch to match handleEnforce order.
	if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			writeJSON(w, http.StatusUnauthorized, errorResponse("DPoP proof required for sender-constrained token"))
			return
		}

		requestURL := app.reconstructRequestURL(r)

		dpop := &capability.DPoPProof{
			Proof:      dpopProof,
			HTTPMethod: r.Method,
			HTTPURL:    requestURL,
		}
		if err := app.verifyDPoP(r.Context(), dpop, claims); err != nil {
			writeJSON(w, http.StatusUnauthorized, errorResponse(fmt.Sprintf("DPoP verification failed: %v", err)))
			return
		}
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

	// Validate X-Tool-Name against a strict allowlist.
	// Rejects empty, oversized, or path-traversal-style tool names before they
	// reach the enforcement engine or are written into audit records.
	toolName := r.Header.Get("X-Tool-Name")
	if !validToolNameRE.MatchString(toolName) {
		writeJSON(w, http.StatusBadRequest, errorResponse(`X-Tool-Name header is missing or invalid; must match ^[a-zA-Z0-9_\-:.]{1,256}$`))
		return
	}

	// Build enforce request from proxy context
	enforceReq := capability.EnforceRequest{
		SessionID: r.Header.Get("X-Session-ID"),
		ToolName:  toolName,
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

	// Inject the gateway-assigned request ID into the upstream request so that
	// logs and traces across gateway → backend can be correlated.
	r.Header.Set("X-Request-Id", requestID)

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

// reconstructRequestURL returns the full request URL for DPoP verification.
//
// When the gateway sits behind a TLS-terminating proxy (common deployment),
// X-Forwarded-Proto and X-Forwarded-Host headers are honored when the immediate
// peer is in TrustedProxyCIDRs.  This ensures the computed htu matches the
// public URL the client used to sign the DPoP proof, preventing spurious
// rejections in reverse-proxy deployments.
func (app *App) reconstructRequestURL(r *http.Request) string {
	scheme := "http"
	host := r.Host

	if len(app.trustedProxyNets) > 0 {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		if remoteIP := net.ParseIP(remoteHost); remoteIP != nil && app.isTrustedProxy(remoteIP) {
			// Trust forwarded headers from known proxies
			if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
				scheme = fwdProto
			}
			if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
				host = fwdHost
			}
		}
	}

	// Fallback: if not from a trusted proxy, use direct TLS state
	if scheme == "http" && r.TLS != nil {
		scheme = "https"
	}

	// Use URL.Path and RawQuery (not RequestURI) to avoid including fragment
	// and to ensure we match what the client signed in the DPoP proof.
	path := r.URL.Path
	query := r.URL.RawQuery
	if query != "" {
		return fmt.Sprintf("%s://%s%s?%s", scheme, host, path, query)
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// emitEnforceAuditEvent emits an OCSF API-Activity event for an enforcement
// decision.  The write is non-blocking when the pipeline is an AsyncPipeline;
// errors are not returned to the caller so that audit failures never affect
// enforcement response latency or correctness. A buffer-full error is logged
// as a warning for operator visibility.
func (app *App) emitEnforceAuditEvent(
	ctx context.Context,
	claims *capability.TokenPayload,
	req *capability.EnforceRequest,
	resp *capability.EnforceResponse,
	requestID string,
) {
	if app.deps.Audit == nil || app.deps.Audit.Pipeline == nil {
		return
	}

	actor := ocsf.Actor{}
	if claims != nil {
		tenantID := ""
		if claims.AuthorizedBy != nil {
			tenantID = claims.AuthorizedBy.TenantID
		}
		actor = ocsf.Actor{
			UserID:   claims.Subject,
			TenantID: tenantID,
		}
	}

	activityID := ocsf.ActivityAPIAllow
	statusID := ocsf.StatusSuccess
	outcome := "allow"
	if resp.Decision == capability.DecisionDeny {
		activityID = ocsf.ActivityAPIDeny
		statusID = ocsf.StatusFailure
		outcome = "deny"
	}

	toolName := ""
	toolAction := ""
	sessionID := ""
	if req != nil {
		toolName = req.ToolName
		toolAction = req.Context.Operation
		sessionID = req.SessionID
	}

	ocsfEvent := ocsf.NewAPIActivityEvent(activityID, &actor).
		WithStatus(statusID, outcome)
	ocsfEvent.ToolName = toolName
	ocsfEvent.ToolAction = toolAction
	ocsfEvent.SessionID = sessionID
	ocsfEvent.RequestID = requestID

	entry := &audit.LogEntry{
		ID:        requestID,
		Timestamp: time.Now().UTC(),
		TenantID:  actor.TenantID,
		EventType: "enforce." + outcome,
		Actor:     actor,
		Action:    "enforce",
		Resource: ocsf.Resource{
			UID:  toolName,
			Type: "tool",
		},
		Outcome:   outcome,
		OCSFEvent: ocsfEvent,
	}

	// Fire-and-forget: enforcement correctness is independent of audit writes.
	// Log a warning when the async buffer is full so operators can detect
	// sustained audit pressure and tune BufferSize accordingly.
	if err := app.deps.Audit.Pipeline.Append(ctx, entry); err != nil {
		if errors.Is(err, audit.ErrAsyncPipelineBufferFull) {
			logger := slog.Default()
			if app.deps.Logger != nil {
				logger = app.deps.Logger
			}
			logger.Warn("audit: enforce event dropped, async pipeline buffer full",
				slog.String("request_id", requestID),
				slog.String("tenant_id", entry.TenantID),
				slog.String("outcome", entry.Outcome),
			)
		}
	}
}

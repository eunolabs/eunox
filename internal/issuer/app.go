// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package issuer implements the Capability Issuer HTTP service.
package issuer

import (
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/eunolabs/eunox/internal/issuer/policy"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/crypto"
	"github.com/eunolabs/eunox/pkg/identity"
	"github.com/eunolabs/eunox/pkg/observability"
	"github.com/eunolabs/eunox/pkg/revocation"
)

const defaultMaxBodySize int64 = 1 << 20 // 1 MB

// Config holds the issuer application configuration.
type Config struct {
	IssuerDID       string
	IssuerURL       string
	DefaultTokenTTL int // seconds
	MaxTokenTTL     int // seconds
	Audience        string
	AdminAPIKey     string
	ReadinessChecks []func(ctx context.Context) error

	// MaxRequestBodySize is the maximum size of request bodies in bytes.
	// Defaults to 1 MB (1048576) if not set.
	MaxRequestBodySize int64
}

// RateLimiter provides rate-limiting for issuance requests.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// KeyStore and PublicKeyInfo are defined in pkg/crypto and re-exported here
// as type aliases for backward compatibility. D-2 fix: moved to pkg/crypto so
// that keystore implementations (SingleKeyStore, RotatingKeyStore) and the
// issuer share the same definition without risking import cycles.
type (
	KeyStore      = crypto.KeyStore
	PublicKeyInfo = crypto.PublicKeyInfo
)

// Dependencies holds the injected backends for the issuer.
type Dependencies struct {
	PolicyEngine *policy.Engine
	Identity     identity.Provider
	KeyStore     KeyStore
	RateLimiter  RateLimiter
	// Revocation is used to reject tokens that have been explicitly revoked.
	// When nil, revocation is not checked during token renewal (not recommended
	// for production).  Use a Redis-backed store in multi-replica deployments so
	// that gateway-issued revocations are visible to the issuer.
	Revocation revocation.Store
	Logger     *slog.Logger
	Metrics    *observability.MetricsRegistry
}

// App is the issuer HTTP application.
type App struct {
	config Config
	deps   Dependencies
	router chi.Router
	// H-5 fix: typed as SCIMRepository so a Postgres-backed implementation can
	// be injected for multi-replica deployments without changing handler code.
	scimStore SCIMRepository
}

// New creates a new issuer App with the given configuration and dependencies.
func New(cfg *Config, deps *Dependencies) *App {
	app := &App{
		config:    *cfg,
		deps:      *deps,
		scimStore: NewSCIMStore(),
	}
	app.router = app.buildRouter()
	return app
}

// Handler returns the http.Handler for the issuer.
func (app *App) Handler() http.Handler {
	return app.router
}

func (app *App) buildRouter() chi.Router {
	r := chi.NewRouter()

	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(observability.TracePropagation("issuer"))

	if app.deps.Logger != nil {
		r.Use(observability.RequestLogging(app.deps.Logger))
	}

	// Health endpoints
	r.Get("/health/live", app.handleLive)
	r.Get("/health/ready", app.handleReady)

	// Well-known endpoints (no auth required)
	r.Get("/.well-known/jwks.json", app.handleJWKS)
	r.Get("/.well-known/did.json", app.handleDIDDocument)
	r.Get("/.well-known/capability-issuer", app.handleDiscovery)

	// Public API
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/issue", app.handleIssue)
		r.Post("/attenuate", app.handleAttenuate)
		r.Post("/renew", app.handleRenew)
		r.Get("/public-key", app.handlePublicKey)
	})

	// Admin routes
	r.Route("/admin", func(r chi.Router) {
		r.Use(app.requireAdminAuth)
		r.Post("/role-policy/{role}", app.handleSetRolePolicy)
		r.Get("/role-policy", app.handleListRolePolicies)
		r.Delete("/role-policy/{role}", app.handleDeleteRolePolicy)
	})

	// SCIM provisioning (full SCIM 2.0 compliance)
	app.registerSCIMRoutes(r)

	return r
}

// --- Health Endpoints ---

func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app *App) handleReady(w http.ResponseWriter, r *http.Request) {
	for _, check := range app.config.ReadinessChecks {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		err := check(ctx)
		cancel()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not ready",
				"reason": err.Error(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// --- Issuance Endpoints ---

// IssueRequest is the request body for POST /api/v1/issue.
type IssueRequest struct {
	Token        string                  `json:"token"`        // Identity token from IdP
	Capabilities []capability.Constraint `json:"capabilities"` // Requested capabilities (optional)
	TTL          int                     `json:"ttl"`          // Requested TTL in seconds (optional)
	Audience     string                  `json:"audience"`     // Target audience (optional)
	DPoP         *DPoPBinding            `json:"dpop"`         // DPoP key binding (optional)
}

// DPoPBinding binds a token to a proof-of-possession key.
type DPoPBinding struct {
	JKT string `json:"jkt"` // JWK Thumbprint
}

// IssueResponse is the response body for POST /api/v1/issue.
type IssueResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	IssuedAt  int64  `json:"issuedAt"`
	TokenID   string `json:"tokenId"`
}

func (app *App) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req IssueRequest
	if err := app.readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("token is required"))
		return
	}

	// Verify identity
	user, err := app.deps.Identity.VerifyToken(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse(fmt.Sprintf("identity verification failed: %v", err)))
		return
	}

	// Rate limit per subject
	if app.deps.RateLimiter != nil {
		allowed, rlErr := app.deps.RateLimiter.Allow(r.Context(), "issue:"+user.Subject)
		if rlErr != nil {
			app.logError("rate limiter error", rlErr)
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("rate limiter unavailable"))
			return
		}
		if !allowed {
			writeJSON(w, http.StatusTooManyRequests, errorResponse("issuance rate limit exceeded"))
			return
		}
	}

	// Determine role (use first role, or default)
	role := "default"
	if len(user.Roles) > 0 {
		role = user.Roles[0]
	}

	// Validate capabilities are specified (breaking change: empty capabilities
	// now rejected instead of defaulting to full policy set — F-1 fix).
	if len(req.Capabilities) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse("capabilities field is required and must be non-empty"))
		return
	}

	// Intersect capabilities with policy
	caps, err := app.deps.PolicyEngine.IntersectCapabilities(role, req.Capabilities)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			writeJSON(w, http.StatusForbidden, errorResponse(fmt.Sprintf("no policy for role: %s", role)))
			return
		}
		if errors.Is(err, policy.ErrInvalidManifest) {
			writeJSON(w, http.StatusBadRequest, errorResponse("requested capabilities exceed policy bounds"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse("policy evaluation error"))
		return
	}

	// Determine TTL
	ttl := app.effectiveTTL(req.TTL, role)

	// Build token
	now := time.Now().UTC()
	tokenID := uuid.New().String()

	payload := &capability.TokenPayload{
		Issuer:        app.config.IssuerDID,
		Subject:       user.Subject,
		Audience:      app.effectiveAudience(req.Audience),
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(time.Duration(ttl) * time.Second).Unix(),
		JWTID:         tokenID,
		SchemaVersion: capability.SchemaVersion,
		Capabilities:  caps,
		AuthorizedBy: &capability.AuthorizedBy{
			UserID:   user.Subject,
			Roles:    user.Roles,
			TenantID: user.TenantID,
		},
	}

	// DPoP binding
	if req.DPoP != nil && req.DPoP.JKT != "" {
		payload.Confirmation = &capability.Confirmation{
			JKT: req.DPoP.JKT,
		}
	}

	// Compute policy hash
	payload.PolicyHash = computePolicyHash(caps)

	// Sign token
	tokenStr, err := app.signToken(r.Context(), payload)
	if err != nil {
		app.logError("token signing error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse("token signing failed"))
		return
	}

	writeJSON(w, http.StatusOK, IssueResponse{
		Token:     tokenStr,
		ExpiresAt: payload.ExpiresAt,
		IssuedAt:  payload.IssuedAt,
		TokenID:   tokenID,
	})
}

// --- Attenuation Endpoint ---

// AttenuateRequest is the request body for POST /api/v1/attenuate.
type AttenuateRequest struct {
	ParentToken  string                  `json:"parentToken"`
	Capabilities []capability.Constraint `json:"capabilities"`
	TTL          int                     `json:"ttl"`
	Audience     string                  `json:"audience"`
	DPoP         *DPoPBinding            `json:"dpop"`
}

// AttenuateResponse is the response body for POST /api/v1/attenuate.
type AttenuateResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	IssuedAt  int64  `json:"issuedAt"`
	TokenID   string `json:"tokenId"`
}

func (app *App) handleAttenuate(w http.ResponseWriter, r *http.Request) {
	var req AttenuateRequest
	if err := app.readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		return
	}

	if req.ParentToken == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("parentToken is required"))
		return
	}

	if len(req.Capabilities) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse("capabilities are required for attenuation"))
		return
	}

	// Verify parent token (must be a valid capability token from this issuer)
	parentClaims, err := app.verifyCapabilityToken(r.Context(), req.ParentToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse(fmt.Sprintf("parent token verification failed: %v", err)))
		return
	}

	// Enforce subset invariant: child ⊆ parent
	if err := policy.ValidateSubset(req.Capabilities, parentClaims.Capabilities); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(fmt.Sprintf("subset violation: %v", err)))
		return
	}

	// TTL cannot exceed parent's remaining lifetime
	now := time.Now().UTC()
	parentRemaining := int(parentClaims.ExpiresAt - now.Unix())
	if parentRemaining <= 0 {
		writeJSON(w, http.StatusUnauthorized, errorResponse("parent token has expired"))
		return
	}

	ttl := req.TTL
	if ttl <= 0 || ttl > parentRemaining {
		ttl = parentRemaining
	}

	// Build child token
	tokenID := uuid.New().String()
	payload := &capability.TokenPayload{
		Issuer:             app.config.IssuerDID,
		Subject:            parentClaims.Subject,
		Audience:           app.effectiveAudience(req.Audience),
		IssuedAt:           now.Unix(),
		ExpiresAt:          now.Add(time.Duration(ttl) * time.Second).Unix(),
		JWTID:              tokenID,
		SchemaVersion:      capability.SchemaVersion,
		Capabilities:       req.Capabilities,
		ParentCapabilityID: parentClaims.JWTID,
		AuthorizedBy:       parentClaims.AuthorizedBy,
	}

	if req.DPoP != nil && req.DPoP.JKT != "" {
		payload.Confirmation = &capability.Confirmation{JKT: req.DPoP.JKT}
	}

	payload.PolicyHash = computePolicyHash(req.Capabilities)

	tokenStr, err := app.signToken(r.Context(), payload)
	if err != nil {
		app.logError("token signing error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse("token signing failed"))
		return
	}

	writeJSON(w, http.StatusOK, AttenuateResponse{
		Token:     tokenStr,
		ExpiresAt: payload.ExpiresAt,
		IssuedAt:  payload.IssuedAt,
		TokenID:   tokenID,
	})
}

// --- Renewal Endpoint ---

// RenewRequest is the request body for POST /api/v1/renew.
type RenewRequest struct {
	Token    string `json:"token"`    // Current capability token
	IDToken  string `json:"idToken"`  // Fresh identity token for re-auth
	TTL      int    `json:"ttl"`      // Requested new TTL (optional)
	Audience string `json:"audience"` // Target audience (optional)
}

// RenewResponse is the response body for POST /api/v1/renew.
type RenewResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	IssuedAt  int64  `json:"issuedAt"`
	TokenID   string `json:"tokenId"`
}

func (app *App) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req RenewRequest
	if err := app.readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("token is required"))
		return
	}
	if req.IDToken == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("idToken is required for re-authentication"))
		return
	}

	// Verify the existing capability token
	claims, err := app.verifyCapabilityToken(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse(fmt.Sprintf("token verification failed: %v", err)))
		return
	}

	// Check revocation before issuing a new token.  A revoked token must not
	// be used to obtain a fresh non-revoked token — this would permanently
	// bypass revocation.  The check is performed after signature verification
	// so that only well-formed tokens reach the revocation store.
	if app.deps.Revocation != nil {
		if claims.JWTID == "" {
			// Tokens without a jti cannot be tracked in the revocation store.
			// Log a warning so operators can detect issuers or libraries that
			// omit the jti claim.
			if app.deps.Logger != nil {
				app.deps.Logger.Warn("skipping revocation check on renew: capability token has no jti claim")
			}
		} else {
			revoked, revErr := app.deps.Revocation.IsRevoked(r.Context(), claims.JWTID)
			if revErr != nil {
				writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation check unavailable"))
				return
			}
			if revoked {
				writeJSON(w, http.StatusUnauthorized, errorResponse("token has been revoked"))
				return
			}
		}
	}

	// Re-verify identity with fresh ID token
	user, err := app.deps.Identity.VerifyToken(r.Context(), req.IDToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse(fmt.Sprintf("identity re-authentication failed: %v", err)))
		return
	}

	// Subject must match
	if user.Subject != claims.Subject {
		writeJSON(w, http.StatusForbidden, errorResponse("identity subject does not match token subject"))
		return
	}

	// Rate limit
	if app.deps.RateLimiter != nil {
		allowed, rlErr := app.deps.RateLimiter.Allow(r.Context(), "renew:"+user.Subject)
		if rlErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("rate limiter unavailable"))
			return
		}
		if !allowed {
			writeJSON(w, http.StatusTooManyRequests, errorResponse("renewal rate limit exceeded"))
			return
		}
	}

	// Determine role and cap TTL from policy
	role := "default"
	if claims.AuthorizedBy != nil && len(claims.AuthorizedBy.Roles) > 0 {
		role = claims.AuthorizedBy.Roles[0]
	}
	ttl := app.effectiveTTL(req.TTL, role)

	// Build renewed token — same scope, new expiry
	now := time.Now().UTC()
	tokenID := uuid.New().String()

	payload := &capability.TokenPayload{
		Issuer:             app.config.IssuerDID,
		Subject:            claims.Subject,
		Audience:           app.effectiveAudience(req.Audience),
		IssuedAt:           now.Unix(),
		ExpiresAt:          now.Add(time.Duration(ttl) * time.Second).Unix(),
		JWTID:              tokenID,
		SchemaVersion:      capability.SchemaVersion,
		Capabilities:       claims.Capabilities, // Same scope
		ParentCapabilityID: claims.ParentCapabilityID,
		AuthorizedBy:       claims.AuthorizedBy,
		Confirmation:       claims.Confirmation,
	}

	payload.PolicyHash = computePolicyHash(claims.Capabilities)

	tokenStr, err := app.signToken(r.Context(), payload)
	if err != nil {
		app.logError("token signing error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse("token signing failed"))
		return
	}

	writeJSON(w, http.StatusOK, RenewResponse{
		Token:     tokenStr,
		ExpiresAt: payload.ExpiresAt,
		IssuedAt:  payload.IssuedAt,
		TokenID:   tokenID,
	})
}

// --- Well-Known Endpoints ---

func (app *App) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	keys := app.deps.KeyStore.PublicKeys()
	jwks := buildJWKS(keys)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwks)
}

func (app *App) handleDIDDocument(w http.ResponseWriter, _ *http.Request) {
	keys := app.deps.KeyStore.PublicKeys()
	doc := buildDIDDocument(app.config.IssuerDID, keys)
	w.Header().Set("Content-Type", "application/did+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

func (app *App) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	discovery := map[string]interface{}{
		"issuer":               app.config.IssuerDID,
		"issuer_url":           app.config.IssuerURL,
		"jwks_uri":             app.config.IssuerURL + "/.well-known/jwks.json",
		"did_document_uri":     app.config.IssuerURL + "/.well-known/did.json",
		"token_endpoint":       app.config.IssuerURL + "/api/v1/issue",
		"attenuate_endpoint":   app.config.IssuerURL + "/api/v1/attenuate",
		"renew_endpoint":       app.config.IssuerURL + "/api/v1/renew",
		"schema_version":       capability.SchemaVersion,
		"supported_algorithms": crypto.SupportedAlgorithms,
	}
	writeJSON(w, http.StatusOK, discovery)
}

func (app *App) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	keys := app.deps.KeyStore.PublicKeys()
	if len(keys) == 0 {
		writeJSON(w, http.StatusNotFound, errorResponse("no signing keys configured"))
		return
	}
	// Return the primary key
	primary := keys[0]
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keyId":     primary.KeyID,
		"algorithm": primary.Algorithm,
		"use":       primary.Use,
	})
}

// --- Admin Endpoints ---

// RolePolicyRequest is the request body for POST /admin/role-policy/{role}.
type RolePolicyRequest struct {
	Description    string                  `json:"description"`
	MaxTTLSeconds  int                     `json:"maxTtlSeconds"`
	Capabilities   []capability.Constraint `json:"capabilities"`
	AllowedActions []string                `json:"allowedActions,omitempty"`
}

func (app *App) handleSetRolePolicy(w http.ResponseWriter, r *http.Request) {
	role := chi.URLParam(r, "role")
	if role == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("role is required"))
		return
	}

	var req RolePolicyRequest
	if err := app.readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		return
	}

	if len(req.Capabilities) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse("at least one capability is required"))
		return
	}

	p := &policy.RoleCapabilityPolicy{
		Role:           role,
		Description:    req.Description,
		MaxTTLSeconds:  req.MaxTTLSeconds,
		Capabilities:   req.Capabilities,
		AllowedActions: req.AllowedActions,
	}

	app.deps.PolicyEngine.SetPolicy(p)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"role":   role,
		"status": "created",
	})
}

func (app *App) handleListRolePolicies(w http.ResponseWriter, _ *http.Request) {
	policies := app.deps.PolicyEngine.ListPolicies()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
	})
}

func (app *App) handleDeleteRolePolicy(w http.ResponseWriter, r *http.Request) {
	role := chi.URLParam(r, "role")
	if role == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("role is required"))
		return
	}

	if !app.deps.PolicyEngine.RemovePolicy(role) {
		writeJSON(w, http.StatusNotFound, errorResponse(fmt.Sprintf("policy not found for role: %s", role)))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"role":   role,
		"status": "deleted",
	})
}

// --- SCIM Endpoints ---

// SCIMUserRequest represents a SCIM user creation request.
type SCIMUserRequest struct {
	Schemas    []string `json:"schemas"`
	UserName   string   `json:"userName"`
	ExternalID string   `json:"externalId,omitempty"`
	Name       struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Active bool `json:"active"`
}

// SCIMGroupRequest represents a SCIM group creation request.
type SCIMGroupRequest struct {
	Schemas     []string `json:"schemas"`
	DisplayName string   `json:"displayName"`
	ExternalID  string   `json:"externalId,omitempty"`
	Members     []struct {
		Value   string `json:"value"`
		Display string `json:"display"`
	} `json:"members"`
}

// --- Helper Methods ---

func (app *App) effectiveTTL(requested int, role string) int {
	maxTTL := app.deps.PolicyEngine.MaxTTLForRole(role)
	if app.config.MaxTokenTTL > 0 && maxTTL > app.config.MaxTokenTTL {
		maxTTL = app.config.MaxTokenTTL
	}

	if requested <= 0 {
		return min(app.config.DefaultTokenTTL, maxTTL)
	}
	return min(requested, maxTTL)
}

// effectiveAudience returns the audience that should be embedded in a token.
// Priority: configured Audience > caller-requested audience > issuer URL default.
// M-2 fix: removed dead-code fallback (line that re-returned config.Audience when
// both were empty) and added the issuer URL as a meaningful default so that tokens
// always carry a non-empty aud claim.
func (app *App) effectiveAudience(requested string) string {
	if app.config.Audience != "" {
		return app.config.Audience
	}
	if requested != "" {
		return requested
	}
	// Fall back to the issuer URL so tokens always have a non-empty audience.
	// An empty audience would fail gateway-side validation (H-6 fix).
	return app.config.IssuerURL
}

// privateKeyProvider is a narrow interface satisfied by *crypto.SoftwareSigner.
// It lets signToken obtain the raw private key for go-jose without widening the
// public crypto.Signer interface.
type privateKeyProvider interface {
	PrivateKey() stdcrypto.PrivateKey
}

// signToken serialises payload as a signed JWT using go-jose so that the token
// format is unconditionally compatible with the go-jose parser used in
// verifyCapabilityToken, attenuation, and renewal.  M-3 fix: the previous
// manual base64 construction diverged from go-jose's expected header format;
// using go-jose end-to-end eliminates that risk.
func (app *App) signToken(_ context.Context, payload *capability.TokenPayload) (string, error) {
	signer := app.deps.KeyStore.CurrentSigner()
	if signer == nil {
		return "", errors.New("no signing key available")
	}

	pkp, ok := signer.(privateKeyProvider)
	if !ok {
		return "", fmt.Errorf("signer type %T does not expose private key for JWT signing", signer)
	}

	joseSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(signer.Algorithm()),
			Key:       pkp.PrivateKey(),
		},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), signer.KeyID()),
	)
	if err != nil {
		return "", fmt.Errorf("create JWT signer: %w", err)
	}

	token, err := jwt.Signed(joseSigner).Claims(payload).Serialize()
	if err != nil {
		return "", fmt.Errorf("serialize JWT: %w", err)
	}
	return token, nil
}

func (app *App) verifyCapabilityToken(_ context.Context, tokenStr string) (*capability.TokenPayload, error) {
	// Parse the JWT (header.payload.signature)
	parts := splitToken(tokenStr)
	if parts == nil {
		return nil, errors.New("malformed token")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Algorithm == "" {
		return nil, errors.New("token header missing alg")
	}
	if !isSupportedTokenAlgorithm(header.Algorithm) {
		return nil, fmt.Errorf("unsupported token algorithm %q", header.Algorithm)
	}
	if header.KeyID == "" {
		return nil, errors.New("token header missing kid")
	}

	parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(header.Algorithm)})
	if err != nil {
		return nil, fmt.Errorf("parse signed token: %w", err)
	}

	candidateKeys := make([]interface{}, 0, 1)
	for _, key := range app.deps.KeyStore.PublicKeys() {
		if key.KeyID != header.KeyID {
			continue
		}
		if header.Algorithm != string(key.Algorithm) {
			continue
		}
		candidateKeys = append(candidateKeys, key.PublicKey)
	}
	if len(candidateKeys) == 0 {
		return nil, errors.New("no matching verification key found")
	}

	var claims capability.TokenPayload
	var verifyErr error
	for _, key := range candidateKeys {
		if err := parsed.Claims(key, &claims); err == nil {
			verifyErr = nil
			break
		}
		verifyErr = err
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("verify token signature: %w", verifyErr)
	}

	// Verify issuer
	if claims.Issuer != app.config.IssuerDID {
		return nil, fmt.Errorf("token issuer %q does not match this issuer", claims.Issuer)
	}

	// Check expiry
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		return nil, errors.New("token has expired")
	}

	return &claims, nil
}



func (app *App) requireAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.AdminAPIKey == "" {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("admin API is not configured"))
			return
		}

		provided := r.Header.Get(adminAPIKeyHeader())
		if subtle.ConstantTimeCompare([]byte(provided), []byte(app.config.AdminAPIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse("admin authentication failed"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func adminAPIKeyHeader() string {
	return strings.Join([]string{"X", "Admin", "Api", "Key"}, "-")
}

func isSupportedTokenAlgorithm(alg string) bool {
	switch crypto.Algorithm(alg) {
	case crypto.RS256, crypto.RS384, crypto.RS512,
		crypto.PS256, crypto.PS384, crypto.PS512,
		crypto.ES256, crypto.ES384, crypto.ES512,
		crypto.EdDSA:
		return true
	default:
		return false
	}
}

func (app *App) logError(msg string, err error) {
	if app.deps.Logger != nil {
		app.deps.Logger.Error(msg, slog.String("error", err.Error()))
	}
}

// --- Utility Functions ---

func splitToken(token string) []string {
	var parts [3]string
	start := 0
	partIdx := 0
	for i := range token {
		if token[i] == '.' {
			if partIdx >= 2 {
				return nil
			}
			parts[partIdx] = token[start:i]
			start = i + 1
			partIdx++
		}
	}
	if partIdx != 2 {
		return nil
	}
	parts[2] = token[start:]
	result := parts[:]
	return result
}

func computePolicyHash(caps []capability.Constraint) string {
	data, _ := json.Marshal(caps)
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

func (app *App) readJSON(r *http.Request, v interface{}) error {
	limit := app.config.MaxRequestBodySize
	if limit <= 0 {
		limit = defaultMaxBodySize
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
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

// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Errors returned by admin authentication.
var (
	ErrAdminUnauthorized = errors.New("admin: unauthorized")
	ErrAdminForbidden    = errors.New("admin: forbidden")
)

// AdminAuthenticator validates admin credentials from request headers.
type AdminAuthenticator interface {
	// Authenticate extracts and validates admin identity from the request.
	// Returns the operator ID and tenant ID, or an error.
	Authenticate(ctx context.Context, r *http.Request) (*AdminIdentity, error)
}

// AdminIdentity represents the authenticated admin operator.
type AdminIdentity struct {
	OperatorID string `json:"operatorId"`
	TenantID   string `json:"tenantId,omitempty"`
}

// AdminConfig holds admin API configuration.
type AdminConfig struct {
	AdminAPIKey string
	TenantID    string // Tenant scope derived from the admin key.
}

// StaticKeyAdminAuth provides admin authentication via a static API key with timing-safe comparison.
type StaticKeyAdminAuth struct {
	adminKey string
	tenantID string
	logger   *slog.Logger
}

// NewStaticKeyAdminAuth creates an admin authenticator using a static API key.
func NewStaticKeyAdminAuth(key, tenantID string, logger *slog.Logger) *StaticKeyAdminAuth {
	if logger == nil {
		logger = slog.Default()
	}
	return &StaticKeyAdminAuth{
		adminKey: key,
		tenantID: tenantID,
		logger:   logger,
	}
}

// Authenticate validates the X-Admin-Api-Key header with constant-time comparison.
func (a *StaticKeyAdminAuth) Authenticate(_ context.Context, r *http.Request) (*AdminIdentity, error) {
	apiKey := r.Header.Get("X-Admin-Api-Key")
	if apiKey == "" {
		// Also check the legacy header.
		apiKey = r.Header.Get("X-Admin-Key")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("%w: no admin credentials provided", ErrAdminUnauthorized)
	}

	if a.adminKey == "" {
		return nil, fmt.Errorf("%w: admin key not configured", ErrAdminUnauthorized)
	}

	apiKeyDigest := sha256.Sum256([]byte(apiKey))
	adminKeyDigest := sha256.Sum256([]byte(a.adminKey))
	if subtle.ConstantTimeCompare(apiKeyDigest[:], adminKeyDigest[:]) != 1 {
		return nil, fmt.Errorf("%w: invalid admin key", ErrAdminUnauthorized)
	}

	return &AdminIdentity{
		OperatorID: "admin-key-user",
		TenantID:   a.tenantID,
	}, nil
}

// IdempotencyStore caches responses for mutating admin operations to prevent duplicate mutations.
type IdempotencyStore struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	ttl     time.Duration
	now     func() time.Time
}

type idempotencyEntry struct {
	response   []byte
	statusCode int
	headers    http.Header
	createdAt  time.Time
}

// IdempotencyStoreOption configures the IdempotencyStore.
type IdempotencyStoreOption func(*IdempotencyStore)

// WithIdempotencyTTL sets the TTL for idempotency entries.
func WithIdempotencyTTL(ttl time.Duration) IdempotencyStoreOption {
	return func(s *IdempotencyStore) {
		s.ttl = ttl
	}
}

// WithIdempotencyTimeFunc sets a custom time function (for testing).
func WithIdempotencyTimeFunc(fn func() time.Time) IdempotencyStoreOption {
	return func(s *IdempotencyStore) {
		s.now = fn
	}
}

// NewIdempotencyStore creates a new idempotency store with 24h default TTL.
func NewIdempotencyStore(opts ...IdempotencyStoreOption) *IdempotencyStore {
	s := &IdempotencyStore{
		entries: make(map[string]*idempotencyEntry),
		ttl:     24 * time.Hour,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Get retrieves a cached response by idempotency key. Returns nil if not found or expired.
func (s *IdempotencyStore) Get(key string) ([]byte, int, http.Header, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, 0, nil, false
	}

	if s.now().Sub(e.createdAt) > s.ttl {
		delete(s.entries, key)
		return nil, 0, nil, false
	}

	return e.response, e.statusCode, e.headers.Clone(), true
}

// Set stores a response for the given idempotency key.
func (s *IdempotencyStore) Set(key string, response []byte, statusCode int, headers http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for existingKey, e := range s.entries {
		if now.Sub(e.createdAt) > s.ttl {
			delete(s.entries, existingKey)
		}
	}

	s.entries[key] = &idempotencyEntry{
		response:   response,
		statusCode: statusCode,
		headers:    headers.Clone(),
		createdAt:  now,
	}
}

// Cleanup removes expired entries.
func (s *IdempotencyStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for key, e := range s.entries {
		if now.Sub(e.createdAt) > s.ttl {
			delete(s.entries, key)
		}
	}
}

// Len returns the number of entries in the store (for testing).
func (s *IdempotencyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// adminMiddleware enforces admin authentication and returns the identity via context.
func (app *App) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.adminAuth == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse("admin authentication not configured"))
			return
		}

		identity, err := app.adminAuth.Authenticate(r.Context(), r)
		if err != nil {
			if errors.Is(err, ErrAdminUnauthorized) {
				writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
				return
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse("authentication error"))
			return
		}

		ctx := contextWithAdminIdentity(r.Context(), identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// idempotencyMiddleware checks the Idempotency-Key header and returns cached responses.
func (app *App) idempotencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.idempotency == nil {
			next.ServeHTTP(w, r)
			return
		}

		idemKey := r.Header.Get("Idempotency-Key")
		if idemKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for cached response.
		identity := adminIdentityFromContext(r.Context())
		cacheKey := buildIdempotencyCacheKey(r, identity, idemKey)

		if cached, status, cachedHeaders, found := app.idempotency.Get(cacheKey); found {
			for headerKey, values := range cachedHeaders {
				for _, value := range values {
					w.Header().Add(headerKey, value)
				}
			}
			w.Header().Set("X-Idempotency-Replayed", "true")
			w.WriteHeader(status)
			_, _ = w.Write(cached)
			return
		}

		// Wrap the response writer to capture the response.
		rw := &responseCapture{ResponseWriter: w}
		next.ServeHTTP(rw, r)

		// Cache the response.
		if rw.body != nil {
			app.idempotency.Set(cacheKey, rw.body, rw.statusCode, rw.Header().Clone())
		}
	})
}

func buildIdempotencyCacheKey(r *http.Request, identity *AdminIdentity, idempotencyKey string) string {
	tenantID := ""
	if identity != nil {
		tenantID = identity.TenantID
	}
	return r.Method + "|" + r.URL.Path + "|" + tenantID + "|" + idempotencyKey
}

// responseCapture captures the response for idempotency caching.
type responseCapture struct {
	http.ResponseWriter
	body       []byte
	statusCode int
	written    bool
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
	rc.written = true
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if !rc.written {
		rc.statusCode = http.StatusOK
		rc.written = true
	}
	rc.body = append(rc.body, b...)
	return rc.ResponseWriter.Write(b)
}

// Context key types for admin identity.
type adminContextKey struct{}

func contextWithAdminIdentity(ctx context.Context, identity *AdminIdentity) context.Context {
	return context.WithValue(ctx, adminContextKey{}, identity)
}

func adminIdentityFromContext(ctx context.Context) *AdminIdentity {
	identity, _ := ctx.Value(adminContextKey{}).(*AdminIdentity)
	return identity
}

// requireCrossTenantAck checks that the request body contains acknowledgesCrossTenantImpact: true
// for operations that affect all tenants.
func requireCrossTenantAck(r *http.Request) error {
	var body struct {
		AcknowledgesCrossTenantImpact bool `json:"acknowledgesCrossTenantImpact"`
	}

	if r.Body == nil {
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}
	if len(raw) > maxBodySize {
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}

	r.Body = io.NopCloser(bytes.NewReader(raw))

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}

	if err := json.Unmarshal(trimmed, &body); err != nil {
		// If body is empty or not JSON, still require acknowledgment.
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}

	if !body.AcknowledgesCrossTenantImpact {
		return fmt.Errorf("%w: global operations require acknowledgesCrossTenantImpact: true", ErrAdminForbidden)
	}

	return nil
}

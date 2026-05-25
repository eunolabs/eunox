// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	defaultJWKSCacheTTL   = 5 * time.Minute
	defaultValidationSkew = time.Minute
	defaultHTTPTimeout    = 10 * time.Second
)

var supportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
}

// OIDCConfig configures the generic OIDC provider.
type OIDCConfig struct {
	IssuerURL      string
	Audience       string
	RequiredScopes []string
	RolesClaimPath string        // JSONPath-style dot notation for roles claim (e.g., "realm_access.roles")
	CacheTTL       time.Duration // JWKS cache TTL (default 5 min)
}

// JWKSClient fetches JSON Web Key Sets for JWT verification.
type JWKSClient interface {
	GetKeySet(ctx context.Context, jwksURL string) (*jose.JSONWebKeySet, error)
}

// HTTPJWKSClient fetches and caches JSON Web Key Sets over HTTP.
type HTTPJWKSClient struct {
	httpClient *http.Client
	ttl        time.Duration
	now        func() time.Time

	mu    sync.RWMutex
	cache map[string]cachedJWKS
}

type cachedJWKS struct {
	keySet    *jose.JSONWebKeySet
	expiresAt time.Time
}

type oidcDiscoveryDocument struct {
	JWKSURI string `json:"jwks_uri"`
}

type claimsMapper func(registered jwt.Claims, raw map[string]interface{}) (*UserContext, error)

// OIDCProvider verifies tokens against any OIDC-compliant identity provider.
type OIDCProvider struct {
	cfg          OIDCConfig
	providerType ProviderType
	jwksURI      string
	jwksClient   JWKSClient
	claimsMapper claimsMapper
	now          func() time.Time
}

// NewHTTPJWKSClient creates an HTTP-backed JWKS client with in-memory caching.
func NewHTTPJWKSClient(httpClient *http.Client, ttl time.Duration) *HTTPJWKSClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if ttl <= 0 {
		ttl = defaultJWKSCacheTTL
	}

	return &HTTPJWKSClient{
		httpClient: httpClient,
		ttl:        ttl,
		now:        time.Now,
		cache:      make(map[string]cachedJWKS),
	}
}

// GetKeySet fetches a JWKS document and caches it for the configured TTL.
func (c *HTTPJWKSClient) GetKeySet(ctx context.Context, jwksURL string) (*jose.JSONWebKeySet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := c.now()
	c.mu.RLock()
	entry, ok := c.cache[jwksURL]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.keySet, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(keySet.Keys) == 0 {
		return nil, errors.New("decode JWKS: no keys returned")
	}

	c.mu.Lock()
	c.cache[jwksURL] = cachedJWKS{
		keySet:    &keySet,
		expiresAt: now.Add(c.ttl),
	}
	c.mu.Unlock()

	return &keySet, nil
}

// NewOIDCProvider creates a generic OIDC provider using an HTTP-backed JWKS client.
func NewOIDCProvider(cfg OIDCConfig, httpClient *http.Client) (*OIDCProvider, error) {
	return NewOIDCProviderWithJWKSClient(cfg, httpClient, NewHTTPJWKSClient(httpClient, cfg.CacheTTL))
}

// NewOIDCProviderWithJWKSClient creates a generic OIDC provider using the supplied JWKS client.
func NewOIDCProviderWithJWKSClient(cfg OIDCConfig, httpClient *http.Client, jwksClient JWKSClient) (*OIDCProvider, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if err := validateOIDCConfig(cfg); err != nil {
		return nil, err
	}
	if jwksClient == nil {
		return nil, errors.New("jwks client is required")
	}

	jwksURI, err := discoverJWKSURI(context.Background(), httpClient, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	provider := &OIDCProvider{
		cfg:          normalizeOIDCConfig(cfg),
		providerType: ProviderTypeOIDC,
		jwksURI:      jwksURI,
		jwksClient:   jwksClient,
		now:          time.Now,
	}
	provider.claimsMapper = newDefaultClaimsMapper(provider.providerType, provider.cfg.RolesClaimPath)

	return provider, nil
}

func newOIDCProvider(cfg OIDCConfig, httpClient *http.Client, providerType ProviderType, mapper claimsMapper) (*OIDCProvider, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if err := validateOIDCConfig(cfg); err != nil {
		return nil, err
	}

	normalized := normalizeOIDCConfig(cfg)
	jwksURI, err := discoverJWKSURI(context.Background(), httpClient, normalized.IssuerURL)
	if err != nil {
		return nil, err
	}

	if mapper == nil {
		mapper = newDefaultClaimsMapper(providerType, normalized.RolesClaimPath)
	}

	provider := &OIDCProvider{
		cfg:          normalized,
		providerType: providerType,
		jwksURI:      jwksURI,
		jwksClient:   NewHTTPJWKSClient(httpClient, normalized.CacheTTL),
		claimsMapper: mapper,
		now:          time.Now,
	}

	return provider, nil
}

// VerifyToken validates an OIDC token and maps its claims to a UserContext.
func (p *OIDCProvider) VerifyToken(ctx context.Context, token string) (*UserContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token is required")
	}

	registered, rawClaims, err := p.verifySignedClaims(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := validateStandardClaims(registered, p.cfg.IssuerURL, p.cfg.Audience, p.now()); err != nil {
		return nil, err
	}
	if err := validateRequiredScopes(rawClaims, p.cfg.RequiredScopes); err != nil {
		return nil, err
	}

	userContext, err := p.claimsMapper(registered, rawClaims)
	if err != nil {
		return nil, err
	}
	if userContext.Subject == "" {
		return nil, errors.New("token missing subject claim")
	}

	return userContext, nil
}

func (p *OIDCProvider) verifySignedClaims(ctx context.Context, token string) (jwt.Claims, map[string]interface{}, error) {
	parsed, err := jwt.ParseSigned(token, supportedSignatureAlgorithms)
	if err != nil {
		return jwt.Claims{}, nil, fmt.Errorf("parse token: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return jwt.Claims{}, nil, errors.New("parse token: missing JOSE headers")
	}

	keySet, err := p.jwksClient.GetKeySet(ctx, p.jwksURI)
	if err != nil {
		return jwt.Claims{}, nil, err
	}

	candidateKeys := keySet.Keys
	if kid := parsed.Headers[0].KeyID; kid != "" {
		candidateKeys = keySet.Key(kid)
	}
	if len(candidateKeys) == 0 {
		return jwt.Claims{}, nil, errors.New("verify token: no matching JWK found")
	}

	var lastErr error
	for _, key := range candidateKeys {
		var registered jwt.Claims
		rawClaims := make(map[string]interface{})
		if err := parsed.Claims(key.Key, &registered, &rawClaims); err != nil {
			lastErr = err
			continue
		}
		return registered, rawClaims, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no candidate keys succeeded")
	}
	return jwt.Claims{}, nil, fmt.Errorf("verify token signature: %w", lastErr)
}

func validateOIDCConfig(cfg OIDCConfig) error {
	if strings.TrimSpace(cfg.IssuerURL) == "" {
		return errors.New("issuer URL is required")
	}
	if _, err := url.ParseRequestURI(cfg.IssuerURL); err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return errors.New("audience is required")
	}
	return nil
}

func normalizeOIDCConfig(cfg OIDCConfig) OIDCConfig {
	cfg.IssuerURL = strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.RolesClaimPath = strings.TrimSpace(cfg.RolesClaimPath)
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultJWKSCacheTTL
	}
	return cfg
}

func discoverJWKSURI(ctx context.Context, httpClient *http.Client, issuerURL string) (string, error) {
	discoveryURL := strings.TrimRight(strings.TrimSpace(issuerURL), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("create OIDC discovery request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch OIDC discovery document: unexpected status %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return "", errors.New("OIDC discovery document missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

func validateStandardClaims(claims jwt.Claims, issuerURL, audience string, now time.Time) error {
	if claims.Subject == "" {
		return errors.New("token missing subject claim")
	}
	if claims.IssuedAt == nil {
		return errors.New("token missing issued-at claim")
	}
	if claims.Expiry == nil {
		return errors.New("token missing expiry claim")
	}

	expected := jwt.Expected{
		Issuer:      issuerURL,
		AnyAudience: jwt.Audience{audience},
		Time:        now,
	}
	if err := claims.ValidateWithLeeway(expected, defaultValidationSkew); err != nil {
		return fmt.Errorf("validate token claims: %w", err)
	}

	return nil
}

func validateRequiredScopes(claims map[string]interface{}, required []string) error {
	if len(required) == 0 {
		return nil
	}

	available := make(map[string]struct{})
	for _, key := range []string{"scope", "scp"} {
		value, ok := claimByPath(claims, key)
		if !ok {
			continue
		}
		for _, scope := range normalizeDelimitedStrings(value) {
			available[scope] = struct{}{}
		}
	}
	if len(available) == 0 {
		return errors.New("token missing required scopes")
	}

	missing := make([]string, 0)
	for _, requiredScope := range required {
		requiredScope = strings.TrimSpace(requiredScope)
		if requiredScope == "" {
			continue
		}
		if _, ok := available[requiredScope]; !ok {
			missing = append(missing, requiredScope)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("token missing required scopes: %s", strings.Join(missing, ", "))
	}

	return nil
}

func newDefaultClaimsMapper(providerType ProviderType, rolesClaimPath string) claimsMapper {
	return func(registered jwt.Claims, raw map[string]interface{}) (*UserContext, error) {
		return &UserContext{
			Subject:  registered.Subject,
			Email:    firstNonEmptyString(raw, "email"),
			Name:     firstNonEmptyString(raw, "name", "preferred_username"),
			Roles:    uniqueStrings(stringsFromClaim(raw, rolesClaimPath)),
			TenantID: firstNonEmptyString(raw, "tenant_id", "tid"),
			Provider: string(providerType),
			Claims:   raw,
		}, nil
	}
}

func firstNonEmptyString(claims map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		if value, ok := claimByPath(claims, path); ok {
			if normalized := stringFromClaim(value); normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func stringsFromClaim(claims map[string]interface{}, path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	value, ok := claimByPath(claims, path)
	if !ok {
		return nil
	}
	return normalizeDelimitedStrings(value)
}

func claimByPath(claims map[string]interface{}, path string) (interface{}, bool) {
	if claims == nil || strings.TrimSpace(path) == "" {
		return nil, false
	}
	if value, ok := claims[path]; ok {
		return value, true
	}

	current := interface{}(claims)
	for _, part := range strings.Split(path, ".") {
		asMap, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, ok := asMap[part]
		if !ok {
			return nil, false
		}
		current = value
	}

	return current, true
}

func stringFromClaim(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func normalizeDelimitedStrings(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return splitStringValues(typed)
	case []string:
		return uniqueStrings(typed)
	case []interface{}:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := stringFromClaim(item); normalized != "" {
				items = append(items, normalized)
			}
		}
		return uniqueStrings(items)
	default:
		normalized := stringFromClaim(typed)
		if normalized == "" {
			return nil
		}
		return []string{normalized}
	}
}

func splitStringValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == ','
	})
	return uniqueStrings(fields)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

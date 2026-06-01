// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// JWT PDP mode for IdP-issued capability claims (T-02: --jwks-uri).
//
// When --jwks-uri is set the proxy validates the Authorization: Bearer token
// on every incoming HTTP request and extracts MCP capability claims.  The
// claims are translated into capability.Constraint values and evaluated by the
// enforcement engine on each tools/call.
//
// Claim schema (Keycloak and most IdPs nest on dots in claim names):
//
//	{
//	  "mcp": {
//	    "v":             "0.1",
//	    "capabilities": ["read_file:/reports/*", "query_db:SELECT"],
//	    "task_id":       "task-abc123",
//	    "agent_id":      "agent-xyz"
//	  }
//	}
//
// Claim shorthand format:  "<tool>[:<condition>]"
//
//	"read_file"             → allow read_file, no extra conditions
//	"read_file:/reports/*"  → allow read_file with AllowedValues path=/reports/*
//	"query_db:SELECT"       → allow query_db with AllowedOperations=[SELECT]
//
// When both --jwks-uri and --policy are provided, the intersection is taken:
// the JWT claims can only narrow (restrict) what the manifest already allows,
// never expand it.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// jwtClaimsKey is the unexported context key type for JWT claims.
type jwtClaimsKey struct{}

// JWTClaims holds the MCP capability claims extracted from an IdP JWT.
type JWTClaims struct {
	Capabilities []string
	TaskID       string
	AgentID      string
	Subject      string
	Issuer       string
}

// withJWTClaims returns a child context carrying the given JWT claims.
func withJWTClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, jwtClaimsKey{}, claims)
}

// jwtClaimsFromContext retrieves JWT claims from the context.
func jwtClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	c, ok := ctx.Value(jwtClaimsKey{}).(*JWTClaims)
	return c, ok && c != nil
}

// mcpClaimVersion is the only accepted value for the "v" field in the mcp
// claim set.  Tokens carrying an unrecognised version are rejected so that
// future breaking changes to the claim schema are caught early rather than
// silently misinterpreted.
const mcpClaimVersion = "0.1"

// mcpClaimSet holds the MCP-specific fields nested under the "mcp" key.
// Keycloak's oidc-hardcoded-claim-mapper (and most IdPs) treat dots in a
// claim.name as path separators, so "mcp.capabilities" is emitted as:
//
//	{"mcp": {"v": "0.1", "capabilities": [...], "task_id": "...", "agent_id": "..."}}
//
// rather than as a flat key with a literal dot.
type mcpClaimSet struct {
	Version      string   `json:"v"`
	Capabilities []string `json:"capabilities"`
	TaskID       string   `json:"task_id"`
	AgentID      string   `json:"agent_id"`
}

// idpJWTPayload is the subset of IdP JWT claims relevant to MCP enforcement.
// Standard JWT fields (iss, sub, exp, iat, aud) are parsed separately by
// jwt.Claims; this struct handles only the MCP-specific custom claims.
type idpJWTPayload struct {
	MCP mcpClaimSet `json:"mcp"`
}

// jwksAlgorithmsIDP lists the algorithms accepted for IdP JWTs.
// Mirrors capability.jwksAlgorithms — symmetric algorithms are intentionally excluded.
var jwksAlgorithmsIDP = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// jwksCache fetches and caches a JWKS from a remote URI.
// Concurrent refresh calls are deduplicated: only one HTTP round-trip is in
// flight at any time; other callers receive the same result when it lands.
type jwksCache struct {
	uri      string
	cacheTTL time.Duration
	client   *http.Client

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time

	sfMu    sync.Mutex
	sfDone  chan struct{}
	sfErr   error
	sfJWKS  *jose.JSONWebKeySet
}

func newJWKSCache(uri string, cacheTTL time.Duration, client *http.Client) *jwksCache {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{uri: uri, cacheTTL: cacheTTL, client: client}
}

// getKeys returns the cached JWKS or fetches a fresh copy.
func (c *jwksCache) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.jwks != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		keys := c.jwks
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()
	return c.refresh(ctx)
}

// refresh fetches a fresh JWKS, respecting the cache TTL.
// If the cached JWKS is still within TTL the cached copy is returned
// immediately without an HTTP fetch.
func (c *jwksCache) refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return c.doRefresh(ctx, false)
}

// forceRefresh always performs an HTTP fetch regardless of the cache TTL.
// Used when a kid was not found in the cached JWKS (key rotation case).
func (c *jwksCache) forceRefresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return c.doRefresh(ctx, true)
}

// doRefresh is the shared implementation for refresh and forceRefresh.
// When force is false it respects the TTL; when true it always fetches.
func (c *jwksCache) doRefresh(ctx context.Context, force bool) (*jose.JSONWebKeySet, error) {
	if !force {
		// Double-check under read lock before joining/starting a fetch.
		c.mu.RLock()
		if c.jwks != nil && time.Since(c.fetchedAt) < c.cacheTTL {
			keys := c.jwks
			c.mu.RUnlock()
			return keys, nil
		}
		c.mu.RUnlock()
	}

	c.sfMu.Lock()
	if c.sfDone != nil {
		// A fetch is already in flight — wait for it.
		done := c.sfDone
		c.sfMu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c.sfMu.Lock()
		jwks, err := c.sfJWKS, c.sfErr
		c.sfMu.Unlock()
		return jwks, err
	}

	// We are the leader; start the fetch.
	done := make(chan struct{})
	c.sfDone = done
	c.sfMu.Unlock()

	jwks, err := c.fetch(ctx)

	c.sfMu.Lock()
	c.sfJWKS = jwks
	c.sfErr = err
	c.sfDone = nil
	close(done)
	c.sfMu.Unlock()

	if err == nil {
		c.mu.Lock()
		c.jwks = jwks
		c.fetchedAt = time.Now()
		c.mu.Unlock()
	}
	return jwks, err
}

func (c *jwksCache) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS body: %w", err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}
	return &jwks, nil
}

// JWTPDP validates IdP-issued JWTs and enforces capability claims.
//
// When inner is non-nil (i.e. --policy is also set), the JWTPDP computes the
// intersection: a tool call is allowed only if both the JWT claims and the
// manifest policy allow it.
type JWTPDP struct {
	cache    *jwksCache
	issuer   string
	audience string
	inner    PolicyDecisionPoint // optional manifest PDP for intersection
}

// JWTPDPOptions configures a JWTPDP.
type JWTPDPOptions struct {
	JWKSURI  string
	Issuer   string
	Audience string
	// Inner is the manifest PDP used for intersection when both --jwks-uri and
	// --policy are configured.  When nil, only JWT claims are enforced.
	Inner    PolicyDecisionPoint
	CacheTTL time.Duration
	Client   *http.Client
}

// NewJWTPDP creates a JWTPDP ready to validate tokens.
func NewJWTPDP(opts JWTPDPOptions) *JWTPDP {
	return &JWTPDP{
		cache:    newJWKSCache(opts.JWKSURI, opts.CacheTTL, opts.Client),
		issuer:   opts.Issuer,
		audience: opts.Audience,
		inner:    opts.Inner,
	}
}

// ValidateToken validates the Authorization: Bearer token in the request,
// extracts eunox claims, and returns a new context carrying the claims.
// On failure it returns an error whose message is safe to surface as HTTP 401.
func (p *JWTPDP) ValidateToken(ctx context.Context, authHeader string) (context.Context, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ctx, fmt.Errorf("missing or malformed Authorization header")
	}
	tokenStr := authHeader[len(prefix):]

	tok, err := jwt.ParseSigned(tokenStr, jwksAlgorithmsIDP)
	if err != nil {
		return ctx, fmt.Errorf("invalid JWT: %w", err)
	}

	if len(tok.Headers) == 0 {
		return ctx, fmt.Errorf("JWT has no headers")
	}
	kid := tok.Headers[0].KeyID

	keys, err := p.cache.getKeys(ctx)
	if err != nil {
		return ctx, fmt.Errorf("fetching JWKS: %w", err)
	}

	matchingKeys := findJWKS(keys, kid)
	if len(matchingKeys) == 0 {
		// Key not in cache — force a fresh JWKS fetch in case the IdP rotated keys.
		keys, err = p.cache.forceRefresh(ctx)
		if err != nil {
			return ctx, fmt.Errorf("refreshing JWKS: %w", err)
		}
		matchingKeys = findJWKS(keys, kid)
		if len(matchingKeys) == 0 {
			return ctx, fmt.Errorf("no matching key for kid %q", kid)
		}
	}

	var lastErr error
	for i := range matchingKeys {
		var stdClaims jwt.Claims
		var payload idpJWTPayload

		if err := tok.Claims(&matchingKeys[i], &stdClaims, &payload); err != nil {
			lastErr = err
			continue
		}

		// Standard claim validation.
		expected := jwt.Expected{Time: time.Now()}
		if p.audience != "" {
			expected.AnyAudience = []string{p.audience}
		}
		if err := stdClaims.ValidateWithLeeway(expected, time.Minute); err != nil {
			return ctx, fmt.Errorf("token claims invalid: %w", err)
		}
		if p.issuer != "" && stdClaims.Issuer != p.issuer {
			return ctx, fmt.Errorf("token issuer %q does not match expected %q", stdClaims.Issuer, p.issuer)
		}

		if payload.MCP.Version != mcpClaimVersion {
			return ctx, fmt.Errorf("unsupported mcp claim version %q (want %q)", payload.MCP.Version, mcpClaimVersion)
		}
		claims := &JWTClaims{
			Capabilities: payload.MCP.Capabilities,
			TaskID:       payload.MCP.TaskID,
			AgentID:      payload.MCP.AgentID,
			Subject:      stdClaims.Subject,
			Issuer:       stdClaims.Issuer,
		}
		return withJWTClaims(ctx, claims), nil
	}
	return ctx, fmt.Errorf("JWT signature verification failed: %w", lastErr)
}

// Decide implements PolicyDecisionPoint.
//
// It reads JWT claims from the context (populated by ValidateToken at the HTTP
// layer), builds constraints from the capability strings, and evaluates them.
// When inner is set, the decision is the AND of both PDPs (intersection).
func (p *JWTPDP) Decide(ctx context.Context, sessionID, toolName string, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		return denyResponse("NO_JWT_CLAIMS", "jwtPDP", "no JWT claims in context — token was not validated")
	}

	// Build constraints from the capability claims in the JWT.
	constraints := buildConstraintsFromClaims(claims.Capabilities, toolName)
	if constraints == nil {
		// No claim covers this tool — deny.
		return denyResponse("CAPABILITY_NOT_GRANTED", "jwtCapability",
			fmt.Sprintf("tool %q is not in the JWT capability claims", toolName))
	}

	// Evaluate the matching constraint's conditions directly.
	// Since we built the constraint to match exactly this tool, we can evaluate
	// conditions immediately without a full enforcement engine pass.
	matched := constraints[0]
	if len(matched.Conditions) > 0 {
		if resp := evaluateJWTConditions(matched.Conditions, toolName, args); resp != nil {
			return *resp
		}
	}

	// JWT allows the call — now check the inner (manifest) PDP if configured.
	if p.inner != nil {
		return p.inner.Decide(ctx, sessionID, toolName, args, sourceIP)
	}

	return capability.EnforceResponse{Decision: capability.DecisionAllow}
}

// buildConstraintsFromClaims finds the capability claim matching toolName and
// returns a single-element slice containing the parsed constraint.
// Returns nil if no claim covers toolName.
func buildConstraintsFromClaims(caps []string, toolName string) []capability.Constraint {
	for _, claim := range caps {
		tool, cond := parseCapabilityClaim(claim)
		if tool != toolName {
			continue
		}
		c := buildConstraint(tool, cond)
		return []capability.Constraint{c}
	}
	return nil
}

// parseCapabilityClaim splits "tool:condition" into its two parts.
// Claims without a colon return tool=claim, cond="".
func parseCapabilityClaim(claim string) (tool, cond string) {
	idx := strings.IndexByte(claim, ':')
	if idx < 0 {
		return claim, ""
	}
	return claim[:idx], claim[idx+1:]
}

// buildConstraint converts a parsed claim into a capability.Constraint.
//
// Claim condition syntax:
//
//   - No condition             → plain allow (no conditions)
//   - "VERB:argname"           → AllowedOperationsCondition on argument argname
//     (e.g. "SELECT:query" checks the "query" argument for the SELECT verb)
//   - "/path/glob"             → AllowedValuesCondition on argument "path"
//   - "argname=value"          → AllowedValuesCondition on the named argument
//
// The argument name is always explicit — there is no heuristic guessing.
func buildConstraint(toolName, cond string) capability.Constraint {
	c := capability.Constraint{
		Resource: toolName,
		Actions:  []string{"call"},
	}
	if cond == "" {
		return c
	}

	// "VERB:argname" — AllowedOperationsCondition with explicit argument.
	if idx := strings.IndexByte(cond, ':'); idx > 0 {
		verb := cond[:idx]
		arg := cond[idx+1:]
		if isSQLVerb(verb) && arg != "" {
			c.Conditions = []capability.Condition{
				capability.AllowedOperationsCondition{
					Argument:   arg,
					Operations: []string{verb},
				},
			}
			return c
		}
	}

	// "argname=value" — AllowedValuesCondition on a named argument.
	if idx := strings.IndexByte(cond, '='); idx > 0 {
		arg := cond[:idx]
		val := cond[idx+1:]
		c.Conditions = []capability.Condition{
			capability.AllowedValuesCondition{Argument: arg, Values: []interface{}{val}},
		}
		return c
	}

	// Bare path glob (legacy shorthand): defaults to argument="path".
	c.Conditions = []capability.Condition{
		capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{cond}},
	}
	return c
}

// sqlVerbs is the set of SQL statement verbs recognised by the claim parser.
var sqlVerbs = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"DROP": true, "CREATE": true, "ALTER": true, "TRUNCATE": true,
	"MERGE": true, "UPSERT": true, "REPLACE": true,
}

func isSQLVerb(s string) bool {
	return sqlVerbs[strings.ToUpper(s)] && s == strings.ToUpper(s)
}

// evaluateJWTConditions checks JWT-derived conditions against the tool call
// arguments.  Returns a non-nil denial response if any condition fails.
func evaluateJWTConditions(conditions []capability.Condition, toolName string, args map[string]interface{}) *capability.EnforceResponse {
	for _, cond := range conditions {
		switch c := cond.(type) {
		case capability.AllowedOperationsCondition:
			if c.Argument == "" {
				resp := denyResponse(capability.ErrCodeConditionFailed, capability.ConditionTypeAllowedOperations,
					"allowedOperations condition requires an explicit 'argument' field")
				return &resp
			}
			var op string
			if v, ok := args[c.Argument]; ok {
				if s, ok := v.(string); ok {
					if parts := strings.Fields(s); len(parts) > 0 {
						op = strings.ToUpper(parts[0])
					}
				}
			}
			if op == "" {
				resp := denyResponse(capability.ErrCodeMissingContext, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("tool %q: argument %q is missing or empty", toolName, c.Argument))
				return &resp
			}
			if !containsStringFold(c.Operations, op) {
				resp := denyResponse("OPERATION_NOT_PERMITTED", capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("tool %q: operation %q is not in the permitted set %v", toolName, op, c.Operations))
				return &resp
			}
		case capability.AllowedValuesCondition:
			val, _ := args[c.Argument].(string)
			if !matchesAllowedValues(val, c.Values) {
				resp := denyResponse("VALUE_NOT_PERMITTED", capability.ConditionTypeAllowedValues,
					fmt.Sprintf("tool %q: argument %q value %q is not permitted", toolName, c.Argument, val))
				return &resp
			}
		}
	}
	return nil
}

// matchesAllowedValues reports whether val matches any of the allowed values.
// Values may be exact strings or simple glob patterns (using path.Match semantics
// via matchResource which already handles glob matching).
func matchesAllowedValues(val string, values []interface{}) bool {
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if matchResource(s, val) {
			return true
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// containsStringFold reports whether ss contains s using case-insensitive comparison.
func containsStringFold(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func denyResponse(code, condType, message string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:          code,
			ConditionType: condType,
			Message:       message,
		},
	}
}

// findJWKS returns the keys matching kid from the JWKS.
// When kid is empty all keys are returned (single-key JWKS without kid headers).
func findJWKS(jwks *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if kid != "" {
		return jwks.Key(kid)
	}
	return jwks.Keys
}

// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package did provides W3C Decentralized Identifier (DID) resolution for did:web, did:ion, and did:key methods.
package did

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Resolver resolves a DID URI to its DID Document.
type Resolver interface {
	// Resolve fetches and parses the DID Document for the given DID URI.
	Resolve(ctx context.Context, did string) (*Document, error)
}

// Document represents a W3C DID Document.
type Document struct {
	Context            []string             `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// VerificationMethod represents a public key in a DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// JWK represents a JSON Web Key in a DID Document.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// PublicKeys extracts all public keys from verification methods in the document.
func (d *Document) PublicKeys() []crypto.PublicKey {
	var keys []crypto.PublicKey
	for i := range d.VerificationMethod {
		key, err := d.VerificationMethod[i].ExtractPublicKey()
		if err == nil && key != nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// CachingResolver wraps a Resolver with TTL-based caching.
//
// After a cache entry expires it is eligible for upstream refresh.  When
// StaleWindow is set (via [WithStaleWindow]), a recently-expired entry is
// served as a stale result if the upstream resolver returns an error.  This
// trades a short period of potential staleness for availability during
// transient upstream outages — appropriate for DID documents, which change
// infrequently.
type CachingResolver struct {
	inner       Resolver
	mu          sync.RWMutex
	cache       map[string]*cacheEntry
	ttl         time.Duration
	staleWindow time.Duration
	maxItems    int
	now         func() time.Time
}

type cacheEntry struct {
	doc       *Document
	fetchedAt time.Time
}

// CachingResolverOption configures a CachingResolver.
type CachingResolverOption func(*CachingResolver)

// WithCacheTTL sets the cache TTL.
func WithCacheTTL(ttl time.Duration) CachingResolverOption {
	return func(r *CachingResolver) {
		r.ttl = ttl
	}
}

// WithMaxCacheItems sets the maximum number of cached items.
func WithMaxCacheItems(maxItems int) CachingResolverOption {
	return func(r *CachingResolver) {
		r.maxItems = maxItems
	}
}

// WithStaleWindow sets the extra duration beyond the TTL during which a cached
// entry may be served as a stale result when the upstream resolver returns an
// error.  A zero value (the default) disables stale-on-error behaviour.
func WithStaleWindow(d time.Duration) CachingResolverOption {
	return func(r *CachingResolver) {
		r.staleWindow = d
	}
}

// WithTimeFunc sets a custom time function (for testing).
func WithTimeFunc(fn func() time.Time) CachingResolverOption {
	return func(r *CachingResolver) {
		r.now = fn
	}
}

// NewCachingResolver creates a caching wrapper around a resolver.
func NewCachingResolver(inner Resolver, opts ...CachingResolverOption) *CachingResolver {
	r := &CachingResolver{
		inner:    inner,
		cache:    make(map[string]*cacheEntry),
		ttl:      5 * time.Minute,
		maxItems: 1000,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve resolves a DID, using the cache if available and not expired.
//
// If the upstream resolver returns an error and a stale window has been
// configured (via [WithStaleWindow]), a recently-expired cache entry is
// returned instead of the error.  This improves availability during transient
// upstream outages without changing the API contract for callers.
func (r *CachingResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	r.mu.RLock()
	var staleEntry *cacheEntry
	if entry, ok := r.cache[did]; ok {
		age := r.now().Sub(entry.fetchedAt)
		if age < r.ttl {
			r.mu.RUnlock()
			return entry.doc, nil
		}
		// Entry is past TTL but might be within the stale window.
		if r.staleWindow > 0 && age < r.ttl+r.staleWindow {
			staleEntry = entry
		}
	}
	r.mu.RUnlock()

	doc, err := r.inner.Resolve(ctx, did)
	if err != nil {
		// Serve a stale entry rather than propagating the error when the
		// upstream is temporarily unavailable.
		if staleEntry != nil {
			return staleEntry.doc, nil
		}
		return nil, err
	}

	r.mu.Lock()
	// Evict expired entries if at capacity.
	if len(r.cache) >= r.maxItems {
		r.evictExpired()
	}
	// If still at capacity after eviction, remove oldest entry.
	if len(r.cache) >= r.maxItems {
		r.evictOldest()
	}
	r.cache[did] = &cacheEntry{
		doc:       doc,
		fetchedAt: r.now(),
	}
	r.mu.Unlock()

	return doc, nil
}

// Invalidate removes a cached entry.
func (r *CachingResolver) Invalidate(did string) {
	r.mu.Lock()
	delete(r.cache, did)
	r.mu.Unlock()
}

// Len returns the number of cached entries (for testing).
func (r *CachingResolver) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

func (r *CachingResolver) evictExpired() {
	now := r.now()
	for key, entry := range r.cache {
		// Evict entries that have passed both the TTL and the stale window.
		if now.Sub(entry.fetchedAt) >= r.ttl+r.staleWindow {
			delete(r.cache, key)
		}
	}
}

func (r *CachingResolver) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, entry := range r.cache {
		if first || entry.fetchedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.fetchedAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(r.cache, oldestKey)
	}
}

// MultiResolver tries multiple DID method resolvers based on the DID method prefix.
type MultiResolver struct {
	resolvers map[string]Resolver
}

// NewMultiResolver creates a resolver that delegates to method-specific resolvers.
func NewMultiResolver(resolvers map[string]Resolver) *MultiResolver {
	return &MultiResolver{resolvers: resolvers}
}

// Resolve resolves a DID by delegating to the appropriate method-specific resolver.
func (m *MultiResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	method, err := ParseMethod(did)
	if err != nil {
		return nil, err
	}

	resolver, ok := m.resolvers[method]
	if !ok {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}

	return resolver.Resolve(ctx, did)
}

// ParseMethod extracts the DID method from a DID URI (e.g., "web" from "did:web:example.com").
func ParseMethod(did string) (string, error) {
	if len(did) < 5 || did[:4] != "did:" {
		return "", errors.New("invalid DID: must start with 'did:'")
	}

	rest := did[4:]
	for i, ch := range rest {
		if ch == ':' {
			if i == 0 {
				return "", errors.New("invalid DID: empty method")
			}
			return rest[:i], nil
		}
	}
	return "", errors.New("invalid DID: missing method-specific identifier")
}

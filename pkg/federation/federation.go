// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package federation provides cross-organization trust via W3C DIDs with circuit-breaker resilience.
package federation

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/did"
)

// Errors used by the federation package.
var (
	ErrPartnerNotFound    = errors.New("partner DID not found")
	ErrPartnerNotApproved = errors.New("partner DID not approved")
	ErrCircuitOpen        = errors.New("circuit breaker is open: partner DID resolution rejected")
	ErrNoPublicKey        = errors.New("no public key found in DID document")
)

// PartnerDIDEntry represents a trusted partner in the registry.
type PartnerDIDEntry struct {
	DID          string    `json:"did"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Status       string    `json:"status"`
	RegisteredAt time.Time `json:"registeredAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// PartnerDIDRegistry manages trusted partner DIDs.
type PartnerDIDRegistry struct {
	mu       sync.RWMutex
	partners map[string]*PartnerDIDEntry
	now      func() time.Time
}

// NewPartnerDIDRegistry creates a new registry of trusted partner DIDs.
func NewPartnerDIDRegistry() *PartnerDIDRegistry {
	return &PartnerDIDRegistry{
		partners: make(map[string]*PartnerDIDEntry),
		now:      time.Now,
	}
}

// Register adds a trusted partner DID to the registry.
func (r *PartnerDIDRegistry) Register(didURI, name, description string) error {
	if didURI == "" {
		return errors.New("DID URI is required")
	}
	if name == "" {
		return errors.New("name is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.partners[didURI] = &PartnerDIDEntry{
		DID:          didURI,
		Name:         name,
		Description:  description,
		Status:       "pending",
		RegisteredAt: now,
		UpdatedAt:    now,
	}
	return nil
}

// Approve sets a partner DID's status to "approved".
func (r *PartnerDIDRegistry) Approve(didURI string) error {
	return r.setStatus(didURI, "approved")
}

// Revoke sets a partner DID's status to "revoked".
func (r *PartnerDIDRegistry) Revoke(didURI string) error {
	return r.setStatus(didURI, "revoked")
}

// Unregister removes a partner DID from the registry.
func (r *PartnerDIDRegistry) Unregister(didURI string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.partners[didURI]; !ok {
		return fmt.Errorf("%w: %s", ErrPartnerNotFound, didURI)
	}
	delete(r.partners, didURI)
	return nil
}

// Get retrieves a partner entry.
func (r *PartnerDIDRegistry) Get(didURI string) (*PartnerDIDEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.partners[didURI]
	if !ok {
		return nil, false
	}
	clone := *p
	return &clone, true
}

// List returns all registered partner DIDs.
func (r *PartnerDIDRegistry) List() []PartnerDIDEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PartnerDIDEntry, 0, len(r.partners))
	for _, p := range r.partners {
		result = append(result, *p)
	}
	return result
}

// IsApproved checks whether a DID is registered and approved.
func (r *PartnerDIDRegistry) IsApproved(didURI string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.partners[didURI]
	return ok && p.Status == "approved"
}

func (r *PartnerDIDRegistry) setStatus(didURI, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.partners[didURI]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPartnerNotFound, didURI)
	}
	p.Status = status
	p.UpdatedAt = r.now()
	return nil
}

// PartnerIssuerResolver resolves partner DID URIs to their public keys,
// enforcing circuit breaker policies per DID method.
type PartnerIssuerResolver struct {
	registry *PartnerDIDRegistry
	resolver did.Resolver
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
	config   CircuitBreakerConfig
	metrics  *Metrics
	now      func() time.Time
}

// PartnerIssuerResolverConfig configures the PartnerIssuerResolver.
type PartnerIssuerResolverConfig struct {
	Registry       *PartnerDIDRegistry
	Resolver       did.Resolver
	CircuitBreaker CircuitBreakerConfig
	// Metrics optionally instruments the resolver with Prometheus metrics.
	// If nil, no metrics are emitted.
	Metrics *Metrics
}

// NewPartnerIssuerResolver creates a new partner issuer resolver.
func NewPartnerIssuerResolver(cfg PartnerIssuerResolverConfig) *PartnerIssuerResolver {
	if cfg.CircuitBreaker.FailureThreshold == 0 {
		cfg.CircuitBreaker.FailureThreshold = 5
	}
	if cfg.CircuitBreaker.CooldownDuration == 0 {
		cfg.CircuitBreaker.CooldownDuration = 30 * time.Second
	}
	if cfg.CircuitBreaker.HalfOpenMaxProbes == 0 {
		cfg.CircuitBreaker.HalfOpenMaxProbes = 1
	}

	return &PartnerIssuerResolver{
		registry: cfg.Registry,
		resolver: cfg.Resolver,
		breakers: make(map[string]*CircuitBreaker),
		config:   cfg.CircuitBreaker,
		metrics:  cfg.Metrics,
		now:      time.Now,
	}
}

// ResolvePublicKeys resolves a partner DID to its public keys.
// It checks the registry, circuit breaker, and performs DID resolution.
// Metrics are emitted for each resolution attempt when a Metrics instance is configured.
func (p *PartnerIssuerResolver) ResolvePublicKeys(ctx context.Context, didURI string) ([]crypto.PublicKey, error) {
	if !p.registry.IsApproved(didURI) {
		entry, found := p.registry.Get(didURI)
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrPartnerNotFound, didURI)
		}
		return nil, fmt.Errorf("%w: %s (status: %s)", ErrPartnerNotApproved, didURI, entry.Status)
	}

	// Get or create circuit breaker for this DID method.
	method, err := did.ParseMethod(didURI)
	if err != nil {
		return nil, err
	}

	cb := p.getOrCreateBreaker(method)

	// Check if circuit is open.
	if !cb.Allow() {
		if p.metrics != nil {
			p.metrics.RecordResolution(method, "circuit_open", 0)
		}
		p.emitCircuitBreakerMetrics()
		return nil, fmt.Errorf("%w (method: %s)", ErrCircuitOpen, method)
	}

	// Resolve the DID document, recording duration.
	start := p.now()
	doc, err := p.resolver.Resolve(ctx, didURI)
	durationSec := p.now().Sub(start).Seconds()

	if err != nil {
		cb.RecordFailure()
		if p.metrics != nil {
			p.metrics.RecordResolution(method, "error", durationSec)
		}
		p.emitCircuitBreakerMetrics()
		return nil, fmt.Errorf("resolve partner DID: %w", err)
	}

	keys := doc.PublicKeys()
	if len(keys) == 0 {
		cb.RecordFailure()
		if p.metrics != nil {
			p.metrics.RecordResolution(method, "no_key", durationSec)
		}
		p.emitCircuitBreakerMetrics()
		return nil, fmt.Errorf("%w: %s", ErrNoPublicKey, didURI)
	}

	cb.RecordSuccess()
	if p.metrics != nil {
		p.metrics.RecordResolution(method, "success", durationSec)
	}
	p.emitCircuitBreakerMetrics()
	return keys, nil
}

// emitCircuitBreakerMetrics publishes the current circuit breaker states as Prometheus gauges.
func (p *PartnerIssuerResolver) emitCircuitBreakerMetrics() {
	if p.metrics == nil {
		return
	}
	p.metrics.UpdateCircuitBreakerMetrics(p.GetCircuitBreakerStates())
}

// GetCircuitBreakerStates returns the current state of all circuit breakers.
func (p *PartnerIssuerResolver) GetCircuitBreakerStates() map[string]CircuitBreakerState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	states := make(map[string]CircuitBreakerState, len(p.breakers))
	for method, cb := range p.breakers {
		states[method] = cb.State()
	}
	return states
}

func (p *PartnerIssuerResolver) getOrCreateBreaker(method string) *CircuitBreaker {
	p.mu.RLock()
	cb, ok := p.breakers[method]
	p.mu.RUnlock()
	if ok {
		return cb
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock.
	if cb, ok = p.breakers[method]; ok {
		return cb
	}

	cb = NewCircuitBreaker(p.config)
	p.breakers[method] = cb
	return cb
}

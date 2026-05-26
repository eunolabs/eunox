// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package redisfailover provides failure mode policies for Redis-dependent
// components. It defines fail-open and fail-closed behaviors, implements
// local fallback caches with TTL, and tracks Redis health state for
// readiness probe degradation.
//
// Failure mode policies per component (DI-2):
//   - Kill switch: fail-closed (block if Redis state is unknown)
//   - Revocation: fail-closed (treat token as revoked if lookup fails)
//   - Rate limiter: fail-open with in-memory fallback
//   - Call counter: fail-open (degrade gracefully, allow requests)
package redisfailover

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Policy defines the failure mode for a Redis-dependent component.
type Policy int

const (
	// FailClosed denies requests when Redis is unreachable. Use for
	// security-critical paths (kill switch, revocation) where allowing
	// access to unknown state could be dangerous.
	FailClosed Policy = iota

	// FailOpen allows requests when Redis is unreachable. Use for
	// non-security-critical paths (rate limiting, call counting) where
	// temporary over-provisioning is preferable to total denial of service.
	FailOpen
)

// String returns the policy name.
func (p Policy) String() string {
	switch p {
	case FailClosed:
		return "fail-closed"
	case FailOpen:
		return "fail-open"
	default:
		return "unknown"
	}
}

// HealthState represents the current Redis connectivity state.
type HealthState int32

const (
	// Healthy means Redis is reachable and responding.
	Healthy HealthState = iota
	// Degraded means Redis is unreachable; the component is operating from
	// local fallback cache or applying its failure policy.
	Degraded
)

// String returns the health state name.
func (s HealthState) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Degraded:
		return "degraded"
	default:
		return "unknown"
	}
}

// Monitor tracks Redis health state and provides degradation signals for
// readiness probes. Multiple components can register with a single Monitor.
type Monitor struct {
	mu         sync.RWMutex
	components map[string]*atomic.Int32
}

// NewMonitor creates a new Redis health monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		components: make(map[string]*atomic.Int32),
	}
}

// Register registers a component for health tracking. Returns a Reporter
// that the component uses to update its Redis health state.
func (m *Monitor) Register(name string) *Reporter {
	state := &atomic.Int32{}
	m.mu.Lock()
	m.components[name] = state
	m.mu.Unlock()
	return &Reporter{name: name, state: state}
}

// IsReady returns true if all registered components report healthy Redis
// connectivity. Returns false (503-worthy) if any component is degraded.
func (m *Monitor) IsReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, state := range m.components {
		if HealthState(state.Load()) == Degraded {
			return false
		}
	}
	return true
}

// DegradedComponents returns the names of components currently in degraded state.
func (m *Monitor) DegradedComponents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var degraded []string
	for name, state := range m.components {
		if HealthState(state.Load()) == Degraded {
			degraded = append(degraded, name)
		}
	}
	return degraded
}

// Reporter allows a component to report its Redis health state.
type Reporter struct {
	name  string
	state *atomic.Int32
}

// MarkHealthy marks the component's Redis connection as healthy.
func (r *Reporter) MarkHealthy() {
	r.state.Store(int32(Healthy))
}

// MarkDegraded marks the component's Redis connection as degraded.
func (r *Reporter) MarkDegraded() {
	r.state.Store(int32(Degraded))
}

// State returns the current health state.
func (r *Reporter) State() HealthState {
	return HealthState(r.state.Load())
}

// FallbackCache provides a time-bounded local cache for fail-closed
// components. It stores the last known state from Redis and serves it
// for a configurable grace period when Redis is unreachable.
type FallbackCache[K comparable, V any] struct {
	mu        sync.RWMutex
	entries   map[K]cacheEntry[V]
	staleTTL  time.Duration
	now       func() time.Time
	policy    Policy
	zeroValue V
}

type cacheEntry[V any] struct {
	value     V
	updatedAt time.Time
}

// FallbackCacheConfig configures a FallbackCache.
type FallbackCacheConfig[K comparable, V any] struct {
	// StaleTTL is how long cached entries remain valid after Redis becomes
	// unreachable. After this period, the failure policy takes effect.
	StaleTTL time.Duration

	// Policy is the failure mode when cache is stale or entry is missing.
	Policy Policy

	// DefaultValue is returned for fail-closed when the key is not cached.
	DefaultValue V
}

// NewFallbackCache creates a new local fallback cache.
func NewFallbackCache[K comparable, V any](cfg FallbackCacheConfig[K, V]) *FallbackCache[K, V] {
	staleTTL := cfg.StaleTTL
	if staleTTL <= 0 {
		staleTTL = 30 * time.Second
	}
	return &FallbackCache[K, V]{
		entries:   make(map[K]cacheEntry[V]),
		staleTTL:  staleTTL,
		now:       time.Now,
		policy:    cfg.Policy,
		zeroValue: cfg.DefaultValue,
	}
}

// Put stores or updates a value in the cache.
func (c *FallbackCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	c.entries[key] = cacheEntry[V]{value: value, updatedAt: c.now()}
	c.mu.Unlock()
}

// Get retrieves a value from the cache. Returns the value and true if the
// entry exists and is within the stale TTL. Returns the default value and
// false if the entry is expired or missing.
func (c *FallbackCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return c.zeroValue, false
	}

	if c.now().Sub(entry.updatedAt) > c.staleTTL {
		return c.zeroValue, false
	}

	return entry.value, true
}

// Delete removes an entry from the cache.
func (c *FallbackCache[K, V]) Delete(key K) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Len returns the number of entries currently in the cache.
func (c *FallbackCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Pinger tests Redis connectivity.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthChecker periodically pings Redis and updates a Reporter.
type HealthChecker struct {
	pinger   Pinger
	reporter *Reporter
	interval time.Duration
	cancel   context.CancelFunc
}

// NewHealthChecker creates a health checker that pings Redis at the given interval.
func NewHealthChecker(pinger Pinger, reporter *Reporter, interval time.Duration) *HealthChecker {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &HealthChecker{
		pinger:   pinger,
		reporter: reporter,
		interval: interval,
	}
}

// Start begins the periodic health check. Call Stop to terminate.
func (h *HealthChecker) Start(ctx context.Context) {
	checkCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel

	// Initial check
	h.check(checkCtx)

	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		for {
			select {
			case <-checkCtx.Done():
				return
			case <-ticker.C:
				h.check(checkCtx)
			}
		}
	}()
}

// Stop terminates the health checker.
func (h *HealthChecker) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
}

func (h *HealthChecker) check(ctx context.Context) {
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := h.pinger.Ping(pingCtx); err != nil {
		h.reporter.MarkDegraded()
	} else {
		h.reporter.MarkHealthy()
	}
}

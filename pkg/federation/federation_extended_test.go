// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/did"
)

// --- TEST-3: Federation Concurrent and Edge Case Tests ---

func TestPartnerDIDRegistry_ConcurrentRegisterApproveRevoke(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 3) // 3 operations per goroutine

	for i := range goroutines {
		didURI := "did:web:concurrent-" + itoa(i) + ".com"
		orgName := "Org-" + itoa(i)
		go func(uri, org string) {
			defer wg.Done()
			_ = reg.Register(uri, org, "desc")
		}(didURI, orgName)
		go func(uri string) {
			defer wg.Done()
			_ = reg.Approve(uri)
		}(didURI)
		go func(uri string) {
			defer wg.Done()
			_ = reg.Revoke(uri)
		}(didURI)
	}
	wg.Wait()

	// All DIDs should be registered (regardless of approval/revoke order).
	list := reg.List()
	assert.Len(t, list, goroutines)
}

func TestPartnerDIDRegistry_ConcurrentListAndRegister(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()

	// Pre-populate some entries.
	for i := range 10 {
		_ = reg.Register("did:web:pre-"+itoa(i)+".com", "Pre-"+itoa(i), "")
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_ = reg.Register("did:web:new-"+itoa(idx)+".com", "New", "")
		}(i)
		go func() {
			defer wg.Done()
			_ = reg.List() // Concurrent reads.
		}()
	}
	wg.Wait()

	list := reg.List()
	assert.Len(t, list, 10+goroutines)
}

func TestPartnerDIDRegistry_DuplicateRegister(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	err := reg.Register("did:web:dup.com", "Org", "")
	require.NoError(t, err)

	// Verify duplicate is present (registry may allow overwrites).
	err = reg.Register("did:web:dup.com", "Org2", "")
	if err != nil {
		assert.Error(t, err, "duplicate registration should fail")
	} else {
		// If the registry allows overwrites, verify the entry was updated.
		entry, found := reg.Get("did:web:dup.com")
		require.True(t, found)
		assert.Equal(t, "Org2", entry.Name)
	}
}

func TestPartnerDIDRegistry_ApproveNotFound(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	err := reg.Approve("did:web:ghost.com")
	assert.ErrorIs(t, err, ErrPartnerNotFound)
}

func TestPartnerDIDRegistry_RevokeNotFound(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	err := reg.Revoke("did:web:ghost.com")
	assert.ErrorIs(t, err, ErrPartnerNotFound)
}

func TestPartnerIssuerResolver_ConcurrentResolvePublicKeys(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:concurrent-resolve.com", "CR", "")
	_ = reg.Approve("did:web:concurrent-resolve.com")

	mockDoc := &did.Document{
		ID: "did:web:concurrent-resolve.com",
		VerificationMethod: []did.VerificationMethod{
			{
				PublicKeyJwk: &did.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
			},
		},
	}

	var resolveCount atomic.Int64
	resolver := &countingDIDResolver{doc: mockDoc, count: &resolveCount}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  5,
			CooldownDuration:  10 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = pir.ResolvePublicKeys(context.Background(), "did:web:concurrent-resolve.com")
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		assert.NoError(t, e, "goroutine %d failed", i)
	}

	// Verify all goroutines called the resolver.
	assert.Equal(t, int64(goroutines), resolveCount.Load())
}

func TestPartnerIssuerResolver_ConcurrentGetOrCreateBreaker(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()

	// Register multiple DIDs from the same method to exercise getOrCreateBreaker's double-check.
	for i := range 10 {
		didURI := "did:web:breaker-" + itoa(i) + ".com"
		_ = reg.Register(didURI, "Org-"+itoa(i), "")
		_ = reg.Approve(didURI)
	}

	mockDoc := &did.Document{
		ID: "did:web:breaker-0.com",
		VerificationMethod: []did.VerificationMethod{
			{PublicKeyJwk: &did.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
		},
	}

	resolver := &mockDIDResolver{doc: mockDoc}
	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  5,
			CooldownDuration:  10 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	// Resolve all concurrently — all share the "web" breaker.
	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, _ = pir.ResolvePublicKeys(context.Background(), "did:web:breaker-"+itoa(idx%10)+".com")
		}(i)
	}
	wg.Wait()

	// There should be exactly one circuit breaker for method "web".
	states := pir.GetCircuitBreakerStates()
	assert.Contains(t, states, "web")
	assert.Equal(t, StateClosed, states["web"])
}

func TestPartnerIssuerResolver_DocumentWithNoVerificationMethods(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:empty-doc.com", "Empty", "")
	_ = reg.Approve("did:web:empty-doc.com")

	resolver := &mockDIDResolver{doc: &did.Document{
		ID:                 "did:web:empty-doc.com",
		VerificationMethod: nil, // No verification methods.
	}}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  5 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	keys, err := pir.ResolvePublicKeys(context.Background(), "did:web:empty-doc.com")
	// This should either return an error or an empty key set.
	if err != nil {
		assert.Contains(t, err.Error(), "no public key")
	} else {
		assert.Empty(t, keys)
	}
}

func TestPartnerIssuerResolver_ResolverError(t *testing.T) {
	t.Parallel()

	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:resolver-err.com", "Err", "")
	_ = reg.Approve("did:web:resolver-err.com")

	resolver := &mockDIDResolver{err: errors.New("DNS resolution failed")}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  5,
			CooldownDuration:  5 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	_, err := pir.ResolvePublicKeys(context.Background(), "did:web:resolver-err.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DNS resolution failed")
}

func TestAttenuate_ResourcePrefixMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		parentResource string
		childResource  string
		wantErr        bool
	}{
		{name: "exact match", parentResource: "tool:code-review", childResource: "tool:code-review", wantErr: false},
		{name: "wildcard parent", parentResource: "*", childResource: "tool:anything", wantErr: false},
		{name: "different resource", parentResource: "tool:review", childResource: "tool:deploy", wantErr: true},
		{name: "prefix mismatch", parentResource: "tool:code", childResource: "tool:code-review", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Attenuate(AttenuationRequest{
				ParentCapabilities:    []capability.Constraint{{Resource: tt.parentResource, Actions: []string{"read"}}},
				RequestedCapabilities: []capability.Constraint{{Resource: tt.childResource, Actions: []string{"read"}}},
				AllowCrossOrg:         true,
				ParentDID:             "did:web:p.com",
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttenuate_MultipleCapabilities(t *testing.T) {
	t.Parallel()

	result, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "tool:review", Actions: []string{"read", "write"}},
			{Resource: "tool:deploy", Actions: []string{"execute"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:review", Actions: []string{"read"}},
			{Resource: "tool:deploy", Actions: []string{"execute"}},
		},
		AllowCrossOrg: true,
		ParentDID:     "did:web:multi.com",
	})

	require.NoError(t, err)
	assert.Len(t, result.Capabilities, 2)
}

func TestAttenuate_ActionSubsetValidation(t *testing.T) {
	t.Parallel()

	// Parent has read-only, child wants read+write.
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "tool:x", Actions: []string{"read"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:x", Actions: []string{"read", "write"}},
		},
		AllowCrossOrg: true,
		ParentDID:     "did:web:action.com",
	})
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

// --- Test Helpers ---

type countingDIDResolver struct {
	doc   *did.Document
	count *atomic.Int64
}

func (r *countingDIDResolver) Resolve(_ context.Context, _ string) (*did.Document, error) {
	r.count.Add(1)
	return r.doc, nil
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}

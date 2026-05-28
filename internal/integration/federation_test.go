// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/did"
	"github.com/eunolabs/eunox/pkg/federation"
)

// failingResolver always returns an error for DID resolution.
type failingResolver struct{}

func (f *failingResolver) Resolve(_ context.Context, _ string) (*did.Document, error) {
	return nil, errors.New("network failure")
}

// TestFederation_PartnerDIDLifecycle tests the full partner DID lifecycle:
// register → approve → resolve → revoke.
func TestFederation_PartnerDIDLifecycle(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()

	// Register a partner
	err := registry.Register("did:web:partner-a.example.com", "Partner A", "Primary integration partner")
	require.NoError(t, err)

	// Not approved yet
	assert.False(t, registry.IsApproved("did:web:partner-a.example.com"))

	// Approve
	err = registry.Approve("did:web:partner-a.example.com")
	require.NoError(t, err)
	assert.True(t, registry.IsApproved("did:web:partner-a.example.com"))

	// Can retrieve
	entry, ok := registry.Get("did:web:partner-a.example.com")
	require.True(t, ok)
	assert.Equal(t, "Partner A", entry.Name)
	assert.Equal(t, "Primary integration partner", entry.Description)

	// Revoke
	err = registry.Revoke("did:web:partner-a.example.com")
	require.NoError(t, err)
	assert.False(t, registry.IsApproved("did:web:partner-a.example.com"))
}

// TestFederation_MultiplePartners verifies that multiple partners can coexist independently.
func TestFederation_MultiplePartners(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()

	partners := []struct {
		did  string
		name string
	}{
		{"did:web:partner-a.example.com", "Partner A"},
		{"did:web:partner-b.example.com", "Partner B"},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "DID Key Partner"},
	}

	for _, p := range partners {
		require.NoError(t, registry.Register(p.did, p.name, ""))
		require.NoError(t, registry.Approve(p.did))
	}

	list := registry.List()
	assert.Len(t, list, 3)

	// All approved
	for _, p := range partners {
		assert.True(t, registry.IsApproved(p.did))
	}

	// Revoking one doesn't affect others
	require.NoError(t, registry.Revoke("did:web:partner-b.example.com"))
	assert.True(t, registry.IsApproved("did:web:partner-a.example.com"))
	assert.False(t, registry.IsApproved("did:web:partner-b.example.com"))
	assert.True(t, registry.IsApproved("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"))
}

// TestFederation_DuplicateRegistration verifies duplicate registration overwrites (upsert behavior).
func TestFederation_DuplicateRegistration(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()

	err := registry.Register("did:web:dup.example.com", "First", "first desc")
	require.NoError(t, err)

	// Second registration overwrites (upsert semantics)
	err = registry.Register("did:web:dup.example.com", "Second", "second desc")
	require.NoError(t, err)

	entry, ok := registry.Get("did:web:dup.example.com")
	require.True(t, ok)
	assert.Equal(t, "Second", entry.Name)
	assert.Equal(t, "second desc", entry.Description)
}

// TestFederation_UnregisterPartner verifies unregistration removes the partner entirely.
func TestFederation_UnregisterPartner(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()

	require.NoError(t, registry.Register("did:web:remove.me", "RemoveMe", ""))
	require.NoError(t, registry.Approve("did:web:remove.me"))
	assert.True(t, registry.IsApproved("did:web:remove.me"))

	// Unregister
	require.NoError(t, registry.Unregister("did:web:remove.me"))
	assert.False(t, registry.IsApproved("did:web:remove.me"))
	_, ok := registry.Get("did:web:remove.me")
	assert.False(t, ok)
}

// TestFederation_CircuitBreakerStates verifies circuit breaker states are tracked per DID method.
func TestFederation_CircuitBreakerStates(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()
	// Register and approve a DID so resolution proceeds past the approval check
	require.NoError(t, registry.Register("did:web:failing.example.com", "Failing", ""))
	require.NoError(t, registry.Approve("did:web:failing.example.com"))

	resolver := federation.NewPartnerIssuerResolver(federation.PartnerIssuerResolverConfig{
		Registry: registry,
		Resolver: &failingResolver{},
		CircuitBreaker: federation.CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  0,
			HalfOpenMaxProbes: 1,
		},
	})

	states := resolver.GetCircuitBreakerStates()
	// Initially empty (no methods tried yet)
	assert.Empty(t, states)

	// Trigger resolution failure to create a circuit breaker
	ctx := context.Background()
	_, err := resolver.ResolvePublicKeys(ctx, "did:web:failing.example.com")
	assert.Error(t, err)

	// Now there should be a circuit breaker for "web" method
	states = resolver.GetCircuitBreakerStates()
	assert.Contains(t, states, "web")
}

// TestFederation_ApproveUnknownDID verifies approving unknown DID returns error.
func TestFederation_ApproveUnknownDID(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()
	err := registry.Approve("did:web:unknown.example.com")
	assert.Error(t, err)
}

// TestFederation_RevokeUnknownDID verifies revoking unknown DID returns error.
func TestFederation_RevokeUnknownDID(t *testing.T) {
	registry := federation.NewPartnerDIDRegistry()
	err := registry.Revoke("did:web:unknown.example.com")
	assert.Error(t, err)
}

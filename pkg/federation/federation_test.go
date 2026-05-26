// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/did"
)

// --- Circuit Breaker Tests ---

func TestCircuitBreaker_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	})

	assert.Equal(t, StateClosed, cb.State())
	assert.True(t, cb.Allow())

	// Record successes: stays closed.
	cb.RecordSuccess()
	cb.RecordSuccess()
	assert.Equal(t, StateClosed, cb.State())
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, StateClosed, cb.State())
	assert.True(t, cb.Allow())

	cb.RecordFailure() // Threshold reached.
	assert.Equal(t, StateOpen, cb.State())
	assert.False(t, cb.Allow()) // Blocked.
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	})
	cb.now = func() time.Time { return now }

	// Trip the breaker.
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Advance past cooldown.
	now = now.Add(6 * time.Second)
	assert.True(t, cb.Allow()) // Transitions to half-open.

	// In half-open, only 1 probe allowed.
	assert.False(t, cb.Allow())
}

func TestCircuitBreaker_HalfOpenRecovery(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	})
	cb.now = func() time.Time { return now }

	// Trip.
	cb.RecordFailure()
	cb.RecordFailure()

	// Advance past cooldown and allow probe.
	now = now.Add(6 * time.Second)
	assert.True(t, cb.Allow())

	// Success in half-open closes the breaker.
	cb.RecordSuccess()
	assert.Equal(t, StateClosed, cb.State())
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	})
	cb.now = func() time.Time { return now }

	// Trip.
	cb.RecordFailure()
	cb.RecordFailure()

	// Advance past cooldown.
	now = now.Add(6 * time.Second)
	assert.True(t, cb.Allow())

	// Failure in half-open re-opens.
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())
	assert.False(t, cb.Allow())
}

func TestCircuitBreaker_SuccessResetsFails(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // Reset consecutive fails.
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, StateClosed, cb.State()) // Only 2 consecutive, not 3.
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	})

	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()

	stats := cb.Stats()
	assert.Equal(t, StateOpen, stats.State)
	assert.Equal(t, int64(2), stats.TotalFailures)
	assert.Equal(t, int64(1), stats.TotalSuccesses)
	assert.Equal(t, 2, stats.ConsecutiveFails)
}

// --- Partner DID Registry Tests ---

func TestPartnerDIDRegistry_CRUD(t *testing.T) {
	reg := NewPartnerDIDRegistry()

	t.Run("register", func(t *testing.T) {
		err := reg.Register("did:web:partner.com", "Partner Org", "A trusted partner")
		require.NoError(t, err)

		entry, found := reg.Get("did:web:partner.com")
		require.True(t, found)
		assert.Equal(t, "pending", entry.Status)
		assert.Equal(t, "Partner Org", entry.Name)
	})

	t.Run("approve", func(t *testing.T) {
		err := reg.Approve("did:web:partner.com")
		require.NoError(t, err)

		assert.True(t, reg.IsApproved("did:web:partner.com"))
	})

	t.Run("revoke", func(t *testing.T) {
		err := reg.Revoke("did:web:partner.com")
		require.NoError(t, err)

		assert.False(t, reg.IsApproved("did:web:partner.com"))
		entry, _ := reg.Get("did:web:partner.com")
		assert.Equal(t, "revoked", entry.Status)
	})

	t.Run("unregister", func(t *testing.T) {
		err := reg.Unregister("did:web:partner.com")
		require.NoError(t, err)

		_, found := reg.Get("did:web:partner.com")
		assert.False(t, found)
	})

	t.Run("unregister not found", func(t *testing.T) {
		err := reg.Unregister("did:web:nonexistent.com")
		assert.ErrorIs(t, err, ErrPartnerNotFound)
	})

	t.Run("register validation", func(t *testing.T) {
		err := reg.Register("", "name", "desc")
		assert.Error(t, err)

		err = reg.Register("did:web:x.com", "", "desc")
		assert.Error(t, err)
	})

	t.Run("list", func(t *testing.T) {
		_ = reg.Register("did:web:a.com", "A", "")
		_ = reg.Register("did:web:b.com", "B", "")

		list := reg.List()
		assert.Len(t, list, 2)
	})
}

// --- Partner Issuer Resolver Tests ---

func TestPartnerIssuerResolver_ResolvePublicKeys(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:partner.com", "Partner", "")
	_ = reg.Approve("did:web:partner.com")

	mockDoc := &did.Document{
		ID: "did:web:partner.com",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         "did:web:partner.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:partner.com",
				PublicKeyJwk: &did.JWK{
					Kty: "OKP",
					Crv: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	resolver := &mockDIDResolver{doc: mockDoc}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  5 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	t.Run("success", func(t *testing.T) {
		keys, err := pir.ResolvePublicKeys(context.Background(), "did:web:partner.com")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := pir.ResolvePublicKeys(context.Background(), "did:web:unknown.com")
		assert.ErrorIs(t, err, ErrPartnerNotFound)
	})

	t.Run("not approved", func(t *testing.T) {
		_ = reg.Register("did:web:pending.com", "Pending", "")
		_, err := pir.ResolvePublicKeys(context.Background(), "did:web:pending.com")
		assert.ErrorIs(t, err, ErrPartnerNotApproved)
	})

	t.Run("circuit breaker opens after failures", func(t *testing.T) {
		_ = reg.Register("did:ion:failing", "Failing", "")
		_ = reg.Approve("did:ion:failing")

		failResolver := &mockDIDResolver{err: errors.New("network error")}
		failPir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
			Registry: reg,
			Resolver: failResolver,
			CircuitBreaker: CircuitBreakerConfig{
				FailureThreshold:  2,
				CooldownDuration:  10 * time.Second,
				HalfOpenMaxProbes: 1,
			},
		})

		// Fail twice to trip the breaker.
		_, _ = failPir.ResolvePublicKeys(context.Background(), "did:ion:failing")
		_, _ = failPir.ResolvePublicKeys(context.Background(), "did:ion:failing")

		// Third call should be rejected by circuit breaker.
		_, err := failPir.ResolvePublicKeys(context.Background(), "did:ion:failing")
		assert.ErrorIs(t, err, ErrCircuitOpen)
	})
}

func TestPartnerIssuerResolver_GetCircuitBreakerStates(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:x.com", "X", "")
	_ = reg.Approve("did:web:x.com")

	resolver := &mockDIDResolver{doc: &did.Document{
		ID: "did:web:x.com",
		VerificationMethod: []did.VerificationMethod{
			{PublicKeyJwk: &did.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
		},
	}}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 3,
			CooldownDuration: 5 * time.Second,
		},
	})

	// Trigger resolution to create a breaker.
	_, _ = pir.ResolvePublicKeys(context.Background(), "did:web:x.com")

	states := pir.GetCircuitBreakerStates()
	assert.Contains(t, states, "web")
	assert.Equal(t, StateClosed, states["web"])
}

// --- Attenuation Tests ---

func TestAttenuate_Success(t *testing.T) {
	result, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:code-review", Actions: []string{"read"}},
		},
		ParentDID:     "did:web:partner.com",
		AllowCrossOrg: true,
	})

	require.NoError(t, err)
	assert.True(t, result.CrossOrg)
	assert.Equal(t, "did:web:partner.com", result.ParentDID)
	assert.Len(t, result.Capabilities, 1)
}

func TestAttenuate_SubsetViolation(t *testing.T) {
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "tool:code-review", Actions: []string{"read"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:code-review", Actions: []string{"write"}}, // Not in parent.
		},
		ParentDID:     "did:web:partner.com",
		AllowCrossOrg: true,
	})

	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestAttenuate_WildcardParent(t *testing.T) {
	result, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:anything", Actions: []string{"read", "write"}},
		},
		ParentDID:     "did:web:partner.com",
		AllowCrossOrg: true,
	})

	require.NoError(t, err)
	assert.Len(t, result.Capabilities, 1)
}

func TestAttenuate_ChildWildcardDenied(t *testing.T) {
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities: []capability.Constraint{
			{Resource: "tool:x", Actions: []string{"read"}},
		},
		RequestedCapabilities: []capability.Constraint{
			{Resource: "tool:x", Actions: []string{"*"}}, // Wildcard not in parent.
		},
		ParentDID:     "did:web:partner.com",
		AllowCrossOrg: true,
	})

	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestAttenuate_EmptyParent(t *testing.T) {
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities:    nil,
		RequestedCapabilities: []capability.Constraint{{Resource: "x", Actions: []string{"r"}}},
		AllowCrossOrg:         true,
	})
	assert.ErrorIs(t, err, ErrEmptyParent)
}

func TestAttenuate_EmptyChild(t *testing.T) {
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities:    []capability.Constraint{{Resource: "x", Actions: []string{"r"}}},
		RequestedCapabilities: nil,
		AllowCrossOrg:         true,
	})
	assert.ErrorIs(t, err, ErrEmptyChild)
}

func TestAttenuate_CrossOrgNotPermitted(t *testing.T) {
	_, err := Attenuate(AttenuationRequest{
		ParentCapabilities:    []capability.Constraint{{Resource: "*", Actions: []string{"*"}}},
		RequestedCapabilities: []capability.Constraint{{Resource: "x", Actions: []string{"r"}}},
		AllowCrossOrg:         false,
	})
	assert.ErrorIs(t, err, ErrCrossOrgNotPermitted)
}

func TestAttenuate_ConditionEnforcement(t *testing.T) {
	parentCondition := capability.Condition(&mockCondition{condType: "time-window"})

	t.Run("missing all parent conditions", func(t *testing.T) {
		_, err := Attenuate(AttenuationRequest{
			ParentCapabilities: []capability.Constraint{
				{Resource: "tool:x", Actions: []string{"read"}, Conditions: []capability.Condition{parentCondition}},
			},
			RequestedCapabilities: []capability.Constraint{
				{Resource: "tool:x", Actions: []string{"read"}}, // Missing parent conditions.
			},
			AllowCrossOrg: true,
			ParentDID:     "did:web:p.com",
		})
		assert.ErrorIs(t, err, ErrSubsetViolation)
	})

	t.Run("missing one parent condition type", func(t *testing.T) {
		_, err := Attenuate(AttenuationRequest{
			ParentCapabilities: []capability.Constraint{
				{
					Resource:   "tool:x",
					Actions:    []string{"read"},
					Conditions: []capability.Condition{parentCondition, &mockCondition{condType: "ip-range"}},
				},
			},
			RequestedCapabilities: []capability.Constraint{
				{
					Resource:   "tool:x",
					Actions:    []string{"read"},
					Conditions: []capability.Condition{parentCondition},
				},
			},
			AllowCrossOrg: true,
			ParentDID:     "did:web:p.com",
		})
		assert.ErrorIs(t, err, ErrSubsetViolation)
	})
}

// --- Metrics Tests ---

func TestMetrics_Registration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	assert.NotNil(t, m.CircuitBreakerState)
	assert.NotNil(t, m.ResolutionTotal)
	assert.NotNil(t, m.ResolutionDuration)
}

func TestMetrics_UpdateCircuitBreaker(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	states := map[string]CircuitBreakerState{
		"web": StateClosed,
		"ion": StateOpen,
	}
	m.UpdateCircuitBreakerMetrics(states)

	// Verify metrics were set (basic smoke test).
	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_RecordResolution(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.RecordResolution("web", "success", 0.05)
	m.RecordResolution("web", "failure", 1.2)

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_NilSafe(_ *testing.T) {
	var m *Metrics
	// Should not panic.
	m.UpdateCircuitBreakerMetrics(nil)
	m.RecordResolution("web", "success", 0.1)
}

// --- Resolver + Metrics Integration Tests ---

func TestPartnerIssuerResolver_MetricsWired_Success(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:partner.com", "Partner", "")
	_ = reg.Approve("did:web:partner.com")

	mockDoc := &did.Document{
		ID: "did:web:partner.com",
		VerificationMethod: []did.VerificationMethod{
			{
				PublicKeyJwk: &did.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
			},
		},
	}

	promReg := prometheus.NewRegistry()
	metrics := NewMetrics(promReg)
	resolver := &mockDIDResolver{doc: mockDoc}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		Metrics:  metrics,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  5 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	_, err := pir.ResolvePublicKeys(context.Background(), "did:web:partner.com")
	require.NoError(t, err)

	families, err := promReg.Gather()
	require.NoError(t, err)

	// Should have resolution_total and resolution_duration_seconds and circuit_breaker_state.
	familyNames := make(map[string]bool)
	for _, f := range families {
		familyNames[f.GetName()] = true
	}
	assert.True(t, familyNames["euno_partner_did_resolution_total"], "should emit resolution_total")
	assert.True(t, familyNames["euno_partner_did_resolution_duration_seconds"], "should emit resolution_duration")
	assert.True(t, familyNames["euno_partner_did_circuit_breaker_state"], "should emit circuit_breaker_state")
}

func TestPartnerIssuerResolver_MetricsWired_Failure(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:fail.com", "Fail", "")
	_ = reg.Approve("did:web:fail.com")

	promReg := prometheus.NewRegistry()
	metrics := NewMetrics(promReg)
	resolver := &mockDIDResolver{err: errors.New("timeout")}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		Metrics:  metrics,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  5 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	_, err := pir.ResolvePublicKeys(context.Background(), "did:web:fail.com")
	assert.Error(t, err)

	// Verify resolution_total was recorded with "error" outcome.
	families, err := promReg.Gather()
	require.NoError(t, err)

	foundErrorOutcome := false
	for _, f := range families {
		if f.GetName() == "euno_partner_did_resolution_total" {
			require.NotEmpty(t, f.GetMetric())
			for _, m := range f.GetMetric() {
				metricHasError := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "outcome" && lp.GetValue() == "error" {
						metricHasError = true
						foundErrorOutcome = true
					}
				}
				if metricHasError {
					assert.Equal(t, float64(1), m.GetCounter().GetValue())
				}
			}
		}
	}
	assert.True(t, foundErrorOutcome, "should record error outcome")
}

func TestPartnerIssuerResolver_MetricsWired_CircuitOpen(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:ion:fail", "ION Fail", "")
	_ = reg.Approve("did:ion:fail")

	promReg := prometheus.NewRegistry()
	metrics := NewMetrics(promReg)
	resolver := &mockDIDResolver{err: errors.New("network error")}

	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		Metrics:  metrics,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  2,
			CooldownDuration:  30 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	// Trip the breaker.
	_, _ = pir.ResolvePublicKeys(context.Background(), "did:ion:fail")
	_, _ = pir.ResolvePublicKeys(context.Background(), "did:ion:fail")

	// Third call triggers circuit_open outcome.
	_, err := pir.ResolvePublicKeys(context.Background(), "did:ion:fail")
	assert.ErrorIs(t, err, ErrCircuitOpen)

	// Verify circuit_open was recorded.
	families, err := promReg.Gather()
	require.NoError(t, err)

	hasCircuitOpen := false
	for _, f := range families {
		if f.GetName() == "euno_partner_did_resolution_total" {
			for _, m := range f.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "outcome" && lp.GetValue() == "circuit_open" {
						hasCircuitOpen = true
					}
				}
			}
		}
	}
	assert.True(t, hasCircuitOpen, "should record circuit_open outcome")

	// Verify circuit_breaker_state gauge shows "open" for ion.
	foundIonOpen := false
	for _, f := range families {
		if f.GetName() == "euno_partner_did_circuit_breaker_state" {
			for _, m := range f.GetMetric() {
				method := ""
				state := ""
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "did_method" {
						method = lp.GetValue()
					}
					if lp.GetName() == "state" {
						state = lp.GetValue()
					}
				}
				if method == "ion" && state == "open" {
					foundIonOpen = true
					assert.Equal(t, float64(1), m.GetGauge().GetValue())
				}
			}
		}
	}
	assert.True(t, foundIonOpen, "should emit ion/open circuit breaker gauge")
}

func TestPartnerIssuerResolver_NoMetrics_NoPanic(t *testing.T) {
	reg := NewPartnerDIDRegistry()
	_ = reg.Register("did:web:ok.com", "OK", "")
	_ = reg.Approve("did:web:ok.com")

	resolver := &mockDIDResolver{doc: &did.Document{
		ID: "did:web:ok.com",
		VerificationMethod: []did.VerificationMethod{
			{PublicKeyJwk: &did.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
		},
	}}

	// No metrics configured — should not panic.
	pir := NewPartnerIssuerResolver(PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 3,
			CooldownDuration: 5 * time.Second,
		},
	})

	keys, err := pir.ResolvePublicKeys(context.Background(), "did:web:ok.com")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

// --- Test Helpers ---

type mockDIDResolver struct {
	doc *did.Document
	err error
}

func (m *mockDIDResolver) Resolve(_ context.Context, _ string) (*did.Document, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.doc, nil
}

type mockCondition struct {
	condType string
}

func (c *mockCondition) ConditionType() string { return c.condType }

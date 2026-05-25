// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package testutil

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifierRejectsWrongKeySignaturesAcrossAlgorithms(t *testing.T) {
	rsaSigner, _ := MustGenerateRSASigner("rsa")
	_, ecdsaVerifier := MustGenerateECDSASigner("ecdsa")
	_, eddsaVerifier := MustGenerateEdDSASigner("eddsa")

	digest := sha256.Sum256([]byte("cross algorithm mismatch"))
	signature, err := rsaSigner.Sign(context.Background(), digest[:])
	require.NoError(t, err)

	assert.Error(t, ecdsaVerifier.Verify(context.Background(), digest[:], signature))
	assert.Error(t, eddsaVerifier.Verify(context.Background(), digest[:], signature))
}

func TestFakeClockAfterZeroDurationTriggersImmediately(t *testing.T) {
	now := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(now)

	ch := clock.After(0)
	select {
	case firedAt := <-ch:
		assert.Equal(t, now, firedAt)
	case <-time.After(time.Second):
		t.Fatal("zero-duration waiter did not fire immediately")
	}
}

func TestFakeClockSince(t *testing.T) {
	start := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(start.Add(90 * time.Second))

	assert.Equal(t, 90*time.Second, clock.Since(start))
	assert.Equal(t, -30*time.Second, clock.Since(start.Add(2*time.Minute)))
}

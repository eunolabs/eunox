// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"
	"time"

	eunoxcrypto "github.com/eunolabs/eunox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMustGenerateRSASigner(t *testing.T) {
	signer, verifier := MustGenerateRSASigner("rsa-key")

	digest := sha256.Sum256([]byte("rsa signing payload"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestMustGenerateECDSASigner(t *testing.T) {
	signer, verifier := MustGenerateECDSASigner("ecdsa-key")

	digest := sha256.Sum256([]byte("ecdsa signing payload"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestMustGenerateEdDSASigner(t *testing.T) {
	signer, verifier := MustGenerateEdDSASigner("eddsa-key")

	message := []byte("eddsa signs the full message")
	signature, err := signer.Sign(context.Background(), message)
	require.NoError(t, err)
	assert.Len(t, signature, ed25519.SignatureSize)
	assert.NoError(t, verifier.Verify(context.Background(), message, signature))
}

func TestSignerKeyIDAndAlgorithm(t *testing.T) {
	tests := []struct {
		name              string
		keyID             string
		expectedAlgorithm eunoxcrypto.Algorithm
		generate          func(string) (eunoxcrypto.Signer, eunoxcrypto.Verifier)
	}{
		{name: "rsa", keyID: "rsa-meta", expectedAlgorithm: eunoxcrypto.RS256, generate: MustGenerateRSASigner},
		{name: "ecdsa", keyID: "ecdsa-meta", expectedAlgorithm: eunoxcrypto.ES256, generate: MustGenerateECDSASigner},
		{name: "eddsa", keyID: "eddsa-meta", expectedAlgorithm: eunoxcrypto.EdDSA, generate: MustGenerateEdDSASigner},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, verifier := tt.generate(tt.keyID)
			assert.Equal(t, tt.keyID, signer.KeyID())
			assert.Equal(t, tt.expectedAlgorithm, signer.Algorithm())
			assert.Equal(t, tt.keyID, verifier.KeyID())
			assert.Equal(t, tt.expectedAlgorithm, verifier.Algorithm())
		})
	}
}

func TestFakeClockNow(t *testing.T) {
	now := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(now)

	assert.Equal(t, now, clock.Now())
	assert.Equal(t, 0*time.Second, clock.Since(now))
}

func TestFakeClockAdvance(t *testing.T) {
	start := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(start)

	clock.Advance(5 * time.Minute)

	assert.Equal(t, start.Add(5*time.Minute), clock.Now())
	assert.Equal(t, 5*time.Minute, clock.Since(start))
}

func TestFakeClockAfter(t *testing.T) {
	start := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(start)

	ch := clock.After(10 * time.Second)

	clock.Advance(9 * time.Second)
	select {
	case <-ch:
		t.Fatal("waiter should not fire yet")
	default:
	}

	clock.Advance(1 * time.Second)
	select {
	case firedAt := <-ch:
		assert.Equal(t, start.Add(10*time.Second), firedAt)
	case <-time.After(time.Second):
		t.Fatal("waiter did not fire")
	}
}

func TestFakeClockSet(t *testing.T) {
	start := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	target := start.Add(30 * time.Minute)
	clock := NewFakeClock(start)

	clock.Set(target)

	assert.Equal(t, target, clock.Now())
	assert.Equal(t, 30*time.Minute, clock.Since(start))
}

func TestRealClock(t *testing.T) {
	clock := &RealClock{}
	before := time.Now()
	now := clock.Now()
	after := time.Now()

	assert.False(t, now.Before(before))
	assert.False(t, now.After(after))
}

func TestNewTestServer(t *testing.T) {
	server := NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, err := w.Write([]byte("ok"))
		require.NoError(t, err)
	}))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.BaseURL(), http.NoBody)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}

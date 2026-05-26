// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestSigner(t *testing.T, keyID string) *crypto.SoftwareSigner {
	t.Helper()
	signer, err := crypto.GenerateECDSASigner(keyID, crypto.ES256)
	require.NoError(t, err)
	return signer
}

func TestRotatingKeyStore_CurrentSigner(t *testing.T) {
	signer := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer)

	current := ks.CurrentSigner()
	assert.Equal(t, "key-1", current.KeyID())
	assert.Equal(t, crypto.ES256, current.Algorithm())
}

func TestRotatingKeyStore_PublicKeys_SingleKey(t *testing.T) {
	signer := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer)

	keys := ks.PublicKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, "key-1", keys[0].KeyID)
	assert.Equal(t, crypto.ES256, keys[0].Algorithm)
	assert.Equal(t, "sig", keys[0].Use)
	assert.NotNil(t, keys[0].PublicKey)
}

func TestRotatingKeyStore_Rotate(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	signer2 := generateTestSigner(t, "key-2")
	ks := NewRotatingKeyStore(signer1)

	err := ks.Rotate(signer2)
	require.NoError(t, err)

	// Current signer should be the new key
	current := ks.CurrentSigner()
	assert.Equal(t, "key-2", current.KeyID())

	// PublicKeys should include both
	keys := ks.PublicKeys()
	require.Len(t, keys, 2)
	assert.Equal(t, "key-2", keys[0].KeyID) // Active first
	assert.Equal(t, "key-1", keys[1].KeyID) // Retired second
}

func TestRotatingKeyStore_MultipleRotations(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	signer2 := generateTestSigner(t, "key-2")
	signer3 := generateTestSigner(t, "key-3")
	ks := NewRotatingKeyStore(signer1)

	require.NoError(t, ks.Rotate(signer2))
	require.NoError(t, ks.Rotate(signer3))

	// Current signer should be key-3
	assert.Equal(t, "key-3", ks.CurrentSigner().KeyID())

	// PublicKeys: active first, then retired in reverse chronological order
	keys := ks.PublicKeys()
	require.Len(t, keys, 3)
	assert.Equal(t, "key-3", keys[0].KeyID) // Active
	assert.Equal(t, "key-2", keys[1].KeyID) // Most recently retired
	assert.Equal(t, "key-1", keys[2].KeyID) // Oldest retired
}

func TestRotatingKeyStore_RotateNilReturnsError(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer1)

	err := ks.Rotate(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be nil")

	// Store should be unchanged
	assert.Equal(t, "key-1", ks.CurrentSigner().KeyID())
	assert.Len(t, ks.PublicKeys(), 1)
}

func TestRotatingKeyStore_NewNilPanics(t *testing.T) {
	assert.PanicsWithValue(t, "current signer must not be nil", func() {
		_ = NewRotatingKeyStore(nil)
	})
}

func TestRotatingKeyStore_RotateDuplicateKeyIDReturnsError(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer1)

	duplicate := generateTestSigner(t, "key-1")
	err := ks.Rotate(duplicate)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Equal(t, "key-1", ks.CurrentSigner().KeyID())
	assert.Empty(t, ks.retired)
}

func TestRotatingKeyStore_Prune(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	signer2 := generateTestSigner(t, "key-2")
	signer3 := generateTestSigner(t, "key-3")
	ks := NewRotatingKeyStore(signer1)

	require.NoError(t, ks.Rotate(signer2))
	require.NoError(t, ks.Rotate(signer3))

	assert.Equal(t, 2, ks.RetiredKeyCount())

	// Prune keys retired before now + 1s (all retired keys)
	pruned := ks.Prune(time.Now().Add(time.Second))
	assert.Equal(t, 2, pruned)
	assert.Equal(t, 0, ks.RetiredKeyCount())

	// Only current key remains
	keys := ks.PublicKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, "key-3", keys[0].KeyID)
}

func TestRotatingKeyStore_PruneSelectiveByTime(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer1)

	// Rotate with known timing
	signer2 := generateTestSigner(t, "key-2")
	require.NoError(t, ks.Rotate(signer2))
	midpoint := time.Now()

	// Small delay to ensure time separation
	time.Sleep(10 * time.Millisecond)

	signer3 := generateTestSigner(t, "key-3")
	require.NoError(t, ks.Rotate(signer3))

	// Prune only keys retired before midpoint
	pruned := ks.Prune(midpoint)
	assert.Equal(t, 1, pruned) // key-1 pruned
	assert.Equal(t, 1, ks.RetiredKeyCount())

	// key-2 should still be present (retired after midpoint)
	keys := ks.PublicKeys()
	require.Len(t, keys, 2)
	assert.Equal(t, "key-3", keys[0].KeyID)
	assert.Equal(t, "key-2", keys[1].KeyID)
}

func TestRotatingKeyStore_RotateDuplicateRetiredKeyIDReturnsError(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	signer2 := generateTestSigner(t, "key-2")
	ks := NewRotatingKeyStore(signer1)

	require.NoError(t, ks.Rotate(signer2))

	duplicate := generateTestSigner(t, "key-1")
	err := ks.Rotate(duplicate)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Equal(t, "key-2", ks.CurrentSigner().KeyID())
	assert.Equal(t, 1, ks.RetiredKeyCount())
}

func TestRotatingKeyStore_PruneNothingToPrune(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer1)

	// Prune with no retired keys
	pruned := ks.Prune(time.Now())
	assert.Equal(t, 0, pruned)

	// Prune with cutoff in the past
	signer2 := generateTestSigner(t, "key-2")
	require.NoError(t, ks.Rotate(signer2))
	pruned = ks.Prune(time.Now().Add(-time.Hour))
	assert.Equal(t, 0, pruned)
	assert.Equal(t, 1, ks.RetiredKeyCount())
}

func TestRotatingKeyStore_ConcurrentAccess(t *testing.T) {
	signer1 := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = ks.CurrentSigner()
			_ = ks.PublicKeys()
			_ = ks.RetiredKeyCount()
		}
	}()

	for i := 0; i < 10; i++ {
		s := generateTestSigner(t, "rotated")
		_ = ks.Rotate(s)
	}
	<-done
}

func TestRotatingKeyStore_ImplementsKeyStore(t *testing.T) {
	signer := generateTestSigner(t, "key-1")
	ks := NewRotatingKeyStore(signer)

	// Ensure it satisfies the KeyStore interface
	var _ KeyStore = ks
}

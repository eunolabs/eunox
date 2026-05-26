// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"fmt"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/crypto"
)

// RotatingKeyStore implements KeyStore with support for key rotation.
// It maintains an active signing key and zero or more retired keys.
// Retired keys are still published in the JWKS endpoint so that tokens
// signed with them remain verifiable until they expire naturally.
//
// Rotation procedure:
//  1. Generate or load a new SoftwareSigner.
//  2. Call Rotate(newSigner) — the current key becomes retired.
//  3. After max token TTL has elapsed, call Prune(cutoff) to remove
//     retired keys older than the cutoff time.
//
// Thread safety: all methods are safe for concurrent use.
type RotatingKeyStore struct {
	mu      sync.RWMutex
	current *crypto.SoftwareSigner
	retired []retiredKey
}

// retiredKey tracks a signer that is no longer used for signing
// but whose public key must remain in JWKS for token verification.
type retiredKey struct {
	signer    *crypto.SoftwareSigner
	retiredAt time.Time
}

// NewRotatingKeyStore creates a RotatingKeyStore with the given active signer.
func NewRotatingKeyStore(current *crypto.SoftwareSigner) *RotatingKeyStore {
	if current == nil {
		panic("current signer must not be nil")
	}

	return &RotatingKeyStore{
		current: current,
	}
}

// CurrentSigner returns the active signing key.
func (ks *RotatingKeyStore) CurrentSigner() crypto.Signer {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.current
}

// PublicKeys returns all public keys (active + retired) for JWKS endpoints.
// The active key is listed first, followed by retired keys in reverse
// chronological order (most recently retired first).
func (ks *RotatingKeyStore) PublicKeys() []PublicKeyInfo {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keys := make([]PublicKeyInfo, 0, 1+len(ks.retired))

	// Active key
	if ks.current != nil {
		pub := ks.current.PublicKey()
		if pub != nil {
			keys = append(keys, PublicKeyInfo{
				KeyID:     ks.current.KeyID(),
				Algorithm: ks.current.Algorithm(),
				PublicKey: pub,
				Use:       "sig",
			})
		}
	}

	// Retired keys (reverse chronological)
	for i := len(ks.retired) - 1; i >= 0; i-- {
		rk := ks.retired[i]
		if rk.signer == nil {
			continue
		}

		pub := rk.signer.PublicKey()
		if pub != nil {
			keys = append(keys, PublicKeyInfo{
				KeyID:     rk.signer.KeyID(),
				Algorithm: rk.signer.Algorithm(),
				PublicKey: pub,
				Use:       "sig",
			})
		}
	}

	return keys
}

// Rotate promotes a new signer to active and retires the current key.
// The retired key's public key remains in JWKS until pruned.
func (ks *RotatingKeyStore) Rotate(newSigner *crypto.SoftwareSigner) error {
	if newSigner == nil {
		return fmt.Errorf("new signer must not be nil")
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.current != nil && ks.current.KeyID() == newSigner.KeyID() {
		return fmt.Errorf("signer with key id %q already exists", newSigner.KeyID())
	}

	for _, rk := range ks.retired {
		if rk.signer != nil && rk.signer.KeyID() == newSigner.KeyID() {
			return fmt.Errorf("signer with key id %q already exists", newSigner.KeyID())
		}
	}

	if ks.current != nil {
		ks.retired = append(ks.retired, retiredKey{
			signer:    ks.current,
			retiredAt: time.Now(),
		})
	}

	ks.current = newSigner
	return nil
}

// Prune removes retired keys that were retired before the given cutoff time.
// This should be called after max-token-TTL has elapsed post-rotation to
// ensure no in-flight tokens reference the pruned key.
func (ks *RotatingKeyStore) Prune(cutoff time.Time) int {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	kept := ks.retired[:0]
	pruned := 0
	for _, rk := range ks.retired {
		if rk.retiredAt.Before(cutoff) {
			pruned++
		} else {
			kept = append(kept, rk)
		}
	}

	for i := len(kept); i < len(ks.retired); i++ {
		ks.retired[i] = retiredKey{}
	}

	ks.retired = kept
	return pruned
}

// RetiredKeyCount returns the number of retired keys still in the store.
func (ks *RotatingKeyStore) RetiredKeyCount() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.retired)
}

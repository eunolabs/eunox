// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// PublicKeyResolver resolves a DID URI to the set of public keys declared in its DID document.
// Implementations may apply additional access-control checks (e.g. registry approval) before
// returning keys.
type PublicKeyResolver interface {
	ResolvePublicKeys(ctx context.Context, didURI string) ([]gocrypto.PublicKey, error)
}

// VerifyCoSignatures verifies every co-signature listed in proofs against the given token string.
//
// # Enforcement contract
//
// When proofs is nil or contains no signatures the function returns nil immediately — tokens
// without co-signatures are unaffected. When proofs is non-nil and contains one or more
// signatures, ALL signatures must be valid. A single invalid co-signature causes the whole
// token to be rejected.
//
// # Signing payload
//
// Each co-issuer signs the JWT compact serialization (the literal token string as UTF-8 bytes).
// This binds the co-signature to the exact primary-issuer signature, preventing substitution.
//
// # Signature encoding
//
// Signature bytes follow JWS encoding conventions:
//   - ECDSA (ES256/ES384/ES512): IEEE P1363 format (fixed-length r ‖ s with no ASN.1 wrapper)
//   - RSA PKCS1v15 (RS256/RS384/RS512): raw PKCS#1 v1.5 signature bytes
//   - RSA PSS (PS256/PS384/PS512): raw PSS signature bytes
//   - EdDSA: raw 64-byte Ed25519 signature
//
// The IssuerSignature.Signature field stores these bytes as base64url (no padding).
//
// # Resolver
//
// resolver is used to obtain the co-issuer's public keys. When resolver is nil and proofs
// is non-empty the function fails closed with an error — callers must supply a resolver if
// they want co-signatures to be verifiable.
func VerifyCoSignatures(ctx context.Context, tokenStr string, proofs *IssuanceProofs, resolver PublicKeyResolver) error {
	if proofs == nil || len(proofs.Signatures) == 0 {
		return nil
	}
	if resolver == nil {
		return errors.New("capability: co-signatures present but no key resolver provided; failing closed")
	}

	message := []byte(tokenStr)
	for i, sig := range proofs.Signatures {
		if err := verifyOneSig(ctx, message, sig, resolver); err != nil {
			return fmt.Errorf("co-signature[%d] issuer %q: %w", i, sig.IssuerDID, err)
		}
	}
	return nil
}

// verifyOneSig verifies a single IssuerSignature against message using keys from resolver.
func verifyOneSig(ctx context.Context, message []byte, sig IssuerSignature, resolver PublicKeyResolver) error {
	if sig.IssuerDID == "" {
		return errors.New("issuer DID is empty")
	}
	if sig.Algorithm == "" {
		return errors.New("algorithm is empty")
	}
	if sig.Signature == "" {
		return errors.New("signature is empty")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	keys, err := resolver.ResolvePublicKeys(ctx, sig.IssuerDID)
	if err != nil {
		return fmt.Errorf("resolve co-issuer keys: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("no public keys found for co-issuer")
	}

	var lastErr error
	for _, key := range keys {
		if verifyErr := verifyRawSignature(message, sig.Algorithm, sigBytes, key); verifyErr == nil {
			return nil
		} else {
			lastErr = verifyErr
		}
	}
	return fmt.Errorf("no key verified the signature: %w", lastErr)
}

// verifyRawSignature dispatches to the correct verification function based on algorithm.
func verifyRawSignature(message []byte, algorithm string, sigBytes []byte, key gocrypto.PublicKey) error {
	switch algorithm {
	case "ES256":
		return verifyECDSA(message, sigBytes, key, gocrypto.SHA256)
	case "ES384":
		return verifyECDSA(message, sigBytes, key, gocrypto.SHA384)
	case "ES512":
		return verifyECDSA(message, sigBytes, key, gocrypto.SHA512)
	case "RS256":
		return verifyRSAPKCS1v15(message, sigBytes, key, gocrypto.SHA256)
	case "RS384":
		return verifyRSAPKCS1v15(message, sigBytes, key, gocrypto.SHA384)
	case "RS512":
		return verifyRSAPKCS1v15(message, sigBytes, key, gocrypto.SHA512)
	case "PS256":
		return verifyRSAPSS(message, sigBytes, key, gocrypto.SHA256)
	case "PS384":
		return verifyRSAPSS(message, sigBytes, key, gocrypto.SHA384)
	case "PS512":
		return verifyRSAPSS(message, sigBytes, key, gocrypto.SHA512)
	case "EdDSA":
		return verifyEdDSA(message, sigBytes, key)
	default:
		return fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// verifyECDSA verifies an ECDSA signature encoded in IEEE P1363 format (r‖s).
func verifyECDSA(message, sigBytes []byte, key gocrypto.PublicKey, hash gocrypto.Hash) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected *ecdsa.PublicKey")
	}

	// IEEE P1363: signature is r‖s, each component padded to the curve's byte size.
	keyByteLen := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(sigBytes) != 2*keyByteLen {
		return fmt.Errorf("invalid ECDSA signature length: got %d bytes, want %d (curve %s)",
			len(sigBytes), 2*keyByteLen, ecKey.Curve.Params().Name)
	}

	r := new(big.Int).SetBytes(sigBytes[:keyByteLen])
	s := new(big.Int).SetBytes(sigBytes[keyByteLen:])

	h := hash.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)

	if !ecdsa.Verify(ecKey, digest, r, s) {
		return errors.New("ECDSA verification failed")
	}
	return nil
}

// verifyRSAPKCS1v15 verifies an RSA PKCS#1 v1.5 signature.
func verifyRSAPKCS1v15(message, sigBytes []byte, key gocrypto.PublicKey, hash gocrypto.Hash) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected *rsa.PublicKey")
	}

	h := hash.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(rsaKey, hash, digest, sigBytes); err != nil {
		return fmt.Errorf("RSA PKCS1v15 verification failed: %w", err)
	}
	return nil
}

// verifyRSAPSS verifies an RSA PSS signature.
func verifyRSAPSS(message, sigBytes []byte, key gocrypto.PublicKey, hash gocrypto.Hash) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected *rsa.PublicKey")
	}

	h := hash.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)

	if err := rsa.VerifyPSS(rsaKey, hash, digest, sigBytes, nil); err != nil {
		return fmt.Errorf("RSA PSS verification failed: %w", err)
	}
	return nil
}

// verifyEdDSA verifies an Ed25519 signature.
func verifyEdDSA(message, sigBytes []byte, key gocrypto.PublicKey) error {
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected ed25519.PublicKey")
	}

	if !ed25519.Verify(edKey, message, sigBytes) {
		return errors.New("EdDSA (Ed25519) verification failed")
	}
	return nil
}

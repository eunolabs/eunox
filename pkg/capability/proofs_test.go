// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability_test

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/pkg/capability"
)

// --- test helpers ---

// staticKeyResolver returns a fixed set of public keys for any DID.
type staticKeyResolver struct {
	keys []gocrypto.PublicKey
	err  error
}

func (r *staticKeyResolver) ResolvePublicKeys(_ context.Context, _ string) ([]gocrypto.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.keys, nil
}

// emptyKeyResolver resolves no keys.
type emptyKeyResolver struct{}

func (emptyKeyResolver) ResolvePublicKeys(_ context.Context, _ string) ([]gocrypto.PublicKey, error) {
	return nil, nil
}

// signECDSA signs message with key using the given hash and returns the IEEE P1363 signature.
func signECDSA(tb testing.TB, key *ecdsa.PrivateKey, message []byte, hash gocrypto.Hash) string {
	tb.Helper()
	h := hash.New()
	_, err := h.Write(message)
	require.NoError(tb, err)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	require.NoError(tb, err)

	byteLen := (key.Curve.Params().BitSize + 7) / 8
	sigBytes := make([]byte, 2*byteLen)
	r.FillBytes(sigBytes[:byteLen])
	s.FillBytes(sigBytes[byteLen:])
	return base64.RawURLEncoding.EncodeToString(sigBytes)
}

// signRSAPKCS1v15 signs message and returns the raw signature.
func signRSAPKCS1v15(tb testing.TB, key *rsa.PrivateKey, message []byte, hash gocrypto.Hash) string {
	tb.Helper()
	h := hash.New()
	_, err := h.Write(message)
	require.NoError(tb, err)
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	require.NoError(tb, err)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// signRSAPSS signs message using PSS and returns the raw signature.
func signRSAPSS(tb testing.TB, key *rsa.PrivateKey, message []byte, hash gocrypto.Hash) string {
	tb.Helper()
	h := hash.New()
	_, err := h.Write(message)
	require.NoError(tb, err)
	digest := h.Sum(nil)
	sig, err := rsa.SignPSS(rand.Reader, key, hash, digest, nil)
	require.NoError(tb, err)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// signEdDSA signs message with an Ed25519 private key.
func signEdDSA(tb testing.TB, key ed25519.PrivateKey, message []byte) string {
	tb.Helper()
	sig := ed25519.Sign(key, message)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// --- VerifyCoSignatures tests ---

func TestVerifyCoSignatures_NilProofs(t *testing.T) {
	err := capability.VerifyCoSignatures(context.Background(), "some.token.string", nil, nil)
	require.NoError(t, err, "nil proofs must return nil without touching resolver")
}

func TestVerifyCoSignatures_EmptySignatures(t *testing.T) {
	proofs := &capability.IssuanceProofs{}
	err := capability.VerifyCoSignatures(context.Background(), "some.token.string", proofs, nil)
	require.NoError(t, err, "empty Signatures must return nil without touching resolver")
}

func TestVerifyCoSignatures_NilResolverWithSignatures(t *testing.T) {
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:123", Algorithm: "ES256", Signature: "aaa"},
		},
	}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, nil)
	require.Error(t, err, "nil resolver with non-empty proofs must fail closed")
	assert.Contains(t, err.Error(), "no key resolver")
}

func TestVerifyCoSignatures_ECDSAES256_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, key, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ec256", Algorithm: "ES256", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_ECDSAES384_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, key, []byte(tokenStr), gocrypto.SHA384)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ec384", Algorithm: "ES384", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_ECDSAES512_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, key, []byte(tokenStr), gocrypto.SHA512)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ec512", Algorithm: "ES512", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_RS256_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPKCS1v15(t, key, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:rsa256", Algorithm: "RS256", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_RS384_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPKCS1v15(t, key, []byte(tokenStr), gocrypto.SHA384)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:rsa384", Algorithm: "RS384", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_RS512_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPKCS1v15(t, key, []byte(tokenStr), gocrypto.SHA512)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:rsa512", Algorithm: "RS512", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_PS256_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPSS(t, key, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ps256", Algorithm: "PS256", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_PS384_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPSS(t, key, []byte(tokenStr), gocrypto.SHA384)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ps384", Algorithm: "PS384", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_PS512_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signRSAPSS(t, key, []byte(tokenStr), gocrypto.SHA512)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ps512", Algorithm: "PS512", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_EdDSA_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signEdDSA(t, priv, []byte(tokenStr))

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ed25519", Algorithm: "EdDSA", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{pub}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_MultipleValid(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"

	ecSig := signECDSA(t, ecKey, []byte(tokenStr), gocrypto.SHA256)
	edSig := signEdDSA(t, edPriv, []byte(tokenStr))

	resolver := newDIDMapResolver(
		"did:example:co1", []gocrypto.PublicKey{ecKey.Public()},
		"did:example:co2", []gocrypto.PublicKey{edPub},
	)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:co1", Algorithm: "ES256", Signature: ecSig},
			{IssuerDID: "did:example:co2", Algorithm: "EdDSA", Signature: edSig},
		},
	}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

// didMapResolver resolves DIDs to fixed key sets.
type didMapResolver struct {
	keys map[string][]gocrypto.PublicKey
}

func newDIDMapResolver(pairs ...interface{}) *didMapResolver {
	m := &didMapResolver{keys: make(map[string][]gocrypto.PublicKey)}
	for i := 0; i+1 < len(pairs); i += 2 {
		did := pairs[i].(string)
		ks := pairs[i+1].([]gocrypto.PublicKey)
		m.keys[did] = ks
	}
	return m
}

func (r *didMapResolver) ResolvePublicKeys(_ context.Context, didURI string) ([]gocrypto.PublicKey, error) {
	if ks, ok := r.keys[didURI]; ok {
		return ks, nil
	}
	return nil, errors.New("DID not found")
}

func TestVerifyCoSignatures_WrongSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	// Sign different content — verification must fail.
	sig := signECDSA(t, key, []byte("different content"), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:co", Algorithm: "ES256", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	err = capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "co-signature[0]")
}

func TestVerifyCoSignatures_WrongKey(t *testing.T) {
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, signerKey, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:wrong", Algorithm: "ES256", Signature: sig},
		},
	}
	// Provide the wrong key — resolves to verifyKey, not signerKey.
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{verifyKey.Public()}}
	err = capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA verification failed")
}

func TestVerifyCoSignatures_ResolverError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, key, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:unreachable", Algorithm: "ES256", Signature: sig},
		},
	}
	resolver := &staticKeyResolver{err: errors.New("DID endpoint unavailable")}
	err = capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DID endpoint unavailable")
}

func TestVerifyCoSignatures_EmptyKeys(t *testing.T) {
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:nokeys", Algorithm: "ES256", Signature: "anysig"},
		},
	}
	resolver := emptyKeyResolver{}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public keys found")
}

func TestVerifyCoSignatures_EmptyDID(t *testing.T) {
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "", Algorithm: "ES256", Signature: "anysig"},
		},
	}
	resolver := &staticKeyResolver{}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer DID is empty")
}

func TestVerifyCoSignatures_EmptyAlgorithm(t *testing.T) {
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:co", Algorithm: "", Signature: "anysig"},
		},
	}
	resolver := &staticKeyResolver{}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm is empty")
}

func TestVerifyCoSignatures_UnsupportedAlgorithm(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:co", Algorithm: "HS256", Signature: "anysig"},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported algorithm "HS256"`)
}

func TestVerifyCoSignatures_InvalidBase64Signature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:co", Algorithm: "ES256", Signature: "!!!not-base64!!!"},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	err := capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode signature")
}

func TestVerifyCoSignatures_OneOfTwoFails(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	ecSig := signECDSA(t, ecKey, []byte(tokenStr), gocrypto.SHA256)
	// Sign wrong content for EdDSA — must cause whole verification to fail.
	edSig := signEdDSA(t, edPriv, []byte("wrong content"))

	resolver := newDIDMapResolver(
		"did:example:ec", []gocrypto.PublicKey{ecKey.Public()},
		"did:example:ed", []gocrypto.PublicKey{edPub},
	)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:ec", Algorithm: "ES256", Signature: ecSig},
			{IssuerDID: "did:example:ed", Algorithm: "EdDSA", Signature: edSig},
		},
	}

	err = capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver)
	require.Error(t, err, "one failing co-signature must reject the whole token")
	assert.Contains(t, err.Error(), "co-signature[1]")
}

func TestVerifyCoSignatures_KeyTypeMismatch(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	// Sign with EC key but resolver returns RSA key.
	sig := signECDSA(t, ecKey, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:mismatch", Algorithm: "ES256", Signature: sig},
		},
	}
	// Resolver returns the RSA key — type mismatch should produce an error.
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{rsaKey.Public()}}
	err = capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key type mismatch")
}

func TestVerifyCoSignatures_MultipleKeysOneMatches(t *testing.T) {
	// Resolver returns multiple keys; the second one was used to sign.
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenStr := "header.payload.signature"
	sig := signECDSA(t, key2, []byte(tokenStr), gocrypto.SHA256)

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:multi", Algorithm: "ES256", Signature: sig},
		},
	}
	// Return both keys — verification should succeed by trying key2.
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key1.Public(), key2.Public()}}
	require.NoError(t, capability.VerifyCoSignatures(context.Background(), tokenStr, proofs, resolver))
}

func TestVerifyCoSignatures_ECDSAWrongLength(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Produce a signature that is too short (e.g. only 32 bytes instead of 64).
	shortSig := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:badlen", Algorithm: "ES256", Signature: shortSig},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	err = capability.VerifyCoSignatures(context.Background(), "token", proofs, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ECDSA signature length")
}

// --- Test that big.Int FillBytes padding is correct for small r/s values ---

func TestSignECDSA_SmallRS(t *testing.T) {
	// This test verifies that the fixed-width IEEE P1363 encoding handles
	// leading-zero-padded r and s values correctly.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Override r/s to have values smaller than the key byte length.
	r := big.NewInt(1)
	s := big.NewInt(2)

	byteLen := 32 // P-256 uses 32-byte components
	sigBytes := make([]byte, 2*byteLen)
	r.FillBytes(sigBytes[:byteLen])
	s.FillBytes(sigBytes[byteLen:])
	encoded := base64.RawURLEncoding.EncodeToString(sigBytes)

	// Verification must fail (wrong r, s for this message/key), but must NOT panic.
	proofs := &capability.IssuanceProofs{
		Signatures: []capability.IssuerSignature{
			{IssuerDID: "did:example:small", Algorithm: "ES256", Signature: encoded},
		},
	}
	resolver := &staticKeyResolver{keys: []gocrypto.PublicKey{key.Public()}}
	err = capability.VerifyCoSignatures(context.Background(), "msg", proofs, resolver)
	require.Error(t, err, "invalid r/s must fail, not panic")
}

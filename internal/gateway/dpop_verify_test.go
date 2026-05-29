// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Helper to create a valid DPoP proof JWT for testing.
func createTestDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, url string, iat time.Time) string {
	t.Helper()

	// Build JWK from public key.
	pubKey := key.PublicKey
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Pad to curve byte size.
	curveSize := (pubKey.Curve.Params().BitSize + 7) / 8
	xPadded := make([]byte, curveSize)
	yPadded := make([]byte, curveSize)
	copy(xPadded[curveSize-len(xBytes):], xBytes)
	copy(yPadded[curveSize-len(yBytes):], yBytes)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	jwkBytes, err := json.Marshal(jwk)
	require.NoError(t, err)

	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": json.RawMessage(jwkBytes),
	}

	payload := map[string]interface{}{
		"jti": "test-jti-" + fmt.Sprintf("%d", iat.UnixNano()),
		"htm": method,
		"htu": url,
		"iat": iat.Unix(),
	}

	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	require.NoError(t, err)

	// Encode signature as r||s with proper padding.
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, curveSize)
	sPadded := make([]byte, curveSize)
	copy(rPadded[curveSize-len(rBytes):], rBytes)
	copy(sPadded[curveSize-len(sBytes):], sBytes)

	sig := slices.Concat(rPadded, sPadded)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

func computeTestJKT(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	curveSize := (key.Curve.Params().BitSize + 7) / 8
	xPadded := make([]byte, curveSize)
	yPadded := make([]byte, curveSize)
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	copy(xPadded[curveSize-len(xBytes):], xBytes)
	copy(yPadded[curveSize-len(yBytes):], yBytes)

	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(xPadded),
		base64.RawURLEncoding.EncodeToString(yPadded),
	)
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestVerifyDPoPBinding_ValidProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now())

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.NoError(t, err)
}

func TestVerifyDPoPBinding_WrongKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a different key for the JKT.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &otherKey.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now())

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match token binding")
}

func TestVerifyDPoPBinding_WrongMethod(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "GET", "https://gateway.example.com/api/v1/enforce", time.Now())

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request method")
}

func TestVerifyDPoPBinding_WrongURL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://other.example.com/api/v1/enforce", time.Now())

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request URL")
}

func TestVerifyDPoPBinding_ExpiredProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now().Add(-10*time.Minute))

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestVerifyDPoPBinding_FutureProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now().Add(5*time.Minute))

	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestVerifyDPoPBinding_InvalidJWT(t *testing.T) {
	err := verifyDPoPBinding("not.a.valid-jwt-with-bad-base64", "jkt", "POST", "https://example.com")
	assert.Error(t, err)
}

func TestVerifyDPoPBinding_InvalidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now())

	// Tamper with the signature.
	parts := splitJWT(proof)
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("tampered"))
	tampered := parts[0] + "." + parts[1] + "." + parts[2]

	err = verifyDPoPBinding(tampered, jkt, "POST", "https://gateway.example.com/api/v1/enforce")
	assert.Error(t, err)
}

func TestComputeJWKThumbprint_EC(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`)
	thumbprint, err := computeJWKThumbprint(jwk)
	require.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
	// Thumbprint should be consistent.
	thumbprint2, _ := computeJWKThumbprint(jwk)
	assert.Equal(t, thumbprint, thumbprint2)
}

func TestComputeJWKThumbprint_RSA(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"RSA","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}`)
	thumbprint, err := computeJWKThumbprint(jwk)
	require.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
}

func TestComputeJWKThumbprint_InvalidKty(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"unknown"}`)
	_, err := computeJWKThumbprint(jwk)
	assert.Error(t, err)
}

func TestIsAllowedDPoPAlgorithm(t *testing.T) {
	allowed := []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}
	for _, alg := range allowed {
		assert.True(t, isAllowedDPoPAlgorithm(alg), "should allow %s", alg)
	}
	assert.False(t, isAllowedDPoPAlgorithm("HS256"))
	assert.False(t, isAllowedDPoPAlgorithm("none"))
}

func TestURLMatchesHTU(t *testing.T) {
	assert.True(t, urlMatchesHTU("https://example.com/api/v1/enforce", "https://example.com/api/v1/enforce"))
	assert.True(t, urlMatchesHTU("https://example.com/api/v1/enforce?foo=bar", "https://example.com/api/v1/enforce"))
	assert.True(t, urlMatchesHTU("https://EXAMPLE.com:443/api/v1/enforce", "https://example.com/api/v1/enforce"))
	assert.False(t, urlMatchesHTU("https://example.com/API/v1/enforce", "https://example.com/api/v1/enforce"))
	assert.False(t, urlMatchesHTU("https://example.com/api/v1/other", "https://example.com/api/v1/enforce"))
}

func TestVerifyECDSA_InvalidSignatureSize(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}

	err = verifyECDSA([]byte("test"), []byte("short"), "ES256", jwk)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature size mismatch")
}

func splitJWT(token string) []string {
	result := make([]string, 3)
	first := 0
	part := 0
	for i := 0; i < len(token) && part < 2; i++ {
		if token[i] == '.' {
			result[part] = token[first:i]
			part++
			first = i + 1
		}
	}
	result[2] = token[first:]
	return result
}

func TestVerifyDPoPBinding_URLWithQueryIgnored(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkt := computeTestJKT(t, &key.PublicKey)
	// Proof uses URL without query.
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now())

	// Request has query string — should still match (RFC 9449: htu excludes query).
	err = verifyDPoPBinding(proof, jkt, "POST", "https://gateway.example.com/api/v1/enforce?action=read")
	assert.NoError(t, err)
}

func TestVerifyECDSA_ValidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := []byte("test signing input")
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	require.NoError(t, err)

	curveSize := 32
	rPadded := make([]byte, curveSize)
	sPadded := make([]byte, curveSize)
	rB := r.Bytes()
	sB := s.Bytes()
	copy(rPadded[curveSize-len(rB):], rB)
	copy(sPadded[curveSize-len(sB):], sB)
	sig := slices.Concat(rPadded, sPadded)

	pubX := key.X.Bytes()
	pubY := key.Y.Bytes()
	xPadded := make([]byte, curveSize)
	yPadded := make([]byte, curveSize)
	copy(xPadded[curveSize-len(pubX):], pubX)
	copy(yPadded[curveSize-len(pubY):], pubY)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	err = verifyECDSA(msg, sig, "ES256", jwk)
	assert.NoError(t, err)
}

func TestVerifyECDSA_WrongSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	curveSize := 32
	pubX := key.X.Bytes()
	pubY := key.Y.Bytes()
	xPadded := make([]byte, curveSize)
	yPadded := make([]byte, curveSize)
	copy(xPadded[curveSize-len(pubX):], pubX)
	copy(yPadded[curveSize-len(pubY):], pubY)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	badSig := make([]byte, 64)
	_, _ = rand.Read(badSig)
	// Set r and s to valid-sized but incorrect values.
	r := new(big.Int).SetBytes(badSig[:32])
	s := new(big.Int).SetBytes(badSig[32:])
	rPadded := make([]byte, curveSize)
	sPadded := make([]byte, curveSize)
	rB := r.Bytes()
	sB := s.Bytes()
	copy(rPadded[curveSize-len(rB):], rB)
	copy(sPadded[curveSize-len(sB):], sB)
	sig := slices.Concat(rPadded, sPadded)

	err = verifyECDSA([]byte("test"), sig, "ES256", jwk)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestVerifyDPoP_CrossURLReplay (T-2): the same DPoP proof JWT (same jti) must be
// rejected when replayed to a different URL.  This validates the B-4 fix: replay
// detection uses the jti claim, not a hash of proof+method+URL.
//
// The attack scenario: when a capability token has no DPoP binding (no JKT in
// the cnf claim), verifyDPoPBinding is skipped.  The old composite-hash replay
// key (hash of proof+method+URL) allowed the same proof to be replayed to a
// different URL because the hash changed with the URL.  The fixed code stores
// only the jti, which is URL-independent, so cross-URL replay is detected.
func TestVerifyDPoP_CrossURLReplay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Proof was issued for URL_A.
	proof := createTestDPoPProof(t, key, "POST", "https://gateway.example.com/api/v1/enforce", time.Now())

	store := NewInMemoryDPoPStore(5 * time.Minute)
	app := &App{dpopStore: store}

	// Token has no DPoP binding (no JKT) — verifyDPoPBinding is skipped.
	// This is the scenario where replay protection is the only defence.
	claims := &capability.TokenPayload{}

	// First use: POST to /api/v1/enforce — should succeed; jti is stored.
	dpop1 := &capability.DPoPProof{
		Proof:      proof,
		HTTPMethod: "POST",
		HTTPURL:    "https://gateway.example.com/api/v1/enforce",
	}
	require.NoError(t, app.verifyDPoP(context.Background(), dpop1, claims))

	// Second use: same proof JWT replayed to a different URL — must be rejected
	// because the jti is already in the store, regardless of target URL.
	dpop2 := &capability.DPoPProof{
		Proof:      proof,
		HTTPMethod: "POST",
		HTTPURL:    "https://gateway.example.com/api/v1/OTHER",
	}
	err = app.verifyDPoP(context.Background(), dpop2, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay")
}

// TestParseDPoPJTI_Valid ensures parseDPoPJTI correctly extracts the jti claim.
func TestParseDPoPJTI_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	proof := createTestDPoPProof(t, key, "POST", "https://example.com/api", time.Now())
	jti, err := parseDPoPJTI(proof)
	require.NoError(t, err)
	assert.NotEmpty(t, jti)
}

// TestParseDPoPJTI_InvalidJWT ensures parseDPoPJTI rejects malformed JWTs.
func TestParseDPoPJTI_InvalidJWT(t *testing.T) {
	_, err := parseDPoPJTI("not-a-jwt")
	assert.Error(t, err)
}

func TestVerifyRSA_ExponentOutOfRange(t *testing.T) {
	// A minimal valid RSA modulus (just for parsing; we never reach signature verification).
	nBytes := make([]byte, 256) // 2048-bit modulus placeholder
	nBytes[0] = 0x80            // ensure high bit is set

	tests := []struct {
		name    string
		eBytes  []byte
		wantErr string
	}{
		{
			name:    "exponent exceeds MaxInt32",
			eBytes:  []byte{0x01, 0x00, 0x00, 0x00, 0x01}, // 2^32 + 1 > MaxInt32
			wantErr: "exponent out of safe range",
		},
		{
			name:    "exponent does not fit in int64",
			eBytes:  []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // 2^64 + 1
			wantErr: "exponent out of safe range",
		},
		{
			name:    "exponent is zero",
			eBytes:  []byte{0x00},
			wantErr: "exponent out of safe range",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwk := map[string]interface{}{
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(tc.eBytes),
			}
			err := verifyRSA([]byte("signing input"), []byte("signature"), "RS256", jwk)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

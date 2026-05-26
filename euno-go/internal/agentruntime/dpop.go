// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DPoPProofGenerator generates DPoP proofs for proof-of-possession.
// It manages an ECDSA P-256 key pair and handles nonce rotation.
type DPoPProofGenerator struct {
	mu         sync.RWMutex
	privateKey *ecdsa.PrivateKey
	thumbprint string
	nonce      string
}

// NewDPoPProofGenerator creates a new DPoP proof generator with a fresh ECDSA P-256 key pair.
func NewDPoPProofGenerator() (*DPoPProofGenerator, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DPoP key pair: %w", err)
	}

	thumbprint, err := computeJWKThumbprint(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	return &DPoPProofGenerator{
		privateKey: privateKey,
		thumbprint: thumbprint,
	}, nil
}

// Thumbprint returns the JWK Thumbprint (RFC 7638) of the DPoP key.
// This is used as the "jkt" claim in capability tokens for key binding.
func (g *DPoPProofGenerator) Thumbprint() string {
	return g.thumbprint
}

// SetNonce updates the server-provided nonce for subsequent proofs.
func (g *DPoPProofGenerator) SetNonce(nonce string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nonce = nonce
}

// GenerateProof creates a DPoP proof JWT for the given HTTP method and URL.
func (g *DPoPProofGenerator) GenerateProof(httpMethod, httpURL string) (string, error) {
	g.mu.RLock()
	nonce := g.nonce
	g.mu.RUnlock()

	return g.generateProofWithNonce(httpMethod, httpURL, nonce)
}

func (g *DPoPProofGenerator) generateProofWithNonce(httpMethod, httpURL, nonce string) (string, error) {
	now := time.Now().Unix()
	jti := uuid.New().String()

	// Build JWK for header
	jwk := ecdsaPublicKeyToJWK(&g.privateKey.PublicKey)

	// Build header
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": jwk,
	}

	// Build claims
	claims := map[string]interface{}{
		"jti": jti,
		"htm": httpMethod,
		"htu": httpURL,
		"iat": now,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal DPoP header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal DPoP claims: %w", err)
	}

	// Encode header and payload
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Sign
	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, g.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}

	// Convert to fixed-size JOSE format (32 bytes each for P-256)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// ecdsaPublicKeyToJWK converts an ECDSA public key to a JWK map.
func ecdsaPublicKeyToJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	// P-256 coordinates are 32 bytes
	size := 32
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Pad to fixed size
	xPadded := make([]byte, size)
	yPadded := make([]byte, size)
	copy(xPadded[size-len(xBytes):], xBytes)
	copy(yPadded[size-len(yBytes):], yBytes)

	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

// computeJWKThumbprint computes the JWK Thumbprint (RFC 7638) for an ECDSA P-256 public key.
func computeJWKThumbprint(pub *ecdsa.PublicKey) (string, error) {
	// Per RFC 7638, the thumbprint input is the lexicographically sorted
	// required members for the key type.
	// For EC keys: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
	size := 32
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPadded := make([]byte, size)
	yPadded := make([]byte, size)
	copy(xPadded[size-len(xBytes):], xBytes)
	copy(yPadded[size-len(yBytes):], yBytes)

	thumbprintInput := fmt.Sprintf(
		`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(xPadded),
		base64.RawURLEncoding.EncodeToString(yPadded),
	)

	hash := sha256.Sum256([]byte(thumbprintInput))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// VerifyDPoPProof verifies a DPoP proof JWT signature and returns the claims.
// This is primarily for testing; the gateway performs verification in production.
func VerifyDPoPProof(proof string) (map[string]interface{}, error) {
	parts := splitJWT(proof)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid DPoP proof: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode DPoP header: %w", err)
	}

	var header struct {
		Typ string                 `json:"typ"`
		Alg string                 `json:"alg"`
		JWK map[string]interface{} `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshal DPoP header: %w", err)
	}

	if header.Typ != "dpop+jwt" {
		return nil, fmt.Errorf("invalid DPoP type: %q", header.Typ)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported DPoP algorithm: %q", header.Alg)
	}

	// Extract public key from JWK
	pubKey, err := jwkToECDSAPublicKey(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("extract DPoP public key: %w", err)
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode DPoP signature: %w", err)
	}

	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("invalid DPoP signature length: %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return nil, fmt.Errorf("DPoP signature verification failed")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode DPoP claims: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal DPoP claims: %w", err)
	}

	return claims, nil
}

// ThumbprintFromProof extracts the JWK Thumbprint from a DPoP proof.
func ThumbprintFromProof(proof string) (string, error) {
	parts := splitJWT(proof)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid DPoP proof: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode DPoP header: %w", err)
	}

	var header struct {
		JWK map[string]interface{} `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("unmarshal DPoP header: %w", err)
	}

	pubKey, err := jwkToECDSAPublicKey(header.JWK)
	if err != nil {
		return "", fmt.Errorf("extract public key: %w", err)
	}

	return computeJWKThumbprint(pubKey)
}

func jwkToECDSAPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)

	if kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %q", kty)
	}
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %q", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}


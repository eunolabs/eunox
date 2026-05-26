// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// verifyWithJWK verifies a JWT signature given the raw signing input, signature
// bytes, algorithm, and the JWK as raw JSON. This avoids pulling in go-jose for
// just signature verification and keeps the dependency minimal.
func verifyWithJWK(signingInput, signature []byte, alg string, jwkRaw json.RawMessage) error {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkRaw, &jwk); err != nil {
		return fmt.Errorf("JWK parse error: %w", err)
	}

	kty, _ := jwk["kty"].(string)

	switch {
	case kty == "EC" && (alg == "ES256" || alg == "ES384" || alg == "ES512"):
		return verifyECDSA(signingInput, signature, alg, jwk)
	case kty == "RSA" && (alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "PS256" || alg == "PS384" || alg == "PS512"):
		return verifyRSA(signingInput, signature, alg, jwk)
	case kty == "OKP" && alg == "EdDSA":
		return verifyEdDSA(signingInput, signature, jwk)
	default:
		return fmt.Errorf("unsupported kty/alg combination: %s/%s", kty, alg)
	}
}

func verifyECDSA(signingInput, signature []byte, alg string, jwk map[string]interface{}) error {
	var curve elliptic.Curve
	var hashFunc crypto.Hash
	switch alg {
	case "ES256":
		curve = elliptic.P256()
		hashFunc = crypto.SHA256
	case "ES384":
		curve = elliptic.P384()
		hashFunc = crypto.SHA384
	case "ES512":
		curve = elliptic.P521()
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported EC algorithm: %s", alg)
	}

	xBytes, err := base64URLDecode(jwk["x"])
	if err != nil {
		return fmt.Errorf("EC JWK x decode error: %w", err)
	}
	yBytes, err := base64URLDecode(jwk["y"])
	if err != nil {
		return fmt.Errorf("EC JWK y decode error: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// ECDSA signature in JWS is r||s, each component is curveByteSize.
	keySize := (curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("ECDSA signature size mismatch: got %d, expected %d", len(signature), 2*keySize)
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

func verifyRSA(signingInput, signature []byte, alg string, jwk map[string]interface{}) error {
	nBytes, err := base64URLDecode(jwk["n"])
	if err != nil {
		return fmt.Errorf("RSA JWK n decode error: %w", err)
	}
	eBytes, err := base64URLDecode(jwk["e"])
	if err != nil {
		return fmt.Errorf("RSA JWK e decode error: %w", err)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	var hashFunc crypto.Hash
	switch alg {
	case "RS256", "PS256":
		hashFunc = crypto.SHA256
	case "RS384", "PS384":
		hashFunc = crypto.SHA384
	case "RS512", "PS512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	switch alg {
	case "RS256", "RS384", "RS512":
		return rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, signature)
	case "PS256", "PS384", "PS512":
		return rsa.VerifyPSS(pubKey, hashFunc, digest, signature, nil)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifyEdDSA(signingInput, signature []byte, jwk map[string]interface{}) error {
	xBytes, err := base64URLDecode(jwk["x"])
	if err != nil {
		return fmt.Errorf("OKP JWK x decode error: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("EdDSA key size mismatch: got %d, expected %d", len(xBytes), ed25519.PublicKeySize)
	}

	pubKey := ed25519.PublicKey(xBytes)
	if !ed25519.Verify(pubKey, signingInput, signature) {
		return errors.New("EdDSA signature verification failed")
	}
	return nil
}

func base64URLDecode(v interface{}) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("expected string value")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

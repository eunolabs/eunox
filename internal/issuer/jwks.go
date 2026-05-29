// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/eunolabs/eunox/pkg/crypto"
)

// buildJWKS constructs a JWKS JSON response from a slice of PublicKeyInfo.
func buildJWKS(keys []PublicKeyInfo) map[string]interface{} {
	jwksKeys := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		jwk := publicKeyToJWK(k)
		if jwk != nil {
			jwksKeys = append(jwksKeys, jwk)
		}
	}
	return map[string]interface{}{
		"keys": jwksKeys,
	}
}

// buildDIDDocument constructs a DID document from the issuer DID and public keys.
func buildDIDDocument(did string, keys []PublicKeyInfo) map[string]interface{} {
	verificationMethods := make([]map[string]interface{}, 0, len(keys))
	verificationIDs := make([]string, 0, len(keys))

	for i, k := range keys {
		methodID := did + "#key-" + itoa(i)
		verificationIDs = append(verificationIDs, methodID)
		method := map[string]interface{}{
			"id":           methodID,
			"type":         "JsonWebKey2020",
			"controller":   did,
			"publicKeyJwk": publicKeyToJWK(k),
		}
		verificationMethods = append(verificationMethods, method)
	}

	return map[string]interface{}{
		"@context":             []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":                   did,
		"verificationMethod":   verificationMethods,
		"authentication":       verificationIDs,
		"assertionMethod":      verificationIDs,
		"capabilityDelegation": verificationIDs,
		"capabilityInvocation": verificationIDs,
	}
}

// publicKeyToJWK converts a public key to its JWK representation.
func publicKeyToJWK(k PublicKeyInfo) map[string]interface{} {
	switch pub := k.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsaToJWK(k.KeyID, k.Algorithm, pub)
	case *ecdsa.PublicKey:
		return ecdsaToJWK(k.KeyID, k.Algorithm, pub)
	case ed25519.PublicKey:
		return ed25519ToJWK(k.KeyID, pub)
	default:
		return nil
	}
}

func rsaToJWK(kid string, alg crypto.Algorithm, pub *rsa.PublicKey) map[string]interface{} {
	algStr := string(alg)
	if algStr == "" {
		algStr = "RS256"
	}
	return map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": algStr,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecdsaToJWK(kid string, alg crypto.Algorithm, pub *ecdsa.PublicKey) map[string]interface{} {
	crv := "P-256"
	algStr := "ES256"
	size := 32
	switch pub.Curve {
	case elliptic.P384():
		crv = "P-384"
		algStr = "ES384"
		size = 48
	case elliptic.P521():
		crv = "P-521"
		algStr = "ES512"
		size = 66
	}
	if alg != "" {
		algStr = string(alg)
	}

	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	// Pad to curve size
	x = padBytes(x, size)
	y = padBytes(y, size)

	return map[string]interface{}{
		"kty": "EC",
		"kid": kid,
		"use": "sig",
		"alg": algStr,
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

func ed25519ToJWK(kid string, pub ed25519.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"kty": "OKP",
		"kid": kid,
		"use": "sig",
		"alg": "EdDSA",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i)) //nolint:gosec // G115: i is bounded [0,9]
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

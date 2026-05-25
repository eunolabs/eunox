// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package did

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// KeyResolver resolves did:key DIDs by decoding the key material from the DID URI itself.
type KeyResolver struct{}

// NewKeyResolver creates a did:key resolver.
func NewKeyResolver() *KeyResolver {
	return &KeyResolver{}
}

// Multicodec prefixes for supported key types.
const (
	// ed25519-pub multicodec (0xed).
	multicodecEd25519 = 0xed
	// p256-pub multicodec (0x1200).
	multicodecP256 = 0x1200
)

// Resolve resolves a did:key DID by decoding the embedded public key.
func (r *KeyResolver) Resolve(_ context.Context, did string) (*Document, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, fmt.Errorf("invalid did:key URI: %q", did)
	}

	multibaseKey := did[len("did:key:"):]
	if multibaseKey == "" {
		return nil, errors.New("invalid did:key: empty key material")
	}

	keyBytes, err := decodeMultibase(multibaseKey)
	if err != nil {
		return nil, fmt.Errorf("decode did:key multibase: %w", err)
	}

	keyType, pubKeyBytes, err := decodeMulticodec(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decode did:key multicodec: %w", err)
	}

	vm, err := buildVerificationMethod(did, keyType, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	doc := &Document{
		Context: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		ID:      did,
		VerificationMethod: []VerificationMethod{
			vm,
		},
		Authentication:  []string{did + "#" + multibaseKey},
		AssertionMethod: []string{did + "#" + multibaseKey},
	}

	return doc, nil
}

// decodeMultibase decodes a multibase-encoded string. Supports base58btc (z prefix).
func decodeMultibase(s string) ([]byte, error) {
	if len(s) < 2 {
		return nil, errors.New("multibase string too short")
	}

	prefix := s[0]
	switch prefix {
	case 'z':
		return base58Decode(s[1:])
	default:
		return nil, fmt.Errorf("unsupported multibase prefix: %c", prefix)
	}
}

// decodeMulticodec extracts the key type and raw key bytes from multicodec-prefixed data.
func decodeMulticodec(data []byte) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, errors.New("multicodec data too short")
	}

	// Read varint-encoded codec.
	codec, bytesRead := decodeUvarint(data)

	switch codec {
	case multicodecEd25519:
		keyBytes := data[bytesRead:]
		if len(keyBytes) != ed25519.PublicKeySize {
			return "", nil, fmt.Errorf("ed25519 key must be %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
		}
		return "Ed25519", keyBytes, nil
	case multicodecP256:
		keyBytes := data[bytesRead:]
		if len(keyBytes) != 33 {
			return "", nil, fmt.Errorf("P-256 compressed key must be 33 bytes, got %d", len(keyBytes))
		}
		return "P-256", keyBytes, nil
	default:
		return "", nil, fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
}

// decodeUvarint reads an unsigned varint from a byte slice.
func decodeUvarint(data []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range data {
		if i >= 10 {
			return 0, 0
		}
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

func buildVerificationMethod(did, keyType string, keyBytes []byte) (VerificationMethod, error) {
	multibaseKey := did[len("did:key:"):]
	vmID := did + "#" + multibaseKey

	switch keyType {
	case "Ed25519":
		x := base64.RawURLEncoding.EncodeToString(keyBytes)
		return VerificationMethod{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: did,
			PublicKeyJwk: &JWK{
				Kty: "OKP",
				Crv: "Ed25519",
				X:   x,
			},
		}, nil
	case "P-256":
		// Decompress the point.
		curve := elliptic.P256()
		xCoord, yCoord := elliptic.UnmarshalCompressed(curve, keyBytes)
		if xCoord == nil {
			return VerificationMethod{}, errors.New("invalid P-256 compressed point")
		}
		xEnc := base64.RawURLEncoding.EncodeToString(xCoord.Bytes())
		yEnc := base64.RawURLEncoding.EncodeToString(yCoord.Bytes())
		return VerificationMethod{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: did,
			PublicKeyJwk: &JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   xEnc,
				Y:   yEnc,
			},
		}, nil
	default:
		return VerificationMethod{}, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// ExtractPublicKey extracts the crypto.PublicKey from a VerificationMethod.
func (vm *VerificationMethod) ExtractPublicKey() (interface{}, error) {
	// Try PublicKeyJwk first.
	if vm.PublicKeyJwk != nil {
		return extractFromJWK(vm.PublicKeyJwk)
	}

	// Try PublicKeyMultibase.
	if vm.PublicKeyMultibase != "" {
		return extractFromMultibase(vm.PublicKeyMultibase)
	}

	return nil, errors.New("no publicKeyJwk or publicKeyMultibase in verification method")
}

// extractFromJWK converts a JWK to a crypto.PublicKey.
func extractFromJWK(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("decode Ed25519 x: %w", err)
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key size: %d", len(xBytes))
		}
		return ed25519.PublicKey(xBytes), nil

	case "EC":
		switch jwk.Crv {
		case "P-256":
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, fmt.Errorf("decode P-256 x: %w", err)
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err != nil {
				return nil, fmt.Errorf("decode P-256 y: %w", err)
			}
			return &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}, nil
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// extractFromMultibase extracts a public key from a multibase+multicodec encoded string.
func extractFromMultibase(multibase string) (interface{}, error) {
	decoded, err := decodeMultibase(multibase)
	if err != nil {
		return nil, fmt.Errorf("decode multibase: %w", err)
	}

	keyType, keyBytes, err := decodeMulticodec(decoded)
	if err != nil {
		return nil, fmt.Errorf("decode multicodec: %w", err)
	}

	switch keyType {
	case "Ed25519":
		return ed25519.PublicKey(keyBytes), nil
	case "P-256":
		// P-256 keys from did:key are typically compressed (33 bytes).
		curve := elliptic.P256()
		var xCoord, yCoord *big.Int
		if len(keyBytes) == 33 {
			xCoord, yCoord = elliptic.UnmarshalCompressed(curve, keyBytes)
		} else {
			//nolint:staticcheck // elliptic.Unmarshal needed for uncompressed point decoding
			xCoord, yCoord = elliptic.Unmarshal(curve, keyBytes)
		}
		if xCoord == nil {
			return nil, errors.New("invalid P-256 public key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: xCoord, Y: yCoord}, nil
	default:
		return nil, fmt.Errorf("unsupported key type from multicodec: %s", keyType)
	}
}

// base58Decode decodes a base58btc (Bitcoin alphabet) encoded string.
func base58Decode(s string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, ch := range s {
		idx := strings.IndexRune(alphabet, ch)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %c", ch)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}

	resultBytes := result.Bytes()

	// Count leading zeros.
	var numZeros int
	for _, ch := range s {
		if ch == '1' {
			numZeros++
		} else {
			break
		}
	}

	// Prepend zero bytes for leading '1' characters.
	if numZeros > 0 {
		padding := make([]byte, numZeros)
		resultBytes = append(padding, resultBytes...)
	}

	return resultBytes, nil
}

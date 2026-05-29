// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// dpopMaxClockSkew is the maximum allowed clock skew for DPoP proof timestamps.
const dpopMaxClockSkew = 60 * time.Second

// dpopMaxAge is the maximum age of a DPoP proof (5 minutes per RFC 9449 recommendation).
const dpopMaxAge = 5 * time.Minute

// dpopHeader is the parsed JOSE header from a DPoP proof JWT.
type dpopHeader struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

// dpopPayload is the parsed claims from a DPoP proof JWT.
type dpopPayload struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"` // HTTP method
	HTU string `json:"htu"` // HTTP URI
	IAT int64  `json:"iat"` // Issued at (Unix seconds)
}

// verifyDPoPBinding verifies a DPoP proof JWT and checks that the JWK
// thumbprint matches the token's confirmation JKT claim (RFC 9449 §4.3).
//
// Verification steps:
//  1. Parse JWT header — must have typ=dpop+jwt and include a jwk
//  2. Compute JWK Thumbprint (RFC 7638) using SHA-256
//  3. Compare thumbprint with token's cnf.jkt (base64url, no padding)
//  4. Parse JWT payload — check htm matches request HTTP method, htu matches URL
//  5. Validate iat is within acceptable time window
//  6. Verify JWT signature using the embedded JWK
func verifyDPoPBinding(proofJWT, expectedJKT, httpMethod, httpURL string) error {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return errors.New("DPoP proof is not a valid JWT (expected 3 parts)")
	}

	// 1. Parse header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("DPoP proof header decode error: %w", err)
	}

	var header dpopHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("DPoP proof header parse error: %w", err)
	}

	if !strings.EqualFold(header.Typ, "dpop+jwt") {
		return fmt.Errorf("DPoP proof typ must be 'dpop+jwt', got %q", header.Typ)
	}

	if len(header.JWK) == 0 {
		return errors.New("DPoP proof header missing 'jwk' field")
	}

	// Validate algorithm is acceptable (ES256, ES384, ES512, RS256 are common).
	if !isAllowedDPoPAlgorithm(header.Alg) {
		return fmt.Errorf("DPoP proof uses unsupported algorithm %q", header.Alg)
	}

	// 2. Compute JWK Thumbprint (RFC 7638).
	thumbprint, err := computeJWKThumbprint(header.JWK)
	if err != nil {
		return fmt.Errorf("DPoP JWK thumbprint computation failed: %w", err)
	}

	// 3. Compare with expected JKT.
	if thumbprint != expectedJKT {
		return errors.New("DPoP proof JWK thumbprint does not match token binding (cnf.jkt)")
	}

	// 4. Parse payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("DPoP proof payload decode error: %w", err)
	}

	var payload dpopPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("DPoP proof payload parse error: %w", err)
	}

	if payload.JTI == "" {
		return errors.New("DPoP proof missing required 'jti' claim")
	}

	if !strings.EqualFold(payload.HTM, httpMethod) {
		return fmt.Errorf("DPoP proof htm %q does not match request method %q", payload.HTM, httpMethod)
	}

	if !urlMatchesHTU(httpURL, payload.HTU) {
		return fmt.Errorf("DPoP proof htu %q does not match request URL", payload.HTU)
	}

	// 5. Validate iat.
	now := time.Now()
	iat := time.Unix(payload.IAT, 0)
	if payload.IAT == 0 {
		return errors.New("DPoP proof missing required 'iat' claim")
	}
	if now.Sub(iat) > dpopMaxAge {
		return fmt.Errorf("DPoP proof is too old (issued %v ago, max %v)", now.Sub(iat).Round(time.Second), dpopMaxAge)
	}
	if iat.After(now.Add(dpopMaxClockSkew)) {
		return errors.New("DPoP proof iat is in the future (clock skew exceeds maximum)")
	}

	// 6. Signature verification.
	// We verify the JWT signature using the embedded JWK to confirm that
	// the presenter holds the private key corresponding to the public JWK.
	if err := verifyDPoPSignature(parts[0]+"."+parts[1], parts[2], header.Alg, header.JWK); err != nil {
		return fmt.Errorf("DPoP proof signature verification failed: %w", err)
	}

	return nil
}

// computeJWKThumbprint implements RFC 7638 JWK Thumbprint using SHA-256.
// It normalizes the JWK to its canonical form (only required members, sorted).
func computeJWKThumbprint(jwkRaw json.RawMessage) (string, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkRaw, &jwk); err != nil {
		return "", fmt.Errorf("invalid JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	if kty == "" {
		return "", errors.New("JWK missing required 'kty' field")
	}

	// RFC 7638 §3.2: canonical form includes only required members for each kty.
	var canonical string
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return "", errors.New("EC JWK missing required fields (crv, x, y)")
		}
		//nolint:gocritic // canonical JWK thumbprint format
		canonical = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return "", errors.New("RSA JWK missing required fields (e, n)")
		}
		//nolint:gocritic // canonical JWK thumbprint format
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	case "OKP":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		if crv == "" || x == "" {
			return "", errors.New("OKP JWK missing required fields (crv, x)")
		}
		//nolint:gocritic // canonical JWK thumbprint format
		canonical = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, crv, x)
	default:
		return "", fmt.Errorf("unsupported JWK key type: %s", kty)
	}

	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// isAllowedDPoPAlgorithm checks if the algorithm is acceptable for DPoP proofs.
func isAllowedDPoPAlgorithm(alg string) bool {
	switch alg {
	case "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA":
		return true
	default:
		return false
	}
}

// urlMatchesHTU checks if the request URL matches the DPoP htu claim.
// Per RFC 9449, htu contains the HTTP URI without query and fragment.
func urlMatchesHTU(requestURL, htu string) bool {
	reqParsed, err := normalizeDPoPURL(requestURL)
	if err != nil {
		return false
	}
	htuParsed, err := normalizeDPoPURL(htu)
	if err != nil {
		return false
	}

	if !strings.EqualFold(reqParsed.Scheme, htuParsed.Scheme) {
		return false
	}
	if !strings.EqualFold(normalizeHostPort(reqParsed), normalizeHostPort(htuParsed)) {
		return false
	}

	return normalizedPath(reqParsed) == normalizedPath(htuParsed)
}

func normalizeDPoPURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed, nil
}

func normalizeHostPort(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch {
	case port == "":
		return host
	case strings.EqualFold(u.Scheme, "http") && port == "80":
		return host
	case strings.EqualFold(u.Scheme, "https") && port == "443":
		return host
	default:
		return host + ":" + port
	}
}

func normalizedPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// verifyDPoPSignature verifies the JWT signature using the embedded JWK.
func verifyDPoPSignature(signingInput, signatureB64, alg string, jwkRaw json.RawMessage) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("signature decode error: %w", err)
	}

	// Use the embedded JWK with the local verifier to validate the signature.
	return verifyWithJWK([]byte(signingInput), sigBytes, alg, jwkRaw)
}

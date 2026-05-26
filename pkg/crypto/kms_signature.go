// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

// normalizeKMSSignature converts a signature from the format returned by a KMS
// provider into the JOSE-canonical format expected by consumers.
//
// For RSA and PSS algorithms, signatures are already in the correct format
// (raw PKCS#1 v1.5 or PSS bytes). For ECDSA algorithms, the KMS may return
// DER/ASN.1-encoded signatures which must be converted to the fixed-size
// R||S concatenation used by JOSE (RFC 7518 §3.4).
func normalizeKMSSignature(alg Algorithm, raw []byte) ([]byte, error) {
	switch alg {
	case ES256:
		return ecdsaSignatureToJOSE(raw, 32)
	case ES384:
		return ecdsaSignatureToJOSE(raw, 48)
	case ES512:
		return ecdsaSignatureToJOSE(raw, 66)
	default:
		// RSA, PSS: raw bytes are already in the correct format.
		return raw, nil
	}
}

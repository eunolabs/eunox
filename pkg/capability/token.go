// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

// SchemaVersion and TokenSchemaVersion identify the current capability token schema.
const (
	SchemaVersion      = "1.0"
	TokenSchemaVersion = "1.0"
)

// SupportedSchemaVersions contains the schema versions accepted by this package.
var SupportedSchemaVersions = map[string]bool{"1.0": true}

// TokenPayload mirrors JWT claims for capability tokens.
type TokenPayload struct {
	Issuer             string                `json:"iss"`
	Subject            string                `json:"sub"`
	Audience           string                `json:"aud"`
	IssuedAt           int64                 `json:"iat"`
	ExpiresAt          int64                 `json:"exp"`
	JWTID              string                `json:"jti"`
	SchemaVersion      string                `json:"schemaVersion"`
	Capabilities       []Constraint          `json:"capabilities"`
	ParentCapabilityID string                `json:"parentCapabilityId,omitempty"`
	AuthorizedBy       *AuthorizedBy         `json:"authorizedBy,omitempty"`
	VC                 *VerifiableCredential `json:"vc,omitempty"`
	Region             string                `json:"region,omitempty"`
	PolicyHash         string                `json:"policyHash,omitempty"`
	Confirmation       *Confirmation         `json:"cnf,omitempty"`
	Proofs             *IssuanceProofs       `json:"proofs,omitempty"`
}

// AuthorizedBy describes the end user and roles that authorized issuance.
type AuthorizedBy struct {
	UserID   string   `json:"userId"`
	Roles    []string `json:"roles"`
	TenantID string   `json:"tenantId,omitempty"`
}

// VerifiableCredential embeds a verifiable credential alongside the token.
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	ID                string                 `json:"id,omitempty"`
	Type              []string               `json:"type"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
}

// Confirmation binds the token to proof-of-possession material.
type Confirmation struct {
	JKT string `json:"jkt"`
}

// IssuerSignature records a single co-issuer's signature over the JWT compact serialization
// of the token that carries this proof. Verification MUST use [VerifyCoSignatures].
type IssuerSignature struct {
	// IssuerDID is the decentralised identifier of the co-issuer.
	IssuerDID string `json:"issuerDid"`
	// Algorithm identifies the signature algorithm (e.g. "ES256", "EdDSA").
	// Accepted values mirror JWS algorithm identifiers.
	Algorithm string `json:"algorithm"`
	// Signature is the base64url-encoded (no padding) signature bytes.
	// The encoding follows JWS conventions: IEEE P1363 (r‖s) for ECDSA, raw bytes for RSA and EdDSA.
	Signature string `json:"signature"`
	// IssuedAt is the Unix timestamp at which this co-issuer signed the token.
	IssuedAt int64 `json:"issuedAt,omitempty"`
}

// IssuanceProofs carries optional multi-issuer co-signature material for cross-org delegation.
//
// # Enforcement contract
//
// When this field is nil or the Signatures slice is empty, co-signature verification is
// skipped and the token is evaluated using the primary issuer's signature alone.
//
// When Signatures is non-empty, ALL co-signatures MUST be verified before a token is
// considered valid. Enforcement code must call [VerifyCoSignatures] on every token that
// carries a non-empty Proofs field. Skipping co-signature verification for non-empty proofs
// is a security defect.
//
// This is NOT purely decorative metadata: the presence of co-signatures changes the
// verification requirements for the token.
type IssuanceProofs struct {
	Signatures []IssuerSignature `json:"signatures,omitempty"`
}

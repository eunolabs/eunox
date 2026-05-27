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

// IssuerSignature records a single issuer's signature over the token payload.
type IssuerSignature struct {
	// IssuerDID is the decentralised identifier of the co-issuer.
	IssuerDID string `json:"issuerDid"`
	// Algorithm identifies the signature algorithm (e.g. "ES256", "EdDSA").
	Algorithm string `json:"algorithm"`
	// Signature is the base64url-encoded signature bytes.
	Signature string `json:"signature"`
	// IssuedAt is the Unix timestamp at which this co-issuer signed the token.
	IssuedAt int64 `json:"issuedAt,omitempty"`
}

// IssuanceProofs carries optional multi-issuer proof material.
// Each entry corresponds to a co-issuer that has independently signed the token payload.
type IssuanceProofs struct {
	Signatures []IssuerSignature `json:"signatures,omitempty"`
}

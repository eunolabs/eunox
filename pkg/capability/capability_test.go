// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package capability tests capability token JSON models and related payload types.
package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenPayloadRoundTrip(t *testing.T) {
	strict := true
	maxItems := 5
	payload := TokenPayload{
		Issuer:        "issuer-1",
		Subject:       "subject-1",
		Audience:      "audience-1",
		IssuedAt:      1710000000,
		ExpiresAt:     1710003600,
		JWTID:         "jti-1",
		SchemaVersion: SchemaVersion,
		Capabilities: []Constraint{{
			Resource: "tool:sql",
			Actions:  []string{"query", "read"},
			ArgumentSchema: &ArgumentSchema{
				Type: SchemaType{Single: "object"},
				Properties: map[string]*ArgumentSchema{
					"statement": {
						Type:        SchemaType{Single: "string"},
						Description: "SQL statement",
					},
					"limit": {
						Type: SchemaType{Multiple: []string{"integer", "null"}},
					},
				},
				Required:             []string{"statement"},
				AdditionalProperties: boolPtr(false),
				MaxItems:             &maxItems,
				Strict:               &strict,
			},
			Conditions: []Condition{
				TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2025-12-31T23:59:59Z"},
				IPRangeCondition{CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}},
				AllowedOperationsCondition{Operations: []string{"select", "insert"}},
				AllowedExtensionsCondition{Extensions: []string{".sql", ".psql"}},
				AllowedTablesCondition{Tables: []string{"users", "orders"}, Columns: map[string][]string{"users": {"id", "email"}}},
				MaxCallsCondition{Count: 10, WindowSeconds: 60},
				RecipientDomainCondition{Domains: []string{"example.com", "eunolabs.ai"}},
				RedactFieldsCondition{Fields: []string{"ssn", "secret"}},
				PolicyCondition{Backend: "opa", Config: map[string]interface{}{"bundle": "main"}, Input: map[string]interface{}{"tenantId": "t-1"}},
				CustomCondition{Name: "geoFence", Config: map[string]interface{}{"region": "eu-west-1"}},
			},
		}},
		ParentCapabilityID: "parent-1",
		AuthorizedBy: &AuthorizedBy{
			UserID:   "user-1",
			Roles:    []string{"admin", "operator"},
			TenantID: "tenant-1",
		},
		VC: &VerifiableCredential{
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			ID:      "vc-1",
			Type:    []string{"VerifiableCredential", "CapabilityCredential"},
			CredentialSubject: map[string]interface{}{
				"id":       "did:example:123",
				"verified": true,
			},
		},
		Region:       "us-east-1",
		PolicyHash:   "abc123",
		Confirmation: &Confirmation{JKT: "thumbprint"},
		Proofs:       &IssuanceProofs{},
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"schemaVersion":"1.0"`)
	assert.Contains(t, string(data), `"type":"timeWindow"`)
	assert.Contains(t, string(data), `"type":"custom"`)

	var decoded TokenPayload
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, payload.Issuer, decoded.Issuer)
	assert.Equal(t, payload.Subject, decoded.Subject)
	assert.Equal(t, payload.Audience, decoded.Audience)
	assert.Equal(t, payload.IssuedAt, decoded.IssuedAt)
	assert.Equal(t, payload.ExpiresAt, decoded.ExpiresAt)
	assert.Equal(t, payload.JWTID, decoded.JWTID)
	assert.Equal(t, payload.SchemaVersion, decoded.SchemaVersion)
	assert.Equal(t, payload.ParentCapabilityID, decoded.ParentCapabilityID)
	require.NotNil(t, decoded.AuthorizedBy)
	assert.Equal(t, payload.AuthorizedBy, decoded.AuthorizedBy)
	require.NotNil(t, decoded.VC)
	assert.Equal(t, payload.VC.Context, decoded.VC.Context)
	assert.Equal(t, payload.VC.Type, decoded.VC.Type)
	assert.Equal(t, payload.VC.CredentialSubject["id"], decoded.VC.CredentialSubject["id"])
	assert.Equal(t, payload.VC.CredentialSubject["verified"], decoded.VC.CredentialSubject["verified"])
	assert.Equal(t, payload.Region, decoded.Region)
	assert.Equal(t, payload.PolicyHash, decoded.PolicyHash)
	require.NotNil(t, decoded.Confirmation)
	assert.Equal(t, payload.Confirmation, decoded.Confirmation)
	require.NotNil(t, decoded.Proofs)
	require.Len(t, decoded.Capabilities, 1)
	require.Len(t, decoded.Capabilities[0].Conditions, 10)
	assert.IsType(t, &TimeWindowCondition{}, decoded.Capabilities[0].Conditions[0])
	assert.IsType(t, &CustomCondition{}, decoded.Capabilities[0].Conditions[9])
}

func TestConditionRoundTripByType(t *testing.T) {
	tests := []struct {
		name       string
		condition  Condition
		wantType   string
		assertFunc func(*testing.T, Condition)
	}{
		{
			name:      "time window",
			condition: TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2025-12-31T23:59:59Z"},
			wantType:  ConditionTypeTimeWindow,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*TimeWindowCondition)
				assert.Equal(t, "2025-01-01T00:00:00Z", typed.NotBefore)
				assert.Equal(t, "2025-12-31T23:59:59Z", typed.NotAfter)
			},
		},
		{
			name:      "ip range",
			condition: IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			wantType:  ConditionTypeIPRange,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"10.0.0.0/8"}, condition.(*IPRangeCondition).CIDRs)
			},
		},
		{
			name:      "allowed operations",
			condition: AllowedOperationsCondition{Operations: []string{"read", "write"}},
			wantType:  ConditionTypeAllowedOperations,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"read", "write"}, condition.(*AllowedOperationsCondition).Operations)
			},
		},
		{
			name:      "allowed extensions",
			condition: AllowedExtensionsCondition{Extensions: []string{".txt", ".csv"}},
			wantType:  ConditionTypeAllowedExtensions,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{".txt", ".csv"}, condition.(*AllowedExtensionsCondition).Extensions)
			},
		},
		{
			name:      "allowed tables",
			condition: AllowedTablesCondition{Tables: []string{"users"}, Columns: map[string][]string{"users": {"id", "name"}}},
			wantType:  ConditionTypeAllowedTables,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*AllowedTablesCondition)
				assert.Equal(t, []string{"users"}, typed.Tables)
				assert.Equal(t, []string{"id", "name"}, typed.Columns["users"])
			},
		},
		{
			name:      "max calls",
			condition: MaxCallsCondition{Count: 42, WindowSeconds: 300},
			wantType:  ConditionTypeMaxCalls,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*MaxCallsCondition)
				assert.Equal(t, 42, typed.Count)
				assert.Equal(t, 300, typed.WindowSeconds)
			},
		},
		{
			name:      "recipient domain",
			condition: RecipientDomainCondition{Domains: []string{"example.com"}},
			wantType:  ConditionTypeRecipientDomain,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"example.com"}, condition.(*RecipientDomainCondition).Domains)
			},
		},
		{
			name:      "redact fields",
			condition: RedactFieldsCondition{Fields: []string{"secret"}},
			wantType:  ConditionTypeRedactFields,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"secret"}, condition.(*RedactFieldsCondition).Fields)
			},
		},
		{
			name:      "policy",
			condition: PolicyCondition{Backend: "opa", Config: map[string]interface{}{"bundle": "main"}, Input: map[string]interface{}{"team": "infra"}},
			wantType:  ConditionTypePolicy,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*PolicyCondition)
				assert.Equal(t, "opa", typed.Backend)
				assert.Equal(t, "main", typed.Config.(map[string]interface{})["bundle"])
				assert.Equal(t, "infra", typed.Input.(map[string]interface{})["team"])
			},
		},
		{
			name:      "custom",
			condition: CustomCondition{Name: "labelMatch", Config: map[string]interface{}{"label": "trusted"}},
			wantType:  ConditionTypeCustom,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*CustomCondition)
				assert.Equal(t, "labelMatch", typed.Name)
				assert.Equal(t, "trusted", typed.Config.(map[string]interface{})["label"])
			},
		},
		{
			name:      "allowed values",
			condition: AllowedValuesCondition{Argument: "format", Values: []interface{}{"json", "csv", true, nil}},
			wantType:  ConditionTypeAllowedValues,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*AllowedValuesCondition)
				assert.Equal(t, "format", typed.Argument)
				require.Len(t, typed.Values, 4)
				assert.Equal(t, "json", typed.Values[0])
				assert.Equal(t, "csv", typed.Values[1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.condition)
			require.NoError(t, err)
			assert.Contains(t, string(data), `"type":"`+tt.wantType+`"`)

			var wrapper ConditionWrapper
			require.NoError(t, json.Unmarshal(data, &wrapper))
			require.NotNil(t, wrapper.Condition)
			assert.Equal(t, tt.wantType, wrapper.ConditionType())
			tt.assertFunc(t, wrapper.Condition)
		})
	}
}

func TestConstraintWithMixedConditionsRoundTrip(t *testing.T) {
	constraint := Constraint{
		Resource: "tool:mailer",
		Actions:  []string{"send"},
		Conditions: []Condition{
			RecipientDomainCondition{Domains: []string{"example.com"}},
			MaxCallsCondition{Count: 5, WindowSeconds: 60},
			RedactFieldsCondition{Fields: []string{"ssn"}},
		},
	}

	data, err := json.Marshal(constraint)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"recipientDomain"`)
	assert.Contains(t, string(data), `"type":"maxCalls"`)
	assert.Contains(t, string(data), `"type":"redactFields"`)

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Conditions, 3)
	assert.IsType(t, &RecipientDomainCondition{}, decoded.Conditions[0])
	assert.IsType(t, &MaxCallsCondition{}, decoded.Conditions[1])
	assert.IsType(t, &RedactFieldsCondition{}, decoded.Conditions[2])
}

func TestObligationRoundTrip(t *testing.T) {
	tests := []Obligation{
		{Type: "redactFields", Paths: []string{"$.user.ssn", "$.secret"}},
		{Type: "annotate", Key: "classification", Value: "restricted"},
	}

	for _, obligation := range tests {
		data, err := json.Marshal(obligation)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"type":"`+obligation.Type+`"`)

		var decoded Obligation
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, obligation, decoded)
	}
}

func TestEnforceRequestResponseRoundTrip(t *testing.T) {
	request := EnforceRequest{
		SessionID: "session-1",
		ToolName:  "sql.query",
		Arguments: map[string]interface{}{"statement": "select 1", "limit": 10},
		Context: EnforceRequestContext{
			SourceIP:   "10.0.0.10",
			Recipients: []string{"alice@example.com"},
			Now:        "2025-03-01T12:00:00Z",
			Operation:  "select",
			FilePath:   "/reports/q1.sql",
			Tables: []TableAccess{{
				Table:   "users",
				Columns: []string{"id", "email"},
			}},
		},
	}

	requestData, err := json.Marshal(request)
	require.NoError(t, err)

	var decodedRequest EnforceRequest
	require.NoError(t, json.Unmarshal(requestData, &decodedRequest))
	assert.Equal(t, request.SessionID, decodedRequest.SessionID)
	assert.Equal(t, request.ToolName, decodedRequest.ToolName)
	assert.Equal(t, request.Context.SourceIP, decodedRequest.Context.SourceIP)
	assert.Equal(t, request.Context.Tables[0], decodedRequest.Context.Tables[0])

	response := EnforceResponse{
		RequestID: "request-1",
		Decision:  DecisionDeny,
		Obligations: []Obligation{
			{Type: "redactFields", Paths: []string{"$.user.ssn"}},
			{Type: "annotate", Key: "policy", Value: "masked"},
		},
		Denial: &DenialInfo{
			Code:          ErrCodeConditionFailed,
			ConditionType: ConditionTypeRecipientDomain,
			Message:       "recipient domain not allowed",
			Details:       map[string]interface{}{"recipient": "alice@blocked.test"},
		},
		DecidedAt: "2025-03-01T12:00:05Z",
	}

	responseData, err := json.Marshal(response)
	require.NoError(t, err)

	var decodedResponse EnforceResponse
	require.NoError(t, json.Unmarshal(responseData, &decodedResponse))
	assert.Equal(t, response.RequestID, decodedResponse.RequestID)
	assert.Equal(t, response.Decision, decodedResponse.Decision)
	require.Len(t, decodedResponse.Obligations, 2)
	assert.Equal(t, response.Obligations, decodedResponse.Obligations)
	require.NotNil(t, decodedResponse.Denial)
	assert.Equal(t, response.Denial.Code, decodedResponse.Denial.Code)
	assert.Equal(t, response.Denial.ConditionType, decodedResponse.Denial.ConditionType)
	assert.Equal(t, response.Denial.Message, decodedResponse.Denial.Message)
	assert.Equal(t, response.Denial.Details["recipient"], decodedResponse.Denial.Details["recipient"])
}

func TestSchemaTypeJSON(t *testing.T) {
	single := SchemaType{Single: "object"}
	singleData, err := json.Marshal(single)
	require.NoError(t, err)
	assert.Equal(t, `"object"`, string(singleData))

	var decodedSingle SchemaType
	require.NoError(t, json.Unmarshal(singleData, &decodedSingle))
	assert.Equal(t, single, decodedSingle)

	multiple := SchemaType{Multiple: []string{"object", "null"}}
	multipleData, err := json.Marshal(multiple)
	require.NoError(t, err)
	assert.JSONEq(t, `["object","null"]`, string(multipleData))

	var decodedMultiple SchemaType
	require.NoError(t, json.Unmarshal(multipleData, &decodedMultiple))
	assert.Equal(t, multiple, decodedMultiple)
}

func TestOptionalFieldsOmitted(t *testing.T) {
	payload := TokenPayload{
		Issuer:        "issuer-1",
		Subject:       "subject-1",
		Audience:      "audience-1",
		IssuedAt:      1,
		ExpiresAt:     2,
		JWTID:         "jti-1",
		SchemaVersion: SchemaVersion,
		Capabilities: []Constraint{{
			Resource: "tool:echo",
			Actions:  []string{"call"},
		}},
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)

	jsonText := string(data)
	assert.NotContains(t, jsonText, "parentCapabilityId")
	assert.NotContains(t, jsonText, "authorizedBy")
	assert.NotContains(t, jsonText, "vc")
	assert.NotContains(t, jsonText, "region")
	assert.NotContains(t, jsonText, "policyHash")
	assert.NotContains(t, jsonText, "cnf")
	assert.NotContains(t, jsonText, "proofs")
	assert.NotContains(t, jsonText, "conditions")
	assert.NotContains(t, jsonText, "argumentSchema")
}

func TestIssuanceProofsRoundTrip(t *testing.T) {
	proofs := IssuanceProofs{
		Signatures: []IssuerSignature{
			{IssuerDID: "did:example:123", Algorithm: "ES256", Signature: "abc123", IssuedAt: 1710000000},
			{IssuerDID: "did:example:456", Algorithm: "EdDSA", Signature: "def456"},
		},
	}

	data, err := json.Marshal(proofs)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"issuerDid":"did:example:123"`)
	assert.Contains(t, string(data), `"algorithm":"ES256"`)
	assert.Contains(t, string(data), `"signature":"abc123"`)

	var decoded IssuanceProofs
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Signatures, 2)
	assert.Equal(t, proofs.Signatures[0].IssuerDID, decoded.Signatures[0].IssuerDID)
	assert.Equal(t, proofs.Signatures[0].Algorithm, decoded.Signatures[0].Algorithm)
	assert.Equal(t, proofs.Signatures[1].IssuerDID, decoded.Signatures[1].IssuerDID)

	// Empty signatures omitted
	empty := IssuanceProofs{}
	emptyData, err := json.Marshal(empty)
	require.NoError(t, err)
	assert.NotContains(t, string(emptyData), "signatures")
}

func TestUnknownConditionTypeReturnsError(t *testing.T) {
	data := []byte(`{"resource":"tool:test","actions":["read"],"conditions":[{"type":"unknownKind","value":1}]}`)

	var constraint Constraint
	err := json.Unmarshal(data, &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown condition type: "unknownKind"`)
}

func boolPtr(v bool) *bool {
	return &v
}

// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unsupportedCondition struct{}

func (unsupportedCondition) ConditionType() string { return "unsupported" }

func TestSchemaTypeIsZero(t *testing.T) {
	assert.True(t, SchemaType{}.IsZero())
	assert.False(t, SchemaType{Single: "string"}.IsZero())
	assert.False(t, SchemaType{Multiple: []string{"string", "null"}}.IsZero())
}

func TestMarshalConditionErrors(t *testing.T) {
	_, err := marshalCondition(unsupportedCondition{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported condition payload")

	_, err = json.Marshal(ConditionWrapper{Condition: unsupportedCondition{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported condition payload")
}

func TestConstraintUnmarshalJSONErrors(t *testing.T) {
	var constraint Constraint

	err := json.Unmarshal([]byte(`{"resource":"tool:test","actions":["read"],"conditions":[{"type":"unknownKind","value":1}]}`), &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown condition type: "unknownKind"`)

	err = json.Unmarshal([]byte(`{"resource":"tool:test","actions":["read"],"conditions":[{"type":123}]}`), &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot unmarshal number into Go struct field")
}

func TestObligationAnnotateAndUnknownType(t *testing.T) {
	data, err := json.Marshal(Obligation{Type: "annotate", Key: "classification", Value: "restricted"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"annotate","key":"classification","value":"restricted"}`, string(data))

	var decoded Obligation
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, Obligation{Type: "annotate", Key: "classification", Value: "restricted"}, decoded)
	assert.Nil(t, decoded.Paths)

	_, err = json.Marshal(Obligation{Type: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "unknown"`)

	err = json.Unmarshal([]byte(`{"type":"unknown"}`), &decoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "unknown"`)
}

func TestConstraintEmptyConditionsList(t *testing.T) {
	var decoded Constraint
	err := json.Unmarshal([]byte(`{"resource":"tool:echo","actions":["call"],"conditions":[]}`), &decoded)
	require.NoError(t, err)
	require.NotNil(t, decoded.Conditions)
	assert.Empty(t, decoded.Conditions)

	data, err := json.Marshal(decoded)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"conditions":[]`)
}

func TestTokenPayloadOptionalFieldsEmpty(t *testing.T) {
	payload := TokenPayload{
		Issuer:        "issuer",
		Subject:       "subject",
		Audience:      "audience",
		IssuedAt:      1,
		ExpiresAt:     2,
		JWTID:         "jti",
		SchemaVersion: SchemaVersion,
		Capabilities:  []Constraint{{Resource: "tool:echo", Actions: []string{"call"}}},
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "authorizedBy")
	assert.NotContains(t, string(data), "parentCapabilityId")
	assert.NotContains(t, string(data), "proofs")

	var decoded TokenPayload
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Empty(t, decoded.ParentCapabilityID)
	assert.Nil(t, decoded.AuthorizedBy)
	assert.Nil(t, decoded.VC)
	assert.Empty(t, decoded.Region)
	assert.Empty(t, decoded.PolicyHash)
	assert.Nil(t, decoded.Confirmation)
	assert.Nil(t, decoded.Proofs)
}

func TestConditionJSONMalformedTypeField(t *testing.T) {
	var wrapper ConditionWrapper
	err := json.Unmarshal([]byte(`{"type":{"nested":true}}`), &wrapper)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot unmarshal object into Go struct field")

	data, err := json.Marshal(ConditionWrapper{})
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

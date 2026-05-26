// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"encoding/json"
	"fmt"
)

// Constraint describes the resource, actions, schema, and conditions granted by a capability.
type Constraint struct {
	Resource       string          `json:"resource"`
	Actions        []string        `json:"actions"`
	ArgumentSchema *ArgumentSchema `json:"argumentSchema,omitempty"`
	Conditions     []Condition     `json:"conditions,omitempty"`
}

// ArgumentSchema is a JSON-Schema subset for argument validation.
type ArgumentSchema struct {
	Type                 SchemaType                 `json:"type,omitempty"`
	Properties           map[string]*ArgumentSchema `json:"properties,omitempty"`
	Required             []string                   `json:"required,omitempty"`
	AdditionalProperties *bool                      `json:"additionalProperties,omitempty"`
	Enum                 []interface{}              `json:"enum,omitempty"`
	Pattern              string                     `json:"pattern,omitempty"`
	MinLength            *int                       `json:"minLength,omitempty"`
	MaxLength            *int                       `json:"maxLength,omitempty"`
	Minimum              *float64                   `json:"minimum,omitempty"`
	Maximum              *float64                   `json:"maximum,omitempty"`
	Items                *ArgumentSchema            `json:"items,omitempty"`
	MaxItems             *int                       `json:"maxItems,omitempty"`
	MinItems             *int                       `json:"minItems,omitempty"`
	Description          string                     `json:"description,omitempty"`
	Strict               *bool                      `json:"strict,omitempty"`
}

// SchemaType can be a single type string or an array of type strings.
type SchemaType struct {
	Single   string
	Multiple []string
}

type constraintJSON struct {
	Resource       string             `json:"resource"`
	Actions        []string           `json:"actions"`
	ArgumentSchema *ArgumentSchema    `json:"argumentSchema,omitempty"`
	Conditions     []ConditionWrapper `json:"conditions,omitempty"`
}

// MarshalJSON serializes Constraint while preserving polymorphic conditions.
func (c Constraint) MarshalJSON() ([]byte, error) {
	var conditions []ConditionWrapper
	if c.Conditions != nil {
		conditions = make([]ConditionWrapper, 0, len(c.Conditions))
		for _, condition := range c.Conditions {
			conditions = append(conditions, ConditionWrapper{Condition: condition})
		}
	}

	return json.Marshal(constraintJSON{
		Resource:       c.Resource,
		Actions:        c.Actions,
		ArgumentSchema: c.ArgumentSchema,
		Conditions:     conditions,
	})
}

// UnmarshalJSON deserializes Constraint while restoring concrete condition types.
func (c *Constraint) UnmarshalJSON(data []byte) error {
	var aux constraintJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.Resource = aux.Resource
	c.Actions = aux.Actions
	c.ArgumentSchema = aux.ArgumentSchema

	if aux.Conditions == nil {
		c.Conditions = nil
		return nil
	}

	c.Conditions = make([]Condition, 0, len(aux.Conditions))
	for _, condition := range aux.Conditions {
		c.Conditions = append(c.Conditions, condition.Condition)
	}

	return nil
}

// IsZero reports whether SchemaType has neither a single nor multi-value representation.
func (s SchemaType) IsZero() bool {
	return s.Single == "" && len(s.Multiple) == 0
}

// MarshalJSON serializes SchemaType as either a string, array, or null.
func (s SchemaType) MarshalJSON() ([]byte, error) {
	switch {
	case len(s.Multiple) > 0:
		return json.Marshal(s.Multiple)
	case s.Single != "":
		return json.Marshal(s.Single)
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON deserializes SchemaType from a string, array, or null.
func (s *SchemaType) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = SchemaType{}
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = SchemaType{Single: single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*s = SchemaType{Multiple: multiple}
		return nil
	}

	return fmt.Errorf("schema type must be string, array of strings, or null: %s", string(data))
}

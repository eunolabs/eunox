// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"encoding/json"
	"fmt"
)

type conditionEnvelope struct {
	Type string `json:"type"`
}

// ConditionWrapper wraps a condition so it can be marshaled and unmarshaled polymorphically.
type ConditionWrapper struct {
	Condition
}

// MarshalJSON serializes the wrapped condition.
func (w ConditionWrapper) MarshalJSON() ([]byte, error) {
	if w.Condition == nil {
		return []byte("null"), nil
	}

	return marshalCondition(w.Condition)
}

// UnmarshalJSON deserializes a wrapped condition from its discriminator.
func (w *ConditionWrapper) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		w.Condition = nil
		return nil
	}

	condition, err := unmarshalCondition(data)
	if err != nil {
		return err
	}

	w.Condition = condition
	return nil
}

func marshalCondition(condition Condition) ([]byte, error) {
	switch typed := condition.(type) {
	case TimeWindowCondition:
		type alias TimeWindowCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *TimeWindowCondition:
		type alias TimeWindowCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case IPRangeCondition:
		type alias IPRangeCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *IPRangeCondition:
		type alias IPRangeCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case AllowedOperationsCondition:
		type alias AllowedOperationsCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *AllowedOperationsCondition:
		type alias AllowedOperationsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case AllowedExtensionsCondition:
		type alias AllowedExtensionsCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *AllowedExtensionsCondition:
		type alias AllowedExtensionsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case AllowedTablesCondition:
		type alias AllowedTablesCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *AllowedTablesCondition:
		type alias AllowedTablesCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case MaxCallsCondition:
		type alias MaxCallsCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *MaxCallsCondition:
		type alias MaxCallsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case RecipientDomainCondition:
		type alias RecipientDomainCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *RecipientDomainCondition:
		type alias RecipientDomainCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case RedactFieldsCondition:
		type alias RedactFieldsCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *RedactFieldsCondition:
		type alias RedactFieldsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case PolicyCondition:
		type alias PolicyCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *PolicyCondition:
		type alias PolicyCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case CustomCondition:
		type alias CustomCondition
		return json.Marshal(struct {
			conditionEnvelope
			alias
		}{conditionEnvelope{Type: typed.ConditionType()}, alias(typed)})
	case *CustomCondition:
		type alias CustomCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	default:
		return nil, fmt.Errorf("unsupported condition payload: %T", condition)
	}
}

func unmarshalCondition(data []byte) (Condition, error) {
	var envelope conditionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	target := newCondition(envelope.Type)
	if target == nil {
		return nil, fmt.Errorf("unknown condition type: %q", envelope.Type)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return nil, err
	}

	return target, nil
}

func newCondition(conditionType string) Condition {
	switch conditionType {
	case ConditionTypeTimeWindow:
		return &TimeWindowCondition{}
	case ConditionTypeIPRange:
		return &IPRangeCondition{}
	case ConditionTypeAllowedOperations:
		return &AllowedOperationsCondition{}
	case ConditionTypeAllowedExtensions:
		return &AllowedExtensionsCondition{}
	case ConditionTypeAllowedTables:
		return &AllowedTablesCondition{}
	case ConditionTypeMaxCalls:
		return &MaxCallsCondition{}
	case ConditionTypeRecipientDomain:
		return &RecipientDomainCondition{}
	case ConditionTypeRedactFields:
		return &RedactFieldsCondition{}
	case ConditionTypePolicy:
		return &PolicyCondition{}
	case ConditionTypeCustom:
		return &CustomCondition{}
	default:
		return nil
	}
}

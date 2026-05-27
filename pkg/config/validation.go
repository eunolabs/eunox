// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError represents a single configuration validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Env     string `json:"env"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"` // redacted for sensitive fields
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s (%s): %s", e.Field, e.Env, e.Message)
}

func shouldRecurse(field *reflect.StructField, value reflect.Value) bool {
	if hasLeafTags(field) {
		return false
	}
	if value.Kind() == reflect.Struct {
		return true
	}
	return value.Kind() == reflect.Pointer && value.Type().Elem().Kind() == reflect.Struct
}

func joinFieldPath(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}

func assignValue(field reflect.Value, raw string) error {
	if field.Kind() == reflect.Pointer {
		elem := reflect.New(field.Type().Elem()).Elem()
		if err := assignValue(elem, raw); err != nil {
			return err
		}
		ptr := reflect.New(field.Type().Elem())
		ptr.Elem().Set(elem)
		field.Set(ptr)
		return nil
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, field.Type().Bits())
		if err != nil {
			return err
		}
		field.SetInt(value)
		return nil
	case reflect.Bool:
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		field.SetBool(value)
		return nil
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice type %s", field.Type())
		}
		if raw == "" {
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			return nil
		}
		parts := strings.Split(raw, ",")
		values := reflect.MakeSlice(field.Type(), 0, len(parts))
		for _, part := range parts {
			values = reflect.Append(values, reflect.ValueOf(strings.TrimSpace(part)).Convert(field.Type().Elem()))
		}
		field.Set(values)
		return nil
	default:
		return fmt.Errorf("unsupported field type %s", field.Type())
	}
}

func validateField(fieldPath, envVar string, value reflect.Value, tags *fieldTags, raw string) []ValidationError {
	var errs []ValidationError

	if tags.Min != nil {
		if intValue, ok := intValueOf(value); ok && intValue < int64(*tags.Min) {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     envVar,
				Message: fmt.Sprintf("must be greater than or equal to %d", *tags.Min),
				Value:   displayValue(fieldPath, envVar, raw),
			})
		}
	}

	if tags.Max != nil {
		if intValue, ok := intValueOf(value); ok && intValue > int64(*tags.Max) {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     envVar,
				Message: fmt.Sprintf("must be less than or equal to %d", *tags.Max),
				Value:   displayValue(fieldPath, envVar, raw),
			})
		}
	}

	if len(tags.Enum) > 0 {
		valueText := stringifyValue(value)
		matched := false
		for _, option := range tags.Enum {
			if valueText == option {
				matched = true
				break
			}
		}
		if !matched {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     envVar,
				Message: fmt.Sprintf("must be one of: %s", strings.Join(tags.Enum, ", ")),
				Value:   displayValue(fieldPath, envVar, valueText),
			})
		}
	}

	if tags.Regex != "" {
		// Wrap the caller-supplied pattern with unconditional anchors so that
		// patterns without explicit ^ / $ cannot match partial strings.
		// e.g. "foo" becomes "^(?:foo)$", preventing "xfooy" from matching.
		anchored := "^(?:" + tags.Regex + ")$"
		matched, err := regexp.MatchString(anchored, stringifyValue(value))
		if err != nil {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     envVar,
				Message: fmt.Sprintf("invalid regex pattern %q", tags.Regex),
			})
		} else if !matched {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     envVar,
				Message: fmt.Sprintf("must match regex %q", tags.Regex),
				Value:   displayValue(fieldPath, envVar, raw),
			})
		}
	}

	return errs
}

func validateProductionRules(fieldPath, envVar string, value reflect.Value, tags *fieldTags, found bool, raw string) []ValidationError {
	var errs []ValidationError

	for _, rule := range tags.Production {
		switch rule.Kind {
		case productionRuleRequired:
			if !isConfigured(value, found, raw) {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Env:     envVar,
					Message: "is required in production",
				})
			}
		case productionRuleMinLength:
			if !isConfigured(value, found, raw) {
				continue
			}
			valueText := stringifyValue(value)
			if len(valueText) < rule.Number {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Env:     envVar,
					Message: fmt.Sprintf("must be at least %d characters long in production", rule.Number),
					Value:   displayValue(fieldPath, envVar, valueText),
				})
			}
		case productionRuleNot:
			if !isConfigured(value, found, raw) {
				continue
			}
			valueText := stringifyValue(value)
			if valueText == rule.Value {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Env:     envVar,
					Message: fmt.Sprintf("must not equal %q in production", rule.Value),
					Value:   displayValue(fieldPath, envVar, valueText),
				})
			}
		}
	}

	return errs
}

func intValueOf(value reflect.Value) (int64, bool) {
	value = indirectValue(value)
	if !value.IsValid() {
		return 0, false
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), true
	default:
		return 0, false
	}
}

func indirectValue(value reflect.Value) reflect.Value {
	for value.IsValid() && value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func stringifyValue(value reflect.Value) string {
	value = indirectValue(value)
	if !value.IsValid() {
		return ""
	}

	switch value.Kind() {
	case reflect.String:
		return value.String()
	case reflect.Bool:
		return strconv.FormatBool(value.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(value.Int(), 10)
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.String {
			parts := make([]string, value.Len())
			for i := 0; i < value.Len(); i++ {
				parts[i] = value.Index(i).String()
			}
			return strings.Join(parts, ",")
		}
	}

	return fmt.Sprint(value.Interface())
}

func isConfigured(value reflect.Value, found bool, raw string) bool {
	if !found {
		return false
	}

	value = indirectValue(value)
	if !value.IsValid() {
		return false
	}

	switch value.Kind() {
	case reflect.String:
		return strings.TrimSpace(value.String()) != ""
	case reflect.Slice:
		return value.Len() > 0 || strings.TrimSpace(raw) != ""
	default:
		return true
	}
}

func displayValue(fieldPath, envVar, raw string) string {
	if isSensitiveField(fieldPath, envVar) {
		return ""
	}
	return raw
}

func isSensitiveField(fieldPath, envVar string) bool {
	joined := strings.ToLower(fieldPath + " " + envVar)
	for _, marker := range []string{"api_key", "apikey", "secret", "password", "token", "private_key", "privatekey", "pepper"} {
		if strings.Contains(joined, marker) {
			return true
		}
	}
	return false
}

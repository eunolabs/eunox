// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type productionRuleKind string

const (
	productionRuleRequired  productionRuleKind = "required"
	productionRuleMinLength productionRuleKind = "min_length"
	productionRuleNot       productionRuleKind = "not"
)

type productionRule struct {
	Kind   productionRuleKind
	Value  string
	Number int
}

type fieldTags struct {
	Env        string
	Default    string
	HasDefault bool
	Required   bool
	Min        *int
	Max        *int
	Enum       []string
	Regex      string
	Production []productionRule
}

func parseFieldTags(field reflect.StructField) (fieldTags, error) {
	tags := fieldTags{Env: strings.TrimSpace(field.Tag.Get("env"))}

	if defaultValue, ok := field.Tag.Lookup("default"); ok {
		tags.Default = defaultValue
		tags.HasDefault = true
	}

	if requiredValue := field.Tag.Get("required"); requiredValue != "" {
		required, err := strconv.ParseBool(requiredValue)
		if err != nil {
			return tags, fmt.Errorf("invalid required tag %q", requiredValue)
		}
		tags.Required = required
	}

	if minValue := field.Tag.Get("min"); minValue != "" {
		minVal, err := strconv.Atoi(minValue)
		if err != nil {
			return tags, fmt.Errorf("invalid min tag %q", minValue)
		}
		tags.Min = &minVal
	}

	if maxValue := field.Tag.Get("max"); maxValue != "" {
		maxVal, err := strconv.Atoi(maxValue)
		if err != nil {
			return tags, fmt.Errorf("invalid max tag %q", maxValue)
		}
		tags.Max = &maxVal
	}

	if enumValue := field.Tag.Get("enum"); enumValue != "" {
		for _, item := range strings.Split(enumValue, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				tags.Enum = append(tags.Enum, item)
			}
		}
	}

	tags.Regex = field.Tag.Get("regex")

	if productionValue := field.Tag.Get("production"); productionValue != "" {
		for _, ruleText := range strings.Split(productionValue, ",") {
			ruleText = strings.TrimSpace(ruleText)
			if ruleText == "" {
				continue
			}

			switch {
			case ruleText == string(productionRuleRequired):
				tags.Production = append(tags.Production, productionRule{Kind: productionRuleRequired})
			case strings.HasPrefix(ruleText, string(productionRuleMinLength)+":"):
				numberText := strings.TrimPrefix(ruleText, string(productionRuleMinLength)+":")
				number, err := strconv.Atoi(numberText)
				if err != nil {
					return tags, fmt.Errorf("invalid production rule %q", ruleText)
				}
				tags.Production = append(tags.Production, productionRule{Kind: productionRuleMinLength, Number: number})
			case strings.HasPrefix(ruleText, string(productionRuleNot)+":"):
				tags.Production = append(tags.Production, productionRule{Kind: productionRuleNot, Value: strings.TrimPrefix(ruleText, string(productionRuleNot)+":")})
			default:
				return tags, fmt.Errorf("invalid production rule %q", ruleText)
			}
		}
	}

	return tags, nil
}

func hasLeafTags(field reflect.StructField) bool {
	for _, tag := range []string{"env", "default", "required", "min", "max", "enum", "regex", "production"} {
		if _, ok := field.Tag.Lookup(tag); ok {
			return true
		}
	}
	return false
}

func envName(prefix string, tag string) string {
	prefix = strings.TrimSpace(prefix)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if prefix == "" {
		return tag
	}
	return prefix + "_" + tag
}

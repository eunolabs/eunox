// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Eunox services.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

// LoadOrExit loads configuration from environment variables into the provided struct pointer.
// On validation failure, it prints structured errors to stderr and calls os.Exit(1).
// The prefix is prepended to field env names (e.g., prefix "GATEWAY" + field env "PORT" → "GATEWAY_PORT").
// If prefix is empty, env var names are used as-is from struct tags.
func LoadOrExit[T any](prefix string) T {
	var cfg T
	errs := Load(prefix, &cfg)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration errors:\n")
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		os.Exit(1)
	}
	return cfg
}

// Load populates the struct from environment variables and returns validation errors.
func Load(prefix string, target interface{}) []ValidationError {
	if target == nil {
		return []ValidationError{{Message: "target must be a non-nil pointer to a struct"}}
	}

	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return []ValidationError{{Message: "target must be a non-nil pointer to a struct"}}
	}

	production := inferProductionMode(prefix, rv.Elem())
	errs, _ := loadStruct(prefix, rv.Elem(), "", production)
	return errs
}

func inferProductionMode(prefix string, value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return false
	}

	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		tags, err := parseFieldTags(&field)
		if err == nil && tags.Env == "NODE_ENV" {
			if raw, ok := os.LookupEnv(envName(prefix, tags.Env)); ok {
				return strings.EqualFold(strings.TrimSpace(raw), string(EnvProduction))
			}
			if tags.HasDefault {
				return strings.EqualFold(strings.TrimSpace(tags.Default), string(EnvProduction))
			}
			return false
		}

		fieldValue := value.Field(i)
		switch {
		case fieldValue.Kind() == reflect.Struct && !hasLeafTags(&field):
			if inferProductionMode(prefix, fieldValue) {
				return true
			}
		case fieldValue.Kind() == reflect.Pointer && fieldValue.Type().Elem().Kind() == reflect.Struct && !hasLeafTags(&field):
			if inferProductionMode(prefix, reflect.New(fieldValue.Type().Elem()).Elem()) {
				return true
			}
		}
	}

	return false
}

func loadStruct(prefix string, value reflect.Value, path string, production bool) ([]ValidationError, bool) {
	var errs []ValidationError
	var anySet bool

	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		fieldValue := value.Field(i)
		fieldPath := joinFieldPath(path, field.Name)

		if shouldRecurse(&field, fieldValue) {
			switch {
			case fieldValue.Kind() == reflect.Struct:
				nestedErrs, nestedSet := loadStruct(prefix, fieldValue, fieldPath, production)
				errs = append(errs, nestedErrs...)
				anySet = anySet || nestedSet
			case fieldValue.Kind() == reflect.Pointer && fieldValue.Type().Elem().Kind() == reflect.Struct:
				nestedValue := reflect.New(fieldValue.Type().Elem()).Elem()
				nestedErrs, nestedSet := loadStruct(prefix, nestedValue, fieldPath, production)
				errs = append(errs, nestedErrs...)
				if nestedSet {
					ptr := reflect.New(fieldValue.Type().Elem())
					ptr.Elem().Set(nestedValue)
					fieldValue.Set(ptr)
					anySet = true
				}
			}
			continue
		}

		tags, err := parseFieldTags(&field)
		if err != nil {
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Env:     field.Tag.Get("env"),
				Message: err.Error(),
			})
			continue
		}

		if tags.Env == "" {
			continue
		}

		envVar := envName(prefix, tags.Env)
		raw, found := os.LookupEnv(envVar)
		if !found && tags.HasDefault {
			raw = tags.Default
			found = true
		}

		parsed := true
		if found {
			if err := assignValue(fieldValue, raw); err != nil {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Env:     envVar,
					Message: fmt.Sprintf("invalid value for %s: %v", fieldValue.Type(), err),
					Value:   displayValue(fieldPath, envVar, raw),
				})
				parsed = false
			} else {
				anySet = true
				errs = append(errs, validateField(fieldPath, envVar, fieldValue, &tags, raw)...)
			}
		}

		if parsed {
			if tags.Required && !isConfigured(fieldValue, found, raw) {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Env:     envVar,
					Message: "is required",
				})
			}
			if production {
				errs = append(errs, validateProductionRules(fieldPath, envVar, fieldValue, &tags, found, raw)...)
			}
		}
	}

	return errs, anySet
}

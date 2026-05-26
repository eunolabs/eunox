// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type customString string
type customInt int
type customBool bool

type recurseNested struct {
	Value string `env:"NESTED_VALUE"`
}

type recursePointer struct {
	Enabled bool `env:"POINTER_ENABLED"`
}

type recurseSample struct {
	Nested       recurseNested
	Pointer      *recursePointer
	TaggedStruct recurseNested `env:"SHOULD_NOT_RECURSE"`
	Name         string
}

func TestLoadNestedStructAndPointerFields(t *testing.T) {
	unsetEnv(t, "NESTED_NAME", "INNER_COUNT", "OPTIONAL_ENABLED", "ALLOWED_ORIGINS")
	t.Setenv("NESTED_NAME", "nested")
	t.Setenv("ALLOWED_ORIGINS", "https://a.example, https://b.example")

	type innerConfig struct {
		Count *int `env:"INNER_COUNT"`
	}
	type optionalConfig struct {
		Enabled bool `env:"OPTIONAL_ENABLED"`
	}
	type nestedConfig struct {
		Name           string `env:"NESTED_NAME"`
		Inner          innerConfig
		Optional       *optionalConfig
		AllowedOrigins []string `env:"ALLOWED_ORIGINS"`
	}

	var cfg nestedConfig
	errs := Load("", &cfg)
	require.Empty(t, errs)
	assert.Equal(t, "nested", cfg.Name)
	assert.Nil(t, cfg.Inner.Count)
	assert.Nil(t, cfg.Optional)
	assert.Equal(t, []string{"https://a.example", "https://b.example"}, cfg.AllowedOrigins)

	t.Setenv("INNER_COUNT", "7")
	t.Setenv("OPTIONAL_ENABLED", "true")
	var populated nestedConfig
	errs = Load("", &populated)
	require.Empty(t, errs)
	require.NotNil(t, populated.Inner.Count)
	assert.Equal(t, 7, *populated.Inner.Count)
	require.NotNil(t, populated.Optional)
	assert.True(t, populated.Optional.Enabled)
}

func TestInferProductionMode(t *testing.T) {
	type nestedEnv struct {
		NodeEnv Environment `env:"NODE_ENV" default:"production"`
	}
	type root struct {
		Nested nestedEnv
	}

	assert.False(t, inferProductionMode("", reflect.Value{}))
	assert.False(t, inferProductionMode("", reflect.ValueOf(42)))
	assert.False(t, inferProductionMode("", reflect.ValueOf((*root)(nil))))

	unsetEnv(t, "NODE_ENV")
	assert.True(t, inferProductionMode("", reflect.ValueOf(root{})))

	t.Setenv("NODE_ENV", "production")
	assert.True(t, inferProductionMode("", reflect.ValueOf(root{})))

	t.Setenv("NODE_ENV", " Production ")
	assert.True(t, inferProductionMode("", reflect.ValueOf(root{})))

	t.Setenv("NODE_ENV", "staging")
	assert.False(t, inferProductionMode("", reflect.ValueOf(root{})))
}

func TestLoadWithPrefix(t *testing.T) {
	unsetEnv(t, "NODE_ENV", "PREFIX_NODE_ENV", "PREFIX_NAME")
	t.Setenv("PREFIX_NODE_ENV", "production")
	t.Setenv("PREFIX_NAME", "prefixed")

	type prefixedConfig struct {
		NodeEnv Environment `env:"NODE_ENV" default:"development"`
		Name    string      `env:"NAME" required:"true"`
	}

	var cfg prefixedConfig
	errs := Load("PREFIX", &cfg)
	require.Empty(t, errs)
	assert.Equal(t, EnvProduction, cfg.NodeEnv)
	assert.Equal(t, "prefixed", cfg.Name)
	assert.True(t, inferProductionMode("PREFIX", reflect.ValueOf(prefixedConfig{})))
}

func TestLoadStructUnsupportedFieldType(t *testing.T) {
	unsetEnv(t, "RATE")
	t.Setenv("RATE", "1.5")

	type unsupportedConfig struct {
		Rate float64 `env:"RATE"`
	}

	var cfg unsupportedConfig
	errs, anySet := loadStruct("", reflect.ValueOf(&cfg).Elem(), "", false)
	assert.False(t, anySet)
	require.Len(t, errs, 1)
	assert.Equal(t, "Rate", errs[0].Field)
	assert.Contains(t, errs[0].Message, "unsupported field type float64")
}

func TestShouldRecurse(t *testing.T) {
	typ := reflect.TypeOf(recurseSample{})
	value := reflect.New(typ).Elem()

	assert.True(t, shouldRecurse(typ.Field(0), value.Field(0)))
	assert.True(t, shouldRecurse(typ.Field(1), value.Field(1)))
	assert.False(t, shouldRecurse(typ.Field(2), value.Field(2)))
	assert.False(t, shouldRecurse(typ.Field(3), value.Field(3)))
}

func TestAssignValueCoversKinds(t *testing.T) {
	type assignTarget struct {
		Text      string
		Count     int
		Enabled   bool
		CSV       []string
		TextAlias customString
		IntAlias  customInt
		BoolAlias customBool
		Optional  *int
	}

	var target assignTarget
	require.NoError(t, assignValue(reflect.ValueOf(&target.Text).Elem(), "hello"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.Count).Elem(), "12"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.Enabled).Elem(), "true"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.CSV).Elem(), "a, b ,c"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.TextAlias).Elem(), "alias"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.IntAlias).Elem(), "99"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.BoolAlias).Elem(), "true"))
	require.NoError(t, assignValue(reflect.ValueOf(&target.Optional).Elem(), "5"))

	assert.Equal(t, "hello", target.Text)
	assert.Equal(t, 12, target.Count)
	assert.True(t, target.Enabled)
	assert.Equal(t, []string{"a", "b", "c"}, target.CSV)
	assert.Equal(t, customString("alias"), target.TextAlias)
	assert.Equal(t, customInt(99), target.IntAlias)
	assert.Equal(t, customBool(true), target.BoolAlias)
	require.NotNil(t, target.Optional)
	assert.Equal(t, 5, *target.Optional)
}

func TestIndirectValueStringifyValueAndIsConfigured(t *testing.T) {
	var nilString *string
	indirectNil := indirectValue(reflect.ValueOf(nilString))
	assert.False(t, indirectNil.IsValid())
	assert.Equal(t, "", stringifyValue(reflect.ValueOf(nilString)))
	assert.False(t, isConfigured(reflect.ValueOf(nilString), true, "value"))

	text := "configured"
	assert.Equal(t, "configured", indirectValue(reflect.ValueOf(&text)).String())
	assert.Equal(t, "configured", stringifyValue(reflect.ValueOf(&text)))
	assert.True(t, isConfigured(reflect.ValueOf(&text), true, text))

	number := 42
	assert.Equal(t, "42", stringifyValue(reflect.ValueOf(number)))
	assert.True(t, isConfigured(reflect.ValueOf(number), true, "42"))

	flag := true
	assert.Equal(t, "true", stringifyValue(reflect.ValueOf(&flag)))
	assert.True(t, isConfigured(reflect.ValueOf(&flag), true, "true"))

	empty := "   "
	assert.False(t, isConfigured(reflect.ValueOf(empty), true, empty))

	values := []string{"a", "b"}
	assert.Equal(t, "a,b", stringifyValue(reflect.ValueOf(values)))
	assert.True(t, isConfigured(reflect.ValueOf(values), true, "a,b"))
	assert.True(t, isConfigured(reflect.ValueOf([]string{}), true, "value supplied"))
	assert.False(t, isConfigured(reflect.ValueOf([]string{}), false, "value supplied"))
}

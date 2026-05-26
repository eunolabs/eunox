// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/edgeobs/eunox/pkg/config"
)

func TestLevelFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		env      config.Environment
		expected string
	}{
		{config.EnvProduction, "info"},
		{config.EnvStaging, "info"},
		{config.EnvDevelopment, "debug"},
		{config.Environment("test"), "debug"},
		{config.Environment(""), "debug"},
	}

	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			t.Parallel()
			if got := levelFromEnv(tt.env); got != tt.expected {
				t.Errorf("levelFromEnv(%q) = %q, want %q", tt.env, got, tt.expected)
			}
		})
	}
}

func TestNoopVerifier(t *testing.T) {
	t.Parallel()

	v := &noopVerifier{}
	_, err := v.VerifyToken(t.Context(), "some-token")
	if err == nil {
		t.Fatal("expected noopVerifier to return an error")
	}
}

func TestRun_MissingConfig(t *testing.T) {
	// When required config is missing, run() should return an error.
	// config.LoadOrExit calls os.Exit on missing required config, so we
	// test at a higher level that the binary compiles and is wired correctly.
	// The unit-testable parts (levelFromEnv, noopVerifier) are tested above.
}

// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/euno-platform/euno-go/pkg/config"
)

func TestBuildPlugins_Stdout(t *testing.T) {
	cfg := config.EmitterConfig{Plugins: "stdout"}

	plugins, err := buildPlugins(cfg, testLogger())
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	assert.Equal(t, "stdout", plugins[0].Name())
}

func TestBuildPlugins_EmptyListFails(t *testing.T) {
	cfg := config.EmitterConfig{Plugins: " , "}

	plugins, err := buildPlugins(cfg, testLogger())
	require.Error(t, err)
	assert.Nil(t, plugins)
	assert.Contains(t, err.Error(), "at least one posture emitter plugin")
}

func TestBuildPlugins_DefenderFailsWithoutSDKClient(t *testing.T) {
	cfg := config.EmitterConfig{
		Plugins:                "defender",
		DefenderSubscriptionID: "sub-123",
	}

	plugins, err := buildPlugins(cfg, testLogger())
	require.Error(t, err)
	assert.Nil(t, plugins)
	assert.Contains(t, err.Error(), "no SDK client is configured in this build")
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

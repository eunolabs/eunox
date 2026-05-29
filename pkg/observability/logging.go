// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package observability provides logging and metrics helpers.
package observability

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// LogConfig configures the structured logger.
type LogConfig struct {
	// Level is the minimum log level (debug, info, warn, error). Default: info.
	Level string
	// Format is the output format (json, text). Default: json.
	Format string
	// Output is the writer for log output. Default: os.Stderr.
	Output io.Writer
	// AddSource adds source file information to log entries.
	AddSource bool
	// ServiceName is included in every log entry as "service" field.
	ServiceName string
	// Version is included in every log entry as "version" field.
	Version string
}

// NewLogger creates a configured slog.Logger.
func NewLogger(cfg *LogConfig) *slog.Logger {
	resolvedCfg := &LogConfig{}
	if cfg != nil {
		resolvedCfg = cfg
	}
	if resolvedCfg.Output == nil {
		resolvedCfg.Output = os.Stderr
	}
	if resolvedCfg.Format == "" {
		resolvedCfg.Format = "json"
	}
	if resolvedCfg.Level == "" {
		resolvedCfg.Level = "info"
	}

	level := parseLevel(resolvedCfg.Level)
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: resolvedCfg.AddSource,
	}

	var handler slog.Handler
	switch strings.ToLower(resolvedCfg.Format) {
	case "text":
		handler = slog.NewTextHandler(resolvedCfg.Output, opts)
	default:
		handler = slog.NewJSONHandler(resolvedCfg.Output, opts)
	}

	attrs := []slog.Attr{}
	if resolvedCfg.ServiceName != "" {
		attrs = append(attrs, slog.String("service", resolvedCfg.ServiceName))
	}
	if resolvedCfg.Version != "" {
		attrs = append(attrs, slog.String("version", resolvedCfg.Version))
	}
	if len(attrs) > 0 {
		handler = handler.WithAttrs(attrs)
	}

	return slog.New(handler)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

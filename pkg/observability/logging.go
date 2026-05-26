// Copyright 2026 Eunox Authors
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
func NewLogger(cfg LogConfig) *slog.Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	}
	if cfg.Level == "" {
		cfg.Level = "info"
	}

	level := parseLevel(cfg.Level)
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "text":
		handler = slog.NewTextHandler(cfg.Output, opts)
	default:
		handler = slog.NewJSONHandler(cfg.Output, opts)
	}

	attrs := []slog.Attr{}
	if cfg.ServiceName != "" {
		attrs = append(attrs, slog.String("service", cfg.ServiceName))
	}
	if cfg.Version != "" {
		attrs = append(attrs, slog.String("version", cfg.Version))
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

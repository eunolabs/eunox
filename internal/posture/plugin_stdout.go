// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// StdoutPlugin writes posture events to an io.Writer (default: stdout).
// Useful for development, debugging, and testing.
type StdoutPlugin struct {
	writer io.Writer
}

// NewStdoutPlugin creates a new stdout plugin that writes to the given writer.
// If writer is nil, os.Stdout is used.
func NewStdoutPlugin(writer io.Writer) *StdoutPlugin {
	if writer == nil {
		writer = os.Stdout
	}
	return &StdoutPlugin{writer: writer}
}

// Name returns the plugin identifier.
func (p *StdoutPlugin) Name() string {
	return "stdout"
}

// EmitObserved writes the observed record as JSON to the writer.
func (p *StdoutPlugin) EmitObserved(_ context.Context, record AgentInventoryRecord) error {
	entry := map[string]interface{}{
		"type":   "observed",
		"record": record,
		"time":   time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("stdout plugin: marshal: %w", err)
	}
	_, err = fmt.Fprintf(p.writer, "%s\n", data)
	return err
}

// EmitRevoked writes the revocation event as JSON to the writer.
func (p *StdoutPlugin) EmitRevoked(_ context.Context, agentID string, revokedAt time.Time) error {
	entry := map[string]interface{}{
		"type":      "revoked",
		"agentId":   agentID,
		"revokedAt": revokedAt.UTC().Format(time.RFC3339),
		"time":      time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("stdout plugin: marshal: %w", err)
	}
	_, err = fmt.Fprintf(p.writer, "%s\n", data)
	return err
}

// Compile-time interface check.
var _ Plugin = (*StdoutPlugin)(nil)

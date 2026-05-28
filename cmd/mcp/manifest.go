// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/eunolabs/eunox/internal/agentruntime"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"gopkg.in/yaml.v3"
)

// LocalManifest is an alias for agentruntime.AgentCapabilityManifest — the
// canonical capability manifest type shared across the eunox codebase.
type LocalManifest = agentruntime.AgentCapabilityManifest

// LoadManifest reads and validates a LocalManifest from a YAML or JSON file.
// YAML files are converted to JSON before unmarshalling so the existing
// capability.Constraint JSON unmarshalling (with polymorphic conditions) is
// reused without change.
func LoadManifest(path string) (*LocalManifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a user-specified manifest file path (CLI argument)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %q: %w", path, err)
	}

	lp := strings.ToLower(path)
	if strings.HasSuffix(lp, ".yaml") || strings.HasSuffix(lp, ".yml") {
		var raw interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parsing YAML manifest %q: %w", path, err)
		}
		if data, err = json.Marshal(raw); err != nil {
			return nil, fmt.Errorf("converting manifest to JSON: %w", err)
		}
	}

	var m LocalManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	if err := validateLocalManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return &m, nil
}

// MergeManifests combines the Capabilities lists from all manifests.
// The first manifest's name and version are used for the merged result.
func MergeManifests(ms []*LocalManifest) *LocalManifest {
	if len(ms) == 1 {
		return ms[0]
	}
	merged := &LocalManifest{
		Name:    ms[0].Name,
		Version: ms[0].Version,
	}
	for _, m := range ms {
		merged.Capabilities = append(merged.Capabilities, m.Capabilities...)
	}
	return merged
}

func validateLocalManifest(m *LocalManifest) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("'name' must not be empty")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("'version' must not be empty")
	}
	for i, c := range m.Capabilities {
		if strings.TrimSpace(c.Resource) == "" {
			return fmt.Errorf("capability at index %d: 'resource' must not be empty", i)
		}
		if len(c.Actions) == 0 {
			return fmt.Errorf("capability at index %d: 'actions' must not be empty", i)
		}
		if err := enforcement.ValidateResourcePattern(c.Resource); err != nil {
			return fmt.Errorf("capability at index %d: %w", i, err)
		}
	}
	return nil
}

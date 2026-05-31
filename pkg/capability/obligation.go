// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
)

// Obligation represents a post-decision action to apply.
type Obligation struct {
	Type string
	// For redactFields:
	Paths []string
	// For annotate:
	Key   string
	Value string
}

// MarshalJSON serializes Obligation based on its type-specific payload.
func (o Obligation) MarshalJSON() ([]byte, error) {
	switch o.Type {
	case "redactFields":
		return json.Marshal(struct {
			Type  string   `json:"type"`
			Paths []string `json:"paths"`
		}{
			Type:  o.Type,
			Paths: o.Paths,
		})
	case "annotate":
		return json.Marshal(struct {
			Type  string `json:"type"`
			Key   string `json:"key"`
			Value string `json:"value"`
		}{
			Type:  o.Type,
			Key:   o.Key,
			Value: o.Value,
		})
	default:
		return nil, fmt.Errorf("unknown obligation type: %q", o.Type)
	}
}

// UnmarshalJSON deserializes Obligation based on its discriminator.
func (o *Obligation) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}

	switch envelope.Type {
	case "redactFields":
		var payload struct {
			Type  string   `json:"type"`
			Paths []string `json:"paths"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		o.Type = payload.Type
		o.Paths = payload.Paths
		o.Key = ""
		o.Value = ""
		return nil
	case "annotate":
		var payload struct {
			Type  string `json:"type"`
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		o.Type = payload.Type
		o.Paths = nil
		o.Key = payload.Key
		o.Value = payload.Value
		return nil
	default:
		return fmt.Errorf("unknown obligation type: %q", envelope.Type)
	}
}

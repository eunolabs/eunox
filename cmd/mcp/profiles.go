// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// profilesFS embeds all YAML profiles shipped with the binary.
//
//go:embed profiles/*.yaml
var profilesFS embed.FS

// profileData is the YAML schema for a built-in server profile.
type profileData struct {
	Server      string                    `yaml:"server"`
	Description string                    `yaml:"description"`
	Tools       map[string]ActionCategory `yaml:"tools"`
}

// builtinProfiles is the registry of built-in server profiles, keyed by
// the server identifier (e.g. "github", "slack", "filesystem").
// Populated from embedded YAML files at program init.
var builtinProfiles map[string]*StaticActionResolver

// builtinProfileDescriptions maps server identifier → human-readable description.
var builtinProfileDescriptions map[string]string

func init() {
	builtinProfiles = make(map[string]*StaticActionResolver)
	builtinProfileDescriptions = make(map[string]string)

	entries, err := profilesFS.ReadDir("profiles")
	if err != nil {
		panic("failed to read embedded profiles directory: " + err.Error())
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := profilesFS.ReadFile("profiles/" + entry.Name())
		if err != nil {
			panic(fmt.Sprintf("failed to read embedded profile %q: %v", entry.Name(), err))
		}
		var pd profileData
		if err := yaml.Unmarshal(data, &pd); err != nil {
			panic(fmt.Sprintf("failed to parse embedded profile %q: %v", entry.Name(), err))
		}
		if pd.Server == "" {
			pd.Server = strings.TrimSuffix(entry.Name(), ".yaml")
		}
		builtinProfiles[pd.Server] = NewStaticActionResolver(pd.Tools)
		builtinProfileDescriptions[pd.Server] = pd.Description
	}
}

// BuiltinResolver returns the ActionResolver for the named built-in server
// profile, or nil if no profile with that name is registered.
func BuiltinResolver(serverID string) ActionResolver {
	r, ok := builtinProfiles[serverID]
	if !ok {
		return nil
	}
	return r
}

// ListBuiltinProfiles returns the names of all built-in server profiles in
// alphabetical order.
func ListBuiltinProfiles() []string {
	names := make([]string, 0, len(builtinProfiles))
	for k := range builtinProfiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// BuiltinProfileDescription returns the human-readable description for a
// built-in profile, or "" if the profile is unknown.
func BuiltinProfileDescription(serverID string) string {
	return builtinProfileDescriptions[serverID]
}

// -----------------------------------------------------------------
// Custom action-map loading
// -----------------------------------------------------------------

// actionMapFile is the YAML/JSON schema for a user-supplied custom action map.
// Unlike full server profiles it does not require a "server" field.
//
// Example:
//
//	tools:
//	  process_document: read
//	  send_feedback:    write
//	  admin_delete:     admin
type actionMapFile struct {
	Tools map[string]ActionCategory `yaml:"tools" json:"tools"`
}

// LoadActionMap reads a YAML or JSON action-map file from path and returns a
// StaticActionResolver populated from the "tools" map.
func LoadActionMap(path string) (*StaticActionResolver, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a user-specified file path (CLI argument)
	if err != nil {
		return nil, fmt.Errorf("reading action-map %q: %w", path, err)
	}

	var am actionMapFile
	lp := strings.ToLower(filepath.Ext(path))
	if lp == ".json" {
		if err := json.Unmarshal(data, &am); err != nil {
			return nil, fmt.Errorf("parsing action-map %q as JSON: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, &am); err != nil {
			return nil, fmt.Errorf("parsing action-map %q as YAML: %w", path, err)
		}
	}

	if len(am.Tools) == 0 {
		return nil, fmt.Errorf("action-map %q: 'tools' map is empty or missing", path)
	}

	// Validate that all categories are known.
	known := map[ActionCategory]bool{
		ActionRead: true, ActionWrite: true, ActionDelete: true,
		ActionExecute: true, ActionAdmin: true,
	}
	for tool, cat := range am.Tools {
		if !known[cat] {
			return nil, fmt.Errorf("action-map %q: unknown action category %q for tool %q (valid: read, write, delete, execute, admin)", path, cat, tool)
		}
	}

	return NewStaticActionResolver(am.Tools), nil
}

// BuildResolver constructs the ActionResolver chain used by ManifestPDP.
//
// Priority (highest to lowest):
//  1. Custom action-map file (--action-map)
//  2. Built-in server profile (--server or manifest.Server)
//  3. HeuristicResolver (name-prefix inference)
//
// Returns HeuristicResolver when no profile or custom map is configured.
func BuildResolver(serverID, actionMapPath string) (ActionResolver, error) {
	var chain []ActionResolver

	if actionMapPath != "" {
		custom, err := LoadActionMap(actionMapPath)
		if err != nil {
			return nil, err
		}
		chain = append(chain, custom)
	}

	if serverID != "" {
		r := BuiltinResolver(serverID)
		if r == nil {
			return nil, fmt.Errorf("unknown built-in server profile %q; available: %s",
				serverID, strings.Join(ListBuiltinProfiles(), ", "))
		}
		chain = append(chain, r)
	}

	// Always fall through to the heuristic resolver.
	chain = append(chain, HeuristicResolver{})

	if len(chain) == 1 {
		return chain[0], nil // only heuristic — no alloc overhead
	}
	return NewChainedResolver(chain...), nil
}


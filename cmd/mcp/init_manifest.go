// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Starter manifest generator for the init subcommand (Fix 4).
//
// generateInitManifestYAML produces a YAML manifest where every tool is
// commented out.  Operators uncomment and add conditions only for tools the
// agent genuinely needs.  Re-running init after a server update and diffing
// against the current manifest surfaces additions and removals.

package main

import (
	"fmt"
	"sort"
	"strings"
)

// generateInitManifestYAML returns a deny-all starter YAML manifest for the
// given tool list.  Every tool entry is commented out; the capabilities section
// is valid but empty until the operator uncomments individual entries.
func generateInitManifestYAML(tools []UpstreamTool, manifestName string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "name: %q\n", manifestName)
	sb.WriteString("version: \"1.0.0\"\n\n")

	if len(tools) == 0 {
		sb.WriteString("capabilities: [] # no tools found on upstream\n")
		return sb.String()
	}

	sb.WriteString("capabilities:\n")
	sb.WriteString("  # REVIEW: uncomment and add conditions before enabling each tool.\n")

	for i, tool := range tools {
		if i > 0 {
			// Blank comment line separates entries for readability.
			sb.WriteString("  #\n")
		}
		for _, line := range toolEntryYAMLLines(tool) {
			sb.WriteString("  # ")
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// toolEntryYAMLLines returns the unindented YAML content lines for one tool
// entry.  Each line is prefixed with "  # " by the caller.
func toolEntryYAMLLines(tool UpstreamTool) []string {
	lines := []string{
		fmt.Sprintf("- resource: %s", tool.Name),
		"  actions: [call]",
	}
	if schemaLines := argumentSchemaYAML(tool.InputSchema); len(schemaLines) > 0 {
		lines = append(lines, "  argumentSchema:")
		lines = append(lines, schemaLines...)
	}
	return lines
}

// argumentSchemaYAML returns indented YAML lines for the argumentSchema block,
// or nil when the schema has no properties to emit.
func argumentSchemaYAML(schema map[string]interface{}) []string {
	props, ok := schemaProperties(schema)
	if !ok {
		return nil
	}

	lines := []string{
		"    type: object",
		"    properties:",
	}

	for _, name := range sortedMapKeys(props) {
		typeStr := "string"
		if propMap, ok := props[name].(map[string]interface{}); ok {
			if t, ok := propMap["type"].(string); ok && t != "" {
				typeStr = t
			}
		}
		lines = append(lines, fmt.Sprintf("      %s: { type: %s }", name, typeStr))
	}

	if reqRaw, ok := schema["required"].([]interface{}); ok && len(reqRaw) > 0 {
		required := make([]string, 0, len(reqRaw))
		for _, r := range reqRaw {
			if s, ok := r.(string); ok {
				required = append(required, s)
			}
		}
		if len(required) > 0 {
			lines = append(lines, fmt.Sprintf("    required: [%s]", strings.Join(required, ", ")))
		}
	}

	return lines
}

// sortedMapKeys returns the keys of m in sorted order.
func sortedMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

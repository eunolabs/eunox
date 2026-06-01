// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// ─── generateInitManifestYAML ─────────────────────────────────────────────────

func TestGenerateInitManifestYAML_Header(t *testing.T) {
	yaml := generateInitManifestYAML(nil, "my-policy", "")

	if !strings.Contains(yaml, `name: "my-policy"`) {
		t.Errorf("header: missing name field, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, `version: "1.0.0"`) {
		t.Errorf("header: missing version field, got:\n%s", yaml)
	}
}

func TestGenerateInitManifestYAML_EmptyTools(t *testing.T) {
	yaml := generateInitManifestYAML(nil, "empty-manifest", "")

	if !strings.Contains(yaml, "capabilities:") {
		t.Error("should contain capabilities:")
	}
	if !strings.Contains(yaml, "no tools") {
		t.Errorf("should indicate no tools found, got:\n%s", yaml)
	}
	// Must not contain any resource entries.
	if strings.Contains(yaml, "resource:") {
		t.Error("empty tool list must not contain any resource entries")
	}
}

func TestGenerateInitManifestYAML_ToolNoSchema(t *testing.T) {
	tools := []UpstreamTool{{Name: "simple_tool"}}
	yaml := generateInitManifestYAML(tools, "test", "")

	if !strings.Contains(yaml, "# - resource: simple_tool") {
		t.Errorf("should have commented-out resource entry, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "#   actions: [call]") {
		t.Errorf("should have commented-out actions entry, got:\n%s", yaml)
	}
	// No argumentSchema when the tool has no inputSchema.
	if strings.Contains(yaml, "argumentSchema") {
		t.Error("should not emit argumentSchema for a tool with no inputSchema")
	}
}

func TestGenerateInitManifestYAML_ToolWithSchema(t *testing.T) {
	tools := []UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":     map[string]interface{}{"type": "string"},
				"encoding": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"path"},
		},
	}}
	yaml := generateInitManifestYAML(tools, "test", "")

	for _, want := range []string{
		"#   argumentSchema:",
		"#     type: object",
		"#     properties:",
		"#       encoding: { type: string }",
		"#       path: { type: string }",
		"#     required: [path]",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("missing expected line %q in:\n%s", want, yaml)
		}
	}
}

func TestGenerateInitManifestYAML_ToolSchemaUnknownType(t *testing.T) {
	// Property without an explicit "type" field should default to "string".
	tools := []UpstreamTool{{
		Name: "tool_a",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"param": map[string]interface{}{}, // no "type" field
			},
		},
	}}
	yaml := generateInitManifestYAML(tools, "test", "")

	if !strings.Contains(yaml, "param: { type: string }") {
		t.Errorf("unknown type should default to string, got:\n%s", yaml)
	}
}

func TestGenerateInitManifestYAML_MultipleTools(t *testing.T) {
	tools := []UpstreamTool{
		{Name: "tool_a"},
		{Name: "tool_b"},
		{Name: "tool_c"},
	}
	yaml := generateInitManifestYAML(tools, "test", "")

	for _, name := range []string{"tool_a", "tool_b", "tool_c"} {
		if !strings.Contains(yaml, "resource: "+name) {
			t.Errorf("should contain resource entry for %s", name)
		}
	}

	// There should be separator comment lines between tools.
	if !strings.Contains(yaml, "  #\n") {
		t.Error("should have blank separator comment lines between tool entries")
	}
}

func TestGenerateInitManifestYAML_ReviewComment(t *testing.T) {
	tools := []UpstreamTool{{Name: "some_tool"}}
	yaml := generateInitManifestYAML(tools, "test", "")

	if !strings.Contains(yaml, "REVIEW") {
		t.Error("should contain the REVIEW guidance comment")
	}
}

func TestGenerateInitManifestYAML_AllEntriesCommentedOut(t *testing.T) {
	tools := []UpstreamTool{{Name: "tool_a"}, {Name: "tool_b"}}
	yaml := generateInitManifestYAML(tools, "test", "")

	// Every line in the capabilities block must be a comment or blank.
	// Scan the lines after "capabilities:".
	lines := strings.Split(yaml, "\n")
	inCaps := false
	for _, line := range lines {
		if line == "capabilities:" {
			inCaps = true
			continue
		}
		if !inCaps {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			t.Errorf("non-comment line in capabilities block: %q", line)
		}
	}
}

// ─── toolEntryYAMLLines ──────────────────────────────────────────────────────

func TestToolEntryYAMLLines_NoSchema(t *testing.T) {
	lines := toolEntryYAMLLines(UpstreamTool{Name: "my_tool"})

	if len(lines) != 2 {
		t.Fatalf("no-schema tool: want 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "- resource: my_tool" {
		t.Errorf("line[0]: want '- resource: my_tool', got %q", lines[0])
	}
	if lines[1] != "  actions: [call]" {
		t.Errorf("line[1]: want '  actions: [call]', got %q", lines[1])
	}
}

func TestToolEntryYAMLLines_WithSchema(t *testing.T) {
	tool := UpstreamTool{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"path"},
		},
	}
	lines := toolEntryYAMLLines(tool)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{
		"- resource: read_file",
		"  actions: [call]",
		"  argumentSchema:",
		"    type: object",
		"    properties:",
		"      path: { type: string }",
		"    required: [path]",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("toolEntryYAMLLines: missing %q in:\n%s", want, joined)
		}
	}
}

// ─── argumentSchemaYAML ──────────────────────────────────────────────────────

func TestArgumentSchemaYAML_Nil(t *testing.T) {
	if lines := argumentSchemaYAML(nil); len(lines) != 0 {
		t.Errorf("nil schema: want no lines, got %v", lines)
	}
}

func TestArgumentSchemaYAML_EmptyProperties(t *testing.T) {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
	if lines := argumentSchemaYAML(schema); len(lines) != 0 {
		t.Errorf("empty properties: want no lines, got %v", lines)
	}
}

func TestArgumentSchemaYAML_MultipleProperties_SortedAlphabetically(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"z_param": map[string]interface{}{"type": "string"},
			"a_param": map[string]interface{}{"type": "integer"},
			"m_param": map[string]interface{}{"type": "boolean"},
		},
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	aPos := strings.Index(joined, "a_param")
	mPos := strings.Index(joined, "m_param")
	zPos := strings.Index(joined, "z_param")
	if aPos < 0 || mPos < 0 || zPos < 0 {
		t.Fatal("all properties should appear in output")
	}
	if aPos >= mPos || mPos >= zPos {
		t.Errorf("properties should be sorted alphabetically: a < m < z, got positions a=%d m=%d z=%d", aPos, mPos, zPos)
	}
}

func TestArgumentSchemaYAML_RequiredFields(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{"type": "string"},
			"b": map[string]interface{}{"type": "string"},
		},
		"required": []interface{}{"a", "b"},
	}
	lines := argumentSchemaYAML(schema)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "required: [a, b]") {
		t.Errorf("should contain required: [a, b], got:\n%s", joined)
	}
}

func TestArgumentSchemaYAML_NoRequiredField(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param": map[string]interface{}{"type": "string"},
		},
	}
	lines := argumentSchemaYAML(schema)
	for _, l := range lines {
		if strings.Contains(l, "required") {
			t.Errorf("should not emit required line when schema has no required field: %q", l)
		}
	}
}

// ─── server version in generated YAML ────────────────────────────────────────

func TestGenerateInitManifestYAML_ServerVersionComment(t *testing.T) {
	yaml := generateInitManifestYAML(nil, "test", "1.2.3")

	// Should include a commented-out serverVersion line with the exact version.
	if !strings.Contains(yaml, `# serverVersion: "1.2.3"`) {
		t.Errorf("should include commented serverVersion with exact version, got:\n%s", yaml)
	}
	// Should also suggest the patch-wildcard form.
	if !strings.Contains(yaml, "1.2.*") {
		t.Errorf("should suggest patch wildcard 1.2.*, got:\n%s", yaml)
	}
}

func TestGenerateInitManifestYAML_NoServerVersion(t *testing.T) {
	yaml := generateInitManifestYAML(nil, "test", "")

	if strings.Contains(yaml, "serverVersion") {
		t.Errorf("should not emit serverVersion when none provided, got:\n%s", yaml)
	}
}

// ─── serverVersionWildcard ────────────────────────────────────────────────────

func TestServerVersionWildcard(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3", "1.2.*"},
		{"1.2", "1.2.*"},
		{"1", "1.*"},
		{"", "*"},
		{"1.2.3.4", "1.2.*"}, // only first two parts used
	}
	for _, tc := range cases {
		got := serverVersionWildcard(tc.in)
		if got != tc.want {
			t.Errorf("serverVersionWildcard(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── sortedMapKeys ───────────────────────────────────────────────────────────

func TestSortedMapKeys(t *testing.T) {
	m := map[string]interface{}{"z": 1, "a": 2, "m": 3}
	got := sortedMapKeys(m)
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("sortedMapKeys: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortedMapKeys[%d]: want %q, got %q", i, want[i], got[i])
		}
	}
}

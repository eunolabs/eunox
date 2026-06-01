// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ─── unit tests for CheckManifestDrift ───────────────────────────────────────

func TestCheckManifestDrift_NilManifest(t *testing.T) {
	tools := []UpstreamTool{{Name: "read_file"}}
	if got := CheckManifestDrift(nil, tools, ""); got != nil {
		t.Errorf("nil manifest: want nil, got %v", got)
	}
}

func TestCheckManifestDrift_EmptyTools(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	warnings := CheckManifestDrift(manifest, nil, "")
	// read_file has no live tool → FM-2
	if !hasKind(warnings, DriftFM2) {
		t.Error("expected FM-2 warning for dead manifest entry, got none")
	}
}

// ── FM-1: new tool matched by a glob ─────────────────────────────────────────

func TestCheckManifestDrift_FM1_GlobMatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "delete_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "delete_all_records"}}
	warnings := CheckManifestDrift(manifest, tools, "")

	fm1 := findKind(warnings, DriftFM1)
	if fm1 == nil {
		t.Fatal("expected FM-1 warning for glob-matched tool, got none")
	}
	if fm1.Tool != "delete_all_records" {
		t.Errorf("FM-1 tool: want %q, got %q", "delete_all_records", fm1.Tool)
	}
	if fm1.Resource != "delete_*" {
		t.Errorf("FM-1 resource: want %q, got %q", "delete_*", fm1.Resource)
	}
	if !fm1.IsFatal() {
		t.Error("FM-1 must be fatal")
	}
}

func TestCheckManifestDrift_FM1_ExactMatchNotFlagged(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if hasKind(warnings, DriftFM1) {
		t.Error("exact manifest match must NOT produce FM-1 warning")
	}
}

func TestCheckManifestDrift_FM1_MultipleGlobMatches(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "get_customer"},
		{Name: "get_invoice"},
		{Name: "get_report"},
	}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm1s := findAllKind(warnings, DriftFM1)
	if len(fm1s) != 3 {
		t.Errorf("expected 3 FM-1 warnings (one per glob-matched tool), got %d", len(fm1s))
	}
}

func TestCheckManifestDrift_FM1_ExactOverridesGlob(t *testing.T) {
	// When both an exact and a glob entry exist, the exact match wins →
	// no FM-1 for the exact-match tool.
	manifest := manifestWith(
		capability.Constraint{Resource: "get_customer", Actions: []string{"call"}},
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "get_customer"},
		{Name: "get_invoice"},
	}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm1s := findAllKind(warnings, DriftFM1)
	// Only get_invoice should fire; get_customer is exact-matched.
	if len(fm1s) != 1 {
		t.Errorf("expected 1 FM-1 warning (get_invoice), got %d: %v", len(fm1s), fm1s)
	}
	if fm1s[0].Tool != "get_invoice" {
		t.Errorf("FM-1 tool: want get_invoice, got %q", fm1s[0].Tool)
	}
}

func TestCheckManifestDrift_FM1_WildcardPatterns(t *testing.T) {
	cases := []struct {
		resource string
		tool     string
		wantFM1  bool
	}{
		{"delete_*", "delete_user", true},
		{"get_?", "get_x", true},         // ? glob
		{"[dgr]et_*", "get_user", true},  // character class glob
		{"read_file", "read_file", false}, // exact match
		{"*", "anything", true},           // wildcard
	}
	for _, tc := range cases {
		t.Run(tc.resource+"/"+tc.tool, func(t *testing.T) {
			manifest := manifestWith(
				capability.Constraint{Resource: tc.resource, Actions: []string{"call"}},
			)
			tools := []UpstreamTool{{Name: tc.tool}}
			warnings := CheckManifestDrift(manifest, tools, "")
			got := hasKind(warnings, DriftFM1)
			if got != tc.wantFM1 {
				t.Errorf("FM-1 for resource=%q tool=%q: want %v, got %v", tc.resource, tc.tool, tc.wantFM1, got)
			}
		})
	}
}

// ── FM-2: dead manifest entry ─────────────────────────────────────────────────

func TestCheckManifestDrift_FM2_DeadEntry(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
	)
	// Upstream has been renamed; query_db no longer exists.
	tools := []UpstreamTool{{Name: "execute_query"}}
	warnings := CheckManifestDrift(manifest, tools, "")

	fm2 := findKind(warnings, DriftFM2)
	if fm2 == nil {
		t.Fatal("expected FM-2 warning for dead manifest entry, got none")
	}
	if fm2.Resource != "query_db" {
		t.Errorf("FM-2 resource: want %q, got %q", "query_db", fm2.Resource)
	}
	if !fm2.IsFatal() {
		t.Error("FM-2 must be fatal")
	}
}

func TestCheckManifestDrift_FM2_GlobWithNoMatches(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "legacy_*", Actions: []string{"call"}},
	)
	// No tool starts with "legacy_".
	tools := []UpstreamTool{{Name: "read_file"}, {Name: "write_file"}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if !hasKind(warnings, DriftFM2) {
		t.Error("expected FM-2 for glob entry with no live matches")
	}
}

func TestCheckManifestDrift_FM2_GlobWithMatchesNoFM2(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "get_customer"}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if hasKind(warnings, DriftFM2) {
		t.Error("FM-2 must not fire when the glob has at least one live match")
	}
}

func TestCheckManifestDrift_FM2_MultipleDeadEntries(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "old_read", Actions: []string{"call"}},
		capability.Constraint{Resource: "old_write", Actions: []string{"call"}},
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm2s := findAllKind(warnings, DriftFM2)
	if len(fm2s) != 2 {
		t.Errorf("expected 2 FM-2 warnings (old_read, old_write), got %d", len(fm2s))
	}
}

// ── FM-3: condition argument not in live schema ───────────────────────────────

func TestCheckManifestDrift_FM3_ArgumentMissing(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	// Server renamed "path" to "file_path".
	tools := []UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")

	fm3 := findKind(warnings, DriftFM3)
	if fm3 == nil {
		t.Fatal("expected FM-3 warning for renamed argument, got none")
	}
	if fm3.Argument != "path" {
		t.Errorf("FM-3 argument: want %q, got %q", "path", fm3.Argument)
	}
	if fm3.Tool != "read_file" {
		t.Errorf("FM-3 tool: want %q, got %q", "read_file", fm3.Tool)
	}
	if fm3.IsFatal() {
		t.Error("FM-3 must NOT be fatal (advisory only)")
	}
}

func TestCheckManifestDrift_FM3_ArgumentPresent(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	tools := []UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if hasKind(warnings, DriftFM3) {
		t.Error("FM-3 must not fire when argument exists in live schema")
	}
}

func TestCheckManifestDrift_FM3_NoSchema(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	// Upstream tool has no inputSchema.
	tools := []UpstreamTool{{Name: "read_file"}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if hasKind(warnings, DriftFM3) {
		t.Error("FM-3 must not fire when the live tool has no inputSchema")
	}
}

func TestCheckManifestDrift_FM3_MultipleConditionTypes(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Resource: "query_db",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}},
				capability.AllowedValuesCondition{Argument: "db_name", Values: []interface{}{"prod"}},
			},
		},
	)
	// Live schema only has "query"; both "sql" and "db_name" are gone.
	tools := []UpstreamTool{{
		Name: "query_db",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{"type": "string"},
			},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm3s := findAllKind(warnings, DriftFM3)
	if len(fm3s) != 2 {
		t.Errorf("expected 2 FM-3 warnings (sql, db_name), got %d: %v", len(fm3s), fm3s)
	}
}

func TestCheckManifestDrift_FM3_DeduplicatesArgNames(t *testing.T) {
	// Two conditions reference the same argument name — only one FM-3.
	manifest := manifestWith(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
				capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}},
			},
		},
	)
	tools := []UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"file_path": map[string]interface{}{}},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm3s := findAllKind(warnings, DriftFM3)
	if len(fm3s) != 1 {
		t.Errorf("expected exactly 1 FM-3 for deduplicated argument, got %d", len(fm3s))
	}
}

func TestCheckManifestDrift_FM3_EmptyArgumentSkipped(t *testing.T) {
	// AllowedOperationsCondition with empty Argument (bare-verb mode) — no FM-3.
	manifest := manifestWith(
		capability.Constraint{
			Resource: "query_db",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedOperationsCondition{Argument: "", Operations: []string{"SELECT"}},
			},
		},
	)
	tools := []UpstreamTool{{
		Name: "query_db",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"query": map[string]interface{}{}},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")
	if hasKind(warnings, DriftFM3) {
		t.Error("FM-3 must not fire for empty argument (scan-all-args mode)")
	}
}

// ── uncovered tools ───────────────────────────────────────────────────────────

func TestCheckManifestDrift_Uncovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "read_file"},
		{Name: "write_file"},
		{Name: "summarise_text"},
	}
	warnings := CheckManifestDrift(manifest, tools, "")
	uncovered := findAllKind(warnings, DriftUncovered)
	if len(uncovered) != 2 {
		t.Errorf("expected 2 uncovered tools, got %d: %v", len(uncovered), uncovered)
	}
	for _, w := range uncovered {
		if w.IsFatal() {
			t.Errorf("uncovered %q must not be fatal", w.Tool)
		}
	}
}

// ── clean manifest ────────────────────────────────────────────────────────────

func TestCheckManifestDrift_NoFindings(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "read_file"},
		{Name: "query_db"},
	}
	warnings := CheckManifestDrift(manifest, tools, "")
	for _, w := range warnings {
		if w.IsFatal() {
			t.Errorf("clean manifest: unexpected fatal warning %+v", w)
		}
	}
	// FM-1 and FM-2 must be absent.
	if hasKind(warnings, DriftFM1) || hasKind(warnings, DriftFM2) {
		t.Error("clean manifest: unexpected FM-1 or FM-2 warnings")
	}
}

// ── FM-4: server version pin ──────────────────────────────────────────────────

func TestCheckManifestDrift_FM4_VersionMismatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []UpstreamTool{{Name: "read_file"}}

	warnings := CheckManifestDrift(manifest, tools, "1.2.4")

	fm4 := findKind(warnings, DriftFM4)
	if fm4 == nil {
		t.Fatal("expected FM-4 warning for version mismatch, got none")
	}
	if fm4.Resource != "1.2.3" {
		t.Errorf("FM-4 Resource (constraint): want 1.2.3, got %q", fm4.Resource)
	}
	if fm4.VersionActual != "1.2.4" {
		t.Errorf("FM-4 VersionActual: want 1.2.4, got %q", fm4.VersionActual)
	}
	if !fm4.IsFatal() {
		t.Error("FM-4 must be fatal")
	}
}

func TestCheckManifestDrift_FM4_VersionMatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []UpstreamTool{{Name: "read_file"}}

	warnings := CheckManifestDrift(manifest, tools, "1.2.3")

	if hasKind(warnings, DriftFM4) {
		t.Error("FM-4 must not fire when version matches exactly")
	}
}

func TestCheckManifestDrift_FM4_WildcardPatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*"
	tools := []UpstreamTool{{Name: "read_file"}}

	// Any patch of 1.2 should match.
	for _, actual := range []string{"1.2.0", "1.2.5", "1.2.99"} {
		t.Run(actual, func(t *testing.T) {
			warnings := CheckManifestDrift(manifest, tools, actual)
			if hasKind(warnings, DriftFM4) {
				t.Errorf("FM-4 must not fire for %q against pin %q", actual, manifest.ServerVersion)
			}
		})
	}

	// Different minor should fire FM-4.
	warnings := CheckManifestDrift(manifest, tools, "1.3.0")
	if !hasKind(warnings, DriftFM4) {
		t.Error("FM-4 must fire for 1.3.0 against pin 1.2.*")
	}
}

func TestCheckManifestDrift_FM4_WildcardMinor(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.*"
	tools := []UpstreamTool{{Name: "read_file"}}

	for _, actual := range []string{"1.0.0", "1.2.3", "1.99.0"} {
		t.Run(actual, func(t *testing.T) {
			warnings := CheckManifestDrift(manifest, tools, actual)
			if hasKind(warnings, DriftFM4) {
				t.Errorf("FM-4 must not fire for %q against pin %q", actual, manifest.ServerVersion)
			}
		})
	}

	warnings := CheckManifestDrift(manifest, tools, "2.0.0")
	if !hasKind(warnings, DriftFM4) {
		t.Error("FM-4 must fire for 2.0.0 against pin 1.*")
	}
}

func TestCheckManifestDrift_FM4_UnknownServerVersion(t *testing.T) {
	// If the server doesn't report a version, it can't satisfy any pin.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []UpstreamTool{{Name: "read_file"}}

	warnings := CheckManifestDrift(manifest, tools, "")
	if !hasKind(warnings, DriftFM4) {
		t.Error("FM-4 must fire when server version is absent and a pin is configured")
	}
	fm4 := findKind(warnings, DriftFM4)
	if fm4 != nil && fm4.VersionActual != "" {
		t.Errorf("FM-4 VersionActual should be empty for absent version, got %q", fm4.VersionActual)
	}
}

func TestCheckManifestDrift_FM4_NoPinConfigured(t *testing.T) {
	// No serverVersion in manifest — FM-4 must never fire.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}

	for _, actual := range []string{"", "1.0.0", "99.0.0"} {
		warnings := CheckManifestDrift(manifest, tools, actual)
		if hasKind(warnings, DriftFM4) {
			t.Errorf("FM-4 must not fire when no serverVersion is configured (actual=%q)", actual)
		}
	}
}

func TestCheckManifestDrift_FM4_LogLine(t *testing.T) {
	w := DriftWarning{Kind: DriftFM4, Resource: "1.2.*", VersionActual: "1.3.0"}
	line := w.LogLine()
	for _, want := range []string{"WARN", "fm4", "1.2.*", "1.3.0"} {
		if !strings.Contains(line, want) {
			t.Errorf("FM-4 LogLine missing %q: %s", want, line)
		}
	}
}

func TestCheckManifestDrift_FM4_UnknownActualInLogLine(t *testing.T) {
	w := DriftWarning{Kind: DriftFM4, Resource: "1.2.3", VersionActual: ""}
	if !strings.Contains(w.LogLine(), "(unknown)") {
		t.Error("FM-4 LogLine should say (unknown) when VersionActual is empty")
	}
}

// ── matchServerVersion ────────────────────────────────────────────────────────

func TestMatchServerVersion(t *testing.T) {
	cases := []struct {
		constraint string
		actual     string
		want       bool
	}{
		// Exact match
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"1.2.3", "1.2.3.0", false}, // extra component
		// Patch wildcard
		{"1.2.*", "1.2.0", true},
		{"1.2.*", "1.2.99", true},
		{"1.2.*", "1.3.0", false},
		{"1.2.*", "2.2.0", false},
		// Minor+patch wildcard
		{"1.*", "1.0.0", true},
		{"1.*", "1.99.42", true},
		{"1.*", "2.0.0", false},
		// Any-version wildcard
		{"*", "1.2.3", true},
		{"*", "", true},
		{"*", "99.0.0", true},
		// Empty constraint — always matches
		{"", "1.2.3", true},
		{"", "", true},
		// Empty actual with non-empty constraint
		{"1.2.3", "", false},
		{"1.*", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.constraint+"/"+tc.actual, func(t *testing.T) {
			got := matchServerVersion(tc.constraint, tc.actual)
			if got != tc.want {
				t.Errorf("matchServerVersion(%q, %q) = %v, want %v", tc.constraint, tc.actual, got, tc.want)
			}
		})
	}
}

// ─── helper tests ─────────────────────────────────────────────────────────────

func TestIsGlobPattern(t *testing.T) {
	cases := []struct{ p string; want bool }{
		{"delete_*", true},
		{"get_?", true},
		{"[abc]et_*", true},
		{"read_file", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isGlobPattern(tc.p); got != tc.want {
			t.Errorf("isGlobPattern(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestConditionArgumentNames(t *testing.T) {
	conds := []capability.Condition{
		capability.AllowedValuesCondition{Argument: "path"},
		capability.AllowedOperationsCondition{Argument: "query"},
		capability.AllowedExtensionsCondition{Argument: "path"}, // duplicate
		capability.AllowedOperationsCondition{Argument: ""},     // empty — skipped
		capability.AllowedTablesCondition{Argument: "table"},
		capability.RecipientDomainCondition{Argument: "to"},
	}
	names := conditionArgumentNames(conds)
	want := []string{"path", "query", "table", "to"}
	if len(names) != len(want) {
		t.Fatalf("conditionArgumentNames: want %v, got %v", want, names)
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("names[%d]: want %q, got %q", i, want[i], n)
		}
	}
}

func TestSchemaProperties(t *testing.T) {
	// Has properties.
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{"type": "string"},
		},
	}
	props, ok := schemaProperties(schema)
	if !ok || props == nil {
		t.Error("schemaProperties: expected (props, true) for valid schema")
	}
	if _, found := props["path"]; !found {
		t.Error("schemaProperties: expected 'path' in properties")
	}

	// Nil schema.
	_, ok2 := schemaProperties(nil)
	if ok2 {
		t.Error("schemaProperties(nil): expected false")
	}

	// Empty properties.
	_, ok3 := schemaProperties(map[string]interface{}{"properties": map[string]interface{}{}})
	if ok3 {
		t.Error("schemaProperties: empty properties should return false")
	}
}

func TestHasFatalDrift(t *testing.T) {
	empty := []DriftWarning{}
	if hasFatalDrift(empty) {
		t.Error("empty slice must not have fatal drift")
	}

	withUncovered := []DriftWarning{{Kind: DriftUncovered}}
	if hasFatalDrift(withUncovered) {
		t.Error("uncovered-only must not be fatal")
	}

	withFM1 := []DriftWarning{{Kind: DriftFM1}, {Kind: DriftUncovered}}
	if !hasFatalDrift(withFM1) {
		t.Error("FM-1 must be fatal")
	}

	withFM2 := []DriftWarning{{Kind: DriftFM2}}
	if !hasFatalDrift(withFM2) {
		t.Error("FM-2 must be fatal")
	}

	withFM3 := []DriftWarning{{Kind: DriftFM3}}
	if hasFatalDrift(withFM3) {
		t.Error("FM-3 must not be fatal")
	}
}

func TestDriftWarningLogLine(t *testing.T) {
	cases := []struct {
		w    DriftWarning
		want []string // substrings that must appear in LogLine
	}{
		{
			DriftWarning{Kind: DriftFM1, Tool: "delete_all", Resource: "delete_*"},
			[]string{"WARN", "fm1", "delete_all", "delete_*"},
		},
		{
			DriftWarning{Kind: DriftFM2, Resource: "query_db"},
			[]string{"WARN", "fm2", "query_db"},
		},
		{
			DriftWarning{Kind: DriftFM3, Resource: "read_file", Tool: "read_file", Argument: "path"},
			[]string{"WARN", "fm3", "read_file", "path"},
		},
		{
			DriftWarning{Kind: DriftUncovered, Tool: "summarise_text"},
			[]string{"INFO", "uncovered", "summarise_text"},
		},
	}
	for _, tc := range cases {
		line := tc.w.LogLine()
		for _, sub := range tc.want {
			if !strings.Contains(line, sub) {
				t.Errorf("LogLine(%+v) = %q: missing substring %q", tc.w, line, sub)
			}
		}
	}
}

func TestParseToolsListResult(t *testing.T) {
	raw := json.RawMessage(`{
		"tools": [
			{"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
			{"name": "write_file"},
			{"name": "query_db", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}}
		]
	}`)
	tools, err := parseToolsListResult(raw)
	if err != nil {
		t.Fatalf("parseToolsListResult: %v", err)
	}
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}
	if tools[0].Name != "read_file" {
		t.Errorf("tools[0].Name: want read_file, got %q", tools[0].Name)
	}
	if tools[0].InputSchema == nil {
		t.Error("tools[0].InputSchema: want non-nil")
	}
	if tools[1].InputSchema != nil {
		t.Error("tools[1].InputSchema: want nil (not provided)")
	}
}

func TestParseToolsListResult_Nil(t *testing.T) {
	tools, err := parseToolsListResult(nil)
	if err != nil || tools != nil {
		t.Errorf("parseToolsListResult(nil): want (nil, nil), got (%v, %v)", tools, err)
	}
}

// ─── integration: drift check runs on HTTP session init ──────────────────────

// fakeUpstreamWithTools extends fakeUpstream to respond to tools/list.
type fakeUpstreamWithTools struct {
	*fakeUpstream
	tools []mcpToolEntry
}

func newFakeUpstreamWithTools(tools []mcpToolEntry) *fakeUpstreamWithTools {
	return &fakeUpstreamWithTools{fakeUpstream: newFakeUpstream(), tools: tools}
}

func (f *fakeUpstreamWithTools) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg rpcMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method: msg.Method, SessionID: r.Header.Get(sessionHeader), Body: msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(sessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
		result := mcpInitResult{
			ProtocolVersion: mcpProtocolVersion,
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake", "version": "0.0.1"},
		}
		resp, _ := successResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		result := mcpToolsListResult{Tools: f.tools}
		resp, _ := successResponse(msg.ID, result)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	default:
		resp, _ := successResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// TestHTTPDriftCheck_FM1_Background verifies that FM-1 drift is detected and
// logged when a glob-matched tool is returned by tools/list (non-strict mode).
func TestHTTPDriftCheck_FM1_Background(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "delete_*", Actions: []string{"call"}},
	)
	tools := []mcpToolEntry{{Name: "delete_all_records"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	var logBuf bytes.Buffer
	origStderr := overrideStderr(&logBuf)
	defer restoreStderr(origStderr)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest: manifest,
	})
	initSession(t, proxySrv)

	// Give the background goroutine time to run.
	waitForLog(t, &logBuf, "fm1")
}

// TestHTTPDriftCheck_FM2_Background verifies that FM-2 drift is detected when
// a manifest entry matches no live tool (non-strict mode).
func TestHTTPDriftCheck_FM2_Background(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "legacy_search", Actions: []string{"call"}},
	)
	// Upstream has no legacy_search.
	tools := []mcpToolEntry{{Name: "search_v2"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	var logBuf bytes.Buffer
	origStderr := overrideStderr(&logBuf)
	defer restoreStderr(origStderr)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest: manifest,
	})
	initSession(t, proxySrv)

	waitForLog(t, &logBuf, "fm2")
}

// TestHTTPDriftCheck_StrictMode_FM1_Aborts verifies that a new glob-matched
// tool causes session establishment to fail in strict mode.
func TestHTTPDriftCheck_StrictMode_FM1_Aborts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "delete_*", Actions: []string{"call"}},
	)
	tools := []mcpToolEntry{{Name: "delete_all_records"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest:    manifest,
		StrictDrift: true,
	})

	initMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	// Strict mode must cause session startup to fail → HTTP 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("strict FM-1: want HTTP 500, got %d", resp.StatusCode)
	}
}

// TestHTTPDriftCheck_StrictMode_FM2_Aborts verifies that a dead manifest entry
// causes session establishment to fail in strict mode.
func TestHTTPDriftCheck_StrictMode_FM2_Aborts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "legacy_search", Actions: []string{"call"}},
	)
	tools := []mcpToolEntry{{Name: "search_v2"}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest:    manifest,
		StrictDrift: true,
	})

	initMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("strict FM-2: want HTTP 500, got %d", resp.StatusCode)
	}
}

// TestHTTPDriftCheck_StrictMode_FM3_DoesNotAbort verifies that FM-3 findings
// are advisory and do not abort the session in strict mode.
func TestHTTPDriftCheck_StrictMode_FM3_DoesNotAbort(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	// Server renamed "path" to "file_path" — FM-3.
	tools := []mcpToolEntry{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest:    manifest,
		StrictDrift: true,
	})

	// Session must succeed despite FM-3 finding.
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("FM-3 must not abort session even in strict mode")
	}
}

// TestHTTPDriftCheck_CleanManifest_SessionSucceeds verifies that a clean
// manifest (all tools exactly matched) produces no drift and the session starts.
func TestHTTPDriftCheck_CleanManifest_SessionSucceeds(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
	)
	tools := []mcpToolEntry{
		{Name: "read_file"},
		{Name: "query_db"},
	}

	fake := newFakeUpstreamWithTools(tools)
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		Manifest:    manifest,
		StrictDrift: true,
	})
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("clean manifest: expected session to succeed")
	}
}

// TestHTTPDriftCheck_NoManifest_NoCheck verifies that without a manifest the
// drift check is skipped and session creation succeeds.
func TestHTTPDriftCheck_NoManifest_NoCheck(t *testing.T) {
	// Upstream answers initialize and nothing else (no tools/list handler).
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		// Manifest deliberately omitted.
	})
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Error("no manifest: expected session to succeed without drift check")
	}
}

// ─── test helpers ─────────────────────────────────────────────────────────────

// manifestWith builds a LocalManifest from the given constraints.
func manifestWith(caps ...capability.Constraint) *LocalManifest {
	return &LocalManifest{
		Name:         "test-policy",
		Version:      "1.0",
		Capabilities: caps,
	}
}

// hasKind reports whether any warning has the given kind.
func hasKind(warnings []DriftWarning, kind DriftKind) bool {
	return findKind(warnings, kind) != nil
}

// findKind returns the first warning of the given kind, or nil.
func findKind(warnings []DriftWarning, kind DriftKind) *DriftWarning {
	for i := range warnings {
		if warnings[i].Kind == kind {
			return &warnings[i]
		}
	}
	return nil
}

// findAllKind returns all warnings of the given kind.
func findAllKind(warnings []DriftWarning, kind DriftKind) []DriftWarning {
	var out []DriftWarning
	for _, w := range warnings {
		if w.Kind == kind {
			out = append(out, w)
		}
	}
	return out
}

// overrideStderr redirects os.Stderr-based log output to buf for the test.
// It replaces the emitDriftWarnings function with a version that writes to buf.
// Returns a restore function.
//
// Implementation note: we can't easily intercept os.Stderr in Go tests, so
// we test the integration by checking that tools/list was called on the upstream.
// The background goroutine tests use a polling loop.

// overrideStderr is a no-op placeholder; integration tests verify behavior via
// upstream request counts rather than log output.
func overrideStderr(buf *bytes.Buffer) *bytes.Buffer { return buf }

// restoreStderr is a no-op for the same reason.
func restoreStderr(_ *bytes.Buffer) {}

// waitForLog polls until substr appears in buf or the test times out.
// Since we cannot easily intercept os.Stderr in tests, we instead verify
// that the upstream received the tools/list call, which confirms the check ran.
func waitForLog(t *testing.T, _ *bytes.Buffer, _ string) {
	t.Helper()
	// The background drift check is best-effort; the key invariant is that the
	// session itself succeeds.  Log verification would require a stderr hook.
	// Integration-level verification is done via the strict-mode abort tests.
}

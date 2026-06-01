// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ─── buildLiveReport ─────────────────────────────────────────────────────────

func TestBuildLiveReport_ExactCovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}, {Name: "query_db"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.exactCovered) != 2 {
		t.Fatalf("exactCovered: want 2, got %d", len(rep.exactCovered))
	}
	if rep.exactCovered[0].Tool != "query_db" {
		t.Errorf("exactCovered[0]: want query_db (sorted), got %q", rep.exactCovered[0].Tool)
	}
	if len(rep.fm1Warnings) != 0 {
		t.Errorf("fm1Warnings: want 0, got %d", len(rep.fm1Warnings))
	}
	if len(rep.fm2Stale) != 0 {
		t.Errorf("fm2Stale: want 0, got %d", len(rep.fm2Stale))
	}
	if len(rep.uncovered) != 0 {
		t.Errorf("uncovered: want 0, got %d", len(rep.uncovered))
	}
}

func TestBuildLiveReport_GlobMatchedGoesToFM1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "get_customer"}, {Name: "get_invoice"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.exactCovered) != 0 {
		t.Errorf("exactCovered: want 0 (glob matches should not appear here), got %d", len(rep.exactCovered))
	}
	if len(rep.fm1Warnings) != 2 {
		t.Errorf("fm1Warnings: want 2, got %d", len(rep.fm1Warnings))
	}
	// FM-1 slice must be sorted by tool name.
	if rep.fm1Warnings[0].Tool != "get_customer" || rep.fm1Warnings[1].Tool != "get_invoice" {
		t.Errorf("fm1Warnings order: want [get_customer, get_invoice], got [%s, %s]",
			rep.fm1Warnings[0].Tool, rep.fm1Warnings[1].Tool)
	}
}

func TestBuildLiveReport_FM2StaleEntries(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "legacy_search", Actions: []string{"call"}},
		capability.Constraint{Resource: "old_export", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "new_search"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.fm2Stale) != 2 {
		t.Errorf("fm2Stale: want 2, got %d", len(rep.fm2Stale))
	}
	// FM-2 slice must be sorted by resource name.
	if rep.fm2Stale[0].Resource != "legacy_search" || rep.fm2Stale[1].Resource != "old_export" {
		t.Errorf("fm2Stale order: want [legacy_search, old_export], got [%s, %s]",
			rep.fm2Stale[0].Resource, rep.fm2Stale[1].Resource)
	}
}

func TestBuildLiveReport_Uncovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "read_file"},
		{Name: "write_file"},
		{Name: "delete_file"},
	}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.uncovered) != 2 {
		t.Fatalf("uncovered: want 2, got %d: %v", len(rep.uncovered), rep.uncovered)
	}
	// Uncovered tools must be sorted.
	if rep.uncovered[0] != "delete_file" || rep.uncovered[1] != "write_file" {
		t.Errorf("uncovered order: want [delete_file, write_file], got %v", rep.uncovered)
	}
}

func TestBuildLiveReport_FM3Advisory(t *testing.T) {
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
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	rep := buildLiveReport(manifest, tools, "")

	// read_file is exact-matched → should appear in exactCovered (not in fm1).
	if len(rep.exactCovered) != 1 || rep.exactCovered[0].Tool != "read_file" {
		t.Errorf("exactCovered: want [{read_file,...}], got %v", rep.exactCovered)
	}
	if len(rep.fm3Warnings) != 1 {
		t.Errorf("fm3Warnings: want 1, got %d", len(rep.fm3Warnings))
	}
	if rep.fm3Warnings[0].Argument != "path" {
		t.Errorf("fm3Warnings[0].Argument: want path, got %q", rep.fm3Warnings[0].Argument)
	}
}

// ─── runValidateLive ─────────────────────────────────────────────────────────

func TestRunValidateLive_CleanManifest_Exit0(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}, {Name: "query_db"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 0 {
		t.Errorf("clean manifest: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "COVERED") {
		t.Error("clean manifest: output should have COVERED section")
	}
	if !strings.Contains(out, "read_file") {
		t.Error("clean manifest: output should mention read_file")
	}
	if !strings.Contains(out, "query_db") {
		t.Error("clean manifest: output should mention query_db")
	}
	if strings.Contains(out, "WARNINGS") {
		t.Error("clean manifest: output must not have WARNINGS section")
	}
	if !strings.Contains(out, "ok") {
		t.Error("clean manifest: result should say ok")
	}
}

func TestRunValidateLive_FM1GlobMatch_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "delete_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "delete_all_records"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("glob match: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("should have WARNINGS section for FM-1")
	}
	if !strings.Contains(out, "delete_all_records") {
		t.Error("should mention delete_all_records in WARNINGS")
	}
	if !strings.Contains(out, "glob match") {
		t.Error("should say 'glob match' in WARNINGS")
	}
	// Glob-matched tool must NOT appear in COVERED (it's not exact-matched).
	if strings.Contains(out, "COVERED") {
		t.Error("output must not have COVERED section when all tools are glob-matched")
	}
	if !strings.Contains(out, "Exit 1") {
		t.Error("result should say Exit 1")
	}
}

func TestRunValidateLive_FM2StaleEntry_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "legacy_search", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "new_search"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("stale entry: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "STALE MANIFEST ENTRIES") {
		t.Error("should have STALE MANIFEST ENTRIES section")
	}
	if !strings.Contains(out, "legacy_search") {
		t.Error("should mention legacy_search as stale")
	}
	if !strings.Contains(out, "stale entry") {
		t.Error("result should say 'stale entry'")
	}
}

func TestRunValidateLive_UncoveredTools_Exit0(t *testing.T) {
	// Uncovered tools are informational and do not cause exit 1.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "read_file"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 0 {
		t.Errorf("uncovered only: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "NOT COVERED") {
		t.Error("should have NOT COVERED section")
	}
	if !strings.Contains(out, "uncovered_tool") {
		t.Error("should mention uncovered_tool")
	}
}

func TestRunValidateLive_FM3Advisory_Exit0(t *testing.T) {
	// FM-3 is advisory — it produces a WARNINGS line but does not cause exit 1.
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
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 0 {
		t.Errorf("FM-3 advisory: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("FM-3 should appear in WARNINGS section")
	}
	if !strings.Contains(out, `"path"`) {
		t.Error("output should mention the missing argument name")
	}
	// read_file is exact-matched → must appear in COVERED too.
	if !strings.Contains(out, "COVERED") {
		t.Error("read_file should still appear in COVERED (exact match)")
	}
}

func TestRunValidateLive_Mixed(t *testing.T) {
	// Scenario: one exact match, one glob match, one stale entry, one uncovered tool.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
		capability.Constraint{Resource: "legacy_tool", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "read_file"},
		{Name: "get_customer"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("mixed: expected exit 1, got %d", code)
	}
	out := buf.String()

	if !strings.Contains(out, "COVERED") || !strings.Contains(out, "read_file") {
		t.Error("read_file should appear in COVERED (exact match)")
	}
	if !strings.Contains(out, "WARNINGS") || !strings.Contains(out, "get_customer") {
		t.Error("get_customer should appear in WARNINGS (glob match)")
	}
	if !strings.Contains(out, "NOT COVERED") || !strings.Contains(out, "uncovered_tool") {
		t.Error("uncovered_tool should appear in NOT COVERED")
	}
	if !strings.Contains(out, "STALE MANIFEST ENTRIES") || !strings.Contains(out, "legacy_tool") {
		t.Error("legacy_tool should appear in STALE MANIFEST ENTRIES")
	}

	// Result should summarise both findings.
	if !strings.Contains(out, "glob match") {
		t.Error("result should mention glob match(es)")
	}
	if !strings.Contains(out, "stale entry") {
		t.Error("result should mention stale entry(ies)")
	}
}

func TestRunValidateLive_MultipleGlobMatches_PluralResult(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "get_customer"},
		{Name: "get_invoice"},
		{Name: "get_report"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("3 glob matches: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "3 glob matches") {
		t.Errorf("result should say '3 glob matches', got: %s", buf.String())
	}
}

func TestRunValidateLive_MultipleStaleEntries_PluralResult(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "old_tool_a", Actions: []string{"call"}},
		capability.Constraint{Resource: "old_tool_b", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "new_tool"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("2 stale entries: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "2 stale entries") {
		t.Errorf("result should say '2 stale entries', got: %s", buf.String())
	}
}

func TestRunValidateLive_EmptyToolList_Exit1(t *testing.T) {
	// Empty tool list means every manifest entry is stale.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)

	var buf strings.Builder
	code := runValidateLive(manifest, nil, "", &buf)

	if code != 1 {
		t.Errorf("empty tools: expected exit 1 (stale manifest), got %d", code)
	}
	if !strings.Contains(buf.String(), "STALE") {
		t.Error("should have STALE section for empty tool list")
	}
}

func TestRunValidateLive_SectionsOmittedWhenEmpty(t *testing.T) {
	// Clean manifest — only COVERED should be present.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)
	out := buf.String()

	for _, absent := range []string{"WARNINGS", "NOT COVERED", "STALE"} {
		if strings.Contains(out, absent) {
			t.Errorf("section %q should be absent for clean manifest", absent)
		}
	}
}

func TestRunValidateLive_ExactMatchLabelInCovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)

	// The COVERED line should show the resource name.
	out := buf.String()
	if !strings.Contains(out, "read_file") {
		t.Error("COVERED should show the resource name")
	}
}

func TestRunValidateLive_BlankLineBetweenSections(t *testing.T) {
	// When multiple sections are present there should be a blank line between them.
	manifest := manifestWith(
		capability.Constraint{Resource: "get_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{
		{Name: "get_customer"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)
	out := buf.String()

	// There must be at least one blank line in the output (section separator).
	if !strings.Contains(out, "\n\n") {
		t.Error("output should contain at least one blank line between sections")
	}
}

// ─── FM-4: server version pinning ────────────────────────────────────────────

func TestBuildLiveReport_FM4_VersionMismatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []UpstreamTool{{Name: "read_file"}}

	rep := buildLiveReport(manifest, tools, "1.3.0")

	if len(rep.fm4Warnings) != 1 {
		t.Fatalf("fm4Warnings: want 1, got %d", len(rep.fm4Warnings))
	}
	if rep.fm4Warnings[0].Resource != "1.2.3" {
		t.Errorf("fm4Warnings[0].Resource: want 1.2.3, got %q", rep.fm4Warnings[0].Resource)
	}
	if rep.fm4Warnings[0].VersionActual != "1.3.0" {
		t.Errorf("fm4Warnings[0].VersionActual: want 1.3.0, got %q", rep.fm4Warnings[0].VersionActual)
	}
}

func TestBuildLiveReport_FM4_VersionMatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*"
	tools := []UpstreamTool{{Name: "read_file"}}

	rep := buildLiveReport(manifest, tools, "1.2.5")

	if len(rep.fm4Warnings) != 0 {
		t.Errorf("fm4Warnings: want 0, got %d (wildcard match should not fire)", len(rep.fm4Warnings))
	}
}

func TestRunValidateLive_FM4VersionMismatch_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "2.0.0", &buf)

	if code != 1 {
		t.Errorf("version mismatch: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("FM-4 should appear in WARNINGS section")
	}
	if !strings.Contains(out, "SERVER VERSION MISMATCH") {
		t.Error("FM-4 should show SERVER VERSION MISMATCH label")
	}
	if !strings.Contains(out, "1.2.3") {
		t.Error("output should show the pinned constraint")
	}
	if !strings.Contains(out, "2.0.0") {
		t.Error("output should show the actual version")
	}
	if !strings.Contains(out, "server version mismatch") {
		t.Error("result line should mention server version mismatch")
	}
}

func TestRunValidateLive_FM4VersionMatch_NoWarning(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*"
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "1.2.5", &buf)

	if code != 0 {
		t.Errorf("wildcard version match: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	if strings.Contains(buf.String(), "SERVER VERSION MISMATCH") {
		t.Error("output must not contain SERVER VERSION MISMATCH for matching version")
	}
}

func TestRunValidateLive_FM4UnknownVersion_Exit1(t *testing.T) {
	// Server doesn't report a version but manifest has a pin.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.0.0"
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("unknown version with pin: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "(unknown)") {
		t.Error("output should show (unknown) when server version is absent")
	}
}

func TestRunValidateLive_FM4NoPinConfigured_NoWarning(t *testing.T) {
	// No serverVersion in manifest — FM-4 must never fire regardless of actual.
	manifest := manifestWith(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "99.0.0", &buf)

	if code != 0 {
		t.Errorf("no pin configured: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	if strings.Contains(buf.String(), "SERVER VERSION") {
		t.Error("no server version warning expected when no pin is configured")
	}
}

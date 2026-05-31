// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

// -----------------------------------------------------------------
// StaticActionResolver
// -----------------------------------------------------------------

func TestStaticActionResolver_known(t *testing.T) {
	r := NewStaticActionResolver(map[string]ActionCategory{
		"read_file":  ActionRead,
		"write_file": ActionWrite,
	})
	if got := r.Resolve("read_file"); got != ActionRead {
		t.Errorf("Resolve(read_file) = %q, want %q", got, ActionRead)
	}
	if got := r.Resolve("write_file"); got != ActionWrite {
		t.Errorf("Resolve(write_file) = %q, want %q", got, ActionWrite)
	}
}

func TestStaticActionResolver_unknown(t *testing.T) {
	r := NewStaticActionResolver(map[string]ActionCategory{"read_file": ActionRead})
	if got := r.Resolve("delete_file"); got != "" {
		t.Errorf("Resolve(delete_file) = %q, want empty string", got)
	}
}

// -----------------------------------------------------------------
// HeuristicResolver
// -----------------------------------------------------------------

func TestHeuristicResolver(t *testing.T) {
	h := HeuristicResolver{}
	tests := []struct {
		toolName string
		want     ActionCategory
	}{
		{"get_issue", ActionRead},
		{"list_users", ActionRead},
		{"search_files", ActionRead},
		{"read_file", ActionRead},
		{"describe_table", ActionRead},
		{"fetch_data", ActionRead},
		{"create_issue", ActionWrite},
		{"update_record", ActionWrite},
		{"push_files", ActionWrite},
		{"save_document", ActionWrite},
		{"upsert_contact", ActionWrite},
		{"delete_file", ActionDelete},
		{"remove_item", ActionDelete},
		{"purge_cache", ActionDelete},
		{"run_query", ActionExecute},
		{"execute_command", ActionExecute},
		{"launch_browser", ActionExecute},
		{"invoke_function", ActionExecute},
		{"deploy_stack", ActionExecute},
		{"admin_panel", ActionAdmin},
		{"grant_permission", ActionAdmin},
		{"revoke_token", ActionAdmin},
		{"unknown_tool_xyz", ""},        // no prefix match
		{"process_document", ""},        // "process" has no matching prefix
		{"send_feedback", ActionWrite},  // "send" → write (send_ prefix)
	}
	for _, tc := range tests {
		got := h.Resolve(tc.toolName)
		if got != tc.want {
			t.Errorf("HeuristicResolver.Resolve(%q) = %q, want %q", tc.toolName, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------
// ChainedResolver
// -----------------------------------------------------------------

func TestChainedResolver_firstMatch(t *testing.T) {
	r1 := NewStaticActionResolver(map[string]ActionCategory{"my_tool": ActionAdmin})
	r2 := NewStaticActionResolver(map[string]ActionCategory{"my_tool": ActionRead, "other": ActionWrite})

	chain := NewChainedResolver(r1, r2)

	// r1 should win for "my_tool"
	if got := chain.Resolve("my_tool"); got != ActionAdmin {
		t.Errorf("chain.Resolve(my_tool) = %q, want %q", got, ActionAdmin)
	}
	// r1 misses "other", r2 should provide it
	if got := chain.Resolve("other"); got != ActionWrite {
		t.Errorf("chain.Resolve(other) = %q, want %q", got, ActionWrite)
	}
	// nothing knows "unknown"
	if got := chain.Resolve("unknown"); got != "" {
		t.Errorf("chain.Resolve(unknown) = %q, want empty", got)
	}
}

// -----------------------------------------------------------------
// Built-in profiles
// -----------------------------------------------------------------

func TestBuiltinProfiles_allLoad(t *testing.T) {
	names := ListBuiltinProfiles()
	if len(names) < 10 {
		t.Errorf("expected at least 10 built-in profiles, got %d", len(names))
	}
	for _, name := range names {
		r := BuiltinResolver(name)
		if r == nil {
			t.Errorf("BuiltinResolver(%q) returned nil", name)
		}
	}
}

func TestBuiltinProfiles_unknownReturnsNil(t *testing.T) {
	if r := BuiltinResolver("nonexistent-server-xyz"); r != nil {
		t.Errorf("BuiltinResolver(nonexistent) expected nil, got %v", r)
	}
}

func TestBuiltinProfile_filesystem(t *testing.T) {
	r := BuiltinResolver("filesystem")
	if r == nil {
		t.Fatal("filesystem profile not found")
	}
	cases := []struct {
		tool string
		want ActionCategory
	}{
		{"read_file", ActionRead},
		{"write_file", ActionWrite},
		{"delete_file", ActionDelete},
		{"list_directory", ActionRead},
		{"create_directory", ActionWrite},
		{"move_file", ActionWrite},
	}
	for _, c := range cases {
		if got := r.Resolve(c.tool); got != c.want {
			t.Errorf("filesystem.Resolve(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestBuiltinProfile_github(t *testing.T) {
	r := BuiltinResolver("github")
	if r == nil {
		t.Fatal("github profile not found")
	}
	cases := []struct {
		tool string
		want ActionCategory
	}{
		{"get_file_contents", ActionRead},
		{"search_repositories", ActionRead},
		{"list_issues", ActionRead},
		{"create_issue", ActionWrite},
		{"create_or_update_file", ActionWrite},
		{"merge_pull_request", ActionWrite},
		{"delete_file", ActionDelete},
	}
	for _, c := range cases {
		if got := r.Resolve(c.tool); got != c.want {
			t.Errorf("github.Resolve(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestBuiltinProfile_slack(t *testing.T) {
	r := BuiltinResolver("slack")
	if r == nil {
		t.Fatal("slack profile not found")
	}
	cases := []struct {
		tool string
		want ActionCategory
	}{
		{"slack_list_channels", ActionRead},
		{"slack_get_channel_history", ActionRead},
		{"slack_post_message", ActionWrite},
		{"slack_reply_to_thread", ActionWrite},
		{"slack_delete_message", ActionDelete},
	}
	for _, c := range cases {
		if got := r.Resolve(c.tool); got != c.want {
			t.Errorf("slack.Resolve(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestBuiltinProfile_memory(t *testing.T) {
	r := BuiltinResolver("memory")
	if r == nil {
		t.Fatal("memory profile not found")
	}
	cases := []struct {
		tool string
		want ActionCategory
	}{
		{"read_graph", ActionRead},
		{"search_nodes", ActionRead},
		{"create_entities", ActionWrite},
		{"delete_entities", ActionDelete},
	}
	for _, c := range cases {
		if got := r.Resolve(c.tool); got != c.want {
			t.Errorf("memory.Resolve(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

// -----------------------------------------------------------------
// BuildResolver
// -----------------------------------------------------------------

func TestBuildResolver_heuristicOnly(t *testing.T) {
	r, err := BuildResolver("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HeuristicResolver should classify get_* as read
	if got := r.Resolve("get_user"); got != ActionRead {
		t.Errorf("BuildResolver('','').Resolve(get_user) = %q, want %q", got, ActionRead)
	}
}

func TestBuildResolver_builtinProfile(t *testing.T) {
	r, err := BuildResolver("filesystem", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := r.Resolve("read_file"); got != ActionRead {
		t.Errorf("BuildResolver(filesystem).Resolve(read_file) = %q, want %q", got, ActionRead)
	}
}

func TestBuildResolver_unknownProfile(t *testing.T) {
	_, err := BuildResolver("nonexistent-xyz", "")
	if err == nil {
		t.Fatal("expected error for unknown profile, got nil")
	}
}

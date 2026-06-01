// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// newTestManifestPDP builds a ManifestPDP with the given capabilities.
// No ActionResolver is attached; tests rely on generic "call"/"*" actions.
func newTestManifestPDP(caps ...capability.Constraint) *ManifestPDP {
	manifest := &LocalManifest{
		Name:         "test-policy",
		Version:      "1.0",
		Capabilities: caps,
	}
	engine := enforcement.New()
	ks := killswitch.NewInMemory()
	return NewManifestPDP(manifest, engine, ks)
}

// ── absent tools ─────────────────────────────────────────────────────────────

// TestManifestPDP_AbsentTool_Deny verifies the core deny-by-default behaviour:
// a tool not listed in the manifest must be denied.
func TestManifestPDP_AbsentTool_Deny(t *testing.T) {
	pdp := newTestManifestPDP(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)

	resp := pdp.Decide(context.Background(), "sess", "write_file",
		map[string]interface{}{"path": "/etc/passwd", "content": "x"}, "127.0.0.1")

	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (write_file absent from manifest)", resp.Decision)
	}
	if resp.Denial == nil {
		t.Fatal("denial info must not be nil")
	}
}

// TestManifestPDP_AbsentTool_EmptyManifest checks that every tool is denied
// when the manifest has no capability entries at all.
func TestManifestPDP_AbsentTool_EmptyManifest(t *testing.T) {
	pdp := newTestManifestPDP() // no capabilities

	for _, tool := range []string{"read_file", "write_file", "query_db"} {
		resp := pdp.Decide(context.Background(), "sess", tool,
			map[string]interface{}{}, "127.0.0.1")
		if resp.Decision != capability.DecisionDeny {
			t.Errorf("tool=%q: decision = %q, want deny (empty manifest)", tool, resp.Decision)
		}
	}
}

// ── listed tools ─────────────────────────────────────────────────────────────

// TestManifestPDP_ListedTool_NoConditions_Allow verifies that a tool explicitly
// listed in the manifest with no conditions is allowed.
func TestManifestPDP_ListedTool_NoConditions_Allow(t *testing.T) {
	pdp := newTestManifestPDP(
		capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
	)

	resp := pdp.Decide(context.Background(), "sess", "read_file",
		map[string]interface{}{"path": "/reports/q3.pdf"}, "127.0.0.1")

	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %q, want allow; denial = %+v", resp.Decision, resp.Denial)
	}
}

// TestManifestPDP_ListedTool_AllowedValues_Allow verifies that a tool with an
// allowedValues condition is allowed when the argument value matches.
func TestManifestPDP_ListedTool_AllowedValues_Allow(t *testing.T) {
	pdp := newTestManifestPDP(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
	)

	resp := pdp.Decide(context.Background(), "sess", "read_file",
		map[string]interface{}{"path": "/reports/q3.pdf"}, "127.0.0.1")

	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %q, want allow; denial = %+v", resp.Decision, resp.Denial)
	}
}

// TestManifestPDP_ListedTool_AllowedValues_Deny verifies that a tool with an
// allowedValues condition is denied when the argument value does not match.
func TestManifestPDP_ListedTool_AllowedValues_Deny(t *testing.T) {
	pdp := newTestManifestPDP(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
	)

	resp := pdp.Decide(context.Background(), "sess", "read_file",
		map[string]interface{}{"path": "/etc/shadow"}, "127.0.0.1")

	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (path outside /reports/*)", resp.Decision)
	}
}

// ── multiple capabilities ─────────────────────────────────────────────────────

// TestManifestPDP_MultipleCapabilities verifies that each tool is evaluated
// against its own constraint and absent tools remain denied.
func TestManifestPDP_MultipleCapabilities(t *testing.T) {
	pdp := newTestManifestPDP(
		capability.Constraint{
			Resource: "read_file",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
		capability.Constraint{
			Resource: "query_db",
			Actions:  []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{
					Argument:   "query", // the argument that carries the SQL string
					Operations: []string{"SELECT"},
				},
			},
		},
	)

	tests := []struct {
		tool string
		args map[string]interface{}
		want capability.Decision
	}{
		// read_file: path matches glob → allow
		{"read_file", map[string]interface{}{"path": "/reports/q3.pdf"}, capability.DecisionAllow},
		// read_file: path outside glob → deny
		{"read_file", map[string]interface{}{"path": "/etc/shadow"}, capability.DecisionDeny},
		// query_db: SELECT is in allowedOperations → allow
		{"query_db", map[string]interface{}{"query": "SELECT * FROM reports"}, capability.DecisionAllow},
		// query_db: DELETE not in allowedOperations → deny
		{"query_db", map[string]interface{}{"query": "DELETE FROM reports"}, capability.DecisionDeny},
		// write_file: absent from manifest → deny
		{"write_file", map[string]interface{}{"path": "/etc/passwd", "content": "x"}, capability.DecisionDeny},
	}

	for _, tc := range tests {
		resp := pdp.Decide(context.Background(), "sess", tc.tool, tc.args, "127.0.0.1")
		if resp.Decision != tc.want {
			t.Errorf("tool=%q args=%v: decision = %q, want %q; denial = %+v",
				tc.tool, tc.args, resp.Decision, tc.want, resp.Denial)
		}
	}
}

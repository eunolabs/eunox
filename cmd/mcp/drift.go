// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Startup manifest drift detection — FM-1, FM-2, FM-3.
//
// After the MCP initialize handshake the proxy fetches tools/list from the
// upstream and compares the live tool set against the capability manifest.
// Three failure modes are detected:
//
//	FM-1  A new upstream tool is matched by a manifest glob — silent over-permission.
//	FM-2  A manifest resource entry matches no live upstream tool — dead reference.
//	FM-3  A condition argument name is absent from the live inputSchema — silent bypass risk.
//
// In non-strict mode all findings are emitted as structured log lines to
// stderr and the session continues.  With --strict-drift, FM-1 and FM-2
// findings abort session establishment.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// UpstreamTool describes one tool returned by the upstream tools/list response.
type UpstreamTool struct {
	Name        string
	InputSchema map[string]interface{}
}

// DriftKind classifies a drift finding.
type DriftKind string

const (
	// DriftFM1 — upstream tool matched by a manifest glob (FM-1, silent over-permission).
	DriftFM1 DriftKind = "fm1"
	// DriftFM2 — manifest resource entry matches no live upstream tool (FM-2, dead reference).
	DriftFM2 DriftKind = "fm2"
	// DriftFM3 — condition argument not found in live inputSchema (FM-3, silent bypass risk).
	DriftFM3 DriftKind = "fm3"
	// DriftUncovered — upstream tool has no manifest entry (informational; denied by default).
	DriftUncovered DriftKind = "uncovered"
)

// DriftWarning is one finding produced by CheckManifestDrift.
type DriftWarning struct {
	Kind     DriftKind
	Tool     string // upstream tool name (empty for FM-2)
	Resource string // manifest resource pattern (empty for uncovered)
	Argument string // condition argument name (FM-3 only)
}

// IsFatal reports whether this finding should abort session establishment
// when --strict-drift is set.  FM-1 and FM-2 are fatal; FM-3 and uncovered
// are advisory.
func (w DriftWarning) IsFatal() bool {
	return w.Kind == DriftFM1 || w.Kind == DriftFM2
}

// severity returns the log-level label for this finding.
func (w DriftWarning) severity() string {
	if w.Kind == DriftUncovered {
		return "INFO"
	}
	return "WARN"
}

// LogLine formats the finding as a single structured stderr line.
func (w DriftWarning) LogLine() string {
	switch w.Kind {
	case DriftFM1:
		return fmt.Sprintf(
			`[eunox-mcp] %s drift=fm1 tool=%q resource=%q — new upstream tool matched by manifest glob; verify this is intentional before deploying`,
			w.severity(), w.Tool, w.Resource,
		)
	case DriftFM2:
		return fmt.Sprintf(
			`[eunox-mcp] %s drift=fm2 resource=%q — manifest entry matches no live upstream tool (tool removed or renamed?)`,
			w.severity(), w.Resource,
		)
	case DriftFM3:
		return fmt.Sprintf(
			`[eunox-mcp] %s drift=fm3 resource=%q tool=%q argument=%q — condition argument not in live inputSchema; condition may not enforce if argument was renamed`,
			w.severity(), w.Resource, w.Tool, w.Argument,
		)
	case DriftUncovered:
		return fmt.Sprintf(
			`[eunox-mcp] %s drift=uncovered tool=%q — not covered by manifest; all calls will be denied`,
			w.severity(), w.Tool,
		)
	default:
		return fmt.Sprintf(`[eunox-mcp] WARN drift=%s tool=%q resource=%q`, w.Kind, w.Tool, w.Resource)
	}
}

// CheckManifestDrift compares the manifest against the live upstream tool list
// and returns all drift findings.  Returns nil when no issues are found.
//
// This function is pure (no I/O) and safe to call from tests.
func CheckManifestDrift(manifest *LocalManifest, tools []UpstreamTool) []DriftWarning {
	if manifest == nil {
		return nil
	}

	var warnings []DriftWarning

	// ── FM-1 and uncovered: iterate each live tool against the manifest ────────

	for _, tool := range tools {
		constraint := bestManifestConstraint(manifest, tool.Name)
		if constraint == nil {
			// Not covered — denied by default; informational only.
			warnings = append(warnings, DriftWarning{
				Kind: DriftUncovered,
				Tool: tool.Name,
			})
			continue
		}
		// FM-1: any glob match is a potential silent over-permission.
		// Exact-name matches are intentional by construction.
		if isGlobPattern(constraint.Resource) {
			warnings = append(warnings, DriftWarning{
				Kind:     DriftFM1,
				Tool:     tool.Name,
				Resource: constraint.Resource,
			})
		}
	}

	// ── FM-2: each manifest entry must match at least one live tool ───────────

	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		if anyToolMatches(c.Resource, tools) {
			continue
		}
		warnings = append(warnings, DriftWarning{
			Kind:     DriftFM2,
			Resource: c.Resource,
		})
	}

	// ── FM-3: condition argument names must appear in the live inputSchema ─────

	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		for _, tool := range tools {
			if !matchResource(c.Resource, tool.Name) {
				continue
			}
			props, ok := schemaProperties(tool.InputSchema)
			if !ok {
				// No explicit properties — cannot verify argument names.
				continue
			}
			for _, argName := range conditionArgumentNames(c.Conditions) {
				if _, found := props[argName]; !found {
					warnings = append(warnings, DriftWarning{
						Kind:     DriftFM3,
						Tool:     tool.Name,
						Resource: c.Resource,
						Argument: argName,
					})
				}
			}
		}
	}

	return warnings
}

// hasFatalDrift reports whether warnings contains any finding that should
// abort session establishment under --strict-drift.
func hasFatalDrift(warnings []DriftWarning) bool {
	for _, w := range warnings {
		if w.IsFatal() {
			return true
		}
	}
	return false
}

// emitDriftWarnings writes each finding to w.
func emitDriftWarnings(warnings []DriftWarning) {
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w.LogLine())
	}
}

// isGlobPattern reports whether pattern contains any path.Match metacharacter.
func isGlobPattern(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// anyToolMatches reports whether any tool name in tools matches resource.
func anyToolMatches(resource string, tools []UpstreamTool) bool {
	for _, t := range tools {
		if matchResource(resource, t.Name) {
			return true
		}
	}
	return false
}

// bestManifestConstraint returns the highest-specificity manifest constraint
// whose Resource pattern matches toolName, or nil if none match.
func bestManifestConstraint(manifest *LocalManifest, toolName string) *capability.Constraint {
	best := -1
	bestScore := -(1 << 30)
	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		if !matchResource(c.Resource, toolName) {
			continue
		}
		if s := resSpecificity(c.Resource, toolName); s > bestScore {
			bestScore = s
			best = i
		}
	}
	if best < 0 {
		return nil
	}
	return &manifest.Capabilities[best]
}

// schemaProperties extracts the "properties" map from a JSON Schema.
// Returns (nil, false) when the schema is absent or has no properties.
func schemaProperties(schema map[string]interface{}) (map[string]interface{}, bool) {
	if schema == nil {
		return nil, false
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok || len(props) == 0 {
		return nil, false
	}
	return props, true
}

// conditionArgumentNames returns the explicit argument field values from all
// conditions in the list.  Empty argument fields are omitted.  Duplicates are
// deduplicated.
func conditionArgumentNames(conditions []capability.Condition) []string {
	var names []string
	seen := make(map[string]bool)
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, cond := range conditions {
		switch c := cond.(type) {
		case capability.AllowedValuesCondition:
			add(c.Argument)
		case *capability.AllowedValuesCondition:
			add(c.Argument)
		case capability.AllowedOperationsCondition:
			add(c.Argument)
		case *capability.AllowedOperationsCondition:
			add(c.Argument)
		case capability.AllowedExtensionsCondition:
			add(c.Argument)
		case *capability.AllowedExtensionsCondition:
			add(c.Argument)
		case capability.AllowedTablesCondition:
			add(c.Argument)
		case *capability.AllowedTablesCondition:
			add(c.Argument)
		case capability.RecipientDomainCondition:
			add(c.Argument)
		case *capability.RecipientDomainCondition:
			add(c.Argument)
		}
	}
	return names
}

// ─── tools/list fetch helpers ─────────────────────────────────────────────────

// mcpToolsListResult is the result field of a tools/list response.
type mcpToolsListResult struct {
	Tools []mcpToolEntry `json:"tools"`
}

// mcpToolEntry is one tool in the tools/list result.
type mcpToolEntry struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// parseToolsListResult decodes the raw JSON result from a tools/list response.
func parseToolsListResult(raw json.RawMessage) ([]UpstreamTool, error) {
	if raw == nil {
		return nil, nil
	}
	var result mcpToolsListResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parsing tools/list result: %w", err)
	}
	tools := make([]UpstreamTool, len(result.Tools))
	for i, t := range result.Tools {
		tools[i] = UpstreamTool{Name: t.Name, InputSchema: t.InputSchema}
	}
	return tools, nil
}

// fetchHTTPSessionTools sends tools/list via the HTTP session's callUpstream
// and returns the parsed tool list.
func fetchHTTPSessionTools(ctx context.Context, sess *httpSession) ([]UpstreamTool, error) {
	req := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`"_drift"`),
		Method:  "tools/list",
	}
	resp, err := sess.callUpstream(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list: upstream error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return parseToolsListResult(resp.Result)
}

// fetchStdioTools sends tools/list directly to the upstream subprocess before
// the background readUpstream goroutine is started.
func fetchStdioTools(proxy *StdioProxy) ([]UpstreamTool, error) {
	req := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`"_drift"`),
		Method:  "tools/list",
	}
	if err := proxy.upWriter.Write(req); err != nil {
		return nil, fmt.Errorf("tools/list write: %w", err)
	}
	const maxDiscard = 20
	for i := 0; i < maxDiscard; i++ {
		msg, err := proxy.upReader.Read()
		if err != nil {
			return nil, fmt.Errorf("tools/list read: %w", err)
		}
		if msg.isResponse() && msgKey(msg.ID) == `"_drift"` {
			if msg.Error != nil {
				return nil, fmt.Errorf("tools/list: upstream error %d: %s", msg.Error.Code, msg.Error.Message)
			}
			return parseToolsListResult(msg.Result)
		}
		// Discard notifications arriving before the response.
	}
	return nil, fmt.Errorf("tools/list: no response within %d messages", maxDiscard)
}

// runHTTPDriftCheck performs the drift check for an HTTP session.
//
// It fetches tools/list, runs CheckManifestDrift, and emits warnings to
// stderr.  In strict mode it returns a non-nil error when any fatal finding
// is present; the caller must close the session and abort.
//
// On tools/list failure the check is silently skipped (best-effort): the
// upstream may not support tools/list, or the session may be in a state where
// the method is unavailable.
func runHTTPDriftCheck(ctx context.Context, sess *httpSession, manifest *LocalManifest, strict bool) error {
	tools, err := fetchHTTPSessionTools(ctx, sess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] WARN drift check skipped (tools/list unavailable): %v\n", err)
		return nil
	}
	warnings := CheckManifestDrift(manifest, tools)
	emitDriftWarnings(warnings)
	if strict && hasFatalDrift(warnings) {
		return fmt.Errorf("startup aborted by --strict-drift: manifest drift detected (see warnings above)")
	}
	return nil
}

// runStdioDriftCheck performs the drift check for a stdio session.
//
// It must be called after initUpstream but before the readUpstream goroutine
// is started (so it can read directly from upReader without racing).
func runStdioDriftCheck(proxy *StdioProxy, manifest *LocalManifest, strict bool) error {
	tools, err := fetchStdioTools(proxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] WARN drift check skipped (tools/list unavailable): %v\n", err)
		return nil
	}
	warnings := CheckManifestDrift(manifest, tools)
	emitDriftWarnings(warnings)
	if strict && hasFatalDrift(warnings) {
		return fmt.Errorf("startup aborted by --strict-drift: manifest drift detected (see warnings above)")
	}
	return nil
}

// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// PolicyDecisionPoint evaluates whether a tool call should be permitted.
// It returns a capability.EnforceResponse — the same type used by the
// enforcement engine and the hosted gateway.
type PolicyDecisionPoint interface {
	Decide(ctx context.Context, sessionID, toolName string, args map[string]interface{}, sourceIP string) capability.EnforceResponse
}

// -----------------------------------------------------------------
// AlwaysAllowPDP — transparent passthrough
// -----------------------------------------------------------------

type alwaysAllowPDP struct{}

func (alwaysAllowPDP) Decide(_ context.Context, _, _ string, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{Decision: capability.DecisionAllow}
}

// -----------------------------------------------------------------
// ManifestPDP — enforces the LocalManifest using the Go enforcement engine
// -----------------------------------------------------------------

// ManifestPDP applies the local capability manifest to every tool call.
//
// Matching semantics (mirrors the TypeScript PDP):
//   - A tool call is allowed if NO constraint in the manifest matches the tool name.
//   - If a constraint matches, conditions are evaluated.  A failure denies.
//   - Actions must include "call", "*", or a semantic category ("read", "write",
//     "delete", "execute", "admin") that matches the resolved action for the tool.
//
// Action resolution (in priority order):
//  1. Exact match in the configured ActionResolver (custom map or built-in profile).
//  2. HeuristicResolver — name-prefix inference (e.g. "get_*" → read).
//  3. Generic fallback — if neither resolver classifies the tool, "call" or "*"
//     in the constraint's actions list still permits the call.
//
// The enforcement engine is used for condition evaluation, but capability
// matching uses proxy-local resource matching so that Context.Operation can
// be set to the extracted SQL/operation verb (for allowedOperations) rather
// than to "call" (which is the MCP action literal).
type ManifestPDP struct {
	manifest *LocalManifest
	engine   *enforcement.Engine
	ks       killswitch.Manager
	resolver ActionResolver // optional; enables semantic action matching
}

// NewManifestPDP creates a PDP backed by the given manifest.
// engine must have a CallCounter configured to support maxCalls conditions.
func NewManifestPDP(manifest *LocalManifest, engine *enforcement.Engine, ks killswitch.Manager) *ManifestPDP {
	return &ManifestPDP{manifest: manifest, engine: engine, ks: ks}
}

// WithResolver attaches an ActionResolver to the PDP, enabling semantic action
// matching in manifest constraints (actions: ["read"], actions: ["write"], etc.).
// Returns p for fluent chaining.
func (p *ManifestPDP) WithResolver(r ActionResolver) *ManifestPDP {
	p.resolver = r
	return p
}

func (p *ManifestPDP) Decide(ctx context.Context, sessionID, toolName string, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	// 1. Kill switch check.
	blocked, _ := p.ks.ShouldBlock(ctx, "", sessionID)
	if blocked {
		return capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial: &capability.DenialInfo{
				Code:          "KILL_SWITCH",
				ConditionType: "kill",
				Message:       "session has been terminated by a kill-switch command",
			},
		}
	}

	// 2. Find the most specific matching constraint.
	matched := p.findConstraint(toolName)
	if matched == nil {
		// No constraint covers this tool → allow (manifest restricts only listed tools).
		return capability.EnforceResponse{Decision: capability.DecisionAllow}
	}

	// 3. Verify the constraint permits this tool call.
	// Two modes are supported:
	//   Generic:   actions includes "call" or "*" → permits any MCP tool call.
	//   Semantic:  actions includes a resolved category ("read", "write", "delete",
	//              "execute", "admin") → matched via the ActionResolver chain.
	if !p.actionPermitted(matched.Actions, toolName) {
		resolvedCat := p.resolveAction(toolName)
		catDesc := string(resolvedCat)
		if catDesc == "" {
			catDesc = "unknown (not classified by resolver)"
		}
		return capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial: &capability.DenialInfo{
				Code:    "CAPABILITY_DENIED",
				Message: fmt.Sprintf("tool %q resolved to action %q which is not permitted by constraint %q (allowed: %s)", toolName, catDesc, matched.Resource, strings.Join(matched.Actions, ", ")),
			},
		}
	}

	// 4. Argument schema validation.
	if matched.ArgumentSchema != nil {
		if err := validateSchema("$", args, matched.ArgumentSchema); err != nil {
			return capability.EnforceResponse{
				Decision: capability.DecisionDeny,
				Denial: &capability.DenialInfo{
					Code:          "ARGUMENT_VALIDATION_FAILED",
					ConditionType: "argumentSchema",
					Message:       err.Error(),
				},
			}
		}
	}

	// 5. Condition evaluation via the enforcement engine.
	//    We pass a synthetic constraint (resource="*", actions=["*"]) so that the
	//    engine's action-matching logic does not interfere with the MCP "call"
	//    action.  Context.Operation is set to the extracted SQL/operation verb so
	//    that allowedOperations conditions work correctly against the tool args.
	synth := capability.Constraint{
		Resource:   "*",
		Actions:    []string{"*"},
		Conditions: matched.Conditions,
	}
	req := &capability.EnforceRequest{
		SessionID: sessionID,
		ToolName:  toolName,
		Arguments: args,
		Context: capability.EnforceRequestContext{
			SourceIP:   sourceIP,
			Operation:  extractSQLOperation(args),
			FilePath:   extractFilePath(args),
			Recipients: extractRecipients(args),
			Tables:     extractTables(args),
		},
	}

	resp, err := p.engine.ValidateAction(ctx, req, []capability.Constraint{synth})
	if err != nil {
		return capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial:   &capability.DenialInfo{Code: "ENFORCEMENT_ERROR", Message: err.Error()},
		}
	}
	return resp
}

// actionPermitted reports whether the constraint actions list permits a call
// to toolName.
//
// Rules (checked in order):
//  1. "call" or "*" in actions → always permit (backwards-compatible generic mode).
//  2. Resolved semantic category (via resolver chain) matches one of the listed
//     actions → permit.
//  3. Neither rule satisfied → deny.
func (p *ManifestPDP) actionPermitted(actions []string, toolName string) bool {
	// Generic mode: "call" / "*" passthrough — preserves backwards compatibility
	// for manifests written before ActionResolver support was added.
	if containsAction(actions, "call") || containsAction(actions, "*") {
		return true
	}
	// Semantic mode: check whether the resolved category is in the actions list.
	cat := p.resolveAction(toolName)
	if cat == "" {
		// No resolver could classify the tool and "call"/"*" is absent → deny.
		return false
	}
	return containsAction(actions, string(cat))
}

// resolveAction returns the semantic ActionCategory for toolName by querying
// the configured resolver first, then falling back to the HeuristicResolver.
func (p *ManifestPDP) resolveAction(toolName string) ActionCategory {
	if p.resolver != nil {
		if cat := p.resolver.Resolve(toolName); cat != "" {
			return cat
		}
	}
	return HeuristicResolver{}.Resolve(toolName)
}

// findConstraint returns the most specific capability.Constraint whose Resource
// pattern matches toolName, or nil if none match.
func (p *ManifestPDP) findConstraint(toolName string) *capability.Constraint {
	best := -1
	bestScore := -(1 << 30)
	for i := range p.manifest.Capabilities {
		c := &p.manifest.Capabilities[i]
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
	return &p.manifest.Capabilities[best]
}

// matchResource reports whether the resource pattern matches the tool name.
// Mirrors enforcement.matchesResource (which is unexported).
func matchResource(pattern, toolName string) bool {
	if pattern == "*" || pattern == toolName {
		return true
	}
	matched, err := path.Match(pattern, toolName)
	return err == nil && matched
}

// resSpecificity scores how specific a resource pattern is.
// Mirrors enforcement.resourceSpecificity (unexported).
func resSpecificity(pattern, toolName string) int {
	if pattern == toolName {
		return 1000
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return 900
	}
	prefix := 0
	for _, r := range pattern {
		if strings.ContainsRune("*?[", r) {
			break
		}
		prefix++
	}
	wildcards := strings.Count(pattern, "*") + strings.Count(pattern, "?") + strings.Count(pattern, "[")
	return prefix*10 - wildcards
}

// containsAction reports whether actions contains act or the wildcard "*".
func containsAction(actions []string, act string) bool {
	for _, a := range actions {
		if a == act || a == "*" {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------
// Argument context extraction helpers
// -----------------------------------------------------------------

func extractSQLOperation(args map[string]interface{}) string {
	for _, key := range []string{"sql", "query", "statement"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					parts := strings.Fields(s)
					if len(parts) > 0 {
						return strings.ToUpper(parts[0])
					}
				}
			}
		}
	}
	return ""
}

func extractFilePath(args map[string]interface{}) string {
	for _, key := range []string{"filePath", "path", "file", "filename"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func extractRecipients(args map[string]interface{}) []string {
	var out []string
	addField := func(v interface{}) {
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				out = append(out, s)
			}
		case []interface{}:
			for _, item := range t {
				if s, ok := item.(string); ok {
					if s = strings.TrimSpace(s); s != "" {
						out = append(out, s)
					}
				}
			}
		}
	}
	for _, key := range []string{"to", "recipients", "cc", "bcc"} {
		if v, ok := args[key]; ok {
			addField(v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractTables(args map[string]interface{}) []capability.TableAccess {
	if v, ok := args["table"]; ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return []capability.TableAccess{{Table: strings.TrimSpace(s)}}
		}
	}
	if v, ok := args["tables"]; ok {
		if arr, ok := v.([]interface{}); ok {
			var out []capability.TableAccess
			for _, entry := range arr {
				switch e := entry.(type) {
				case string:
					if s := strings.TrimSpace(e); s != "" {
						out = append(out, capability.TableAccess{Table: s})
					}
				case map[string]interface{}:
					tbl, _ := e["table"].(string)
					if tbl = strings.TrimSpace(tbl); tbl == "" {
						continue
					}
					ta := capability.TableAccess{Table: tbl}
					if cols, ok := e["columns"].([]interface{}); ok {
						for _, c := range cols {
							if col, ok := c.(string); ok && col != "" {
								ta.Columns = append(ta.Columns, col)
							}
						}
					}
					out = append(out, ta)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------
// JSON Schema argument validation (subset: type, pattern, minLength,
// maxLength, minimum, maximum, required, enum, properties,
// additionalProperties, items, minItems, maxItems)
// -----------------------------------------------------------------

func validateSchema(jsonPath string, args map[string]interface{}, schema *capability.ArgumentSchema) error {
	return validateValue(jsonPath, args, schema)
}

func validateValue(jsonPath string, val interface{}, schema *capability.ArgumentSchema) error {
	if schema == nil {
		return nil
	}

	if len(schema.Enum) > 0 {
		for _, allowed := range schema.Enum {
			if reflect.DeepEqual(allowed, val) {
				return nil
			}
		}
		return fmt.Errorf("%s: value not in enum", jsonPath)
	}

	switch v := val.(type) {
	case string:
		if err := validateString(jsonPath, v, schema); err != nil {
			return err
		}
	case float64:
		if err := validateNumber(jsonPath, v, schema); err != nil {
			return err
		}
	case map[string]interface{}:
		if err := validateObject(jsonPath, v, schema); err != nil {
			return err
		}
	case []interface{}:
		if err := validateArray(jsonPath, v, schema); err != nil {
			return err
		}
	}
	return nil
}

func validateString(p, v string, s *capability.ArgumentSchema) error {
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("%s: invalid pattern %q: %w", p, s.Pattern, err)
		}
		if !re.MatchString(v) {
			return fmt.Errorf("%s: value does not match pattern %q", p, s.Pattern)
		}
	}
	if s.MinLength != nil && len(v) < *s.MinLength {
		return fmt.Errorf("%s: string length %d is less than minLength %d", p, len(v), *s.MinLength)
	}
	if s.MaxLength != nil && len(v) > *s.MaxLength {
		return fmt.Errorf("%s: string length %d exceeds maxLength %d", p, len(v), *s.MaxLength)
	}
	return nil
}

func validateNumber(p string, v float64, s *capability.ArgumentSchema) error {
	if s.Minimum != nil && v < *s.Minimum {
		return fmt.Errorf("%s: value %g is less than minimum %g", p, v, *s.Minimum)
	}
	if s.Maximum != nil && v > *s.Maximum {
		return fmt.Errorf("%s: value %g exceeds maximum %g", p, v, *s.Maximum)
	}
	return nil
}

func validateObject(p string, v map[string]interface{}, s *capability.ArgumentSchema) error {
	for _, req := range s.Required {
		if _, ok := v[req]; !ok {
			return fmt.Errorf("%s: missing required field %q", p, req)
		}
	}
	for name, propSchema := range s.Properties {
		propVal, ok := v[name]
		if !ok {
			continue
		}
		if err := validateValue(p+"."+name, propVal, propSchema); err != nil {
			return err
		}
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties {
		for name := range v {
			if _, ok := s.Properties[name]; !ok {
				return fmt.Errorf("%s: additional property %q is not allowed", p, name)
			}
		}
	}
	return nil
}

func validateArray(p string, v []interface{}, s *capability.ArgumentSchema) error {
	if s.MinItems != nil && len(v) < *s.MinItems {
		return fmt.Errorf("%s: array length %d is less than minItems %d", p, len(v), *s.MinItems)
	}
	if s.MaxItems != nil && len(v) > *s.MaxItems {
		return fmt.Errorf("%s: array length %d exceeds maxItems %d", p, len(v), *s.MaxItems)
	}
	if s.Items != nil {
		for i, item := range v {
			if err := validateValue(fmt.Sprintf("%s[%d]", p, i), item, s.Items); err != nil {
				return err
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------
// redactFields obligation: strip JSON paths from tool-call result text
// -----------------------------------------------------------------

func applyRedactObligs(resultBytes []byte, obligs []capability.Obligation) []byte {
	if len(obligs) == 0 {
		return resultBytes
	}

	var paths []string
	for _, ob := range obligs {
		if ob.Type == "redactFields" {
			paths = append(paths, ob.Paths...)
		}
	}
	if len(paths) == 0 {
		return resultBytes
	}

	var result mcpToolCallResult
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return resultBytes
	}

	for i, c := range result.Content {
		if c.Type != "text" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(c.Text), &obj); err != nil {
			continue
		}
		for _, p := range paths {
			redactDotPath(obj, p)
		}
		redacted, err := json.Marshal(obj)
		if err == nil {
			result.Content[i].Text = string(redacted)
		}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return resultBytes
	}
	return out
}

func redactDotPath(obj map[string]interface{}, dotPath string) {
	dotPath = strings.TrimPrefix(dotPath, "$.")
	dotPath = strings.TrimPrefix(dotPath, "$")

	parts := strings.SplitN(dotPath, ".", 2)
	key := parts[0]
	if len(parts) == 1 {
		delete(obj, key)
		return
	}
	if child, ok := obj[key].(map[string]interface{}); ok {
		redactDotPath(child, parts[1])
	}
}

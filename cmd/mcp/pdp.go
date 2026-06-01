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
// Matching semantics:
//   - The manifest is an allowlist: only tools with an explicit capability entry
//     are permitted.  A tool absent from the manifest is denied by default.
//   - The actions list must contain "call" or "*" to permit the call.
//   - If a constraint matches, conditions are evaluated.  A failure denies.
type ManifestPDP struct {
	manifest *LocalManifest
	engine   *enforcement.Engine
	ks       killswitch.Manager
}

// NewManifestPDP creates a PDP backed by the given manifest.
// engine must have a CallCounter configured to support maxCalls conditions.
func NewManifestPDP(manifest *LocalManifest, engine *enforcement.Engine, ks killswitch.Manager) *ManifestPDP {
	return &ManifestPDP{manifest: manifest, engine: engine, ks: ks}
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
	// The manifest is an allowlist: absent tools are denied by default so that
	// operators must explicitly grant access rather than accidentally permitting
	// any tool the upstream MCP server happens to expose.
	matched := p.findConstraint(toolName)
	if matched == nil {
		return capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial: &capability.DenialInfo{
				Code:    capability.ErrCodeAuthorizationFailed,
				Message: fmt.Sprintf("tool %q is not listed in the capability manifest", toolName),
			},
		}
	}

	// 3. Check that the constraint's actions list contains "call" or "*".
	if !containsAction(matched.Actions, "call") && !containsAction(matched.Actions, "*") {
		return capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial: &capability.DenialInfo{
				Code:    "CAPABILITY_DENIED",
				Message: fmt.Sprintf("constraint %q does not permit tool calls (actions must include 'call' or '*'; got: %s)", matched.Resource, strings.Join(matched.Actions, ", ")),
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
	//    engine's action-matching logic does not re-check the actions list.
	synth := capability.Constraint{
		Resource:   "*",
		Actions:    []string{"*"},
		Conditions: matched.Conditions,
	}
	req := &capability.EnforceRequest{
		SessionID: sessionID,
		ToolName:  toolName,
		Arguments: args,
		Context:   capability.EnforceRequestContext{SourceIP: sourceIP},
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

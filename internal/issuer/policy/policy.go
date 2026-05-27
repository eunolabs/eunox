// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package policy implements the role-to-capability policy engine for the Capability Issuer.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
)

// ErrPolicyNotFound indicates no policy exists for the requested role.
var ErrPolicyNotFound = errors.New("no policy found for role")

// ErrInvalidManifest indicates the requested capabilities exceed what the manifest allows.
var ErrInvalidManifest = errors.New("requested capabilities exceed manifest bounds")

// ErrSubsetViolation indicates an attenuation request violates the subset invariant.
var ErrSubsetViolation = errors.New("child capabilities must be a strict subset of parent")

// RoleCapabilityPolicy defines the capabilities granted to a role.
type RoleCapabilityPolicy struct {
	Role           string                  `json:"role"`
	Description    string                  `json:"description,omitempty"`
	MaxTTLSeconds  int                     `json:"maxTtlSeconds"`
	Capabilities   []capability.Constraint `json:"capabilities"`
	AllowedActions []string                `json:"allowedActions,omitempty"`
	MaxCalls       *int                    `json:"maxCalls,omitempty"`
	Conditions     []capability.Condition  `json:"conditions,omitempty"`
}

// File represents the on-disk JSON policy file structure.
type File struct {
	Version  string                 `json:"version"`
	Policies []RoleCapabilityPolicy `json:"policies"`
}

// Engine manages role-to-capability policies with hot-reload support.
type Engine struct {
	mu            sync.RWMutex
	policies      map[string]*RoleCapabilityPolicy
	filePath      string
	lastModified  time.Time
	pollInterval  time.Duration
	stopCh        chan struct{}
	stopOnce      sync.Once
	startOnce     sync.Once
	defaultMaxTTL int
	onReloadError func(error)
}

// Option configures the policy Engine.
type Option func(*Engine)

// WithPollInterval sets the interval for checking policy file changes.
func WithPollInterval(d time.Duration) Option {
	return func(e *Engine) {
		e.pollInterval = d
	}
}

// WithDefaultMaxTTL sets the default maximum token TTL in seconds.
func WithDefaultMaxTTL(seconds int) Option {
	return func(e *Engine) {
		e.defaultMaxTTL = seconds
	}
}

// WithOnReloadError sets a callback for policy reload errors.
func WithOnReloadError(fn func(error)) Option {
	return func(e *Engine) {
		e.onReloadError = fn
	}
}

// New creates a new policy Engine. If filePath is non-empty, it loads policies from disk.
func New(opts ...Option) *Engine {
	e := &Engine{
		policies:      make(map[string]*RoleCapabilityPolicy),
		stopCh:        make(chan struct{}),
		pollInterval:  30 * time.Second,
		defaultMaxTTL: 900, // 15 minutes
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// LoadFromFile loads policies from a JSON file.
func (e *Engine) LoadFromFile(filePath string) error {
	e.filePath = filePath
	return e.reload()
}

// StartHotReload starts a background goroutine that watches for policy file changes.
func (e *Engine) StartHotReload() {
	if e.filePath == "" {
		return
	}
	e.startOnce.Do(func() {
		go e.pollLoop()
	})
}

// Stop stops the hot-reload polling loop.
func (e *Engine) Stop() {
	if e.stopCh == nil {
		return
	}
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
}

// GetPolicy returns the policy for the given role.
func (e *Engine) GetPolicy(role string) (*RoleCapabilityPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policy, ok := e.policies[role]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, role)
	}
	return policy, nil
}

// ListPolicies returns all configured policies.
func (e *Engine) ListPolicies() []*RoleCapabilityPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*RoleCapabilityPolicy, 0, len(e.policies))
	for _, p := range e.policies {
		result = append(result, p)
	}
	return result
}

// SetPolicy adds or updates a policy for a role.
func (e *Engine) SetPolicy(policy *RoleCapabilityPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[policy.Role] = policy
}

// RemovePolicy removes the policy for a role. Returns true if it existed.
func (e *Engine) RemovePolicy(role string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, existed := e.policies[role]
	delete(e.policies, role)
	return existed
}

// MaxTTLForRole returns the maximum token TTL for a role in seconds.
func (e *Engine) MaxTTLForRole(role string) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policy, ok := e.policies[role]
	if !ok || policy.MaxTTLSeconds <= 0 {
		return e.defaultMaxTTL
	}
	return policy.MaxTTLSeconds
}

// IntersectCapabilities narrows requested capabilities to the intersection
// of what's allowed by the role policy. Returns only constraints that are
// within policy bounds.
func (e *Engine) IntersectCapabilities(role string, requested []capability.Constraint) ([]capability.Constraint, error) {
	policy, err := e.GetPolicy(role)
	if err != nil {
		return nil, err
	}

	if len(requested) == 0 {
		// If no specific request, return policy defaults
		return policy.Capabilities, nil
	}

	result := make([]capability.Constraint, 0, len(requested))
	for _, req := range requested {
		matched := findMatchingPolicyConstraint(req, policy.Capabilities)
		if matched == nil {
			continue
		}
		intersected := intersectConstraint(req, matched)
		if intersected != nil {
			result = append(result, *intersected)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("%w: no requested capabilities match policy for role %s", ErrInvalidManifest, role)
	}

	return result, nil
}

// ValidateSubset checks that child capabilities are a strict subset of parent capabilities.
// Used for attenuation: child ⊆ parent.
func ValidateSubset(child, parent []capability.Constraint) error {
	for _, c := range child {
		if !isSubsetOfAny(c, parent) {
			return fmt.Errorf("%w: resource %q not covered by parent capabilities", ErrSubsetViolation, c.Resource)
		}
	}
	return nil
}

func (e *Engine) reload() error {
	data, err := os.ReadFile(e.filePath)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	var pf File
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse policy file: %w", err)
	}

	newPolicies := make(map[string]*RoleCapabilityPolicy, len(pf.Policies))
	for i := range pf.Policies {
		p := &pf.Policies[i]
		newPolicies[p.Role] = p
	}

	e.mu.Lock()
	e.policies = newPolicies
	e.mu.Unlock()

	return nil
}

func (e *Engine) pollLoop() {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			info, err := os.Stat(e.filePath)
			if err != nil {
				if e.onReloadError != nil {
					e.onReloadError(err)
				}
				continue
			}
			if info.ModTime().After(e.lastModified) {
				if err := e.reload(); err != nil {
					if e.onReloadError != nil {
						e.onReloadError(err)
					}
				} else {
					e.lastModified = info.ModTime()
				}
			}
		}
	}
}

// findMatchingPolicyConstraint finds the policy constraint that covers the requested resource.
func findMatchingPolicyConstraint(requested capability.Constraint, policyConstraints []capability.Constraint) *capability.Constraint {
	for i := range policyConstraints {
		pc := &policyConstraints[i]
		if resourceCovers(pc.Resource, requested.Resource) {
			return pc
		}
	}
	return nil
}

// resourceCovers checks if the policy resource pattern covers the requested resource.
func resourceCovers(policyResource, requestedResource string) bool {
	if policyResource == "*" {
		return true
	}
	if policyResource == requestedResource {
		return true
	}
	// Glob-style prefix: "tool:*" covers "tool:read"
	if policyResource != "" && policyResource[len(policyResource)-1] == '*' {
		prefix := policyResource[:len(policyResource)-1]
		return len(requestedResource) >= len(prefix) && requestedResource[:len(prefix)] == prefix
	}
	return false
}

// intersectConstraint returns the intersection of a requested and policy constraint.
func intersectConstraint(requested capability.Constraint, policy *capability.Constraint) *capability.Constraint {
	// Resource: use the more specific one (requested)
	result := &capability.Constraint{
		Resource: requested.Resource,
	}

	// Actions: intersection
	switch {
	case len(policy.Actions) == 0 || containsWildcard(policy.Actions):
		result.Actions = requested.Actions
	case len(requested.Actions) == 0 || containsWildcard(requested.Actions):
		result.Actions = policy.Actions
	default:
		result.Actions = intersectStrings(requested.Actions, policy.Actions)
		if len(result.Actions) == 0 {
			return nil
		}
	}

	// Conditions: union (both requested + policy conditions apply)
	result.Conditions = mergeConditions(requested.Conditions, policy.Conditions)

	// ArgumentSchema: use policy's schema if provided
	if policy.ArgumentSchema != nil {
		result.ArgumentSchema = policy.ArgumentSchema
	} else {
		result.ArgumentSchema = requested.ArgumentSchema
	}

	return result
}

// isSubsetOfAny checks if a child constraint is covered by at least one parent constraint.
func isSubsetOfAny(child capability.Constraint, parents []capability.Constraint) bool {
	for _, parent := range parents {
		if isSubset(child, parent) {
			return true
		}
	}
	return false
}

// isSubset checks if child is a subset of parent.
func isSubset(child, parent capability.Constraint) bool {
	// Resource must be covered
	if !resourceCovers(parent.Resource, child.Resource) {
		return false
	}

	// Actions must be subset
	if len(parent.Actions) > 0 && !containsWildcard(parent.Actions) {
		if len(child.Actions) == 0 || containsWildcard(child.Actions) {
			return false // child requests more than parent allows
		}
		for _, ca := range child.Actions {
			if !containsString(parent.Actions, ca) {
				return false
			}
		}
	}

	if !isConditionSubset(child.Conditions, parent.Conditions) {
		return false
	}

	if parent.ArgumentSchema != nil && !isArgumentSchemaEqual(child.ArgumentSchema, parent.ArgumentSchema) {
		return false
	}

	return true
}

func containsWildcard(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, item := range ss {
		if item == s {
			return true
		}
	}
	return false
}

func intersectStrings(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, s := range b {
		bSet[s] = struct{}{}
	}
	var result []string
	for _, s := range a {
		if _, ok := bSet[s]; ok {
			result = append(result, s)
		}
	}
	return result
}

func mergeConditions(a, b []capability.Condition) []capability.Condition {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	merged := make([]capability.Condition, 0, len(a)+len(b))
	merged = append(merged, a...)
	merged = append(merged, b...)
	return merged
}

func isConditionSubset(child, parent []capability.Condition) bool {
	if len(parent) == 0 {
		return true
	}
	if len(child) == 0 {
		return false
	}

	childDigests := make([]string, 0, len(child))
	for _, condition := range child {
		digest, ok := conditionDigest(condition)
		if !ok {
			return false
		}
		childDigests = append(childDigests, digest)
	}

	for _, condition := range parent {
		digest, ok := conditionDigest(condition)
		if !ok {
			return false
		}
		if !slices.Contains(childDigests, digest) {
			return false
		}
	}

	return true
}

func conditionDigest(condition capability.Condition) (string, bool) {
	encoded, err := json.Marshal(condition)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func isArgumentSchemaEqual(child, parent *capability.ArgumentSchema) bool {
	if parent == nil {
		return true
	}
	if child == nil {
		return false
	}
	return jsonEqual(child, parent)
}

func jsonEqual(a, b interface{}) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

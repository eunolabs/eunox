// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package enforcement implements the capability enforcement engine that evaluates
// conditions against incoming requests and produces allow/deny decisions.
package enforcement

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/google/uuid"
)

// ConditionHandler evaluates a single condition against an enforcement request.
// It returns nil if the condition is satisfied, or a non-nil *ConditionError if not.
type ConditionHandler func(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) *ConditionError

// ConditionError describes a condition evaluation failure.
type ConditionError struct {
	Code          string
	ConditionType string
	Message       string
	Details       map[string]interface{}
}

func (e *ConditionError) Error() string {
	return e.Message
}

// Clock provides the current time for condition evaluation. It is satisfied by
// [testutil.FakeClock] in tests and by the system clock in production.
type Clock interface {
	Now() time.Time
}

// CallCounter is the interface for tracking per-key call counts (used by maxCalls condition).
type CallCounter interface {
	IncrementAndGet(ctx context.Context, key string, windowSec int) (int64, error)
}

// PolicyEvaluator evaluates a policy condition against an enforce request by
// calling an external policy decision point (e.g. OPA, Cedar). Implementations
// must return nil to allow or a non-nil [*ConditionError] to deny.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, backend string, config, input interface{}, req *capability.EnforceRequest) *ConditionError
}

// Engine is the enforcement decision engine. It evaluates enforce requests
// against a set of capabilities and registered condition handlers.
type Engine struct {
	mu              sync.RWMutex
	handlers        map[string]ConditionHandler
	clock           Clock
	counter         CallCounter
	policyEvaluator PolicyEvaluator
}

// Option configures the Engine.
type Option func(*Engine)

// WithClock sets a custom clock for time-based condition evaluation.
func WithClock(clock Clock) Option {
	return func(e *Engine) {
		e.clock = clock
	}
}

// WithCallCounter sets the call counter backend for maxCalls evaluation.
func WithCallCounter(counter CallCounter) Option {
	return func(e *Engine) {
		e.counter = counter
	}
}

// WithPolicyEvaluator sets the evaluator used to resolve policy conditions.
// When no evaluator is configured, any capability that contains a policy
// condition is denied (fail-closed). Set this option to connect the engine to
// an external policy decision point such as OPA or Cedar.
func WithPolicyEvaluator(pe PolicyEvaluator) Option {
	return func(e *Engine) {
		e.policyEvaluator = pe
	}
}

// ctxDryRunKey is the unexported context key used by WithDryRun.
type ctxDryRunKey struct{}

// WithDryRun returns a context that signals the engine to skip counter-based
// side effects (MaxCalls) during condition evaluation.
//
// Use this for preflight paths (e.g. /api/v1/validate) where conditions such
// as time windows and IP ranges must be evaluated but call quotas must not be
// consumed.  WithDryRun does NOT skip any other condition type — the decision
// reflects actual policy except that MaxCalls is treated as always-passing.
func WithDryRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxDryRunKey{}, true)
}

// isDryRun reports whether ctx was decorated with WithDryRun.
func isDryRun(ctx context.Context) bool {
	v, _ := ctx.Value(ctxDryRunKey{}).(bool)
	return v
}

// systemClock is the default Clock backed by the real system time.
type systemClock struct{}

// Now returns the current system time.
func (systemClock) Now() time.Time { return time.Now() }

// New creates a new enforcement Engine with all built-in condition handlers registered.
func New(opts ...Option) *Engine {
	e := &Engine{
		handlers: make(map[string]ConditionHandler),
		clock:    systemClock{},
	}
	for _, opt := range opts {
		opt(e)
	}
	e.registerBuiltins()
	return e
}

// Enforcer is the minimal interface that enforcement consumers (e.g. the
// gateway) should depend on rather than the concrete *Engine type. Accepting
// Enforcer instead of *Engine decouples the caller from the implementation,
// making it straightforward to substitute a remote enforcement backend or a
// test double without modifying call sites.
type Enforcer interface {
	// ValidateAction evaluates req against capabilities and returns a decision.
	ValidateAction(ctx context.Context, req *capability.EnforceRequest, capabilities []capability.Constraint) (capability.EnforceResponse, error)
	// FindMatchingCapability returns the most specific matching constraint, or
	// nil if none match.
	FindMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint
}

// RegisterCondition registers a custom condition handler. It overwrites any existing handler
// for the same condition type.
func (e *Engine) RegisterCondition(name string, handler ConditionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[name] = handler
}

// ValidateAction evaluates an enforce request against the provided capabilities.
// It returns an EnforceResponse with the decision and any obligations.
func (e *Engine) ValidateAction(ctx context.Context, req *capability.EnforceRequest, capabilities []capability.Constraint) (capability.EnforceResponse, error) {
	requestID := uuid.New().String()
	now := e.clock.Now().UTC().Format(time.RFC3339)

	// Find matching capability
	matched := e.findMatchingCapability(req, capabilities)
	if matched == nil {
		return capability.EnforceResponse{
			RequestID: requestID,
			Decision:  capability.DecisionDeny,
			DecidedAt: now,
			Denial: &capability.DenialInfo{
				Code:    capability.ErrCodeAuthorizationFailed,
				Message: "no matching capability for requested action",
			},
		}, nil
	}

	// Evaluate all conditions on the matched capability
	var obligations []capability.Obligation
	for _, cond := range matched.Conditions {
		condType := cond.ConditionType()

		// RedactFields produces an obligation, not a denial
		if condType == capability.ConditionTypeRedactFields {
			rc, ok := cond.(*capability.RedactFieldsCondition)
			if !ok {
				// unmarshalCondition always returns *RedactFieldsCondition for this
				// condition type; a value-form assertion here would be dead code.
				// If this invariant is ever violated it is a programming error.
				panic(fmt.Sprintf("enforcement: ConditionTypeRedactFields yielded unexpected type %T", cond))
			}
			obligations = append(obligations, capability.Obligation{
				Type:  "redactFields",
				Paths: rc.Fields,
			})
			continue
		}

		e.mu.RLock()
		handler, exists := e.handlers[condType]
		e.mu.RUnlock()

		if !exists {
			// Fail closed on unknown condition types
			return capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: now,
				Denial: &capability.DenialInfo{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: condType,
					Message:       fmt.Sprintf("unknown condition type: %s", condType),
				},
			}, nil
		}

		if condErr := handler(ctx, cond, req); condErr != nil {
			return capability.EnforceResponse{
				RequestID: requestID,
				Decision:  capability.DecisionDeny,
				DecidedAt: now,
				Denial: &capability.DenialInfo{
					Code:          condErr.Code,
					ConditionType: condErr.ConditionType,
					Message:       condErr.Message,
					Details:       condErr.Details,
				},
			}, nil
		}
	}

	return capability.EnforceResponse{
		RequestID:   requestID,
		Decision:    capability.DecisionAllow,
		Obligations: obligations,
		DecidedAt:   now,
	}, nil
}

// FindMatchingCapability returns the most specific capability that matches the
// request, or nil if none match.  It uses the same glob semantics and
// specificity scoring as [ValidateAction], and is exported so that callers
// that need the matched constraint (e.g. the validate endpoint) can obtain it
// without re-implementing the selection logic.
func (e *Engine) FindMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	return e.findMatchingCapability(req, capabilities)
}

// findMatchingCapability finds the most specific capability that matches the request.
//
// noMatchScore is the sentinel value for "no matching capability found yet".
const noMatchScore = -1 << 30

// resourceScoreWeight weights resource specificity 10× more than action specificity
// so that a narrower resource pattern always beats a broader one, regardless of
// how specific the action match is.
const resourceScoreWeight = 10

// Tie-breaking is stable: if two capabilities have identical resource and action
// specificity scores, the one that appears first in the list wins.
func (e *Engine) findMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	bestIndex := -1
	bestScore := noMatchScore
	for i := range capabilities {
		constraint := &capabilities[i]
		if !matchesResource(constraint.Resource, req.ToolName) {
			continue
		}
		actionScore, ok := actionMatchScore(constraint.Actions, req)
		if !ok {
			continue
		}
		score := resourceSpecificity(constraint.Resource, req.ToolName)*resourceScoreWeight + actionScore
		if score > bestScore {
			bestIndex = i
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return nil
	}
	return &capabilities[bestIndex]
}

// matchesResource reports whether a capability resource pattern matches the tool name.
//
// Pattern syntax follows [path.Match] semantics:
//   - '*' matches any sequence of non-Separator characters (here, '/' is the only
//     separator, so '*' effectively matches any characters except '/').
//   - '?' matches any single non-Separator character.
//   - '[abc]' matches any character in the set.
//   - An exact value (e.g. "email:send") matches only that value.
//   - The special value "*" matches any tool name.
//
// Because capability resources use ':' as a namespace separator (not '/'),
// the path.Match '*' glob matches across colons, giving full glob semantics
// (e.g. "file:*.csv" matches "file:data.csv").
func matchesResource(resource, toolName string) bool {
	if resource == "*" || resource == toolName {
		return true
	}
	// path.Match provides consistent glob semantics: *, ?, and character classes.
	// An error is only returned for malformed patterns (e.g. unclosed '[');
	// such patterns should have been rejected at capability validation time, so
	// we treat them as non-matching here rather than propagating an error through
	// the hot enforcement path.
	matched, err := path.Match(resource, toolName)
	if err != nil {
		return false
	}
	return matched
}

// ValidateResourcePattern returns an error if the resource pattern is not a
// valid glob pattern according to [path.Match] semantics.  Callers should
// reject capabilities with invalid patterns at load time.
func ValidateResourcePattern(resource string) error {
	if _, err := path.Match(resource, ""); err != nil {
		return fmt.Errorf("enforcement: invalid resource pattern %q: %w", resource, err)
	}
	return nil
}

func actionMatchScore(actions []string, req *capability.EnforceRequest) (int, bool) {
	if len(actions) == 0 {
		return 0, true
	}
	// When no specific operation is set, treat toolName as the explicit operation,
	// consistent with allowedOperations handling.
	operation := req.Context.Operation
	if operation == "" {
		operation = req.ToolName
	}
	bestScore := -1
	hasWildcard := false
	for _, a := range actions {
		if a == "*" {
			hasWildcard = true
		}
		score := -1
		switch a {
		case operation:
			score = 2
		case req.ToolName:
			score = 1
		case "*":
			score = 0
		}
		if score > bestScore {
			bestScore = score
		}
	}
	if bestScore < 0 {
		return 0, false
	}
	// Apply a breadth penalty so that a narrower action set beats a broader one at
	// the same score level. Scale by 1000 so that levels remain strictly ordered even
	// after the maximum possible penalty (≤999) is subtracted, preventing a large
	// action list from flipping a level-2 match below a level-1 match.
	penalty := len(actions)
	if hasWildcard {
		penalty += 10
	}
	if penalty > 999 {
		penalty = 999
	}
	return bestScore*1000 - penalty, true
}

func resourceSpecificity(resource, toolName string) int {
	if resource == toolName {
		return 1000
	}
	if !strings.ContainsAny(resource, "*?[") {
		return 900
	}
	prefixLen := 0
	for _, r := range resource {
		if strings.ContainsRune("*?[", r) {
			break
		}
		prefixLen++
	}
	wildcardCount := 0
	for _, r := range resource {
		if strings.ContainsRune("*?[", r) {
			wildcardCount++
		}
	}
	return prefixLen*10 - wildcardCount
}

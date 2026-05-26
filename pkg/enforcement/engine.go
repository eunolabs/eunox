// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package enforcement implements the capability enforcement engine that evaluates
// conditions against incoming requests and produces allow/deny decisions.
package enforcement

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/testutil"
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

// CallCounter is the interface for tracking per-key call counts (used by maxCalls condition).
type CallCounter interface {
	IncrementAndGet(ctx context.Context, key string, windowSec int) (int64, error)
}

// Engine is the enforcement decision engine. It evaluates enforce requests
// against a set of capabilities and registered condition handlers.
type Engine struct {
	mu       sync.RWMutex
	handlers map[string]ConditionHandler
	clock    testutil.Clock
	counter  CallCounter
}

// Option configures the Engine.
type Option func(*Engine)

// WithClock sets a custom clock for time-based condition evaluation.
func WithClock(clock testutil.Clock) Option {
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

// New creates a new enforcement Engine with all built-in condition handlers registered.
func New(opts ...Option) *Engine {
	e := &Engine{
		handlers: make(map[string]ConditionHandler),
		clock:    &testutil.RealClock{},
	}
	for _, opt := range opts {
		opt(e)
	}
	e.registerBuiltins()
	return e
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
func (e *Engine) ValidateAction(ctx context.Context, req capability.EnforceRequest, capabilities []capability.Constraint) (capability.EnforceResponse, error) {
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
			if rc, ok := cond.(*capability.RedactFieldsCondition); ok {
				obligations = append(obligations, capability.Obligation{
					Type:  "redactFields",
					Paths: rc.Fields,
				})
				continue
			}
			if rc, ok := cond.(capability.RedactFieldsCondition); ok {
				obligations = append(obligations, capability.Obligation{
					Type:  "redactFields",
					Paths: rc.Fields,
				})
				continue
			}
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

		if condErr := handler(ctx, cond, &req); condErr != nil {
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

// findMatchingCapability finds the first capability that matches the request's tool/action.
func (e *Engine) findMatchingCapability(req capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	for i := range capabilities {
		constraint := &capabilities[i]
		if matchesResource(constraint.Resource, req.ToolName) && matchesAction(constraint.Actions, req) {
			return constraint
		}
	}
	return nil
}

// matchesResource checks if a capability resource pattern matches the tool name.
func matchesResource(resource, toolName string) bool {
	if resource == "*" || resource == toolName {
		return true
	}
	// Glob-style prefix match: "tool:*" matches any tool
	if len(resource) > 0 && resource[len(resource)-1] == '*' {
		prefix := resource[:len(resource)-1]
		return len(toolName) >= len(prefix) && toolName[:len(prefix)] == prefix
	}
	return false
}

// matchesAction checks if the capability grants the requested action/operation.
func matchesAction(actions []string, req capability.EnforceRequest) bool {
	if len(actions) == 0 {
		return true
	}
	for _, a := range actions {
		if a == "*" {
			return true
		}
		// Match against context operation or tool name
		if req.Context.Operation != "" && a == req.Context.Operation {
			return true
		}
		if a == req.ToolName {
			return true
		}
	}
	return false
}

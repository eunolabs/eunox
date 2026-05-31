// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
)

// goConditionTypes lists every condition type discriminator registered in Go.
// This must be kept in sync with condition.go.
var goConditionTypes = []string{
	ConditionTypeTimeWindow,
	ConditionTypeIPRange,
	ConditionTypeAllowedOperations,
	ConditionTypeAllowedExtensions,
	ConditionTypeAllowedTables,
	ConditionTypeMaxCalls,
	ConditionTypeRecipientDomain,
	ConditionTypeRedactFields,
	ConditionTypeAllowedValues,
	ConditionTypePolicy,
	ConditionTypeCustom,
}

// TestConditionTypeConstantsValid verifies that each Go condition type constant
// is a non-empty camelCase string and matches the JSON round-trip discriminator.
func TestConditionTypeConstantsValid(t *testing.T) {
	camelCase := regexp.MustCompile(`^[a-z][a-zA-Z0-9]+$`)
	for _, ct := range goConditionTypes {
		ct := ct
		t.Run(ct, func(t *testing.T) {
			if ct == "" {
				t.Error("condition type constant is empty")
			}
			if !camelCase.MatchString(ct) {
				t.Errorf("condition type %q is not camelCase", ct)
			}

			// Verify that newCondition can create an instance for this type.
			cond := newCondition(ct)
			if cond == nil {
				t.Errorf("newCondition(%q) returned nil", ct)
				return
			}
			if cond.ConditionType() != ct {
				t.Errorf("ConditionType() = %q, want %q", cond.ConditionType(), ct)
			}

			// Verify that JSON round-trip preserves the discriminator.
			data, err := json.Marshal(cond)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if envelope.Type != ct {
				t.Errorf("JSON type discriminator = %q, want %q", envelope.Type, ct)
			}
		})
	}
}

// TestAllConditionTypesHaveHandlers checks that every condition type constant
// exposed by the capability package can be JSON-marshalled with its discriminator
// and round-tripped through ConditionWrapper unmarshalling without error. It does
// not verify enforcement-engine handler registration; see enforcement_test.go for that.
func TestAllConditionTypesHaveHandlers(t *testing.T) {
	for _, ct := range goConditionTypes {
		ct := ct
		t.Run(ct, func(t *testing.T) {
			cond := newCondition(ct)
			if cond == nil {
				t.Fatalf("newCondition(%q) returned nil", ct)
			}
			// Verifying condition type is registered: just ensure it round-trips.
			data, err := json.Marshal(cond)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if envelope.Type != ct {
				t.Errorf("got type %q, want %q", envelope.Type, ct)
			}
			// Marshal via ConditionWrapper to exercise full polymorphic path.
			w := ConditionWrapper{Condition: cond}
			wData, err := json.Marshal(w)
			if err != nil {
				t.Fatalf("marshal wrapper: %v", err)
			}
			var decoded ConditionWrapper
			if err := json.Unmarshal(wData, &decoded); err != nil {
				t.Fatalf("unmarshal wrapper: %v (%s)", err, ct)
			}
			if decoded.ConditionType() != ct {
				t.Errorf("decoded type = %q, want %q", decoded.ConditionType(), ct)
			}
			_ = fmt.Sprintf("ok: %s", ct)
		})
	}
}

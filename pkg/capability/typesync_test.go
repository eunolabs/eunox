// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package capability provides a types-sync test that verifies all condition
// type discriminators defined in the Go package match those in the upstream
// TypeScript wire type definitions at github.com/eunolabs/eunox.
package capability

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	// upstreamWireURL is the raw URL of the canonical TypeScript wire definitions.
	upstreamWireURL = "https://raw.githubusercontent.com/eunolabs/eunox/main/packages/common/src/wire.ts"
	// upstreamWireURLEnv overrides the URL for testing without network access.
	upstreamWireURLEnv = "EUNOX_WIRE_TS_URL"
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

// TestConditionTypesInSyncWithUpstreamTypeScript fetches the canonical
// TypeScript wire definitions and verifies that every condition type found
// there has a corresponding Go implementation. If the upstream cannot be
// reached, the test is skipped (so local and offline builds always pass).
func TestConditionTypesInSyncWithUpstreamTypeScript(t *testing.T) {
	url := upstreamWireURL
	if override := os.Getenv(upstreamWireURLEnv); override != "" {
		url = override
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url) //nolint:noctx // test helper, no request context needed
	if err != nil {
		if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatalf("types-sync: cannot reach upstream in CI (%v)", err)
		}
		t.Skipf("skipping types-sync: cannot reach upstream (%v)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatalf("types-sync: upstream returned HTTP %d in CI", resp.StatusCode)
		}
		t.Skipf("skipping types-sync: upstream returned HTTP %d", resp.StatusCode)
	}

	// Parse type discriminator strings from TypeScript.
	// We look for patterns like:  type: 'allowedValues'
	tsTypes := extractTSConditionTypes(t, resp.Body)
	if len(tsTypes) == 0 {
		t.Skip("skipping types-sync: no condition types found in upstream source")
	}

	goTypeSet := make(map[string]bool, len(goConditionTypes))
	for _, ct := range goConditionTypes {
		goTypeSet[ct] = true
	}

	var missing []string
	for _, tsType := range tsTypes {
		if !goTypeSet[tsType] {
			missing = append(missing, tsType)
		}
	}

	if len(missing) > 0 {
		t.Errorf("condition type(s) present in upstream TypeScript but missing from Go:\n  %s\n"+
			"Add these to pkg/capability/condition.go and register handlers in pkg/enforcement/handlers.go",
			strings.Join(missing, "\n  "))
	}

	t.Logf("types-sync OK: %d upstream types, %d Go types", len(tsTypes), len(goConditionTypes))
}

// extractTSConditionTypes reads the TypeScript source and returns all condition
// type discriminator strings found in it. It understands two common patterns:
//
//	type: 'allowedValues'
//	"type": "allowedValues"
func extractTSConditionTypes(t *testing.T, body interface{ Read([]byte) (int, error) }) []string {
	t.Helper()

	buf := new(strings.Builder)
	tmp := make([]byte, 4096)
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	src := buf.String()

	// Match:  type: 'foo'  or  type: "foo"
	re := regexp.MustCompile(`type\s*:\s*['"]([a-zA-Z][a-zA-Z0-9_]*)['"]`)
	matches := re.FindAllStringSubmatch(src, -1)

	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		v := m[1]
		if v == "object" || v == "string" || v == "number" || v == "boolean" || v == "null" || v == "array" {
			continue // JSON Schema type keywords, not condition discriminators
		}
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
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

// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway export_test.go exposes internal test helpers for use by the
// external gateway_test package.  This file is compiled only during `go test`.

package gateway

import (
	"crypto/ecdsa"
	"testing"
	"time"
)

// CreateTestDPoPProof creates a valid DPoP proof JWT signed with key for the
// given HTTP method, URL, and issued-at time.  Exported for use by external
// test packages (package gateway_test).
func CreateTestDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, url string, iat time.Time) string {
	t.Helper()
	return createTestDPoPProof(t, key, method, url, iat)
}

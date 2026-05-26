// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServer wraps httptest.Server with convenience methods.
type TestServer struct {
	*httptest.Server
	t *testing.T
}

// NewTestServer creates a test HTTP server. Auto-closed when test finishes.
func NewTestServer(t *testing.T, handler http.Handler) *TestServer {
	t.Helper()

	server := httptest.NewServer(handler)
	ts := &TestServer{Server: server, t: t}
	t.Cleanup(ts.Close)
	return ts
}

// NewTLSTestServer creates a TLS test HTTP server.
func NewTLSTestServer(t *testing.T, handler http.Handler) *TestServer {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	ts := &TestServer{Server: server, t: t}
	t.Cleanup(ts.Close)
	return ts
}

// BaseURL returns the server's base URL.
func (ts *TestServer) BaseURL() string {
	return ts.URL
}

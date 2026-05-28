// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newJSONRequest creates a new HTTP request with JSON content type.
func newJSONRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, http.NoBody)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// doRequest executes an HTTP request against the given handler and returns the recorder.
func doRequest(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// projectRoot walks up from the working directory until it finds go.mod,
// returning that directory as the project root.
func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("projectRoot: getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("projectRoot: could not find go.mod")
		}
		dir = parent
	}
}

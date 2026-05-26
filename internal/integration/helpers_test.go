// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newJSONRequest creates a new HTTP request with JSON content type.
func newJSONRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
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

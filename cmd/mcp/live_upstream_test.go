// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestFetchLiveTools_HappyPath verifies the full handshake sequence and that
// the returned tools match the upstream's tools/list response.
func TestFetchLiveTools_HappyPath(t *testing.T) {
	tools := []mcpToolEntry{
		{
			Name: "read_file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"path"},
			},
		},
		{Name: "write_file"},
	}
	fake := newFakeUpstreamWithTools(tools)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	got, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(got))
	}
	if got[0].Name != "read_file" {
		t.Errorf("got[0].Name: want read_file, got %q", got[0].Name)
	}
	if got[1].Name != "write_file" {
		t.Errorf("got[1].Name: want write_file, got %q", got[1].Name)
	}
	if got[0].InputSchema == nil {
		t.Error("got[0].InputSchema: want non-nil")
	}
	if got[1].InputSchema != nil {
		t.Error("got[1].InputSchema: want nil for tool without schema")
	}

	// Verify the handshake sequence: initialize → notifications/initialized → tools/list.
	reqs := fake.Received()
	counts := make(map[string]int)
	for _, r := range reqs {
		counts[r.Body.Method]++
	}
	if counts["initialize"] != 1 {
		t.Errorf("initialize count: want 1, got %d", counts["initialize"])
	}
	if counts["notifications/initialized"] != 1 {
		t.Errorf("notifications/initialized count: want 1, got %d", counts["notifications/initialized"])
	}
	if counts["tools/list"] != 1 {
		t.Errorf("tools/list count: want 1, got %d", counts["tools/list"])
	}
}

// TestFetchLiveTools_EmptyToolList verifies that a tools/list with no tools
// returns an empty slice without error.
func TestFetchLiveTools_EmptyToolList(t *testing.T) {
	fake := newFakeUpstreamWithTools(nil)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	got, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 tools, got %d", len(got))
	}
}

// TestFetchLiveTools_ConnectionRefused verifies that a refused connection
// produces an error.
func TestFetchLiveTools_ConnectionRefused(t *testing.T) {
	_, err := fetchLiveTools(context.Background(), "http://127.0.0.1:1", "", false)
	if err == nil {
		t.Error("expected error for refused connection, got nil")
	}
}

// TestFetchLiveTools_InitializeRPCError verifies that a JSON-RPC error in the
// initialize response is surfaced as a Go error.
func TestFetchLiveTools_InitializeRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg rpcMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &rpcError{Code: -32000, Message: "server initialise rejected"},
		}
		w.Header().Set("Content-Type", ctJSON)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected error for RPC error response, got nil")
	}
	if !strings.Contains(err.Error(), "initialize") {
		t.Errorf("error should mention 'initialize', got %q", err.Error())
	}
}

// TestFetchLiveTools_UpstreamHTTP500 verifies that an HTTP 500 from the
// upstream is surfaced as an error.
func TestFetchLiveTools_UpstreamHTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// TestFetchLiveTools_AuthHeaderForwarded verifies that --upstream-auth-header
// is sent on every upstream request.
func TestFetchLiveTools_AuthHeaderForwarded(t *testing.T) {
	var mu sync.Mutex
	captured := make(map[string]string) // method → Authorization value

	fake := newFakeUpstreamWithTools([]mcpToolEntry{{Name: "tool_a"}})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg rpcMsg
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		captured[msg.Method] = r.Header.Get("Authorization")
		mu.Unlock()
		// Replay the body for the real handler — body already consumed, so
		// re-encode and serve.
		fake.serveMsg(w, r, msg)
	})
	srv := httptest.NewServer(http.StripPrefix("/mcp", wrapped))
	t.Cleanup(srv.Close)

	const wantAuth = "Bearer live-test-token"
	_, err := fetchLiveTools(context.Background(), srv.URL, "Authorization: "+wantAuth, false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for method, got := range captured {
		if got != wantAuth {
			t.Errorf("method %q: want Authorization=%q, got %q", method, wantAuth, got)
		}
	}
}

// TestFetchLiveTools_TLSSkipVerify verifies TLS behaviour in both modes.
func TestFetchLiveTools_TLSSkipVerify(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcpToolEntry{{Name: "tool_a"}})
	tlsSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(tlsSrv.Close)

	// Without skip-verify: self-signed cert should cause an error.
	_, err := fetchLiveTools(context.Background(), tlsSrv.URL, "", false)
	if err == nil {
		t.Error("expected TLS error without skip-verify, got nil")
	}

	// With skip-verify: should succeed despite the self-signed certificate.
	got, err := fetchLiveTools(context.Background(), tlsSrv.URL, "", true)
	if err != nil {
		t.Fatalf("fetchLiveTools with skip-verify: %v", err)
	}
	if len(got) != 1 || got[0].Name != "tool_a" {
		t.Errorf("skip-verify: expected [{tool_a}], got %v", got)
	}
}

// TestFetchLiveTools_BaseURLTrailingSlash verifies that a trailing slash in the
// base URL does not result in a double-slash in the MCP endpoint path.
func TestFetchLiveTools_BaseURLTrailingSlash(t *testing.T) {
	fake := newFakeUpstreamWithTools([]mcpToolEntry{{Name: "tool_a"}})
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	// Pass URL with trailing slash.
	got, err := fetchLiveTools(context.Background(), srv.URL+"/", "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools with trailing slash: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 tool, got %d", len(got))
	}
}

// TestFetchLiveTools_ContextCancelled verifies that a pre-cancelled context
// causes fetchLiveTools to return an error immediately.
func TestFetchLiveTools_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	_, err := fetchLiveTools(ctx, "http://127.0.0.1:19999", "", false)
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// serveMsg allows fakeUpstreamWithTools to be used from a wrapper handler that
// has already decoded the JSON body.  It re-dispatches based on Method.
func (f *fakeUpstreamWithTools) serveMsg(w http.ResponseWriter, _ *http.Request, msg rpcMsg) {
	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method: msg.Method,
		Body:   msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(sessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", ctJSON)
		result := mcpInitResult{
			ProtocolVersion: mcpProtocolVersion,
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake", "version": "0.0.1"},
		}
		resp, _ := successResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		result := mcpToolsListResult{Tools: f.tools}
		resp, _ := successResponse(msg.ID, result)
		w.Header().Set("Content-Type", ctJSON)
		_ = json.NewEncoder(w).Encode(resp)
	default:
		resp, _ := successResponse(msg.ID, map[string]interface{}{})
		w.Header().Set("Content-Type", ctJSON)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

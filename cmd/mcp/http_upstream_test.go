// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the remote HTTP upstream mode (T-01: --upstream-url).
//
// Each test starts a fake MCP HTTP server using httptest.NewServer, wires an
// HTTPProxy against it, and exercises the proxy's handleMCP handler directly
// (bypassing Serve so no real TCP port is needed).

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// -----------------------------------------------------------------
// Fake upstream MCP server
// -----------------------------------------------------------------

// fakeRequest records a single HTTP request received by the fake upstream.
type fakeRequest struct {
	Method    string
	SessionID string
	Body      rpcMsg
}

// fakeUpstream is a minimal MCP HTTP server for testing.
// It handles initialize + notifications/initialized correctly, and returns
// configurable responses for tools/call.
type fakeUpstream struct {
	mu       sync.Mutex
	received []fakeRequest

	toolResult json.RawMessage // returned for tools/call; defaults to a text result

	// toolCallback, when non-nil, is called instead of using toolResult.
	// It receives the tool name and arguments and returns a raw JSON result.
	toolCallback func(name string, args map[string]interface{}) json.RawMessage
}

func newFakeUpstream() *fakeUpstream {
	defaultResult, _ := json.Marshal(mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: `{"ok":true}`}},
	})
	return &fakeUpstream{toolResult: defaultResult}
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg rpcMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method:    msg.Method,
		SessionID: r.Header.Get(sessionHeader),
		Body:      msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(sessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
		caps, _ := json.Marshal(map[string]interface{}{"tools": map[string]interface{}{}})
		result := mcpInitResult{
			ProtocolVersion: mcpProtocolVersion,
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake-upstream", "version": "0.0.1"},
		}
		_ = caps
		resp, _ := successResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)

	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)

	case "tools/call":
		var params mcpToolCallParams
		_ = json.Unmarshal(msg.Params, &params)

		var resultBytes json.RawMessage
		f.mu.Lock()
		if f.toolCallback != nil {
			resultBytes = f.toolCallback(params.Name, params.Arguments)
		} else {
			resultBytes = f.toolResult
		}
		f.mu.Unlock()

		resp := rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resultBytes,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)

	default:
		// Forward all other methods: echo back a generic success.
		resp, _ := successResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Received returns a copy of all requests received so far.
func (f *fakeUpstream) Received() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]fakeRequest, len(f.received))
	copy(cp, f.received)
	return cp
}

// CountByMethod returns the number of requests with the given method.
func (f *fakeUpstream) CountByMethod(method string) int {
	received := f.Received()
	n := 0
	for i := range received {
		if received[i].Body.Method == method {
			n++
		}
	}
	return n
}

// -----------------------------------------------------------------
// Test helper: proxy server backed by a fake upstream
// -----------------------------------------------------------------

// newTestRemoteProxy creates an HTTPProxy wired to the given fake upstream URL,
// and returns both the proxy and a test HTTP server that routes through its
// handleMCP handler.  The test server is cleaned up automatically.
func newTestRemoteProxy(t *testing.T, upstreamURL string, opts HTTPProxyOptions) (*HTTPProxy, *httptest.Server) {
	t.Helper()
	opts.UpstreamURL = upstreamURL
	if opts.Port == 0 {
		opts.Port = 3000 // ignored — we're using httptest.Server directly
	}
	proxy := NewHTTPProxy(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return proxy, srv
}

// postMCP sends a POST /mcp request to the proxy test server with the given
// rpcMsg body.  Optional sessionID is set as the Mcp-Session-Id header.
func postMCP(t *testing.T, srv *httptest.Server, msg rpcMsg, sessionID string) *http.Response {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(sessionHeader, sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decodeRPC decodes a JSON-RPC message from an HTTP response body.
func decodeRPC(t *testing.T, resp *http.Response) rpcMsg {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var msg rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return msg
}

// initSession sends an initialize request to the proxy and returns the session ID.
func initSession(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	initMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, srv, initMsg, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: unexpected status %d", resp.StatusCode)
	}
	sid := resp.Header.Get(sessionHeader)
	if sid == "" {
		t.Fatal("initialize: no Mcp-Session-Id in response")
	}
	_ = resp.Body.Close()
	return sid
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

// TestRemoteUpstream_Initialize verifies that an initialize request creates a
// proxy session, returns a session ID, and performs the upstream handshake.
func TestRemoteUpstream_Initialize(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{})

	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Fatal("expected a session ID from proxy")
	}

	// Upstream should have received: initialize + notifications/initialized.
	reqs := fake.Received()
	if len(reqs) < 2 {
		t.Fatalf("expected at least 2 upstream requests, got %d", len(reqs))
	}
	if reqs[0].Body.Method != "initialize" {
		t.Errorf("first upstream request: want initialize, got %q", reqs[0].Body.Method)
	}
	if reqs[1].Body.Method != "notifications/initialized" {
		t.Errorf("second upstream request: want notifications/initialized, got %q", reqs[1].Body.Method)
	}
}

// TestRemoteUpstream_ToolsCallAllowed verifies that a permitted tools/call is
// forwarded to the upstream and its result returned to the client.
func TestRemoteUpstream_ToolsCallAllowed(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		PDP: alwaysAllowPDP{},
	})

	sid := initSession(t, proxySrv)

	callMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}`),
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	if msg.Error != nil {
		t.Errorf("tools/call: unexpected error %+v", msg.Error)
	}
	if msg.Result == nil {
		t.Error("tools/call: expected non-nil result")
	}

	// Upstream must have received the tools/call.
	if n := fake.CountByMethod("tools/call"); n != 1 {
		t.Errorf("upstream tools/call count: want 1, got %d", n)
	}
}

// TestRemoteUpstream_ToolsCallDenied verifies that a denied tools/call is NOT
// forwarded to the upstream — the proxy returns a denial result directly.
func TestRemoteUpstream_ToolsCallDenied(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	denyPDP := denyAllPDP{}
	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		PDP: denyPDP,
	})

	sid := initSession(t, proxySrv)
	beforeCount := fake.CountByMethod("tools/call")

	callMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"write_file","arguments":{"path":"/etc/passwd"}}`),
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call denied: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	// Denial is encoded as a successful JSON-RPC result with isError:true.
	if msg.Result == nil {
		t.Fatal("tools/call denied: expected result envelope, got nil")
	}

	var result mcpToolCallResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("tools/call denied: unmarshal result: %v", err)
	}
	if !result.IsError {
		t.Error("tools/call denied: expected isError=true in result")
	}

	// Upstream must NOT have received any tools/call.
	afterCount := fake.CountByMethod("tools/call")
	if afterCount != beforeCount {
		t.Errorf("upstream received %d tools/call(s) after denial, want 0", afterCount-beforeCount)
	}
}

// TestRemoteUpstream_NonToolsCallForwarded verifies that methods other than
// tools/call are forwarded transparently to the upstream.
func TestRemoteUpstream_NonToolsCallForwarded(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{})

	sid := initSession(t, proxySrv)

	listMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`3`),
		Method:  "tools/list",
	}
	resp := postMCP(t, proxySrv, listMsg, sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list: unexpected status %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp)
	if msg.Error != nil {
		t.Errorf("tools/list: unexpected error: %+v", msg.Error)
	}
	if fake.CountByMethod("tools/list") != 1 {
		t.Error("tools/list was not forwarded to upstream")
	}
}

// TestRemoteUpstream_AuthHeaderForwarded verifies that the configured
// upstream-auth-header is sent on every request to the remote upstream.
func TestRemoteUpstream_AuthHeaderForwarded(t *testing.T) {
	const wantHeader = "Authorization"
	const wantValue = "Bearer test-token-123"

	var receivedAuth string
	var mu sync.Mutex

	fake := newFakeUpstream()
	// Wrap fake to capture the Authorization header.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get(wantHeader)
		mu.Unlock()
		fake.ServeHTTP(w, r)
	})
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", wrapped))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		UpstreamAuthHeader: wantHeader + ": " + wantValue,
	})

	initSession(t, proxySrv)

	mu.Lock()
	got := receivedAuth
	mu.Unlock()

	if got != wantValue {
		t.Errorf("upstream auth header: want %q, got %q", wantValue, got)
	}
}

// TestRemoteUpstream_SessionDelete verifies that DELETE /mcp closes the proxy
// session and subsequent requests with that session ID return 404.
func TestRemoteUpstream_SessionDelete(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{})

	sid := initSession(t, proxySrv)

	// Send DELETE /mcp with the session ID.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, proxySrv.URL+"/mcp", http.NoBody)
	req.Header.Set(sessionHeader, sid)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /mcp: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE /mcp: want 204, got %d", delResp.StatusCode)
	}

	// A subsequent POST with the now-deleted session ID should return 404.
	callMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`5`),
		Method:  "tools/list",
	}
	resp := postMCP(t, proxySrv, callMsg, sid)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("after DELETE: want 404, got %d", resp.StatusCode)
	}
}

// TestRemoteUpstream_TLSSkipVerify verifies that proxy connects to a TLS
// upstream when --upstream-tls-skip-verify is set.
func TestRemoteUpstream_TLSSkipVerify(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		UpstreamTLSSkipVerify: true,
	})

	// Should succeed despite the test server's self-signed certificate.
	sid := initSession(t, proxySrv)
	if sid == "" {
		t.Fatal("expected session ID from TLS upstream")
	}
}

// TestRemoteUpstream_TLSVerifyFails verifies that without skip-verify the
// proxy fails to connect to a TLS upstream with a self-signed certificate.
func TestRemoteUpstream_TLSVerifyFails(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewTLSServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	// No TLS skip — default verification should reject the self-signed cert.
	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		UpstreamTLSSkipVerify: false,
	})

	initMsg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	_ = resp.Body.Close()
	// Expect 500 because the upstream TLS handshake fails.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("TLS verify failure: want 500, got %d", resp.StatusCode)
	}
}

// TestRemoteUpstream_UpstreamAuthHeaderParsing verifies edge cases in the
// "Header-Name: Header-Value" parsing used by setUpstreamAuthHeader.
func TestRemoteUpstream_UpstreamAuthHeaderParsing(t *testing.T) {
	cases := []struct {
		input     string
		wantName  string
		wantValue string
	}{
		{"Authorization: Bearer tok", "Authorization", "Bearer tok"},
		{"X-Api-Key:  secret", "X-Api-Key", "secret"},
		// Value contains a colon — only the first colon is the separator.
		{"Authorization: Bearer a:b:c", "Authorization", "Bearer a:b:c"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			var gotName, gotValue string
			capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotName = tc.wantName
				gotValue = r.Header.Get(tc.wantName)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			})
			srv := httptest.NewServer(capture)
			defer srv.Close()

			p := &HTTPProxy{upstreamAuthHeader: tc.input}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("{}"))
			p.setUpstreamAuthHeader(req)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()

			if gotName != tc.wantName || gotValue != tc.wantValue {
				t.Errorf("auth header: got %q=%q, want %q=%q", gotName, gotValue, tc.wantName, tc.wantValue)
			}
		})
	}
}

// TestRemoteUpstream_mcpEndpointURL verifies URL construction.
func TestRemoteUpstream_mcpEndpointURL(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"https://mcp.stripe.com", "https://mcp.stripe.com/mcp"},
		{"https://mcp.stripe.com/", "https://mcp.stripe.com/mcp"},
		{"https://api.example.com/v1", "https://api.example.com/v1/mcp"},
	}
	for _, tc := range cases {
		p := &HTTPProxy{upstreamURL: tc.base}
		if got := p.mcpEndpointURL(); got != tc.want {
			t.Errorf("mcpEndpointURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

// TestRemoteUpstream_MultipleSessionsIndependent verifies that two concurrent
// sessions each get their own upstream session context and don't interfere.
func TestRemoteUpstream_MultipleSessionsIndependent(t *testing.T) {
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	_, proxySrv := newTestRemoteProxy(t, upSrv.URL, HTTPProxyOptions{
		PDP: alwaysAllowPDP{},
	})

	sid1 := initSession(t, proxySrv)
	sid2 := initSession(t, proxySrv)

	if sid1 == sid2 {
		t.Fatal("two sessions received the same session ID")
	}

	// Both sessions can make independent tool calls.
	for i, sid := range []string{sid1, sid2} {
		callMsg := rpcMsg{
			JSONRPC: "2.0",
			ID:      rawJSON(`10`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/reports/test.pdf"}}`),
		}
		resp := postMCP(t, proxySrv, callMsg, sid)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("session %d: tools/call: unexpected status %d", i+1, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// -----------------------------------------------------------------
// Helper PDPs used in tests
// -----------------------------------------------------------------

// denyAllPDP always denies every tool call.
type denyAllPDP struct{}

func (denyAllPDP) Decide(_ context.Context, _, toolName string, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "CAPABILITY_DENIED",
			Message: "denied by test policy: " + toolName,
		},
	}
}

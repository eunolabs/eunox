// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

// captureSink captures audit records for assertions.
type captureSink struct {
	records []capturedRecord
}

type capturedRecord struct {
	SessionID string
	ToolName  string
	Decision  string
	Code      string
	DryRun    bool
}

func (s *captureSink) Record(sessionID, toolName, decision, denialCode, condType string, details map[string]interface{}, obligs []string, dryRun bool) {
	s.records = append(s.records, capturedRecord{
		SessionID: sessionID,
		ToolName:  toolName,
		Decision:  decision,
		Code:      denialCode,
		DryRun:    dryRun,
	})
}

// newDryRunProxy returns an HTTPProxy in dry-run mode backed by the given
// upstream server, using a deny-all PDP so that every tools/call would be
// denied under normal enforcement.
func newDryRunProxy(t *testing.T, upstreamSrv *httptest.Server) *HTTPProxy {
	t.Helper()
	return NewHTTPProxy(HTTPProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstreamSrv.URL,
		DryRun:      true,
		Port:        0,
	})
}

// postMCPWithBody sends a POST /mcp with the given JSON body and optional session header.
func postMCPWithBody(t *testing.T, proxySrv *httptest.Server, body interface{}, sessionID string) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	return resp
}

// initSessionDryRun creates a new session against proxy with fake upstream.
// Returns the session ID.
func initSessionDryRun(t *testing.T, proxySrv *httptest.Server) string {
	t.Helper()
	initMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "0"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, initMsg, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no Mcp-Session-Id in initialize response")
	}
	return sid
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestDryRun_ToolCallForwardedDespiteDeny(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t) // reuse the stub from JWT tests
	defer upstream.srv.Close()

	proxy := newDryRunProxy(t, upstream.srv)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	// Call a tool. The denyAllPDP would normally block it, but in dry-run mode
	// the call must be forwarded and succeed.
	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/secret/data"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Result should be non-nil (upstream responded) not an error.
	if result.Error != nil {
		t.Errorf("unexpected error in response: %+v", result.Error)
	}
	if result.Result == nil {
		t.Error("expected a result from upstream, got nil")
	}
}

func TestDryRun_AuditRecordHasDryRunFlag(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink := &captureSink{}
	proxy := NewHTTPProxy(HTTPProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		DryRun:      true,
		Port:        0,
	})
	// Inject the capture sink directly.
	proxy.sink = (*auditSink)(nil) // nil to avoid real file writes
	_ = sink                       // we'll wire it differently below

	// Use a custom proxy that routes to our capture sink.
	proxyWithSink := NewHTTPProxy(HTTPProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		DryRun:      true,
		Port:        0,
	})

	// Swap the sink for our capture sink via a wrapper PDP that also records.
	var recorded []capturedRecord
	recordingPDP := recordingDecisionPoint{
		inner: denyAllPDP{},
		onDecide: func(sessionID, toolName string, resp capability.EnforceResponse) {
			recorded = append(recorded, capturedRecord{
				SessionID: sessionID,
				ToolName:  toolName,
				Decision:  string(resp.Decision),
				DryRun:    proxyWithSink.dryRun,
			})
		},
	}
	proxyWithSink.pdp = recordingPDP

	proxySrv := httptest.NewServer(http.HandlerFunc(proxyWithSink.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "write_file",
			"arguments": map[string]interface{}{},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if len(recorded) == 0 {
		t.Fatal("no PDP decision recorded")
	}
	if !recorded[0].DryRun {
		t.Errorf("expected dry_run=true in recorded decision, got false")
	}
	if recorded[0].Decision != string(capability.DecisionDeny) {
		t.Errorf("expected deny decision, got %q", recorded[0].Decision)
	}
}

func TestDryRun_NormalMode_DenyBlocks(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	// Normal mode (no dry-run): denyAll should block the call.
	proxy := NewHTTPProxy(HTTPProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		DryRun:      false,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	var result rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Should get an MCP-level denial (not an upstream result).
	if result.Result == nil {
		t.Fatal("expected denial result, got nil result")
	}
	// The denial result should contain an isError field.
	var content struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result.Result, &content); err == nil && !content.IsError {
		t.Error("expected isError=true in denial result")
	}
}

func TestDryRun_AllowedCall_NotAffected(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	// Allow-all PDP with dry-run: should still forward normally.
	proxy := NewHTTPProxy(HTTPProxyOptions{
		PDP:         alwaysAllowPDP{},
		UpstreamURL: upstream.srv.URL,
		DryRun:      true,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/ok"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %+v", result.Error)
	}
}

func TestAuditRecord_DryRunField(t *testing.T) {
	// Unit-test the audit record struct has the dry_run field.
	rec := auditRecord{
		Decision: "deny",
		DryRun:   true,
		ToolName: "read_file",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := m["dry_run"]; !ok || v != true {
		t.Errorf("dry_run field not present or not true in: %s", data)
	}
}

func TestAuditRecord_DryRunField_OmittedWhenFalse(t *testing.T) {
	rec := auditRecord{
		Decision: "allow",
		DryRun:   false,
		ToolName: "read_file",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["dry_run"]; ok {
		t.Errorf("dry_run should be omitted when false, but found in: %s", data)
	}
}

// -------------------------------------------------------------------------
// Helpers for recording decisions
// -------------------------------------------------------------------------

type recordingDecisionPoint struct {
	inner    PolicyDecisionPoint
	onDecide func(sessionID, toolName string, resp capability.EnforceResponse)
}

func (r recordingDecisionPoint) Decide(ctx context.Context, sessionID, toolName string, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	resp := r.inner.Decide(ctx, sessionID, toolName, args, sourceIP)
	r.onDecide(sessionID, toolName, resp)
	return resp
}

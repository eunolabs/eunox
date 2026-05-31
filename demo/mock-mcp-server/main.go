// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// mock-mcp-server is a minimal MCP Streamable HTTP server used only in the
// eunox demo (demo/docker-compose.yml).  It exposes three tools — read_file,
// write_file, query_db — and returns deterministic fake responses so every
// demo scenario produces predictable, inspectable output.
//
// The server is intentionally not wired to any real storage.  Its sole purpose
// is to give eunox-mcp a realistic upstream to enforce policies against.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	sessionHeader      = "Mcp-Session-Id"
	mcpProtocolVersion = "2025-11-25"
	serverName         = "mock-mcp-server"
	serverVersion      = "1.0.0"
)

// rpcMsg is a JSON-RPC 2.0 envelope.
type rpcMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (m *rpcMsg) isRequest() bool      { return m.ID != nil && m.Method != "" }
func (m *rpcMsg) isNotification() bool { return m.ID == nil && m.Method != "" }

// server holds active session IDs in memory.
type server struct {
	mu       sync.RWMutex
	sessions map[string]struct{}
}

func newServer() *server {
	return &server{sessions: make(map[string]struct{})}
}

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// ServeHTTP dispatches GET/POST/DELETE on /mcp.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet:
		// Hold the SSE stream open until the client disconnects.
		// This server does not push server-initiated notifications.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	case http.MethodDelete:
		sid := r.Header.Get(sessionHeader)
		if sid != "" {
			s.mu.Lock()
			delete(s.sessions, sid)
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePost(w http.ResponseWriter, r *http.Request) {
	var msg rpcMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid JSON-RPC body", http.StatusBadRequest)
		return
	}

	// initialize always creates a new session regardless of any existing header.
	if msg.Method == "initialize" {
		sid := newSessionID()
		s.mu.Lock()
		s.sessions[sid] = struct{}{}
		s.mu.Unlock()
		w.Header().Set(sessionHeader, sid)
		writeResult(w, msg.ID, map[string]interface{}{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo": map[string]interface{}{
				"name":    serverName,
				"version": serverVersion,
			},
		})
		return
	}

	// Notifications do not require a valid session (idempotent).
	if msg.isNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !msg.isRequest() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// All other requests require an existing session.
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	_, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	switch msg.Method {
	case "tools/list":
		s.handleToolsList(w, msg)
	case "tools/call":
		s.handleToolsCall(w, msg)
	default:
		writeRPCError(w, msg.ID, -32601, "method not found: "+msg.Method)
	}
}

// toolDef describes one MCP tool for tools/list.
type toolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

var toolList = []toolDef{
	{
		Name:        "read_file",
		Description: "Read the contents of a file at the given path.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Absolute file path, e.g. /reports/q3.pdf",
				},
			},
			"required": []string{"path"},
		},
	},
	{
		Name:        "write_file",
		Description: "Write content to a file at the given path.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Absolute file path to write.",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content to write.",
				},
			},
			"required": []string{"path", "content"},
		},
	},
	{
		Name:        "query_db",
		Description: "Execute a SQL query against the demo database.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "SQL statement to execute.",
				},
			},
			"required": []string{"query"},
		},
	},
}

func (s *server) handleToolsList(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally (mirrors cmd/mcp convention)
	writeResult(w, msg.ID, map[string]interface{}{"tools": toolList})
}

func (s *server) handleToolsCall(w http.ResponseWriter, msg rpcMsg) { //nolint:gocritic // hugeParam: rpcMsg passed by value intentionally
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		writeRPCError(w, msg.ID, -32602, "invalid tools/call params")
		return
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}

	text := dispatchTool(params.Name, params.Arguments)
	if text == "" {
		writeRPCError(w, msg.ID, -32602, "unknown tool: "+params.Name)
		return
	}

	writeResult(w, msg.ID, map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
		"isError": false,
	})
}

// dispatchTool returns the fake response text for the named tool, or "" if
// the tool name is unknown.
func dispatchTool(name string, args map[string]interface{}) string {
	switch name {
	case "read_file":
		path, _ := args["path"].(string)
		return fmt.Sprintf("[mock] Contents of %s:\n\n"+
			"Q3 Financial Summary\n"+
			"Revenue:  $12,400,000\n"+
			"Expenses: $ 8,900,000\n"+
			"EBITDA:   $ 3,500,000\n"+
			"(end of mock file %s)", path, path)

	case "write_file":
		path, _ := args["path"].(string)
		content, _ := args["content"].(string)
		return fmt.Sprintf("[mock] Wrote %d bytes to %s", len(content), path)

	case "query_db":
		query, _ := args["query"].(string)
		q := strings.ToUpper(strings.TrimSpace(query))
		if strings.HasPrefix(q, "SELECT") {
			return "[mock] Query result:\n\n" +
				"id | name        | value\n" +
				"---|-------------|----------\n" +
				" 1 | revenue_q3  | 12400000\n" +
				" 2 | revenue_q4  | 15800000\n" +
				" 3 | expenses_q3 |  8900000\n" +
				"\n(3 rows)"
		}
		return fmt.Sprintf("[mock] Executed: %s  (1 row affected)", query)

	default:
		return ""
	}
}

func writeResult(w http.ResponseWriter, id *json.RawMessage, result interface{}) {
	res, _ := json.Marshal(result)
	resp := rpcMsg{JSONRPC: "2.0", ID: id, Result: res}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeRPCError(w http.ResponseWriter, id *json.RawMessage, code int, message string) {
	resp := rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("mock-mcp-server listening on :%s", port) //nolint:gosec // G706: port is an env var used only for logging, not a command string
	if err := http.ListenAndServe(":"+port, newServer()); err != nil { //nolint:gosec // G114: demo server; no timeout required
		log.Fatalf("mock-mcp-server: %v", err)
	}
}

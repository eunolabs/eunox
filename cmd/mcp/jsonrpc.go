// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// rpcMsg is a JSON-RPC 2.0 message.  It can represent a request, response, or
// notification depending on which fields are populated.
type rpcMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"` // nil for notifications
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// isRequest reports whether msg is a JSON-RPC request (has id + method).
func (m *rpcMsg) isRequest() bool {
	return m.ID != nil && m.Method != ""
}

// isNotification reports whether msg is a notification (no id, has method).
func (m *rpcMsg) isNotification() bool {
	return m.ID == nil && m.Method != ""
}

// isResponse reports whether msg is a response (has id, no method).
func (m *rpcMsg) isResponse() bool {
	return m.ID != nil && m.Method == ""
}

// msgKey returns a stable string key for a message ID suitable for use as a
// map key.  JSON-RPC IDs may be strings, integers, or null.
func msgKey(id *json.RawMessage) string {
	if id == nil {
		return ""
	}
	return string(*id)
}

// rawJSON returns a json.RawMessage pointing at a compile-time string literal.
func rawJSON(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

// successResponse builds a JSON-RPC 2.0 success response.
func successResponse(id *json.RawMessage, result interface{}) (rpcMsg, error) {
	res, err := json.Marshal(result)
	if err != nil {
		return rpcMsg{}, err
	}
	return rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Result:  res,
	}, nil
}

// errorResponse builds a JSON-RPC 2.0 error response.
func errorResponse(id *json.RawMessage, code int, message string) rpcMsg {
	return rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
}

// notificationMsg builds a JSON-RPC 2.0 notification (no id).
func notificationMsg(method string, params interface{}) (rpcMsg, error) {
	var p json.RawMessage
	if params != nil {
		var err error
		p, err = json.Marshal(params)
		if err != nil {
			return rpcMsg{}, err
		}
	}
	return rpcMsg{JSONRPC: "2.0", Method: method, Params: p}, nil
}

// -----------------------------------------------------------------
// MCP-specific message types
// -----------------------------------------------------------------

// mcpInitParams is the params field of an `initialize` request.
type mcpInitParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      map[string]interface{} `json:"clientInfo"`
}

// mcpInitResult is the result field of an `initialize` response.
type mcpInitResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]interface{} `json:"serverInfo"`
}

// mcpToolCallParams is the params field of a `tools/call` request.
type mcpToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpToolCallResult is a `tools/call` result.
type mcpToolCallResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

// mcpContent is a single content item in a `tools/call` result.
type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// denialResult builds a tools/call result that signals a policy denial.
func denialResult(id *json.RawMessage, toolName, code, reason string, details map[string]interface{}) rpcMsg {
	payload := map[string]interface{}{
		"error":   "CapabilityDenied",
		"tool":    toolName,
		"code":    code,
		"message": reason,
	}
	if len(details) > 0 {
		payload["details"] = details
	}
	text, _ := json.Marshal(payload)

	res, _ := json.Marshal(mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(text)}},
		IsError: true,
	})

	return rpcMsg{JSONRPC: "2.0", ID: id, Result: res}
}

// -----------------------------------------------------------------
// Framed I/O: newline-delimited JSON
// -----------------------------------------------------------------

// msgWriter writes newline-delimited JSON-RPC messages to an io.Writer.
// Concurrent-safe.
type msgWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newMsgWriter(w io.Writer) *msgWriter { return &msgWriter{w: w} }

// Write encodes msg and writes it as a single line to the underlying writer.
func (mw *msgWriter) Write(msg rpcMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling message: %w", err)
	}
	mw.mu.Lock()
	defer mw.mu.Unlock()
	_, err = fmt.Fprintf(mw.w, "%s\n", data)
	return err
}

// msgReader reads newline-delimited JSON-RPC messages from a *bufio.Scanner.
// NOT concurrent-safe: only one goroutine should call Scan at a time.
type msgReader struct {
	s *bufio.Scanner
}

func newMsgReader(r io.Reader) *msgReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4<<20), 4<<20) // 4 MiB per-message limit
	return &msgReader{s: s}
}

// Read returns the next message. Returns io.EOF when the stream ends.
func (mr *msgReader) Read() (rpcMsg, error) {
	if !mr.s.Scan() {
		if err := mr.s.Err(); err != nil {
			return rpcMsg{}, err
		}
		return rpcMsg{}, io.EOF
	}
	var msg rpcMsg
	if err := json.Unmarshal(mr.s.Bytes(), &msg); err != nil {
		return rpcMsg{}, fmt.Errorf("parsing JSON-RPC message: %w", err)
	}
	return msg, nil
}

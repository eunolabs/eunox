// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Lightweight one-shot MCP client used by the validate --live and init
// subcommands.  It is intentionally thin: no session management, no proxy
// machinery — just the initialize handshake followed by tools/list.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// LiveUpstreamInfo holds the tool list and server metadata fetched from a
// live MCP HTTP server during the validate --live and init handshake.
type LiveUpstreamInfo struct {
	Tools         []UpstreamTool
	ServerVersion string // version field from initialize serverInfo; empty if absent
}

// fetchLiveTools connects to the remote MCP HTTP server at baseURL, performs
// the initialize handshake, sends tools/list, and returns the live tool set
// together with the server version reported in the initialize response.
//
// baseURL is the server's base URL (e.g. "https://mcp.example.com"); "/mcp"
// is appended automatically, matching the proxy convention.
func fetchLiveTools(ctx context.Context, baseURL, authHeader string, tlsSkipVerify bool) (LiveUpstreamInfo, error) {
	client := buildUpstreamClient(tlsSkipVerify)
	endpoint := strings.TrimRight(baseURL, "/") + "/mcp"

	initParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	})
	initResp, respHdr, err := liveDoHTTP(ctx, client, endpoint, rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`1`),
		Method:  "initialize",
		Params:  initParams,
	}, "", authHeader)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}
	if initResp.Error != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: server error %d: %s", initResp.Error.Code, initResp.Error.Message)
	}
	sessID := respHdr.Get(sessionHeader)

	// Extract the server version from the initialize result.
	var serverVersion string
	if initResp.Result != nil {
		var initResult mcpInitResult
		if json.Unmarshal(initResp.Result, &initResult) == nil {
			if sv, ok := initResult.ServerInfo["version"].(string); ok {
				serverVersion = sv
			}
		}
	}

	notif, _ := notificationMsg("notifications/initialized", nil)
	if _, _, err := liveDoHTTP(ctx, client, endpoint, notif, sessID, authHeader); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("notifications/initialized: %w", err)
	}

	listResp, _, err := liveDoHTTP(ctx, client, endpoint, rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON(`2`),
		Method:  "tools/list",
	}, sessID, authHeader)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("tools/list: %w", err)
	}
	if listResp.Error != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("tools/list: server error %d: %s", listResp.Error.Code, listResp.Error.Message)
	}
	tools, err := parseToolsListResult(listResp.Result)
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	return LiveUpstreamInfo{Tools: tools, ServerVersion: serverVersion}, nil
}

// liveDoHTTP POSTs msg to endpoint, attaching sessID and authHeader as
// request headers.  A 202 Accepted response (notifications) returns an empty
// rpcMsg without error.
func liveDoHTTP(ctx context.Context, client *http.Client, endpoint string, msg rpcMsg, sessID, authHeader string) (rpcMsg, http.Header, error) { //nolint:gocritic // hugeParam: rpcMsg intentionally passed by value
	data, err := json.Marshal(msg)
	if err != nil {
		return rpcMsg{}, nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data)) //nolint:gosec // G107: endpoint constructed from user-specified --upstream-url flag
	if err != nil {
		return rpcMsg{}, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", ctJSON)
	if sessID != "" {
		req.Header.Set(sessionHeader, sessID)
	}
	if authHeader != "" {
		parts := strings.SplitN(authHeader, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return rpcMsg{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusAccepted {
		return rpcMsg{}, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return rpcMsg{}, resp.Header, fmt.Errorf("upstream returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return rpcMsg{}, resp.Header, fmt.Errorf("decode response: %w", err)
	}
	return result, resp.Header, nil
}

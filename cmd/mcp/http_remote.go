// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Remote HTTP upstream support for the MCP proxy (T-01: --upstream-url).
//
// When UpstreamURL is set, each client session forwards its requests to a
// remote MCP HTTP server instead of spawning a local subprocess.  The proxy
// still applies the full PDP enforcement stack before forwarding.
//
// Session model:
//
//	Client → eunox-mcp proxy → remote MCP server (HTTP)
//
// The proxy initialises its own session with the remote server on the first
// client initialize request, stores the upstream Mcp-Session-Id, then uses it
// for every subsequent forwarded call.
//
// Limitations (MVP):
//   - SSE notifications pushed by the remote server are not forwarded to the
//     client.  The client's GET /mcp SSE stream is held open but events arrive
//     only if the proxy itself emits them (e.g. kill-switch).

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
)

// buildUpstreamClient returns an HTTP client for communicating with the remote
// upstream.  When tlsSkipVerify is true the client accepts any TLS certificate
// (for development only — callers are responsible for emitting a warning).
func buildUpstreamClient(tlsSkipVerify bool) *http.Client {
	if tlsSkipVerify {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: explicit dev flag; warning logged at startup
			},
		}
	}
	return &http.Client{}
}

// setUpstreamAuthHeader attaches the configured auth header to req.
// The header value is expected in "Header-Name: Header-Value" format.
func (p *HTTPProxy) setUpstreamAuthHeader(req *http.Request) {
	if p.upstreamAuthHeader == "" {
		return
	}
	parts := strings.SplitN(p.upstreamAuthHeader, ":", 2)
	if len(parts) != 2 {
		return
	}
	req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
}

// mcpEndpointURL returns the full URL of the remote MCP endpoint.
// The proxy appends /mcp to the configured base URL.
func (p *HTTPProxy) mcpEndpointURL() string {
	return strings.TrimRight(p.upstreamURL, "/") + "/mcp"
}

// newRemoteSession creates a client session backed by the configured remote
// HTTP upstream.  It performs the MCP initialize handshake, stores the
// upstream session ID, and registers the session in p.sessions.
func (p *HTTPProxy) newRemoteSession(ctx context.Context) (*httpSession, error) {
	client := buildUpstreamClient(p.upstreamTLSSkipVerify)

	sess := &httpSession{
		id:           uuid.New().String(),
		proxy:        p,
		pending:      make(map[string]chan rpcMsg),
		done:         make(chan struct{}),
		upHTTPClient: client,
		upstreamURL:  p.upstreamURL,
	}

	if err := sess.initRemoteUpstream(ctx); err != nil {
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}

	// Drift check (remote mode: callUpstream works directly without a goroutine).
	if p.manifest != nil {
		if p.strictDrift {
			if err := runHTTPDriftCheck(ctx, sess, p.manifest, true); err != nil {
				close(sess.done)
				return nil, err
			}
		} else {
			driftCtx := context.WithoutCancel(ctx)
			go func() {
				if err := runHTTPDriftCheck(driftCtx, sess, p.manifest, false); err != nil {
					_ = err
				}
			}()
		}
	}

	// Cleanup goroutine: remove the session once done is closed.
	go func() {
		<-sess.done
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[eunox-mcp] HTTP session %s ended.\n", sess.id)
	}()

	p.mu.Lock()
	p.sessions[sess.id] = sess
	p.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[eunox-mcp] HTTP session %s started (remote: %s).\n", sess.id, p.upstreamURL)
	return sess, nil
}

// initRemoteUpstream performs the MCP initialize handshake with the remote
// upstream server.  It sends an initialize request, captures the upstream
// Mcp-Session-Id, stores the server capabilities, then sends the
// notifications/initialized notification.
func (s *httpSession) initRemoteUpstream(ctx context.Context) error {
	s.idCounter++
	initID := rawJSON(fmt.Sprintf("%d", s.idCounter))

	params, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	})
	initReq := rpcMsg{JSONRPC: "2.0", ID: initID, Method: "initialize", Params: params}

	respMsg, respHdr, err := s.doRemoteHTTP(ctx, initReq, "")
	if err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	// Capture the upstream session ID from the response header.
	s.upstreamSessID = respHdr.Get(sessionHeader)

	// Extract server capabilities.
	if respMsg.Result != nil {
		var result mcpInitResult
		if json.Unmarshal(respMsg.Result, &result) == nil {
			s.upstreamCaps = result.Capabilities
		}
	}

	// Send notifications/initialized to the upstream.
	notif, _ := notificationMsg("notifications/initialized", nil)
	_, _, err = s.doRemoteHTTP(ctx, notif, s.upstreamSessID)
	return err
}

// callRemoteUpstream forwards msg to the remote upstream and returns the
// response.  For notifications (no ID) it returns an empty rpcMsg on success.
func (s *httpSession) callRemoteUpstream(ctx context.Context, msg rpcMsg) (rpcMsg, error) { //nolint:gocritic // hugeParam: rpcMsg is passed by value intentionally
	resp, _, err := s.doRemoteHTTP(ctx, msg, s.upstreamSessID)
	return resp, err
}

// doRemoteHTTP marshals msg and POSTs it to the upstream MCP endpoint,
// setting the given session ID header (empty string omits the header).
// It returns the decoded JSON-RPC response and the response headers.
func (s *httpSession) doRemoteHTTP(ctx context.Context, msg rpcMsg, sessID string) (rpcMsg, http.Header, error) { //nolint:gocritic // hugeParam: rpcMsg is passed by value intentionally
	data, err := json.Marshal(msg)
	if err != nil {
		return rpcMsg{}, nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.proxy.mcpEndpointURL(), bytes.NewReader(data))
	if err != nil {
		return rpcMsg{}, nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", ctJSON)
	if sessID != "" {
		req.Header.Set(sessionHeader, sessID)
	}
	s.proxy.setUpstreamAuthHeader(req)

	resp, err := s.upHTTPClient.Do(req)
	if err != nil {
		return rpcMsg{}, nil, fmt.Errorf("upstream HTTP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 202 Accepted is the expected response for notifications; no body to parse.
	if resp.StatusCode == http.StatusAccepted {
		return rpcMsg{}, resp.Header, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return rpcMsg{}, resp.Header, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result rpcMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return rpcMsg{}, resp.Header, fmt.Errorf("decoding upstream response: %w", err)
	}
	return result, resp.Header, nil
}

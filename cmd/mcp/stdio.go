// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: Apache-2.0

// Package main — stdio proxy transport.
//
// Architecture:
//
//	MCP host  ──stdin/stdout──►  StdioProxy  ──►  upstream MCP server (subprocess)
//
// Message flow:
//
//	host request (tools/call) → PDP decision → allow: upstream → result → host
//	                                         → deny:  denial result → host
//	host request (other)      → upstream → response → host
//	host notification         → upstream (forwarded verbatim)
//	upstream notification     → host (forwarded verbatim)
//
// Concurrency: one goroutine reads from the host, one from the upstream.
// Pending host requests are tracked in a map keyed by JSON-RPC message ID.
// Responses from the upstream are routed to the correct pending entry.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

const (
	proxyName    = "eunox-mcp-proxy"
	proxyVersion = "0.1.0"

	mcpProtocolVersion = "2025-11-25"
)

// StdioProxy proxies MCP messages between the host (stdin/stdout) and an
// upstream MCP server subprocess, applying PDP enforcement to tools/call.
type StdioProxy struct {
	command        string
	args           []string
	pdp            PolicyDecisionPoint
	sink           *auditSink
	sessionID      string
	shutdownMs     int
	upstreamTimeMs int // 0 = no timeout

	// runtime (set in Start)
	upCmd    *exec.Cmd
	upIn     io.WriteCloser
	upReader *msgReader

	hostReader *msgReader
	hostWriter *msgWriter

	upWriter *msgWriter // guarded by upWriter's internal mutex

	// pendingMu guards pending.
	pendingMu sync.Mutex
	pending   map[string]chan rpcMsg

	// upstreamCaps holds the server capabilities from the upstream initialize response.
	upstreamCaps map[string]interface{}

	// idCounter is used for the proxy→upstream initialize request ID.
	idCounter int64
}

// StdioProxyOptions configures a StdioProxy.
type StdioProxyOptions struct {
	Command        string
	Args           []string
	PDP            PolicyDecisionPoint
	Sink           *auditSink
	SessionID      string
	ShutdownMs     int
	UpstreamTimeMs int
}

// NewStdioProxy creates a StdioProxy ready to call Start.
func NewStdioProxy(opts StdioProxyOptions) *StdioProxy {
	if opts.PDP == nil {
		opts.PDP = alwaysAllowPDP{}
	}
	if opts.ShutdownMs <= 0 {
		opts.ShutdownMs = 5000
	}
	return &StdioProxy{
		command:        opts.Command,
		args:           opts.Args,
		pdp:            opts.PDP,
		sink:           opts.Sink,
		sessionID:      opts.SessionID,
		shutdownMs:     opts.ShutdownMs,
		upstreamTimeMs: opts.UpstreamTimeMs,
		pending:        make(map[string]chan rpcMsg),
		hostReader:     newMsgReader(os.Stdin),
		hostWriter:     newMsgWriter(os.Stdout),
	}
}

// Start runs the proxy until the host closes stdin or the upstream exits.
// It returns when the session ends.
func (p *StdioProxy) Start(ctx context.Context) error {
	// ── 1. Launch upstream ────────────────────────────────────────────────────
	p.upCmd = exec.CommandContext(ctx, p.command, p.args...)
	p.upCmd.Stderr = os.Stderr

	upIn, err := p.upCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("upstream stdin: %w", err)
	}
	p.upIn = upIn

	upOut, err := p.upCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("upstream stdout: %w", err)
	}
	p.upWriter = newMsgWriter(upIn)
	p.upReader = newMsgReader(upOut)

	if err := p.upCmd.Start(); err != nil {
		return fmt.Errorf("starting upstream %q: %w", p.command, err)
	}

	// ── 2. Initialize handshake with upstream ─────────────────────────────────
	if err := p.initUpstream(); err != nil {
		_ = p.upCmd.Process.Kill()
		return fmt.Errorf("upstream initialize: %w", err)
	}

	// ── 3. Read upstream messages in background ────────────────────────────────
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		p.readUpstream()
	}()

	// ── 4. Install signal handler → SIGINT/SIGTERM forwarded to upstream ───────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig, ok := <-sigCh
		if !ok {
			return
		}
		fmt.Fprintf(os.Stderr, "[eunox-mcp] Received %s; forwarding to upstream.\n", sig)
		if p.upCmd.Process != nil {
			_ = p.upCmd.Process.Signal(sig)
		}
		// Start the kill timer.
		killMs := p.shutdownMs
		if killMs <= 0 {
			killMs = 5000
		}
		time.AfterFunc(time.Duration(killMs)*time.Millisecond, func() {
			if p.upCmd.Process != nil {
				fmt.Fprintf(os.Stderr, "[eunox-mcp] Upstream did not exit; sending SIGKILL.\n")
				_ = p.upCmd.Process.Kill()
			}
		})
	}()

	fmt.Fprintf(os.Stderr, "[eunox-mcp] Session %s initialized; proxying to %q.\n", p.sessionID, p.command)

	// ── 5. Serve host ─────────────────────────────────────────────────────────
	p.serveHost(ctx)

	// ── 6. Drain upstream reader ──────────────────────────────────────────────
	signal.Stop(sigCh)
	close(sigCh)
	_ = p.upIn.Close()
	<-upstreamDone
	_ = p.upCmd.Wait()

	return nil
}

// initUpstream performs the MCP initialize handshake with the upstream server.
func (p *StdioProxy) initUpstream() error {
	p.idCounter++
	initID := rawJSON(fmt.Sprintf("%d", p.idCounter))

	initReq := rpcMsg{
		JSONRPC: "2.0",
		ID:      initID,
		Method:  "initialize",
	}
	params, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	})
	initReq.Params = params

	if err := p.upWriter.Write(initReq); err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	// Read messages until we get the initialize response.
	for {
		msg, err := p.upReader.Read()
		if err != nil {
			return fmt.Errorf("reading initialize response: %w", err)
		}
		if msg.isResponse() && msgKey(msg.ID) == msgKey(initID) {
			// Extract server capabilities.
			var result mcpInitResult
			if err := json.Unmarshal(msg.Result, &result); err == nil {
				p.upstreamCaps = result.Capabilities
			}
			break
		}
		// Discard any notifications that arrive before the initialize response.
	}

	// Send `initialized` notification to upstream.
	notif, err := notificationMsg("notifications/initialized", nil)
	if err != nil {
		return err
	}
	return p.upWriter.Write(notif)
}

// serveHost reads from host stdin until EOF and dispatches messages.
func (p *StdioProxy) serveHost(ctx context.Context) {
	var wg sync.WaitGroup
	for {
		msg, err := p.hostReader.Read()
		if err != nil {
			break
		}
		if msg.isNotification() {
			// Forward host→upstream notifications verbatim (e.g. notifications/cancelled).
			// We swallow notifications/initialized since the upstream was already
			// initialized by the proxy's own client handshake.
			if msg.Method != "notifications/initialized" {
				_ = p.upWriter.Write(msg)
			}
			continue
		}
		if msg.isRequest() {
			wg.Add(1)
			go func(m rpcMsg) {
				defer wg.Done()
				p.handleHostRequest(ctx, m)
			}(msg)
		}
		// Ignore malformed messages.
	}
	wg.Wait()
}

// handleHostRequest processes a single request from the host.
func (p *StdioProxy) handleHostRequest(ctx context.Context, msg rpcMsg) {
	switch msg.Method {
	case "initialize":
		p.handleInitialize(msg)
	case "tools/call":
		p.handleToolsCall(ctx, msg)
	default:
		p.forwardToUpstream(ctx, msg)
	}
}

// handleInitialize responds to the host's initialize request using the
// upstream capabilities gathered during proxy startup.
func (p *StdioProxy) handleInitialize(msg rpcMsg) {
	caps := p.upstreamCaps
	if caps == nil {
		caps = map[string]interface{}{"tools": map[string]interface{}{}}
	}
	result := mcpInitResult{
		ProtocolVersion: mcpProtocolVersion,
		Capabilities:    caps,
		ServerInfo: map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	}
	resp, err := successResponse(msg.ID, result)
	if err != nil {
		resp = errorResponse(msg.ID, -32603, "internal error building initialize response")
	}
	_ = p.hostWriter.Write(resp)

	fmt.Fprintf(os.Stderr,
		"[eunox-mcp] Session %s: host initialized (protocol %s).\n",
		p.sessionID, mcpProtocolVersion,
	)
}

// handleToolsCall applies the PDP and either forwards to upstream or returns a denial.
func (p *StdioProxy) handleToolsCall(ctx context.Context, msg rpcMsg) {
	var params mcpToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		_ = p.hostWriter.Write(errorResponse(msg.ID, -32602, "invalid tools/call params"))
		return
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}

	dec := p.pdp.Decide(ctx, p.sessionID, params.Name, params.Arguments, "")

	if dec.Decision == capability.DecisionDeny {
		denial := dec.Denial
		if p.sink != nil {
			p.sink.Record(p.sessionID, params.Name, "deny", denial.Code, denial.ConditionType, denial.Details, nil)
		}
		resp := denialResult(msg.ID, params.Name, denial.Code, denial.Message, denial.Details)
		_ = p.hostWriter.Write(resp)
		return
	}

	// Forward to upstream with optional timeout.
	var upResp rpcMsg
	var fwdErr error
	if p.upstreamTimeMs > 0 {
		deadline := time.Duration(p.upstreamTimeMs) * time.Millisecond
		ctx2, cancel := context.WithTimeout(ctx, deadline)
		defer cancel()
		upResp, fwdErr = p.callUpstream(ctx2, msg)
	} else {
		upResp, fwdErr = p.callUpstream(ctx, msg)
	}

	if fwdErr != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] upstream error on %q: %v\n", params.Name, fwdErr)
		code := "UPSTREAM_ERROR"
		reason := "upstream error: " + fwdErr.Error()
		if ctx.Err() != nil {
			code = "UPSTREAM_TIMEOUT"
			reason = fmt.Sprintf("upstream did not respond within %d ms", p.upstreamTimeMs)
		}
		if p.sink != nil {
			p.sink.Record(p.sessionID, params.Name, "deny", code, "", nil, nil)
		}
		_ = p.hostWriter.Write(denialResult(msg.ID, params.Name, code, reason, nil))
		return
	}

	// Apply redactFields obligations.
	if len(dec.Obligations) > 0 && upResp.Result != nil {
		upResp.Result = applyRedactObligs(upResp.Result, dec.Obligations)
	}

	var oblNames []string
	for _, ob := range dec.Obligations {
		oblNames = append(oblNames, ob.Type)
	}
	if p.sink != nil {
		p.sink.Record(p.sessionID, params.Name, "allow", "", "", nil, oblNames)
	}
	upResp.ID = msg.ID // ensure the response carries the host's original ID
	_ = p.hostWriter.Write(upResp)
}

// forwardToUpstream sends a request to the upstream and returns its response.
func (p *StdioProxy) forwardToUpstream(ctx context.Context, msg rpcMsg) {
	resp, err := p.callUpstream(ctx, msg)
	if err != nil {
		_ = p.hostWriter.Write(errorResponse(msg.ID, -32603, "upstream error: "+err.Error()))
		return
	}
	resp.ID = msg.ID
	_ = p.hostWriter.Write(resp)
}

// callUpstream registers a pending entry, sends msg to the upstream, and waits
// for the matching response.  The response's ID is the upstream's echo.
func (p *StdioProxy) callUpstream(ctx context.Context, msg rpcMsg) (rpcMsg, error) {
	key := msgKey(msg.ID)
	ch := make(chan rpcMsg, 1)

	p.pendingMu.Lock()
	p.pending[key] = ch
	p.pendingMu.Unlock()

	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, key)
		p.pendingMu.Unlock()
	}()

	if err := p.upWriter.Write(msg); err != nil {
		return rpcMsg{}, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return rpcMsg{}, ctx.Err()
	}
}

// readUpstream continuously reads from the upstream stdout and routes messages.
// Responses are delivered to waiting pending entries; notifications are forwarded
// to the host.
func (p *StdioProxy) readUpstream() {
	for {
		msg, err := p.upReader.Read()
		if err != nil {
			return
		}

		if msg.isNotification() {
			_ = p.hostWriter.Write(msg)
			continue
		}

		if msg.isResponse() {
			key := msgKey(msg.ID)
			p.pendingMu.Lock()
			ch, ok := p.pending[key]
			p.pendingMu.Unlock()
			if ok {
				ch <- msg
			}
		}
	}
}

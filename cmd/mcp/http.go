// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP proxy transport (MCP Streamable HTTP / SSE).
//
// Architecture:
//
//	MCP client ──HTTP──► HTTPProxy (one httpSession per client session)
//	                          │
//	                    upstream subprocess (stdio JSON-RPC)
//
// Session lifecycle:
//
//	POST /mcp (initialize, no session ID) → spawn upstream → initialize handshake → mint session ID
//	POST /mcp (session ID)               → route request to session's upstream
//	GET  /mcp (session ID)               → SSE stream of upstream notifications
//	DELETE /mcp (session ID)             → close session and upstream
//
// POST /control/kill (loopback only) → kill a session or all sessions.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/google/uuid"
)

const (
	sessionHeader = "Mcp-Session-Id"
	ctJSON        = "application/json"
	ctSSE         = "text/event-stream"
)

// HTTPProxy implements the MCP Streamable HTTP transport.
// Each client session gets its own upstream subprocess.
type HTTPProxy struct {
	command        string
	args           []string
	pdp            PolicyDecisionPoint
	sink           *auditSink
	ks             killswitch.Manager
	shutdownMs     int
	upstreamTimeMs int
	authToken      string
	trustFwdFor    bool
	bind           string
	port           int

	mu       sync.Mutex
	sessions map[string]*httpSession
}

// HTTPProxyOptions configures an HTTPProxy.
type HTTPProxyOptions struct {
	Command        string
	Args           []string
	PDP            PolicyDecisionPoint
	Sink           *auditSink
	KS             killswitch.Manager
	ShutdownMs     int
	UpstreamTimeMs int
	AuthToken      string
	TrustFwdFor    bool
	Port           int
	Bind           string
}

// NewHTTPProxy creates an HTTPProxy ready to call Serve.
func NewHTTPProxy(opts HTTPProxyOptions) *HTTPProxy { //nolint:gocritic // hugeParam: value copy is intentional; callers build opts inline
	if opts.PDP == nil {
		opts.PDP = alwaysAllowPDP{}
	}
	if opts.KS == nil {
		opts.KS = killswitch.NewInMemory()
	}
	if opts.ShutdownMs <= 0 {
		opts.ShutdownMs = 5000
	}
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	if opts.Port <= 0 {
		opts.Port = 3000
	}
	return &HTTPProxy{
		command:        opts.Command,
		args:           opts.Args,
		pdp:            opts.PDP,
		sink:           opts.Sink,
		ks:             opts.KS,
		shutdownMs:     opts.ShutdownMs,
		upstreamTimeMs: opts.UpstreamTimeMs,
		authToken:      opts.AuthToken,
		trustFwdFor:    opts.TrustFwdFor,
		bind:           opts.Bind,
		port:           opts.Port,
		sessions:       make(map[string]*httpSession),
	}
}

// httpSession is one client session with its own upstream subprocess.
type httpSession struct {
	id    string
	proxy *HTTPProxy

	upCmd    *exec.Cmd
	upIn     io.WriteCloser
	upWriter *msgWriter
	upReader *msgReader

	pendingMu sync.Mutex
	pending   map[string]chan rpcMsg

	upstreamCaps map[string]interface{}
	idCounter    int64

	notifMu   sync.Mutex
	notifSubs []chan rpcMsg

	closeOnce sync.Once
	done      chan struct{} // closed by readUpstream when the upstream exits
}

// Serve starts the HTTP server and blocks until ctx is cancelled or a fatal
// error occurs.
func (p *HTTPProxy) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", p.handleMCP)
	mux.HandleFunc("/control/kill", p.handleKill)

	addr := fmt.Sprintf("%s:%d", p.bind, p.port)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	fmt.Fprintf(os.Stderr, "[eunox-mcp] HTTP proxy listening on http://%s/mcp\n", ln.Addr())

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		// ctx is already cancelled; fresh context required for graceful shutdown.
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Duration(p.shutdownMs)*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		p.closeAllSessions()
		return nil
	case err := <-errCh:
		return err
	}
}

// checkAuth validates the Authorization header when an auth token is configured.
// Returns true if the request is authorised; false if not (response already written).
func (p *HTTPProxy) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if p.authToken == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || auth[len("Bearer "):] != p.authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// sourceIP extracts the client IP address for PDP evaluation.
func (p *HTTPProxy) sourceIP(r *http.Request) string {
	if p.trustFwdFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// handleMCP dispatches POST / GET / DELETE requests to /mcp.
func (p *HTTPProxy) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodPost:
		p.handleMCPPost(w, r)
	case http.MethodGet:
		p.handleMCPGet(w, r)
	case http.MethodDelete:
		p.handleMCPDelete(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleMCPPost processes a JSON-RPC request from the MCP host.
func (p *HTTPProxy) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	var msg rpcMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid JSON-RPC body", http.StatusBadRequest)
		return
	}

	sessionID := r.Header.Get(sessionHeader)

	// An initialize request with no session ID creates a new session.
	if msg.Method == "initialize" && sessionID == "" {
		sess, err := p.newSession()
		if err != nil {
			http.Error(w, "failed to start upstream: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set(sessionHeader, sess.id)
		resp := sess.buildInitResponse(msg)
		w.Header().Set("Content-Type", ctJSON)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	sess := p.getSession(sessionID)
	if sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Host notifications are forwarded verbatim (except notifications/initialized).
	if msg.isNotification() {
		if msg.Method != "notifications/initialized" {
			_ = sess.upWriter.Write(msg)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !msg.isRequest() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	ctx := r.Context()
	var resp rpcMsg
	switch msg.Method {
	case "initialize":
		resp = sess.buildInitResponse(msg)
	case "tools/call":
		resp = p.handleHTTPToolsCall(ctx, sess, msg, p.sourceIP(r))
	default:
		var err error
		resp, err = sess.callUpstream(ctx, msg)
		if err != nil {
			resp = errorResponse(msg.ID, -32603, "upstream error: "+err.Error())
		}
		resp.ID = msg.ID
	}

	w.Header().Set("Content-Type", ctJSON)
	_ = json.NewEncoder(w).Encode(resp)
}

// buildInitResponse builds an initialize response for the host using the
// upstream capabilities gathered during session startup.
func (s *httpSession) buildInitResponse(msg rpcMsg) rpcMsg { //nolint:gocritic // hugeParam: rpcMsg is passed by value intentionally for clarity
	caps := s.upstreamCaps
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
		return errorResponse(msg.ID, -32603, "internal error building initialize response")
	}
	return resp
}

// handleHTTPToolsCall applies the PDP and either forwards to the upstream or
// returns a denial result.
func (p *HTTPProxy) handleHTTPToolsCall(ctx context.Context, sess *httpSession, msg rpcMsg, sourceIP string) rpcMsg { //nolint:gocritic // hugeParam: rpcMsg is passed by value intentionally
	var params mcpToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return errorResponse(msg.ID, -32602, "invalid tools/call params")
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}

	dec := p.pdp.Decide(ctx, sess.id, params.Name, params.Arguments, sourceIP)
	if dec.Decision == capability.DecisionDeny {
		denial := dec.Denial
		if p.sink != nil {
			p.sink.Record(sess.id, params.Name, "deny", denial.Code, denial.ConditionType, denial.Details, nil)
		}
		return denialResult(msg.ID, params.Name, denial.Code, denial.Message, denial.Details)
	}

	var (
		upResp rpcMsg
		fwdErr error
	)
	if p.upstreamTimeMs > 0 {
		deadline := time.Duration(p.upstreamTimeMs) * time.Millisecond
		ctx2, cancel := context.WithTimeout(ctx, deadline)
		defer cancel()
		upResp, fwdErr = sess.callUpstream(ctx2, msg)
	} else {
		upResp, fwdErr = sess.callUpstream(ctx, msg)
	}

	if fwdErr != nil {
		code := "UPSTREAM_ERROR"
		reason := "upstream error: " + fwdErr.Error()
		if ctx.Err() != nil {
			code = "UPSTREAM_TIMEOUT"
			reason = fmt.Sprintf("upstream did not respond within %d ms", p.upstreamTimeMs)
		}
		if p.sink != nil {
			p.sink.Record(sess.id, params.Name, "deny", code, "", nil, nil)
		}
		return denialResult(msg.ID, params.Name, code, reason, nil)
	}

	if len(dec.Obligations) > 0 && upResp.Result != nil {
		upResp.Result = applyRedactObligs(upResp.Result, dec.Obligations)
	}
	var oblNames []string
	for _, ob := range dec.Obligations {
		oblNames = append(oblNames, ob.Type)
	}
	if p.sink != nil {
		p.sink.Record(sess.id, params.Name, "allow", "", "", nil, oblNames)
	}
	upResp.ID = msg.ID
	return upResp
}

// handleMCPGet opens a server-sent events stream for upstream notifications.
func (p *HTTPProxy) handleMCPGet(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(sessionHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	sess := p.getSession(sessionID)
	if sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ctSSE)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := make(chan rpcMsg, 16)
	sess.addSub(ch)
	defer sess.removeSub(ch)

	for {
		select {
		case msg := <-ch:
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-sess.done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// handleMCPDelete closes an existing session.
func (p *HTTPProxy) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(sessionHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	sess, ok := p.sessions[sessionID]
	if ok {
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	sess.close(p.shutdownMs)
	w.WriteHeader(http.StatusNoContent)
}

// handleKill processes POST /control/kill (loopback only).
func (p *HTTPProxy) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		SessionID string `json:"sessionId"`
		All       bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.All {
		_ = p.ks.ActivateGlobal(r.Context())
		w.Header().Set("Content-Type", ctJSON)
		_, _ = fmt.Fprint(w, `{"ok":true,"killed":"all"}`)
		return
	}
	if body.SessionID == "" {
		http.Error(w, "sessionId or all required", http.StatusBadRequest)
		return
	}
	_ = p.ks.KillSession(r.Context(), body.SessionID)
	w.Header().Set("Content-Type", ctJSON)
	b, _ := json.Marshal(map[string]interface{}{"ok": true, "killed": body.SessionID})
	_, _ = w.Write(b)
}

// newSession spawns a new upstream subprocess and performs the MCP initialize
// handshake.  The session is registered in p.sessions before returning.
func (p *HTTPProxy) newSession() (*httpSession, error) {
	sess := &httpSession{
		id:      uuid.New().String(),
		proxy:   p,
		pending: make(map[string]chan rpcMsg),
		done:    make(chan struct{}),
	}

	cmd := exec.Command(p.command, p.args...) //nolint:gosec,noctx // G204: args are user-supplied CLI arguments; session lifecycle managed via done channel, not ctx
	cmd.Stderr = os.Stderr

	upIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("upstream stdin: %w", err)
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("upstream stdout: %w", err)
	}
	sess.upCmd = cmd
	sess.upIn = upIn
	sess.upWriter = newMsgWriter(upIn)
	sess.upReader = newMsgReader(upOut)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting upstream %q: %w", p.command, err)
	}

	if err := sess.initUpstream(); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}

	go sess.readUpstream()

	// Cleanup goroutine: wait for the upstream to exit, then remove the session.
	go func() {
		<-sess.done
		_ = sess.upCmd.Wait()
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[eunox-mcp] HTTP session %s ended.\n", sess.id)
	}()

	p.mu.Lock()
	p.sessions[sess.id] = sess
	p.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[eunox-mcp] HTTP session %s started.\n", sess.id)
	return sess, nil
}

// getSession returns the session for id, or nil.
func (p *HTTPProxy) getSession(id string) *httpSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessions[id]
}

// closeAllSessions closes every active session (called during server shutdown).
func (p *HTTPProxy) closeAllSessions() {
	p.mu.Lock()
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.sessions = make(map[string]*httpSession)
	p.mu.Unlock()
	for _, s := range sessions {
		s.close(p.shutdownMs)
	}
}

// initUpstream performs the MCP initialize handshake with the upstream server.
func (s *httpSession) initUpstream() error {
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
	req := rpcMsg{JSONRPC: "2.0", ID: initID, Method: "initialize", Params: params}
	if err := s.upWriter.Write(req); err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	for {
		msg, err := s.upReader.Read()
		if err != nil {
			return fmt.Errorf("reading initialize response: %w", err)
		}
		if msg.isResponse() && msgKey(msg.ID) == msgKey(initID) {
			var result mcpInitResult
			if err := json.Unmarshal(msg.Result, &result); err == nil {
				s.upstreamCaps = result.Capabilities
			}
			break
		}
	}

	notif, err := notificationMsg("notifications/initialized", nil)
	if err != nil {
		return err
	}
	return s.upWriter.Write(notif)
}

// readUpstream continuously reads from the upstream and routes messages.
// Responses are delivered to waiting callUpstream callers; notifications are
// broadcast to all active SSE subscribers.
func (s *httpSession) readUpstream() {
	defer close(s.done)
	for {
		msg, err := s.upReader.Read()
		if err != nil {
			return
		}
		if msg.isNotification() {
			s.broadcast(msg)
			continue
		}
		if msg.isResponse() {
			key := msgKey(msg.ID)
			s.pendingMu.Lock()
			ch, ok := s.pending[key]
			s.pendingMu.Unlock()
			if ok {
				ch <- msg
			}
		}
	}
}

// callUpstream registers a pending entry, sends msg to the upstream, and waits
// for the matching response.
func (s *httpSession) callUpstream(ctx context.Context, msg rpcMsg) (rpcMsg, error) { //nolint:gocritic // hugeParam: rpcMsg is passed by value intentionally
	key := msgKey(msg.ID)
	ch := make(chan rpcMsg, 1)

	s.pendingMu.Lock()
	s.pending[key] = ch
	s.pendingMu.Unlock()

	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, key)
		s.pendingMu.Unlock()
	}()

	if err := s.upWriter.Write(msg); err != nil {
		return rpcMsg{}, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return rpcMsg{}, ctx.Err()
	case <-s.done:
		return rpcMsg{}, fmt.Errorf("session upstream exited")
	}
}

// close shuts down the upstream subprocess for this session.
func (s *httpSession) close(shutdownMs int) {
	s.closeOnce.Do(func() {
		_ = s.upIn.Close()
		select {
		case <-s.done:
		case <-time.After(time.Duration(shutdownMs) * time.Millisecond):
			if s.upCmd.Process != nil {
				_ = s.upCmd.Process.Kill()
			}
			<-s.done
		}
	})
}

// broadcast delivers a notification to all active SSE subscribers.
func (s *httpSession) broadcast(msg rpcMsg) {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	for _, ch := range s.notifSubs {
		select {
		case ch <- msg:
		default: // slow subscriber; drop the notification
		}
	}
}

func (s *httpSession) addSub(ch chan rpcMsg) {
	s.notifMu.Lock()
	s.notifSubs = append(s.notifSubs, ch)
	s.notifMu.Unlock()
}

func (s *httpSession) removeSub(ch chan rpcMsg) {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	for i, c := range s.notifSubs {
		if c == ch {
			s.notifSubs = append(s.notifSubs[:i], s.notifSubs[i+1:]...)
			return
		}
	}
}

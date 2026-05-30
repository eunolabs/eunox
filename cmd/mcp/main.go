// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// eunox-mcp is a policy-enforcement proxy for MCP (Model Context Protocol)
// servers.  It sits between an MCP host (e.g. Claude Desktop) and an upstream
// MCP server subprocess, evaluating every tools/call request against a local
// capability manifest before forwarding it.
//
// Subcommands:
//
//	proxy          Start the proxy (stdio or HTTP transport).
//	validate       Validate one or more manifest files and exit.
//	kill           Send a kill-switch signal to a running HTTP proxy.
//	validate-token Verify HMAC signatures in the audit log.
//	stats          Print a denial histogram from the audit log.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "proxy":
		cmdProxy()
	case "validate":
		cmdValidate()
	case "kill":
		cmdKill()
	case "validate-token":
		cmdValidateToken()
	case "stats":
		cmdStats()
	case "profiles":
		cmdProfiles()
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "eunox-mcp: unknown subcommand %q\n\nRun 'eunox-mcp --help' for usage.\n", os.Args[1])
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `eunox-mcp — MCP policy-enforcement proxy

Usage:
  eunox-mcp proxy   [flags] -- <command> [args...]        local subprocess upstream
  eunox-mcp proxy   --transport http --upstream-url <url> remote MCP server
  eunox-mcp validate <manifest.yaml> [...]
  eunox-mcp kill    [--port N] [--host H] <session-id|all>
  eunox-mcp validate-token [flags]
  eunox-mcp stats   [flags]
  eunox-mcp profiles [<name>]

Subcommands:
  proxy           Start the proxy (default: stdio transport).
  validate        Validate manifest file(s) and exit 0 on success.
  kill            Activate the kill switch on a running HTTP proxy.
  validate-token  Verify HMAC signatures in the local audit log.
  stats           Print a denial count histogram from the audit log.
  profiles        List built-in server profiles (or show tools for one profile).

Run 'eunox-mcp <subcommand> --help' for per-command flags.
`)
}

// -----------------------------------------------------------------
// proxy subcommand
// -----------------------------------------------------------------

func cmdProxy() {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox-mcp proxy [flags] -- <command> [args...]   local subprocess upstream
  eunox-mcp proxy [flags] --upstream-url <url>      remote HTTP upstream

Start the MCP policy-enforcement proxy.

Upstream modes (exactly one required):
  Local:  pass the upstream command after '--'. The proxy spawns it as a subprocess.
  Remote: pass --upstream-url pointing at a running MCP HTTP server. No subprocess.

Flags:
`)
		fs.PrintDefaults()
	}

	transport := fs.String("transport", "stdio", `Transport type: "stdio" (default) or "http".`)
	port := fs.Int("port", 3000, "Port to listen on (HTTP transport only).")
	bind := fs.String("bind", "127.0.0.1", "Address to bind to (HTTP transport only).")
	unsafeBindAll := fs.Bool("unsafe-bind-all", false, "Allow binding to all interfaces (HTTP transport only).")
	policyFiles := stringSliceFlag(fs, "policy", "Path to a capability manifest YAML/JSON file (repeatable).")
	auditLog := fs.String("audit-log", "", "Path to the OCSF audit JSONL file (default: ~/.eunox/audit.jsonl).")
	auditRotateSize := fs.Int64("audit-rotate-size", 0, "Rotate the audit log when it reaches this size in bytes (default: 100 MiB).")
	sessionID := fs.String("session-id", "", "Session ID to use (default: random UUID).")
	shutdownTimeout := fs.Int("shutdown-timeout", 5000, "Milliseconds to wait for graceful upstream shutdown before SIGKILL.")
	upstreamTimeout := fs.Int("upstream-timeout", 0, "Milliseconds to wait for the upstream to respond (0 = no timeout).")
	authToken := fs.String("auth-token", "", "Bearer token required on incoming requests (HTTP transport only).")
	trustFwdFor := fs.Bool("trust-forwarded-for", false, "Trust X-Forwarded-For header for source IP (HTTP + loopback bind only).")
	serverProfile := fs.String("server", "", fmt.Sprintf("Built-in server profile for semantic action resolution (e.g. github, slack, filesystem).\nAvailable: %s", strings.Join(ListBuiltinProfiles(), ", ")))
	actionMapFile := fs.String("action-map", "", "Path to a YAML/JSON file mapping tool names to action categories (read/write/delete/execute/admin).\nTakes priority over --server when both are supplied.")

	// Remote upstream flags (HTTP transport only).
	upstreamURL := fs.String("upstream-url", "", "Base URL of a remote MCP HTTP server (e.g. https://mcp.stripe.com).\nWhen set, the proxy forwards requests to this server instead of spawning a subprocess.\nRequires --transport http. Mutually exclusive with '-- <command>'.")
	upstreamAuthHeader := fs.String("upstream-auth-header", "", `Header forwarded to the remote upstream on every request, in "Name: Value" format.\nExample: --upstream-auth-header "Authorization: Bearer sk-..."`)
	upstreamTLSSkipVerify := fs.Bool("upstream-tls-skip-verify", false, "Skip TLS certificate verification for the remote upstream (development only).")

	// JWT PDP flags (HTTP transport only).
	jwksURI := fs.String("jwks-uri", "", "JWKS endpoint URI for IdP-issued capability JWTs (e.g. https://idp.example.com/.well-known/jwks.json).\nWhen set, every request must carry a valid Bearer JWT with eunox capability claims.\nRequires --transport http.")
	jwtIssuer := fs.String("jwt-issuer", "", "Expected issuer (iss) claim in incoming JWTs. Leave empty to skip issuer validation.")
	jwtAudience := fs.String("jwt-audience", "", "Expected audience (aud) claim in incoming JWTs. Leave empty to skip audience validation.")

	// Dry-run flag.
	dryRun := fs.Bool("dry-run", false, "Evaluate policies but do not block tool calls.\nDenials are logged to the audit trail with dry_run=true but the request is forwarded.\nUse for observation mode before production enforcement.")

	// Find the optional '--' separator between proxy flags and the upstream command.
	allArgs := os.Args[2:]
	ddIdx := -1
	for i, a := range allArgs {
		if a == "--" {
			ddIdx = i
			break
		}
	}

	var flagArgs, upstreamAll []string
	if ddIdx >= 0 {
		flagArgs = allArgs[:ddIdx]
		upstreamAll = allArgs[ddIdx+1:]
	} else {
		flagArgs = allArgs
	}

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(1)
	}

	// Determine upstream mode and validate flags.
	hasRemoteURL := *upstreamURL != ""
	hasLocalCmd := len(upstreamAll) > 0

	switch {
	case hasRemoteURL && hasLocalCmd:
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: --upstream-url and '-- <command>' are mutually exclusive\n")
		os.Exit(1)
	case !hasRemoteURL && !hasLocalCmd:
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: upstream is required: either --upstream-url or '-- <command>'\n\nUsage: eunox-mcp proxy [flags] -- <command> [args...]\n       eunox-mcp proxy --transport http --upstream-url <url> [flags]\n")
		os.Exit(1)
	case hasRemoteURL && *transport != "http":
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: --upstream-url requires --transport http\n")
		os.Exit(1)
	case hasLocalCmd && len(upstreamAll) == 0:
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: no upstream command after '--'\n")
		os.Exit(1)
	case *jwksURI != "" && *transport != "http":
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: --jwks-uri requires --transport http\n")
		os.Exit(1)
	}

	var upstreamCmd string
	var upstreamArgs []string
	if hasLocalCmd {
		upstreamCmd = upstreamAll[0]
		upstreamArgs = upstreamAll[1:]
	}

	// Validate transport.
	if *transport != "stdio" && *transport != "http" {
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: --transport must be 'stdio' or 'http', got %q\n", *transport)
		os.Exit(1)
	}

	// Validate HTTP bind address.
	if *transport == "http" {
		unsafeAddrs := map[string]bool{"0.0.0.0": true, "::": true}
		if unsafeAddrs[*bind] && !*unsafeBindAll {
			fmt.Fprintf(os.Stderr, "eunox-mcp proxy: binding to %q exposes the proxy to all network interfaces.\nPass --unsafe-bind-all to proceed.\n", *bind)
			os.Exit(1)
		}
		if unsafeAddrs[*bind] && *unsafeBindAll {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] WARNING: proxy is bound to all interfaces (%s). Ensure appropriate network controls are in place.\n", *bind)
		}
	}

	// Validate port.
	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "eunox-mcp proxy: --port must be in [1, 65535], got %d\n", *port)
		os.Exit(1)
	}

	// Load manifest(s).
	var pdp PolicyDecisionPoint
	if len(*policyFiles) > 0 {
		manifests := make([]*LocalManifest, 0, len(*policyFiles))
		for _, p := range *policyFiles {
			m, err := LoadManifest(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "eunox-mcp proxy: %v\n", err)
				os.Exit(1)
			}
			manifests = append(manifests, m)
		}
		merged := MergeManifests(manifests)

		// Resolve the server profile: CLI flag > manifest.Server field.
		effectiveServer := *serverProfile
		if effectiveServer == "" {
			effectiveServer = merged.Server
		}

		resolver, err := BuildResolver(effectiveServer, *actionMapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox-mcp proxy: %v\n", err)
			os.Exit(1)
		}

		counter := callcounter.NewInMemory()
		engine := enforcement.New(enforcement.WithCallCounter(counter))
		ks := killswitch.NewInMemory()
		pdp = NewManifestPDP(merged, engine, ks).WithResolver(resolver)
	}

	// Open audit sink.
	var sink *auditSink
	if *auditLog != "" || true { // always open audit sink (uses default path if empty)
		var err error
		sink, err = openAuditSink(*auditLog, *auditRotateSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] Warning: could not open audit log: %v\n", err)
			sink = nil
		}
	}
	if sink != nil {
		defer func() { _ = sink.Close() }()
	}

	// Resolve session ID.
	sid := *sessionID
	if sid == "" {
		sid = uuid.New().String()
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] DRY-RUN MODE: policies are evaluated but not enforced\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	switch *transport {
	case "stdio":
		proxy := NewStdioProxy(StdioProxyOptions{
			Command:        upstreamCmd,
			Args:           upstreamArgs,
			PDP:            pdp,
			Sink:           sink,
			SessionID:      sid,
			ShutdownMs:     *shutdownTimeout,
			UpstreamTimeMs: *upstreamTimeout,
			DryRun:         *dryRun,
		})
		if err := proxy.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] Fatal: %v\n", err)
			os.Exit(1) //nolint:gocritic // exitAfterDefer: deferred sink.Close is not critical on fatal error
		}

	case "http":
		if *trustFwdFor {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] WARNING: --trust-forwarded-for is enabled; only use when a trusted reverse proxy sets X-Forwarded-For.\n")
		}
		if *upstreamTLSSkipVerify {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] WARNING: --upstream-tls-skip-verify is enabled. TLS certificate verification is DISABLED. Do NOT use in production.\n")
		}

		// Build the JWT PDP when --jwks-uri is configured.
		var jwtPDP *JWTPDP
		if *jwksURI != "" {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] JWT PDP enabled (JWKS URI: %s)\n", *jwksURI)
			jwtPDP = NewJWTPDP(JWTPDPOptions{
				JWKSURI:  *jwksURI,
				Issuer:   *jwtIssuer,
				Audience: *jwtAudience,
				Inner:    pdp, // nil when no --policy; intersection with manifest when both are set
			})
		}

		var ks killswitch.Manager
		if mp, ok := pdp.(*ManifestPDP); ok {
			ks = mp.ks
		} else {
			ks = killswitch.NewInMemory()
		}

		// When --jwks-uri is set, the JWTPDP is the primary PDP; the manifest
		// PDP (if any) becomes its inner (intersection) PDP.  When --jwks-uri is
		// not set, the manifest PDP (or alwaysAllow) is used directly.
		effectivePDP := pdp
		if jwtPDP != nil {
			effectivePDP = jwtPDP
		}

		proxy := NewHTTPProxy(HTTPProxyOptions{
			Command:               upstreamCmd,
			Args:                  upstreamArgs,
			PDP:                   effectivePDP,
			JWTPDP:                jwtPDP,
			Sink:                  sink,
			KS:                    ks,
			ShutdownMs:            *shutdownTimeout,
			UpstreamTimeMs:        *upstreamTimeout,
			AuthToken:             *authToken,
			TrustFwdFor:           *trustFwdFor,
			Port:                  *port,
			Bind:                  *bind,
			UpstreamURL:           *upstreamURL,
			UpstreamAuthHeader:    *upstreamAuthHeader,
			UpstreamTLSSkipVerify: *upstreamTLSSkipVerify,
			DryRun:                *dryRun,
		})
		if err := proxy.Serve(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[eunox-mcp] Fatal: %v\n", err)
			os.Exit(1)
		}
	}
}

// -----------------------------------------------------------------
// validate subcommand
// -----------------------------------------------------------------

func cmdValidate() {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: eunox-mcp validate <manifest.yaml> [...]\n\nValidate manifest file(s) and exit 0 on success.\n")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "eunox-mcp validate: at least one manifest file is required\n")
		os.Exit(1)
	}

	ok := true
	for _, f := range files {
		m, err := LoadManifest(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", f, err)
			ok = false
		} else {
			fmt.Printf("OK    %s  (name=%q version=%q capabilities=%d)\n", f, m.Name, m.Version, len(m.Capabilities))
		}
	}
	if !ok {
		os.Exit(1)
	}
}

// -----------------------------------------------------------------
// kill subcommand
// -----------------------------------------------------------------

func cmdKill() {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox-mcp kill [flags] <session-id|all>

Send a kill-switch signal to a running eunox-mcp HTTP proxy.

Flags:
`)
		fs.PrintDefaults()
	}
	port := fs.Int("port", 3000, "Port the HTTP proxy is listening on.")
	host := fs.String("host", "127.0.0.1", "Host the HTTP proxy is bound to.")

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "eunox-mcp kill: expected exactly one argument: <session-id|all>\n")
		os.Exit(1)
	}
	target := fs.Arg(0)

	var body map[string]interface{}
	if target == "all" {
		body = map[string]interface{}{"all": true}
	} else {
		body = map[string]interface{}{"sessionId": target}
	}

	data, _ := json.Marshal(body)
	url := fmt.Sprintf("http://%s:%d/control/kill", *host, *port)
	resp, err := http.Post(url, ctJSON, bytes.NewReader(data)) //nolint:noctx,gosec // G107: URL constructed from user-specified --host/--port flags
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp kill: request failed: %v\n", err)
		os.Exit(1)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "eunox-mcp kill: proxy returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		os.Exit(1)
	}
	fmt.Println(string(respBody))
}

// -----------------------------------------------------------------
// validate-token subcommand
// -----------------------------------------------------------------

func cmdValidateToken() {
	fs := flag.NewFlagSet("validate-token", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox-mcp validate-token [flags]

Verify HMAC-SHA256 signatures in the local audit log.

Flags:
`)
		fs.PrintDefaults()
	}
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	requestID := fs.String("request-id", "", "Verify only the record with this request ID.")
	since := fs.String("since", "", "Verify only records after this RFC3339 timestamp.")

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	logPath := *auditLogPath
	if logPath == "" {
		logPath = defaultAuditLog
	}
	logPath = expandHome(logPath)

	keyPath := expandHome(defaultAuditKeyPath)
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp validate-token: loading audit key: %v\n", err)
		os.Exit(1)
	}

	// Build a temporary sink just for VerifyRecord.
	verifier := &auditSink{key: key}

	f, err := os.Open(logPath) //nolint:gosec // G304: path is user-configured audit log location
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp validate-token: opening %q: %v\n", logPath, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	var sinceTime time.Time
	if *since != "" {
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox-mcp validate-token: invalid --since value %q: %v\n", *since, err)
			os.Exit(1)
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4<<20), 4<<20)
	total, valid, invalid, skipped := 0, 0, 0, 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		total++

		// Apply filters.
		if *requestID != "" || !sinceTime.IsZero() {
			var rec map[string]interface{}
			if err := json.Unmarshal(line, &rec); err != nil {
				skipped++
				continue
			}
			if *requestID != "" {
				if rid, _ := rec["request_id"].(string); rid != *requestID {
					skipped++
					continue
				}
			}
			if !sinceTime.IsZero() {
				ts, _ := rec["time"].(string)
				t, err := time.Parse(time.RFC3339Nano, ts)
				if err != nil || !t.After(sinceTime) {
					skipped++
					continue
				}
			}
		}

		ok, err := verifier.VerifyRecord(line)
		if err != nil {
			fmt.Printf("ERROR  line %d: %v\n", total, err)
			invalid++
			continue
		}
		if ok {
			valid++
		} else {
			var rec map[string]interface{}
			_ = json.Unmarshal(line, &rec)
			fmt.Printf("INVALID  request_id=%v session_id=%v tool=%v\n",
				rec["request_id"], rec["session_id"], rec["tool_name"])
			invalid++
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp validate-token: reading log: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Checked %d record(s): %d valid, %d invalid, %d skipped.\n", total, valid, invalid, skipped)
	if invalid > 0 {
		os.Exit(1)
	}
}

// -----------------------------------------------------------------
// stats subcommand
// -----------------------------------------------------------------

func cmdStats() {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox-mcp stats [flags]

Print a denial count histogram from the local audit log.

Flags:
`)
		fs.PrintDefaults()
	}
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	logPath := *auditLogPath
	if logPath == "" {
		logPath = defaultAuditLog
	}
	logPath = expandHome(logPath)

	f, err := os.Open(logPath) //nolint:gosec // G304: path is user-configured audit log location
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp stats: opening %q: %v\n", logPath, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	type key struct{ tool, code string }
	denials := make(map[key]int)
	allowed, denied, total := 0, 0, 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4<<20), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		total++
		var rec struct {
			Decision   string `json:"decision"`
			ToolName   string `json:"tool_name"`
			DenialCode string `json:"denial_code"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		switch rec.Decision {
		case "allow":
			allowed++
		case "deny":
			denied++
			k := key{tool: rec.ToolName, code: rec.DenialCode}
			denials[k]++
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp stats: reading log: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Total records: %d  (allowed: %d, denied: %d)\n\n", total, allowed, denied)
	if len(denials) == 0 {
		fmt.Println("No denials recorded.")
		return
	}

	// Sort for deterministic output.
	type row struct {
		tool, code string
		count      int
	}
	rows := make([]row, 0, len(denials))
	for k, n := range denials {
		rows = append(rows, row{tool: k.tool, code: k.code, count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		if rows[i].tool != rows[j].tool {
			return rows[i].tool < rows[j].tool
		}
		return rows[i].code < rows[j].code
	})

	fmt.Printf("%-30s  %-30s  %s\n", "TOOL", "CODE", "COUNT")
	fmt.Println(strings.Repeat("-", 72))
	for _, r := range rows {
		fmt.Printf("%-30s  %-30s  %d\n", r.tool, r.code, r.count)
	}
}

// -----------------------------------------------------------------
// profiles subcommand
// -----------------------------------------------------------------

// cmdProfiles lists the built-in server profiles or prints the tool map for
// one profile.
//
// Usage:
//
//	eunox-mcp profiles           # list all profiles
//	eunox-mcp profiles github    # show tool→action map for "github"
func cmdProfiles() {
	args := os.Args[2:]
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(os.Stderr, `Usage:
  eunox-mcp profiles           List all built-in server profiles
  eunox-mcp profiles <name>    Show the tool-to-action map for a profile
`)
		return
	}

	if len(args) == 0 {
		// List all profiles.
		names := ListBuiltinProfiles()
		maxLen := 0
		for _, n := range names {
			if len(n) > maxLen {
				maxLen = len(n)
			}
		}
		fmt.Printf("%-*s  %s\n", maxLen, "PROFILE", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", maxLen+2+60))
		for _, n := range names {
			desc := BuiltinProfileDescription(n)
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}
			fmt.Printf("%-*s  %s\n", maxLen, n, desc)
		}
		return
	}

	// Show tool map for the named profile.
	name := args[0]
	r := BuiltinResolver(name)
	if r == nil {
		fmt.Fprintf(os.Stderr, "eunox-mcp profiles: unknown profile %q\nAvailable: %s\n",
			name, strings.Join(ListBuiltinProfiles(), ", "))
		os.Exit(1)
	}
	sr, ok := r.(*StaticActionResolver)
	if !ok {
		fmt.Fprintf(os.Stderr, "eunox-mcp profiles: profile %q is not a static resolver\n", name)
		os.Exit(1)
	}

	type entry struct {
		tool string
		cat  ActionCategory
	}
	entries := make([]entry, 0, len(sr.toolMap))
	for tool, cat := range sr.toolMap {
		entries = append(entries, entry{tool, cat})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].tool < entries[j].tool })

	maxTool := 0
	for _, e := range entries {
		if len(e.tool) > maxTool {
			maxTool = len(e.tool)
		}
	}
	fmt.Printf("Profile: %s\n", name)
	if desc := BuiltinProfileDescription(name); desc != "" {
		fmt.Printf("         %s\n", desc)
	}
	fmt.Println()
	fmt.Printf("%-*s  %s\n", maxTool, "TOOL", "ACTION")
	fmt.Println(strings.Repeat("-", maxTool+2+10))
	for _, e := range entries {
		fmt.Printf("%-*s  %s\n", maxTool, e.tool, e.cat)
	}
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

// stringSliceFlag registers a repeatable string flag on fs and returns a
// pointer to the accumulated slice.
func stringSliceFlag(fs *flag.FlagSet, name, usage string) *[]string {
	var vals []string
	fs.Func(name, usage, func(v string) error {
		vals = append(vals, v)
		return nil
	})
	return &vals
}

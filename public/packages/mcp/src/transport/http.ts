/**
 * Streamable HTTP proxy transport for @euno/mcp.
 *
 * Architecture
 * ────────────
 *   MCP client  ──HTTP──►  HttpProxy  (one StreamableHTTPServerTransport per session)
 *                                │
 *                        StdioClientTransport  (one per session)
 *                                │
 *                       upstream MCP server process  (one per session)
 *
 * Session model
 * ─────────────
 *   One HTTP `initialize` → `shutdown` cycle = one session.  The proxy mints a
 *   random UUID as the session id and returns it in the `Mcp-Session-Id`
 *   response header, following the MCP streamable-HTTP spec.
 *
 *   Each session has its own upstream child process and its own
 *   {@link StreamableHTTPServerTransport} instance.  Counter keys
 *   (`<sessionId>|<toolName>|<resource>`) include the session id so concurrent
 *   sessions are fully isolated — mirroring the production
 *   `IssuanceRateLimitSubject` shape for a mechanical Stage 3 swap-in.
 *
 * Security
 * ────────
 *   Binds to `127.0.0.1` by default.  Binding to `0.0.0.0` (or `::`) is
 *   rejected unless {@link HttpProxyOptions.unsafeBindAll} is explicitly set to
 *   `true`, in which case a one-line warning is emitted to stderr at startup.
 *
 * @module
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  CompatibilityCallToolResultSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ResultSchema,
  type ClientNotification,
  type Notification,
  type ServerNotification,
} from '@modelcontextprotocol/sdk/types.js';
import {
  hasRedactObligation,
} from '@euno/common-core';
import { AlwaysAllowPDP, type PolicyDecisionPoint } from '../pdp';
import {
  MCP_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
} from '../protocol';
import type { TelemetryHooks } from '../telemetry/types';
import { NullAuditSink, type McpAuditSink } from '../audit/audit-sink';
import { applyRedactObligations, applyRemoteObligations, type ToolCallResult } from './obligations';
import { UpstreamTimeoutError, withTimeout } from './timeout';

/** Proxy name/version sent to the upstream during the MCP initialize handshake. */
const PROXY_NAME = 'euno-mcp-proxy';
const PROXY_VERSION = '1.0.0';

/**
 * All-interfaces addresses that are disallowed unless
 * {@link HttpProxyOptions.unsafeBindAll} is set.
 */
const UNSAFE_BIND_ADDRESSES = new Set(['0.0.0.0', '::']);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Minimal interface for activating the kill switch from an external command.
 *
 * Implemented by {@link ConditionEnforcerPDP} — pass a `ConditionEnforcerPDP`
 * instance here when you want the {@link HttpProxy} to expose the
 * `POST /control/kill` endpoint.
 */
export interface KillController {
  /** Deny all subsequent `tools/call` requests for the given session. */
  killSession(sessionId: string): void;
  /** Deny all subsequent `tools/call` requests across every session. */
  killAll(): void;
}

/**
 * Options for {@link HttpProxy}.
 */
export interface HttpProxyOptions {
  /**
   * The upstream command to spawn for each new session.  Forwarded verbatim to
   * `child_process.spawn`.
   */
  command: string;
  /** Arguments to pass to the upstream command. */
  args?: string[];
  /**
   * Additional environment variables merged on top of the current process
   * environment when spawning each upstream.
   */
  env?: Record<string, string>;
  /** Working directory for each upstream process. */
  cwd?: string;
  /**
   * PolicyDecisionPoint used to evaluate `tools/call` requests.
   * Defaults to {@link AlwaysAllowPDP} when not supplied.
   */
  pdp?: PolicyDecisionPoint;
  /**
   * Optional kill controller that enables the `POST /control/kill` endpoint.
   *
   * When provided, the proxy exposes:
   *   `POST /control/kill`  — body `{ sessionId: "<id>" }` or `{ all: true }`
   *
   * Use `euno-mcp kill <sessionId|all> --port <n>` to invoke it.
   * Primarily a testing helper; the kill state is in-memory only.
   */
  killController?: KillController;
  /**
   * TCP port to listen on.  `0` picks an ephemeral port — useful for tests.
   * @default 3000
   */
  port?: number;
  /**
   * Address to bind to.
   * Defaults to `'127.0.0.1'` (loopback only).
   *
   * Binding to `0.0.0.0` or `::` is rejected unless
   * {@link HttpProxyOptions.unsafeBindAll} is `true`.
   */
  bind?: string;
  /**
   * Allow binding to all interfaces (`0.0.0.0` / `::`).
   *
   * When `true` and the bind address is an all-interfaces address, a warning is
   * emitted to stderr at startup but the server proceeds.
   *
   * @default false
   */
  unsafeBindAll?: boolean;
  /**
   * Time in milliseconds to wait for each upstream to exit gracefully after
   * forwarding SIGTERM before sending SIGKILL.
   *
   * @default 5000
   */
  shutdownTimeoutMs?: number;
  /**
   * Optional telemetry hooks for recording session lifecycle events and
   * tool-call enforcement decisions.  No-op when not supplied.
   */
  telemetryHooks?: TelemetryHooks;
  /**
   * When `true` and the proxy is bound to a loopback address (`127.0.0.1` or
   * `::1`), the `X-Forwarded-For` header is trusted and its first value is
   * used as the source IP passed to the PDP for `ipRange` enforcement.  When
   * the first `X-Forwarded-For` value is absent the source IP falls back to
   * `req.socket.remoteAddress`.
   *
   * When `false` (the default) or when the proxy is **not** bound to loopback,
   * the source IP is always taken from `req.socket.remoteAddress` and
   * `X-Forwarded-For` is ignored.  A startup warning is emitted to stderr if
   * the flag is `true` but the bind address is not loopback, to alert operators
   * that the flag has no effect in that configuration.
   * This protects against IP spoofing when the
   * proxy is directly reachable from the network.
   *
   * Enable this flag only when a trusted reverse proxy (e.g. nginx or a cloud
   * load balancer) sits in front of the euno-mcp proxy on the same host and
   * forwards the real client IP in `X-Forwarded-For`.  A warning is emitted to
   * stderr at startup when this flag is set.
   *
   * @default false
   */
  trustForwardedFor?: boolean;
  /**
   * Audit sink that receives one record per `tools/call` enforcement decision.
   *
   * Defaults to {@link NullAuditSink} (no-op) when not supplied.  Pass a
   * {@link LocalAuditSink} to write OCSF+HMAC-signed records to disk.
   *
   * The sink's `close()` method is called when the proxy shuts down via
   * {@link HttpProxy.close}.
   */
  auditSink?: McpAuditSink;
  /**
   * Maximum time in milliseconds to wait for the upstream to respond to a
   * `tools/call` request before the proxy returns a structured timeout error
   * to the MCP host.  The upstream call is abandoned (though the upstream
   * process itself is not killed — use {@link shutdownTimeoutMs} for that).
   *
   * When `undefined` (the default) no timeout is applied and the proxy waits
   * indefinitely.  Pass a positive integer to bound the wait.
   *
   * @default undefined (no timeout)
   */
  upstreamTimeoutMs?: number;
  /**
   * When set, every `POST /mcp` and `GET /mcp` request must carry an
   * `Authorization: Bearer <token>` header whose value matches this string
   * exactly.  Requests that are missing the header or carry the wrong token
   * receive `401 Unauthorized`.
   *
   * Use this when binding to `127.0.0.1` (loopback) to prevent other
   * processes on the same machine from making unauthenticated calls to the
   * proxy endpoint.
   *
   * Pass via `--auth-token <token>` on the CLI.  The token is never logged.
   *
   * @default undefined (no token required)
   */
  authToken?: string;
}

// ---------------------------------------------------------------------------
// Internal session state
// ---------------------------------------------------------------------------

interface HttpProxySession {
  readonly serverTransport: StreamableHTTPServerTransport;
  readonly server: Server;
  readonly upstreamClient: Client;
  readonly upstreamTransport: StdioClientTransport;
}

// ---------------------------------------------------------------------------
// Helpers (shared with StdioProxy)
// ---------------------------------------------------------------------------

/**
 * Builds an MCP tool-call result payload with `isError: true` carrying a
 * structured `CapabilityDenied` payload in its text content.
 *
 * When `details` is provided (e.g. for `argumentSchema` denials), it is
 * included in the JSON payload under the `details` key so MCP clients can
 * react programmatically without parsing the human-readable `message` string.
 */
function buildDenialResult(
  toolName: string,
  reason: string | undefined,
  denialCode: string | undefined,
  details?: Record<string, unknown>,
) {
  const message = reason ?? 'Tool call denied by euno policy';
  const payload: Record<string, unknown> = {
    error: 'CapabilityDenied',
    tool: toolName,
    code: denialCode ?? 'CAPABILITY_DENIED',
    message,
  };
  if (details !== undefined) {
    payload['details'] = details;
  }
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(payload),
      },
    ],
    isError: true,
  };
}

// ---------------------------------------------------------------------------
// HttpProxy
// ---------------------------------------------------------------------------

/**
 * An HTTP MCP proxy.
 *
 * Instantiate and call {@link start} to begin listening.  Each incoming
 * `initialize` request spawns a new upstream child process and creates an
 * isolated MCP session.  Subsequent requests carrying the session id returned
 * in the `Mcp-Session-Id` header are routed to the corresponding session.
 *
 * @example
 * ```ts
 * const proxy = new HttpProxy({
 *   command: 'node',
 *   args: ['/path/to/upstream-mcp-server.js'],
 *   port: 0, // ephemeral port — useful for tests
 * });
 * const port = await proxy.start();
 * console.log(`Listening on http://127.0.0.1:${port}/mcp`);
 * ```
 */
export class HttpProxy {
  private readonly _opts: Required<Omit<HttpProxyOptions, 'env' | 'cwd' | 'killController' | 'telemetryHooks' | 'upstreamTimeoutMs' | 'authToken'>> &
    Pick<HttpProxyOptions, 'env' | 'cwd' | 'killController' | 'telemetryHooks' | 'upstreamTimeoutMs' | 'authToken'>;

  private _httpServer?: http.Server;
  private _sessions = new Map<string, HttpProxySession>();
  private _pendingSessions = new Set<HttpProxySession>();
  private _started = false;
  private _port?: number;
  /**
   * Carries the source IP of the active HTTP request into the
   * `CallToolRequestSchema` handler without shared mutable state.  Each call
   * to `serverTransport.handleRequest` is wrapped in `_sourceIpStorage.run()`
   * so concurrent requests for the same session each see their own IP.
   */
  private readonly _sourceIpStorage = new AsyncLocalStorage<string | undefined>();

  constructor(opts: HttpProxyOptions) {
    if (opts.authToken !== undefined && opts.authToken.trim().length === 0) {
      throw new Error(
        'HttpProxy: authToken must not be an empty or whitespace-only string. ' +
          'Pass a non-empty token or omit the option to disable auth.',
      );
    }
    this._opts = {
      command: opts.command,
      args: opts.args ?? [],
      env: opts.env,
      cwd: opts.cwd,
      pdp: opts.pdp ?? new AlwaysAllowPDP(),
      auditSink: opts.auditSink ?? new NullAuditSink(),
      killController: opts.killController,
      port: opts.port ?? 3000,
      bind: opts.bind ?? '127.0.0.1',
      unsafeBindAll: opts.unsafeBindAll ?? false,
      shutdownTimeoutMs: opts.shutdownTimeoutMs ?? 5_000,
      telemetryHooks: opts.telemetryHooks,
      trustForwardedFor: opts.trustForwardedFor ?? false,
      upstreamTimeoutMs: opts.upstreamTimeoutMs,
      authToken: opts.authToken,
    };
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Starts the HTTP server.
   *
   * @returns The port the server is listening on (useful when `port: 0`).
   * @throws If `bind` is an all-interfaces address and `unsafeBindAll` is
   *   `false`.
   */
  async start(): Promise<number> {
    if (this._started) {
      throw new Error('HttpProxy.start() called more than once');
    }
    this._started = true;

    const { bind, unsafeBindAll } = this._opts;

    if (UNSAFE_BIND_ADDRESSES.has(bind) && !unsafeBindAll) {
      this._started = false;
      throw new Error(
        `[euno-mcp] Refusing to bind to ${bind}: binding to all interfaces exposes the proxy ` +
          `to the network. Pass --unsafe-bind-all (or set unsafeBindAll: true) to override ` +
          `and acknowledge the security implications.`,
      );
    }

    if (UNSAFE_BIND_ADDRESSES.has(bind) && unsafeBindAll) {
      process.stderr.write(
        `[euno-mcp] WARNING: HTTP proxy is binding to ${bind} (all interfaces). ` +
          `This is potentially unsafe — only do this in controlled environments.\n`,
      );
    }

    const { trustForwardedFor } = this._opts;
    const isLoopbackBind = bind === '127.0.0.1' || bind === '::1';
    if (trustForwardedFor) {
      if (!isLoopbackBind) {
        process.stderr.write(
          `[euno-mcp] WARNING: --trust-forwarded-for is set but the proxy is not bound to ` +
            `loopback (bind=${bind}). X-Forwarded-For will NOT be trusted — ` +
            `trusting XFF on a non-loopback bind address is a security risk.\n`,
        );
      } else {
        process.stderr.write(
          `[euno-mcp] INFO: --trust-forwarded-for is set. X-Forwarded-For headers will be ` +
            `trusted for ipRange enforcement (loopback bind only).\n`,
        );
      }
    }

    return new Promise<number>((resolve, reject) => {
      const server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch((err: unknown) => {
          process.stderr.write(
            `[euno-mcp] Unhandled error in HTTP request handler: ${String(err)}\n`,
          );
          if (!res.headersSent) {
            res.writeHead(500);
          }
          res.end();
        });
      });

      this._httpServer = server;

      server.once('error', (err) => {
        this._started = false;
        reject(err);
      });

      server.listen(this._opts.port, bind, () => {
        const addr = server.address();
        const port = addr !== null && typeof addr === 'object' ? addr.port : /* istanbul ignore next */ 0;
        this._port = port;
        process.stderr.write(
          `[euno-mcp] HTTP proxy listening on http://${bind}:${port}/mcp ` +
            `(primary protocol: ${MCP_PROTOCOL_VERSION}, ` +
            `accepted: ${MCP_SUPPORTED_PROTOCOL_VERSIONS.join(', ')})\n`,
        );
        resolve(port);
      });
    });
  }

  /**
   * Closes all sessions and the HTTP server.  Safe to call multiple times.
   */
  async close(): Promise<void> {
    // Close all active sessions.
    const closures = Array.from(
      new Set([...this._sessions.values(), ...this._pendingSessions.values()]),
    ).map((s) =>
      this._closeSession(s),
    );
    await Promise.allSettled(closures);
    this._sessions.clear();
    this._pendingSessions.clear();

    if (this._httpServer) {
      await new Promise<void>((resolve) => {
        this._httpServer!.close(() => resolve());
      });
    }

    // Flush and close the audit sink after all sessions have been torn down so
    // the sink receives every record before it is closed.
    await this._opts.auditSink.close();
    this._opts.pdp.dispose?.();
  }

  /**
   * The port the server is bound to after {@link start} has resolved.
   * `undefined` before `start()` is called.
   */
  get port(): number | undefined {
    return this._port;
  }

  // ── Request routing ───────────────────────────────────────────────────────

  /**
   * Dispatches an incoming HTTP request to the appropriate session transport or
   * creates a new session for `initialize` requests.
   *
   * All MCP traffic is routed to `POST|GET|DELETE /mcp`.  Other paths receive
   * 404 Not Found.
   */
  private async _handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

    // ── Control endpoint ──────────────────────────────────────────────────
    if (url.pathname === '/control/kill') {
      await this._handleControlKill(req, res);
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }

    // ── Bearer token authentication ────────────────────────────────────────
    // When authToken is configured, every /mcp request must present it in the
    // Authorization header.  Constant-time comparison prevents timing attacks.
    if (this._opts.authToken !== undefined) {
      const authHeader = req.headers['authorization'] ?? '';
      const prefix = 'Bearer ';
      const provided = authHeader.startsWith(prefix)
        ? authHeader.slice(prefix.length)
        : '';
      const expected = this._opts.authToken;
      const providedBuf = Buffer.from(provided);
      const expectedBuf = Buffer.from(expected);
      // timingSafeEqual requires equal-length buffers; when lengths differ the
      // token is definitely invalid — skip the comparison and reject immediately.
      const tokenValid =
        providedBuf.length === expectedBuf.length &&
        crypto.timingSafeEqual(providedBuf, expectedBuf);
      if (!tokenValid) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="euno-mcp"' });
        res.end(JSON.stringify({ error: 'Unauthorized: valid Bearer token required' }));
        return;
      }
    }

    const sessionId = Array.isArray(req.headers['mcp-session-id'])
      ? req.headers['mcp-session-id'][0]
      : req.headers['mcp-session-id'];

    if (sessionId !== undefined) {
      // Route to an existing session.
      const session = this._sessions.get(sessionId);
      if (!session) {
        res.writeHead(404);
        res.end(
          JSON.stringify({ error: 'Session not found', sessionId }),
        );
        return;
      }
      // Wrap handleRequest in AsyncLocalStorage so the CallToolRequestSchema
      // handler sees this request's source IP regardless of concurrency.
      const sourceIp = this._extractSourceIp(req);
      await this._sourceIpStorage.run(sourceIp, () =>
        session.serverTransport.handleRequest(req, res),
      );
      return;
    }

    // No session id — validate that this is a well-formed initialize POST before
    // spawning an upstream process.  Accepting any request here (e.g. GET/DELETE
    // without a session id, or a POST with a non-JSON body) would let a malicious
    // or buggy client exhaust upstream process resources at zero cost.
    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' });
      res.end(JSON.stringify({ error: 'Method Not Allowed: session initialization requires POST' }));
      return;
    }

    const contentType = req.headers['content-type'] ?? '';
    if (!contentType.includes('application/json')) {
      res.writeHead(415);
      res.end(JSON.stringify({ error: 'Unsupported Media Type: expected application/json' }));
      return;
    }

    // All checks passed — create a new session for this initialize request.
    await this._createSession(req, res);
  }

  // ── Session lifecycle ─────────────────────────────────────────────────────

  /**
   * Creates a new session: connects to the upstream and wires the proxy
   * handlers, then routes the current (initialize) request to the new
   * session's transport.
   */
  private async _createSession(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    // ── 1. Connect to the upstream ─────────────────────────────────────────
    // Merge caller-supplied extra env on top of the current process environment
    // so that PATH, HOME, and other inherited variables remain available to the
    // upstream process.  Undefined values from process.env are stripped so that
    // the resulting object satisfies StdioClientTransport's Record<string,string>.
    const mergedEnv: Record<string, string> | undefined =
      this._opts.env !== undefined
        ? (Object.fromEntries(
            Object.entries({ ...process.env, ...this._opts.env }).filter(
              (entry): entry is [string, string] => entry[1] !== undefined,
            ),
          ) as Record<string, string>)
        : undefined;

    const upstreamTransport = new StdioClientTransport({
      command: this._opts.command,
      args: this._opts.args,
      env: mergedEnv,
      cwd: this._opts.cwd,
      stderr: 'pipe',
    });

    const upstreamClient = new Client(
      { name: PROXY_NAME, version: PROXY_VERSION },
      { capabilities: {} },
    );

    // Forward upstream stderr to our own stderr immediately.
    const upstreamStderr = upstreamTransport.stderr;
    if (upstreamStderr) {
      upstreamStderr.on('data', (chunk: Buffer) => {
        process.stderr.write(chunk);
      });
    }

    await upstreamClient.connect(upstreamTransport);

    const upstreamCaps = upstreamClient.getServerCapabilities() ?? {};

    // ── 2. Build the proxy MCP server ──────────────────────────────────────
    const proxyServer = new Server(
      { name: PROXY_NAME, version: PROXY_VERSION },
      { capabilities: { ...upstreamCaps } },
    );

    // ── 3. Create the HTTP session transport ──────────────────────────────
    let registeredSessionId: string | undefined;

    // Create a fresh per-session hook set so that concurrent sessions do not
    // share state (e.g. hadEnforcement flags are independent per session).
    const sessionTelemetry =
      this._opts.telemetryHooks?.createSessionHooks?.() ??
      this._opts.telemetryHooks;

    const serverTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (sid) => {
        registeredSessionId = sid;
        this._pendingSessions.delete(session);
        this._sessions.set(sid, session);
        process.stderr.write(
          `[euno-mcp] HTTP session ${sid} initialized. ` +
            `Active sessions: ${this._sessions.size}.\n`,
        );
        // Notify telemetry that a new session has started.
        sessionTelemetry?.onSessionStart?.();
      },
      onsessionclosed: (sid) => {
        const session = this._sessions.get(sid);
        if (session !== undefined) {
          this._pendingSessions.delete(session);
        }
        this._sessions.delete(sid);
        process.stderr.write(
          `[euno-mcp] HTTP session ${sid} closed. ` +
            `Active sessions: ${this._sessions.size}.\n`,
        );
        // Notify telemetry that the session has ended.
        sessionTelemetry?.onSessionEnd?.();
        if (session !== undefined) {
          // Tear down the upstream process and both transports so the child
          // process doesn't linger after the HTTP client ends the session.
          this._closeSession(session).catch((err: unknown) => {
            process.stderr.write(
              `[euno-mcp] Error closing session ${sid}: ${String(err)}\n`,
            );
          });
        }
      },
    });
    const session: HttpProxySession = {
      serverTransport,
      server: proxyServer,
      upstreamClient,
      upstreamTransport,
    };
    this._pendingSessions.add(session);

    const pdp = this._opts.pdp;
    const shutdownTimeoutMs = this._opts.shutdownTimeoutMs;
    const upstreamTimeoutMs = this._opts.upstreamTimeoutMs;

    // ── 4. Wire passthrough handlers (same set as StdioProxy) ─────────────

    // After initialize: log the client version.
    proxyServer.oninitialized = () => {
      const clientVersion = proxyServer.getClientVersion();
      const clientLabel = clientVersion
        ? `${clientVersion.name}@${clientVersion.version}`
        : 'unknown client';
      process.stderr.write(
        `[euno-mcp] HTTP session ${registeredSessionId ?? '(pending)'} ` +
          `initialized with ${clientLabel}.\n`,
      );
    };

    proxyServer.setRequestHandler(ListToolsRequestSchema, async (reqMsg) => {
      return await upstreamClient.listTools(reqMsg.params);
    });

    if (upstreamCaps.resources !== undefined) {
      proxyServer.setRequestHandler(ListResourcesRequestSchema, async (reqMsg) => {
        return await upstreamClient.listResources(reqMsg.params);
      });
    }

    if (upstreamCaps.prompts !== undefined) {
      proxyServer.setRequestHandler(ListPromptsRequestSchema, async (reqMsg) => {
        return await upstreamClient.listPrompts(reqMsg.params);
      });
    }

    proxyServer.setRequestHandler(CallToolRequestSchema, async (reqMsg) => {
      const sessionId = registeredSessionId ?? 'pending';
      // Read the source IP from AsyncLocalStorage — populated by the
      // _handleRequest wrapper for this specific HTTP request, safe under
      // concurrency since each request has its own async context.
      const sourceIp = this._sourceIpStorage.getStore();
      const decision = await pdp.decide(reqMsg, { sessionId, sourceIp });

      // Notify telemetry hooks about this enforcement decision.
      sessionTelemetry?.onDecision?.(decision.allow, decision.conditionType);

      if (!decision.allow) {
        // Record the enforcement decision — fire-and-forget so audit I/O never
        // blocks the response to the MCP client.
        void this._opts.auditSink.record({
          sessionId,
          toolName: reqMsg.params.name,
          decision: 'deny',
          denialCode: decision.denialCode,
          conditionType: decision.conditionType,
          details: decision.details,
        });
        return buildDenialResult(
          reqMsg.params.name,
          decision.reason,
          decision.denialCode,
          decision.details,
        );
      }

      // Allowed — forward to upstream and apply any response-path obligations.
      // Race the upstream call against the configurable timeout so a slow or
      // unresponsive upstream doesn't hang the MCP host indefinitely.
      let upstreamResult: Awaited<ReturnType<typeof upstreamClient.callTool>>;
      try {
        upstreamResult = await withTimeout(
          upstreamClient.callTool(reqMsg.params, CompatibilityCallToolResultSchema),
          upstreamTimeoutMs,
          reqMsg.params.name,
        );
      } catch (err) {
        const isTimeout = err instanceof UpstreamTimeoutError;
        process.stderr.write(
          `[euno-mcp] ${isTimeout ? 'Upstream timeout' : 'Upstream error'} on tool "${reqMsg.params.name}": ${String(err)}\n`,
        );
        return buildDenialResult(
          reqMsg.params.name,
          isTimeout
            ? `Upstream did not respond within ${upstreamTimeoutMs} ms`
            : `Upstream error: ${String(err)}`,
          isTimeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR',
        );
      }

      const { matchedConditions, obligations } = decision;
      const appliedTypes = new Set<string>();
      let finalResult = upstreamResult;

      // Extract annotate key/values regardless of isError.
      let annotateValues: Record<string, string> | undefined;
      if (obligations) {
        for (const o of obligations) {
          if (o.type === 'annotate') {
            annotateValues ??= {};
            annotateValues[o.key] = o.value;
          }
        }
      }

      const isErrorResult = (upstreamResult as ToolCallResult).isError === true;
      if (!isErrorResult) {
        if (obligations && obligations.length > 0) {
          // Remote-enforcer mode: apply response-mutating obligations.
          finalResult = applyRemoteObligations(
            upstreamResult as ToolCallResult,
            obligations,
          ) as typeof upstreamResult;
          if (obligations.some((o) => o.type === 'redactFields')) {
            appliedTypes.add('redactFields');
          }
        } else if (matchedConditions && hasRedactObligation(matchedConditions)) {
          // Local mode: derive obligations from the matched capability conditions.
          finalResult = applyRedactObligations(
            upstreamResult as ToolCallResult,
            matchedConditions,
          ) as typeof upstreamResult;
          appliedTypes.add('redactFields');
        }
      }
      const obligationsApplied = appliedTypes.size > 0 ? Array.from(appliedTypes) : undefined;

      // Record the allow decision (with any obligations applied) fire-and-forget.
      void this._opts.auditSink.record({
        sessionId,
        toolName: reqMsg.params.name,
        decision: 'allow',
        obligationsApplied,
        annotateValues,
      });

      return finalResult;
    });

    proxyServer.fallbackRequestHandler = async (request) => {
      return await upstreamClient.request(
        { method: request.method, params: request.params },
        ResultSchema,
      );
    };

    // Upstream → host notifications (e.g. list_changed).
    // The upstream client receives ServerNotification (server→client);
    // the proxy server forwards them onward as ServerNotification to the host.
    upstreamClient.fallbackNotificationHandler = async (
      notification: Notification,
    ) => {
      await proxyServer.notification(notification as ServerNotification);
    };

    // Host → upstream notifications (e.g. cancelled).
    // The proxy server receives ClientNotification (client→server);
    // the proxy client forwards them onward as ClientNotification to the upstream.
    proxyServer.fallbackNotificationHandler = async (
      notification: Notification,
    ) => {
      await upstreamClient.notification(notification as ClientNotification);
    };

    // ── 5. Connect server to the HTTP transport ────────────────────────────
    await proxyServer.connect(serverTransport);

    // ── 6. Wire upstream exit → session cleanup ────────────────────────────
    let upstreamExited = false;
    upstreamTransport.onclose = () => {
      upstreamExited = true;
      this._pendingSessions.delete(session);
      if (registeredSessionId !== undefined) {
        const session = this._sessions.get(registeredSessionId);
        this._sessions.delete(registeredSessionId);
        // Close the proxy-server side so the HTTP client receives an error
        // rather than hanging indefinitely after the upstream disappears.
        if (session !== undefined) {
          session.server.close().catch(() => {
            // Best-effort — the server may already be closing.
          });
        }
      }
    };

    // ── 7. Register graceful shutdown for this session's upstream ──────────
    // Unlike stdio (one upstream = one signal handler), HTTP sessions are
    // cleaned up by close() or by the onsessionclosed callback when the client
    // sends DELETE.  We attach a local timer-based kill here only as defence-
    // in-depth for unresponsive upstream processes.
    const originalOnclose = serverTransport.onclose;
    serverTransport.onclose = () => {
      if (!upstreamExited) {
        const pid = upstreamTransport.pid;
        if (pid != null) {
          try {
            process.kill(pid, 'SIGTERM');
          } catch {
            // Already dead.
          }
          const timer = setTimeout(() => {
            if (!upstreamExited && pid != null) {
              try {
                process.kill(pid, 'SIGKILL');
              } catch {
                // Already dead.
              }
            }
          }, shutdownTimeoutMs);
          timer.unref();
        }
      }
      originalOnclose?.();
    };

    // ── 8. Route the current request to the new transport ─────────────────
    try {
      await serverTransport.handleRequest(req, res);
    } finally {
      if (registeredSessionId === undefined) {
        this._pendingSessions.delete(session);
        await this._closeSession(session);
      }
    }
  }

  /**
   * Gracefully closes a single session (upstream process + transports).
   */
  private async _closeSession(session: HttpProxySession): Promise<void> {
    await Promise.allSettled([
      session.serverTransport.close(),
      session.server.close(),
      session.upstreamClient.close(),
      session.upstreamTransport.close(),
    ]);
  }

  // ── Source IP extraction ──────────────────────────────────────────────────

  /**
   * Extracts the client source IP from an incoming HTTP request.
   *
   * When {@link HttpProxyOptions.trustForwardedFor} is `true` **and** the
   * proxy is bound to a loopback address (`127.0.0.1` or `::1`), the first
   * value of the `X-Forwarded-For` header is used.  In all other cases the
   * source IP is taken from `req.socket.remoteAddress`.
   *
   * The `::ffff:` IPv4-mapped prefix is stripped so that condition handlers
   * always receive a bare IPv4 or IPv6 address.  Returns `undefined` when no
   * address can be determined.
   */
  private _extractSourceIp(req: http.IncomingMessage): string | undefined {
    const { trustForwardedFor, bind } = this._opts;
    const isLoopbackBind = bind === '127.0.0.1' || bind === '::1';

    if (trustForwardedFor && isLoopbackBind) {
      const xffHeader = req.headers['x-forwarded-for'];
      const xff = Array.isArray(xffHeader) ? xffHeader[0] : xffHeader;
      if (xff) {
        const ip = xff.split(',')[0]?.trim();
        if (ip) {
          return ip.replace(/^::ffff:/i, '');
        }
      }
    }

    const raw = req.socket.remoteAddress ?? '';
    const stripped = raw.replace(/^::ffff:/i, '');
    return stripped.length > 0 ? stripped : undefined;
  }

  // ── Control endpoint ──────────────────────────────────────────────────────

  /**
   * Maximum allowed body size for `POST /control/kill` in bytes (16 KiB).
   *
   * A valid kill request body is at most a few tens of bytes
   * (`{"sessionId":"<uuid>"}` or `{"all":true}`).  This limit is deliberately
   * large to be permissive but still prevent memory exhaustion from an
   * attacker who manages to reach the endpoint.
   */
  private static readonly _CONTROL_KILL_MAX_BODY_BYTES = 16 * 1024;

  /**
   * Handles `POST /control/kill` — activates the kill switch for a session or
   * for all sessions.
   *
   * Expected request body (JSON):
   *   `{ "sessionId": "<id>" }` — kill a specific session
   *   `{ "all": true }`         — kill all active sessions
   *
   * Requires {@link HttpProxyOptions.killController} to be set; responds with
   * 503 Service Unavailable when no kill controller is configured.
   *
   * **Loopback-only**: This endpoint always rejects requests that do not
   * originate from the loopback interface (127.0.0.1 or ::1), regardless of
   * the `bind` address.  This provides defence-in-depth when the proxy is
   * started with `--unsafe-bind-all`: even if the HTTP port is reachable from
   * the network, the control endpoint is not.
   */
  private async _handleControlKill(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    // ── 1. Loopback-only gate ─────────────────────────────────────────────
    const remoteAddr = req.socket.remoteAddress ?? '';
    const isLoopback =
      remoteAddr === '127.0.0.1' ||
      remoteAddr === '::1' ||
      remoteAddr === '::ffff:127.0.0.1';
    if (!isLoopback) {
      res.writeHead(403);
      res.end(
        JSON.stringify({
          error: 'Forbidden: /control/kill is only accessible from localhost',
        }),
      );
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' });
      res.end(JSON.stringify({ error: 'Method Not Allowed: /control/kill requires POST' }));
      return;
    }

    const killController = this._opts.killController;
    if (!killController) {
      res.writeHead(503);
      res.end(
        JSON.stringify({
          error:
            'Kill switch not available: start the proxy with a policy file ' +
            '(--policy <file>) to enable the kill controller.',
        }),
      );
      return;
    }

    // ── 2. Read body with size limit ──────────────────────────────────────
    const maxBytes = HttpProxy._CONTROL_KILL_MAX_BODY_BYTES;

    // Reject early when Content-Length already signals an oversized request.
    const clHeader = req.headers['content-length'];
    if (clHeader !== undefined) {
      const cl = parseInt(clHeader, 10);
      if (Number.isFinite(cl) && cl > maxBytes) {
        res.writeHead(413);
        res.end(
          JSON.stringify({
            error: `Request Entity Too Large: /control/kill body must be ≤ ${maxBytes} bytes`,
          }),
        );
        return;
      }
    }

    let bodyRaw: string;
    let bodyTooLarge = false;
    try {
      bodyRaw = await new Promise<string>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let bytesRead = 0;
        req.on('data', (chunk: Buffer) => {
          bytesRead += chunk.length;
          if (bytesRead <= maxBytes) {
            chunks.push(chunk);
          } else {
            // Flag the oversize condition and stop accumulating.
            bodyTooLarge = true;
          }
        });
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
      });
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Bad Request: error reading request body' }));
      return;
    }

    if (bodyTooLarge) {
      res.writeHead(413);
      res.end(
        JSON.stringify({
          error: `Request Entity Too Large: /control/kill body must be ≤ ${maxBytes} bytes`,
        }),
      );
      return;
    }

    // ── 3. Parse and dispatch ─────────────────────────────────────────────
    let body: unknown;
    try {
      body = JSON.parse(bodyRaw);
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Bad Request: expected a JSON body' }));
      return;
    }

    if (
      body === null ||
      typeof body !== 'object' ||
      Array.isArray(body)
    ) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Bad Request: body must be a JSON object' }));
      return;
    }

    const payload = body as Record<string, unknown>;

    if (payload['all'] === true) {
      killController.killAll();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ killed: 'all' }));
      process.stderr.write('[euno-mcp] Global kill switch activated via /control/kill.\n');
      return;
    }

    if (typeof payload['sessionId'] === 'string' && payload['sessionId'].length > 0) {
      const sessionId = payload['sessionId'];
      killController.killSession(sessionId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ killed: sessionId }));
      // JSON.stringify prevents log injection if sessionId contains control characters.
      process.stderr.write(
        `[euno-mcp] Kill switch activated for session ${JSON.stringify(sessionId)} via /control/kill.\n`,
      );
      return;
    }

    res.writeHead(400);
    res.end(
      JSON.stringify({
        error: 'Bad Request: body must contain either { "sessionId": "<id>" } or { "all": true }',
      }),
    );
  }
}

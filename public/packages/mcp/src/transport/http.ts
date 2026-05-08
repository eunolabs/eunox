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
import { AlwaysAllowPDP, type PolicyDecisionPoint } from '../pdp';
import {
  MCP_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
} from '../protocol';
import type { TelemetryHooks } from '../telemetry/types';

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
 */
function buildDenialResult(
  toolName: string,
  reason: string | undefined,
  denialCode: string | undefined,
) {
  const message = reason ?? 'Tool call denied by euno policy';
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify({
          error: 'CapabilityDenied',
          tool: toolName,
          code: denialCode ?? 'CAPABILITY_DENIED',
          message,
        }),
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
  private readonly _opts: Required<Omit<HttpProxyOptions, 'env' | 'cwd' | 'killController' | 'telemetryHooks'>> &
    Pick<HttpProxyOptions, 'env' | 'cwd' | 'killController' | 'telemetryHooks'>;

  private _httpServer?: http.Server;
  private _sessions = new Map<string, HttpProxySession>();
  private _started = false;
  private _port?: number;

  constructor(opts: HttpProxyOptions) {
    this._opts = {
      command: opts.command,
      args: opts.args ?? [],
      env: opts.env,
      cwd: opts.cwd,
      pdp: opts.pdp ?? new AlwaysAllowPDP(),
      killController: opts.killController,
      port: opts.port ?? 3000,
      bind: opts.bind ?? '127.0.0.1',
      unsafeBindAll: opts.unsafeBindAll ?? false,
      shutdownTimeoutMs: opts.shutdownTimeoutMs ?? 5_000,
      telemetryHooks: opts.telemetryHooks,
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
    const closures = Array.from(this._sessions.values()).map((s) =>
      this._closeSession(s),
    );
    await Promise.allSettled(closures);
    this._sessions.clear();

    if (this._httpServer) {
      await new Promise<void>((resolve) => {
        this._httpServer!.close(() => resolve());
      });
    }
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
      await session.serverTransport.handleRequest(req, res);
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
        const session: HttpProxySession = {
          serverTransport,
          server: proxyServer,
          upstreamClient,
          upstreamTransport,
        };
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

    const pdp = this._opts.pdp;
    const shutdownTimeoutMs = this._opts.shutdownTimeoutMs;

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
      const decision = await pdp.decide(reqMsg, { sessionId });

      // Notify telemetry hooks about this enforcement decision.
      sessionTelemetry?.onDecision?.(decision.allow, decision.conditionType);

      if (!decision.allow) {
        return buildDenialResult(
          reqMsg.params.name,
          decision.reason,
          decision.denialCode,
        );
      }

      return await upstreamClient.callTool(
        reqMsg.params,
        CompatibilityCallToolResultSchema,
      );
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
    await serverTransport.handleRequest(req, res);
  }

  /**
   * Gracefully closes a single session (upstream process + transports).
   */
  private async _closeSession(session: HttpProxySession): Promise<void> {
    await Promise.allSettled([
      session.server.close(),
      session.upstreamClient.close(),
    ]);
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

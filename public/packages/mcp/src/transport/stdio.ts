/**
 * Stdio proxy transport for @euno/mcp.
 *
 * Architecture
 * ────────────
 *   MCP host  ──stdin/stdout──►  StdioServerTransport  ──►  StdioProxy
 *                                                              │
 *                                                     StdioClientTransport
 *                                                              │
 *                                              upstream MCP server process
 *
 * The proxy runs two MCP endpoints:
 *   • A {@link Server} (server-side) connected to a {@link StdioServerTransport}
 *     that reads from the current process's stdin / writes to stdout.  This is
 *     what Claude Desktop / Cursor / Windsurf talks to.
 *   • A {@link Client} (client-side) connected to a {@link StdioClientTransport}
 *     that spawns the upstream command and talks to it.
 *
 * Forwarding rules
 * ────────────────
 *   `tools/list`, `resources/list`, `prompts/list` — proxied verbatim.
 *   `tools/call`                                   — intercepted; the PDP is
 *       consulted before forwarding.  On deny the upstream is never called and
 *       a structured error result is returned to the client.
 *   All other requests                             — proxied verbatim via the
 *       generic fallback handler.
 *   Notifications (upstream → host)                — forwarded via
 *       `client.fallbackNotificationHandler` (e.g. list_changed events).
 *   Notifications (host → upstream)                — forwarded via
 *       `server.fallbackNotificationHandler` (e.g. cancelled).
 *   Stderr from the upstream                       — propagated to the proxy
 *       process's own stderr so debugging output is never silently lost.
 *
 * Signal handling
 * ───────────────
 *   SIGINT / SIGTERM → forwarded to the upstream child; the proxy waits up to
 *   {@link StdioProxyOptions.shutdownTimeoutMs} ms then sends SIGKILL.
 *
 * @module
 */

import { Readable, Writable } from 'node:stream';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
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
import { PolicyDecisionPoint, AlwaysAllowPDP } from '../pdp';
import {
  MCP_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
} from '../protocol';
import { McpAuditSink, NullAuditSink } from '../audit';
import type { TelemetryHooks } from '../telemetry/types';
import { applyRedactObligations, applyRemoteObligations, type ToolCallResult } from './obligations';
import { UpstreamTimeoutError, withTimeout } from './timeout';

/** Unique id for the proxy's own server identity (shown to the upstream). */
const PROXY_NAME = 'euno-mcp-proxy';
const PROXY_VERSION = '1.0.0';

/**
 * Options for {@link StdioProxy}.
 */
export interface StdioProxyOptions {
  /**
   * The upstream command to spawn.  Forwarded verbatim to
   * `child_process.spawn`.
   */
  command: string;
  /**
   * Arguments to pass to the upstream command.
   */
  args?: string[];
  /**
   * Additional environment variables merged on top of the current process
   * environment when spawning the upstream.  Defaults to the SDK's
   * `getDefaultEnvironment()` result.
   */
  env?: Record<string, string>;
  /**
   * Working directory for the upstream process.  Defaults to
   * `process.cwd()`.
   */
  cwd?: string;
  /**
   * PolicyDecisionPoint used to evaluate `tools/call` requests.
   * Defaults to {@link AlwaysAllowPDP} (transparent passthrough) when not
   * supplied.
   */
  pdp?: PolicyDecisionPoint;
  /**
   * Audit sink for recording every `tools/call` enforcement decision.
   * Defaults to {@link NullAuditSink} (no-op) when not supplied.
   *
   * The sink's {@link McpAuditSink.record} is called fire-and-forget after
   * every allow/deny decision so audit I/O never blocks enforcement.
   */
  auditSink?: McpAuditSink;
  /**
   * The session ID for this proxy session.  For stdio, the session is the
   * lifetime of the proxy process.  Defaults to a random UUID.
   */
  sessionId?: string;
  /**
   * Time in milliseconds to wait for the upstream to exit gracefully after
   * forwarding SIGTERM before sending SIGKILL.
   *
   * @default 5000
   */
  shutdownTimeoutMs?: number;
  /**
   * Optional readable stream to use as the host-side stdin (useful for
   * testing).  Defaults to `process.stdin`.
   */
  hostStdin?: Readable;
  /**
   * Optional writable stream to use as the host-side stdout (useful for
   * testing).  Defaults to `process.stdout`.
   */
  hostStdout?: Writable;
  /**
   * Optional telemetry hooks for recording session lifecycle events and
   * tool-call enforcement decisions.  No-op when not supplied.
   */
  telemetryHooks?: TelemetryHooks;
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
}

/**
 * Builds an MCP tool-call result payload with `isError: true` that carries a
 * structured `CapabilityDenied` payload in its text content.
 *
 * Intentionally returns a tool-call *result* (not a transport-level JSON-RPC
 * error) so the host presents the denial as structured output rather than
 * treating it as a connection failure.
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

/**
 * A stdio MCP proxy.
 *
 * Instantiate and call {@link start} to begin proxying.  The proxy takes
 * ownership of stdin / stdout once started; do not write to them directly.
 *
 * @example
 * ```ts
 * const proxy = new StdioProxy({
 *   command: 'node',
 *   args: ['/path/to/upstream-mcp-server.js'],
 * });
 * await proxy.start();
 * ```
 */
export class StdioProxy {
  private readonly _opts: Required<
    Omit<StdioProxyOptions, 'env' | 'cwd' | 'hostStdin' | 'hostStdout' | 'telemetryHooks' | 'upstreamTimeoutMs'>
  > &
    Pick<StdioProxyOptions, 'env' | 'cwd' | 'hostStdin' | 'hostStdout' | 'telemetryHooks' | 'upstreamTimeoutMs'>;

  private _server?: Server;
  private _client?: Client;
  private _started = false;
  private _shutdownInProgress = false;

  constructor(opts: StdioProxyOptions) {
    this._opts = {
      command: opts.command,
      args: opts.args ?? [],
      env: opts.env,
      cwd: opts.cwd,
      pdp: opts.pdp ?? new AlwaysAllowPDP(),
      auditSink: opts.auditSink ?? new NullAuditSink(),
      sessionId: opts.sessionId ?? crypto.randomUUID(),
      shutdownTimeoutMs: opts.shutdownTimeoutMs ?? 5_000,
      hostStdin: opts.hostStdin,
      hostStdout: opts.hostStdout,
      telemetryHooks: opts.telemetryHooks,
      upstreamTimeoutMs: opts.upstreamTimeoutMs,
    };
  }

  /**
   * Starts the proxy and blocks until the host-side session ends.
   *
   * What happens inside:
   *   1. Spawns the upstream MCP server process.
   *   2. Connects a client to the upstream (completes the upstream `initialize`
   *      handshake).
   *   3. Builds the proxy `Server` that listens on stdin/stdout and registers
   *      all forwarding and enforcement handlers.
   *   4. Waits until the host closes the connection (stdin EOF or an explicit
   *      `server.close()` call from the SIGTERM handler).
   *
   * Callers (the CLI) rely on the returned Promise staying pending for the
   * entire session lifetime so that cleanup code in a `finally` block (e.g.
   * `auditSink.close()`) only runs after all requests have been processed.
   * Do NOT change this to resolve at the `server.connect()` point — doing so
   * silently discards every audit record written after the Promise resolves.
   *
   * @throws if the upstream connection or server setup fails.  Safe to retry
   *   after a throw because `_started` is reset on error.
   */
  async start(): Promise<void> {
    if (this._started) {
      throw new Error('StdioProxy.start() called more than once');
    }
    // Mark started *after* all async setup succeeds so a caller can retry
    // (or inspect the error) if connect() throws.
    try {
      await this._startInternal();
    } catch (err) {
      // Reset the flag so that the failure is visible and a retry is possible.
      this._started = false;
      throw err;
    }
  }

  private async _startInternal(): Promise<void> {
    this._started = true;

    // ── 1. Connect to the upstream ──────────────────────────────────────────
    const clientTransport = new StdioClientTransport({
      command: this._opts.command,
      args: this._opts.args,
      env: this._opts.env,
      cwd: this._opts.cwd,
      // Pipe stderr so we can forward it to our own stderr.
      stderr: 'pipe',
    });

    // Forward upstream stderr to our stderr immediately (before start() so we
    // don't miss early output).
    const upstreamStderr = clientTransport.stderr;
    if (upstreamStderr) {
      upstreamStderr.on('data', (chunk: Buffer) => {
        process.stderr.write(chunk);
      });
    }

    const client = new Client(
      { name: PROXY_NAME, version: PROXY_VERSION },
      { capabilities: {} },
    );
    this._client = client;

    await client.connect(clientTransport);

    // Upstream connected successfully — now the session is truly established.
    // Notify telemetry after the connect so failed connections aren't counted.
    this._opts.telemetryHooks?.onSessionStart?.();

    // Retrieve upstream server capabilities to advertise them verbatim to the
    // host.
    const upstreamCaps = client.getServerCapabilities() ?? {};

    // ── 2. Build the proxy server ───────────────────────────────────────────
    const server = new Server(
      { name: PROXY_NAME, version: PROXY_VERSION },
      {
        capabilities: {
          // Mirror the upstream's capabilities so the host sees the real
          // surface area (tools, resources, prompts, etc.).
          ...upstreamCaps,
        },
      },
    );
    this._server = server;

    // After the host has completed the initialize handshake, verify that the
    // client is using a protocol revision within our documented support window.
    // The SDK negotiates the version internally during initialize; this check
    // is a defence-in-depth assertion that we log clearly rather than silently
    // accepting an out-of-window revision.  MCP_PROTOCOL_VERSION is the
    // primary (preferred) revision; MCP_SUPPORTED_PROTOCOL_VERSIONS is the
    // full accept list.
    server.oninitialized = () => {
      const clientVersion = server.getClientVersion();
      const clientLabel = clientVersion
        ? `${clientVersion.name}@${clientVersion.version}`
        : 'unknown client';
      process.stderr.write(
        `[euno-mcp] Session ${this._opts.sessionId} initialized with ${clientLabel}. ` +
          `Primary protocol revision: ${MCP_PROTOCOL_VERSION}. ` +
          `Accepted revisions: ${MCP_SUPPORTED_PROTOCOL_VERSIONS.join(', ')}.\n`,
      );
    };

    // ── 3. Wire passthrough handlers ───────────────────────────────────────

    // tools/list — passthrough
    server.setRequestHandler(ListToolsRequestSchema, async (req) => {
      return await client.listTools(req.params);
    });

    // resources/list — passthrough (only if upstream supports resources)
    if (upstreamCaps.resources !== undefined) {
      server.setRequestHandler(ListResourcesRequestSchema, async (req) => {
        return await client.listResources(req.params);
      });
    }

    // prompts/list — passthrough (only if upstream supports prompts)
    if (upstreamCaps.prompts !== undefined) {
      server.setRequestHandler(ListPromptsRequestSchema, async (req) => {
        return await client.listPrompts(req.params);
      });
    }

    // ── 4. Intercept tools/call ─────────────────────────────────────────────
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
      // Consult the PDP.
      const decision = await this._opts.pdp.decide(req, {
        sessionId: this._opts.sessionId,
      });

      // Notify telemetry hooks (fire-and-forget, no await).
      this._opts.telemetryHooks?.onDecision?.(decision.allow, decision.conditionType);

      if (!decision.allow) {
        // Record the enforcement decision — fire-and-forget so audit I/O never
        // blocks the response to the MCP client.  `_writeRecord` swallows its
        // own errors; failures are emitted to stderr by the sink.
        void this._opts.auditSink.record({
          sessionId: this._opts.sessionId,
          toolName: req.params.name,
          decision: 'deny',
          denialCode: decision.denialCode,
          conditionType: decision.conditionType,
          details: decision.details,
        });
        // Return a structured CapabilityDenied result (not a transport-level
        // error) so the host can present a human-readable denial.
        return buildDenialResult(
          req.params.name,
          decision.reason,
          decision.denialCode,
          decision.details,
        );
      }

      // Allowed — forward to upstream and apply any response-path obligations.
      // Race the upstream call against the configurable timeout so a slow or
      // unresponsive upstream doesn't hang the MCP host indefinitely.
      let upstreamResult: Awaited<ReturnType<typeof client.callTool>>;
      try {
        upstreamResult = await withTimeout(
          client.callTool(req.params, CompatibilityCallToolResultSchema),
          this._opts.upstreamTimeoutMs,
          req.params.name,
        );
      } catch (err) {
        const isTimeout = err instanceof UpstreamTimeoutError;
        process.stderr.write(
          `[euno-mcp] ${isTimeout ? 'Upstream timeout' : 'Upstream error'} on tool "${req.params.name}": ${String(err)}\n`,
        );
        return buildDenialResult(
          req.params.name,
          isTimeout
            ? `Upstream did not respond within ${this._opts.upstreamTimeoutMs} ms`
            : `Upstream error: ${String(err)}`,
          isTimeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR',
        );
      }

      // Apply redactFields (and any other response-path) obligations when the
      // matched constraint carries conditions that have a `redact` lobe, or
      // when the remote enforcer returned explicit obligations.
      const { matchedConditions, obligations } = decision;
      const obligationsApplied: string[] = [];
      let finalResult = upstreamResult;
      if (obligations && obligations.length > 0) {
        // Remote-enforcer mode: apply obligations from the gateway response.
        finalResult = applyRemoteObligations(
          upstreamResult as ToolCallResult,
          obligations,
        ) as typeof upstreamResult;
        for (const o of obligations) {
          if (!obligationsApplied.includes(o.type)) {
            obligationsApplied.push(o.type);
          }
        }
      } else if (matchedConditions && hasRedactObligation(matchedConditions)) {
        // Local mode: derive obligations from the matched capability conditions.
        finalResult = applyRedactObligations(
          upstreamResult as ToolCallResult,
          matchedConditions,
        ) as typeof upstreamResult;
        obligationsApplied.push('redactFields');
      }

      // Record the allow decision (with any obligations applied) fire-and-forget.
      void this._opts.auditSink.record({
        sessionId: this._opts.sessionId,
        toolName: req.params.name,
        decision: 'allow',
        obligationsApplied: obligationsApplied.length > 0 ? obligationsApplied : undefined,
      });

      return finalResult;
    });

    // ── 5. Connect the server to host stdio ─────────────────────────────────
    const serverTransport = new StdioServerTransport(
      this._opts.hostStdin,
      this._opts.hostStdout,
    );

    // Forward unknown requests generically so the proxy remains forward-
    // compatible with new MCP methods added in future revisions.  ResultSchema
    // is the base MCP result type (an open-ended object with an optional
    // _meta field) and accepts any well-formed JSON-RPC result.
    server.fallbackRequestHandler = async (request) => {
      return await client.request(
        { method: request.method, params: request.params },
        ResultSchema,
      );
    };

    // ── 6. Bridge notifications in both directions ──────────────────────────
    // Upstream → host: notifications emitted by the upstream server (e.g.
    //   notifications/tools/list_changed) are forwarded to the MCP host.
    client.fallbackNotificationHandler = async (notification: Notification) => {
      await server.notification(notification as ServerNotification);
    };

    // Host → upstream: notifications from the host (e.g. cancelled) are
    // forwarded to the upstream so it can react accordingly.
    server.fallbackNotificationHandler = async (notification: Notification) => {
      await client.notification(notification as ClientNotification);
    };

    await server.connect(serverTransport);

    // ── 7. Register signal handlers ─────────────────────────────────────────
    // Track whether the upstream has already exited so we can avoid a spurious
    // SIGKILL and misleading log when the child exits before the timeout fires.
    let upstreamExited = false;
    clientTransport.onclose = () => {
      upstreamExited = true;
      // Notify telemetry that the session has ended.
      this._opts.telemetryHooks?.onSessionEnd?.();
    };

    const shutdown = (signal: NodeJS.Signals) => {
      if (this._shutdownInProgress) return;
      this._shutdownInProgress = true;

      process.stderr.write(`[euno-mcp] Received ${signal}; shutting down.\n`);

      // Forward the signal to the upstream child process.
      const pid = clientTransport.pid;
      if (pid != null) {
        try {
          process.kill(pid, signal);
        } catch {
          // Process already gone — fine.
        }
      }

      const timer = setTimeout(() => {
        // Only SIGKILL if the upstream hasn't already exited on its own.
        if (!upstreamExited) {
          process.stderr.write(
            '[euno-mcp] Upstream did not exit in time; sending SIGKILL.\n',
          );
          if (pid != null) {
            try {
              process.kill(pid, 'SIGKILL');
            } catch {
              // Already dead.
            }
          }
        }
        void this.close();
      }, this._opts.shutdownTimeoutMs);

      // Don't keep the Node.js event loop alive waiting for this timer.
      timer.unref();
    };

    process.once('SIGINT', () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));

    // ── 8. Wait for the host-side session to end ─────────────────────────────
    // `server.connect()` returns as soon as the MCP transport is set up, but
    // the session is still active.  We wait here until the server transport
    // closes (stdin EOF from the host or an explicit `server.close()` call
    // from the SIGTERM shutdown handler).
    //
    // Without this await, `start()` would return immediately and the CLI's
    // `finally` block would call `auditSink.close()` before any `tools/call`
    // requests are processed — silently discarding every audit record.
    await new Promise<void>((resolve) => {
      // `server.connect()` already installed the SDK's own onclose handler on
      // `serverTransport`.  Wrap it so we are notified when the session ends,
      // while preserving the SDK's cleanup logic.  `resolve()` is placed in a
      // `finally` block so that a throw inside `sdkOnclose` can never leave
      // this Promise pending indefinitely.
      const sdkOnclose = serverTransport.onclose;
      serverTransport.onclose = () => {
        try {
          sdkOnclose?.();
        } finally {
          resolve();
        }
      };
    });
  }

  /**
   * Closes both the upstream client connection and the host server connection.
   *
   * Safe to call multiple times.
   */
  async close(): Promise<void> {
    await Promise.allSettled([
      this._server?.close(),
      this._client?.close(),
    ]);
    this._opts.pdp.dispose?.();
  }

  /**
   * The session ID for this proxy session.
   */
  get sessionId(): string {
    return this._opts.sessionId;
  }

  /**
   * The primary MCP protocol revision this proxy is configured to advertise.
   * See {@link MCP_SUPPORTED_PROTOCOL_VERSIONS} for all accepted revisions.
   */
  get protocolVersion(): string {
    return MCP_PROTOCOL_VERSION;
  }
}

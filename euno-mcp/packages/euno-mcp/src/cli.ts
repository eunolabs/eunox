#!/usr/bin/env node
/**
 * euno-mcp CLI entry point.
 *
 * Commands:
 *   proxy    — Start the euno-mcp proxy in front of an upstream MCP server.
 *              Supports stdio (default) and streamable HTTP transports.
 *
 *              Examples:
 *                euno-mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
 *                euno-mcp proxy --transport http --port 3000 -- node ./my-mcp-server.js
 *
 *   validate — Validate a policy file (Phase B / Task 9).
 */

import { Command } from 'commander';
import { version } from '../package.json';
import { StdioProxy } from './transport/stdio';
import { HttpProxy } from './transport/http';
import { createLocalAuditSink, McpAuditSink } from './audit';
import { FilePolicySource } from './policy/source';
import { ConditionEnforcerPDP, AlwaysAllowPDP, PolicyDecisionPoint } from './pdp';
import { createTelemetry } from './telemetry';

const program = new Command();

program
  .name('euno-mcp')
  .description('Euno MCP bridge — capability-native agent governance over the Model Context Protocol')
  .version(version);

// ── proxy ──────────────────────────────────────────────────────────────────
program
  .command('proxy')
  .description('Start the euno-mcp proxy in front of an upstream MCP server')
  .option(
    '--transport <type>',
    'Transport type: "stdio" (default) or "http"',
    'stdio',
  )
  .option(
    '--port <n>',
    'Port to listen on (HTTP transport only)',
    '3000',
  )
  .option(
    '--bind <addr>',
    'Address to bind to (HTTP transport only, default: 127.0.0.1)',
    '127.0.0.1',
  )
  .option(
    '--unsafe-bind-all',
    'Allow binding to 0.0.0.0 / :: (HTTP transport only; implies a security warning)',
    false,
  )
  .option(
    '--policy <file>',
    'Path to a YAML/JSON capability policy file (enforces conditions on tools/call)',
  )
  .option(
    '--audit-log <path>',
    'Path to the OCSF audit JSONL file (default: ~/.euno/audit.jsonl)',
  )
  .option(
    '--audit-rotate-size <bytes>',
    'Rotate the audit log when it reaches this size in bytes (default: 104857600 = 100 MiB)',
  )
  .option(
    '--session-id <id>',
    'Override the auto-generated session ID (stdio transport only — useful for testing)',
  )
  .option(
    '--shutdown-timeout <ms>',
    'Milliseconds to wait for the upstream to exit before SIGKILL',
    '5000',
  )
  .allowUnknownOption(false)
  .argument('<command>', 'Upstream MCP server command (after --)')
  .argument('[args...]', 'Arguments for the upstream MCP server command')
  .addHelpText(
    'after',
    `
Examples:
  # stdio (default) — drop-in for claude_desktop_config.json
  euno-mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # stdio with a policy file and custom audit log path
  euno-mcp proxy --policy ./policy.yaml --audit-log /var/log/euno/audit.jsonl -- node ./my-mcp-server.js

  # HTTP (LangChain.js / in-process clients)
  euno-mcp proxy --transport http --port 3000 -- node ./my-mcp-server.js
`,
  )
  .action(async (upstreamCommand: string, upstreamArgs: string[], options) => {
    // ── Validate common options ───────────────────────────────────────────
    const transport: string = options.transport as string;
    if (transport !== 'stdio' && transport !== 'http') {
      process.stderr.write(
        `[euno-mcp] Invalid --transport value "${transport}": must be "stdio" or "http".\n`,
      );
      process.exit(1);
    }

    let shutdownTimeoutMs: number | undefined;
    if (options.shutdownTimeout !== undefined) {
      const parsed = parseInt(options.shutdownTimeout as string, 10);
      if (!Number.isFinite(parsed) || parsed < 0) {
        process.stderr.write(
          `[euno-mcp] Invalid --shutdown-timeout value "${options.shutdownTimeout}": ` +
            `must be a non-negative integer (milliseconds).\n`,
        );
        process.exit(1);
      }
      shutdownTimeoutMs = parsed;
    }

    let rotateSizeBytes: number | undefined;
    if (options.auditRotateSize !== undefined) {
      const parsed = parseInt(options.auditRotateSize as string, 10);
      if (!Number.isFinite(parsed) || parsed < 1) {
        process.stderr.write(
          `[euno-mcp] Invalid --audit-rotate-size value "${options.auditRotateSize}": ` +
            `must be a positive integer (bytes).\n`,
        );
        process.exit(1);
      }
      rotateSizeBytes = parsed;
    }

    // ── Build PDP ─────────────────────────────────────────────────────────
    let pdp: PolicyDecisionPoint;
    let conditionPdp: ConditionEnforcerPDP | undefined;
    if (options.policy) {
      const policySource = new FilePolicySource({ filePath: options.policy as string });
      conditionPdp = new ConditionEnforcerPDP({ policySource });
      pdp = conditionPdp;
    } else {
      pdp = new AlwaysAllowPDP();
    }

    // ── Create telemetry collector ────────────────────────────────────────
    // Must be called before proxy.start() so the consent prompt (if any) is
    // shown while stdin is still available for user input.
    const telemetry = await createTelemetry({
      subcommand: 'proxy',
      upstreamCommand: upstreamCommand,
      upstreamArgs: upstreamArgs,
    });

    // Register beforeExit to flush telemetry once the event loop drains.
    // This fires after the proxy session ends and all I/O has settled.
    process.once('beforeExit', () => { void telemetry.flush(); });

    // ── stdio transport ───────────────────────────────────────────────────
    if (transport === 'stdio') {
      // Initialise the audit sink. Errors here are fatal — we want operators
      // to know early if the key or log path is misconfigured.
      let auditSink: McpAuditSink;
      try {
        auditSink = await createLocalAuditSink({
          logPath: options.auditLog as string | undefined,
          rotateSizeBytes,
        });
      } catch (err) {
        process.stderr.write(
          `[euno-mcp] Failed to initialise audit log: ${String(err)}\n`,
        );
        process.exit(1);
      }

      const proxy = new StdioProxy({
        command: upstreamCommand,
        args: upstreamArgs,
        sessionId: options.sessionId as string | undefined,
        shutdownTimeoutMs,
        auditSink,
        pdp,
        telemetryHooks: telemetry.sessionHooks(),
      });

      let exitCode = 0;
      try {
        await proxy.start();
      } catch (err) {
        process.stderr.write(
          `[euno-mcp] Fatal error starting stdio proxy: ${String(err)}\n`,
        );
        exitCode = 1;
      } finally {
        await auditSink.close();
        conditionPdp?.dispose();
      }
      if (exitCode !== 0) {
        process.exitCode = exitCode;
      }
      return;
    }

    // ── http transport ────────────────────────────────────────────────────
    let port: number | undefined;
    if (options.port !== undefined) {
      const parsed = parseInt(options.port as string, 10);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > 65535) {
        process.stderr.write(
          `[euno-mcp] Invalid --port value "${options.port}": ` +
            `must be an integer in [0, 65535].\n`,
        );
        process.exit(1);
      }
      port = parsed;
    }

    const bind: string = options.bind as string;
    const unsafeBindAll: boolean = options.unsafeBindAll as boolean;

    const proxy = new HttpProxy({
      command: upstreamCommand,
      pdp,
      // Wire the conditionPdp as the kill controller so `euno-mcp kill`
      // can activate the kill switch via POST /control/kill.
      killController: conditionPdp,
      args: upstreamArgs,
      port,
      bind,
      unsafeBindAll,
      shutdownTimeoutMs,
      telemetryHooks: telemetry.sessionHooks(),
    });

    try {
      const listenPort = await proxy.start();
      process.stderr.write(
        `[euno-mcp] HTTP proxy ready on http://${bind}:${listenPort}/mcp\n`,
      );

      // Keep the process alive until interrupted.
      const shutdown = async () => {
        process.stderr.write('[euno-mcp] Shutting down HTTP proxy.\n');
        let exitCode = 0;
        try {
          await proxy.close();
        } catch (err) {
          process.stderr.write(`[euno-mcp] Error during shutdown: ${String(err)}\n`);
          exitCode = 1;
        }
        conditionPdp?.dispose();
        await telemetry.flush();
        process.exit(exitCode);
      };
      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] Fatal error starting HTTP proxy: ${String(err)}\n`,
      );
      process.exit(1);
    }
  });

// ── validate ───────────────────────────────────────────────────────────────
program
  .command('validate')
  .description('Validate a capability policy file against the Stage-1 policy schema')
  .argument('<policy-file>', 'Path to the YAML/JSON policy file to validate')
  .addHelpText(
    'after',
    `
Examples:
  # Validate a policy file — exits 0 on success, non-zero on failure
  euno-mcp validate ./euno.policy.yaml

  # Use with npx
  npx -y @euno/mcp validate ./euno.policy.yaml
`,
  )
  .action(async (policyFile: string) => {
    const telemetry = await createTelemetry({ subcommand: 'validate' });
    const source = new FilePolicySource({ filePath: policyFile });
    try {
      const manifest = await source.load();
      // Output format matches `euno validate` for consistent UX.
      console.log('✓ Manifest is valid');
      console.log(`  Agent: ${manifest.name} (${manifest.agentId})`);
      console.log(`  Version: ${manifest.version}`);
      console.log(`  Required capabilities: ${manifest.requiredCapabilities.length}`);
      await telemetry.flush();
    } catch (err) {
      if (err instanceof Error) {
        console.error(`✗ Validation failed: ${err.message}`);
      } else {
        console.error(`✗ Validation failed: ${String(err)}`);
      }
      await telemetry.flush();
      process.exit(1);
    }
  });

// ── kill ───────────────────────────────────────────────────────────────────
program
  .command('kill')
  .description(
    'Activate the kill switch for a session (or all sessions) in a running HTTP proxy.\n' +
    'This is a testing helper — it sends a POST to the proxy\'s /control/kill endpoint.\n' +
    'Only available when the proxy is running with --transport http.',
  )
  .argument('<target>', 'Session ID to kill, or "all" to kill every active session')
  .option(
    '--port <n>',
    'Port the HTTP proxy is listening on',
    '3000',
  )
  .option(
    '--host <addr>',
    'Host the HTTP proxy is bound to',
    '127.0.0.1',
  )
  .addHelpText(
    'after',
    `
Examples:
  # Kill a specific session
  euno-mcp kill abc123 --port 3000

  # Kill all active sessions
  euno-mcp kill all --port 3000
`,
  )
  .action(async (target: string, options) => {
    const telemetry = await createTelemetry({ subcommand: 'kill' });
    const port = parseInt(options.port as string, 10);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      process.stderr.write(
        `[euno-mcp] Invalid --port value "${options.port}": must be an integer in [1, 65535].\n`,
      );
      process.exit(1);
    }

    const host: string = options.host as string;
    const url = `http://${host}:${port}/control/kill`;

    const body =
      target === 'all'
        ? JSON.stringify({ all: true })
        : JSON.stringify({ sessionId: target });

    /** Fail-fast timeout for the kill request (ms). */
    const KILL_REQUEST_TIMEOUT_MS = 10_000;

    try {
      const http = await import('node:http');
      const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = http.request(
          url,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
            },
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            incoming.on('data', (chunk: Buffer) => { chunks.push(chunk); });
            incoming.on('end', () => resolve({
              status: incoming.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8'),
            }));
          },
        );
        // Fail fast if the proxy accepts the connection but stops responding.
        req.setTimeout(KILL_REQUEST_TIMEOUT_MS, () => {
          req.destroy(
            new Error(
              `request timed out after ${KILL_REQUEST_TIMEOUT_MS / 1000}s — ` +
              `the proxy is connected but not responding`,
            ),
          );
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });

      if (result.status >= 200 && result.status < 300) {
        try {
          const json = JSON.parse(result.body) as Record<string, unknown>;
          if (json['killed'] === 'all') {
            console.log('✓ Global kill switch activated — all sessions will be denied');
          } else if (typeof json['killed'] === 'string') {
            console.log(`✓ Kill switch activated for session ${json['killed']}`);
          } else {
            console.log(`✓ Kill switch activated (${result.body})`);
          }
        } catch {
          console.log('✓ Kill switch activated');
        }
        await telemetry.flush();
      } else {
        process.stderr.write(
          `[euno-mcp] Kill request failed (HTTP ${result.status}): ${result.body}\n`,
        );
        await telemetry.flush();
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] Could not reach the proxy at ${url}: ${String(err)}\n` +
        `  Make sure the proxy is running with --transport http on port ${port}.\n`,
      );
      await telemetry.flush();
      process.exit(1);
    }
  });

program.parse(process.argv);

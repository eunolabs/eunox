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
      args: upstreamArgs,
      port,
      bind,
      unsafeBindAll,
      shutdownTimeoutMs,
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
  .description('Validate a capability policy file (Phase B)')
  .argument('<policy-file>', 'Path to the YAML/JSON policy file to validate')
  .action((_policyFile: string) => {
    process.stderr.write(
      'euno-mcp validate is not yet implemented (Phase B — Task 9).\n',
    );
    process.exit(1);
  });

program.parse(process.argv);

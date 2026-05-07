#!/usr/bin/env node
/**
 * euno-mcp CLI entry point.
 *
 * Commands:
 *   proxy  — Start the stdio proxy in front of an upstream MCP server.
 *            Example:
 *              euno-mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
 *   validate — Validate a policy file (coming in Phase B / Task 9).
 */

import { Command } from 'commander';
import { version } from '../package.json';
import { StdioProxy } from './transport/stdio';

const program = new Command();

program
  .name('euno-mcp')
  .description('Euno MCP bridge — capability-native agent governance over the Model Context Protocol')
  .version(version);

// ── proxy ──────────────────────────────────────────────────────────────────
program
  .command('proxy')
  .description('Start the euno-mcp stdio proxy in front of an upstream MCP server')
  .option(
    '--policy <file>',
    'Path to a YAML/JSON capability policy file (Phase B — not yet enforced)',
  )
  .option(
    '--audit-log <path>',
    'Path to the OCSF audit log file (Phase B — not yet active)',
  )
  .option(
    '--session-id <id>',
    'Override the auto-generated session ID (useful for testing)',
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
  # Proxy the filesystem MCP server (from Claude Desktop config)
  euno-mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # With a policy file
  euno-mcp proxy --policy ./policy.yaml -- node ./my-mcp-server.js
`,
  )
  .action(async (upstreamCommand: string, upstreamArgs: string[], options) => {
    let shutdownTimeoutMs: number | undefined;
    if (options.shutdownTimeout !== undefined) {
      const parsed = parseInt(options.shutdownTimeout, 10);
      if (!Number.isFinite(parsed) || parsed < 0) {
        process.stderr.write(
          `[euno-mcp] Invalid --shutdown-timeout value "${options.shutdownTimeout}": ` +
            `must be a non-negative integer (milliseconds).\n`,
        );
        process.exit(1);
      }
      shutdownTimeoutMs = parsed;
    }

    const proxy = new StdioProxy({
      command: upstreamCommand,
      args: upstreamArgs,
      sessionId: options.sessionId,
      shutdownTimeoutMs,
    });

    try {
      await proxy.start();
    } catch (err) {
      process.stderr.write(
        `[euno-mcp] Fatal error starting proxy: ${String(err)}\n`,
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

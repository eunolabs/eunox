#!/usr/bin/env node
/**
 * euno-mcp CLI entry point.
 *
 * Proxy / server logic will be wired up later in Stage 1.
 */

import { Command } from 'commander';
import { version } from '../package.json';

const program = new Command();

program
  .name('euno-mcp')
  .description('Euno MCP bridge — capability-native agent governance over the Model Context Protocol')
  .version(version);

program
  .command('serve')
  .description('Start the euno-mcp server (coming in Stage 1)')
  .action(() => {
    process.stderr.write('euno-mcp serve is not yet implemented (Stage 1).\n');
    process.exit(1);
  });

program.parse(process.argv);

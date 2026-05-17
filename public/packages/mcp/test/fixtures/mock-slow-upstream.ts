#!/usr/bin/env node
/**
 * A minimal stdio MCP server that hangs indefinitely on every `tools/call`.
 *
 * Used by the upstream-timeout integration tests to verify that the proxy
 * correctly times out and returns a structured UPSTREAM_TIMEOUT denial instead
 * of blocking indefinitely.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'mock-slow-upstream', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'slow_tool',
      description: 'A tool that hangs indefinitely — never sends a response',
      inputSchema: {
        type: 'object' as const,
        properties: { input: { type: 'string' } },
        required: [],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (_req) => {
  // Hang forever — the proxy's upstreamTimeoutMs should fire before this resolves.
  await new Promise<never>(() => { /* intentionally never resolves */ });
  // This line is unreachable at runtime but required by TypeScript to satisfy
  // the return type of the handler.
  throw new Error('unreachable');
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  process.stderr.write(`[mock-slow-upstream] fatal: ${String(err)}\n`);
  process.exit(1);
});

#!/usr/bin/env node
/**
 * Minimal stdio MCP server used as a test fixture for @euno/mcp integration tests.
 *
 * Exposes:
 *   • Tool `echo`     — returns the input `text` verbatim.
 *   • Tool `query_db` — simulates a DB query; returns a fixed row containing the SQL string.
 *   • Resource `file:///data/mock.txt` — a synthetic read-only text resource.
 *
 * This file is intentionally kept small (~30 lines of logic) so every integration
 * test that needs an upstream can spawn it without ceremony.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'mock-upstream', version: '1.0.0' },
  { capabilities: { tools: {}, resources: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'echo',
      description: 'Echoes the input text back to the caller',
      inputSchema: {
        type: 'object' as const,
        properties: { text: { type: 'string', description: 'Text to echo' } },
        required: ['text'],
      },
    },
    {
      name: 'query_db',
      description: 'Simulates a database query and returns a fixed result',
      inputSchema: {
        type: 'object' as const,
        properties: { sql: { type: 'string', description: 'SQL query string' } },
        required: ['sql'],
      },
    },
    {
      name: 'get_user',
      description: 'Returns a synthetic user record with sensitive fields',
      inputSchema: {
        type: 'object' as const,
        properties: { id: { type: 'string', description: 'User ID' } },
        required: ['id'],
      },
    },
  ],
}));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: 'file:///data/mock.txt',
      name: 'Mock data file',
      description: 'A synthetic read-only text resource for testing',
      mimeType: 'text/plain',
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;

  if (req.params.name === 'echo') {
    const text = typeof args['text'] === 'string' ? args['text'] : '';
    return { content: [{ type: 'text' as const, text }] };
  }

  if (req.params.name === 'query_db') {
    const sql = typeof args['sql'] === 'string' ? args['sql'] : '';
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify({ rows: [{ id: 1, sql }] }),
        },
      ],
    };
  }

  if (req.params.name === 'get_user') {
    const id = typeof args['id'] === 'string' ? args['id'] : '0';
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify({ id, name: 'Alice', ssn: '123-45-6789', credit: '4111-1111-1111-1111' }),
        },
      ],
    };
  }

  throw new Error(`Unknown tool: ${req.params.name}`);
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  process.stderr.write(`[mock-upstream] fatal: ${String(err)}\n`);
  process.exit(1);
});

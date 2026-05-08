#!/usr/bin/env node
/**
 * Recording mock upstream MCP server used by the Task-11 e2e test.
 *
 * Identical to `mock-upstream.ts` except that every `tools/call` invocation
 * is durably logged to a JSONL file before the tool's response is produced.
 * The log path is read from `process.argv[2]` (the first positional argument
 * after the script path); when the argument is absent recording is skipped.
 *
 * Passing the path as a CLI argument (rather than an environment variable)
 * avoids POSIX env-var filtering in the MCP SDK's `getDefaultEnvironment()`
 * which only forwards a restricted safe-list of environment variables to
 * spawned upstream processes.
 *
 * Record format (one JSON object per line):
 * ```json
 * { "name": "<toolName>", "args": { … }, "ts": <unix-ms> }
 * ```
 *
 * ### Why write-before-respond?
 *
 * The Task-11 acceptance criteria require that "mock upstream's recorder shows
 * zero query_db invocations" when the proxy denies a call.  If the proxy
 * blocks the call correctly, the upstream's `tools/call` handler is never
 * entered — the JSONL file therefore remains empty (or is never created).
 * Recording synchronously at handler entry (before any response is emitted)
 * makes this guarantee testable without races.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// ---------------------------------------------------------------------------
// Recorder helper
// ---------------------------------------------------------------------------

/**
 * Path to the JSONL recorder file.  Supplied as the first positional argument
 * (`process.argv[2]`) so it is immune to the MCP SDK's POSIX env-var filter.
 */
const RECORDER_FILE: string | undefined = process.argv[2];

/** Append one JSONL record to the recorder file (synchronous for reliability). */
function recordCall(toolName: string, args: Record<string, unknown>): void {
  if (!RECORDER_FILE) return;

  const line = JSON.stringify({ name: toolName, args, ts: Date.now() });
  try {
    // Ensure the parent directory exists before the first write.
    fs.mkdirSync(path.dirname(RECORDER_FILE), { recursive: true });
    fs.appendFileSync(RECORDER_FILE, line + '\n', 'utf8');
  } catch (err) {
    // Writing to the recorder must never crash the mock upstream.
    process.stderr.write(
      `[mock-upstream-recorder] Failed to write recorder entry: ${String(err)}\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

const server = new Server(
  { name: 'mock-upstream-recorder', version: '1.0.0' },
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
        properties: {
          sql: { type: 'string', description: 'SQL query string' },
          query: { type: 'string', description: 'Alternative SQL query key' },
        },
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

  // Record the call BEFORE producing a response so that the assertion
  // "zero invocations" is reliable even when the handler would throw.
  recordCall(req.params.name, args);

  if (req.params.name === 'echo') {
    const text = typeof args['text'] === 'string' ? args['text'] : '';
    return { content: [{ type: 'text' as const, text }] };
  }

  if (req.params.name === 'query_db') {
    // Support both 'sql' and 'query' argument keys.
    const sql =
      typeof args['sql'] === 'string'
        ? args['sql']
        : typeof args['query'] === 'string'
          ? args['query']
          : '';
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
  process.stderr.write(`[mock-upstream-recorder] fatal: ${String(err)}\n`);
  process.exit(1);
});

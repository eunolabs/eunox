/**
 * Integration tests for @euno/langchain.
 *
 * These tests use a real policy YAML file (test/fixtures/integration.policy.yaml)
 * and exercise the full FilePolicySource → ConditionEnforcerPDP → LocalAuditSink
 * stack via the public API (createLocalRuntime + wrapAsLangChainTool).
 *
 * Audit output is redirected to a temp directory so tests are self-contained.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

import { LocalHmacSigner } from '@euno/mcp';
import { LocalAuditSink } from '@euno/mcp';
import { ConditionEnforcerPDP, FilePolicySource, NullAuditSink } from '@euno/mcp';

import { LocalCapabilityRuntime } from '../runtime';
import { wrapAsLangChainTool } from '../tool';
import { CapabilityDenialError } from '../types';
import { EunoLangChainCallbackHandler } from '../callback';
import type { EunoCallbackEvent } from '../callback';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POLICY_FILE = path.resolve(__dirname, '..', '..', 'test', 'fixtures', 'integration.policy.yaml');

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'euno-langchain-integration-'));
}

function freshSigner(): LocalHmacSigner {
  return new LocalHmacSigner(crypto.randomBytes(32));
}

/** Track runtimes created in each test so they can be disposed in afterEach. */
const _createdRuntimes: LocalCapabilityRuntime[] = [];

function makeRuntime(auditLogDir?: string): LocalCapabilityRuntime {
  const policySource = new FilePolicySource({ filePath: POLICY_FILE });
  const pdp = new ConditionEnforcerPDP({ policySource });

  let auditSink;
  if (auditLogDir) {
    const signer = freshSigner();
    auditSink = new LocalAuditSink(signer, {
      logPath: path.join(auditLogDir, 'audit.jsonl'),
    });
  } else {
    auditSink = new NullAuditSink();
  }

  const runtime = new LocalCapabilityRuntime(pdp, auditSink, crypto.randomUUID());
  _createdRuntimes.push(runtime);
  return runtime;
}

afterEach(async () => {
  // Dispose all runtimes created during the test to release file watchers.
  const batch = _createdRuntimes.splice(0);
  await Promise.all(batch.map((r) => r.dispose()));
});

// ---------------------------------------------------------------------------
// Integration tests — policy enforcement via file
// ---------------------------------------------------------------------------

describe('Integration: createLocalRuntime-equivalent via FilePolicySource', () => {
  describe('query_db tool', () => {
    it('allows a SELECT query', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 'SELECT * FROM users' },
      });
      expect(result.success).toBe(true);
    });

    it('denies a DROP TABLE query (allowedOperations)', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 'DROP TABLE users' },
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('OPERATION_NOT_ALLOWED');
    });

    it('denies a DELETE query', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 'DELETE FROM orders WHERE id = 1' },
      });
      expect(result.success).toBe(false);
    });

    it('allows a SHOW query', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 'SHOW TABLES' },
      });
      expect(result.success).toBe(true);
    });

    it('denies when maxCalls is exceeded', async () => {
      const runtime = makeRuntime();
      // 5 allowed
      for (let i = 0; i < 5; i++) {
        const r = await runtime.invokeTool({
          tool: 'query_db',
          args: { sql: 'SELECT 1' },
        });
        expect(r.success).toBe(true);
      }
      // 6th denied
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 'SELECT 1' },
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('MAX_CALLS_EXCEEDED');
    });

    it('denies when argumentSchema is violated (sql is not a string)', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: { sql: 12345 }, // number, not string
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
    });

    it('denies when sql arg is missing (required by schema)', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'query_db',
        args: {}, // missing required sql
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('ARGUMENT_VALIDATION_FAILED');
    });
  });

  describe('send_email tool', () => {
    it('allows email to trusted domain', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'send_email',
        args: { to: 'user@example.com', body: 'Hello' },
      });
      expect(result.success).toBe(true);
    });

    it('allows email to trusted.org', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'send_email',
        args: { to: 'admin@trusted.org' },
      });
      expect(result.success).toBe(true);
    });

    it('denies email to untrusted domain', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'send_email',
        args: { to: 'hacker@evil.com' },
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
    });

    it('denies email when to field is missing (no recipients)', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'send_email',
        args: { body: 'Hello' },
      });
      expect(result.success).toBe(false);
    });
  });

  describe('read_file tool', () => {
    it('allows reading a .csv file', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'read_file',
        args: { path: '/data/report.csv' },
      });
      expect(result.success).toBe(true);
    });

    it('allows reading a .txt file', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'read_file',
        args: { path: '/data/readme.txt' },
      });
      expect(result.success).toBe(true);
    });

    it('denies reading a .exe file', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'read_file',
        args: { path: '/data/malware.exe' },
      });
      expect(result.success).toBe(false);
      expect(result.denialCode).toBe('EXTENSION_NOT_ALLOWED');
    });

    it('denies reading a .sh file', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'read_file',
        args: { path: '/data/script.sh' },
      });
      expect(result.success).toBe(false);
    });
  });

  describe('unlisted tool', () => {
    it('allows calls to tools not in the manifest', async () => {
      const runtime = makeRuntime();
      const result = await runtime.invokeTool({
        tool: 'unlisted_tool',
        args: {},
      });
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Integration tests — wrapAsLangChainTool with real policy file
// ---------------------------------------------------------------------------

describe('Integration: wrapAsLangChainTool with FilePolicySource', () => {
  it('blocks a destructive SQL call from a governed tool', async () => {
    const runtime = makeRuntime();
    const tool = wrapAsLangChainTool(runtime, {
      name: 'query_db',
      description: 'Run a SQL query on the database',
      schema: {
        type: 'object',
        required: ['sql'],
        properties: { sql: { type: 'string' } },
      },
    });

    // BEFORE: this would execute without enforcement
    // AFTER:  the policy blocks DROP TABLE
    await expect(tool.invoke({ sql: 'DROP TABLE users' })).rejects.toThrow(CapabilityDenialError);
  });

  it('allows a permitted SELECT call via wrapAsLangChainTool', async () => {
    const runtime = makeRuntime();
    const rows = [{ id: 1, name: 'Alice' }];
    const tool = wrapAsLangChainTool(runtime, {
      name: 'query_db',
      description: 'Run a SQL query',
      handler: async (_args) => rows,
    });

    const result = await tool.invoke({ sql: 'SELECT * FROM users' });
    expect(JSON.parse(result)).toEqual(rows);
  });

  it('callback handler receives tool-error on denial', async () => {
    const runtime = makeRuntime();
    const tool = wrapAsLangChainTool(runtime, {
      name: 'query_db',
      description: 'Run a SQL query',
    });

    const events: EunoCallbackEvent[] = [];
    const callbackHandler = new EunoLangChainCallbackHandler((e) => events.push(e));

    callbackHandler.handleToolStart({ name: 'query_db' }, '', 'run-1');
    let caught: CapabilityDenialError | undefined;
    try {
      await tool.invoke({ sql: 'DELETE FROM orders' });
    } catch (e) {
      caught = e as CapabilityDenialError;
      callbackHandler.handleToolError(caught, 'run-1');
    }

    expect(caught).toBeInstanceOf(CapabilityDenialError);
    const errorEvent = events.find((e) => e.phase === 'tool-error');
    expect(errorEvent).toBeDefined();
    expect(errorEvent!.errorCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('callback handler receives tool-end on success', async () => {
    const runtime = makeRuntime();
    const tool = wrapAsLangChainTool(runtime, {
      name: 'query_db',
      description: 'Run a SQL query',
      handler: () => 'results',
    });

    const events: EunoCallbackEvent[] = [];
    const callbackHandler = new EunoLangChainCallbackHandler((e) => events.push(e));

    callbackHandler.handleToolStart({ name: 'query_db' }, '', 'run-1');
    await tool.invoke({ sql: 'SELECT 1' });
    callbackHandler.handleToolEnd('results', 'run-1');

    const endEvent = events.find((e) => e.phase === 'tool-end');
    expect(endEvent).toBeDefined();
    expect(endEvent!.toolName).toBe('query_db');
  });
});

// ---------------------------------------------------------------------------
// Integration tests — audit log writing
// ---------------------------------------------------------------------------

describe('Integration: audit log writing', () => {
  it('writes audit records to the log file', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    const runtime = makeRuntime(dir);
    await runtime.invokeTool({ tool: 'query_db', args: { sql: 'SELECT 1' } });
    await runtime.invokeTool({ tool: 'query_db', args: { sql: 'DROP TABLE t' } });

    await runtime.dispose();

    const lines = fs
      .readFileSync(logPath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));

    expect(lines).toHaveLength(2);
    expect(lines[0].status).toBe('Success');
    expect(lines[1].status).toBe('Failure');
  });

  it('audit records contain the tool name', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    const runtime = makeRuntime(dir);
    await runtime.invokeTool({ tool: 'query_db', args: { sql: 'SELECT 1' } });
    await runtime.dispose();

    const line = JSON.parse(fs.readFileSync(logPath, 'utf8').trim());
    expect(line.api.operation).toBe('query_db');
  });

  it('audit records have hmac enrichment', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    const runtime = makeRuntime(dir);
    await runtime.invokeTool({ tool: 'query_db', args: { sql: 'SELECT 1' } });
    await runtime.dispose();

    const line = JSON.parse(fs.readFileSync(logPath, 'utf8').trim());
    expect(Array.isArray(line.enrichments)).toBe(true);
    expect(line.enrichments[0].name).toBe('hmac-signature');
  });

  it('denial records contain denialCode in unmapped', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    const runtime = makeRuntime(dir);
    await runtime.invokeTool({ tool: 'query_db', args: { sql: 'DROP TABLE t' } });
    await runtime.dispose();

    const line = JSON.parse(fs.readFileSync(logPath, 'utf8').trim());
    expect(line.unmapped.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });
});

// ---------------------------------------------------------------------------
// Integration tests — dispose + terminate
// ---------------------------------------------------------------------------

describe('Integration: lifecycle', () => {
  it('terminate blocks subsequent calls', async () => {
    const runtime = makeRuntime();
    runtime.terminate();
    const result = await runtime.invokeTool({ tool: 'query_db', args: { sql: 'SELECT 1' } });
    expect(result.success).toBe(false);
    expect(result.denialCode).toBe('KILL_SWITCH');
  });

  it('dispose resolves without error', async () => {
    const runtime = makeRuntime();
    await expect(runtime.dispose()).resolves.not.toThrow();
  });
});

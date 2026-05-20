/**
 * Tests for `euno-mcp kill` CLI command and the HttpProxy `/control/kill` endpoint
 * (Task 9 acceptance criteria).
 *
 * Test matrix — HTTP endpoint (direct)
 * -------------------------------------
 * ✓ POST /control/kill { sessionId } activates per-session kill switch
 * ✓ POST /control/kill { all: true } activates global kill switch
 * ✓ POST /control/kill with no kill controller → 503
 * ✓ POST /control/kill with malformed body → 400
 * ✓ POST /control/kill with oversized body → 413
 * ✓ GET /control/kill → 405 Method Not Allowed
 * ✓ Killed session denies subsequent tools/call (via ConditionEnforcerPDP)
 * ✓ Global kill denies tools/call in all sessions
 *
 * Test matrix — CLI subprocess
 * ----------------------------
 * ✓ euno-mcp kill all → exit 0, "✓ Global kill switch activated" on stdout
 * ✓ euno-mcp kill <sessionId> → exit 0, "✓ Kill switch activated for session …"
 * ✓ euno-mcp kill … --port not-a-number → exit 1, "Invalid --port value" on stderr
 * ✓ euno-mcp kill … → exit 1 when no proxy is listening (connection refused)
 */

import * as http from 'node:http';
import * as childProcess from 'node:child_process';
import * as path from 'node:path';
import {
  HttpProxy,
  ConditionEnforcerPDP,
  FilePolicySource,
} from '../../src/index';
import type { KillController } from '../../src/index';
import * as fs from 'node:fs';
import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Temporary directories created during tests. */
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Write a temp policy file and return its absolute path. */
function writeTempPolicy(content: string, ext: 'yaml' | 'json' = 'yaml'): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-kill-test-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, `policy.${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

/**
 * Send an HTTP POST to the given URL with a JSON body.
 * Returns `{ status, body }`.
 */
function httpPost(
  url: string,
  body: unknown,
): Promise<{ status: number; body: unknown }> {
  const bodyStr = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => { chunks.push(chunk); });
        res.on('end', () => {
          const data = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown;
          try { parsed = JSON.parse(data); } catch { parsed = data; }
          resolve({ status: res.statusCode ?? 0, body: parsed });
        });
      },
    );
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

/**
 * Send an HTTP GET to the given URL.
 */
function httpGet(url: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: 'GET' }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => { chunks.push(chunk); });
      res.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf8');
        let parsed: unknown;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

const MINIMAL_POLICY = `
agentId: kill-test-agent
name: Kill Test Agent
version: 0.1.0
requiredCapabilities: []
`.trim();

// ---------------------------------------------------------------------------
// /control/kill — no kill controller configured
// ---------------------------------------------------------------------------

describe('HttpProxy /control/kill — no kill controller', () => {
  let proxy: HttpProxy;
  let proxyPort: number;

  beforeEach(async () => {
    proxy = new HttpProxy({
      command: 'echo',
      port: 0,
      // No killController — control endpoint should return 503.
    });
    proxyPort = await proxy.start();
  });

  afterEach(async () => {
    await proxy.close();
  });

  it('returns 503 when no kill controller is configured', async () => {
    const { status } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { all: true },
    );
    expect(status).toBe(503);
  });
});

// ---------------------------------------------------------------------------
// /control/kill — with a ConditionEnforcerPDP kill controller
// ---------------------------------------------------------------------------

describe('HttpProxy /control/kill — with kill controller', () => {
  let proxy: HttpProxy;
  let proxyPort: number;
  let pdp: ConditionEnforcerPDP;
  let policyPath: string;

  beforeEach(async () => {
    policyPath = writeTempPolicy(MINIMAL_POLICY);
    pdp = new ConditionEnforcerPDP({
      policySource: new FilePolicySource({ filePath: policyPath }),
    });
    proxy = new HttpProxy({
      command: 'echo',
      port: 0,
      pdp,
      killController: pdp,
    });
    proxyPort = await proxy.start();
  });

  afterEach(async () => {
    await proxy.close();
    pdp.dispose();
  });

  it('returns 200 and { killed: "all" } for { all: true }', async () => {
    const { status, body } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { all: true },
    );
    expect(status).toBe(200);
    expect((body as Record<string, unknown>)['killed']).toBe('all');
  });

  it('returns 200 and { killed: "<id>" } for { sessionId }', async () => {
    const { status, body } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { sessionId: 'test-session-abc' },
    );
    expect(status).toBe(200);
    expect((body as Record<string, unknown>)['killed']).toBe('test-session-abc');
  });

  it('returns 405 for GET /control/kill', async () => {
    const { status } = await httpGet(
      `http://127.0.0.1:${proxyPort}/control/kill`,
    );
    expect(status).toBe(405);
  });

  it('returns 400 for a missing sessionId and missing all flag', async () => {
    const { status } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { someOtherKey: 'value' },
    );
    expect(status).toBe(400);
  });

  it('returns 400 for a non-object body', async () => {
    const bodyStr = '"just a string"';
    const result = await new Promise<{ status: number }>((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:${proxyPort}/control/kill`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(bodyStr),
          },
        },
        (res) => {
          res.resume();
          resolve({ status: res.statusCode ?? 0 });
        },
      );
      req.on('error', reject);
      req.write(bodyStr);
      req.end();
    });
    expect(result.status).toBe(400);
  });

  it('returns 413 for an oversized body (> 16 KiB)', async () => {
    // Build a body that just exceeds the 16 KiB limit.
    const oversizedBody = Buffer.alloc(16 * 1024 + 1, 'x').toString();
    const result = await new Promise<{ status: number }>((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:${proxyPort}/control/kill`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(oversizedBody),
          },
        },
        (res) => {
          res.resume();
          resolve({ status: res.statusCode ?? 0 });
        },
      );
      req.on('error', reject);
      req.write(oversizedBody);
      req.end();
    });
    expect(result.status).toBe(413);
  });

  it('returns 413 early when Content-Length header exceeds the limit', async () => {
    const result = await new Promise<{ status: number }>((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:${proxyPort}/control/kill`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            // Claim a huge body via header — the server should reject immediately.
            'Content-Length': String(1024 * 1024),
          },
        },
        (res) => {
          res.resume();
          resolve({ status: res.statusCode ?? 0 });
        },
      );
      req.on('error', reject);
      // Don't send a body — the response should arrive before the body.
      req.end();
    });
    expect(result.status).toBe(413);
  });

  it('activates the session kill switch in the PDP', async () => {
    const sessionId = 'session-to-kill';

    // Kill the session via the control endpoint.
    const { status } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { sessionId },
    );
    expect(status).toBe(200);

    // Verify the PDP now denies calls for that session.
    const decision = await pdp.decide(
      { method: 'tools/call', params: { name: 'echo', arguments: {} } },
      { sessionId },
    );
    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('KILL_SWITCH');
  });

  it('activates the global kill switch in the PDP', async () => {
    // Kill all sessions via the control endpoint.
    const { status } = await httpPost(
      `http://127.0.0.1:${proxyPort}/control/kill`,
      { all: true },
    );
    expect(status).toBe(200);

    // Verify the PDP denies calls for any session.
    for (const sid of ['session-a', 'session-b', 'any-random-id']) {
      const decision = await pdp.decide(
        { method: 'tools/call', params: { name: 'echo', arguments: {} } },
        { sessionId: sid },
      );
      expect(decision.allow).toBe(false);
      expect(decision.denialCode).toBe('KILL_SWITCH');
    }
  });
});

// ---------------------------------------------------------------------------
// euno-mcp kill — subprocess tests
// ---------------------------------------------------------------------------

/** Absolute path to ts-node register hook. */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/** Absolute path to the CLI entry point. */
const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');

/**
 * Invoke `euno-mcp kill <target> [extraArgs...]` as a subprocess (via ts-node).
 *
 * Uses async `spawn` (not `spawnSync`) so that the Node.js event loop is not
 * blocked while the subprocess is running.  This is required for tests where
 * the proxy runs in the same process — `spawnSync` would deadlock because the
 * proxy's HTTP server cannot process the incoming connection while the event
 * loop is frozen.
 */
function runKillAsync(
  target: string,
  extraArgs: string[] = [],
  timeoutMs = 15_000,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const proc = childProcess.spawn(
      process.execPath,
      ['--require', TS_NODE_REGISTER, CLI, 'kill', target, ...extraArgs],
      { encoding: 'utf8' } as childProcess.SpawnOptions,
    );

    let stdout = '';
    let stderr = '';
    (proc.stdout as NodeJS.ReadableStream | null)?.on('data', (d: Buffer | string) => {
      stdout += d.toString();
    });
    (proc.stderr as NodeJS.ReadableStream | null)?.on('data', (d: Buffer | string) => {
      stderr += d.toString();
    });

    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(new Error(`runKillAsync timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    proc.on('close', (code: number | null) => {
      clearTimeout(timer);
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
    proc.on('error', (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Invoke `euno-mcp kill <target> [extraArgs...]` synchronously.
 *
 * Use only for tests that do NOT require a running proxy in the same process
 * (e.g. invalid port format, unreachable proxy).  Synchronous invocation is
 * safe there because the subprocess either fails immediately (ECONNREFUSED)
 * or never connects.
 */
function runKillSync(
  target: string,
  extraArgs: string[] = [],
): { exitCode: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(
    process.execPath,
    ['--require', TS_NODE_REGISTER, CLI, 'kill', target, ...extraArgs],
    { encoding: 'utf8', timeout: 15_000 },
  );
  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

describe('euno-mcp kill CLI — subprocess', () => {
  let proxy: HttpProxy;
  let proxyPort: number;
  let pdp: ConditionEnforcerPDP;

  beforeEach(async () => {
    const policyPath = writeTempPolicy(MINIMAL_POLICY);
    pdp = new ConditionEnforcerPDP({
      policySource: new FilePolicySource({ filePath: policyPath }),
    });
    proxy = new HttpProxy({
      command: 'echo',
      port: 0,
      pdp,
      killController: pdp,
    });
    proxyPort = await proxy.start();
  });

  afterEach(async () => {
    await proxy.close();
    pdp.dispose();
  });

  it('exits 0 and prints global kill confirmation for "kill all"', async () => {
    const { exitCode, stdout } = await runKillAsync('all', ['--port', String(proxyPort)]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Global kill switch activated');
  }, 15_000);

  it('exits 0 and prints session kill confirmation for a specific session id', async () => {
    const { exitCode, stdout } = await runKillAsync(
      'my-session-xyz',
      ['--port', String(proxyPort)],
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Kill switch activated for session my-session-xyz');
  }, 15_000);

  it('exits 1 and prints "Invalid --port value" for a non-numeric port', () => {
    // Does not connect to the proxy — safe to use synchronous spawn.
    const { exitCode, stderr } = runKillSync('all', ['--port', 'not-a-port']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Invalid --port value');
  });

  it('exits 1 and prints "Could not reach the proxy" when no proxy is listening', () => {
    // Fails immediately with ECONNREFUSED — safe to use synchronous spawn.
    const { exitCode, stderr } = runKillSync('all', ['--port', '19991']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Could not reach the proxy');
  });
});

// ---------------------------------------------------------------------------
// KillController interface satisfaction by ConditionEnforcerPDP
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — KillController interface', () => {
  it('satisfies the KillController interface', () => {
    const policyPath = writeTempPolicy(`
agentId: iface-test
name: Interface Test
version: 0.1.0
requiredCapabilities: []
`.trim());
    const pdp = new ConditionEnforcerPDP({
      policySource: new FilePolicySource({ filePath: policyPath }),
    });

    // Type-check: pdp is assignable to KillController.
    const controller: KillController = pdp;
    expect(typeof controller.killSession).toBe('function');
    expect(typeof controller.killAll).toBe('function');

    pdp.dispose();
  });
});

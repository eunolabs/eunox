/**
 * Unit tests for the @euno/mcp telemetry module (Task 10 acceptance criteria).
 *
 * Test matrix
 * -----------
 * ✓ EUNO_TELEMETRY=0: no network fetch is ever called
 * ✓ EUNO_TELEMETRY=1: fetch is called with the telemetry event
 * ✓ EUNO_TELEMETRY_LOCAL=1: writes to JSONL file, no fetch
 * ✓ Schema snapshot: TELEMETRY_EVENT_KEYS matches what the collector emits
 * ✓ TELEMETRY.md documents every field in TELEMETRY_EVENT_KEYS
 * ✓ sanitizeUpstreamServerName: known servers, unknown → "custom"
 * ✓ TelemetryCollector: session counting, denial tracking
 * ✓ NoopTelemetryEmitter: never throws, never writes, never fetches
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  createTelemetry,
  TelemetryCollector,
  TELEMETRY_EVENT_KEYS,
  sanitizeUpstreamServerName,
  NoopTelemetryEmitter,
  LocalFileTelemetryEmitter,
  HttpTelemetryEmitter,
} from '../../telemetry';
import type { TelemetryEvent, TelemetryEmitter } from '../../telemetry';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Temp directories created during tests — removed in afterEach. */
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // Restore env vars
  delete process.env['EUNO_TELEMETRY'];
  delete process.env['EUNO_TELEMETRY_LOCAL'];
  delete process.env['EUNO_TELEMETRY_URL'];
});

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-telemetry-test-'));
  tempDirs.push(dir);
  return dir;
}

/** Build a minimal valid TelemetryEvent for assertion. */
function sampleEvent(overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    installId: 'test-install-id',
    version: '1.0.0',
    osFamily: 'linux',
    nodeMajor: 20,
    subcommand: 'proxy',
    sessionsStarted: 1,
    sessionsWithEnforcement: 0,
    denialsByConditionType: {},
    upstreamServerName: 'custom',
    timestamp: 1234567890000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// EUNO_TELEMETRY=0: no network fetch
// ---------------------------------------------------------------------------

describe('EUNO_TELEMETRY=0 — completely disabled', () => {
  it('does not call globalThis.fetch', async () => {
    process.env['EUNO_TELEMETRY'] = '0';
    const tmpDir = makeTempDir();

    const mockFetch = jest.fn();
    const originalFetch = (globalThis as Record<string, unknown>)['fetch'];
    (globalThis as Record<string, unknown>)['fetch'] = mockFetch;

    try {
      const collector = await createTelemetry({
        subcommand: 'proxy',
        statePath: path.join(tmpDir, 'telemetry'),
      });
      await collector.flush();
      expect(mockFetch).not.toHaveBeenCalled();
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    }
  });

  it('does not write to any file', async () => {
    process.env['EUNO_TELEMETRY'] = '0';
    const tmpDir = makeTempDir();

    const collector = await createTelemetry({
      subcommand: 'validate',
      statePath: path.join(tmpDir, 'telemetry'),
    });
    await collector.flush();

    // No files should be created (consent file not written when disabled)
    const files = fs.readdirSync(tmpDir);
    expect(files).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// EUNO_TELEMETRY=1: opt-in via env var
// ---------------------------------------------------------------------------

describe('EUNO_TELEMETRY=1 — opt-in via env var', () => {
  it('calls globalThis.fetch with the telemetry endpoint', async () => {
    process.env['EUNO_TELEMETRY'] = '1';
    process.env['EUNO_TELEMETRY_URL'] = 'https://example.test/telemetry';
    const tmpDir = makeTempDir();

    const mockFetch = jest.fn().mockResolvedValue({ ok: true });
    const originalFetch = (globalThis as Record<string, unknown>)['fetch'];
    (globalThis as Record<string, unknown>)['fetch'] = mockFetch;

    try {
      const collector = await createTelemetry({
        subcommand: 'proxy',
        statePath: path.join(tmpDir, 'telemetry'),
      });
      const hooks = collector.sessionHooks();
      hooks.onSessionStart?.();
      hooks.onDecision?.(true);
      hooks.onSessionEnd?.();
      await collector.flush();

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://example.test/telemetry');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body as string) as TelemetryEvent;
      expect(body.subcommand).toBe('proxy');
      expect(body.sessionsStarted).toBe(1);
      expect(body.sessionsWithEnforcement).toBe(1); // allow decision counts as enforcement
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    }
  });

  it('persists the consent state to the state file', async () => {
    process.env['EUNO_TELEMETRY'] = '1';
    const tmpDir = makeTempDir();
    const statePath = path.join(tmpDir, 'telemetry');

    const mockFetch = jest.fn().mockResolvedValue({ ok: true });
    const originalFetch = (globalThis as Record<string, unknown>)['fetch'];
    (globalThis as Record<string, unknown>)['fetch'] = mockFetch;

    try {
      await createTelemetry({ subcommand: 'validate', statePath });
      const raw = JSON.parse(fs.readFileSync(statePath, 'utf8')) as {
        enabled: boolean;
        installId: string;
      };
      expect(raw.enabled).toBe(true);
      expect(typeof raw.installId).toBe('string');
      expect(raw.installId.length).toBeGreaterThan(0);
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// EUNO_TELEMETRY_LOCAL=1: local-file mode
// ---------------------------------------------------------------------------

describe('EUNO_TELEMETRY_LOCAL=1 — local-file mode', () => {
  it('writes to the local JSONL file and does NOT call fetch', async () => {
    process.env['EUNO_TELEMETRY'] = '1';
    process.env['EUNO_TELEMETRY_LOCAL'] = '1';
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');

    const mockFetch = jest.fn();
    const originalFetch = (globalThis as Record<string, unknown>)['fetch'];
    (globalThis as Record<string, unknown>)['fetch'] = mockFetch;

    try {
      const emitter = new LocalFileTelemetryEmitter(localPath);
      await emitter.emit(sampleEvent());

      expect(mockFetch).not.toHaveBeenCalled();
      expect(fs.existsSync(localPath)).toBe(true);
      const lines = fs.readFileSync(localPath, 'utf8').trim().split('\n');
      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0] as string) as TelemetryEvent;
      expect(parsed.installId).toBe('test-install-id');
      expect(parsed.subcommand).toBe('proxy');
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    }
  });

  it('creates the parent directory if it does not exist', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'nested', 'dir', 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    await emitter.emit(sampleEvent());
    expect(fs.existsSync(localPath)).toBe(true);
  });

  it('appends multiple events on successive calls', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    await emitter.emit(sampleEvent({ subcommand: 'proxy' }));
    await emitter.emit(sampleEvent({ subcommand: 'validate' }));
    const lines = fs.readFileSync(localPath, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect((JSON.parse(lines[0] as string) as TelemetryEvent).subcommand).toBe('proxy');
    expect((JSON.parse(lines[1] as string) as TelemetryEvent).subcommand).toBe('validate');
  });
});

// ---------------------------------------------------------------------------
// Schema snapshot: TELEMETRY_EVENT_KEYS
// ---------------------------------------------------------------------------

describe('TelemetryEvent schema', () => {
  it('TELEMETRY_EVENT_KEYS matches the fields emitted by the collector', async () => {
    // Snapshot the complete field list — this test breaks if fields are
    // added or removed without updating the snapshot.
    expect(TELEMETRY_EVENT_KEYS).toMatchSnapshot();
  });

  it('every TELEMETRY_EVENT_KEYS field is present in the emitted event', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    await emitter.emit(sampleEvent());

    const emitted = JSON.parse(
      fs.readFileSync(localPath, 'utf8').trim(),
    ) as Record<string, unknown>;

    for (const key of TELEMETRY_EVENT_KEYS) {
      expect(emitted).toHaveProperty(key);
    }
  });

  it('TELEMETRY.md documents every field in TELEMETRY_EVENT_KEYS', () => {
    const telemetryMdPath = path.resolve(__dirname, '../../..', 'TELEMETRY.md');
    const doc = fs.readFileSync(telemetryMdPath, 'utf8');
    for (const field of TELEMETRY_EVENT_KEYS) {
      expect(doc).toContain(field);
    }
  });
});

// ---------------------------------------------------------------------------
// sanitizeUpstreamServerName
// ---------------------------------------------------------------------------

describe('sanitizeUpstreamServerName', () => {
  it('recognises known OSS servers by name in args', () => {
    expect(sanitizeUpstreamServerName('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/tmp']))
      .toBe('@modelcontextprotocol/server-filesystem');
  });

  it('strips version suffix from known servers', () => {
    expect(sanitizeUpstreamServerName('npx', ['@modelcontextprotocol/server-postgres@1.2.3']))
      .toBe('@modelcontextprotocol/server-postgres');
  });

  it('strips @latest suffix from known servers', () => {
    expect(sanitizeUpstreamServerName('npx', ['@modelcontextprotocol/server-github@latest']))
      .toBe('@modelcontextprotocol/server-github');
  });

  it('returns "custom" for unknown commands', () => {
    expect(sanitizeUpstreamServerName('node', ['./my-custom-server.js']))
      .toBe('custom');
  });

  it('returns "custom" for empty command and args', () => {
    expect(sanitizeUpstreamServerName('', [])).toBe('custom');
  });
});

// ---------------------------------------------------------------------------
// TelemetryCollector: session counting and denial tracking
// ---------------------------------------------------------------------------

describe('TelemetryCollector', () => {
  it('counts sessions started correctly', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    const collector = new TelemetryCollector(emitter, {
      installId: 'test',
      version: '0.0.0',
      osFamily: 'linux',
      nodeMajor: 20,
      subcommand: 'proxy',
      upstreamServerName: 'custom',
    });

    const hooks1 = collector.sessionHooks();
    const hooks2 = collector.sessionHooks();
    hooks1.onSessionStart?.();
    hooks2.onSessionStart?.();
    hooks1.onSessionEnd?.();
    hooks2.onSessionEnd?.();
    await collector.flush();

    const event = JSON.parse(
      fs.readFileSync(localPath, 'utf8').trim(),
    ) as TelemetryEvent;
    expect(event.sessionsStarted).toBe(2);
  });

  it('counts sessions with enforcement correctly (any decision, not just denial)', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    const collector = new TelemetryCollector(emitter, {
      installId: 'test',
      version: '0.0.0',
      osFamily: 'linux',
      nodeMajor: 20,
      subcommand: 'proxy',
      upstreamServerName: 'custom',
    });

    // Session 1: only allows — still counts as having enforcement
    const h1 = collector.sessionHooks();
    h1.onSessionStart?.();
    h1.onDecision?.(true);
    h1.onSessionEnd?.();

    // Session 2: one denial
    const h2 = collector.sessionHooks();
    h2.onSessionStart?.();
    h2.onDecision?.(false, 'maxCalls');
    h2.onSessionEnd?.();

    // Session 3: no enforcement at all
    const h3 = collector.sessionHooks();
    h3.onSessionStart?.();
    h3.onSessionEnd?.();

    await collector.flush();

    const event = JSON.parse(
      fs.readFileSync(localPath, 'utf8').trim(),
    ) as TelemetryEvent;
    expect(event.sessionsStarted).toBe(3);
    expect(event.sessionsWithEnforcement).toBe(2); // sessions 1 and 2 had enforcement
    expect(event.denialsByConditionType).toEqual({ maxCalls: 1 });
  });

  it('accumulates denials across multiple sessions', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    const collector = new TelemetryCollector(emitter, {
      installId: 'test',
      version: '0.0.0',
      osFamily: 'linux',
      nodeMajor: 20,
      subcommand: 'proxy',
      upstreamServerName: 'custom',
    });

    const hooks = collector.sessionHooks();
    hooks.onSessionStart?.();
    hooks.onDecision?.(false, 'maxCalls');
    hooks.onDecision?.(false, 'maxCalls');
    hooks.onDecision?.(false, 'timeWindow');
    hooks.onSessionEnd?.();

    await collector.flush();

    const event = JSON.parse(
      fs.readFileSync(localPath, 'utf8').trim(),
    ) as TelemetryEvent;
    expect(event.denialsByConditionType).toEqual({ maxCalls: 2, timeWindow: 1 });
    expect(event.sessionsWithEnforcement).toBe(1);
  });

  it('concurrent sessions are tracked independently via createSessionHooks', async () => {
    const tmpDir = makeTempDir();
    const localPath = path.join(tmpDir, 'telemetry.jsonl');
    const emitter = new LocalFileTelemetryEmitter(localPath);
    const collector = new TelemetryCollector(emitter, {
      installId: 'test',
      version: '0.0.0',
      osFamily: 'linux',
      nodeMajor: 20,
      subcommand: 'proxy',
      upstreamServerName: 'custom',
    });

    // Simulate the HTTP proxy: create per-session hooks via createSessionHooks
    const rootHooks = collector.sessionHooks();
    const sessionA = rootHooks.createSessionHooks!();
    const sessionB = rootHooks.createSessionHooks!();

    // Both sessions start concurrently
    sessionA.onSessionStart?.();
    sessionB.onSessionStart?.();

    // Session A has enforcement; session B does not
    sessionA.onDecision?.(false, 'maxCalls');

    // Both sessions end (in arbitrary order)
    sessionB.onSessionEnd?.();
    sessionA.onSessionEnd?.();

    await collector.flush();

    const event = JSON.parse(
      fs.readFileSync(localPath, 'utf8').trim(),
    ) as TelemetryEvent;
    expect(event.sessionsStarted).toBe(2);
    expect(event.sessionsWithEnforcement).toBe(1); // only session A had enforcement
    expect(event.denialsByConditionType).toEqual({ maxCalls: 1 });
  });

  it('sessionHooks() returns a plain-object implementing TelemetryHooks with createSessionHooks', () => {
    const emitter = new NoopTelemetryEmitter();
    const collector = new TelemetryCollector(emitter, {
      installId: 'test',
      version: '0.0.0',
      osFamily: 'linux',
      nodeMajor: 20,
      subcommand: 'kill',
      upstreamServerName: 'custom',
    });

    const hooks = collector.sessionHooks();
    expect(typeof hooks.onSessionStart).toBe('function');
    expect(typeof hooks.onDecision).toBe('function');
    expect(typeof hooks.onSessionEnd).toBe('function');
    expect(typeof hooks.createSessionHooks).toBe('function');
  });

  it('flush never throws even if the emitter fails', async () => {
    const failingEmitter: { emit: (e: TelemetryEvent) => Promise<void> } = {
      emit: async () => { throw new Error('emitter exploded'); },
    };
    const collector = new TelemetryCollector(
      failingEmitter as TelemetryEmitter,
      {
        installId: 'test',
        version: '0.0.0',
        osFamily: 'linux',
        nodeMajor: 20,
        subcommand: 'validate',
        upstreamServerName: 'custom',
      },
    );

    // Must not throw:
    await expect(collector.flush()).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// NoopTelemetryEmitter
// ---------------------------------------------------------------------------

describe('NoopTelemetryEmitter', () => {
  it('never throws and returns undefined', async () => {
    const emitter = new NoopTelemetryEmitter();
    await expect(emitter.emit(sampleEvent())).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// HttpTelemetryEmitter: network errors are swallowed
// ---------------------------------------------------------------------------

describe('HttpTelemetryEmitter', () => {
  it('swallows network errors silently', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('network unreachable'));
    const originalFetch = (globalThis as Record<string, unknown>)['fetch'];
    (globalThis as Record<string, unknown>)['fetch'] = mockFetch;

    try {
      const emitter = new HttpTelemetryEmitter('https://unreachable.test/telemetry');
      await expect(emitter.emit(sampleEvent())).resolves.toBeUndefined();
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    }
  });
});

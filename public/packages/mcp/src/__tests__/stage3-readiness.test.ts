/**
 * Unit tests for scripts/stage3-readiness.ts — Stage 3 gate evaluation logic.
 *
 * Test matrix
 * -----------
 * evaluateCriterion1
 *   ✓ returns UNKNOWN when stats is null (no API configured)
 *   ✓ returns false when both installs and peakSessions are below thresholds
 *   ✓ returns false when distinctInstalls14d < threshold and peakSessions < threshold
 *   ✓ returns UNKNOWN when installs signal is present but confirmedTeams < threshold
 *   ✓ returns UNKNOWN when peakSessions signal is present but confirmedTeams < threshold
 *   ✓ returns true when confirmedTeams >= C1_THRESHOLD_TEAMS
 *   ✓ returns true when confirmedTeams exactly equals C1_THRESHOLD_TEAMS
 *   ✓ detail string includes distinctInstalls14d, installsWithPeakSessions3Plus, confirmedTeams when stats available
 *   ✓ detail string mentions EUNO_TELEMETRY_API when no API configured
 *   ✓ detail string mentions API unreachable when API configured but null stats
 *   ✓ trackingPointer includes API URL when configured
 *   ✓ trackingPointer mentions CRM/Notion when no API configured
 *   ✓ label is 'C1 — Team adoption'
 *
 * evaluateCriterion2
 *   ✓ always returns UNKNOWN
 *   ✓ label is 'C2 — Feature asks'
 *   ✓ detail mentions the C2_THRESHOLD_ASKS count
 *   ✓ detail mentions "share this policy across the team"
 *   ✓ detail mentions "see what the agent did from my laptop"
 *   ✓ trackingPointer mentions stage-3-signal label
 *   ✓ trackingPointer mentions stage-3-signal.md template
 *
 * evaluateCriterion3
 *   ✓ always returns UNKNOWN
 *   ✓ label is 'C3 — Hand-rolled audit'
 *   ✓ detail mentions cross-process MCP enforcement
 *   ✓ trackingPointer mentions CRM/Notion
 *
 * buildCriteria
 *   ✓ returns array of exactly 3 criteria
 *   ✓ first criterion is C1 (Team adoption)
 *   ✓ second criterion is C2 (Feature asks)
 *   ✓ third criterion is C3 (Hand-rolled audit)
 *   ✓ passes stats and apiUrl to C1
 *   ✓ C2 and C3 are always UNKNOWN regardless of stats
 *
 * computeOverallResult
 *   ✓ all UNKNOWN criteria → status 'unknown', exitCode 2
 *   ✓ all true criteria → status 'ready', exitCode 0
 *   ✓ one false criterion → status 'not-ready', exitCode 1
 *   ✓ mix of true and false → status 'not-ready', exitCode 1
 *   ✓ mix of true and UNKNOWN → status 'unknown', exitCode 2
 *   ✓ mix of false and UNKNOWN → status 'not-ready', exitCode 1
 *   ✓ single true criterion → status 'ready', exitCode 0
 *   ✓ single false criterion → status 'not-ready', exitCode 1
 *   ✓ single UNKNOWN criterion → status 'unknown', exitCode 2
 *   ✓ empty criteria array → status 'ready', exitCode 0
 *
 * queryTelemetry
 *   ✓ returns null when apiUrl is empty string
 *   ✓ returns null when HTTP request fails (connection refused)
 *   ✓ returns null when API returns non-2xx status
 *   ✓ returns parsed stats when API returns valid JSON
 *   ✓ returns null when API returns invalid JSON
 *
 * fetchJson
 *   ✓ rejects when server returns 404
 *   ✓ rejects when server returns 500
 *   ✓ rejects on parse error (non-JSON response)
 *   ✓ resolves with parsed object on 200 response
 *   ✓ times out when server does not respond within timeoutMs
 *
 * Constants
 *   ✓ C1_THRESHOLD_TEAMS is 5
 *   ✓ C1_THRESHOLD_INSTALLS_SIGNAL is 5
 *   ✓ C1_THRESHOLD_DISTINCT_INSTALLS is 5
 *   ✓ C2_THRESHOLD_ASKS is 3
 */

import * as net from 'node:net';
import * as http from 'node:http';

// Import the exported functions from the stage3-readiness script.
// We use a require with ts-jest transpiling the script module.
// The script uses `require.main === module` guard so the main() is NOT called.
import {
  evaluateCriterion1,
  evaluateCriterion2,
  evaluateCriterion3,
  buildCriteria,
  computeOverallResult,
  queryTelemetry,
  fetchJson,
  C1_THRESHOLD_TEAMS,
  C1_THRESHOLD_INSTALLS_SIGNAL,
  C1_THRESHOLD_DISTINCT_INSTALLS,
  C2_THRESHOLD_ASKS,
  type Stage3TelemetryStats,
  type CriterionResult,
} from '../../../../../scripts/stage3-readiness';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStats(overrides: Partial<Stage3TelemetryStats> = {}): Stage3TelemetryStats {
  return {
    distinctInstalls14d: 0,
    installsWithPeakSessions3Plus: 0,
    confirmedTeams: 0,
    ...overrides,
  };
}

function makeMockHttpServer(
  statusCode: number,
  body: string,
  contentType = 'application/json',
): Promise<{ server: http.Server; url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(statusCode, { 'Content-Type': contentType });
      res.end(body);
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as net.AddressInfo;
      const url = `http://127.0.0.1:${address.port}`;
      resolve({
        server,
        url,
        close: () =>
          new Promise<void>((r, rj) =>
            server.close((err) => (err ? rj(err) : r())),
          ),
      });
    });
  });
}

// A server that accepts the connection but never sends a response (for timeout tests).
function makeHangingServer(): Promise<{ server: net.Server; url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const sockets: net.Socket[] = [];
    const server = net.createServer((socket) => {
      sockets.push(socket);
      // Read incoming bytes but never respond.
      socket.resume();
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as net.AddressInfo;
      const url = `http://127.0.0.1:${address.port}`;
      resolve({
        server,
        url,
        close: () =>
          new Promise<void>((r) => {
            for (const s of sockets) s.destroy();
            server.close(() => r());
          }),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// evaluateCriterion1
// ---------------------------------------------------------------------------

describe('evaluateCriterion1', () => {
  it('returns UNKNOWN when stats is null (no API configured)', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns false when both installs and peakSessions are below thresholds', () => {
    const result = evaluateCriterion1(
      makeStats({ distinctInstalls14d: 0, installsWithPeakSessions3Plus: 0, confirmedTeams: 0 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(false);
  });

  it('returns false when distinctInstalls14d < threshold and peakSessions < threshold', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctInstalls14d: C1_THRESHOLD_DISTINCT_INSTALLS - 1,
        installsWithPeakSessions3Plus: C1_THRESHOLD_INSTALLS_SIGNAL - 1,
        confirmedTeams: 0,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe(false);
  });

  it('returns UNKNOWN when installs signal is present but confirmedTeams < threshold', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctInstalls14d: C1_THRESHOLD_DISTINCT_INSTALLS + 10,
        installsWithPeakSessions3Plus: 0,
        confirmedTeams: C1_THRESHOLD_TEAMS - 1,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns UNKNOWN when peakSessions signal is present but confirmedTeams < threshold', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctInstalls14d: 0,
        installsWithPeakSessions3Plus: C1_THRESHOLD_INSTALLS_SIGNAL + 1,
        confirmedTeams: 2,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns true when confirmedTeams >= C1_THRESHOLD_TEAMS', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctInstalls14d: 10,
        installsWithPeakSessions3Plus: 7,
        confirmedTeams: C1_THRESHOLD_TEAMS,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('returns true when confirmedTeams exactly equals C1_THRESHOLD_TEAMS', () => {
    const result = evaluateCriterion1(
      makeStats({ distinctInstalls14d: 10, installsWithPeakSessions3Plus: 5, confirmedTeams: C1_THRESHOLD_TEAMS }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('returns true when confirmedTeams far exceeds threshold', () => {
    const result = evaluateCriterion1(
      makeStats({ distinctInstalls14d: 100, installsWithPeakSessions3Plus: 50, confirmedTeams: 20 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('detail string includes distinctInstalls14d, installsWithPeakSessions3Plus, confirmedTeams when stats available', () => {
    const stats = makeStats({ distinctInstalls14d: 12, installsWithPeakSessions3Plus: 7, confirmedTeams: 3 });
    const result = evaluateCriterion1(stats, 'http://api.example.com');
    expect(result.detail).toContain('12');
    expect(result.detail).toContain('7');
    expect(result.detail).toContain('3');
  });

  it('detail string mentions EUNO_TELEMETRY_API when no API configured', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.detail).toContain('EUNO_TELEMETRY_API');
  });

  it('detail string mentions API unreachable when API configured but null stats', () => {
    const result = evaluateCriterion1(null, 'http://api.example.com');
    expect(result.detail).toContain('unreachable');
  });

  it('trackingPointer includes API URL when configured', () => {
    const stats = makeStats({ distinctInstalls14d: 10, installsWithPeakSessions3Plus: 5, confirmedTeams: 5 });
    const result = evaluateCriterion1(stats, 'http://my-api.example.com');
    expect(result.trackingPointer).toContain('http://my-api.example.com');
  });

  it('trackingPointer mentions CRM/Notion when no API configured', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.trackingPointer).toContain('Notion');
  });

  it('label is C1 — Team adoption', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.label).toBe('C1 — Team adoption');
  });

  it('detail includes threshold count for confirmed teams', () => {
    const stats = makeStats({ distinctInstalls14d: 10, installsWithPeakSessions3Plus: 5, confirmedTeams: 3 });
    const result = evaluateCriterion1(stats, 'http://api.example.com');
    expect(result.detail).toContain(`${C1_THRESHOLD_TEAMS}`);
  });
});

// ---------------------------------------------------------------------------
// evaluateCriterion2
// ---------------------------------------------------------------------------

describe('evaluateCriterion2', () => {
  it('always returns UNKNOWN', () => {
    expect(evaluateCriterion2().met).toBe('UNKNOWN');
  });

  it('label is C2 — Feature asks', () => {
    expect(evaluateCriterion2().label).toBe('C2 — Feature asks');
  });

  it('detail mentions the C2_THRESHOLD_ASKS count', () => {
    expect(evaluateCriterion2().detail).toContain(`${C2_THRESHOLD_ASKS}`);
  });

  it('detail mentions "share this policy across the team"', () => {
    expect(evaluateCriterion2().detail).toContain('share this policy across');
  });

  it('detail mentions "see what the agent did from my laptop"', () => {
    expect(evaluateCriterion2().detail).toContain('see what the agent did from my laptop');
  });

  it('trackingPointer mentions stage-3-signal label', () => {
    expect(evaluateCriterion2().trackingPointer).toContain('stage-3-signal');
  });

  it('trackingPointer mentions stage-3-signal.md template', () => {
    expect(evaluateCriterion2().trackingPointer).toContain('stage-3-signal.md');
  });

  it('result is deterministic (same value on every call)', () => {
    const r1 = evaluateCriterion2();
    const r2 = evaluateCriterion2();
    expect(r1).toEqual(r2);
  });
});

// ---------------------------------------------------------------------------
// evaluateCriterion3
// ---------------------------------------------------------------------------

describe('evaluateCriterion3', () => {
  it('always returns UNKNOWN', () => {
    expect(evaluateCriterion3().met).toBe('UNKNOWN');
  });

  it('label is C3 — Hand-rolled audit', () => {
    expect(evaluateCriterion3().label).toBe('C3 — Hand-rolled audit');
  });

  it('detail mentions cross-process MCP enforcement', () => {
    expect(evaluateCriterion3().detail).toContain('cross-process');
  });

  it('detail mentions at least 1 conversation', () => {
    expect(evaluateCriterion3().detail).toContain('1');
  });

  it('trackingPointer mentions CRM/Notion', () => {
    expect(evaluateCriterion3().trackingPointer).toContain('Notion');
  });

  it('result is deterministic (same value on every call)', () => {
    const r1 = evaluateCriterion3();
    const r2 = evaluateCriterion3();
    expect(r1).toEqual(r2);
  });
});

// ---------------------------------------------------------------------------
// buildCriteria
// ---------------------------------------------------------------------------

describe('buildCriteria', () => {
  it('returns array of exactly 3 criteria', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria).toHaveLength(3);
  });

  it('first criterion is C1 — Team adoption', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[0]!.label).toBe('C1 — Team adoption');
  });

  it('second criterion is C2 — Feature asks', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[1]!.label).toBe('C2 — Feature asks');
  });

  it('third criterion is C3 — Hand-rolled audit', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[2]!.label).toBe('C3 — Hand-rolled audit');
  });

  it('passes stats and apiUrl to C1 (met=false when stats indicate not met)', () => {
    const stats = makeStats({ distinctInstalls14d: 0, installsWithPeakSessions3Plus: 0, confirmedTeams: 0 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[0]!.met).toBe(false);
  });

  it('C2 is always UNKNOWN regardless of stats', () => {
    const stats = makeStats({ distinctInstalls14d: 100, installsWithPeakSessions3Plus: 50, confirmedTeams: 10 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[1]!.met).toBe('UNKNOWN');
  });

  it('C3 is always UNKNOWN regardless of stats', () => {
    const stats = makeStats({ distinctInstalls14d: 100, installsWithPeakSessions3Plus: 50, confirmedTeams: 10 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[2]!.met).toBe('UNKNOWN');
  });

  it('C1 is UNKNOWN when stats is null', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[0]!.met).toBe('UNKNOWN');
  });

  it('C1 is true when confirmedTeams meets threshold', () => {
    const stats = makeStats({ distinctInstalls14d: 10, installsWithPeakSessions3Plus: 6, confirmedTeams: 5 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[0]!.met).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeOverallResult
// ---------------------------------------------------------------------------

describe('computeOverallResult', () => {
  function makeCriterion(met: boolean | 'UNKNOWN'): CriterionResult {
    return { met, label: 'Test', detail: '', trackingPointer: '' };
  }

  it('all UNKNOWN criteria → status "unknown", exitCode 2', () => {
    const criteria = [makeCriterion('UNKNOWN'), makeCriterion('UNKNOWN'), makeCriterion('UNKNOWN')];
    expect(computeOverallResult(criteria)).toEqual({ status: 'unknown', exitCode: 2 });
  });

  it('all true criteria → status "ready", exitCode 0', () => {
    const criteria = [makeCriterion(true), makeCriterion(true), makeCriterion(true)];
    expect(computeOverallResult(criteria)).toEqual({ status: 'ready', exitCode: 0 });
  });

  it('one false criterion → status "not-ready", exitCode 1', () => {
    const criteria = [makeCriterion(true), makeCriterion(false), makeCriterion('UNKNOWN')];
    expect(computeOverallResult(criteria)).toEqual({ status: 'not-ready', exitCode: 1 });
  });

  it('mix of true and false → status "not-ready", exitCode 1', () => {
    const criteria = [makeCriterion(true), makeCriterion(false), makeCriterion(true)];
    expect(computeOverallResult(criteria)).toEqual({ status: 'not-ready', exitCode: 1 });
  });

  it('mix of true and UNKNOWN → status "unknown", exitCode 2', () => {
    const criteria = [makeCriterion(true), makeCriterion('UNKNOWN')];
    expect(computeOverallResult(criteria)).toEqual({ status: 'unknown', exitCode: 2 });
  });

  it('mix of false and UNKNOWN → status "not-ready", exitCode 1 (false takes precedence)', () => {
    const criteria = [makeCriterion(false), makeCriterion('UNKNOWN')];
    expect(computeOverallResult(criteria)).toEqual({ status: 'not-ready', exitCode: 1 });
  });

  it('single true criterion → status "ready", exitCode 0', () => {
    expect(computeOverallResult([makeCriterion(true)])).toEqual({ status: 'ready', exitCode: 0 });
  });

  it('single false criterion → status "not-ready", exitCode 1', () => {
    expect(computeOverallResult([makeCriterion(false)])).toEqual({ status: 'not-ready', exitCode: 1 });
  });

  it('single UNKNOWN criterion → status "unknown", exitCode 2', () => {
    expect(computeOverallResult([makeCriterion('UNKNOWN')])).toEqual({ status: 'unknown', exitCode: 2 });
  });

  it('empty criteria array → status "ready", exitCode 0 (vacuously all met)', () => {
    expect(computeOverallResult([])).toEqual({ status: 'ready', exitCode: 0 });
  });

  it('two false criteria → notMetCount is reflected correctly', () => {
    const criteria = [makeCriterion(false), makeCriterion(false), makeCriterion(true)];
    expect(computeOverallResult(criteria)).toEqual({ status: 'not-ready', exitCode: 1 });
  });

  it('all false criteria → status "not-ready", exitCode 1', () => {
    const criteria = [makeCriterion(false), makeCriterion(false), makeCriterion(false)];
    expect(computeOverallResult(criteria)).toEqual({ status: 'not-ready', exitCode: 1 });
  });
});

// ---------------------------------------------------------------------------
// queryTelemetry
// ---------------------------------------------------------------------------

describe('queryTelemetry', () => {
  it('returns null when apiUrl is empty string', async () => {
    const result = await queryTelemetry('');
    expect(result).toBeNull();
  });

  it('returns null when HTTP request fails (connection refused)', async () => {
    // Port 1 is almost certainly not listening.
    const result = await queryTelemetry('http://127.0.0.1:1');
    expect(result).toBeNull();
  });

  it('returns null when API returns non-2xx status', async () => {
    const { url, close } = await makeMockHttpServer(404, '{"error":"not found"}');
    try {
      const result = await queryTelemetry(url);
      expect(result).toBeNull();
    } finally {
      await close();
    }
  });

  it('returns null when API returns 500', async () => {
    const { url, close } = await makeMockHttpServer(500, 'Internal Server Error', 'text/plain');
    try {
      const result = await queryTelemetry(url);
      expect(result).toBeNull();
    } finally {
      await close();
    }
  });

  it('returns parsed stats when API returns valid JSON', async () => {
    const statsBody: Stage3TelemetryStats = {
      distinctInstalls14d: 7,
      installsWithPeakSessions3Plus: 4,
      confirmedTeams: 2,
    };
    const { url, close } = await makeMockHttpServer(200, JSON.stringify(statsBody));
    try {
      const result = await queryTelemetry(url);
      expect(result).toEqual(statsBody);
    } finally {
      await close();
    }
  });

  it('returns null when API returns invalid JSON', async () => {
    const { url, close } = await makeMockHttpServer(200, 'this is not json');
    try {
      const result = await queryTelemetry(url);
      expect(result).toBeNull();
    } finally {
      await close();
    }
  });

  it('returns null when API returns empty body', async () => {
    const { url, close } = await makeMockHttpServer(200, '');
    try {
      const result = await queryTelemetry(url);
      expect(result).toBeNull();
    } finally {
      await close();
    }
  });
});

// ---------------------------------------------------------------------------
// fetchJson
// ---------------------------------------------------------------------------

describe('fetchJson', () => {
  it('rejects when server returns 404', async () => {
    const { url, close } = await makeMockHttpServer(404, '{"error":"not found"}');
    try {
      await expect(fetchJson(`${url}/v1/stats/stage3-gate`)).rejects.toThrow(/HTTP 404/);
    } finally {
      await close();
    }
  });

  it('rejects when server returns 500', async () => {
    const { url, close } = await makeMockHttpServer(500, 'Internal Server Error', 'text/plain');
    try {
      await expect(fetchJson(`${url}/v1/stats`)).rejects.toThrow(/HTTP 500/);
    } finally {
      await close();
    }
  });

  it('rejects on parse error (non-JSON response)', async () => {
    const { url, close } = await makeMockHttpServer(200, 'not json', 'text/plain');
    try {
      await expect(fetchJson(`${url}/endpoint`)).rejects.toThrow(/Failed to parse/);
    } finally {
      await close();
    }
  });

  it('resolves with parsed object on 200 response', async () => {
    const payload = { hello: 'world', count: 42 };
    const { url, close } = await makeMockHttpServer(200, JSON.stringify(payload));
    try {
      const result = await fetchJson(`${url}/endpoint`);
      expect(result).toEqual(payload);
    } finally {
      await close();
    }
  });

  it('resolves with parsed array on 200 response', async () => {
    const payload = [1, 2, 3];
    const { url, close } = await makeMockHttpServer(200, JSON.stringify(payload));
    try {
      const result = await fetchJson(`${url}/list`);
      expect(result).toEqual(payload);
    } finally {
      await close();
    }
  });

  it('times out when server does not respond within timeoutMs', async () => {
    const { url, close } = await makeHangingServer();
    try {
      // Use a very short timeout so the test does not hang.
      await expect(fetchJson(`${url}/endpoint`, 50)).rejects.toThrow(/timed out/);
    } finally {
      await close();
    }
  }, 5000);

  it('rejects with ECONNREFUSED when server is not listening', async () => {
    await expect(fetchJson('http://127.0.0.1:1/endpoint')).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('Constants', () => {
  it('C1_THRESHOLD_TEAMS is 5', () => {
    expect(C1_THRESHOLD_TEAMS).toBe(5);
  });

  it('C1_THRESHOLD_INSTALLS_SIGNAL is 5', () => {
    expect(C1_THRESHOLD_INSTALLS_SIGNAL).toBe(5);
  });

  it('C1_THRESHOLD_DISTINCT_INSTALLS is 5', () => {
    expect(C1_THRESHOLD_DISTINCT_INSTALLS).toBe(5);
  });

  it('C2_THRESHOLD_ASKS is 3', () => {
    expect(C2_THRESHOLD_ASKS).toBe(3);
  });

  it('all thresholds are positive integers', () => {
    expect(C1_THRESHOLD_TEAMS).toBeGreaterThan(0);
    expect(C1_THRESHOLD_INSTALLS_SIGNAL).toBeGreaterThan(0);
    expect(C1_THRESHOLD_DISTINCT_INSTALLS).toBeGreaterThan(0);
    expect(C2_THRESHOLD_ASKS).toBeGreaterThan(0);
  });
});

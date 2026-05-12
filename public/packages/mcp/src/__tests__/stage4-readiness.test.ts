/**
 * Unit tests for scripts/stage4-readiness.ts — Stage 4 gate evaluation logic.
 *
 * Test matrix
 * -----------
 * evaluateCriterion1
 *   ✓ returns UNKNOWN when stats is null (no API configured)
 *   ✓ returns false when both hosted tenants and confirmedPayingTeams are 0
 *   ✓ returns false when distinctHostedTenants14d is 0 and confirmedPayingTeams is 0
 *   ✓ returns UNKNOWN when hosted tenants present but confirmedPayingTeams = 0
 *   ✓ returns true when confirmedPayingTeams >= C1_THRESHOLD_PAYING_TEAMS
 *   ✓ returns true when confirmedPayingTeams exactly equals C1_THRESHOLD_PAYING_TEAMS (1)
 *   ✓ detail string includes counts when stats available
 *   ✓ detail string mentions EUNO_TELEMETRY_API when no API configured and stats null
 *   ✓ detail string mentions API unreachable when API configured but stats null
 *   ✓ trackingPointer includes API URL when configured
 *   ✓ trackingPointer mentions CRM/Notion when no API configured
 *   ✓ label is 'C1 — Paying team'
 *
 * evaluateCriterion2
 *   ✓ returns UNKNOWN when stats is null
 *   ✓ returns UNKNOWN when confirmedSecurityQuestions is 0
 *   ✓ returns true when confirmedSecurityQuestions >= C2_THRESHOLD_SECURITY_QUESTIONS
 *   ✓ label is 'C2 — Security/compliance question'
 *   ✓ detail string includes question count when stats available
 *   ✓ detail mentions SOC2 and GDPR as examples
 *   ✓ trackingPointer mentions stage-4-signal label
 *   ✓ trackingPointer mentions SOC2 as an example
 *
 * buildCriteria
 *   ✓ returns array of exactly 2 criteria
 *   ✓ first criterion is C1 (Paying team)
 *   ✓ second criterion is C2 (Security/compliance question)
 *   ✓ passes stats and apiUrl to both criteria
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
 *   ✓ C1_THRESHOLD_PAYING_TEAMS is 1
 *   ✓ C1_THRESHOLD_HOSTED_TENANTS is 1
 *   ✓ C2_THRESHOLD_SECURITY_QUESTIONS is 1
 */

import * as net from 'node:net';
import * as http from 'node:http';

// Import the exported functions from the stage4-readiness script.
// The script uses `require.main === module` guard so main() is NOT called.
import {
  evaluateCriterion1,
  evaluateCriterion2,
  buildCriteria,
  computeOverallResult,
  queryTelemetry,
  fetchJson,
  C1_THRESHOLD_PAYING_TEAMS,
  C1_THRESHOLD_HOSTED_TENANTS,
  C2_THRESHOLD_SECURITY_QUESTIONS,
  type Stage4TelemetryStats,
  type CriterionResult,
} from '../../../../../scripts/stage4-readiness';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStats(overrides: Partial<Stage4TelemetryStats> = {}): Stage4TelemetryStats {
  return {
    distinctHostedTenants14d: 0,
    confirmedPayingTeams: 0,
    confirmedSecurityQuestions: 0,
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

// A server that accepts connections but never sends a response (timeout test).
function makeHangingServer(): Promise<{ server: net.Server; url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const sockets: net.Socket[] = [];
    const server = net.createServer((socket) => {
      sockets.push(socket);
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

  it('returns false when both hosted tenants and confirmedPayingTeams are 0', () => {
    const result = evaluateCriterion1(
      makeStats({ distinctHostedTenants14d: 0, confirmedPayingTeams: 0 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(false);
  });

  it('returns false when distinctHostedTenants14d is 0 and confirmedPayingTeams is 0', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctHostedTenants14d: 0,
        confirmedPayingTeams: 0,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe(false);
  });

  it('returns UNKNOWN when hosted tenants present but confirmedPayingTeams = 0', () => {
    const result = evaluateCriterion1(
      makeStats({
        distinctHostedTenants14d: 3,
        confirmedPayingTeams: 0,
      }),
      'http://api.example.com',
    );
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns true when confirmedPayingTeams >= C1_THRESHOLD_PAYING_TEAMS', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedPayingTeams: C1_THRESHOLD_PAYING_TEAMS }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('returns true when confirmedPayingTeams exactly equals 1', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedPayingTeams: 1 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('detail string includes counts when stats available', () => {
    const result = evaluateCriterion1(
      makeStats({ distinctHostedTenants14d: 4, confirmedPayingTeams: 1 }),
      'http://api.example.com',
    );
    expect(result.detail).toContain('4');
    expect(result.detail).toContain('1');
  });

  it('detail string mentions EUNO_TELEMETRY_API when no API configured and stats null', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.detail).toContain('EUNO_TELEMETRY_API');
  });

  it('detail string mentions API unreachable when API configured but stats null', () => {
    const result = evaluateCriterion1(null, 'http://api.example.com');
    expect(result.detail).toContain('unreachable');
  });

  it('trackingPointer includes API URL when configured', () => {
    const result = evaluateCriterion1(
      makeStats(),
      'http://api.example.com',
    );
    expect(result.trackingPointer).toContain('http://api.example.com');
  });

  it('trackingPointer mentions CRM/Notion when no API configured', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.trackingPointer).toMatch(/CRM|Notion/);
  });

  it('label is "C1 — Paying team"', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.label).toBe('C1 — Paying team');
  });
});

// ---------------------------------------------------------------------------
// evaluateCriterion2
// ---------------------------------------------------------------------------

describe('evaluateCriterion2', () => {
  it('returns UNKNOWN when stats is null', () => {
    const result = evaluateCriterion2(null, '');
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns UNKNOWN when confirmedSecurityQuestions is 0', () => {
    const result = evaluateCriterion2(
      makeStats({ confirmedSecurityQuestions: 0 }),
      'http://api.example.com',
    );
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns true when confirmedSecurityQuestions >= C2_THRESHOLD_SECURITY_QUESTIONS', () => {
    const result = evaluateCriterion2(
      makeStats({ confirmedSecurityQuestions: C2_THRESHOLD_SECURITY_QUESTIONS }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('label is "C2 — Security/compliance question"', () => {
    const result = evaluateCriterion2(null, '');
    expect(result.label).toBe('C2 — Security/compliance question');
  });

  it('detail string includes question count when stats available', () => {
    const result = evaluateCriterion2(
      makeStats({ confirmedSecurityQuestions: 2 }),
      'http://api.example.com',
    );
    expect(result.detail).toContain('2');
  });

  it('detail mentions SOC2 and GDPR as examples', () => {
    const result = evaluateCriterion2(makeStats(), 'http://api.example.com');
    expect(result.detail).toMatch(/SOC2|GDPR/);
  });

  it('trackingPointer mentions stage-4-signal label', () => {
    const result = evaluateCriterion2(null, '');
    expect(result.trackingPointer).toContain('stage-4-signal');
  });

  it('trackingPointer mentions SOC2 as an example', () => {
    const result = evaluateCriterion2(null, '');
    expect(result.trackingPointer).toMatch(/SOC2/);
  });
});

// ---------------------------------------------------------------------------
// buildCriteria
// ---------------------------------------------------------------------------

describe('buildCriteria', () => {
  it('returns array of exactly 2 criteria', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria).toHaveLength(2);
  });

  it('first criterion is C1 (Paying team)', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[0]?.label).toBe('C1 — Paying team');
  });

  it('second criterion is C2 (Security/compliance question)', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[1]?.label).toBe('C2 — Security/compliance question');
  });

  it('passes stats and apiUrl to both criteria', () => {
    const stats = makeStats({ confirmedPayingTeams: 1, confirmedSecurityQuestions: 1 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[0]?.met).toBe(true);
    expect(criteria[1]?.met).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeOverallResult
// ---------------------------------------------------------------------------

describe('computeOverallResult', () => {
  function makeCriterion(met: boolean | 'UNKNOWN'): CriterionResult {
    return { met, label: '', detail: '', trackingPointer: '' };
  }

  it('all UNKNOWN criteria → status "unknown", exitCode 2', () => {
    const result = computeOverallResult([
      makeCriterion('UNKNOWN'),
      makeCriterion('UNKNOWN'),
    ]);
    expect(result.status).toBe('unknown');
    expect(result.exitCode).toBe(2);
  });

  it('all true criteria → status "ready", exitCode 0', () => {
    const result = computeOverallResult([
      makeCriterion(true),
      makeCriterion(true),
    ]);
    expect(result.status).toBe('ready');
    expect(result.exitCode).toBe(0);
  });

  it('one false criterion → status "not-ready", exitCode 1', () => {
    const result = computeOverallResult([
      makeCriterion(false),
      makeCriterion(true),
    ]);
    expect(result.status).toBe('not-ready');
    expect(result.exitCode).toBe(1);
  });

  it('mix of true and false → status "not-ready", exitCode 1', () => {
    const result = computeOverallResult([
      makeCriterion(true),
      makeCriterion(false),
    ]);
    expect(result.status).toBe('not-ready');
    expect(result.exitCode).toBe(1);
  });

  it('mix of true and UNKNOWN → status "unknown", exitCode 2', () => {
    const result = computeOverallResult([
      makeCriterion(true),
      makeCriterion('UNKNOWN'),
    ]);
    expect(result.status).toBe('unknown');
    expect(result.exitCode).toBe(2);
  });

  it('mix of false and UNKNOWN → status "not-ready", exitCode 1', () => {
    const result = computeOverallResult([
      makeCriterion(false),
      makeCriterion('UNKNOWN'),
    ]);
    expect(result.status).toBe('not-ready');
    expect(result.exitCode).toBe(1);
  });

  it('single true criterion → status "ready", exitCode 0', () => {
    const result = computeOverallResult([makeCriterion(true)]);
    expect(result.status).toBe('ready');
    expect(result.exitCode).toBe(0);
  });

  it('single false criterion → status "not-ready", exitCode 1', () => {
    const result = computeOverallResult([makeCriterion(false)]);
    expect(result.status).toBe('not-ready');
    expect(result.exitCode).toBe(1);
  });

  it('single UNKNOWN criterion → status "unknown", exitCode 2', () => {
    const result = computeOverallResult([makeCriterion('UNKNOWN')]);
    expect(result.status).toBe('unknown');
    expect(result.exitCode).toBe(2);
  });

  it('empty criteria array → status "ready", exitCode 0', () => {
    const result = computeOverallResult([]);
    expect(result.status).toBe('ready');
    expect(result.exitCode).toBe(0);
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
    // Use a port that is almost certainly not listening.
    const result = await queryTelemetry('http://127.0.0.1:1');
    expect(result).toBeNull();
  });

  it('returns null when API returns non-2xx status', async () => {
    const { url, close } = await makeMockHttpServer(500, '{"error":"oops"}');
    try {
      const result = await queryTelemetry(url);
      expect(result).toBeNull();
    } finally {
      await close();
    }
  });

  it('returns parsed stats when API returns valid JSON', async () => {
    const body: Stage4TelemetryStats = {
      distinctHostedTenants14d: 3,
      confirmedPayingTeams: 1,
      confirmedSecurityQuestions: 2,
    };
    const { url, close } = await makeMockHttpServer(200, JSON.stringify(body));
    try {
      const result = await queryTelemetry(url);
      expect(result).toEqual(body);
    } finally {
      await close();
    }
  });

  it('returns null when API returns invalid JSON', async () => {
    const { url, close } = await makeMockHttpServer(200, 'not-json', 'text/plain');
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
    const { url, close } = await makeMockHttpServer(404, 'not found');
    try {
      await expect(fetchJson(url)).rejects.toThrow(/404/);
    } finally {
      await close();
    }
  });

  it('rejects when server returns 500', async () => {
    const { url, close } = await makeMockHttpServer(500, 'server error');
    try {
      await expect(fetchJson(url)).rejects.toThrow(/500/);
    } finally {
      await close();
    }
  });

  it('rejects on parse error (non-JSON response)', async () => {
    const { url, close } = await makeMockHttpServer(200, 'not-json', 'text/plain');
    try {
      await expect(fetchJson(url)).rejects.toThrow(/parse/i);
    } finally {
      await close();
    }
  });

  it('resolves with parsed object on 200 response', async () => {
    const payload = { distinctHostedTenants14d: 5, confirmedPayingTeams: 1, confirmedSecurityQuestions: 2 };
    const { url, close } = await makeMockHttpServer(200, JSON.stringify(payload));
    try {
      const result = await fetchJson(url);
      expect(result).toEqual(payload);
    } finally {
      await close();
    }
  });

  it('times out when server does not respond within timeoutMs', async () => {
    const { url, close } = await makeHangingServer();
    try {
      await expect(fetchJson(url, 200)).rejects.toThrow(/timed out/i);
    } finally {
      await close();
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('Constants', () => {
  it('C1_THRESHOLD_PAYING_TEAMS is 1', () => {
    expect(C1_THRESHOLD_PAYING_TEAMS).toBe(1);
  });

  it('C1_THRESHOLD_HOSTED_TENANTS is 1', () => {
    expect(C1_THRESHOLD_HOSTED_TENANTS).toBe(1);
  });

  it('C2_THRESHOLD_SECURITY_QUESTIONS is 1', () => {
    expect(C2_THRESHOLD_SECURITY_QUESTIONS).toBe(1);
  });
});

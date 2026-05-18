/**
 * Unit tests for scripts/stage5-readiness.ts — Stage 5 gate evaluation logic.
 *
 * Test matrix
 * -----------
 * evaluateCriterion1
 *   ✓ returns UNKNOWN when stats is null (no API configured)
 *   ✓ returns UNKNOWN when confirmedEnterpriseInbound is 0 (indistinguishable from not-yet-tracked)
 *   ✓ returns true when confirmedEnterpriseInbound >= C1_THRESHOLD_ENTERPRISE_INBOUND
 *   ✓ returns true when confirmedEnterpriseInbound exactly equals 1
 *   ✓ returns true when confirmedEnterpriseInbound is greater than threshold
 *   ✓ detail string includes counts when stats available
 *   ✓ detail string mentions EUNO_TELEMETRY_API when no API configured and stats null
 *   ✓ detail string mentions API unreachable when API configured but stats null
 *   ✓ detail mentions CISO as an example
 *   ✓ trackingPointer includes API URL when configured
 *   ✓ trackingPointer mentions CRM/Notion when no API configured
 *   ✓ trackingPointer mentions CISO review as an example qualifier
 *   ✓ label is 'C1 — Enterprise inbound'
 *
 * buildCriteria
 *   ✓ returns array of exactly 1 criterion
 *   ✓ first criterion is C1 (Enterprise inbound)
 *   ✓ passes stats and apiUrl to C1
 *
 * computeOverallResult
 *   ✓ UNKNOWN criterion → status 'unknown', exitCode 2
 *   ✓ true criterion → status 'ready', exitCode 0
 *   ✓ false criterion → status 'not-ready', exitCode 1
 *   ✓ mix of true and false → status 'not-ready', exitCode 1
 *   ✓ mix of true and UNKNOWN → status 'unknown', exitCode 2
 *   ✓ mix of false and UNKNOWN → status 'not-ready', exitCode 1
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
 *   ✓ C1_THRESHOLD_ENTERPRISE_INBOUND is 1
 */

import * as net from 'node:net';
import * as http from 'node:http';

// Import the exported functions from the stage5-readiness script.
// The script uses `require.main === module` guard so main() is NOT called.
import {
  evaluateCriterion1,
  buildCriteria,
  computeOverallResult,
  queryTelemetry,
  fetchJson,
  C1_THRESHOLD_ENTERPRISE_INBOUND,
  type Stage5TelemetryStats,
  type CriterionResult,
} from '../../../../../scripts/stage5-readiness';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStats(overrides: Partial<Stage5TelemetryStats> = {}): Stage5TelemetryStats {
  return {
    confirmedEnterpriseInbound: 0,
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

  it('returns UNKNOWN when confirmedEnterpriseInbound is 0 (indistinguishable from not-yet-tracked)', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedEnterpriseInbound: 0 }),
      'http://api.example.com',
    );
    expect(result.met).toBe('UNKNOWN');
  });

  it('returns true when confirmedEnterpriseInbound >= C1_THRESHOLD_ENTERPRISE_INBOUND', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedEnterpriseInbound: C1_THRESHOLD_ENTERPRISE_INBOUND }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('returns true when confirmedEnterpriseInbound exactly equals 1', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedEnterpriseInbound: 1 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('returns true when confirmedEnterpriseInbound is greater than threshold', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedEnterpriseInbound: 5 }),
      'http://api.example.com',
    );
    expect(result.met).toBe(true);
  });

  it('detail string includes counts when stats available', () => {
    const result = evaluateCriterion1(
      makeStats({ confirmedEnterpriseInbound: 2 }),
      'http://api.example.com',
    );
    expect(result.detail).toContain('2');
    expect(result.detail).toContain(String(C1_THRESHOLD_ENTERPRISE_INBOUND));
  });

  it('detail string mentions EUNO_TELEMETRY_API when no API configured and stats null', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.detail).toContain('EUNO_TELEMETRY_API');
  });

  it('detail string mentions API unreachable when API configured but stats null', () => {
    const result = evaluateCriterion1(null, 'http://api.example.com');
    expect(result.detail).toContain('unreachable');
  });

  it('detail mentions CISO as an example', () => {
    const result = evaluateCriterion1(makeStats(), 'http://api.example.com');
    expect(result.detail).toMatch(/CISO/);
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

  it('trackingPointer mentions CISO review as an example qualifier', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.trackingPointer).toMatch(/CISO/);
  });

  it('label is "C1 — Enterprise inbound"', () => {
    const result = evaluateCriterion1(null, '');
    expect(result.label).toBe('C1 — Enterprise inbound');
  });
});

// ---------------------------------------------------------------------------
// buildCriteria
// ---------------------------------------------------------------------------

describe('buildCriteria', () => {
  it('returns array of exactly 1 criterion', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria).toHaveLength(1);
  });

  it('first criterion is C1 (Enterprise inbound)', () => {
    const criteria = buildCriteria(null, '');
    expect(criteria[0]?.label).toBe('C1 — Enterprise inbound');
  });

  it('passes stats and apiUrl to C1', () => {
    const stats = makeStats({ confirmedEnterpriseInbound: 1 });
    const criteria = buildCriteria(stats, 'http://api.example.com');
    expect(criteria[0]?.met).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeOverallResult
// ---------------------------------------------------------------------------

describe('computeOverallResult', () => {
  function makeCriterion(met: boolean | 'UNKNOWN'): CriterionResult {
    return { met, label: '', detail: '', trackingPointer: '' };
  }

  it('UNKNOWN criterion → status "unknown", exitCode 2', () => {
    const result = computeOverallResult([makeCriterion('UNKNOWN')]);
    expect(result.status).toBe('unknown');
    expect(result.exitCode).toBe(2);
  });

  it('true criterion → status "ready", exitCode 0', () => {
    const result = computeOverallResult([makeCriterion(true)]);
    expect(result.status).toBe('ready');
    expect(result.exitCode).toBe(0);
  });

  it('false criterion → status "not-ready", exitCode 1', () => {
    const result = computeOverallResult([makeCriterion(false)]);
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
    const body: Stage5TelemetryStats = {
      confirmedEnterpriseInbound: 2,
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
    const payload: Stage5TelemetryStats = { confirmedEnterpriseInbound: 3 };
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
  it('C1_THRESHOLD_ENTERPRISE_INBOUND is 1', () => {
    expect(C1_THRESHOLD_ENTERPRISE_INBOUND).toBe(1);
  });
});

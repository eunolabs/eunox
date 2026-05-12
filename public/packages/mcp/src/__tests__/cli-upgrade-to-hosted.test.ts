/**
 * Unit tests for `src/cli/upgrade-to-hosted.ts`.
 *
 * All tests use injectable fakes (mock fetcher, temp files) to avoid
 * any real network I/O or writing to system config locations.
 *
 * Test matrix
 * -----------
 *
 * MinterClient.health()
 *   ✓ resolves when server returns 200
 *   ✓ throws when server returns non-200
 *   ✓ throws on network error
 *
 * MinterClient.ping()
 *   ✓ returns tenantId/policyId/scopes on valid Bearer key (200)
 *   ✓ throws descriptive error on 401
 *   ✓ throws on non-200 status
 *   ✓ throws when response shape is missing tenantId
 *   ✓ sends Authorization: Bearer header
 *
 * MinterClient.uploadPolicy()
 *   ✓ returns updatedKeys/capabilityCount on 200
 *   ✓ throws descriptive error on 401
 *   ✓ throws with server error detail on non-200
 *   ✓ sends X-Admin-Key header and body
 *
 * loadManifestFromFile()
 *   ✓ loads and validates a valid YAML manifest
 *   ✓ loads and validates a valid JSON manifest
 *   ✓ throws on non-existent file
 *   ✓ throws on invalid YAML
 *   ✓ throws on manifest validation failure
 *
 * claudeDesktopConfigPath()
 *   ✓ ends with claude_desktop_config.json
 *
 * discoverConfigFiles()
 *   ✓ returns empty array when no files exist
 *   ✓ returns matching files that exist on disk
 *   ✓ includes explicit paths when they exist
 *   ✓ excludes explicit paths that don't exist
 *
 * backupFile()
 *   ✓ creates a .bak.<timestamp> copy
 *   ✓ the backup file has the same content as the original
 *
 * computeConfigPatch()
 *   ✓ returns empty patches for empty mcpServers
 *   ✓ returns empty patches when no euno-mcp entries exist
 *   ✓ returns empty patches when BOTH enforcer flags are present
 *   ✓ patches entry when --enforcer-url present but --enforcer-api-key missing
 *   ✓ returns a patch for a plain proxy entry (no --policy)
 *   ✓ patch removes --policy <path> from args
 *   ✓ patch inserts --enforcer-url and --enforcer-api-key before --
 *   ✓ patch inserts at end of args when no -- separator
 *   ✓ entries with non-euno-mcp command are ignored
 *   ✓ matches command ending in /euno-mcp
 *   ✓ matches Windows euno-mcp.cmd launcher
 *   ✓ matches Windows euno-mcp.exe launcher
 *   ✓ matches proxy subcommand when flags precede it
 *   ✓ does not match when no proxy subcommand appears before --
 *
 * patchArgs()
 *   ✓ inserts enforcer flags before --
 *   ✓ inserts enforcer flags at end when no --
 *   ✓ removes --policy and its value
 *   ✓ does not remove --policy when followed by a named flag (--other)
 *   ✓ does not remove the -- separator itself
 *
 * redactArgs()
 *   ✓ replaces value after --enforcer-api-key with ***
 *   ✓ leaves args unchanged when --enforcer-api-key is absent
 *   ✓ does not redact --enforcer-url value
 *
 * applyConfigPatches()
 *   ✓ mutates the config's args in place
 *   ✓ ignores patches for missing server names
 *
 * readJsonConfigFile() / writeJsonConfigFile()
 *   ✓ round-trips a JSON object
 *   ✓ readJsonConfigFile throws on non-existent file
 *   ✓ readJsonConfigFile throws on invalid JSON
 *
 * runUpgrade() — integration
 *   ✓ exits 1 when health check fails
 *   ✓ exits 1 when ping returns 401
 *   ✓ skips step 2 when --policy not provided
 *   ✓ skips step 2 when --admin-key not provided
 *   ✓ exits 1 when policy file does not exist
 *   ✓ uploads policy when --policy and --admin-key provided
 *   ✓ patches config file (non-dry-run)
 *   ✓ does not write files in dry-run mode
 *   ✓ exits 0 on full success
 *   ✓ exits 1 when a config file cannot be read
 *   ✓ does not print the raw API key in Step 3 preview output
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  MinterClient,
  type UpgradeFetcher,
  loadManifestFromFile,
  claudeDesktopConfigPath,
  discoverConfigFiles,
  backupFile,
  computeConfigPatch,
  patchArgs,
  redactArgs,
  applyConfigPatches,
  readJsonConfigFile,
  writeJsonConfigFile,
  runUpgrade,
  type ClaudeDesktopConfig,
} from '../cli/upgrade-to-hosted';

// ---------------------------------------------------------------------------
// Temp-dir helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

beforeEach(() => { /* nothing */ });
afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'upgrade-test-'));
  tempDirs.push(dir);
  return dir;
}

function writeFile(dir: string, name: string, content: string): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

// ---------------------------------------------------------------------------
// Mock fetcher helpers
// ---------------------------------------------------------------------------

function mockFetcher(
  responses: Array<{
    status: number;
    body: unknown;
  }>,
): UpgradeFetcher {
  let idx = 0;
  return async (_url, _init) => {
    const resp = responses[idx++] ?? { status: 200, body: {} };
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: async () => resp.body,
      text: async () => JSON.stringify(resp.body),
    };
  };
}

function captureFetcher(
  response: { status: number; body: unknown },
): { fetcher: UpgradeFetcher; calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> } {
  const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];
  const fetcher: UpgradeFetcher = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      json: async () => response.body,
      text: async () => JSON.stringify(response.body),
    };
  };
  return { fetcher, calls };
}

function errorFetcher(err: Error): UpgradeFetcher {
  return async () => { throw err; };
}

// ---------------------------------------------------------------------------
// MinterClient.health()
// ---------------------------------------------------------------------------

describe('MinterClient.health()', () => {
  it('resolves when server returns 200', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 200, body: { status: 'ok' } }]),
    });
    await expect(client.health()).resolves.toBeUndefined();
  });

  it('throws when server returns non-200', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 503, body: {} }]),
    });
    await expect(client.health()).rejects.toThrow('HTTP 503');
  });

  it('throws on network error', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: errorFetcher(new Error('ECONNREFUSED')),
    });
    await expect(client.health()).rejects.toThrow('ECONNREFUSED');
  });
});

// ---------------------------------------------------------------------------
// MinterClient.ping()
// ---------------------------------------------------------------------------

describe('MinterClient.ping()', () => {
  const validPingBody = { valid: true, tenantId: 'tenant-1', policyId: 'policy-1', scopes: ['enforce'] };

  it('returns tenantId/policyId/scopes on valid key', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 200, body: validPingBody }]),
    });
    const result = await client.ping('sk-test.key');
    expect(result.tenantId).toBe('tenant-1');
    expect(result.policyId).toBe('policy-1');
    expect(result.scopes).toEqual(['enforce']);
  });

  it('throws descriptive error on 401', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 401, body: { error: { message: 'Unauthorized' } } }]),
    });
    await expect(client.ping('bad-key')).rejects.toThrow('API key is not valid');
  });

  it('throws on non-200 status', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 500, body: {} }]),
    });
    await expect(client.ping('sk-test')).rejects.toThrow('HTTP 500');
  });

  it('throws when response shape is missing tenantId', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 200, body: { valid: true } }]),
    });
    await expect(client.ping('sk-test')).rejects.toThrow('Unexpected response shape');
  });

  it('sends Authorization: Bearer header', async () => {
    const { fetcher, calls } = captureFetcher({ status: 200, body: validPingBody });
    const client = new MinterClient({ baseUrl: 'http://localhost', fetcher });
    await client.ping('sk-my-key');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers['Authorization']).toBe('Bearer sk-my-key');
  });
});

// ---------------------------------------------------------------------------
// MinterClient.uploadPolicy()
// ---------------------------------------------------------------------------

describe('MinterClient.uploadPolicy()', () => {
  const minimalManifest = {
    name: 'test',
    agentId: 'agent-1',
    version: '1.0.0',
    requiredCapabilities: [],
  };

  const uploadBody = { policyId: 'policy-1', updatedKeys: 1, capabilityCount: 0 };

  it('returns updatedKeys/capabilityCount on 200', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 200, body: uploadBody }]),
    });
    const result = await client.uploadPolicy({
      adminKey: 'admin-key',
      policyId: 'policy-1',
      manifest: minimalManifest as never,
    });
    expect(result.updatedKeys).toBe(1);
    expect(result.capabilityCount).toBe(0);
  });

  it('throws descriptive error on 401', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{ status: 401, body: {} }]),
    });
    await expect(
      client.uploadPolicy({ adminKey: 'bad', policyId: 'p', manifest: minimalManifest as never }),
    ).rejects.toThrow('Admin key rejected');
  });

  it('throws with server error detail on non-200', async () => {
    const client = new MinterClient({
      baseUrl: 'http://localhost',
      fetcher: mockFetcher([{
        status: 400,
        body: { error: { message: 'policyId is required' } },
      }]),
    });
    await expect(
      client.uploadPolicy({ adminKey: 'k', policyId: '', manifest: minimalManifest as never }),
    ).rejects.toThrow('policyId is required');
  });

  it('sends X-Admin-Key header and serialised body', async () => {
    const { fetcher, calls } = captureFetcher({ status: 200, body: uploadBody });
    const client = new MinterClient({ baseUrl: 'http://localhost', fetcher });
    await client.uploadPolicy({
      adminKey: 'secret-admin',
      policyId: 'policy-1',
      manifest: minimalManifest as never,
    });
    expect(calls[0]!.headers['X-Admin-Key']).toBe('secret-admin');
    const body = JSON.parse(calls[0]!.body ?? '{}') as Record<string, unknown>;
    expect(body['policyId']).toBe('policy-1');
  });
});

// ---------------------------------------------------------------------------
// loadManifestFromFile()
// ---------------------------------------------------------------------------

describe('loadManifestFromFile()', () => {
  const validYaml = `
name: test-agent
agentId: agent-test
version: "1.0.0"
requiredCapabilities:
  - resource: "/api"
    actions: ["read"]
    conditions: []
`;
  const validJson = JSON.stringify({
    name: 'test',
    agentId: 'agent-json',
    version: '1.0.0',
    requiredCapabilities: [{ resource: '/api', actions: ['read'], conditions: [] }],
  });

  it('loads and validates a valid YAML manifest', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'policy.yaml', validYaml);
    const manifest = loadManifestFromFile(p);
    expect(manifest.agentId).toBe('agent-test');
  });

  it('loads and validates a valid JSON manifest', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'policy.json', validJson);
    const manifest = loadManifestFromFile(p);
    expect(manifest.agentId).toBe('agent-json');
  });

  it('throws on non-existent file', () => {
    expect(() => loadManifestFromFile('/does/not/exist.yaml')).toThrow(
      /Cannot read policy file/,
    );
  });

  it('throws on invalid YAML', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'bad.yaml', '{{ invalid yaml:');
    expect(() => loadManifestFromFile(p)).toThrow(/Cannot parse YAML/);
  });

  it('throws on manifest validation failure (missing requiredCapabilities)', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'bad.yaml', 'name: test\nagentId: a\nversion: "1.0"');
    expect(() => loadManifestFromFile(p)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// claudeDesktopConfigPath()
// ---------------------------------------------------------------------------

describe('claudeDesktopConfigPath()', () => {
  it('ends with claude_desktop_config.json', () => {
    const p = claudeDesktopConfigPath();
    expect(p.endsWith('claude_desktop_config.json')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// discoverConfigFiles()
// ---------------------------------------------------------------------------

describe('discoverConfigFiles()', () => {
  it('returns empty array when no files exist', () => {
    const result = discoverConfigFiles(['/does/not/exist.json']);
    expect(result).toHaveLength(0);
  });

  it('includes explicit paths when they exist', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'mcp.json', '{}');
    const result = discoverConfigFiles([p]);
    expect(result.some((c) => c.filePath === p)).toBe(true);
  });

  it('excludes explicit paths that do not exist', () => {
    const result = discoverConfigFiles(['/tmp/definitely-not-there.json']);
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// backupFile()
// ---------------------------------------------------------------------------

describe('backupFile()', () => {
  it('creates a .bak.<timestamp> copy', () => {
    const dir = makeTempDir();
    const orig = writeFile(dir, 'config.json', '{"a":1}');
    const bak = backupFile(orig);
    expect(fs.existsSync(bak)).toBe(true);
    expect(bak).toMatch(/\.bak\.\d{14}$/);
  });

  it('the backup file has the same content as the original', () => {
    const dir = makeTempDir();
    const orig = writeFile(dir, 'config.json', '{"hello":"world"}');
    const bak = backupFile(orig);
    expect(fs.readFileSync(bak, 'utf8')).toBe('{"hello":"world"}');
  });
});

// ---------------------------------------------------------------------------
// computeConfigPatch()
// ---------------------------------------------------------------------------

describe('computeConfigPatch()', () => {
  const url = 'https://gw.example.com';
  const key = 'sk-abc';

  it('returns empty patches for empty mcpServers', () => {
    const config: ClaudeDesktopConfig = { mcpServers: {} };
    expect(computeConfigPatch(config, url, key)).toHaveLength(0);
  });

  it('returns empty patches when no euno-mcp entries exist', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { other: { command: 'npx', args: ['some-server'] } },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(0);
  });

  it('returns empty patches when entry already has --enforcer-url', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy', '--enforcer-url', url, '--enforcer-api-key', key, '--', 'npx', 'server'],
        },
      },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(0);
  });

  it('patches entry when --enforcer-url is present but --enforcer-api-key is missing', () => {
    // Only both flags present → skip; partial upgrade is re-run.
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy', '--enforcer-url', url, '--', 'npx', 'server'],
        },
      },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(1);
  });

  it('returns a patch for a plain proxy entry (no --policy)', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy', '--', 'npx', 'server'],
        },
      },
    };
    const patches = computeConfigPatch(config, url, key);
    expect(patches).toHaveLength(1);
    expect(patches[0]!.serverName).toBe('euno');
    expect(patches[0]!.after).toContain('--enforcer-url');
    expect(patches[0]!.after).toContain(url);
  });

  it('patch removes --policy <path> from args', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy', '--policy', './policy.yaml', '--', 'npx', 'server'],
        },
      },
    };
    const patches = computeConfigPatch(config, url, key);
    expect(patches[0]!.after).not.toContain('--policy');
    expect(patches[0]!.after).not.toContain('./policy.yaml');
  });

  it('patch inserts --enforcer-url and --enforcer-api-key before --', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy', '--', 'npx', 'server'],
        },
      },
    };
    const { after } = computeConfigPatch(config, url, key)[0]!;
    const sepIdx = after.indexOf('--');
    const urlIdx = after.indexOf('--enforcer-url');
    expect(urlIdx).toBeGreaterThan(-1);
    expect(urlIdx).toBeLessThan(sepIdx);
  });

  it('patch inserts at end of args when no -- separator', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: {
          command: 'euno-mcp',
          args: ['proxy'],
        },
      },
    };
    const { after } = computeConfigPatch(config, url, key)[0]!;
    const urlIdx = after.indexOf('--enforcer-url');
    expect(urlIdx).toBe(after.length - 4); // [proxy, --enforcer-url, url, --enforcer-api-key, key]
  });

  it('entries with non-euno-mcp command are ignored', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { other: { command: 'other-mcp', args: ['proxy'] } },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(0);
  });

  it('matches command ending in /euno-mcp', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { euno: { command: '/usr/local/bin/euno-mcp', args: ['proxy'] } },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(1);
  });

  it('matches Windows euno-mcp.cmd launcher', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { euno: { command: 'C:\\tools\\euno-mcp.cmd', args: ['proxy'] } },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(1);
  });

  it('matches Windows euno-mcp.exe launcher', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { euno: { command: 'euno-mcp.exe', args: ['proxy'] } },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(1);
  });

  it('matches proxy subcommand when flags precede it (--log-level debug proxy)', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: {
        euno: { command: 'euno-mcp', args: ['--log-level', 'debug', 'proxy', '--', 'npx'] },
      },
    };
    expect(computeConfigPatch(config, url, key)).toHaveLength(1);
  });

  it('does not match when no proxy subcommand appears before --', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { euno: { command: 'euno-mcp', args: ['--', 'proxy'] } },
    };
    // 'proxy' is after '--', so it is the upstream command, not the subcommand
    expect(computeConfigPatch(config, url, key)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// patchArgs()
// ---------------------------------------------------------------------------

describe('patchArgs()', () => {
  const url = 'https://gw.example.com';
  const key = 'sk-abc';

  it('inserts enforcer flags before --', () => {
    const result = patchArgs(['proxy', '--', 'npx', 'server'], url, key);
    const sep = result.indexOf('--');
    // result: ['proxy', '--enforcer-url', url, '--enforcer-api-key', key, '--', 'npx', 'server']
    expect(result[sep - 4]).toBe('--enforcer-url');
    expect(result[sep - 3]).toBe(url);
  });

  it('inserts enforcer flags at end when no --', () => {
    const result = patchArgs(['proxy'], url, key);
    expect(result).toEqual(['proxy', '--enforcer-url', url, '--enforcer-api-key', key]);
  });

  it('removes --policy and its value', () => {
    const result = patchArgs(['proxy', '--policy', './p.yaml', '--', 'npx'], url, key);
    expect(result).not.toContain('--policy');
    expect(result).not.toContain('./p.yaml');
  });

  it('does not remove --policy when followed by a named flag (--other)', () => {
    // When the next token after --policy starts with '--' it looks like a flag,
    // not a value, so --policy is preserved to avoid accidentally dropping a
    // real flag.
    const result = patchArgs(['proxy', '--policy', '--other', '--', 'npx'], url, key);
    expect(result).toContain('--policy');
    expect(result).toContain('--other');
  });

  it('does not remove the -- separator itself', () => {
    const result = patchArgs(['proxy', '--', 'npx', 'server'], url, key);
    expect(result).toContain('--');
  });
});

// ---------------------------------------------------------------------------
// redactArgs()
// ---------------------------------------------------------------------------

describe('redactArgs()', () => {
  it('replaces value after --enforcer-api-key with ***', () => {
    const args = ['proxy', '--enforcer-url', 'https://gw', '--enforcer-api-key', 'sk-secret'];
    expect(redactArgs(args)).toEqual(['proxy', '--enforcer-url', 'https://gw', '--enforcer-api-key', '***']);
  });

  it('leaves args unchanged when --enforcer-api-key is absent', () => {
    const args = ['proxy', '--enforcer-url', 'https://gw'];
    expect(redactArgs(args)).toEqual(args);
  });

  it('does not redact --enforcer-url value', () => {
    const args = ['proxy', '--enforcer-url', 'https://gw.example.com', '--enforcer-api-key', 'sk-x'];
    const result = redactArgs(args);
    expect(result[2]).toBe('https://gw.example.com');
  });
});

describe('applyConfigPatches()', () => {
  it('mutates the config args in place', () => {
    const config: ClaudeDesktopConfig = {
      mcpServers: { euno: { command: 'euno-mcp', args: ['proxy'] } },
    };
    applyConfigPatches(config, [{
      serverName: 'euno',
      before: ['proxy'],
      after: ['proxy', '--enforcer-url', 'https://x'],
    }]);
    expect(config.mcpServers!['euno']!.args).toEqual(['proxy', '--enforcer-url', 'https://x']);
  });

  it('ignores patches for missing server names', () => {
    const config: ClaudeDesktopConfig = { mcpServers: {} };
    // Should not throw
    expect(() =>
      applyConfigPatches(config, [{
        serverName: 'nonexistent',
        before: [],
        after: ['proxy'],
      }]),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// readJsonConfigFile() / writeJsonConfigFile()
// ---------------------------------------------------------------------------

describe('readJsonConfigFile() / writeJsonConfigFile()', () => {
  it('round-trips a JSON object', () => {
    const dir = makeTempDir();
    const p = path.join(dir, 'config.json');
    const obj = { mcpServers: { euno: { command: 'euno-mcp', args: ['proxy'] } } };
    writeJsonConfigFile(p, obj);
    const loaded = readJsonConfigFile(p);
    expect(loaded).toEqual(obj);
  });

  it('readJsonConfigFile throws on non-existent file', () => {
    expect(() => readJsonConfigFile('/does/not/exist.json')).toThrow(/Cannot read/);
  });

  it('readJsonConfigFile throws on invalid JSON', () => {
    const dir = makeTempDir();
    const p = writeFile(dir, 'bad.json', 'not json {{');
    expect(() => readJsonConfigFile(p)).toThrow(/Cannot parse/);
  });
});

// ---------------------------------------------------------------------------
// runUpgrade() integration
// ---------------------------------------------------------------------------

describe('runUpgrade()', () => {
  const pingOk = { valid: true, tenantId: 'tenant-1', policyId: 'policy-1', scopes: ['enforce'] };
  const uploadOk = { policyId: 'policy-1', updatedKeys: 1, capabilityCount: 0 };

  const validYaml = `
name: test-agent
agentId: agent-test
version: "1.0.0"
requiredCapabilities:
  - resource: "/api"
    actions: ["read"]
    conditions: []
`;

  function makeRunOpts(
    overrides: Partial<Parameters<typeof runUpgrade>[0]> = {},
  ): Parameters<typeof runUpgrade>[0] {
    return {
      gatewayUrl: 'http://localhost:3000',
      apiKey: 'sk-test.key',
      fetcher: mockFetcher([
        { status: 200, body: { status: 'ok' } }, // health
        { status: 200, body: pingOk },            // ping
      ]),
      out: () => { /* suppress output */ },
      err: () => { /* suppress output */ },
      ...overrides,
    };
  }

  it('exits 1 when health check fails', async () => {
    const code = await runUpgrade(makeRunOpts({
      fetcher: errorFetcher(new Error('ECONNREFUSED')),
    }));
    expect(code).toBe(1);
  });

  it('exits 1 when ping returns 401', async () => {
    const code = await runUpgrade(makeRunOpts({
      fetcher: mockFetcher([
        { status: 200, body: { status: 'ok' } },
        { status: 401, body: {} },
      ]),
    }));
    expect(code).toBe(1);
  });

  it('skips step 2 when --policy not provided', async () => {
    const lines: string[] = [];
    const code = await runUpgrade(makeRunOpts({
      out: (l) => lines.push(l),
    }));
    expect(code).toBe(0);
    expect(lines.some((l) => l.includes('Skipped'))).toBe(true);
  });

  it('skips step 2 when --admin-key not provided', async () => {
    const dir = makeTempDir();
    const policy = writeFile(dir, 'policy.yaml', validYaml);
    const lines: string[] = [];
    const code = await runUpgrade(makeRunOpts({
      policyFile: policy,
      out: (l) => lines.push(l),
    }));
    expect(code).toBe(0);
    expect(lines.some((l) => l.includes('Skipped'))).toBe(true);
  });

  it('exits 1 when policy file does not exist', async () => {
    const code = await runUpgrade(makeRunOpts({
      policyFile: '/does/not/exist.yaml',
      adminKey: 'admin-key',
      fetcher: mockFetcher([
        { status: 200, body: { status: 'ok' } },
        { status: 200, body: pingOk },
      ]),
    }));
    expect(code).toBe(1);
  });

  it('uploads policy when --policy and --admin-key provided', async () => {
    const dir = makeTempDir();
    const policy = writeFile(dir, 'policy.yaml', validYaml);
    const lines: string[] = [];
    const code = await runUpgrade(makeRunOpts({
      policyFile: policy,
      adminKey: 'admin-key',
      fetcher: mockFetcher([
        { status: 200, body: { status: 'ok' } },
        { status: 200, body: pingOk },
        { status: 200, body: uploadOk },
      ]),
      out: (l) => lines.push(l),
    }));
    expect(code).toBe(0);
    expect(lines.some((l) => l.includes('✓ Policy uploaded'))).toBe(true);
  });

  it('patches config file in non-dry-run mode', async () => {
    const dir = makeTempDir();
    const configObj: ClaudeDesktopConfig = {
      mcpServers: {
        euno: { command: 'euno-mcp', args: ['proxy', '--policy', './p.yaml', '--', 'npx', 'srv'] },
      },
    };
    const configFile = path.join(dir, 'claude_desktop_config.json');
    writeJsonConfigFile(configFile, configObj);

    const code = await runUpgrade(makeRunOpts({
      configFiles: [configFile],
      out: () => { /* suppress */ },
    }));
    expect(code).toBe(0);

    const patched = readJsonConfigFile(configFile);
    const args = patched.mcpServers!['euno']!.args ?? [];
    expect(args).toContain('--enforcer-url');
    expect(args).not.toContain('--policy');
  });

  it('does not write files in dry-run mode', async () => {
    const dir = makeTempDir();
    const configObj: ClaudeDesktopConfig = {
      mcpServers: {
        euno: { command: 'euno-mcp', args: ['proxy', '--', 'npx', 'srv'] },
      },
    };
    const configFile = path.join(dir, 'claude_desktop_config.json');
    const originalContent = JSON.stringify(configObj, null, 2) + '\n';
    fs.writeFileSync(configFile, originalContent);

    await runUpgrade(makeRunOpts({
      configFiles: [configFile],
      dryRun: true,
      out: () => { /* suppress */ },
    }));

    // File should be unchanged
    expect(fs.readFileSync(configFile, 'utf8')).toBe(originalContent);
  });

  it('exits 0 on full success with no config files', async () => {
    const code = await runUpgrade(makeRunOpts());
    expect(code).toBe(0);
  });

  it('exits 1 when a config file cannot be read', async () => {
    const dir = makeTempDir();
    // Create a file that exists but contains invalid JSON so readJsonConfigFile throws
    const badFile = writeFile(dir, 'bad.json', 'not valid json {{{{');
    const code = await runUpgrade(makeRunOpts({
      configFiles: [badFile],
      out: () => { /* suppress */ },
      err: () => { /* suppress */ },
    }));
    expect(code).toBe(1);
  });

  it('does not print the raw API key in Step 3 preview output', async () => {
    const dir = makeTempDir();
    const secretKey = 'sk-very-secret-value';
    const configObj: ClaudeDesktopConfig = {
      mcpServers: {
        euno: { command: 'euno-mcp', args: ['proxy', '--', 'npx', 'srv'] },
      },
    };
    const configFile = path.join(dir, 'claude_desktop_config.json');
    writeJsonConfigFile(configFile, configObj);

    const lines: string[] = [];
    await runUpgrade(makeRunOpts({
      apiKey: secretKey,
      configFiles: [configFile],
      dryRun: true,
      out: (l) => lines.push(l),
      err: (l) => lines.push(l),
    }));

    const joined = lines.join('\n');
    expect(joined).not.toContain(secretKey);
    expect(joined).toContain('***');
  });
});

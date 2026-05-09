/**
 * Tests for the reference policy library under public/packages/mcp/policies/.
 *
 * Task 10 acceptance criteria
 * ──────────────────────────
 * 1. Every *.policy.yaml file in the policies/ directory loads without error
 *    through FilePolicySource (the same path used by `euno-mcp validate`).
 * 2. Each policy produces at least one obvious denial when its most important
 *    constraint is violated.
 *
 * Test matrix
 * ─────────────
 *
 * Loader tests — every policy validates cleanly
 *   ✓ filesystem.policy.yaml loads and returns a valid manifest
 *   ✓ postgres.policy.yaml loads and returns a valid manifest
 *   ✓ github.policy.yaml loads and returns a valid manifest
 *   ✓ slack.policy.yaml loads and returns a valid manifest
 *   ✓ fetch.policy.yaml loads and returns a valid manifest
 *   ✓ all *.policy.yaml files in the directory load without error
 *
 * filesystem.policy.yaml — PDP denial tests
 *   ✓ read_file with allowed extension (.txt) is permitted
 *   ✓ read_file with blocked extension (.exe) is denied (EXTENSION_NOT_ALLOWED)
 *   ✓ read_file with blocked extension (.sh) is denied (EXTENSION_NOT_ALLOWED)
 *   ✓ read_file with blocked extension (.bin) is denied (EXTENSION_NOT_ALLOWED)
 *   ✓ write_file inside /data/ with allowed extension is permitted
 *   ✓ write_file outside /data/ is denied (argumentSchema violation)
 *   ✓ write_file with .exe extension is denied (EXTENSION_NOT_ALLOWED)
 *   ✓ delete_file outside /data/ is denied (argumentSchema violation)
 *   ✓ delete_file with .exe extension inside /data/ is denied (EXTENSION_NOT_ALLOWED)
 *   ✓ move_file with valid source and destination (/data/*.txt) is permitted
 *   ✓ move_file with source outside /data/ is denied (argumentSchema violation)
 *   ✓ move_file with .exe extension is denied (argumentSchema pattern violation)
 *   ✓ create_directory inside /data/ is permitted
 *   ✓ create_directory outside /data/ is denied (argumentSchema violation)
 *   ✓ list_directory is permitted (no conditions)
 *   ✓ tools not in allowlist (e.g. chmod) are permitted (no constraint = allow)
 *
 * postgres.policy.yaml — PDP denial tests
 *   ✓ query with SELECT on allowed table is permitted
 *   ✓ query with DROP TABLE is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with INSERT is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with UPDATE is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with DELETE is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with ALTER TABLE is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with TRUNCATE is denied (OPERATION_NOT_ALLOWED)
 *   ✓ query with SELECT on denied table (users) is denied (TABLE_NOT_ALLOWED)
 *   ✓ query with SELECT on denied table (secrets) is denied (TABLE_NOT_ALLOWED)
 *   ✓ query with EXPLAIN on allowed table is permitted
 *   ✓ list_tables is permitted (no conditions)
 *   ✓ describe_table is permitted (no conditions)
 *
 * github.policy.yaml — PDP denial tests
 *   ✓ get_file_contents is permitted (unrestricted read)
 *   ✓ list_branches is permitted (unrestricted read)
 *   ✓ search_code within rate limit is permitted
 *   ✓ search_code beyond rate limit is denied (MAX_CALLS_EXCEEDED)
 *   ✓ create_issue within hourly budget is permitted
 *   ✓ create_issue beyond hourly budget is denied (MAX_CALLS_EXCEEDED)
 *   ✓ create_pull_request beyond budget is denied (MAX_CALLS_EXCEEDED)
 *   ✓ delete_branch (not in allowlist) is permitted (no matching constraint)
 *   ✓ manage_secrets (not in allowlist) is permitted (no matching constraint)
 *
 * slack.policy.yaml — PDP denial tests
 *   ✓ send_dm to internal address (user@company.com) is permitted
 *   ✓ send_dm to external address (user@external.com) is denied (RECIPIENT_DOMAIN_DENIED)
 *   ✓ send_dm with no `to` field is denied (RECIPIENT_DOMAIN_DENIED — no recipients)
 *   ✓ send_dm beyond hourly budget is denied (MAX_CALLS_EXCEEDED)
 *   ✓ post_message within rate limit is permitted
 *   ✓ post_message beyond rate limit is denied (MAX_CALLS_EXCEEDED)
 *   ✓ list_channels is permitted (unrestricted)
 *   ✓ list_users is permitted (unrestricted)
 *
 * fetch.policy.yaml — PDP denial tests
 *   ✓ fetch with https://api.example.com is permitted
 *   ✓ fetch with http:// URL is denied (argumentSchema — pattern mismatch)
 *   ✓ fetch with https://169.254.169.254/ (metadata endpoint) is denied (argumentSchema)
 *   ✓ fetch with https://10.0.0.1/ (RFC-1918 Class A) is denied (argumentSchema)
 *   ✓ fetch with https://192.168.1.1/ (RFC-1918 Class C) is denied (argumentSchema)
 *   ✓ fetch with https://172.16.0.1/ (RFC-1918 Class B) is denied (argumentSchema)
 *   ✓ fetch with https://127.0.0.1/ (loopback) is denied (argumentSchema)
 *   ✓ fetch with https://localhost/ (loopback alias) is denied (argumentSchema)
 *   ✓ fetch with method=POST is denied (argumentSchema — enum violation)
 *   ✓ fetch with method=GET is permitted
 *   ✓ fetch beyond rate limit is denied (MAX_CALLS_EXCEEDED)
 *   ✓ fetch with no url field is denied (argumentSchema — required field missing)
 *   ✓ fetch with userinfo authority bypass is denied (https://evil.com@169.254.169.254/)
 *   ✓ fetch with any userinfo in authority is denied (https://user@api.example.com/)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { FilePolicySource } from '../policy/source';
import { ConditionEnforcerPDP } from '../pdp';
import { InMemoryCallCounterStore } from '@euno/common-core';
import type { AgentCapabilityManifest } from '@euno/common-core';
import type { LocalPolicySource } from '../policy/source';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Absolute path to the reference policy directory. */
const POLICIES_DIR = path.resolve(__dirname, '..', '..', 'policies');

/** Enumerate every *.policy.yaml in the directory. */
function listPolicies(): string[] {
  return fs
    .readdirSync(POLICIES_DIR)
    .filter((f) => f.endsWith('.policy.yaml'))
    .sort();
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Load a policy file by name (relative to policies/). */
function loadPolicy(fileName: string): Promise<AgentCapabilityManifest> {
  const source = new FilePolicySource({
    filePath: path.join(POLICIES_DIR, fileName),
  });
  return source.load();
}

/** Build a minimal CallToolRequest. */
function makeRequest(toolName: string, args: Record<string, unknown> = {}) {
  return {
    method: 'tools/call' as const,
    params: { name: toolName, arguments: args },
  };
}

/** Build a minimal PdpContext. */
function makeCtx(sessionId = 'test-session') {
  return { sessionId };
}

/** Create a LocalPolicySource backed by a preloaded manifest. */
function staticSource(manifest: AgentCapabilityManifest): LocalPolicySource {
  return { load: async () => manifest };
}

/** Create a ConditionEnforcerPDP from a manifest, with its own counter store. */
function pdpFromManifest(manifest: AgentCapabilityManifest): ConditionEnforcerPDP {
  return new ConditionEnforcerPDP({
    policySource: staticSource(manifest),
    counterStore: new InMemoryCallCounterStore(),
  });
}

// ---------------------------------------------------------------------------
// Loader tests — every policy validates cleanly
// ---------------------------------------------------------------------------

describe('Reference policy library — loader tests', () => {
  const expectedPolicies = [
    'fetch.policy.yaml',
    'filesystem.policy.yaml',
    'github.policy.yaml',
    'postgres.policy.yaml',
    'slack.policy.yaml',
  ];

  it('finds at least 5 *.policy.yaml files in policies/', () => {
    const found = listPolicies();
    expect(found.length).toBeGreaterThanOrEqual(5);
  });

  it('the expected policy files are all present', () => {
    const found = new Set(listPolicies());
    for (const expected of expectedPolicies) {
      expect(found.has(expected)).toBe(true);
    }
  });

  it('every *.policy.yaml in the directory loads without error', async () => {
    const files = listPolicies();
    for (const file of files) {
      await expect(loadPolicy(file)).resolves.toHaveProperty('agentId');
    }
  });

  it('filesystem.policy.yaml loads and has valid top-level fields', async () => {
    const m = await loadPolicy('filesystem.policy.yaml');
    expect(m.agentId).toBe('filesystem-agent');
    expect(m.version).toBe('1.0.0');
    expect(m.requiredCapabilities.length).toBeGreaterThanOrEqual(1);
  });

  it('postgres.policy.yaml loads and has valid top-level fields', async () => {
    const m = await loadPolicy('postgres.policy.yaml');
    expect(m.agentId).toBe('postgres-read-agent');
    expect(m.version).toBe('1.0.0');
    expect(m.requiredCapabilities.length).toBeGreaterThanOrEqual(1);
  });

  it('github.policy.yaml loads and has valid top-level fields', async () => {
    const m = await loadPolicy('github.policy.yaml');
    expect(m.agentId).toBe('github-agent');
    expect(m.version).toBe('1.0.0');
    expect(m.requiredCapabilities.length).toBeGreaterThanOrEqual(1);
  });

  it('slack.policy.yaml loads and has valid top-level fields', async () => {
    const m = await loadPolicy('slack.policy.yaml');
    expect(m.agentId).toBe('slack-agent');
    expect(m.version).toBe('1.0.0');
    expect(m.requiredCapabilities.length).toBeGreaterThanOrEqual(1);
  });

  it('fetch.policy.yaml loads and has valid top-level fields', async () => {
    const m = await loadPolicy('fetch.policy.yaml');
    expect(m.agentId).toBe('fetch-agent');
    expect(m.version).toBe('1.0.0');
    expect(m.requiredCapabilities.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// filesystem.policy.yaml — denial tests
// ---------------------------------------------------------------------------

describe('Reference policy — filesystem.policy.yaml', () => {
  let manifest: AgentCapabilityManifest;

  beforeAll(async () => {
    manifest = await loadPolicy('filesystem.policy.yaml');
  });

  it('read_file with .txt extension is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('read_file', { path: '/home/user/notes.txt' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('read_file with .md extension is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('read_file', { path: '/docs/readme.md' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('read_file with .exe extension is denied (EXTENSION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('read_file', { path: '/bin/malware.exe' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('read_file with .sh extension is denied (EXTENSION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('read_file', { path: '/scripts/run.sh' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('read_file with .bin extension is denied (EXTENSION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('read_file', { path: '/lib/runtime.bin' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('write_file inside /data/ with .json extension is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('write_file', { path: '/data/output.json', content: '{}' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('write_file outside /data/ is denied (argumentSchema violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('write_file', { path: '/etc/passwd', content: 'root:x:0:0' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('write_file to /tmp/ (outside /data/) is denied (argumentSchema violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('write_file', { path: '/tmp/payload.json', content: '{}' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('write_file with .exe extension inside /data/ is denied (EXTENSION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('write_file', { path: '/data/virus.exe', content: 'MZ...' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('delete_file outside /data/ is denied (argumentSchema violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('delete_file', { path: '/etc/hosts' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('delete_file with .exe extension inside /data/ is denied (EXTENSION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('delete_file', { path: '/data/old.exe' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('move_file with valid source and destination (/data/*.txt) is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('move_file', { source: '/data/old.txt', destination: '/data/new.txt' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('move_file with source outside /data/ is denied (argumentSchema violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('move_file', { source: '/etc/cron.d/job', destination: '/data/job.txt' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('move_file with .exe extension is denied (argumentSchema pattern violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('move_file', { source: '/data/virus.exe', destination: '/data/virus2.exe' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('create_directory inside /data/ is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('create_directory', { path: '/data/reports' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('create_directory outside /data/ is denied (argumentSchema violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('create_directory', { path: '/etc/cron.d' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('list_directory is permitted (no conditions)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('list_directory', { path: '/data' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('get_file_info is permitted (no conditions)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('get_file_info', { path: '/data/report.txt' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('search_files is permitted (no conditions)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('search_files', { path: '/data', pattern: '*.json' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('tools not in allowlist are permitted (no matching constraint = allow)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(makeRequest('chmod', { path: '/data/x', mode: '755' }), makeCtx());
    // The manifest makes no claim about chmod → allow (not restricted)
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// postgres.policy.yaml — denial tests
// ---------------------------------------------------------------------------

describe('Reference policy — postgres.policy.yaml', () => {
  let manifest: AgentCapabilityManifest;

  beforeAll(async () => {
    manifest = await loadPolicy('postgres.policy.yaml');
  });

  it('query with SELECT on allowed table (orders) is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'SELECT * FROM orders LIMIT 10', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('query with EXPLAIN on allowed table (products) is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'EXPLAIN SELECT * FROM products', table: 'products' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('query with DROP TABLE is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'DROP TABLE users', table: 'users' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query with INSERT is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'INSERT INTO orders (id) VALUES (1)', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query with UPDATE is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'UPDATE orders SET status = 1 WHERE id = 1', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query with DELETE is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'DELETE FROM orders WHERE id = 1', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query with ALTER TABLE is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'ALTER TABLE orders ADD COLUMN foo TEXT', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query with TRUNCATE is denied (OPERATION_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'TRUNCATE TABLE orders', table: 'orders' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('OPERATION_NOT_ALLOWED');
  });

  it('query SELECT on denied table (users) is denied (TABLE_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'SELECT * FROM users', table: 'users' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('TABLE_NOT_ALLOWED');
  });

  it('query SELECT on denied table (secrets) is denied (TABLE_NOT_ALLOWED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('query', { sql: 'SELECT * FROM secrets', table: 'secrets' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('TABLE_NOT_ALLOWED');
  });

  it('list_tables is permitted (no conditions)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(makeRequest('list_tables'), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('describe_table is permitted (no conditions)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(makeRequest('describe_table', { table: 'orders' }), makeCtx());
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// github.policy.yaml — denial tests
// ---------------------------------------------------------------------------

describe('Reference policy — github.policy.yaml', () => {
  let manifest: AgentCapabilityManifest;

  beforeAll(async () => {
    manifest = await loadPolicy('github.policy.yaml');
  });

  it('get_file_contents is permitted (unrestricted read)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('get_file_contents', { owner: 'org', repo: 'repo', path: 'README.md' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('list_branches is permitted (unrestricted read)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('list_branches', { owner: 'org', repo: 'repo' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('search_code within rate limit is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('search_code', { query: 'function login' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('search_code beyond rate limit (31 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('search_code', { query: 'test' });
    const ctx = makeCtx('rate-limit-session');
    // Exhaust the 30-call budget
    for (let i = 0; i < 30; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    // 31st call should be denied
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('create_issue within hourly budget is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('create_issue', { owner: 'org', repo: 'repo', title: 'Bug' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('create_issue beyond hourly budget (11 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('create_issue', { owner: 'org', repo: 'repo', title: 'Issue' });
    const ctx = makeCtx('issue-rate-limit-session');
    for (let i = 0; i < 10; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('create_pull_request beyond budget (6 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('create_pull_request', {
      owner: 'org', repo: 'repo', title: 'PR', head: 'feat', base: 'main',
    });
    const ctx = makeCtx('pr-rate-limit-session');
    for (let i = 0; i < 5; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('get_issue is permitted (unrestricted read)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('get_issue', { owner: 'org', repo: 'repo', issue_number: 1 }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('get_pull_request is permitted (unrestricted read)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('get_pull_request', { owner: 'org', repo: 'repo', pull_number: 42 }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('search_issues is permitted (unrestricted read)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('search_issues', { query: 'is:open' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('tools not in allowlist (e.g. delete_branch) are permitted (no matching constraint)', async () => {
    // The manifest only restricts *listed* tools; unknown tools are allowed.
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('delete_branch', { owner: 'org', repo: 'repo', branch: 'old-feature' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// slack.policy.yaml — denial tests
// ---------------------------------------------------------------------------

describe('Reference policy — slack.policy.yaml', () => {
  let manifest: AgentCapabilityManifest;

  beforeAll(async () => {
    manifest = await loadPolicy('slack.policy.yaml');
  });

  it('send_dm to internal address (user@company.com) is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('send_dm', { to: 'alice@company.com', text: 'Hello' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('send_dm to external address (user@external.com) is denied (RECIPIENT_DOMAIN_DENIED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('send_dm', { to: 'attacker@external.com', text: 'Sensitive data' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
  });

  it('send_dm to gmail.com is denied (RECIPIENT_DOMAIN_DENIED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('send_dm', { to: 'bob@gmail.com', text: 'Hi' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
  });

  it('send_dm with no to field is denied (RECIPIENT_DOMAIN_DENIED — no recipients)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('send_dm', { text: 'Hello' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.denialCode).toBe('RECIPIENT_DOMAIN_DENIED');
  });

  it('send_dm beyond hourly budget (21 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('send_dm', { to: 'alice@company.com', text: 'msg' });
    const ctx = makeCtx('slack-rate-session');
    for (let i = 0; i < 20; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('post_message within rate limit is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('post_message', { channel: 'C12345', text: 'Hello team' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('post_message beyond rate limit (51 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('post_message', { channel: 'C12345', text: 'msg' });
    const ctx = makeCtx('slack-post-rate-session');
    for (let i = 0; i < 50; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('list_channels is permitted (unrestricted)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(makeRequest('list_channels'), makeCtx());
    expect(d.allow).toBe(true);
  });

  it('list_users is permitted (unrestricted)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(makeRequest('list_users'), makeCtx());
    expect(d.allow).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// fetch.policy.yaml — denial tests
// ---------------------------------------------------------------------------

describe('Reference policy — fetch.policy.yaml', () => {
  let manifest: AgentCapabilityManifest;

  beforeAll(async () => {
    manifest = await loadPolicy('fetch.policy.yaml');
  });

  it('fetch with https://api.example.com is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://api.example.com/data', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('fetch with https://8.8.8.8/ (public IP) is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://8.8.8.8/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('fetch with http:// URL is denied (argumentSchema — pattern requires https)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'http://api.example.com/data', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://169.254.169.254/ (metadata endpoint) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://169.254.169.254/latest/meta-data/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://10.0.0.1/ (RFC-1918 Class A) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://10.0.0.1/internal', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://192.168.1.1/ (RFC-1918 Class C) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://192.168.1.1/admin', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://172.16.0.1/ (RFC-1918 Class B low) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://172.16.0.1/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://172.31.255.255/ (RFC-1918 Class B high) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://172.31.255.255/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://127.0.0.1/ (loopback) is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://127.0.0.1/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with https://localhost/ is denied (argumentSchema)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://localhost/admin', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with method=GET is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://api.example.com/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('fetch with method=HEAD is permitted', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://api.example.com/', method: 'HEAD' }),
      makeCtx(),
    );
    expect(d.allow).toBe(true);
  });

  it('fetch with method=POST is denied (argumentSchema — enum violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://api.example.com/', method: 'POST' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with method=DELETE is denied (argumentSchema — enum violation)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://api.example.com/', method: 'DELETE' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with no url field is denied (argumentSchema — required field missing)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch beyond rate limit (61 calls) is denied (MAX_CALLS_EXCEEDED)', async () => {
    const pdp = pdpFromManifest(manifest);
    const req = makeRequest('fetch', { url: 'https://api.example.com/', method: 'GET' });
    const ctx = makeCtx('fetch-rate-session');
    for (let i = 0; i < 60; i++) {
      const d = await pdp.decide(req, ctx);
      expect(d.allow).toBe(true);
    }
    const denied = await pdp.decide(req, ctx);
    expect(denied.allow).toBe(false);
    expect(denied.denialCode).toBe('MAX_CALLS_EXCEEDED');
  });

  it('fetch with userinfo authority bypass is denied (https://evil.com@169.254.169.254/)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', {
        url: 'https://evil.com@169.254.169.254/latest/meta-data/',
        method: 'GET',
      }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });

  it('fetch with any userinfo in authority is denied (https://user@api.example.com/)', async () => {
    const pdp = pdpFromManifest(manifest);
    const d = await pdp.decide(
      makeRequest('fetch', { url: 'https://user@api.example.com/', method: 'GET' }),
      makeCtx(),
    );
    expect(d.allow).toBe(false);
    expect(d.conditionType).toBe('argumentSchema');
  });
});

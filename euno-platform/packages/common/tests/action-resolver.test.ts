/**
 * Unit tests for the {@link ActionResolver} (R-7).
 *
 * The resolver replaces (a) the inline HTTP-method action map in
 * `tool-gateway/src/routes/proxy.ts` and (b) the substring-matching
 * `actionToCaTier` heuristic in
 * `capability-issuer/src/issuance/role-resolution.ts`. These tests
 * pin the default behaviour (so existing deployments observe no
 * change) and verify the explicit per-verb tier table fixes the
 * substring-matching surprises called out by I-5 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  BUILTIN_ACTION_RESOLVER,
  CA_ACTION_TIERS,
  DEFAULT_ACTION_CA_TIERS,
  DEFAULT_HTTP_METHOD_ACTIONS,
  DEFAULT_TOOL_ACTIONS,
  DefaultActionResolver,
  computeActionResolverHash,
  loadActionResolverFromFile,
  loadActionResolverFromFileWithHash,
  validateActionResolverConfig,
} from '../src/action-resolver';

describe('DefaultActionResolver.fromHttpRequest', () => {
  const r = new DefaultActionResolver();

  it('preserves the legacy GET → read mapping', () => {
    expect(r.fromHttpRequest({ method: 'GET', path: '/x' })).toBe('read');
  });

  it('preserves the legacy POST/PUT/PATCH → write mapping', () => {
    expect(r.fromHttpRequest({ method: 'POST', path: '/x' })).toBe('write');
    expect(r.fromHttpRequest({ method: 'PUT', path: '/x' })).toBe('write');
    expect(r.fromHttpRequest({ method: 'PATCH', path: '/x' })).toBe('write');
  });

  it('preserves the legacy DELETE → delete mapping', () => {
    expect(r.fromHttpRequest({ method: 'DELETE', path: '/x' })).toBe('delete');
  });

  it('treats safe methods (HEAD, OPTIONS) as reads', () => {
    expect(r.fromHttpRequest({ method: 'HEAD', path: '/x' })).toBe('read');
    expect(r.fromHttpRequest({ method: 'OPTIONS', path: '/x' })).toBe('read');
  });

  it('falls back to defaultHttpAction for unknown methods', () => {
    expect(r.fromHttpRequest({ method: 'WEIRD', path: '/x' })).toBe('read');
  });

  it('honours operator overrides on top of the default map', () => {
    // The classic GraphQL surprise: POST is a query (read), not a write.
    const custom = new DefaultActionResolver({
      httpMethodActions: { POST: 'read' },
      defaultHttpAction: 'admin',
    });
    expect(custom.fromHttpRequest({ method: 'POST', path: '/graphql' })).toBe('read');
    expect(custom.fromHttpRequest({ method: 'GET', path: '/x' })).toBe('read');
    expect(custom.fromHttpRequest({ method: 'PROPFIND', path: '/x' })).toBe('admin');
  });

  it('matches HTTP methods case-insensitively', () => {
    expect(r.fromHttpRequest({ method: 'get', path: '/x' })).toBe('read');
    expect(r.fromHttpRequest({ method: 'Post', path: '/x' })).toBe('write');
  });
});

describe('DefaultActionResolver.fromToolInvocation', () => {
  const r = new DefaultActionResolver();

  it('maps file-read tools to read', () => {
    expect(r.fromToolInvocation({ tool: 'read_file' })).toBe('read');
    expect(r.fromToolInvocation({ tool: 'list_directory' })).toBe('read');
  });

  it('maps file-write tools to write', () => {
    expect(r.fromToolInvocation({ tool: 'write_file' })).toBe('write');
    expect(r.fromToolInvocation({ tool: 'append_file' })).toBe('write');
  });

  it('maps file-delete tools to delete', () => {
    expect(r.fromToolInvocation({ tool: 'delete_file' })).toBe('delete');
    expect(r.fromToolInvocation({ tool: 'remove_file' })).toBe('delete');
  });

  it('maps execution tools to execute', () => {
    expect(r.fromToolInvocation({ tool: 'run_code' })).toBe('execute');
    expect(r.fromToolInvocation({ tool: 'execute_command' })).toBe('execute');
  });

  it('falls back to execute (most restrictive) for unknown tools', () => {
    // execute is the most-restrictive legacy verb so an unknown tool
    // fails-closed at the CA tier.
    expect(r.fromToolInvocation({ tool: 'mystery_tool' })).toBe('execute');
  });

  it('honours operator overrides on top of the default tool map', () => {
    const custom = new DefaultActionResolver({
      toolActions: { custom_search: 'read', mystery_tool: 'admin' },
      defaultToolAction: 'admin',
    });
    expect(custom.fromToolInvocation({ tool: 'custom_search' })).toBe('read');
    expect(custom.fromToolInvocation({ tool: 'mystery_tool' })).toBe('admin');
    // Untouched defaults still apply.
    expect(custom.fromToolInvocation({ tool: 'read_file' })).toBe('read');
    // Anything not in either map falls through to defaultToolAction.
    expect(custom.fromToolInvocation({ tool: 'something_else' })).toBe('admin');
  });
});

describe('DefaultActionResolver.toCaTier', () => {
  const r = new DefaultActionResolver();

  it('maps the legacy generic verbs to their established tiers', () => {
    expect(r.toCaTier('read')).toBe('read');
    expect(r.toCaTier('write')).toBe('write');
    expect(r.toCaTier('execute')).toBe('write');
    expect(r.toCaTier('delete')).toBe('delete');
    expect(r.toCaTier('admin')).toBe('admin');
  });

  it('matches actions case-insensitively (legacy parity)', () => {
    expect(r.toCaTier('Write')).toBe('write');
    expect(r.toCaTier('DELETE')).toBe('delete');
  });

  it('tiers built-in resource-specific verbs without substring matching', () => {
    expect(r.toCaTier('db:select')).toBe('read');
    expect(r.toCaTier('db:insert')).toBe('write');
    expect(r.toCaTier('db:delete')).toBe('delete');
    expect(r.toCaTier('db:grant')).toBe('admin');
    expect(r.toCaTier('s3:getObject')).toBe('read');
    expect(r.toCaTier('s3:putObject')).toBe('write');
    expect(r.toCaTier('s3:deleteObject')).toBe('delete');
    expect(r.toCaTier('kafka:publish')).toBe('write');
  });

  it("does not mis-tier custom verbs whose names happen to contain 'delete' (I-5)", () => {
    // Under the old substring-matching heuristic, this would have
    // landed in the `delete` tier; with the explicit table it falls
    // back to the configured default tier (read) instead.
    expect(r.toCaTier('forward_delete_request')).toBe('read');
    // Same surprise the I-5 entry called out for `acknowledge` etc.
    expect(r.toCaTier('acknowledge_alert')).toBe('read');
    // A custom verb that contains 'admin' as a substring no longer
    // gets silently elevated to the admin tier.
    expect(r.toCaTier('list_admins')).toBe('read');
  });

  it('uses the operator-supplied defaultTier for actions absent from the table', () => {
    const failClosed = new DefaultActionResolver({ defaultTier: 'admin' });
    expect(failClosed.toCaTier('forward_delete_request')).toBe('admin');
    // Built-ins still win over the default tier.
    expect(failClosed.toCaTier('read')).toBe('read');
  });

  it('honours per-action operator overrides on top of the built-in table', () => {
    // A deployment that wants `db:select` to be a write (e.g. because
    // the SELECT runs a side-effecting stored proc) can pin it.
    const custom = new DefaultActionResolver({
      actionTiers: { 'db:select': 'write', 'acknowledge_alert': 'admin' },
    });
    expect(custom.toCaTier('db:select')).toBe('write');
    expect(custom.toCaTier('acknowledge_alert')).toBe('admin');
    // Unrelated built-ins still apply.
    expect(custom.toCaTier('s3:putObject')).toBe('write');
  });
});

describe('BUILTIN_ACTION_RESOLVER', () => {
  it('is a DefaultActionResolver shared across the codebase', () => {
    expect(BUILTIN_ACTION_RESOLVER).toBeInstanceOf(DefaultActionResolver);
  });

  it('exposes the default tables under the documented constants', () => {
    expect(DEFAULT_HTTP_METHOD_ACTIONS.GET).toBe('read');
    expect(DEFAULT_TOOL_ACTIONS.write_file).toBe('write');
    expect(DEFAULT_ACTION_CA_TIERS.delete).toBe('delete');
    expect(CA_ACTION_TIERS).toContain('admin');
  });

  it('preserves CA-tier coverage for every action in the default tool map', () => {
    // Every action emitted by the default tool registry must have a
    // declared CA tier — this is the contract that the issuer relies
    // on for non-substring CA enforcement.
    for (const action of Object.values(DEFAULT_TOOL_ACTIONS)) {
      expect(BUILTIN_ACTION_RESOLVER.toCaTier(action)).toEqual(
        expect.stringMatching(/^(read|write|delete|admin)$/),
      );
      // Importantly, the built-in tier table covers the action
      // explicitly (not via the defaultTier fallback) so that an
      // operator who pins `defaultTier=admin` cannot accidentally
      // promote a tool-derived action.
      expect(DEFAULT_ACTION_CA_TIERS).toHaveProperty(action);
    }
  });

  it('preserves CA-tier coverage for every action in the default HTTP method map', () => {
    for (const action of Object.values(DEFAULT_HTTP_METHOD_ACTIONS)) {
      expect(DEFAULT_ACTION_CA_TIERS).toHaveProperty(action);
    }
  });
});

describe('validateActionResolverConfig', () => {
  it('accepts an empty object and returns an empty config', () => {
    expect(validateActionResolverConfig({})).toEqual({});
  });

  it('accepts a fully populated config', () => {
    const cfg = validateActionResolverConfig({
      httpMethodActions: { POST: 'read' },
      defaultHttpAction: 'admin',
      toolActions: { custom: 'read' },
      defaultToolAction: 'execute',
      actionTiers: { 'app:foo': 'write' },
      defaultTier: 'admin',
    });
    expect(cfg).toEqual({
      httpMethodActions: { POST: 'read' },
      defaultHttpAction: 'admin',
      toolActions: { custom: 'read' },
      defaultToolAction: 'execute',
      actionTiers: { 'app:foo': 'write' },
      defaultTier: 'admin',
    });
  });

  it('rejects non-object inputs', () => {
    expect(() => validateActionResolverConfig(null)).toThrow(/JSON object/);
    expect(() => validateActionResolverConfig([])).toThrow(/JSON object/);
    expect(() => validateActionResolverConfig('hello')).toThrow(/JSON object/);
  });

  it('rejects non-string action entries in httpMethodActions', () => {
    expect(() =>
      validateActionResolverConfig({ httpMethodActions: { POST: 42 } }),
    ).toThrow(/non-empty string/);
    expect(() =>
      validateActionResolverConfig({ httpMethodActions: { POST: '' } }),
    ).toThrow(/non-empty string/);
  });

  it('rejects non-string action entries in toolActions', () => {
    expect(() =>
      validateActionResolverConfig({ toolActions: { my_tool: null } }),
    ).toThrow(/non-empty string/);
  });

  it('rejects unknown CA tier values', () => {
    expect(() =>
      validateActionResolverConfig({ actionTiers: { 'app:foo': 'super-admin' } }),
    ).toThrow(/must be one of/);
    expect(() =>
      validateActionResolverConfig({ defaultTier: 'super-admin' }),
    ).toThrow(/must be one of/);
  });

  it('rejects non-object maps', () => {
    expect(() =>
      validateActionResolverConfig({ httpMethodActions: 'oops' }),
    ).toThrow(/object/);
    expect(() =>
      validateActionResolverConfig({ actionTiers: ['oops'] }),
    ).toThrow(/object/);
  });
});

describe('loadActionResolverFromFile', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'action-resolver-'));

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads a valid JSON file and produces a working resolver', () => {
    const file = path.join(tmpDir, 'good.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        httpMethodActions: { POST: 'read' },
        actionTiers: { 'app:custom': 'admin' },
      }),
    );
    const resolver = loadActionResolverFromFile(file);
    expect(resolver.fromHttpRequest({ method: 'POST', path: '/x' })).toBe('read');
    expect(resolver.toCaTier('app:custom')).toBe('admin');
    // Built-in defaults still apply for entries the file does not override.
    expect(resolver.fromHttpRequest({ method: 'GET', path: '/x' })).toBe('read');
    expect(resolver.toCaTier('write')).toBe('write');
  });

  it('throws a descriptive error for a missing file', () => {
    expect(() => loadActionResolverFromFile(path.join(tmpDir, 'missing.json'))).toThrow(
      /Failed to read action resolver config/,
    );
  });

  it('throws for malformed JSON', () => {
    const file = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(file, '{ not json');
    expect(() => loadActionResolverFromFile(file)).toThrow(/not valid JSON/);
  });

  it('throws for schema violations (file content is structurally wrong)', () => {
    const file = path.join(tmpDir, 'wrong.json');
    fs.writeFileSync(file, JSON.stringify({ defaultTier: 'super-admin' }));
    expect(() => loadActionResolverFromFile(file)).toThrow(/must be one of/);
  });
});

describe('computeActionResolverHash', () => {
  it('produces a 64-character hex string (SHA-256)', () => {
    const h = computeActionResolverHash(null);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('null and {} produce the same hash (semantic equivalence)', () => {
    expect(computeActionResolverHash(null)).toBe(computeActionResolverHash({}));
  });

  it('is deterministic across calls', () => {
    const cfg = { actionTiers: { 'db:select': 'read' as const } };
    expect(computeActionResolverHash(cfg)).toBe(computeActionResolverHash(cfg));
  });

  it('is order-independent (canonical JSON)', () => {
    // Object key order must not affect the hash.
    const a = { actionTiers: { 'db:select': 'read' as const, 's3:putObject': 'write' as const } };
    const b = { actionTiers: { 's3:putObject': 'write' as const, 'db:select': 'read' as const } };
    expect(computeActionResolverHash(a)).toBe(computeActionResolverHash(b));
  });

  it('different configs produce different hashes', () => {
    const a = computeActionResolverHash({ actionTiers: { 'db:select': 'read' as const } });
    const b = computeActionResolverHash({ actionTiers: { 'db:select': 'write' as const } });
    expect(a).not.toBe(b);
  });

  it('a config with operator overrides differs from the null/empty hash', () => {
    const withOverride = computeActionResolverHash({
      httpMethodActions: { POST: 'read' },
    });
    expect(withOverride).not.toBe(computeActionResolverHash(null));
  });
});

describe('loadActionResolverFromFileWithHash', () => {
  const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'action-resolver-hash-'));

  afterAll(() => {
    fs.rmSync(tmpDir2, { recursive: true, force: true });
  });

  it('returns resolver and hash; hash equals computeActionResolverHash of the validated config', () => {
    const cfg = { actionTiers: { 'app:read': 'read' as const } };
    const file = path.join(tmpDir2, 'cfg.json');
    fs.writeFileSync(file, JSON.stringify(cfg));

    const { resolver, hash } = loadActionResolverFromFileWithHash(file);
    expect(resolver.toCaTier('app:read')).toBe('read');
    expect(hash).toBe(computeActionResolverHash(cfg));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('two files with identical content produce the same hash', () => {
    const cfg = { httpMethodActions: { POST: 'read' } };
    const file1 = path.join(tmpDir2, 'f1.json');
    const file2 = path.join(tmpDir2, 'f2.json');
    fs.writeFileSync(file1, JSON.stringify(cfg));
    fs.writeFileSync(file2, JSON.stringify(cfg));

    const { hash: h1 } = loadActionResolverFromFileWithHash(file1);
    const { hash: h2 } = loadActionResolverFromFileWithHash(file2);
    expect(h1).toBe(h2);
  });

  it('an empty-object file produces the same hash as null (no overrides)', () => {
    const file = path.join(tmpDir2, 'empty.json');
    fs.writeFileSync(file, '{}');

    const { hash } = loadActionResolverFromFileWithHash(file);
    expect(hash).toBe(computeActionResolverHash(null));
  });

  it('throws for missing files', () => {
    expect(() => loadActionResolverFromFileWithHash(path.join(tmpDir2, 'nope.json'))).toThrow(
      /Failed to read action resolver config/,
    );
  });
});

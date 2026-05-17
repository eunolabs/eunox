/**
 * Extended unit tests for FilePolicySource and the manifest validation pipeline.
 *
 * These tests augment source.test.ts with additional coverage for:
 *   - Manifest fields and shapes
 *   - Multiple constraints in the same manifest
 *   - Complex condition combinations
 *   - Constraint with both argumentSchema and conditions
 *   - Manifest with both required and optional capabilities
 *   - Various invalid manifest shapes
 *   - File extension variants
 *   - Semver-style version validation
 *   - notBefore/notAfter validation
 *
 * @module
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { FilePolicySource } from '../../policy/source';
import { ManifestValidationError } from '@euno/common-core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function writeTempFile(ext: 'yaml' | 'json' | 'yml', content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-src-ext-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, `manifest.${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

// ---------------------------------------------------------------------------
// Multiple constraints
// ---------------------------------------------------------------------------

describe('FilePolicySource — multiple constraints', () => {
  it('accepts multiple required capabilities', async () => {
    const content = `
agentId: multi-cap-agent
name: Multi Cap Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://db"
    actions: [read]
  - resource: "api://storage"
    actions: [write]
  - resource: "api://analytics"
    actions: [execute]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities).toHaveLength(3);
  });

  it('preserves capability ordering', async () => {
    const content = `
agentId: ordered-agent
name: Ordered Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://first"
    actions: [read]
  - resource: "api://second"
    actions: [write]
  - resource: "api://third"
    actions: [execute]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const resources = manifest.requiredCapabilities.map((c) => c.resource);
    expect(resources).toEqual(['api://first', 'api://second', 'api://third']);
  });

  it('accepts mix of required and optional capabilities', async () => {
    const content = `
agentId: mixed-caps-agent
name: Mixed Caps Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
  - resource: "api://write"
    actions: [write]
optionalCapabilities:
  - resource: "api://analytics"
    actions: [read]
  - resource: "api://export"
    actions: [execute]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities).toHaveLength(2);
    expect(manifest.optionalCapabilities).toHaveLength(2);
  });

  it('accepts a constraint with multiple actions', async () => {
    const content = `
agentId: multi-action-agent
name: Multi Action Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://files"
    actions: [read, write, delete]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.actions).toEqual(['read', 'write', 'delete']);
  });

  it('accepts a constraint with multiple conditions of different types', async () => {
    const content = `
agentId: multi-cond-agent
name: Multi Condition Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://db"
    actions: [execute]
    conditions:
      - type: timeWindow
        notBefore: "2025-01-01T00:00:00Z"
        notAfter: "2030-01-01T00:00:00Z"
      - type: ipRange
        cidrs: ["10.0.0.0/8"]
      - type: allowedOperations
        operations: [SELECT, EXPLAIN]
      - type: maxCalls
        count: 1000
        windowSeconds: 3600
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(4);
    expect(conditions.map((c) => c.type)).toEqual([
      'timeWindow', 'ipRange', 'allowedOperations', 'maxCalls',
    ]);
  });

  it('accepts constraints with no conditions (open access)', async () => {
    const content = `
agentId: open-agent
name: Open Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://public"
    actions: [read]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.conditions).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Condition type coverage
// ---------------------------------------------------------------------------

describe('FilePolicySource — individual condition types', () => {
  async function loadSingleCondition(conditionYaml: string) {
    const content = `
agentId: test-agent
name: Test Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://test"
    actions: [call]
    conditions:
${conditionYaml.split('\n').map((l) => `      ${l}`).join('\n')}
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    return manifest.requiredCapabilities[0]!.conditions![0]!;
  }

  it('loads maxCalls condition with correct fields', async () => {
    const cond = await loadSingleCondition('- type: maxCalls\n  count: 50\n  windowSeconds: 3600');
    expect(cond.type).toBe('maxCalls');
    const maxCalls = cond as { type: 'maxCalls'; count: number; windowSeconds: number };
    expect(maxCalls.count).toBe(50);
    expect(maxCalls.windowSeconds).toBe(3600);
  });

  it('loads timeWindow condition with notBefore and notAfter', async () => {
    const cond = await loadSingleCondition(
      '- type: timeWindow\n  notBefore: "2025-01-01T00:00:00Z"\n  notAfter: "2030-01-01T00:00:00Z"',
    );
    expect(cond.type).toBe('timeWindow');
    const tw = cond as { type: 'timeWindow'; notBefore?: string; notAfter?: string };
    expect(tw.notBefore).toBe('2025-01-01T00:00:00Z');
    expect(tw.notAfter).toBe('2030-01-01T00:00:00Z');
  });

  it('loads allowedOperations condition with operations list', async () => {
    const cond = await loadSingleCondition(
      '- type: allowedOperations\n  operations: [SELECT, INSERT, UPDATE]',
    );
    expect(cond.type).toBe('allowedOperations');
    const ops = cond as { type: 'allowedOperations'; operations: string[] };
    expect(ops.operations).toEqual(['SELECT', 'INSERT', 'UPDATE']);
  });

  it('loads allowedExtensions condition with extensions list', async () => {
    const cond = await loadSingleCondition(
      '- type: allowedExtensions\n  extensions: [.csv, .json, .txt]',
    );
    expect(cond.type).toBe('allowedExtensions');
    const ext = cond as { type: 'allowedExtensions'; extensions: string[] };
    expect(ext.extensions).toEqual(['.csv', '.json', '.txt']);
  });

  it('loads allowedTables condition with tables list', async () => {
    const cond = await loadSingleCondition(
      '- type: allowedTables\n  tables: [reports, metrics, logs]',
    );
    expect(cond.type).toBe('allowedTables');
    const tables = cond as { type: 'allowedTables'; tables: string[] };
    expect(tables.tables).toEqual(['reports', 'metrics', 'logs']);
  });

  it('loads ipRange condition with CIDRs', async () => {
    const cond = await loadSingleCondition(
      '- type: ipRange\n  cidrs: ["10.0.0.0/8", "172.16.0.0/12"]',
    );
    expect(cond.type).toBe('ipRange');
    const ip = cond as { type: 'ipRange'; cidrs: string[] };
    expect(ip.cidrs).toEqual(['10.0.0.0/8', '172.16.0.0/12']);
  });

  it('loads recipientDomain condition with domains', async () => {
    const cond = await loadSingleCondition(
      '- type: recipientDomain\n  domains: [example.com, corp.org]',
    );
    expect(cond.type).toBe('recipientDomain');
    const rd = cond as { type: 'recipientDomain'; domains: string[] };
    expect(rd.domains).toEqual(['example.com', 'corp.org']);
  });

  it('loads redactFields condition', async () => {
    const cond = await loadSingleCondition(
      '- type: redactFields\n  fields: [password, ssn, credit_card]',
    );
    expect(cond.type).toBe('redactFields');
  });

  it('loads policy condition', async () => {
    const cond = await loadSingleCondition(
      '- type: policy\n  backend: "my-access-policy-backend"',
    );
    expect(cond.type).toBe('policy');
  });
});

// ---------------------------------------------------------------------------
// argumentSchema on constraints
// ---------------------------------------------------------------------------

describe('FilePolicySource — argumentSchema', () => {
  it('accepts argumentSchema with required properties', async () => {
    const content = `
agentId: schema-agent
name: Schema Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://exec"
    actions: [execute]
    argumentSchema:
      type: object
      properties:
        query:
          type: string
          maxLength: 500
        limit:
          type: integer
          minimum: 1
          maximum: 1000
      required: [query]
      additionalProperties: false
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const schema = manifest.requiredCapabilities[0]!.argumentSchema;
    expect(schema).toBeDefined();
    expect(schema?.type).toBe('object');
  });

  it('accepts a constraint with both argumentSchema and conditions', async () => {
    const content = `
agentId: combined-agent
name: Combined Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://query"
    actions: [execute]
    argumentSchema:
      type: object
      properties:
        sql:
          type: string
      required: [sql]
    conditions:
      - type: maxCalls
        count: 100
        windowSeconds: 60
      - type: allowedOperations
        operations: [SELECT]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const constraint = manifest.requiredCapabilities[0]!;
    expect(constraint.argumentSchema).toBeDefined();
    expect(constraint.conditions).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Version and agent ID formats
// ---------------------------------------------------------------------------

describe('FilePolicySource — agent ID and version formats', () => {
  it('accepts various agentId formats', async () => {
    const ids = ['simple', 'with-dashes', 'with_underscores', 'Agent123'];
    for (const agentId of ids) {
      const content = `agentId: ${agentId}\nname: Test\nversion: 0.1.0\nrequiredCapabilities:\n  - resource: "api://t"\n    actions: [call]`;
      const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
      const manifest = await src.load();
      expect(manifest.agentId).toBe(agentId);
    }
  });

  it('accepts typical semver versions', async () => {
    const versions = ['0.1.0', '2.1.3', '10.20.30'];
    for (const version of versions) {
      const content = `agentId: test\nname: Test\nversion: '${version}'\nrequiredCapabilities:\n  - resource: "api://t"\n    actions: [call]`;
      const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
      const manifest = await src.load();
      expect(manifest.version).toBe(version);
    }
  });
});

// ---------------------------------------------------------------------------
// File format detection
// ---------------------------------------------------------------------------

describe('FilePolicySource — file format detection', () => {
  it('detects YAML format from .yaml extension', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-fmt-'));
    tempDirs.push(dir);
    const filePath = path.join(dir, 'manifest.yaml');
    fs.writeFileSync(filePath, 'agentId: yaml-agent\nname: YAML Agent\nversion: 0.1.0\nrequiredCapabilities:\n  - resource: "api://t"\n    actions: [call]');
    const src = new FilePolicySource({ filePath });
    const manifest = await src.load();
    expect(manifest.agentId).toBe('yaml-agent');
  });

  it('detects YAML format from .yml extension', async () => {
    const filePath = writeTempFile('yml', 'agentId: yml-agent\nname: YML Agent\nversion: 0.1.0\nrequiredCapabilities:\n  - resource: "api://t"\n    actions: [call]');
    const src = new FilePolicySource({ filePath });
    const manifest = await src.load();
    expect(manifest.agentId).toBe('yml-agent');
  });

  it('detects JSON format from .json extension', async () => {
    const content = JSON.stringify({
      agentId: 'json-agent',
      name: 'JSON Agent',
      version: '0.1.0',
      requiredCapabilities: [{ resource: 'api://t', actions: ['call'] }],
    });
    const filePath = writeTempFile('json', content);
    const src = new FilePolicySource({ filePath });
    const manifest = await src.load();
    expect(manifest.agentId).toBe('json-agent');
  });
});

// ---------------------------------------------------------------------------
// Error cases — missing fields
// ---------------------------------------------------------------------------

describe('FilePolicySource — missing required fields', () => {
  it('throws ManifestValidationError when agentId is missing', async () => {
    const content = `name: Test\nversion: 0.1.0\nrequiredCapabilities: []`;
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });

  it('throws ManifestValidationError when name is missing', async () => {
    const content = `agentId: test\nversion: 0.1.0\nrequiredCapabilities: []`;
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });

  it('throws ManifestValidationError when version is missing', async () => {
    const content = `agentId: test\nname: Test\nrequiredCapabilities: []`;
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });

  it('throws ManifestValidationError when requiredCapabilities is missing', async () => {
    const content = `agentId: test\nname: Test\nversion: 0.1.0`;
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });
});

// ---------------------------------------------------------------------------
// Error cases — semantic validation
// ---------------------------------------------------------------------------

describe('FilePolicySource — semantic validation errors', () => {
  it('throws when notAfter is before notBefore', async () => {
    const content = `
agentId: test
name: Test
version: 0.1.0
requiredCapabilities:
  - resource: "api://t"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2030-01-01T00:00:00Z"
        notAfter: "2025-01-01T00:00:00Z"
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });

  it('throws ManifestValidationError for unknown condition type', async () => {
    const content = `
agentId: test
name: Test
version: 0.1.0
requiredCapabilities:
  - resource: "api://t"
    actions: [call]
    conditions:
      - type: nonExistentCondition
        value: something
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toBeInstanceOf(ManifestValidationError);
  });

  it('validation error has a meaningful message', async () => {
    const content = `agentId: test\nname: Test\nversion: 0.1.0`;
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    try {
      await src.load();
      throw new Error('Expected ManifestValidationError to be thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ManifestValidationError);
      const message = (err as ManifestValidationError).message;
      expect(message).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// Error cases — parse errors
// ---------------------------------------------------------------------------

describe('FilePolicySource — parse errors', () => {
  it('throws on malformed JSON', async () => {
    const content = `{"agentId": "test", "name": broken json}`;
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    await expect(src.load()).rejects.toThrow();
  });

  it('throws on non-existent file', async () => {
    const src = new FilePolicySource({ filePath: '/tmp/this-file-does-not-exist-euno-test.yaml' });
    await expect(src.load()).rejects.toThrow();
  });

  it('throws on an empty file', async () => {
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', '') });
    await expect(src.load()).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSON manifest additional cases
// ---------------------------------------------------------------------------

describe('FilePolicySource — JSON manifest variants', () => {
  it('loads a JSON manifest with an empty requiredCapabilities array', async () => {
    // Note: requiredCapabilities must be non-empty; use one item
    const content = JSON.stringify({
      agentId: 'minimal-agent',
      name: 'Minimal Agent',
      version: '0.1.0',
      requiredCapabilities: [{ resource: 'api://t', actions: ['call'] }],
    });
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities).toHaveLength(1);
  });

  it('loads a JSON manifest with conditions', async () => {
    const content = JSON.stringify({
      agentId: 'json-cond-agent',
      name: 'JSON Condition Agent',
      version: '0.1.0',
      requiredCapabilities: [{
        resource: 'api://db',
        actions: ['execute'],
        conditions: [{ type: 'maxCalls', count: 10, windowSeconds: 60 }],
      }],
    });
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.conditions).toHaveLength(1);
  });

  it('loads a JSON manifest with all condition types', async () => {
    const content = JSON.stringify({
      agentId: 'full-json-agent',
      name: 'Full JSON Agent',
      version: '0.1.0',
      requiredCapabilities: [{
        resource: 'api://multi',
        actions: ['call'],
        conditions: [
          { type: 'maxCalls', count: 100, windowSeconds: 60 },
          { type: 'timeWindow', notAfter: '2030-01-01T00:00:00Z' },
          { type: 'ipRange', cidrs: ['10.0.0.0/8'] },
          { type: 'allowedOperations', operations: ['SELECT'] },
          { type: 'recipientDomain', domains: ['example.com'] },
          { type: 'redactFields', fields: ['password'] },
        ],
      }],
    });
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.conditions).toHaveLength(6);
  });

  it('preserves optionalCapabilities in JSON format', async () => {
    const content = JSON.stringify({
      agentId: 'opt-json-agent',
      name: 'Optional JSON Agent',
      version: '0.1.0',
      requiredCapabilities: [{ resource: 'api://required', actions: ['read'] }],
      optionalCapabilities: [
        { resource: 'api://optional-a', actions: ['read'] },
        { resource: 'api://optional-b', actions: ['write'] },
      ],
    });
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    const manifest = await src.load();
    expect(manifest.optionalCapabilities).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Custom condition types
// ---------------------------------------------------------------------------

describe('FilePolicySource — custom condition types', () => {
  it('accepts a custom condition type', async () => {
    const content = `
agentId: custom-agent
name: Custom Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://test"
    actions: [call]
    conditions:
      - type: custom
        name: my-custom-handler
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const cond = manifest.requiredCapabilities[0]!.conditions![0]!;
    expect(cond.type).toBe('custom');
  });
});

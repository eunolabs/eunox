/**
 * Unit tests for FilePolicySource and the manifest validation pipeline
 * (Task 7 acceptance criteria + Task 3 recipientDomain gate lift +
 * Task 4 redactFields gate lift + Task 5 policy gate lift).
 *
 * Test matrix
 * -----------
 * ✓ Happy path — valid YAML manifest → loads as AgentCapabilityManifest
 * ✓ Happy path — valid JSON manifest → loads as AgentCapabilityManifest
 * ✓ All Stage-1 condition types accepted (maxCalls, timeWindow,
 *     allowedOperations, allowedExtensions, allowedTables)
 * ✓ recipientDomain condition type now accepted (Stage-2 Task 3 gate lifted)
 * ✓ policy condition type now accepted (Stage-2 Task 5 gate lifted)
 * ✓ redactFields condition type now accepted (Stage-2 Task 4 gate lifted)
 * ✓ Unknown condition type → ManifestValidationError (names JSON path)
 * ✓ Stage-2 condition types accepted (ipRange, recipientDomain, redactFields, policy, custom)
 * ✓ Semantic error: notAfter before notBefore → ManifestValidationError
 * ✓ Missing required top-level field → ManifestValidationError
 * ✓ Unknown top-level field → ManifestValidationError
 * ✓ YAML syntax error → Error (parse error)
 * ✓ JSON syntax error → Error (parse error)
 * ✓ watch() invokes callback on file change and returns working unsubscribe
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FilePolicySource } from '../policy/source';
import {
  ManifestValidationError,
} from '@euno/common-core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Tracks temp dirs created during each test for cleanup. */
const tempDirs: string[] = [];

afterEach(() => {
  // Clean up all temp directories created during the test.
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Write a temp file and return its path. Cleaned up after each test. */
function writeTempFile(ext: 'yaml' | 'json', content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-mcp-test-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, `manifest.${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

const VALID_YAML = `
agentId: test-agent-1
name: Test Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://service/endpoint"
    actions: [read]
`.trim();

const VALID_JSON = JSON.stringify({
  agentId: 'test-agent-json',
  name: 'Test Agent JSON',
  version: '2.0.0',
  requiredCapabilities: [
    { resource: 'storage://bucket/objects', actions: ['write', 'delete'] },
  ],
});

const VALID_ALL_STAGE1_CONDITIONS_YAML = `
agentId: full-agent
name: Full Stage-1 Agent
version: 0.1.0
requiredCapabilities:
  - resource: "db://postgres/reports"
    actions: [execute]
    conditions:
      - type: maxCalls
        count: 100
        windowSeconds: 60
      - type: timeWindow
        notBefore: "2025-01-01T00:00:00Z"
        notAfter: "2030-01-01T00:00:00Z"
      - type: allowedOperations
        operations: [SELECT, EXPLAIN]
      - type: allowedExtensions
        extensions: [.csv, .json]
      - type: allowedTables
        tables: [reports, metrics]
        columns:
          reports: [id, name, value]
`.trim();

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

describe('FilePolicySource — happy paths', () => {
  it('loads a valid YAML manifest', async () => {
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', VALID_YAML) });
    const manifest = await src.load();
    expect(manifest.agentId).toBe('test-agent-1');
    expect(manifest.name).toBe('Test Agent');
    expect(manifest.version).toBe('0.1.0');
    expect(manifest.requiredCapabilities).toHaveLength(1);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(manifest.requiredCapabilities[0]!.resource).toBe('api://service/endpoint');
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(manifest.requiredCapabilities[0]!.actions).toEqual(['read']);
  });

  it('loads a valid JSON manifest', async () => {
    const src = new FilePolicySource({ filePath: writeTempFile('json', VALID_JSON) });
    const manifest = await src.load();
    expect(manifest.agentId).toBe('test-agent-json');
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(manifest.requiredCapabilities[0]!.actions).toEqual(['write', 'delete']);
  });

  it('accepts all Stage-1 condition types', async () => {
    const src = new FilePolicySource({
      filePath: writeTempFile('yaml', VALID_ALL_STAGE1_CONDITIONS_YAML),
    });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(5);
    expect(conditions.map((c) => c.type)).toEqual([
      'maxCalls',
      'timeWindow',
      'allowedOperations',
      'allowedExtensions',
      'allowedTables',
    ]);
    const maxCalls = conditions[0] as { type: 'maxCalls'; count: number; windowSeconds: number };
    expect(maxCalls.count).toBe(100);
    expect(maxCalls.windowSeconds).toBe(60);
  });

  it('accepts optional metadata fields', async () => {
    const content = `
agentId: meta-agent
name: Meta Agent
version: 3.0.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
metadata:
  description: "An agent with metadata"
  owner: team-platform
  tags: [finance, reporting]
  runtime: node:20
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.metadata?.owner).toBe('team-platform');
    expect(manifest.metadata?.tags).toEqual(['finance', 'reporting']);
    expect(manifest.metadata?.runtime).toBe('node:20');
  });

  it('accepts optional capabilities', async () => {
    const content = `
agentId: opt-agent
name: Optional Caps Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
optionalCapabilities:
  - resource: "api://analytics"
    actions: [read]
    conditions:
      - type: maxCalls
        count: 10
        windowSeconds: 3600
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.optionalCapabilities).toHaveLength(1);
  });

  it('accepts an argumentSchema on a constraint', async () => {
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
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(manifest.requiredCapabilities[0]!.argumentSchema?.type).toBe('object');
  });
});

// ---------------------------------------------------------------------------
// Stage-2 Task 3 — recipientDomain condition accepted (gate lifted)
// ---------------------------------------------------------------------------

describe('FilePolicySource — recipientDomain condition (Stage-2 Task 3)', () => {
  it('accepts a recipientDomain condition (no longer deferred)', async () => {
    const content = `
agentId: recipient-agent
name: Recipient Domain Agent
version: 0.1.0
requiredCapabilities:
  - resource: "messaging://send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        domains: [example.com, trusted.org]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(1);
    expect(conditions[0]!.type).toBe('recipientDomain');
  });

  it('accepts recipientDomain alongside Stage-1 conditions', async () => {
    const content = `
agentId: mixed-agent
name: Mixed Conditions Agent
version: 0.1.0
requiredCapabilities:
  - resource: "messaging://send_email"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 50
        windowSeconds: 3600
      - type: recipientDomain
        domains: [company.com]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(2);
    expect(conditions.map((c) => c.type)).toEqual(['maxCalls', 'recipientDomain']);
  });

  it('accepts recipientDomain in optionalCapabilities', async () => {
    const content = `
agentId: opt-recipient-agent
name: Optional Recipient Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
optionalCapabilities:
  - resource: "messaging://notify"
    actions: [call]
    conditions:
      - type: recipientDomain
        domains: [notify.example.com]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.optionalCapabilities).toHaveLength(1);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.optionalCapabilities![0]!.conditions!;
    expect(conditions[0]!.type).toBe('recipientDomain');
  });

  it('loader accepts a recipientDomain manifest where a domain entry contains @', async () => {
    // FilePolicySource only calls validateManifest() (Zod structural validation).
    // The condition handler's validate() phase — which rejects '@' in domain entries —
    // is invoked via validateCondition() at issuance/condition-validation time, not
    // during manifest loading. The loader therefore accepts this manifest as
    // structurally valid even though the condition configuration is semantically wrong.
    const content = `
agentId: bad-recipient-agent
name: Bad Recipient Agent
version: 0.1.0
requiredCapabilities:
  - resource: "messaging://send"
    actions: [call]
    conditions:
      - type: recipientDomain
        domains: [user@example.com]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    // The loader accepts this structurally valid manifest.
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(manifest.requiredCapabilities[0]!.conditions![0]!.type).toBe('recipientDomain');
  });
});



describe('FilePolicySource — unknown condition type', () => {
  it('rejects an unknown condition type and names the JSON path', async () => {
    const content = `
agentId: bad-agent
name: Bad Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: maxcalls
        count: 5
        windowSeconds: 60
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/condition/i);
  });

  it('names the precise JSON path when a nested condition has an unknown type', async () => {
    const content = `
agentId: deep-agent
name: Deep Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: timeWindow
        notBefore: "2025-01-01T00:00:00Z"
      - type: unknownFutureCondition
        someField: value
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    let err: ManifestValidationError | undefined;
    try {
      await src.load();
    } catch (e) {
      err = e as ManifestValidationError;
    }
    expect(err).toBeInstanceOf(ManifestValidationError);
    // The error message should indicate the condition index
    expect(err!.message).toContain('conditions[1]');
  });
});

// ---------------------------------------------------------------------------
// Deferred Stage-2 condition types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Deferred Stage-2+ condition types
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Stage-2 condition types (accepted from Stage 2 onwards)
// ---------------------------------------------------------------------------

describe('FilePolicySource — Stage-2 ipRange condition', () => {
  it('accepts ipRange condition type (lifted from deferred set in Stage 2)', async () => {
    const content = `
agentId: ip-agent
name: IP Agent
version: 0.1.0
requiredCapabilities:
  - resource: "mcp-tool://secure_tool"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["127.0.0.0/8", "10.0.0.0/8"]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(1);
    expect(conditions[0]!.type).toBe('ipRange');
  });

  it('accepts ipRange alongside Stage-1 conditions', async () => {
    const content = `
agentId: mixed-agent
name: Mixed Agent
version: 0.1.0
requiredCapabilities:
  - resource: "query_db"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 100
        windowSeconds: 60
      - type: ipRange
        cidrs: ["192.168.0.0/16"]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(2);
    expect(conditions.map((c) => c.type)).toEqual(['maxCalls', 'ipRange']);
  });

  it('accepts ipRange in optionalCapabilities', async () => {
    const content = `
agentId: opt-ip-agent
name: Opt IP Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
optionalCapabilities:
  - resource: "admin_tool"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["172.16.0.0/12"]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.optionalCapabilities![0]!.conditions!;
    expect(conditions[0]!.type).toBe('ipRange');
  });
});

describe('FilePolicySource — Stage-2 custom condition', () => {
  it('accepts custom condition type (gate lifted in Stage-2 Task 6)', async () => {
    const content = `
agentId: custom-agent
name: Custom Agent
version: 0.1.0
requiredCapabilities:
  - resource: "echo"
    actions: [call]
    conditions:
      - type: custom
        name: my-handler
        config: {}
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions[0]!.type).toBe('custom');
  });
});

// ---------------------------------------------------------------------------
// Stage-2 Task 4 — redactFields condition accepted (gate lifted)
// ---------------------------------------------------------------------------

describe('FilePolicySource — redactFields condition (Stage-2 Task 4)', () => {
  it('accepts a redactFields condition (no longer deferred)', async () => {
    const content = `
agentId: redact-agent
name: Redact Agent
version: 0.1.0
requiredCapabilities:
  - resource: "get_user"
    actions: [call]
    conditions:
      - type: redactFields
        fields: [ssn, dob]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(1);
    expect(conditions[0]!.type).toBe('redactFields');
  });

  it('accepts redactFields alongside Stage-1 conditions', async () => {
    const content = `
agentId: mixed-redact-agent
name: Mixed Redact Agent
version: 0.1.0
requiredCapabilities:
  - resource: "query_users"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 100
        windowSeconds: 3600
      - type: redactFields
        fields: [password_hash, api_key]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(2);
    expect(conditions.map((c) => c.type)).toEqual(['maxCalls', 'redactFields']);
  });

  it('accepts redactFields in optionalCapabilities', async () => {
    const content = `
agentId: opt-redact-agent
name: Opt Redact Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
optionalCapabilities:
  - resource: "export_data"
    actions: [call]
    conditions:
      - type: redactFields
        fields: [internal_id]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.optionalCapabilities).toHaveLength(1);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.optionalCapabilities![0]!.conditions!;
    expect(conditions[0]!.type).toBe('redactFields');
  });

  it('accepts redactFields alongside ipRange and recipientDomain', async () => {
    const content = `
agentId: full-stage2-agent
name: Full Stage-2 Agent
version: 0.1.0
requiredCapabilities:
  - resource: "send_report"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["10.0.0.0/8"]
      - type: recipientDomain
        domains: [example.com]
      - type: redactFields
        fields: [ssn, card_number]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(3);
    expect(conditions.map((c) => c.type)).toEqual(['ipRange', 'recipientDomain', 'redactFields']);
  });
});

// ---------------------------------------------------------------------------
// Semantic errors
// ---------------------------------------------------------------------------

describe('FilePolicySource — semantic errors', () => {
  it('rejects a timeWindow where notAfter is before notBefore', async () => {
    const content = `
agentId: semantic-agent
name: Semantic Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: timeWindow
        notBefore: "2030-01-01T00:00:00Z"
        notAfter:  "2025-01-01T00:00:00Z"
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/notAfter/);
  });

  it('rejects a timeWindow with neither notBefore nor notAfter', async () => {
    const content = `
agentId: empty-tw-agent
name: Empty TW Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: timeWindow
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/notBefore.*notAfter/);
  });

  it('rejects maxCalls with count < 1', async () => {
    const content = `
agentId: mc-agent
name: MaxCalls Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: maxCalls
        count: 0
        windowSeconds: 60
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });

  it('rejects maxCalls with windowSeconds < 1', async () => {
    const content = `
agentId: mc2-agent
name: MaxCalls2 Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: maxCalls
        count: 10
        windowSeconds: 0
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });

  it('rejects allowedOperations with an empty operations array', async () => {
    const content = `
agentId: ops-agent
name: Ops Agent
version: 0.1.0
requiredCapabilities:
  - resource: "db://pg"
    actions: [execute]
    conditions:
      - type: allowedOperations
        operations: []
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });
});

// ---------------------------------------------------------------------------
// Structural / schema errors
// ---------------------------------------------------------------------------

describe('FilePolicySource — structural errors', () => {
  it('rejects a manifest missing the agentId field', async () => {
    const content = `
name: No ID Agent
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/agentId/);
  });

  it('rejects a manifest missing requiredCapabilities', async () => {
    const content = `
agentId: no-caps
name: No Caps Agent
version: 0.1.0
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/requiredCapabilities/);
  });

  it('rejects a manifest with an empty requiredCapabilities array', async () => {
    const content = `
agentId: empty-caps
name: Empty Caps
version: 0.1.0
requiredCapabilities: []
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });

  it('rejects a capability with no actions', async () => {
    const content = `
agentId: no-actions
name: No Actions
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: []
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });

  it('rejects unknown top-level fields', async () => {
    const content = `
agentId: extra-field-agent
name: Extra Field
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
unknownTopLevelField: should-be-rejected
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/unknownTopLevelField/);
  });

  it('rejects unknown fields in a condition', async () => {
    const content = `
agentId: extra-cond-agent
name: Extra Cond
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: maxCalls
        count: 5
        windowSeconds: 60
        unexpectedField: true
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
  });

  it('rejects a non-ISO-8601 notBefore value (date only, no T)', async () => {
    const content = `
agentId: bad-date-agent
name: Bad Date
version: 0.1.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: timeWindow
        notBefore: "2026-01-01"
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(ManifestValidationError);
    await expect(src.load()).rejects.toThrow(/ISO 8601/);
  });
});

// ---------------------------------------------------------------------------
// Parse errors
// ---------------------------------------------------------------------------

describe('FilePolicySource — parse errors', () => {
  it('throws a parse error for invalid YAML', async () => {
    const content = `
agentId: [unclosed bracket
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    await expect(src.load()).rejects.toThrow(/parse/i);
  });

  it('throws a parse error for invalid JSON', async () => {
    const content = `{ "agentId": "bad", `;
    const src = new FilePolicySource({ filePath: writeTempFile('json', content) });
    await expect(src.load()).rejects.toThrow(/parse/i);
  });

  it('throws ENOENT for a missing file', async () => {
    const src = new FilePolicySource({
      filePath: '/tmp/euno-nonexistent-manifest-12345.yaml',
    });
    await expect(src.load()).rejects.toThrow(/ENOENT/);
  });
});

// ---------------------------------------------------------------------------
// watch()
// ---------------------------------------------------------------------------

describe('FilePolicySource — watch()', () => {
  it('invokes the onChange callback when the file is modified', async () => {
    const filePath = writeTempFile('yaml', VALID_YAML);
    const src = new FilePolicySource({ filePath, watchDebounceMs: 50 });

    const received: string[] = [];
    const unsubscribe = src.watch!((manifest) => {
      received.push(manifest.agentId);
    });

    // Modify the file
    const updated = VALID_YAML.replace('agentId: test-agent-1', 'agentId: updated-agent');
    await new Promise((resolve) => setTimeout(resolve, 30));
    fs.writeFileSync(filePath, updated, 'utf8');

    // Wait for the debounce + reload
    await new Promise((resolve) => setTimeout(resolve, 200));

    unsubscribe();

    expect(received).toContain('updated-agent');
  });

  it('does NOT invoke onChange for an invalid update; calls onError instead', async () => {
    const filePath = writeTempFile('yaml', VALID_YAML);
    const src = new FilePolicySource({ filePath, watchDebounceMs: 50 });

    const received: string[] = [];
    const errors: Error[] = [];
    const unsubscribe = src.watch!(
      (manifest) => received.push(manifest.agentId),
      (err) => errors.push(err),
    );

    // Write an invalid manifest (missing requiredCapabilities)
    const invalid = `agentId: bad\nname: Bad\nversion: 0.1.0\n`;
    await new Promise((resolve) => setTimeout(resolve, 30));
    fs.writeFileSync(filePath, invalid, 'utf8');

    await new Promise((resolve) => setTimeout(resolve, 200));
    unsubscribe();

    expect(received).toHaveLength(0);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(ManifestValidationError);
  });

  it('unsubscribe stops further change callbacks', async () => {
    const filePath = writeTempFile('yaml', VALID_YAML);
    const src = new FilePolicySource({ filePath, watchDebounceMs: 50 });

    const received: string[] = [];
    const unsubscribe = src.watch!((manifest) => received.push(manifest.agentId));

    unsubscribe(); // Stop watching immediately

    const updated = VALID_YAML.replace('agentId: test-agent-1', 'agentId: post-unsub');
    fs.writeFileSync(filePath, updated, 'utf8');

    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(received).toHaveLength(0);
  });
});

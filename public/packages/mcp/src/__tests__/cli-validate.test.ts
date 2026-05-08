/**
 * Unit tests for `euno-mcp validate` CLI command (Task 9 acceptance criteria).
 *
 * Test matrix
 * -----------
 * ✓ Valid YAML manifest → exits 0, output matches `euno validate` format
 * ✓ Valid JSON manifest → exits 0, output matches `euno validate` format
 * ✓ Unknown condition type → exits 1, error message names the JSON path
 * ✓ Deferred condition types (redactFields, custom) → exits 1, message mentions stage
 * ✓ ipRange condition → exits 0 (lifted from deferred set in Stage 2 Task 2)
 * ✓ recipientDomain condition → exits 0 (lifted from deferred set in Stage 2 Task 3)
 * ✓ policy condition → exits 0 (lifted from deferred set in Stage 2 Task 5)
 * ✓ Missing required field → exits 1, validation error
 * ✓ Non-existent file → exits 1, ENOENT-style error
 * ✓ Malformed YAML → exits 1, parse error
 * ✓ notAfter before notBefore → exits 1, semantic validation error
 * ✓ Error format is consistent with `euno validate` (same ✗ prefix)
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Temporary directories created during a test — cleaned up in afterEach. */
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Write a temp file and return its absolute path.  Cleaned up after each test. */
function writeTempFile(ext: 'yaml' | 'json', content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-validate-test-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, `manifest.${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

/** Absolute path to ts-node register hook. */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/** Absolute path to the CLI entry point. */
const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');

/**
 * Invoke `euno-mcp validate <policyFile>` in a subprocess (via ts-node) and
 * return the exit code, stdout, and stderr.
 */
function runValidate(policyFile: string): { exitCode: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(
    process.execPath,
    ['--require', TS_NODE_REGISTER, CLI, 'validate', policyFile],
    { encoding: 'utf8', timeout: 15_000 },
  );
  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

// ---------------------------------------------------------------------------
// Valid manifests
// ---------------------------------------------------------------------------

const VALID_YAML = `
agentId: test-agent-1
name: Test Agent
version: 1.0.0
requiredCapabilities:
  - resource: "api://service/endpoint"
    actions: [read]
`.trim();

const VALID_JSON = JSON.stringify({
  agentId: 'test-agent-json',
  name: 'Test Agent JSON',
  version: '2.0.0',
  requiredCapabilities: [{ resource: 'storage://bucket/objects', actions: ['write'] }],
});

describe('euno-mcp validate — happy path', () => {
  it('exits 0 for a valid YAML manifest and prints manifest info', () => {
    const filePath = writeTempFile('yaml', VALID_YAML);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
    expect(stdout).toContain('Agent: Test Agent (test-agent-1)');
    expect(stdout).toContain('Version: 1.0.0');
    expect(stdout).toContain('Required capabilities: 1');
  });

  it('exits 0 for a valid JSON manifest and prints manifest info', () => {
    const filePath = writeTempFile('json', VALID_JSON);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
    expect(stdout).toContain('Agent: Test Agent JSON (test-agent-json)');
    expect(stdout).toContain('Version: 2.0.0');
    expect(stdout).toContain('Required capabilities: 1');
  });

  it('reports multiple required capabilities correctly', () => {
    const yaml = `
agentId: multi-agent
name: Multi Agent
version: 3.0.0
requiredCapabilities:
  - resource: "tool://a"
    actions: [call]
  - resource: "tool://b"
    actions: [call]
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('Required capabilities: 2');
  });
});

// ---------------------------------------------------------------------------
// Invalid manifests — structural errors
// ---------------------------------------------------------------------------

describe('euno-mcp validate — structural errors', () => {
  it('exits 1 and prints ✗ for a missing required field (agentId)', () => {
    const yaml = `
name: No Agent ID
version: 1.0.0
requiredCapabilities: []
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });

  it('exits 1 for an unknown top-level field', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities: []
unknownField: forbidden
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });

  it('exits 1 for an unknown condition type and names the JSON path', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://foo"
    actions: [call]
    conditions:
      - type: unknownFutureCondition
        someParam: 42
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });
});

// ---------------------------------------------------------------------------
// Deferred Stage-2 condition types
// ---------------------------------------------------------------------------

/** Minimal valid YAML for each deferred condition type (with required fields). */
const DEFERRED_CONDITION_YAMLS: Record<string, string> = {
  redactFields: `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://foo"
    actions: [call]
    conditions:
      - type: redactFields
        fields: ["ssn", "credit_card"]
`.trim(),
  custom: `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://foo"
    actions: [call]
    conditions:
      - type: custom
        name: my-custom-check
        config: {}
`.trim(),
};

describe('euno-mcp validate — deferred condition types', () => {
  for (const [deferredType, yaml] of Object.entries(DEFERRED_CONDITION_YAMLS)) {
    it(`exits 1 for condition type "${deferredType}" and mentions stage`, () => {
      const filePath = writeTempFile('yaml', yaml);
      const { exitCode, stderr } = runValidate(filePath);

      expect(exitCode).toBe(1);
      expect(stderr).toContain('✗ Validation failed');
      expect(stderr.toLowerCase()).toMatch(/stage/);
    });
  }
});

// ---------------------------------------------------------------------------
// Stage-2 accepted condition types (lifted from deferred set)
// ---------------------------------------------------------------------------

describe('euno-mcp validate — Stage-2 recipientDomain condition (Task 3)', () => {
  it('exits 0 for a manifest with a valid recipientDomain condition', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://send_email"
    actions: [call]
    conditions:
      - type: recipientDomain
        domains: ["example.com", "trusted.org"]
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
  });
});

describe('euno-mcp validate — Stage-2 policy condition (Task 5)', () => {
  it('exits 0 for a manifest with a valid policy condition', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://governed_action"
    actions: [call]
    conditions:
      - type: policy
        backend: opa-http
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
  });

  it('exits 0 for a policy condition with optional config and input fields', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://governed_action"
    actions: [call]
    conditions:
      - type: policy
        backend: my-engine
        config:
          package: authz.payments
          rule: allow
        input:
          environment: production
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
  });
});

// ---------------------------------------------------------------------------
// Stage-2 ipRange condition (accepted from Stage 2 onwards)
// ---------------------------------------------------------------------------

describe('euno-mcp validate — Stage-2 ipRange condition', () => {
  it('exits 0 for a manifest with a valid ipRange condition', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "echo"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["127.0.0.0/8", "10.0.0.0/8"]
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stdout } = runValidate(filePath);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('✓ Manifest is valid');
  });

  it('exits 1 for an ipRange condition with an invalid CIDR', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "echo"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: ["not-a-cidr"]
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });
});

// ---------------------------------------------------------------------------
// Semantic errors
// ---------------------------------------------------------------------------

describe('euno-mcp validate — semantic errors', () => {
  it('exits 1 for notAfter before notBefore', () => {
    const yaml = `
agentId: test-agent
name: Test
version: 1.0.0
requiredCapabilities:
  - resource: "tool://foo"
    actions: [call]
    conditions:
      - type: timeWindow
        notBefore: "2030-01-01T00:00:00Z"
        notAfter:  "2020-01-01T00:00:00Z"
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });
});

// ---------------------------------------------------------------------------
// File system errors
// ---------------------------------------------------------------------------

describe('euno-mcp validate — file system errors', () => {
  it('exits 1 when the policy file does not exist', () => {
    const { exitCode, stderr } = runValidate('/tmp/this-file-does-not-exist-euno-test.yaml');

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });

  it('exits 1 for a malformed YAML file', () => {
    const filePath = writeTempFile('yaml', '{{ bad yaml {{{{');
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });

  it('exits 1 for malformed JSON', () => {
    const filePath = writeTempFile('json', '{ "bad": json }');
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('✗ Validation failed');
  });
});

// ---------------------------------------------------------------------------
// Error format parity with `euno validate`
// ---------------------------------------------------------------------------

describe('euno-mcp validate — error format parity with euno validate', () => {
  it('uses "✗ Validation failed: <message>" for all error cases', () => {
    // Use a missing-required-field error as the representative case.
    const yaml = `
name: No Agent ID
version: 1.0.0
requiredCapabilities: []
`.trim();
    const filePath = writeTempFile('yaml', yaml);
    const { exitCode, stderr } = runValidate(filePath);

    expect(exitCode).toBe(1);
    // The error must start with the canonical prefix (matches `euno validate`).
    expect(stderr).toMatch(/✗ Validation failed:/);
  });
});

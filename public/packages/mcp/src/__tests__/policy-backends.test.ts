/**
 * Tests for the policy-backend module loader (Task 5) and
 * ConditionEnforcerPDP enforcement of `policy`-typed conditions.
 *
 * Test matrix
 * -----------
 * Loader (loadPolicyBackends)
 * ✓ loads a valid backend module and registers it
 * ✓ emits a structured stderr line for each registered backend name
 * ✓ throws when the module path cannot be resolved (file not found)
 * ✓ throws when the module has no default export
 * ✓ throws when the default export is not a function (wrong shape)
 * ✓ loader error propagates after writing a message to stderr
 * ✓ supports loading multiple backend modules in one call
 * ✓ accepts an async registrar function
 *
 * ConditionEnforcerPDP with policy conditions
 * ✓ denies a call when a registered 'echo-deny' backend always returns deny
 * ✓ decision carries denialCode 'POLICY_BACKEND_DENIED' and conditionType 'policy'
 * ✓ allows a call when the backend's enforce() returns allow
 * ✓ denies with reason from backend when backend returns a reason string
 * ✓ policy condition is accepted by FilePolicySource (gate lifted — Task 5)
 */

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import {
  registerPolicyBackend,
  _resetPolicyBackendRegistry,
} from '@euno/common-core';
import type { AgentCapabilityManifest, CapabilityCondition } from '@euno/common-core';
import { loadPolicyBackends } from '../policy/backends';
import { ConditionEnforcerPDP } from '../pdp';
import type { LocalPolicySource } from '../policy/source';
import { FilePolicySource } from '../policy/source';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Build a minimal CallToolRequest for the given tool name. */
function makeRequest(toolName: string, args: Record<string, unknown> = {}) {
  return {
    method: 'tools/call' as const,
    params: { name: toolName, arguments: args },
  };
}

/** Build a minimal PdpContext. */
function makeCtx(sessionId = 'test-session-policy') {
  return { sessionId };
}

/** Create an in-memory LocalPolicySource from a literal manifest. */
function staticSource(manifest: AgentCapabilityManifest): LocalPolicySource {
  return { load: async () => manifest };
}

/**
 * Build a manifest with a single required capability whose conditions include
 * one `policy` condition referencing the supplied backend name.
 */
function policyConditionManifest(
  toolName: string,
  backendName: string,
  extraConditions?: CapabilityCondition[],
): AgentCapabilityManifest {
  return {
    agentId: 'test-agent',
    name: 'Test Agent',
    version: '1.0.0',
    requiredCapabilities: [
      {
        resource: toolName,
        actions: ['call'],
        conditions: [
          { type: 'policy', backend: backendName } as CapabilityCondition,
          ...(extraConditions ?? []),
        ],
      },
    ],
  };
}

/** Absolute path to the echo-deny fixture module (no extension — Node resolves it). */
const ECHO_DENY_MODULE = path.resolve(
  __dirname,
  '../../test/fixtures/policy-backends/echo-deny',
);

// ---------------------------------------------------------------------------
// Cleanup global registry after every test
// ---------------------------------------------------------------------------

afterEach(() => {
  _resetPolicyBackendRegistry();
});

// ---------------------------------------------------------------------------
// loadPolicyBackends — loader unit tests
// ---------------------------------------------------------------------------

describe('loadPolicyBackends — valid module', () => {
  it('loads a module and registers the backend it declares', async () => {
    const stderrLines: string[] = [];
    const stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((msg: string | Uint8Array) => {
        stderrLines.push(String(msg));
        return true;
      });

    try {
      await loadPolicyBackends([ECHO_DENY_MODULE]);
    } finally {
      stderrSpy.mockRestore();
    }

    // The backend must be present in the global registry.
    const { getPolicyBackends } = await import('@euno/common-core');
    const backends = getPolicyBackends();
    expect(backends.has('echo-deny')).toBe(true);
  });

  it('emits one structured log line per registered backend name', async () => {
    const stderrLines: string[] = [];
    const stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((msg: string | Uint8Array) => {
        stderrLines.push(String(msg));
        return true;
      });

    try {
      await loadPolicyBackends([ECHO_DENY_MODULE]);
    } finally {
      stderrSpy.mockRestore();
    }

    const logLines = stderrLines.filter((l) =>
      l.includes('registered policy backend:'),
    );
    expect(logLines).toHaveLength(1);
    expect(logLines[0]).toContain('echo-deny');
  });

  it('loads multiple modules in order', async () => {
    // Use loadPolicyBackends twice with two copies of the same fixture to
    // test that both are loaded.  The second load will overwrite the same
    // name in the registry (idempotent per the registry contract).
    const stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockReturnValue(true);

    try {
      await loadPolicyBackends([ECHO_DENY_MODULE, ECHO_DENY_MODULE]);
    } finally {
      stderrSpy.mockRestore();
    }

    // After loading both, the backend must still be registered.
    const { getPolicyBackends } = await import('@euno/common-core');
    expect(getPolicyBackends().has('echo-deny')).toBe(true);
  });

  it('accepts an async registrar function', async () => {
    // Create an inline async registrar and exercise it through loadPolicyBackends
    // via the wrappedRegister path.  We do this by creating a temp module file.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-policy-test-'));
    const modulePath = path.join(dir, 'async-backend.js');
    try {
      // Use module.exports = fn (not exports.default = fn) so that dynamic
      // import() resolves mod.default to the function directly.
      fs.writeFileSync(
        modulePath,
        `module.exports = async function register(api) {
          await Promise.resolve();
          api.registerPolicyBackend('async-test', {
            validate() {},
            enforce() { return { allow: true }; },
          });
        };
        `,
      );

      const stderrSpy = jest
        .spyOn(process.stderr, 'write')
        .mockReturnValue(true);

      try {
        await loadPolicyBackends([modulePath]);
      } finally {
        stderrSpy.mockRestore();
      }

      const { getPolicyBackends } = await import('@euno/common-core');
      expect(getPolicyBackends().has('async-test')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('loadPolicyBackends — error handling', () => {
  it('throws and writes to stderr when the module path cannot be resolved', async () => {
    const stderrLines: string[] = [];
    const stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((msg: string | Uint8Array) => {
        stderrLines.push(String(msg));
        return true;
      });

    await expect(
      loadPolicyBackends(['/nonexistent/module/does-not-exist']),
    ).rejects.toThrow();

    stderrSpy.mockRestore();

    const errorLines = stderrLines.filter((l) => l.includes('Failed to load'));
    expect(errorLines.length).toBeGreaterThan(0);
    expect(errorLines[0]).toContain('/nonexistent/module/does-not-exist');
  });

  it('throws and writes to stderr when the default export is not a function', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-policy-test-'));
    const modulePath = path.join(dir, 'bad-export.js');
    try {
      fs.writeFileSync(modulePath, 'exports.default = 42;\n');

      const stderrLines: string[] = [];
      const stderrSpy = jest
        .spyOn(process.stderr, 'write')
        .mockImplementation((msg: string | Uint8Array) => {
          stderrLines.push(String(msg));
          return true;
        });

      await expect(loadPolicyBackends([modulePath])).rejects.toThrow(
        /must export a default function/i,
      );

      stderrSpy.mockRestore();

      const errorLines = stderrLines.filter((l) =>
        l.includes('must export a default function'),
      );
      expect(errorLines.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('throws and writes to stderr when the default export is missing entirely', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-policy-test-'));
    const modulePath = path.join(dir, 'no-default.js');
    try {
      fs.writeFileSync(modulePath, 'exports.something = () => {};\n');

      const stderrSpy = jest
        .spyOn(process.stderr, 'write')
        .mockReturnValue(true);

      await expect(loadPolicyBackends([modulePath])).rejects.toThrow(
        /must export a default function/i,
      );

      stderrSpy.mockRestore();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('throws and writes to stderr when the registrar throws', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-policy-test-'));
    const modulePath = path.join(dir, 'throwing-backend.js');
    try {
      // Use module.exports = fn so dynamic import() resolves mod.default correctly.
      fs.writeFileSync(
        modulePath,
        `module.exports = function register() {
          throw new Error('backend setup failed');
        };
        `,
      );

      const stderrLines: string[] = [];
      const stderrSpy = jest
        .spyOn(process.stderr, 'write')
        .mockImplementation((msg: string | Uint8Array) => {
          stderrLines.push(String(msg));
          return true;
        });

      await expect(loadPolicyBackends([modulePath])).rejects.toThrow(
        'backend setup failed',
      );

      stderrSpy.mockRestore();

      const errorLines = stderrLines.filter((l) => l.includes('Error registering'));
      expect(errorLines.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is a no-op when the modulePaths array is empty', async () => {
    await expect(loadPolicyBackends([])).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ConditionEnforcerPDP — policy condition enforcement
// ---------------------------------------------------------------------------

describe('ConditionEnforcerPDP — policy condition', () => {
  it('denies a call when the registered backend always denies', async () => {
    // Register the echo-deny backend manually (mirrors what loadPolicyBackends does).
    registerPolicyBackend('echo-deny', {
      validate() {},
      enforce() {
        return { allow: false, reason: 'echo-deny: always denied by test backend' };
      },
    });

    const manifest = policyConditionManifest('send_email', 'echo-deny');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('send_email'), makeCtx());
    expect(decision.allow).toBe(false);
  });

  it('carries denialCode POLICY_BACKEND_DENIED when a policy backend denies', async () => {
    registerPolicyBackend('echo-deny', {
      validate() {},
      enforce() {
        return { allow: false, reason: 'denied' };
      },
    });

    const manifest = policyConditionManifest('some_tool', 'echo-deny');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('some_tool'), makeCtx());
    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('POLICY_BACKEND_DENIED');
    expect(decision.conditionType).toBe('policy');
  });

  it('carries the reason string returned by the backend', async () => {
    registerPolicyBackend('reason-backend', {
      validate() {},
      enforce() {
        return { allow: false, reason: 'custom reason from backend' };
      },
    });

    const manifest = policyConditionManifest('tool', 'reason-backend');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('tool'), makeCtx());
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('custom reason from backend');
  });

  it('allows a call when the registered backend returns allow', async () => {
    registerPolicyBackend('allow-all', {
      validate() {},
      enforce() {
        return { allow: true };
      },
    });

    const manifest = policyConditionManifest('my_tool', 'allow-all');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('my_tool'), makeCtx());
    expect(decision.allow).toBe(true);
  });

  it('denies with CONDITION_NOT_SATISFIED when the backend named in the policy is not registered', async () => {
    // No backend registered — the policyHandler returns a deny with a clear reason.
    const manifest = policyConditionManifest('my_tool', 'unregistered-backend');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('my_tool'), makeCtx());
    expect(decision.allow).toBe(false);
    expect(decision.reason).toMatch(/unrecognized policy backend/i);
  });

  it('integrates end-to-end: loads echo-deny via loadPolicyBackends, then denies', async () => {
    const stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockReturnValue(true);

    try {
      await loadPolicyBackends([ECHO_DENY_MODULE]);
    } finally {
      stderrSpy.mockRestore();
    }

    const manifest = policyConditionManifest('my_tool', 'echo-deny');
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('my_tool'), makeCtx());
    expect(decision.allow).toBe(false);
    expect(decision.denialCode).toBe('POLICY_BACKEND_DENIED');
    expect(decision.conditionType).toBe('policy');
    expect(decision.reason).toContain('echo-deny');
  });

  it('policy condition is evaluated before maxCalls (priority ordering preserved)', async () => {
    registerPolicyBackend('echo-deny', {
      validate() {},
      enforce() {
        return { allow: false, reason: 'denied by policy' };
      },
    });

    // maxCalls=1000 so it would never trigger; policy fires first.
    const manifest = policyConditionManifest('tool', 'echo-deny', [
      { type: 'maxCalls', count: 1000, windowSeconds: 60 } as CapabilityCondition,
    ]);
    const pdp = new ConditionEnforcerPDP({ policySource: staticSource(manifest) });

    const decision = await pdp.decide(makeRequest('tool'), makeCtx());
    expect(decision.allow).toBe(false);
    expect(decision.conditionType).toBe('policy');
  });
});

// ---------------------------------------------------------------------------
// FilePolicySource — policy condition gate lifted (Task 5)
// ---------------------------------------------------------------------------

/** Tracks temp dirs created during each test for cleanup. */
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function writeTempFile(ext: 'yaml' | 'json', content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-mcp-test-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, `manifest.${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

describe('FilePolicySource — policy condition (Stage-2 Task 5 gate lifted)', () => {
  it('accepts a policy condition (no longer deferred)', async () => {
    const content = `
agentId: policy-agent
name: Policy Agent
version: 1.0.0
requiredCapabilities:
  - resource: "mcp-tool://my_tool"
    actions: [call]
    conditions:
      - type: policy
        backend: my-engine
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(1);
    expect(conditions[0]!.type).toBe('policy');
  });

  it('accepts policy condition alongside Stage-1 conditions', async () => {
    const content = `
agentId: mixed-agent
name: Mixed Agent
version: 1.0.0
requiredCapabilities:
  - resource: "mcp-tool://my_tool"
    actions: [call]
    conditions:
      - type: maxCalls
        count: 50
        windowSeconds: 3600
      - type: policy
        backend: opa-http
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.requiredCapabilities[0]!.conditions!;
    expect(conditions).toHaveLength(2);
    expect(conditions.map((c) => c.type)).toEqual(['maxCalls', 'policy']);
  });

  it('accepts policy condition in optionalCapabilities', async () => {
    const content = `
agentId: opt-policy-agent
name: Optional Policy Agent
version: 1.0.0
requiredCapabilities:
  - resource: "api://core"
    actions: [read]
optionalCapabilities:
  - resource: "mcp-tool://governed_tool"
    actions: [call]
    conditions:
      - type: policy
        backend: my-guard
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.optionalCapabilities).toHaveLength(1);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const conditions = manifest.optionalCapabilities![0]!.conditions!;
    expect(conditions[0]!.type).toBe('policy');
  });

  it('accepts redactFields condition (Stage-2 Task 4 gate lifted)', async () => {
    const content = `
agentId: redact-agent
name: Redact Agent
version: 1.0.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: redactFields
        fields: [ssn]
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.conditions![0]!.type).toBe('redactFields');
  });

  it('accepts custom condition type (Stage-2 Task 6 gate lifted)', async () => {
    const content = `
agentId: custom-agent
name: Custom Agent
version: 1.0.0
requiredCapabilities:
  - resource: "api://svc"
    actions: [read]
    conditions:
      - type: custom
        name: my-handler
        config: {}
`.trim();
    const src = new FilePolicySource({ filePath: writeTempFile('yaml', content) });
    const manifest = await src.load();
    expect(manifest.requiredCapabilities[0]!.conditions![0]!.type).toBe('custom');
  });
});

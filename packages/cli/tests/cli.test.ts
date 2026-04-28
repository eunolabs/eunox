/**
 * CLI smoke / integration tests.
 *
 * The CLI is a thin wrapper around `commander`; rather than refactor it for
 * unit-testability we drive the actual binary through `ts-node` and assert on
 * its stdout/stderr.  This gives confidence that the user-visible UX (flags,
 * exit codes, error messages) actually works.
 */

import { execFileSync, ExecFileSyncOptions } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as yaml from 'js-yaml';

const CLI_ENTRY = path.resolve(__dirname, '..', 'src', 'index.ts');

/**
 * Resolve the `ts-node` CLI in a layout-independent way.  Using
 * `require.resolve` finds the package wherever the workspace happens to have
 * hoisted it (root `node_modules`, package-local `node_modules`, pnpm store,
 * etc.), and we then point `node` at the package's own `bin` script so this
 * works on Linux, macOS, and Windows without depending on shell shims like
 * `ts-node.cmd`.
 */
function resolveTsNodeCli(): string {
  // ts-node ships its CLI entry as `dist/bin.js`; locate it via its package.json
  // so we don't hard-code that path either.
  const pkgJsonPath = require.resolve('ts-node/package.json');
  const pkg = require(pkgJsonPath) as { bin?: string | Record<string, string> };
  const binEntry =
    typeof pkg.bin === 'string'
      ? pkg.bin
      : (pkg.bin?.['ts-node'] ?? 'dist/bin.js');
  return path.resolve(path.dirname(pkgJsonPath), binEntry);
}

const TS_NODE_CLI = resolveTsNodeCli();

interface CliResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], opts: ExecFileSyncOptions = {}): CliResult {
  try {
    // Spawn `node <ts-node-bin> <cli-entry> <args>` so we don't depend on the
    // platform-specific shell shim (`.bin/ts-node` vs `ts-node.cmd`).
    const stdout = execFileSync(process.execPath, [TS_NODE_CLI, CLI_ENTRY, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      ...opts,
    }) as unknown as string;
    return { status: 0, stdout: stdout.toString(), stderr: '' };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: e.status ?? 1,
      stdout: (e.stdout ?? Buffer.from('')).toString(),
      stderr: (e.stderr ?? Buffer.from('')).toString(),
    };
  }
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-cli-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('euno --help / --version', () => {
  it('prints the help text when --help is requested', () => {
    const r = runCli(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Capability management CLI');
    expect(r.stdout).toContain('init');
    expect(r.stdout).toContain('validate');
  });

  it('prints a version', () => {
    const r = runCli(['--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe('euno init', () => {
  it('creates a manifest with the supplied agent name', () => {
    const out = path.join(tmpDir, 'manifest.yaml');
    const r = runCli(['init', '--agent', 'My Agent', '--output', out]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Created capability manifest');
    expect(fs.existsSync(out)).toBe(true);

    const parsed = yaml.load(fs.readFileSync(out, 'utf8')) as Record<string, unknown>;
    expect(parsed.agentId).toBe('my-agent');
    expect(parsed.name).toBe('My Agent');
    expect(parsed.version).toBe('1.0.0');
    expect(Array.isArray(parsed.requiredCapabilities)).toBe(true);
    expect((parsed.requiredCapabilities as unknown[]).length).toBeGreaterThan(0);
  });

  it('uses default agent name when none supplied', () => {
    const out = path.join(tmpDir, 'agent-capability.yaml');
    const r = runCli(['init', '--output', out]);
    expect(r.status).toBe(0);
    expect(fs.existsSync(out)).toBe(true);
    const parsed = yaml.load(fs.readFileSync(out, 'utf8')) as Record<string, unknown>;
    expect(parsed.agentId).toBe('myagent');
  });

  describe('--framework', () => {
    it.each([
      [
        'langchain',
        'euno-langchain.ts',
        'wrapAsLangChainTools',
        // LangChain callback handler requires a sink function — assert
        // the scaffold actually constructs it with one so future template
        // drift away from the real adapter signature fails CI.
        ['new EunoLangChainCallbackHandler('],
      ],
      [
        'maf',
        'euno-maf.ts',
        'createEunoFunctionToolMiddleware',
        // MAF middleware signature is (runtime, bindings, options) —
        // pin the call shape so refactors that move bindings into an
        // options bag (which would silently break at runtime) fail here.
        ['createEunoFunctionToolMiddleware(\n    runtime,\n    [', "unknownToolPolicy: 'deny'"],
      ],
      [
        'crewai',
        'euno-crewai.ts',
        'wrapAsCrewAITools',
        // EunoCrewAITaskLifecycle requires a runtime in its constructor.
        ['new EunoCrewAITaskLifecycle(runtime'],
      ],
    ] as const)(
      'emits a %s scaffold alongside the manifest',
      (framework, expectedFilename, expectedSymbol, expectedCallSites) => {
        const out = path.join(tmpDir, 'manifest.yaml');
        const r = runCli([
          'init',
          '--agent',
          'Demo Agent',
          '--output',
          out,
          '--framework',
          framework,
        ]);
        expect(r.status).toBe(0);

        // The manifest must always be written.
        expect(fs.existsSync(out)).toBe(true);

        // The scaffold lands next to the manifest.
        const scaffoldPath = path.join(tmpDir, expectedFilename);
        expect(fs.existsSync(scaffoldPath)).toBe(true);

        const scaffoldContents = fs.readFileSync(scaffoldPath, 'utf8');
        // Each scaffold must reference its framework adapter symbol so we
        // catch silent template regressions.
        expect(scaffoldContents).toContain(expectedSymbol);
        // And must thread the agent id through the scaffold so the
        // generated file is actually agent-specific.
        expect(scaffoldContents).toContain('demo-agent');
        // Pin the actual call-site shape for each adapter so a change
        // to the adapter API that the scaffold no longer matches fails
        // CI rather than shipping a non-compilable starter file to
        // users.
        for (const callSite of expectedCallSites) {
          expect(scaffoldContents).toContain(callSite);
        }

        expect(r.stdout).toContain(`Created ${framework} scaffold`);
      },
    );

    it('rejects an unsupported framework with a non-zero exit code', () => {
      const out = path.join(tmpDir, 'manifest.yaml');
      const r = runCli([
        'init',
        '--output',
        out,
        '--framework',
        'autogen', // not in SUPPORTED_FRAMEWORKS
      ]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('Unsupported framework');
      // We must not have written a partial manifest on a validation failure.
      expect(fs.existsSync(out)).toBe(false);
    });

    it('does not emit a scaffold when --framework is omitted', () => {
      const out = path.join(tmpDir, 'manifest.yaml');
      const r = runCli(['init', '--output', out]);
      expect(r.status).toBe(0);
      expect(fs.existsSync(out)).toBe(true);
      // None of the framework scaffolds should have been written.
      for (const f of ['euno-langchain.ts', 'euno-maf.ts', 'euno-crewai.ts']) {
        expect(fs.existsSync(path.join(tmpDir, f))).toBe(false);
      }
    });
  });

  describe('--cloud', () => {
    // Pin the per-cloud signer/identity/edge wiring so a refactor that
    // silently drops e.g. the Azure Key Vault block, the AWS KMS block,
    // or the GCP Cloud KMS block fails CI rather than shipping a scaffold
    // that doesn't match the production env-var contract.  These match
    // the cloud-portability matrix in docs/SPRINT_5_PILOT_LAUNCH.md § 6.
    it.each([
      [
        'azure',
        'euno-deployment.azure.yaml',
        ['azure-ad', 'azure-key-vault', 'azure-api-management', 'microsoft-sentinel'],
      ],
      [
        'aws',
        'euno-deployment.aws.yaml',
        ['aws-cognito', 'aws-kms', 'aws-api-gateway', 'security-hub'],
      ],
      [
        'gcp',
        'euno-deployment.gcp.yaml',
        ['gcp-cloud-identity', 'gcp-cloud-kms', 'gcp-api-gateway', 'security-command-center'],
      ],
    ] as const)(
      'emits a %s deployment scaffold alongside the manifest',
      (cloud, expectedFilename, expectedTokens) => {
        const out = path.join(tmpDir, 'manifest.yaml');
        const r = runCli([
          'init',
          '--agent',
          'Demo Agent',
          '--output',
          out,
          '--cloud',
          cloud,
        ]);
        expect(r.status).toBe(0);
        expect(fs.existsSync(out)).toBe(true);

        const deployPath = path.join(tmpDir, expectedFilename);
        expect(fs.existsSync(deployPath)).toBe(true);

        const contents = fs.readFileSync(deployPath, 'utf8');
        // The cloud-specific signer / identity / edge tokens MUST be in
        // the scaffold so the engineer reading the file sees the right
        // primitives for their target cloud.
        for (const token of expectedTokens) {
          expect(contents).toContain(token);
        }
        // The agent id must be threaded through so the scaffold is
        // actually agent-specific (mirrors the framework-scaffold check).
        expect(contents).toContain('demo-agent');

        // Parse it as YAML to ensure it is well-formed (and not, say,
        // accidentally a string that *happens* to contain the right
        // tokens).  This catches indentation and quoting regressions.
        const parsed = yaml.load(contents) as Record<string, unknown>;
        expect(parsed.cloud).toBe(cloud);
        expect(parsed.identity).toBeDefined();
        expect(parsed.signer).toBeDefined();
        expect(parsed.gateway).toBeDefined();

        expect(r.stdout).toContain(`Created ${cloud} deployment scaffold`);
      },
    );

    it('rejects an unsupported cloud with a non-zero exit code', () => {
      const out = path.join(tmpDir, 'manifest.yaml');
      const r = runCli([
        'init',
        '--output',
        out,
        '--cloud',
        'oracle', // not in SUPPORTED_CLOUDS
      ]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('Unsupported cloud');
      // We must not have written a partial manifest on a validation failure.
      expect(fs.existsSync(out)).toBe(false);
    });

    it('does not emit a deployment scaffold when --cloud is omitted', () => {
      const out = path.join(tmpDir, 'manifest.yaml');
      const r = runCli(['init', '--output', out]);
      expect(r.status).toBe(0);
      for (const f of [
        'euno-deployment.azure.yaml',
        'euno-deployment.aws.yaml',
        'euno-deployment.gcp.yaml',
      ]) {
        expect(fs.existsSync(path.join(tmpDir, f))).toBe(false);
      }
    });

    it('emits both a framework and a cloud scaffold when both flags are set', () => {
      // Per the execution plan, the manifest stays cloud-neutral and
      // framework-neutral; the two scaffolds are independent and can be
      // combined.  Verify they both land alongside one manifest.
      const out = path.join(tmpDir, 'manifest.yaml');
      const r = runCli([
        'init',
        '--agent',
        'Combo Agent',
        '--output',
        out,
        '--framework',
        'langchain',
        '--cloud',
        'aws',
      ]);
      expect(r.status).toBe(0);
      expect(fs.existsSync(out)).toBe(true);
      expect(fs.existsSync(path.join(tmpDir, 'euno-langchain.ts'))).toBe(true);
      expect(fs.existsSync(path.join(tmpDir, 'euno-deployment.aws.yaml'))).toBe(true);
    });
  });
});

describe('euno validate', () => {
  function writeManifest(content: unknown): string {
    const file = path.join(tmpDir, 'manifest.yaml');
    fs.writeFileSync(file, yaml.dump(content));
    return file;
  }

  it('accepts a well-formed manifest', () => {
    const file = writeManifest({
      agentId: 'agent-1',
      name: 'Agent One',
      version: '1.0.0',
      requiredCapabilities: [{ resource: 'api://svc/data', actions: ['read'] }],
    });
    const r = runCli(['validate', file]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Manifest is valid');
    expect(r.stdout).toContain('Agent One');
    expect(r.stdout).toContain('agent-1');
  });

  it('rejects a manifest missing required fields', () => {
    const file = writeManifest({ name: 'No Id' });
    const r = runCli(['validate', file]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('missing required fields');
    expect(r.stderr).toContain('agentId');
  });

  it('rejects a non-existent manifest file with a clear error', () => {
    const r = runCli(['validate', path.join(tmpDir, 'does-not-exist.yaml')]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Validation failed');
  });
});

describe('euno request', () => {
  it('requires an Azure AD token', () => {
    const r = runCli(['request', '--agent', 'a1'], {
      env: { ...process.env, AZURE_AD_TOKEN: '' },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Azure AD bearer token is required');
  });

  it('requires --agent', () => {
    const r = runCli(['request', '--token', 'fake-token'], {
      env: { ...process.env, AZURE_AD_TOKEN: '' },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Agent ID is required');
  });

  it('rejects --resources without --actions', () => {
    const r = runCli(
      ['request', '--agent', 'a1', '--token', 'fake-token', '--resources', 'api://x'],
      { env: { ...process.env, AZURE_AD_TOKEN: '' } }
    );
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--resources and --actions must be provided together');
  });
});

describe('euno config', () => {
  it('shows the configured environment variables', () => {
    const r = runCli(['config'], {
      env: {
        ...process.env,
        EUNO_ISSUER_URL: 'https://issuer.example',
        EUNO_GATEWAY_URL: 'https://gateway.example',
      },
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Euno CLI Configuration');
    expect(r.stdout).toContain('https://issuer.example');
    expect(r.stdout).toContain('https://gateway.example');
  });
});

describe('euno schema-version', () => {
  it('shows help for schema-version command', () => {
    const r = runCli(['schema-version', '--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('schema-version');
  });

  describe('plan subcommand', () => {
    it('generates a minor version migration plan', () => {
      const r = runCli(['schema-version', 'plan', '1.0', '1.1']);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('1.0 → 1.1');
      expect(r.stdout).toContain('minor');
      expect(r.stdout).toContain('SUPPORTED_SCHEMA_VERSIONS');
    });

    it('generates a major version migration plan', () => {
      const r = runCli(['schema-version', 'plan', '1.0', '2.0']);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('1.0 → 2.0');
      expect(r.stdout).toContain('major');
    });

    it('outputs JSON when --json is supplied', () => {
      const r = runCli(['schema-version', 'plan', '1.0', '1.1', '--json']);
      expect(r.status).toBe(0);
      const parsed = JSON.parse(r.stdout);
      expect(parsed.from).toBe('1.0');
      expect(parsed.to).toBe('1.1');
      expect(parsed.type).toBe('minor');
      expect(Array.isArray(parsed.steps)).toBe(true);
      expect(Array.isArray(parsed.warnings)).toBe(true);
    });

    it('rejects invalid version format', () => {
      const r = runCli(['schema-version', 'plan', 'v1', '1.1']);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('MAJOR.MINOR');
    });

    it('rejects downgrade migrations', () => {
      const r = runCli(['schema-version', 'plan', '1.1', '1.0']);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Downgrade');
    });
  });

  describe('validate-token subcommand', () => {
    it('rejects non-JWT input', () => {
      const r = runCli(['schema-version', 'validate-token', 'not-a-jwt']);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('valid JWT');
    });

    it('reports schema version from a valid-looking JWT payload', () => {
      // Construct a minimal JWT (header.payload.signature) without actually signing it
      const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({ schemaVersion: '1.0', iss: 'did:web:test.com', sub: 'agent-1', exp: 9999999999 })
      ).toString('base64url');
      const token = `${header}.${payload}.fakesig`;

      const r = runCli(['schema-version', 'validate-token', token]);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('Token schema version: 1.0');
      expect(r.stdout).toContain('did:web:test.com');
    });

    it('reports missing schemaVersion', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ iss: 'did:web:test.com' })).toString('base64url');
      const token = `${header}.${payload}.fakesig`;

      const r = runCli(['schema-version', 'validate-token', token]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('missing');
    });
  });
});

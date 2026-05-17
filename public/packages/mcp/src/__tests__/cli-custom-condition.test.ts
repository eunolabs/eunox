import * as childProcess from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const TS_NODE_REGISTER = require.resolve('ts-node/register');
const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');
const INVALID_MODULE = path.resolve(
  __dirname,
  '..',
  '..',
  'test',
  'fixtures',
  'custom-conditions',
  'invalid-default.cjs',
);

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function writeTempPolicy(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-mcp-cli-custom-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, 'policy.yaml');
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

function runProxy(args: string[]): { exitCode: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(
    process.execPath,
    [
      '--require',
      TS_NODE_REGISTER,
      CLI,
      'proxy',
      ...args,
      '--',
      process.execPath,
      '--eval',
      'setTimeout(() => {}, 60000)',
    ],
    {
      encoding: 'utf8',
      timeout: 15_000,
      env: {
        ...process.env,
        EUNO_TELEMETRY: '0',
      },
    },
  );

  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

describe('euno-mcp proxy --custom-condition', () => {
  it('fails fast when a custom-condition module path does not exist', () => {
    const missingPath = path.join(os.tmpdir(), 'euno-mcp-custom-missing-module.js');
    const result = runProxy(['--custom-condition', missingPath]);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Failed to load custom condition module');
  });

  it('fails fast when a custom-condition module default export is not a function', () => {
    const result = runProxy(['--custom-condition', INVALID_MODULE]);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('must export a default function');
  });

  it('fails startup validation with a --custom-condition hint when handler is not registered', () => {
    const policyFile = writeTempPolicy(`
agentId: custom-test-agent
name: Custom Test Agent
version: 0.1.0
requiredCapabilities:
  - resource: "echo"
    actions: [call]
    conditions:
      - type: custom
        name: denyBlockedRecipient
        config:
          blockedDomain: "blocked.test"
`.trim());
    const result = runProxy(['--policy', policyFile]);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Policy validation failed');
    expect(result.stderr).toContain('--custom-condition <module>');
  });
});

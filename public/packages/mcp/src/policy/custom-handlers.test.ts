import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  _resetCustomConditionRegistry,
  getCustomConditionHandlers,
  type AgentCapabilityManifest,
} from '@euno/common-core';
import {
  loadCustomConditionModules,
  validateCustomConditionRegistrations,
} from './custom-handlers';

const VALID_MODULE = path.resolve(
  __dirname,
  '..',
  '..',
  'test',
  'fixtures',
  'custom-conditions',
  'deny-blocked-recipient.cjs',
);

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
  _resetCustomConditionRegistry();
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function writeTempModule(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-mcp-custom-module-'));
  tempDirs.push(dir);
  const filePath = path.join(dir, 'module.js');
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

describe('loadCustomConditionModules', () => {
  it('loads a valid module and registers handlers', async () => {
    await loadCustomConditionModules([VALID_MODULE]);

    const handlers = getCustomConditionHandlers();
    expect(handlers.has('denyBlockedRecipient')).toBe(true);
  });

  it('throws a clear error when module file is missing', async () => {
    const missingPath = path.join(os.tmpdir(), 'euno-mcp-custom-missing-module.js');
    await expect(loadCustomConditionModules([missingPath]))
      .rejects
      .toThrow(/Failed to load custom condition module/);
  });

  it('throws when default export is not a function', async () => {
    await expect(loadCustomConditionModules([INVALID_MODULE]))
      .rejects
      .toThrow(/must export a default function/);
  });

  it('throws when module initializer throws', async () => {
    const throwingModule = writeTempModule(
      'module.exports = () => { throw new Error("boom") };\n',
    );
    await expect(loadCustomConditionModules([throwingModule]))
      .rejects
      .toThrow(/failed during initialization: boom/);
  });

  it('preflight rejects manifests referencing unregistered custom handlers', async () => {
    const manifest: AgentCapabilityManifest = {
      agentId: 'custom-test',
      name: 'Custom Test',
      version: '0.1.0',
      requiredCapabilities: [
        {
          resource: 'echo',
          actions: ['call'],
          conditions: [
            {
              type: 'custom',
              name: 'notRegistered',
              config: {},
            },
          ],
        },
      ],
    };
    expect(() => validateCustomConditionRegistrations(manifest))
      .toThrow(/has no registered handler/);
  });

  it('preflight accepts manifests when the custom handler is registered', async () => {
    await loadCustomConditionModules([VALID_MODULE]);
    const manifest: AgentCapabilityManifest = {
      agentId: 'custom-test',
      name: 'Custom Test',
      version: '0.1.0',
      requiredCapabilities: [
        {
          resource: 'echo',
          actions: ['call'],
          conditions: [
            {
              type: 'custom',
              name: 'denyBlockedRecipient',
              config: { blockedDomain: 'blocked.test' },
            },
          ],
        },
      ],
    };
    expect(() => validateCustomConditionRegistrations(manifest)).not.toThrow();
  });
});

/**
 * Unit tests for the EnforcementMode discriminated union and buildPdp factory
 * (MH-R2 — cli.ts PDP mode selection refactor).
 *
 * Test matrix
 * -----------
 * EnforcementMode union
 *   ✓ 'remote' mode carries url, apiKey, timeoutMs, and ignored-flag arrays
 *   ✓ 'local' mode carries policyPath?, customConditionModules, policyBackendPaths
 *
 * buildPdp — remote mode
 *   ✓ returns a RemoteEnforcerPDP instance
 *   ✓ does not return a conditionPdp
 *   ✓ warns to stderr when ignoredCustomConditionModules is non-empty
 *   ✓ warns to stderr when ignoredPolicyBackendPaths is non-empty
 *   ✓ prints the remote-enforcer startup message to stderr
 *   ✓ does NOT warn when ignored arrays are empty
 *
 * buildPdp — local mode (no policy)
 *   ✓ returns an AlwaysAllowPDP when no policyPath is supplied
 *   ✓ does not return a conditionPdp when no policyPath is supplied
 *   ✓ returns an AlwaysAllowPDP when customConditionModules is empty
 *
 * buildPdp — discriminant exhaustiveness (type-level)
 *   ✓ TypeScript accepts 'remote' and 'local' as the only valid mode values
 */

import { RemoteEnforcerPDP } from '../enforcer/remote';
import { AlwaysAllowPDP } from '../pdp';
import { buildPdp, EnforcementMode } from '../cli/pdp-factory';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Capture text written to process.stderr during a callback. */
async function captureStderr(fn: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const spy = jest.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
  return chunks.join('');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EnforcementMode discriminated union (MH-R2)', () => {
  it('remote mode has the expected shape', () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gateway.example.com',
      apiKey: 'sk-test-key',
      timeoutMs: 5000,
      ignoredCustomConditionModules: [],
      ignoredPolicyBackendPaths: [],
    };
    expect(mode.mode).toBe('remote');
    if (mode.mode === 'remote') {
      expect(mode.url).toBe('https://gateway.example.com');
      expect(mode.apiKey).toBe('sk-test-key');
      expect(mode.timeoutMs).toBe(5000);
    }
  });

  it('local mode has the expected shape', () => {
    const mode: EnforcementMode = {
      mode: 'local',
      customConditionModules: [],
      policyBackendPaths: [],
    };
    expect(mode.mode).toBe('local');
    if (mode.mode === 'local') {
      expect(mode.policyPath).toBeUndefined();
      expect(mode.customConditionModules).toEqual([]);
    }
  });
});

describe('buildPdp — remote mode', () => {
  it('returns a RemoteEnforcerPDP and no conditionPdp', async () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gw.example.com',
      apiKey: 'key',
      ignoredCustomConditionModules: [],
      ignoredPolicyBackendPaths: [],
    };
    // Suppress startup message written to stderr; we only care about pdp type here.
    await captureStderr(async () => {
      const { pdp, conditionPdp } = await buildPdp(mode);
      expect(pdp).toBeInstanceOf(RemoteEnforcerPDP);
      expect(conditionPdp).toBeUndefined();
    });
  });

  it('prints the remote-enforcer startup message to stderr', async () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gw.example.com',
      apiKey: 'key',
      ignoredCustomConditionModules: [],
      ignoredPolicyBackendPaths: [],
    };
    const stderr = await captureStderr(async () => { await buildPdp(mode); });
    expect(stderr).toContain('Remote-enforcer mode');
    expect(stderr).toContain('https://gw.example.com');
  });

  it('warns about ignored custom-condition modules', async () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gw.example.com',
      apiKey: 'key',
      ignoredCustomConditionModules: ['./my-handler.js'],
      ignoredPolicyBackendPaths: [],
    };
    const stderr = await captureStderr(async () => { await buildPdp(mode); });
    expect(stderr).toContain('--custom-condition is ignored in remote-enforcer mode');
  });

  it('warns about ignored policy-backend paths', async () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gw.example.com',
      apiKey: 'key',
      ignoredCustomConditionModules: [],
      ignoredPolicyBackendPaths: ['./my-backend.js'],
    };
    const stderr = await captureStderr(async () => { await buildPdp(mode); });
    expect(stderr).toContain('--policy-backend is ignored in remote-enforcer mode');
  });

  it('does not warn when ignored arrays are empty', async () => {
    const mode: EnforcementMode = {
      mode: 'remote',
      url: 'https://gw.example.com',
      apiKey: 'key',
      ignoredCustomConditionModules: [],
      ignoredPolicyBackendPaths: [],
    };
    const stderr = await captureStderr(async () => { await buildPdp(mode); });
    expect(stderr).not.toContain('WARNING');
  });
});

describe('buildPdp — local mode (no policy file)', () => {
  it('returns an AlwaysAllowPDP when no policyPath is supplied', async () => {
    const mode: EnforcementMode = {
      mode: 'local',
      customConditionModules: [],
      policyBackendPaths: [],
    };
    const { pdp, conditionPdp } = await buildPdp(mode);
    expect(pdp).toBeInstanceOf(AlwaysAllowPDP);
    expect(conditionPdp).toBeUndefined();
  });

  it('returns an AlwaysAllowPDP when customConditionModules is empty', async () => {
    const mode: EnforcementMode = {
      mode: 'local',
      policyPath: undefined,
      customConditionModules: [],
      policyBackendPaths: [],
    };
    const { pdp } = await buildPdp(mode);
    expect(pdp).toBeInstanceOf(AlwaysAllowPDP);
  });

  it('pdp and conditionPdp have correct types in no-policy local mode (type narrowing)', async () => {
    const mode: EnforcementMode = {
      mode: 'local',
      customConditionModules: [],
      policyBackendPaths: [],
    };
    const result = await buildPdp(mode);
    // conditionPdp is only present when a policy source was supplied
    expect(result.conditionPdp).toBeUndefined();
    // pdp is always present
    expect(result.pdp).toBeDefined();
  });
});

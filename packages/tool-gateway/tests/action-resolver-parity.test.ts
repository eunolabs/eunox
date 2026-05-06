/**
 * Unit tests for action-resolver hash parity helpers introduced in the
 * ActionResolver signing-artifact PR.
 *
 * These tests exercise:
 *  1. deriveIssuerMetadataUrl — URL derivation from the JWKS URL.
 *  2. checkActionResolverHashParity — hash comparison with warn/error policy.
 *
 * The fetch() call in checkActionResolverHashParity is intercepted via
 * Jest's globalThis.fetch mock so no real network connections are made.
 */

import { createLogger } from '@euno/common';
import { computeActionResolverHash } from '@euno/common';
import { deriveIssuerMetadataUrl, checkActionResolverHashParity } from '../src/bootstrap';

const logger = createLogger('parity-test', 'test');

// ---------------------------------------------------------------------------
// deriveIssuerMetadataUrl
// ---------------------------------------------------------------------------

describe('deriveIssuerMetadataUrl', () => {
  it('uses explicit ISSUER_METADATA_URL when provided', () => {
    expect(
      deriveIssuerMetadataUrl(
        'https://issuer.example.com/.well-known/capability-issuer',
        'https://issuer.example.com/.well-known/jwks.json',
      ),
    ).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('trims whitespace from explicit URL', () => {
    expect(
      deriveIssuerMetadataUrl(
        '  https://issuer.example.com/.well-known/capability-issuer  ',
        'https://issuer.example.com/.well-known/jwks.json',
      ),
    ).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('treats empty string explicit URL as absent', () => {
    expect(
      deriveIssuerMetadataUrl('', 'https://issuer.example.com/.well-known/jwks.json'),
    ).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('derives metadata URL from JWKS URL when it ends with /.well-known/jwks.json', () => {
    expect(
      deriveIssuerMetadataUrl(
        undefined,
        'https://issuer.example.com/.well-known/jwks.json',
      ),
    ).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('derives URL for localhost JWKS URL', () => {
    expect(
      deriveIssuerMetadataUrl(undefined, 'http://localhost:3001/.well-known/jwks.json'),
    ).toBe('http://localhost:3001/.well-known/capability-issuer');
  });

  it('returns undefined when JWKS URL does not end with /.well-known/jwks.json', () => {
    expect(
      deriveIssuerMetadataUrl(undefined, 'https://issuer.example.com/api/v1/public-key'),
    ).toBeUndefined();
  });

  it('returns undefined when both explicit URL and JWKS URL are unusable', () => {
    expect(deriveIssuerMetadataUrl(undefined, 'https://issuer.example.com/keys')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// checkActionResolverHashParity
// ---------------------------------------------------------------------------

describe('checkActionResolverHashParity', () => {
  const matchingHash = computeActionResolverHash(null);
  const differentHash = computeActionResolverHash({ actionTiers: { 'db:select': 'write' as const } });

  // Capture warn calls to verify they carry the right message.
  let warnSpy: jest.SpyInstance;
  // Save and restore global.fetch so mocks from one test cannot bleed into
  // other tests or test files that run in the same Jest worker.
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation((() => logger) as typeof logger.warn);
  });
  afterEach(() => {
    global.fetch = originalFetch;
    warnSpy.mockRestore();
  });

  function mockFetch(response: unknown, status = 200) {
    global.fetch = jest.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: async () => response,
    } as Response);
  }

  it('resolves without logging when hashes match (warn mode)', async () => {
    mockFetch({ actionResolverHash: matchingHash });
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'warn',
        logger,
      }),
    ).resolves.toBeUndefined();
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringMatching(/MISMATCH/));
  });

  it('logs a warn on mismatch when enforcement=warn', async () => {
    mockFetch({ actionResolverHash: differentHash });
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'warn',
        logger,
      }),
    ).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/MISMATCH/),
      expect.objectContaining({
        issuerHash: differentHash,
        localHash: matchingHash,
      }),
    );
  });

  it('throws on mismatch when enforcement=error', async () => {
    mockFetch({ actionResolverHash: differentHash });
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'error',
        logger,
      }),
    ).rejects.toThrow(/MISMATCH/);
  });

  it('logs a warn and continues when remote hash field is absent (forward-compat)', async () => {
    mockFetch({ issuer: 'did:web:issuer.example.com' }); // no actionResolverHash
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'error', // would throw if hash comparison ran
        logger,
      }),
    ).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/does not include actionResolverHash/),
      expect.anything(),
    );
  });

  it('logs a warn and continues on non-OK HTTP response', async () => {
    mockFetch({}, 503);
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'error',
        logger,
      }),
    ).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/non-OK status/),
      expect.anything(),
    );
  });

  it('logs a warn and continues on network error', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(
      checkActionResolverHashParity({
        issuerMetadataUrl: 'http://issuer/.well-known/capability-issuer',
        localHash: matchingHash,
        enforcement: 'error',
        logger,
      }),
    ).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/Failed to fetch issuer metadata/),
      expect.objectContaining({ error: 'ECONNREFUSED' }),
    );
  });
});

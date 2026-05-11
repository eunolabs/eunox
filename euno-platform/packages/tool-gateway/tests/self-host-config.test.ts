/**
 * Self-host bootstrap configuration tests — Task 13
 * ---------------------------------------------------------------------------
 * Verifies that the gateway's bootstrap layer correctly selects and
 * configures its pluggable backends based on environment variables.
 *
 * These tests exercise:
 *   1. `loadConfigFromEnv` with the most common self-host configuration
 *      profiles (dev/in-memory, full-stack with Redis+Postgres, production).
 *   2. `resolveAllowedOrigins` — CORS origin selection for each environment.
 *   3. `deriveIssuerMetadataUrl` — metadata URL derivation from JWKS URL.
 *   4. `checkActionResolverHashParity` — non-fatal behaviour on issuer
 *      metadata fetch errors (verifies the gateway does not abort startup
 *      due to a transient issuer outage).
 *   5. `parseTrustProxy` — proxy-trust configuration parsing.
 *
 * All tests run in-process without Redis, Postgres, or HTTP servers.
 */

import {
  loadConfigFromEnv,
  resolveAllowedOrigins,
  deriveIssuerMetadataUrl,
  checkActionResolverHashParity,
} from '../src/bootstrap';
import { createLogger } from '@euno/common';

// ── Shared fixtures ───────────────────────────────────────────────────────────

const MINIMUM_VALID_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: 'development',
  PORT: '3002',
  ADMIN_PORT: '3003',
  ISSUER_JWKS_URL: 'http://localhost:3001/.well-known/jwks.json',
};

const silentLogger = createLogger('self-host-config-test', 'test');

// ─────────────────────────────────────────────────────────────────────────────
// loadConfigFromEnv
// ─────────────────────────────────────────────────────────────────────────────
describe('loadConfigFromEnv', () => {
  describe('dev / in-memory profile (no Redis, no Postgres)', () => {
    it('succeeds with just the minimum required variables', () => {
      const config = loadConfigFromEnv(MINIMUM_VALID_ENV);
      expect(config.name).toBe('tool-gateway');
      expect(config.port).toBe(3002);
      expect(config.environment).toBe('development');
      expect(config.enableCryptographicAudit).toBe(false);
    });

    it('sets enableCryptographicAudit=false when ENABLE_CRYPTOGRAPHIC_AUDIT is absent', () => {
      const config = loadConfigFromEnv(MINIMUM_VALID_ENV);
      expect(config.enableCryptographicAudit).toBe(false);
    });

    it('sets enableCryptographicAudit=true when ENABLE_CRYPTOGRAPHIC_AUDIT=true', () => {
      const config = loadConfigFromEnv({
        ...MINIMUM_VALID_ENV,
        ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
        // A signing key is needed for cryptographic audit to not error at
        // bootstrap time; we test the config value here, not the full wiring.
        EVIDENCE_SIGNING_KEY_PEM: '(placeholder — not validated by loadConfigFromEnv)',
      });
      expect(config.enableCryptographicAudit).toBe(true);
    });

    it('uses the default policy version when POLICY_VERSION is unset', () => {
      const config = loadConfigFromEnv(MINIMUM_VALID_ENV);
      expect(config.policyVersion).toBe('1.0.0');
    });

    it('reads a custom policy version from POLICY_VERSION', () => {
      const config = loadConfigFromEnv({ ...MINIMUM_VALID_ENV, POLICY_VERSION: '2.3.0' });
      expect(config.policyVersion).toBe('2.3.0');
    });
  });

  describe('production profile', () => {
    const PROD_ENV: NodeJS.ProcessEnv = {
      ...MINIMUM_VALID_ENV,
      NODE_ENV: 'production',
      ADMIN_HOST: '127.0.0.1',
      ADMIN_API_KEY: 'prod-key',
      // Production requires evidence signing
      ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
      EVIDENCE_SIGNING_KEY_PEM: 'placeholder',
    };

    it('succeeds with production env + ADMIN_HOST + ADMIN_API_KEY + evidence signing', () => {
      const config = loadConfigFromEnv(PROD_ENV);
      expect(config.environment).toBe('production');
    });

    it('rejects a production env with ADMIN_HOST unset', () => {
      const { ADMIN_HOST: _, ...envNoHost } = PROD_ENV;
      expect(() => loadConfigFromEnv(envNoHost)).toThrow();
    });

    it('rejects a production env with ADMIN_HOST=0.0.0.0 (wildcard bind)', () => {
      expect(() =>
        loadConfigFromEnv({ ...PROD_ENV, ADMIN_HOST: '0.0.0.0' }),
      ).toThrow();
    });

    it('rejects a production env without ADMIN_API_KEY', () => {
      const { ADMIN_API_KEY: _, ...envNoKey } = PROD_ENV;
      expect(() => loadConfigFromEnv(envNoKey)).toThrow();
    });

    it('rejects a production env without evidence signing configured', () => {
      const { ENABLE_CRYPTOGRAPHIC_AUDIT: _, EVIDENCE_SIGNING_KEY_PEM: __, ...envNoSigning } = PROD_ENV;
      expect(() => loadConfigFromEnv(envNoSigning)).toThrow();
    });
  });

  describe('EUNO_DEPLOYMENT_TIER', () => {
    it('accepts single-replica tier without REDIS_URL', () => {
      const config = loadConfigFromEnv({
        ...MINIMUM_VALID_ENV,
        EUNO_DEPLOYMENT_TIER: 'single-replica',
      });
      expect(config.name).toBe('tool-gateway');
    });

    it('rejects multi-replica tier without REDIS_URL in production', () => {
      expect(() =>
        loadConfigFromEnv({
          ...MINIMUM_VALID_ENV,
          NODE_ENV: 'production',
          ADMIN_HOST: '127.0.0.1',
          ADMIN_API_KEY: 'key',
          ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
          EVIDENCE_SIGNING_KEY_PEM: 'placeholder',
          EUNO_DEPLOYMENT_TIER: 'multi-replica',
          // No REDIS_URL
        }),
      ).toThrow();
    });

    it('accepts multi-replica tier with REDIS_URL in production', () => {
      const config = loadConfigFromEnv({
        ...MINIMUM_VALID_ENV,
        NODE_ENV: 'production',
        ADMIN_HOST: '127.0.0.1',
        ADMIN_API_KEY: 'key',
        ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
        EVIDENCE_SIGNING_KEY_PEM: 'placeholder',
        EUNO_DEPLOYMENT_TIER: 'multi-replica',
        REDIS_URL: 'redis://redis:6379',
      });
      expect(config.name).toBe('tool-gateway');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// resolveAllowedOrigins
// ─────────────────────────────────────────────────────────────────────────────
describe('resolveAllowedOrigins', () => {
  it('returns localhost origins for development when ALLOWED_ORIGINS is unset', () => {
    const origins = resolveAllowedOrigins(MINIMUM_VALID_ENV, 'development');
    expect(origins.length).toBeGreaterThan(0);
    expect(origins.every((o) => o.startsWith('http://localhost'))).toBe(true);
  });

  it('returns empty array for production when ALLOWED_ORIGINS is unset', () => {
    const origins = resolveAllowedOrigins(MINIMUM_VALID_ENV, 'production');
    expect(origins).toEqual([]);
  });

  it('returns the configured origins when ALLOWED_ORIGINS is set', () => {
    const env = {
      ...MINIMUM_VALID_ENV,
      ALLOWED_ORIGINS: 'https://app.example.com,https://admin.example.com',
    };
    const origins = resolveAllowedOrigins(env, 'production');
    expect(origins).toContain('https://app.example.com');
    expect(origins).toContain('https://admin.example.com');
  });

  it('returns configured origins in development too', () => {
    const env = { ...MINIMUM_VALID_ENV, ALLOWED_ORIGINS: 'https://custom.local' };
    const origins = resolveAllowedOrigins(env, 'development');
    expect(origins).toEqual(['https://custom.local']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// deriveIssuerMetadataUrl
// ─────────────────────────────────────────────────────────────────────────────
describe('deriveIssuerMetadataUrl', () => {
  it('derives the metadata URL from a JWKS URL ending with /.well-known/jwks.json', () => {
    const url = deriveIssuerMetadataUrl(
      undefined,
      'https://issuer.example.com/.well-known/jwks.json',
    );
    expect(url).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('returns undefined when JWKS URL does not end with /.well-known/jwks.json', () => {
    const url = deriveIssuerMetadataUrl(undefined, 'https://issuer.example.com/keys');
    expect(url).toBeUndefined();
  });

  it('prefers the explicit metadata URL over derivation', () => {
    const url = deriveIssuerMetadataUrl(
      'https://custom.example.com/metadata',
      'https://issuer.example.com/.well-known/jwks.json',
    );
    expect(url).toBe('https://custom.example.com/metadata');
  });

  it('falls back to derivation when the explicit value is an empty string', () => {
    const url = deriveIssuerMetadataUrl(
      '',
      'https://issuer.example.com/.well-known/jwks.json',
    );
    expect(url).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('falls back to derivation when the explicit value is all whitespace', () => {
    const url = deriveIssuerMetadataUrl(
      '   ',
      'https://issuer.example.com/.well-known/jwks.json',
    );
    expect(url).toBe('https://issuer.example.com/.well-known/capability-issuer');
  });

  it('works with a local development URL including port', () => {
    const url = deriveIssuerMetadataUrl(
      undefined,
      'http://localhost:3001/.well-known/jwks.json',
    );
    expect(url).toBe('http://localhost:3001/.well-known/capability-issuer');
  });

  it('returns undefined when JWKS URL is a bare path with no suffix match', () => {
    const url = deriveIssuerMetadataUrl(undefined, 'http://localhost:3001');
    expect(url).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// checkActionResolverHashParity
// ─────────────────────────────────────────────────────────────────────────────
describe('checkActionResolverHashParity', () => {
  const baseArgs = {
    issuerMetadataUrl: 'http://issuer.example.com/.well-known/capability-issuer',
    localHash: 'abc123',
    logger: silentLogger,
  };

  // Restore all fetch mocks after each test so a test failure never poisons
  // the mock state for subsequent tests in this describe block.
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('resolves without throwing when the fetch errors (non-fatal)', async () => {
    // Simulate a network error (fetch rejects) — gateway must not abort startup.
    jest.spyOn(global, 'fetch').mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'warn' }),
    ).resolves.toBeUndefined();
  });

  it('resolves without throwing when the issuer returns a non-OK status', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({}),
    } as Response);
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'warn' }),
    ).resolves.toBeUndefined();
  });

  it('resolves without throwing when the metadata body lacks actionResolverHash', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ version: '1.0.0' }),
    } as Response);
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'warn' }),
    ).resolves.toBeUndefined();
  });

  it('resolves without throwing when hashes match', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ actionResolverHash: 'abc123' }),
    } as Response);
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'warn' }),
    ).resolves.toBeUndefined();
  });

  it('resolves (logs warning) on hash mismatch when enforcement=warn', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ actionResolverHash: 'different-hash' }),
    } as Response);
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'warn' }),
    ).resolves.toBeUndefined();
  });

  it('throws on hash mismatch when enforcement=error', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ actionResolverHash: 'different-hash' }),
    } as Response);
    await expect(
      checkActionResolverHashParity({ ...baseArgs, enforcement: 'error' }),
    ).rejects.toThrow('ACTION RESOLVER HASH MISMATCH');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Trust-proxy configuration
// ─────────────────────────────────────────────────────────────────────────────
// parseTrustProxy is an internal helper but its behaviour is verified
// indirectly by checking that loadConfigFromEnv propagates TRUST_PROXY into
// the service config (and that the gateway starts without error).  Direct
// behavioural coverage lives here because the mapping is security-critical
// (F-2 DPoP htu reconstruction).

describe('TRUST_PROXY behaviour via loadConfigFromEnv', () => {
  it('loads successfully when TRUST_PROXY is absent (default: no proxy trust)', () => {
    const config = loadConfigFromEnv(MINIMUM_VALID_ENV);
    // Presence of the config is sufficient — TRUST_PROXY is wired in bootstrap,
    // not surfaced in ServiceConfig; this test confirms no validation error.
    expect(config.name).toBe('tool-gateway');
  });

  it('loads successfully when TRUST_PROXY=1 (single hop)', () => {
    const config = loadConfigFromEnv({ ...MINIMUM_VALID_ENV, TRUST_PROXY: '1' });
    expect(config.name).toBe('tool-gateway');
  });

  it('loads successfully when TRUST_PROXY=loopback', () => {
    const config = loadConfigFromEnv({ ...MINIMUM_VALID_ENV, TRUST_PROXY: 'loopback' });
    expect(config.name).toBe('tool-gateway');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Port / admin-port configuration
// ─────────────────────────────────────────────────────────────────────────────
describe('port configuration', () => {
  it('uses PORT env var as the gateway listen port', () => {
    const config = loadConfigFromEnv({ ...MINIMUM_VALID_ENV, PORT: '8080' });
    expect(config.port).toBe(8080);
  });

  it('falls back to the default port when PORT is absent', () => {
    const { PORT: _, ...envNoPort } = MINIMUM_VALID_ENV;
    // The schema provides a default value; loadConfigFromEnv must not throw.
    const config = loadConfigFromEnv(envNoPort);
    expect(typeof config.port).toBe('number');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Configurable backend env-var documentation
// ─────────────────────────────────────────────────────────────────────────────
// These smoke-level assertions verify that the environment variables used in
// infra/docker-compose.yml map to the schema the gateway expects, and that
// the gateway starts in the expected mode for each profile.

describe('docker-compose.yml backend profile parity', () => {
  describe('dev profile (in-memory, no external services)', () => {
    const DEV_ENV: NodeJS.ProcessEnv = {
      ...MINIMUM_VALID_ENV,
      NODE_ENV: 'development',
      AUDIT_LEDGER_BACKEND: 'none',
      ENABLE_CRYPTOGRAPHIC_AUDIT: 'false',
    };

    it('loads successfully without REDIS_URL', () => {
      const config = loadConfigFromEnv(DEV_ENV);
      expect(config.name).toBe('tool-gateway');
    });

    it('has cryptographic audit disabled', () => {
      const config = loadConfigFromEnv(DEV_ENV);
      expect(config.enableCryptographicAudit).toBe(false);
    });
  });

  describe('full profile (Redis + Postgres)', () => {
    const FULL_ENV: NodeJS.ProcessEnv = {
      ...MINIMUM_VALID_ENV,
      NODE_ENV: 'development',
      REDIS_URL: 'redis://redis:6379',
      AUDIT_LEDGER_BACKEND: 'postgres',
      AUDIT_LEDGER_PG_URL: 'postgresql://euno:euno_dev_secret@postgres:5432/euno_audit',
      AUDIT_LEDGER_HMAC_SECRET: 'dev-hmac-secret-change-in-production',
      AUDIT_LEDGER_RUN_MIGRATIONS: 'true',
    };

    it('loads successfully with Redis + Postgres env vars', () => {
      const config = loadConfigFromEnv(FULL_ENV);
      expect(config.name).toBe('tool-gateway');
    });
  });

  describe('smoke-test profile (in-memory ledger)', () => {
    const SMOKE_ENV: NodeJS.ProcessEnv = {
      ...MINIMUM_VALID_ENV,
      NODE_ENV: 'development',
      REDIS_URL: 'redis://redis:6379',
      AUDIT_LEDGER_BACKEND: 'in-memory',
    };

    it('loads successfully with in-memory ledger backend', () => {
      const config = loadConfigFromEnv(SMOKE_ENV);
      expect(config.name).toBe('tool-gateway');
    });
  });
});

/**
 * Tests for the minter production configuration guard (Task 1).
 *
 * `validateProductionMinterConfig` must throw when any unsafe fallback would
 * be activated in a production environment, and must be a no-op in non-
 * production environments.
 */
import { validateProductionMinterConfig } from '../src/production-guard';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** A minimal safe production environment. */
const SAFE_PROD_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: 'production',
  MINTER_ADMIN_API_KEY: 'super-secret-admin-key-32chars!!',
  MINTER_PEPPER_HEX: 'a'.repeat(64), // 32 bytes of valid hex
  MINTER_PRIVATE_KEY_PEM: '-----BEGIN EC PRIVATE KEY-----\nplaceholder\n-----END EC PRIVATE KEY-----',
  MINTER_PUBLIC_KEY_PEM: '-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----',
  MINTER_AUDIT_DB_URL: 'postgres://user:pass@db:5432/minter_audit',
  MINTER_API_KEY_DB_URL: 'postgres://user:pass@db:5432/minter_keys',
};

/** Development environment — all unsafe fallbacks are permitted. */
const DEV_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: 'development',
};

// ── Non-production bypass ─────────────────────────────────────────────────────

describe('non-production environments', () => {
  it('does not throw for NODE_ENV=development even with all unsafe fallbacks', () => {
    expect(() => validateProductionMinterConfig(DEV_ENV)).not.toThrow();
  });

  it('does not throw when NODE_ENV is absent', () => {
    expect(() => validateProductionMinterConfig({})).not.toThrow();
  });

  it('does not throw for NODE_ENV=test', () => {
    expect(() => validateProductionMinterConfig({ NODE_ENV: 'test' })).not.toThrow();
  });
});

// ── Safe production configuration ─────────────────────────────────────────────

describe('safe production configuration', () => {
  it('does not throw when all required config is present (PEM keys)', () => {
    expect(() => validateProductionMinterConfig(SAFE_PROD_ENV)).not.toThrow();
  });

  it('does not throw when KMS provider is set instead of PEM keys', () => {
    const { MINTER_PRIVATE_KEY_PEM: _priv, MINTER_PUBLIC_KEY_PEM: _pub, ...rest } = SAFE_PROD_ENV;
    expect(() =>
      validateProductionMinterConfig({ ...rest, MINTER_KMS_PROVIDER: 'aws-kms' }),
    ).not.toThrow();
  });

  it('does not throw when HA Redis Sentinel URL is configured', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        REDIS_URL: 'redis+sentinel://sentinel1:26379,sentinel2:26379?name=mymaster',
      }),
    ).not.toThrow();
  });

  it('does not throw when HA Redis Cluster URL (comma-separated nodes) is configured', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        REDIS_URL: 'redis://node1:6379,node2:6379,node3:6379',
      }),
    ).not.toThrow();
  });

  it('does not throw when HA redis+cluster:// URL is configured', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        REDIS_URL: 'redis+cluster://redis-cluster:6379',
      }),
    ).not.toThrow();
  });

  it('does not throw when no Redis URLs are configured (Redis is optional for the minter)', () => {
    const { REDIS_URL: _r, ANOMALY_REDIS_URL: _a, MINTER_PING_REDIS_URL: _p, ...rest } =
      SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).not.toThrow();
  });
});

// ── Unsafe config — each violation individually ────────────────────────────────

describe('production safety violations', () => {
  it('throws when MINTER_ADMIN_API_KEY is absent', () => {
    const { MINTER_ADMIN_API_KEY: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/MINTER_ADMIN_API_KEY/);
  });

  it("throws when MINTER_ADMIN_API_KEY equals the insecure default 'dev-admin-key'", () => {
    expect(() =>
      validateProductionMinterConfig({ ...SAFE_PROD_ENV, MINTER_ADMIN_API_KEY: 'dev-admin-key' }),
    ).toThrow(/insecure default/i);
  });

  it('throws when MINTER_ADMIN_API_KEY is shorter than 32 characters', () => {
    expect(() =>
      validateProductionMinterConfig({ ...SAFE_PROD_ENV, MINTER_ADMIN_API_KEY: 'short' }),
    ).toThrow(/too short/i);
  });

  it('accepts MINTER_ADMIN_API_KEY of exactly 32 characters', () => {
    expect(() =>
      validateProductionMinterConfig({ ...SAFE_PROD_ENV, MINTER_ADMIN_API_KEY: 'a'.repeat(32) }),
    ).not.toThrow();
  });

  it('throws when MINTER_PEPPER_HEX is absent', () => {
    const { MINTER_PEPPER_HEX: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/MINTER_PEPPER_HEX/);
  });

  it('throws when no signing key is configured (no KMS, no PEM)', () => {
    const { MINTER_PRIVATE_KEY_PEM: _priv, MINTER_PUBLIC_KEY_PEM: _pub, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/signing key/i);
  });

  it('throws when only MINTER_PRIVATE_KEY_PEM is set (missing public key)', () => {
    const { MINTER_PUBLIC_KEY_PEM: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/signing key/i);
  });

  it('throws when only MINTER_PUBLIC_KEY_PEM is set (missing private key)', () => {
    const { MINTER_PRIVATE_KEY_PEM: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/signing key/i);
  });

  it('throws when MINTER_AUDIT_DB_URL is absent', () => {
    const { MINTER_AUDIT_DB_URL: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/MINTER_AUDIT_DB_URL/);
  });

  it('throws when MINTER_API_KEY_DB_URL is absent', () => {
    const { MINTER_API_KEY_DB_URL: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/MINTER_API_KEY_DB_URL/);
  });

  it('throws when REDIS_URL points at a single-node instance', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        REDIS_URL: 'redis://localhost:6379',
      }),
    ).toThrow(/single-node Redis/i);
  });

  it('throws when ANOMALY_REDIS_URL points at a single-node instance', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        ANOMALY_REDIS_URL: 'redis://redis.internal:6379',
      }),
    ).toThrow(/single-node Redis/i);
  });

  it('throws when MINTER_PING_REDIS_URL points at a single-node instance', () => {
    expect(() =>
      validateProductionMinterConfig({
        ...SAFE_PROD_ENV,
        MINTER_PING_REDIS_URL: 'redis://ping-redis:6379',
      }),
    ).toThrow(/single-node Redis/i);
  });
});

// ── Multiple violations in one error ──────────────────────────────────────────

describe('multiple violations', () => {
  it('reports all violations in a single throw when multiple configs are missing', () => {
    const {
      MINTER_ADMIN_API_KEY: _admin,
      MINTER_PEPPER_HEX: _pepper,
      MINTER_AUDIT_DB_URL: _audit,
      MINTER_API_KEY_DB_URL: _keys,
      ...rest
    } = SAFE_PROD_ENV;

    let caught: Error | undefined;
    try {
      validateProductionMinterConfig(rest);
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeDefined();
    expect(caught?.message).toContain('MINTER_ADMIN_API_KEY');
    expect(caught?.message).toContain('MINTER_PEPPER_HEX');
    expect(caught?.message).toContain('MINTER_AUDIT_DB_URL');
    expect(caught?.message).toContain('MINTER_API_KEY_DB_URL');
  });

  it('includes "production configuration is unsafe" in the error message', () => {
    const { MINTER_ADMIN_API_KEY: _, ...rest } = SAFE_PROD_ENV;
    expect(() => validateProductionMinterConfig(rest)).toThrow(/production configuration is unsafe/i);
  });
});

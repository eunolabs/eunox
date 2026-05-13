/**
 * Tests for the typed `EunoConfig` loader and `.env.example`
 * generator (R-5 in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 */

import {
  loadConfig,
  formatConfigErrors,
  dumpEnvTemplate,
  EUNO_SERVICE_NAMES,
} from '../src/config';

/** Minimal env that passes the minter schema in production. */
const MINTER_PROD_ENV = {
  NODE_ENV: 'production',
  MINTER_ADMIN_API_KEY: 'a'.repeat(32),
  MINTER_PEPPER_HEX: 'a'.repeat(64),
  MINTER_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----',
  MINTER_PUBLIC_KEY_PEM: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu\n-----END PUBLIC KEY-----',
  MINTER_AUDIT_DB_URL: 'postgresql://localhost:5432/audit',
  MINTER_API_KEY_DB_URL: 'postgresql://localhost:5432/keys',
};

describe('loadConfig (issuer)', () => {
  it('rejects an empty environment with the canonical fail-closed errors', () => {
    const result = loadConfig({}, 'issuer');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Default SIGNING_PROVIDER is azure-keyvault, so AZURE_KEYVAULT_URL must be set.
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'AZURE_KEYVAULT_URL',
          message: expect.stringMatching(/AZURE_KEYVAULT_URL/),
        }),
      ]),
    );
  });

  it('accepts a minimal happy path and applies declared defaults', () => {
    const result = loadConfig(
      { AZURE_KEYVAULT_URL: 'https://vault.example/' },
      'issuer',
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.PORT).toBe(3001);
    expect(result.config.NODE_ENV).toBe('development');
    expect(result.config.SIGNING_PROVIDER).toBe('azure-keyvault');
    expect(result.config.IDENTITY_PROVIDER).toBe('azure-ad');
    expect(result.config.DEFAULT_TOKEN_TTL).toBe(900);
    expect(result.config.ENABLE_DETAILED_LOGGING).toBe(false);
  });

  it('rejects a non-numeric PORT with a structured error', () => {
    const result = loadConfig(
      { AZURE_KEYVAULT_URL: 'https://vault.example/', PORT: 'not-a-port' },
      'issuer',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'PORT',
          message: expect.stringContaining('not-a-port'),
        }),
      ]),
    );
  });

  it('rejects partially-numeric values like "10abc" (strict integer parse)', () => {
    const result = loadConfig(
      { AZURE_KEYVAULT_URL: 'https://vault.example/', PORT: '10abc' },
      'issuer',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'PORT',
          message: expect.stringContaining('10abc'),
        }),
      ]),
    );
  });

  it('treats empty strings as unset and applies defaults', () => {
    const result = loadConfig(
      {
        AZURE_KEYVAULT_URL: 'https://vault.example/',
        PORT: '',
        DEFAULT_TOKEN_TTL: '',
      },
      'issuer',
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.PORT).toBe(3001);
    expect(result.config.DEFAULT_TOKEN_TTL).toBe(900);
  });

  it('parses ALLOWED_ORIGINS as a trimmed CSV list', () => {
    const result = loadConfig(
      {
        AZURE_KEYVAULT_URL: 'https://vault.example/',
        ALLOWED_ORIGINS: 'https://a.example, https://b.example , ',
      },
      'issuer',
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.ALLOWED_ORIGINS).toEqual([
      'https://a.example',
      'https://b.example',
    ]);
  });

  it.each([
    ['SIGNING_PROVIDER=aws-kms requires AWS_KMS_KEY_ID', { SIGNING_PROVIDER: 'aws-kms' }, 'AWS_KMS_KEY_ID'],
    [
      'SIGNING_PROVIDER=gcp-cloudkms requires the three GCP keys',
      { SIGNING_PROVIDER: 'gcp-cloudkms' },
      'GCP_PROJECT_ID',
    ],
    [
      'IDENTITY_PROVIDER=gcp-identity requires GCP_IDENTITY_AUDIENCE',
      { AZURE_KEYVAULT_URL: 'https://v/', IDENTITY_PROVIDER: 'gcp-identity' },
      'GCP_IDENTITY_AUDIENCE',
    ],
    [
      'DB_TOKENS_ENABLED=true requires DB_INSTANCES_FILE',
      {
        AZURE_KEYVAULT_URL: 'https://v/',
        DB_TOKENS_ENABLED: 'true',
      },
      'DB_INSTANCES_FILE',
    ],
  ])('cross-field check: %s', (_label, env, expectedField) => {
    const result = loadConfig(env as NodeJS.ProcessEnv, 'issuer');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === expectedField)).toBe(true);
  });

  it('rejects an out-of-range storage grant TTL with a single, structured error', () => {
    const result = loadConfig(
      {
        AZURE_KEYVAULT_URL: 'https://v/',
        STORAGE_GRANT_MAX_TTL_SECONDS: '999999',
      },
      'issuer',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]?.field).toBe('STORAGE_GRANT_MAX_TTL_SECONDS');
  });

  // Production-tier safety invariants for the issuer (mirror of the
  // gateway's superRefine extensions). The issuer's only tier-driven
  // hard requirements are REDIS_URL (for multi-replica / multi-region)
  // and ISSUER_REGION (for multi-region active/active); everything else
  // is enforced on the gateway side.
  describe('production safety invariants', () => {
    const baseProd = {
      NODE_ENV: 'production',
      AZURE_KEYVAULT_URL: 'https://vault.example/',
    };

    it('rejects production + multi-replica without REDIS_URL', () => {
      const result = loadConfig(
        { ...baseProd, EUNO_DEPLOYMENT_TIER: 'multi-replica' },
        'issuer',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'REDIS_URL' }),
        ]),
      );
    });

    it('accepts production + multi-replica when REDIS_URL is set', () => {
      const result = loadConfig(
        {
          ...baseProd,
          EUNO_DEPLOYMENT_TIER: 'multi-replica',
          REDIS_URL: 'redis://redis:6379',
        },
        'issuer',
      );
      expect(result.ok).toBe(true);
    });

    it('rejects production + multi-region-active-active without ISSUER_REGION', () => {
      const result = loadConfig(
        {
          ...baseProd,
          EUNO_DEPLOYMENT_TIER: 'multi-region-active-active',
          REDIS_URL: 'redis://redis:6379',
        },
        'issuer',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'ISSUER_REGION' }),
        ]),
      );
    });

    it('accepts production + single-replica without REDIS_URL', () => {
      const result = loadConfig(
        { ...baseProd, EUNO_DEPLOYMENT_TIER: 'single-replica' },
        'issuer',
      );
      expect(result.ok).toBe(true);
    });
  });
});

describe('loadConfig (gateway)', () => {
  it('accepts an empty environment and applies sane defaults', () => {
    const result = loadConfig({}, 'gateway');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.PORT).toBe(3002);
    expect(result.config.RATE_LIMIT_WINDOW_MS).toBe(60000);
    expect(result.config.RATE_LIMIT_MAX_REQUESTS).toBe(1000);
    expect(result.config.ENABLE_CRYPTOGRAPHIC_AUDIT).toBe(false);
  });

  it('rejects ENABLE_CRYPTOGRAPHIC_AUDIT=true without an evidence key', () => {
    const result = loadConfig(
      { ENABLE_CRYPTOGRAPHIC_AUDIT: 'true' },
      'gateway',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'EVIDENCE_SIGNING_KEY_PEM',
          message: expect.stringMatching(/EVIDENCE_SIGNING_KEY_PEM|EVIDENCE_SIGNING_KEY_FILE/),
        }),
      ]),
    );
  });

  it('accepts ENABLE_CRYPTOGRAPHIC_AUDIT=true with EVIDENCE_SIGNING_KEY_FILE', () => {
    const result = loadConfig(
      {
        ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
        EVIDENCE_SIGNING_KEY_FILE: '/etc/euno/key.pem',
      },
      'gateway',
    );
    expect(result.ok).toBe(true);
  });

  // I-8: per-decision evidence signing
  it('parses EVIDENCE_SIGNED_DECISIONS as a CSV of decisions', () => {
    const result = loadConfig(
      {
        EVIDENCE_SIGNED_DECISIONS: 'deny',
        EVIDENCE_SIGNING_KEY_FILE: '/etc/euno/key.pem',
      },
      'gateway',
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.EVIDENCE_SIGNED_DECISIONS).toEqual(['deny']);
  });

  it('rejects EVIDENCE_SIGNED_DECISIONS with unsupported values', () => {
    const result = loadConfig(
      {
        EVIDENCE_SIGNED_DECISIONS: 'allow,maybe',
        EVIDENCE_SIGNING_KEY_FILE: '/etc/euno/key.pem',
      },
      'gateway',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'EVIDENCE_SIGNED_DECISIONS',
          message: expect.stringMatching(/maybe/),
        }),
      ]),
    );
  });

  it('rejects a non-empty EVIDENCE_SIGNED_DECISIONS without an evidence key', () => {
    const result = loadConfig(
      { EVIDENCE_SIGNED_DECISIONS: 'deny' },
      'gateway',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'EVIDENCE_SIGNING_KEY_PEM',
          message: expect.stringMatching(/EVIDENCE_SIGNED_DECISIONS/),
        }),
      ]),
    );
  });

  it('accepts an empty EVIDENCE_SIGNED_DECISIONS value (signing disabled, no key needed)', () => {
    const result = loadConfig(
      { EVIDENCE_SIGNED_DECISIONS: '' },
      'gateway',
    );
    expect(result.ok).toBe(true);
  });

  // Regression: when EVIDENCE_SIGNED_DECISIONS is defined it must be
  // authoritative — even an explicitly-empty list (e.g. only commas /
  // whitespace, which `envCsv` reduces to []) must disable signing
  // regardless of the legacy ENABLE_CRYPTOGRAPHIC_AUDIT boolean. The
  // schema must therefore NOT demand an evidence signing key in this
  // combination, since the EnforcementEngine will not sign anything.
  it('treats EVIDENCE_SIGNED_DECISIONS as authoritative: empty list overrides ENABLE_CRYPTOGRAPHIC_AUDIT=true', () => {
    const result = loadConfig(
      {
        EVIDENCE_SIGNED_DECISIONS: ',',
        ENABLE_CRYPTOGRAPHIC_AUDIT: 'true',
      },
      'gateway',
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.EVIDENCE_SIGNED_DECISIONS).toEqual([]);
    expect(result.config.ENABLE_CRYPTOGRAPHIC_AUDIT).toBe(true);
  });

  // I-7: strict argument-schema mode
  it('parses ARGUMENT_SCHEMA_REQUIRED as a boolean (default false)', () => {
    const off = loadConfig({}, 'gateway');
    expect(off.ok).toBe(true);
    if (!off.ok) return;
    expect(off.config.ARGUMENT_SCHEMA_REQUIRED).toBe(false);

    const on = loadConfig({ ARGUMENT_SCHEMA_REQUIRED: 'true' }, 'gateway');
    expect(on.ok).toBe(true);
    if (!on.ok) return;
    expect(on.config.ARGUMENT_SCHEMA_REQUIRED).toBe(true);
  });

  it('rejects a non-boolean ENABLE_DETAILED_LOGGING with a structured error', () => {
    const result = loadConfig(
      { ENABLE_DETAILED_LOGGING: 'yes' },
      'gateway',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]?.field).toBe('ENABLE_DETAILED_LOGGING');
  });

  it('aggregates multiple unrelated errors into one report (no early exit)', () => {
    const result = loadConfig(
      {
        PORT: 'oops',
        ENABLE_DETAILED_LOGGING: 'sometimes',
        RATE_LIMIT_WINDOW_MS: '-7',
      },
      'gateway',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const fields = result.errors.map((e) => e.field).sort();
    expect(fields).toEqual(
      expect.arrayContaining([
        'ENABLE_DETAILED_LOGGING',
        'PORT',
        'RATE_LIMIT_WINDOW_MS',
      ]),
    );
  });

  // Admin API protection: ADMIN_API_KEY is required in production
  it('rejects NODE_ENV=production without ADMIN_API_KEY', () => {
    const result = loadConfig({ NODE_ENV: 'production' }, 'gateway');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: 'ADMIN_API_KEY',
          message: expect.stringMatching(/ADMIN_API_KEY.*NODE_ENV=production|NODE_ENV=production.*ADMIN_API_KEY/),
        }),
      ]),
    );
  });

  it('accepts NODE_ENV=production when the full set of production safety invariants are satisfied', () => {
    // After the production-safety-invariant work this is the minimum
    // viable production env: admin API key, JWKS URL, an explicit admin
    // bind interface, and at least one signed-decision class with an
    // evidence key. EUNO_DEPLOYMENT_TIER defaults to single-replica so
    // REDIS_URL is not required here (covered by separate tests).
    const result = loadConfig(
      {
        NODE_ENV: 'production',
        ADMIN_API_KEY: 'super-secret-key',
        ADMIN_HOST: '127.0.0.1',
        ISSUER_JWKS_URL: 'https://issuer.example.com/.well-known/jwks.json',
        EVIDENCE_SIGNED_DECISIONS: 'deny',
        EVIDENCE_SIGNING_KEY_FILE: '/etc/euno/evidence-key.pem',
      },
      'gateway',
    );
    expect(result.ok).toBe(true);
  });

  // ---------------------------------------------------------------------
  // Production-tier safety invariants. These are derived from
  // docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md and rejected by the schema
  // so a misconfigured rollout fails at boot rather than at first
  // request. See `superRefine` in `GatewayConfigSchema`.
  // ---------------------------------------------------------------------
  describe('production safety invariants', () => {
    const baseProd = {
      NODE_ENV: 'production',
      ADMIN_API_KEY: 'super-secret-key',
      ADMIN_HOST: '127.0.0.1',
      ISSUER_JWKS_URL: 'https://issuer.example.com/.well-known/jwks.json',
      EVIDENCE_SIGNED_DECISIONS: 'deny',
      EVIDENCE_SIGNING_KEY_FILE: '/etc/euno/evidence-key.pem',
    };

    it('rejects production + EUNO_DEPLOYMENT_TIER=multi-replica without REDIS_URL', () => {
      const result = loadConfig(
        { ...baseProd, EUNO_DEPLOYMENT_TIER: 'multi-replica' },
        'gateway',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'REDIS_URL',
            message: expect.stringMatching(/EUNO_DEPLOYMENT_TIER=multi-replica/),
          }),
        ]),
      );
    });

    it('accepts production + multi-replica when REDIS_URL is set', () => {
      const result = loadConfig(
        {
          ...baseProd,
          EUNO_DEPLOYMENT_TIER: 'multi-replica',
          REDIS_URL: 'redis://redis:6379',
        },
        'gateway',
      );
      expect(result.ok).toBe(true);
    });

    it('rejects production + multi-region-active-active without GATEWAY_REGION', () => {
      const result = loadConfig(
        {
          ...baseProd,
          EUNO_DEPLOYMENT_TIER: 'multi-region-active-active',
          REDIS_URL: 'redis://redis:6379',
        },
        'gateway',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'GATEWAY_REGION' }),
        ]),
      );
    });

    it('rejects production with DPOP_REQUIRED=false (post-migration default is true)', () => {
      const result = loadConfig(
        { ...baseProd, DPOP_REQUIRED: 'false' },
        'gateway',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'DPOP_REQUIRED',
            message: expect.stringMatching(/DPOP_REQUIRED=false/),
          }),
        ]),
      );
    });

    it('rejects production without ISSUER_JWKS_URL even if deprecated ISSUER_PUBLIC_KEY_URL is set', () => {
      const { ISSUER_JWKS_URL: _strip, ...rest } = baseProd;
      void _strip;
      const result = loadConfig(
        {
          ...rest,
          ISSUER_PUBLIC_KEY_URL: 'http://issuer:3001/api/v1/public-key',
        },
        'gateway',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'ISSUER_JWKS_URL',
            message: expect.stringMatching(/deprecated/),
          }),
        ]),
      );
    });

    it('rejects production with no evidence signing configured', () => {
      const { EVIDENCE_SIGNED_DECISIONS: _a, EVIDENCE_SIGNING_KEY_FILE: _b, ...rest } = baseProd;
      void _a; void _b;
      const result = loadConfig(rest, 'gateway');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'EVIDENCE_SIGNED_DECISIONS',
            message: expect.stringMatching(/Evidence signing/),
          }),
        ]),
      );
    });

    it('accepts production when ENABLE_CRYPTOGRAPHIC_AUDIT=true is used as the legacy shorthand', () => {
      const { EVIDENCE_SIGNED_DECISIONS: _a, ...rest } = baseProd;
      void _a;
      const result = loadConfig(
        { ...rest, ENABLE_CRYPTOGRAPHIC_AUDIT: 'true' },
        'gateway',
      );
      expect(result.ok).toBe(true);
    });

    it('rejects production with ADMIN_HOST unset', () => {
      const { ADMIN_HOST: _a, ...rest } = baseProd;
      void _a;
      const result = loadConfig(rest, 'gateway');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'ADMIN_HOST',
            message: expect.stringMatching(/non-wildcard/),
          }),
        ]),
      );
    });

    it('rejects production with ADMIN_HOST=0.0.0.0 (wildcard)', () => {
      const result = loadConfig(
        { ...baseProd, ADMIN_HOST: '0.0.0.0' },
        'gateway',
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: 'ADMIN_HOST' }),
        ]),
      );
    });

    it('does not apply production rules to NODE_ENV=staging', () => {
      // Staging is exempt from the production safety invariants so
      // pre-prod environments can iterate without the full hardening
      // suite. Single-replica staging without Redis must validate.
      const result = loadConfig(
        { NODE_ENV: 'staging', EUNO_DEPLOYMENT_TIER: 'multi-replica' },
        'gateway',
      );
      expect(result.ok).toBe(true);
    });
  });
});

describe('formatConfigErrors', () => {
  it('produces a multi-line, operator-friendly block', () => {
    const text = formatConfigErrors('issuer', [
      { field: 'PORT', message: 'must be an integer (got "x")' },
      { field: 'AZURE_KEYVAULT_URL', message: 'is required.' },
    ]);
    expect(text).toContain('Invalid issuer configuration — 2 problems');
    expect(text).toContain('• PORT: must be an integer');
    expect(text).toContain('• AZURE_KEYVAULT_URL: is required.');
  });

  it('uses singular "problem" for a single error', () => {
    const text = formatConfigErrors('gateway', [
      { field: 'X', message: 'bad' },
    ]);
    expect(text).toContain('1 problem:');
  });
});

describe('dumpEnvTemplate', () => {
  it.each(EUNO_SERVICE_NAMES)(
    '%s template parses cleanly back through loadConfig',
    (service) => {
      const text = dumpEnvTemplate(service);
      expect(text).toMatch(/^# /); // starts with a comment header
      expect(text.endsWith('\n')).toBe(true);

      // Reconstruct a process.env from the *uncommented* assignments in
      // the template; the loader should accept that environment without
      // errors. This pins down the contract that dump-template only
      // emits values that the loader accepts.
      const env: NodeJS.ProcessEnv = {};
      for (const line of text.split('\n')) {
        if (!line || line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq < 0) continue;
        env[line.slice(0, eq)] = line.slice(eq + 1);
      }
      // The template must be self-validating: copying it and only
      // filling in the *uncommented* placeholders should produce an
      // env that the loader accepts. The dump-template generator
      // emits conditionally-required fields (e.g. AZURE_KEYVAULT_URL
      // when SIGNING_PROVIDER defaults to azure-keyvault) uncommented
      // for exactly this reason.
      const result = loadConfig(env, service);
      expect(result.ok).toBe(true);
    },
  );

  it('emits conditionally-required fields uncommented under defaults', () => {
    // Default SIGNING_PROVIDER=azure-keyvault makes AZURE_KEYVAULT_URL
    // required via superRefine even though the field itself is optional.
    // The template should surface that as an uncommented placeholder
    // rather than a commented-out hint, so a copy-paste flow fails
    // closed at boot with a meaningful message instead of silently
    // skipping the var.
    const issuer = dumpEnvTemplate('issuer');
    expect(issuer).toMatch(/^AZURE_KEYVAULT_URL=/m);
    expect(issuer).not.toMatch(/^# AZURE_KEYVAULT_URL=/m);
  });

  it('emits both required (uncommented) and optional (commented) vars', () => {
    const issuer = dumpEnvTemplate('issuer');
    // SIGNING_PROVIDER has a default => should appear uncommented.
    expect(issuer).toMatch(/^SIGNING_PROVIDER=azure-keyvault$/m);
    // AZURE_KEYVAULT_KEY_NAME is purely optional with no default and
    // no cross-field requirement => commented out.
    expect(issuer).toMatch(/^# AZURE_KEYVAULT_KEY_NAME=/m);
  });

  it('surfaces enum allowed values in the placeholder hint', () => {
    const gateway = dumpEnvTemplate('gateway');
    // ENABLE_CRYPTOGRAPHIC_AUDIT defaults to false, so it appears as
    // an explicit assignment; AWS_COGNITO_TOKEN_USE is enum-typed and
    // optional, so its placeholder shows the allowed values.
    expect(gateway).toMatch(/^ENABLE_CRYPTOGRAPHIC_AUDIT=false$/m);
    const issuer = dumpEnvTemplate('issuer');
    expect(issuer).toMatch(/^# AWS_COGNITO_TOKEN_USE=id \| access$/m);
  });

  it('marks the file as auto-generated to discourage hand-editing', () => {
    for (const service of EUNO_SERVICE_NAMES) {
      expect(dumpEnvTemplate(service)).toMatch(/AUTO-GENERATED/);
    }
  });
});

// ── MinterConfigSchema ────────────────────────────────────────────────────────

describe('loadConfig (minter) — defaults and type coercion', () => {
  it('accepts an empty env and applies all declared defaults in development', () => {
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_PORT).toBe(3004);
    expect(result.config.MINTER_TOKEN_TTL_SECONDS).toBe(300);
    expect(result.config.MINTER_RATE_LIMIT_MAX).toBe(100);
    expect(result.config.MINTER_RATE_LIMIT_WINDOW_SECONDS).toBe(60);
    expect(result.config.MINTER_AUDIT_SCHEMA_INIT).toBe(false);
    expect(result.config.MINTER_API_KEY_SCHEMA_INIT).toBe(false);
    expect(result.config.NODE_ENV).toBe('development');
  });

  it('coerces MINTER_PORT to a number', () => {
    const result = loadConfig({ MINTER_PORT: '4567' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_PORT).toBe(4567);
  });

  it('rejects a non-numeric MINTER_PORT', () => {
    const result = loadConfig({ MINTER_PORT: 'not-a-port' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PORT')).toBe(true);
  });

  it('coerces MINTER_TOKEN_TTL_SECONDS to a number', () => {
    const result = loadConfig({ MINTER_TOKEN_TTL_SECONDS: '600' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_TOKEN_TTL_SECONDS).toBe(600);
  });

  it('coerces MINTER_AUDIT_SCHEMA_INIT to a boolean', () => {
    const result = loadConfig({ MINTER_AUDIT_SCHEMA_INIT: 'true' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_AUDIT_SCHEMA_INIT).toBe(true);
  });

  it('coerces MINTER_KMS_PROVIDER to the allowed enum value', () => {
    const result = loadConfig({ MINTER_KMS_PROVIDER: 'aws-kms' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_KMS_PROVIDER).toBe('aws-kms');
  });

  it('rejects an invalid MINTER_KMS_PROVIDER value', () => {
    const result = loadConfig({ MINTER_KMS_PROVIDER: 'bad-kms' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_KMS_PROVIDER')).toBe(true);
  });

  it('treats empty-string env vars as unset (applies defaults)', () => {
    const result = loadConfig({ MINTER_PORT: '', MINTER_TOKEN_TTL_SECONDS: '' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_PORT).toBe(3004);
    expect(result.config.MINTER_TOKEN_TTL_SECONDS).toBe(300);
  });

  it('accepts MINTER_ADMIN_JWT_ISSUER as an optional string', () => {
    const result = loadConfig({ MINTER_ADMIN_JWT_ISSUER: 'https://idp.example.com' }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_ADMIN_JWT_ISSUER).toBe('https://idp.example.com');
  });

  it('accepts a valid 64-hex-char MINTER_PEPPER_HEX', () => {
    const result = loadConfig({ MINTER_PEPPER_HEX: 'a'.repeat(64) }, 'minter');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.MINTER_PEPPER_HEX).toBe('a'.repeat(64));
  });

  it('rejects a MINTER_PEPPER_HEX that is not 64 hex chars', () => {
    const result = loadConfig({ MINTER_PEPPER_HEX: 'not-hex-and-too-short' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PEPPER_HEX')).toBe(true);
  });

  it('rejects a MINTER_PEPPER_HEX that is 64 chars but contains non-hex characters', () => {
    const result = loadConfig({ MINTER_PEPPER_HEX: 'g'.repeat(64) }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PEPPER_HEX')).toBe(true);
  });

  it('accepts MINTER_PEPPER_HEX with uppercase hex digits', () => {
    const result = loadConfig({ MINTER_PEPPER_HEX: 'A'.repeat(64) }, 'minter');
    expect(result.ok).toBe(true);
  });
});

describe('loadConfig (minter) — production validation', () => {
  it('accepts a valid production configuration', () => {
    const result = loadConfig(MINTER_PROD_ENV, 'minter');
    expect(result.ok).toBe(true);
  });

  it('accepts production with MINTER_KMS_PROVIDER instead of PEM keys', () => {
    const { MINTER_PRIVATE_KEY_PEM: _priv, MINTER_PUBLIC_KEY_PEM: _pub, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig({ ...rest, MINTER_KMS_PROVIDER: 'aws-kms' }, 'minter');
    expect(result.ok).toBe(true);
  });

  it('rejects production when MINTER_ADMIN_API_KEY is absent', () => {
    const { MINTER_ADMIN_API_KEY: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_ADMIN_API_KEY')).toBe(true);
  });

  it('rejects production when MINTER_ADMIN_API_KEY equals the insecure default', () => {
    const result = loadConfig({ ...MINTER_PROD_ENV, MINTER_ADMIN_API_KEY: 'dev-admin-key' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_ADMIN_API_KEY')).toBe(true);
  });

  it('rejects production when MINTER_ADMIN_API_KEY is shorter than 32 chars', () => {
    const result = loadConfig({ ...MINTER_PROD_ENV, MINTER_ADMIN_API_KEY: 'short' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_ADMIN_API_KEY')).toBe(true);
  });

  it('accepts production when MINTER_ADMIN_API_KEY is exactly 32 characters', () => {
    const result = loadConfig({ ...MINTER_PROD_ENV, MINTER_ADMIN_API_KEY: 'x'.repeat(32) }, 'minter');
    expect(result.ok).toBe(true);
  });

  it('rejects production when MINTER_PEPPER_HEX is absent', () => {
    const { MINTER_PEPPER_HEX: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PEPPER_HEX')).toBe(true);
  });

  it('rejects production when no signing key is configured', () => {
    const { MINTER_PRIVATE_KEY_PEM: _priv, MINTER_PUBLIC_KEY_PEM: _pub, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_KMS_PROVIDER')).toBe(true);
  });

  it('rejects production when only MINTER_PRIVATE_KEY_PEM is set (missing public)', () => {
    const { MINTER_PUBLIC_KEY_PEM: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PUBLIC_KEY_PEM')).toBe(true);
  });

  it('rejects production when only MINTER_PUBLIC_KEY_PEM is set (missing private)', () => {
    const { MINTER_PRIVATE_KEY_PEM: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_PRIVATE_KEY_PEM')).toBe(true);
  });

  it('rejects production when MINTER_AUDIT_DB_URL is absent', () => {
    const { MINTER_AUDIT_DB_URL: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_AUDIT_DB_URL')).toBe(true);
  });

  it('rejects production when MINTER_API_KEY_DB_URL is absent', () => {
    const { MINTER_API_KEY_DB_URL: _, ...rest } = MINTER_PROD_ENV;
    const result = loadConfig(rest, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.some((e) => e.field === 'MINTER_API_KEY_DB_URL')).toBe(true);
  });

  it('reports all violations in a single result when multiple production configs are missing', () => {
    const result = loadConfig({ NODE_ENV: 'production' }, 'minter');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const fields = result.errors.map((e) => e.field);
    expect(fields).toContain('MINTER_ADMIN_API_KEY');
    expect(fields).toContain('MINTER_PEPPER_HEX');
    expect(fields).toContain('MINTER_AUDIT_DB_URL');
    expect(fields).toContain('MINTER_API_KEY_DB_URL');
  });

  it('does not apply production validation when NODE_ENV=development', () => {
    // In development, missing MINTER_ADMIN_API_KEY is fine (uses insecure default).
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
  });
});

describe('dumpEnvTemplate (minter)', () => {
  it('includes MINTER_PORT and MINTER_ADMIN_API_KEY in the template', () => {
    const template = dumpEnvTemplate('minter');
    expect(template).toMatch(/MINTER_PORT=/);
    expect(template).toMatch(/MINTER_ADMIN_API_KEY=/);
  });

  it('includes Redis URL hints', () => {
    const template = dumpEnvTemplate('minter');
    expect(template).toMatch(/REDIS_URL/);
    expect(template).toMatch(/ANOMALY_REDIS_URL/);
  });

  it('is included in EUNO_SERVICE_NAMES', () => {
    expect(EUNO_SERVICE_NAMES).toContain('minter');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// New schema fields — Tasks 11 / 13 / 17
// ─────────────────────────────────────────────────────────────────────────────

describe('MinterConfigSchema — Task 11 (MINTER_MINT_REDIS_URL)', () => {
  it('accepts a valid Redis URL for MINTER_MINT_REDIS_URL', () => {
    const result = loadConfig(
      { MINTER_MINT_REDIS_URL: 'redis://mint-redis:6379' },
      'minter',
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_MINT_REDIS_URL).toBe(
        'redis://mint-redis:6379',
      );
    }
  });

  it('leaves MINTER_MINT_REDIS_URL undefined when not set', () => {
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_MINT_REDIS_URL).toBeUndefined();
    }
  });
});

describe('MinterConfigSchema — Task 17 (Postgres pool config)', () => {
  it('defaults MINTER_AUDIT_POOL_SIZE to 5', () => {
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_AUDIT_POOL_SIZE).toBe(5);
    }
  });

  it('defaults MINTER_API_KEY_POOL_SIZE to 5', () => {
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_API_KEY_POOL_SIZE).toBe(5);
    }
  });

  it('defaults MINTER_PG_CONNECTION_TIMEOUT_MS to 5000', () => {
    const result = loadConfig({}, 'minter');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_PG_CONNECTION_TIMEOUT_MS).toBe(5000);
    }
  });

  it('accepts custom pool sizes', () => {
    const result = loadConfig(
      { MINTER_AUDIT_POOL_SIZE: '10', MINTER_API_KEY_POOL_SIZE: '20' },
      'minter',
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).MINTER_AUDIT_POOL_SIZE).toBe(10);
      expect((result.config as Record<string, unknown>).MINTER_API_KEY_POOL_SIZE).toBe(20);
    }
  });
});

describe('GatewayConfigSchema — Task 13 (HOSTED_MODE audience enforcement)', () => {
  it('HOSTED_MODE defaults to false when not set', () => {
    const result = loadConfig({}, 'gateway');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.config as Record<string, unknown>).HOSTED_MODE).toBe(false);
    }
  });

  it('accepts HOSTED_MODE=true with a unique non-default GATEWAY_AUDIENCE', () => {
    const result = loadConfig(
      { HOSTED_MODE: 'true', GATEWAY_AUDIENCE: 'tool-gateway:acme-corp' },
      'gateway',
    );
    expect(result.ok).toBe(true);
  });

  it('rejects HOSTED_MODE=true when GATEWAY_AUDIENCE is the default "tool-gateway"', () => {
    const result = loadConfig(
      { HOSTED_MODE: 'true', GATEWAY_AUDIENCE: 'tool-gateway' },
      'gateway',
    );
    expect(result.ok).toBe(false);
  });

  it('rejects HOSTED_MODE=true when GATEWAY_AUDIENCE is absent (falls back to default)', () => {
    const result = loadConfig({ HOSTED_MODE: 'true' }, 'gateway');
    expect(result.ok).toBe(false);
  });

  it('HOSTED_MODE=false with default GATEWAY_AUDIENCE passes (no constraint)', () => {
    const result = loadConfig({ HOSTED_MODE: 'false' }, 'gateway');
    expect(result.ok).toBe(true);
  });

  it('rejects HOSTED_MODE=true when GATEWAY_AUDIENCE has leading/trailing whitespace around "tool-gateway"', () => {
    // A padded default audience must not bypass the security guard.
    const result = loadConfig(
      { HOSTED_MODE: 'true', GATEWAY_AUDIENCE: '  tool-gateway  ' },
      'gateway',
    );
    expect(result.ok).toBe(false);
  });

  it('accepts HOSTED_MODE=true when GATEWAY_AUDIENCE has whitespace but is tenant-scoped', () => {
    // Whitespace-padded but non-default tenant-scoped value should be accepted.
    const result = loadConfig(
      { HOSTED_MODE: 'true', GATEWAY_AUDIENCE: '  tool-gateway:acme-corp  ' },
      'gateway',
    );
    expect(result.ok).toBe(true);
  });
});

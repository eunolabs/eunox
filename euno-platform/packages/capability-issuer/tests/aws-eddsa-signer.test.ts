/**
 * Unit tests for AwsEdDsaSigner and createAwsEdDsaSignerFromEnv
 */

import * as jose from 'jose';
import { AwsEdDsaSigner, AwsEdDsaSignerConfig, createAwsEdDsaSignerFromEnv } from '../src/aws-eddsa-signer';

// ── Fixtures ──────────────────────────────────────────────────────────────────

/**
 * A freshly-generated Ed25519 key pair used across tests.
 * The private key is in PKCS#8 PEM format (the format Secrets Manager would return).
 */
let testPrivateKeyPem: string;
let testPublicKey: jose.KeyLike;

beforeAll(async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA', {
    crv: 'Ed25519',
  });
  testPrivateKeyPem = await jose.exportPKCS8(privateKey);
  testPublicKey = publicKey;
});

// ── AwsEdDsaSigner constructor ────────────────────────────────────────────────

describe('AwsEdDsaSigner constructor', () => {
  it('throws when neither keyArn nor keyPem is provided', () => {
    expect(
      () =>
        new AwsEdDsaSigner({
          type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
        } as AwsEdDsaSignerConfig),
    ).toThrow('either keyArn');
  });

  it('constructs successfully with keyPem', () => {
    expect(
      () =>
        new AwsEdDsaSigner({
          type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
          keyPem: '-----BEGIN PRIVATE KEY-----\nMC4CAQA=\n-----END PRIVATE KEY-----',
        }),
    ).not.toThrow();
  });

  it('constructs successfully with keyArn', () => {
    expect(
      () =>
        new AwsEdDsaSigner({
          type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
          keyArn: 'arn:aws:secretsmanager:us-east-1:123:secret:euno/eddsa',
        }),
    ).not.toThrow();
  });
});

// ── AwsEdDsaSigner with inline keyPem ─────────────────────────────────────────

describe('AwsEdDsaSigner with inline keyPem', () => {
  it('signs a payload and produces a verifiable EdDSA JWT', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
      keyPem: testPrivateKeyPem,
      keyId: 'test-kid',
    });

    const payload = {
      sub: 'user:123',
      iss: 'https://issuer.example.com',
      aud: 'https://gateway.example.com',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: 'test-jti-1',
      schemaVersion: '1.0',
      capabilities: [],
      scope: 'read:data',
    };

    const token = await signer.sign(payload);
    expect(typeof token).toBe('string');

    // Verify the token with the matching public key
    const { payload: verified, protectedHeader } = await jose.jwtVerify(token, testPublicKey, {
      issuer: 'https://issuer.example.com',
      audience: 'https://gateway.example.com',
    });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(protectedHeader.kid).toBe('test-kid');
    expect(verified['sub']).toBe('user:123');
    expect(verified['scope']).toBe('read:data');
  });

  it('uses default keyId "aws-eddsa-shim" when no keyId is configured', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
      keyPem: testPrivateKeyPem,
    });

    const payload = {
      sub: 'user:456',
      iss: 'https://issuer.example.com',
      aud: 'https://gw.example.com',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: 'test-jti-2',
      schemaVersion: '1.0',
      capabilities: [],
    };

    const token = await signer.sign(payload);
    const { protectedHeader } = await jose.jwtVerify(token, testPublicKey, {
      issuer: 'https://issuer.example.com',
      audience: 'https://gw.example.com',
    });
    expect(protectedHeader.kid).toBe('aws-eddsa-shim');
  });

  it('caches the loaded key (initialize called only once)', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
      keyPem: testPrivateKeyPem,
    });

    const importSpy = jest.spyOn(jose, 'importPKCS8');

    const payload = {
      sub: 'u',
      iss: 'i',
      aud: 'a',
      iat: 0,
      exp: 9999999999,
      jti: 'jti-cache',
      schemaVersion: '1.0',
      capabilities: [],
    };

    await signer.sign(payload);
    await signer.sign(payload);

    expect(importSpy).toHaveBeenCalledTimes(1);
    importSpy.mockRestore();
  });

  it('getKeyId() returns the configured keyId before and after initialize', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      name: 'aws-eddsa-shim',
      keyPem: testPrivateKeyPem,
      keyId: 'my-partner-key',
    });

    // Before initialize
    expect(await signer.getKeyId()).toBe('my-partner-key');

    await signer.initialize();
    expect(await signer.getKeyId()).toBe('my-partner-key');
  });
});

// ── AwsEdDsaSigner with Secrets Manager ARN ───────────────────────────────────

describe('AwsEdDsaSigner with keyArn', () => {
  const TEST_ARN = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/partner-eddsa';

  /**
   * Helper to inject a mock `fetchKeyFromSecretsManager` implementation,
   * avoiding reliance on jest.mock() inline (which Jest hoists to file scope).
   */
  function injectFetchKeyMock(signer: AwsEdDsaSigner, pem: string): void {
    const signerAny = signer as unknown as Record<string, (arn: string) => Promise<string>>;
    signerAny['fetchKeyFromSecretsManager'] = async (_arn: string) => pem;
  }

  it('fetches the key from Secrets Manager and signs successfully', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      keyArn: TEST_ARN,
      keyId: 'partner-key-1',
    });
    injectFetchKeyMock(signer, testPrivateKeyPem);

    const payload = {
      sub: 'partner:abc',
      iss: 'https://partner.example.com',
      aud: 'https://gateway.example.com',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: 'jti-partner',
      schemaVersion: '1.0',
      capabilities: [],
    };

    const token = await signer.sign(payload);
    const { protectedHeader } = await jose.jwtVerify(token, testPublicKey, {
      issuer: 'https://partner.example.com',
      audience: 'https://gateway.example.com',
    });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(protectedHeader.kid).toBe('partner-key-1');
  });

  it('uses the ARN as the default keyId when no keyId is configured', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      keyArn: TEST_ARN,
    });
    injectFetchKeyMock(signer, testPrivateKeyPem);

    const payload = {
      sub: 'u',
      iss: 'i',
      aud: 'a',
      iat: 0,
      exp: 9999999999,
      jti: 'jti-default-kid',
      schemaVersion: '1.0',
      capabilities: [],
    };

    const token = await signer.sign(payload);
    const { protectedHeader } = await jose.jwtVerify(token, testPublicKey, {
      issuer: 'i',
      audience: 'a',
    });
    expect(protectedHeader.kid).toBe(TEST_ARN);
  });

  it('throws when Secrets Manager returns no SecretString', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      keyArn: TEST_ARN,
    });
    // Override fetchKeyFromSecretsManager to simulate empty response
    const signerAny = signer as unknown as Record<string, (arn: string) => Promise<string>>;
    signerAny['fetchKeyFromSecretsManager'] = async (_arn: string) => {
      throw new Error(
        `AwsEdDsaSigner: Secrets Manager secret '${_arn}' does not contain a SecretString.`,
      );
    };

    await expect(
      signer.sign({
        sub: 'u',
        iss: 'i',
        aud: 'a',
        iat: 0,
        exp: 9999999999,
        jti: 'jti-test',
        schemaVersion: '1.0',
        capabilities: [],
      }),
    ).rejects.toThrow('does not contain a SecretString');
  });

  it('throws a clear error when @aws-sdk/client-secrets-manager is not installed', async () => {
    const signer = new AwsEdDsaSigner({
      type: 'aws-eddsa-shim',
      keyArn: TEST_ARN,
    });

    // Override private method to simulate missing SDK
    const signerAny = signer as unknown as Record<string, (arn: string) => Promise<string>>;
    signerAny['fetchKeyFromSecretsManager'] = async (_arn: string) => {
      throw new Error('@aws-sdk/client-secrets-manager package is not installed');
    };

    await expect(
      signer.sign({
        sub: 'u',
        iss: 'i',
        aud: 'a',
        iat: 0,
        exp: 9999999999,
        jti: 'jti-test',
        schemaVersion: '1.0',
        capabilities: [],
      }),
    ).rejects.toThrow('@aws-sdk/client-secrets-manager package is not installed');
  });
});

// ── createAwsEdDsaSignerFromEnv ───────────────────────────────────────────────

describe('createAwsEdDsaSignerFromEnv', () => {
  it('returns undefined when AWS_EDDSA_KEY_ARN is not set', () => {
    expect(createAwsEdDsaSignerFromEnv({})).toBeUndefined();
  });

  it('returns an AwsEdDsaSigner when AWS_EDDSA_KEY_ARN is set', () => {
    const signer = createAwsEdDsaSignerFromEnv({
      AWS_EDDSA_KEY_ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:euno/eddsa',
    });
    expect(signer).toBeInstanceOf(AwsEdDsaSigner);
  });

  it('uses AWS_EDDSA_KEY_ID as the keyId when provided', () => {
    const signer = createAwsEdDsaSignerFromEnv({
      AWS_EDDSA_KEY_ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:euno/eddsa',
      AWS_EDDSA_KEY_ID: 'my-partner-signing-key',
    })!;
    const cfg = (signer as unknown as Record<string, unknown>)['eddsaConfig'] as AwsEdDsaSignerConfig;
    expect(cfg.keyId).toBe('my-partner-signing-key');
  });

  it('passes AWS_REGION as secretsRegion', () => {
    const signer = createAwsEdDsaSignerFromEnv({
      AWS_EDDSA_KEY_ARN: 'arn:aws:secretsmanager:us-west-2:123:secret:euno/eddsa',
      AWS_REGION: 'us-west-2',
    })!;
    const cfg = (signer as unknown as Record<string, unknown>)['eddsaConfig'] as AwsEdDsaSignerConfig;
    expect(cfg.secretsRegion).toBe('us-west-2');
  });

  it('passes explicit credentials when provided', () => {
    const signer = createAwsEdDsaSignerFromEnv({
      AWS_EDDSA_KEY_ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:euno/eddsa',
      AWS_ACCESS_KEY_ID: 'AKIDTEST',
      AWS_SECRET_ACCESS_KEY: 'SECRETTEST',
      AWS_SESSION_TOKEN: 'TOKENTEST',
    })!;
    const cfg = (signer as unknown as Record<string, unknown>)['eddsaConfig'] as AwsEdDsaSignerConfig;
    expect(cfg.accessKeyId).toBe('AKIDTEST');
    expect(cfg.secretAccessKey).toBe('SECRETTEST');
    expect(cfg.sessionToken).toBe('TOKENTEST');
  });
});

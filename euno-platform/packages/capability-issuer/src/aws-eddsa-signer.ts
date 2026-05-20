/**
 * AWS EdDSA Signer Shim — AWS Phase 2
 * ────────────────────────────────────────────────────────────────────────────
 * AWS KMS does not natively support Ed25519 (EdDSA) keys.  This shim fills
 * the gap for partner-DID (`did:ion`) use cases where EdDSA-signed capability
 * tokens are required in an AWS deployment.
 *
 * ## How it works
 *
 * 1. The Ed25519 private key is stored as a PEM-encoded secret in AWS Secrets
 *    Manager (or supplied inline for development / testing).
 * 2. On the first `sign()` call the shim fetches and caches the key from
 *    Secrets Manager (if a `keyArn` is configured) or imports the `keyPem`
 *    directly.
 * 3. Signing is performed locally using `jose.SignJWT` — the resulting JWT
 *    is byte-identical to what a native Ed25519 KMS key would produce (if AWS
 *    KMS supported one).
 *
 * ## Security note
 *
 * The private key is held in process memory after the first `sign()` call.
 * Operators MUST ensure the pod identity (IRSA role) has the minimum IAM
 * policy necessary to call `secretsmanager:GetSecretValue` on the specific
 * secret ARN, and that the pod runs with appropriate security context
 * constraints (read-only root file system, no privilege escalation).
 *
 * ## Environment variables (when using `createAwsEdDsaSignerFromEnv`)
 *
 * | Variable                          | Description                                      |
 * |-----------------------------------|--------------------------------------------------|
 * | `AWS_EDDSA_KEY_ARN`               | Secrets Manager ARN holding the PEM private key  |
 * | `AWS_EDDSA_KEY_ID`                | JWT `kid` claim (defaults to key ARN)            |
 * | `AWS_REGION`                      | AWS region for Secrets Manager calls             |
 * | `AWS_ACCESS_KEY_ID`               | Optional explicit credentials                    |
 * | `AWS_SECRET_ACCESS_KEY`           | Optional explicit credentials                    |
 * | `AWS_SESSION_TOKEN`               | Optional STS session token                       |
 */

import * as jose from 'jose';
import { SigningAdapter, SigningAdapterConfig, CapabilityTokenPayload, IssuanceContext } from '@euno/common';

// ── AwsEdDsaSignerConfig ──────────────────────────────────────────────────────

/**
 * Configuration for {@link AwsEdDsaSigner}.
 */
export interface AwsEdDsaSignerConfig extends SigningAdapterConfig {
  type: 'aws-eddsa-shim';
  /**
   * AWS Secrets Manager ARN (or secret name) containing the PEM-encoded
   * Ed25519 private key.  Exactly one of `keyArn` or `keyPem` MUST be
   * provided.
   *
   * Example:
   *   `arn:aws:secretsmanager:us-east-1:123456789012:secret:euno/eddsa-key`
   */
  keyArn?: string;
  /**
   * PEM-encoded Ed25519 private key (for development/testing or when the key
   * is injected via a Kubernetes Secret rather than Secrets Manager).
   * Exactly one of `keyArn` or `keyPem` MUST be provided.
   */
  keyPem?: string;
  /**
   * JWT `kid` (Key ID) claim to embed in signed tokens.
   * Defaults to the Secrets Manager ARN when `keyArn` is provided, or to
   * `'aws-eddsa-shim'` when only `keyPem` is used.
   */
  keyId?: string;
  /** AWS region for Secrets Manager calls (defaults to `AWS_REGION`). */
  secretsRegion?: string;
  /** Optional explicit AWS access key ID (overrides credential chain). */
  accessKeyId?: string;
  /** Optional explicit AWS secret access key (overrides credential chain). */
  secretAccessKey?: string;
  /** Optional STS session token (for temporary credentials). */
  sessionToken?: string;
}

// ── AwsEdDsaSigner ────────────────────────────────────────────────────────────

/**
 * EdDSA (Ed25519) signing adapter for AWS deployments.
 *
 * Implements {@link SigningAdapter} using a locally-held Ed25519 private key.
 * The key is sourced from AWS Secrets Manager at runtime so it never appears
 * in environment variables or Helm values files.
 *
 * This is a "shim" rather than a KMS-native signer because AWS KMS does not
 * support Ed25519.  The shim uses IRSA / IAM credentials to authenticate to
 * Secrets Manager, preserving the AWS IAM trust boundary while adding EdDSA
 * capability.
 */
export class AwsEdDsaSigner extends SigningAdapter {
  private readonly eddsaConfig: AwsEdDsaSignerConfig;
  private privateKey?: jose.KeyLike | Uint8Array;
  private resolvedKeyId?: string;

  constructor(config: Omit<AwsEdDsaSignerConfig, 'name'> & { name?: string }) {
    super({ name: 'aws-eddsa-shim', ...config } as AwsEdDsaSignerConfig);
    if (!config.keyArn && !config.keyPem) {
      throw new Error(
        'AwsEdDsaSigner: either keyArn (Secrets Manager ARN) or keyPem (PEM string) ' +
          'must be provided.',
      );
    }
    this.eddsaConfig = { name: 'aws-eddsa-shim', ...config } as AwsEdDsaSignerConfig;
  }

  /**
   * Lazily initialise: fetch the private key from Secrets Manager (if
   * `keyArn` is set) or import the inline PEM.
   */
  async initialize(): Promise<void> {
    if (this.privateKey) return;

    let pem: string;

    if (this.eddsaConfig.keyArn) {
      pem = await this.fetchKeyFromSecretsManager(this.eddsaConfig.keyArn);
      this.resolvedKeyId = this.eddsaConfig.keyId ?? this.eddsaConfig.keyArn;
    } else if (this.eddsaConfig.keyPem) {
      pem = this.eddsaConfig.keyPem;
      this.resolvedKeyId = this.eddsaConfig.keyId ?? 'aws-eddsa-shim';
    } else {
      throw new Error('AwsEdDsaSigner: no key source configured.');
    }

    this.privateKey = await jose.importPKCS8(pem, 'EdDSA');
    // Override the algorithm; EdDSA is always the algorithm for Ed25519 keys.
    this.algorithm = 'EdDSA';
  }

  /**
   * Fetch a PEM-encoded private key from AWS Secrets Manager.
   * Uses the same lazy-require pattern as the rest of the codebase so that
   * `@aws-sdk/client-secrets-manager` is not a hard dependency.
   */
  private async fetchKeyFromSecretsManager(arn: string): Promise<string> {
    let sdk: {
      SecretsManagerClient: new (opts: Record<string, unknown>) => unknown;
      GetSecretValueCommand: new (input: Record<string, unknown>) => unknown;
    };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@aws-sdk/client-secrets-manager');
    } catch {
      throw new Error(
        'AwsEdDsaSigner: the "@aws-sdk/client-secrets-manager" package is not installed. ' +
          'Add it to your deployment image: npm install @aws-sdk/client-secrets-manager',
      );
    }

    const opts: Record<string, unknown> = {};
    if (this.eddsaConfig.secretsRegion) opts['region'] = this.eddsaConfig.secretsRegion;
    if (this.eddsaConfig.accessKeyId && this.eddsaConfig.secretAccessKey) {
      const creds: Record<string, string> = {
        accessKeyId: this.eddsaConfig.accessKeyId,
        secretAccessKey: this.eddsaConfig.secretAccessKey,
      };
      if (this.eddsaConfig.sessionToken) {
        creds['sessionToken'] = this.eddsaConfig.sessionToken;
      }
      opts['credentials'] = creds;
    }

    const client = new sdk.SecretsManagerClient(opts);
    const command = new sdk.GetSecretValueCommand({ SecretId: arn });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const response: any = await (client as any).send(command);
    const secretString: string | undefined = response?.SecretString;
    if (!secretString) {
      throw new Error(
        `AwsEdDsaSigner: Secrets Manager secret '${arn}' does not contain a SecretString. ` +
          'Ensure the secret value is a PEM-encoded Ed25519 private key (PKCS#8 format).',
      );
    }
    return secretString;
  }

  /**
   * Sign a capability token payload using the Ed25519 private key.
   */
  async sign(payload: CapabilityTokenPayload, _context?: IssuanceContext): Promise<string> {
    await this.initialize();

    if (!this.privateKey) {
      throw new Error('AwsEdDsaSigner: private key not loaded.');
    }

    // Use jose.SignJWT with the full payload passed as-is so that all
    // CapabilityTokenPayload fields (jti, schemaVersion, capabilities, …)
    // are preserved in the signed token.  The standard claims (iss, sub, aud,
    // iat, exp, jti) are set via the jose builder helpers; the rest are
    // spread into the constructor as additional payload fields.
    const { sub, iss, aud, exp, iat, jti, ...additionalClaims } = payload;

    const builder = new jose.SignJWT({ ...additionalClaims })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'JWT',
        kid: this.resolvedKeyId,
      })
      .setIssuedAt(iat)
      .setExpirationTime(exp);

    if (sub) builder.setSubject(sub);
    if (iss) builder.setIssuer(iss);
    if (aud) builder.setAudience(aud);
    if (jti) builder.setJti(jti);

    return builder.sign(this.privateKey);
  }

  /** Return the resolved key ID (available after `initialize()`). */
  async getKeyId(): Promise<string> {
    return this.resolvedKeyId ?? this.eddsaConfig.keyId ?? 'aws-eddsa-shim';
  }

  /**
   * Return the public key PEM (not available for the EdDSA shim since only
   * the private key is stored in Secrets Manager).
   *
   * Operators can retrieve the public key from their key-generation process
   * or from the issuer's DID document.
   */
  async getPublicKey(): Promise<string> {
    throw new Error(
      'AwsEdDsaSigner: getPublicKey() is not supported. ' +
        'Retrieve the public key from your key-generation process or from the ' +
        "partner issuer's DID document.",
    );
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create an {@link AwsEdDsaSigner} from environment variables.
 *
 * Returns `undefined` when `AWS_EDDSA_KEY_ARN` is not set (allows callers to
 * skip EdDSA shim setup when it is not configured).
 *
 * @param env - Environment variable map.  Defaults to `process.env`.
 */
export function createAwsEdDsaSignerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AwsEdDsaSigner | undefined {
  const keyArn = env['AWS_EDDSA_KEY_ARN'];
  if (!keyArn) return undefined;

  return new AwsEdDsaSigner({
    type: 'aws-eddsa-shim',
    keyArn,
    keyId: env['AWS_EDDSA_KEY_ID'],
    secretsRegion: env['AWS_REGION'],
    accessKeyId: env['AWS_ACCESS_KEY_ID'],
    secretAccessKey: env['AWS_SECRET_ACCESS_KEY'],
    sessionToken: env['AWS_SESSION_TOKEN'],
  });
}

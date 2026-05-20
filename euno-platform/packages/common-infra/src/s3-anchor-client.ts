/**
 * S3 anchor client factory — AWS Phase 2
 * ────────────────────────────────────────────────────────────────────────────
 * Provides a concrete {@link S3AnchorClient} implementation backed by the
 * AWS SDK v3 `@aws-sdk/client-s3`, along with a factory that reads
 * configuration from environment variables.
 *
 * ## Environment variables
 *
 * | Variable                        | Description                                        |
 * |---------------------------------|----------------------------------------------------|
 * | `AWS_REGION`                    | AWS region (required for standard endpoints)       |
 * | `AUDIT_LEDGER_S3_ENDPOINT`      | Optional custom endpoint for VPC/PrivateLink       |
 * | `AUDIT_LEDGER_S3_FORCE_PATH_STYLE` | When `true`, use path-style URLs               |
 * | `AWS_ACCESS_KEY_ID`             | Optional explicit credentials (override chain)     |
 * | `AWS_SECRET_ACCESS_KEY`         | Optional explicit credentials (override chain)     |
 * | `AWS_SESSION_TOKEN`             | Optional STS session token                         |
 *
 * ## GovCloud and FIPS endpoints
 *
 * The AWS SDK resolves GovCloud (`us-gov-west-1` / `us-gov-east-1`) endpoints
 * automatically from the region.  FIPS endpoint selection is handled by the
 * SDK's `useFIPSEndpoint` option (not yet exposed here — set via the standard
 * `AWS_USE_FIPS_ENDPOINT=true` environment variable, which the SDK honours
 * automatically).  The `AUDIT_LEDGER_S3_ENDPOINT` override is only needed
 * for VPC Interface Endpoints, MinIO-compatible local testing, or custom
 * S3-compatible storage.
 *
 * ## Dynamic SDK loading
 *
 * The `@aws-sdk/client-s3` package is **not** a hard dependency of
 * `@euno/common-infra`.  It is lazily `require()`d on the first
 * {@link AwsSdkS3AnchorClient.putObject} call so that deployments which do
 * not use S3 anchoring do not need the SDK installed.  A clear `Error` is
 * thrown if the SDK is absent when the first PUT is attempted.
 */

import { S3AnchorClient } from './ledger-signer';

// ── AwsSdkS3AnchorClient ──────────────────────────────────────────────────────

/**
 * Configuration for {@link AwsSdkS3AnchorClient}.
 */
export interface AwsSdkS3AnchorClientConfig {
  /** AWS region (e.g. `us-east-1`, `us-gov-west-1`). */
  region?: string;
  /**
   * Optional custom S3 endpoint URL.
   *
   * Use this for VPC Interface Endpoints / PrivateLink, MinIO-compatible
   * local testing, or any other S3-compatible storage.
   *
   * Example: `https://bucket.vpce-0a1b2c3d4e5f.s3.us-east-1.vpce.amazonaws.com`
   */
  endpoint?: string;
  /**
   * When `true`, use path-style S3 URL addressing.
   *
   * Required for some VPC endpoint configurations and for MinIO/LocalStack
   * local testing where virtual-hosted-style URLs are not supported.
   *
   * Defaults to `false` (virtual-hosted-style).
   */
  forcePathStyle?: boolean;
  /** Optional explicit AWS access key ID (overrides the credential chain). */
  accessKeyId?: string;
  /** Optional explicit AWS secret access key (overrides the credential chain). */
  secretAccessKey?: string;
  /** Optional STS session token (for temporary credentials). */
  sessionToken?: string;
}

/**
 * Concrete {@link S3AnchorClient} backed by the AWS SDK v3 S3 client.
 *
 * Issues `PutObject` requests with `ObjectLockMode: 'COMPLIANCE'` so the
 * written object is immutable for the bucket's default retention period —
 * this is what makes the cross-chain anchor tamper-evident.
 *
 * The `@aws-sdk/client-s3` package is loaded lazily on the first call to
 * {@link putObject}.
 */
export class AwsSdkS3AnchorClient implements S3AnchorClient {
  private readonly config: AwsSdkS3AnchorClientConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private s3Client?: any;

  constructor(config: AwsSdkS3AnchorClientConfig = {}) {
    this.config = config;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private buildClient(): any {
    let sdk: {
      S3Client: new (opts: Record<string, unknown>) => unknown;
    };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@aws-sdk/client-s3');
    } catch {
      throw new Error(
        'AwsSdkS3AnchorClient: the "@aws-sdk/client-s3" package is not installed. ' +
          'Add it to your deployment image: npm install @aws-sdk/client-s3',
      );
    }

    const opts: Record<string, unknown> = {};
    if (this.config.region) opts['region'] = this.config.region;
    if (this.config.endpoint) opts['endpoint'] = this.config.endpoint;
    if (this.config.forcePathStyle) opts['forcePathStyle'] = true;
    if (this.config.accessKeyId && this.config.secretAccessKey) {
      const creds: Record<string, string> = {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
      };
      if (this.config.sessionToken) {
        creds['sessionToken'] = this.config.sessionToken;
      }
      opts['credentials'] = creds;
    }

    return new sdk.S3Client(opts);
  }

  async putObject(params: {
    bucket: string;
    key: string;
    body: string;
    contentType: string;
  }): Promise<void> {
    if (!this.s3Client) {
      this.s3Client = this.buildClient();
    }

    let sdk: {
      PutObjectCommand: new (input: Record<string, unknown>) => unknown;
    };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      sdk = require('@aws-sdk/client-s3');
    } catch {
      throw new Error(
        'AwsSdkS3AnchorClient: the "@aws-sdk/client-s3" package is not installed.',
      );
    }

    const command = new sdk.PutObjectCommand({
      Bucket: params.bucket,
      Key: params.key,
      Body: params.body,
      ContentType: params.contentType,
      ObjectLockMode: 'COMPLIANCE',
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (this.s3Client as any).send(command);
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create an {@link AwsSdkS3AnchorClient} from environment variables.
 *
 * Reads:
 * - `AWS_REGION`
 * - `AUDIT_LEDGER_S3_ENDPOINT`
 * - `AUDIT_LEDGER_S3_FORCE_PATH_STYLE`
 * - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
 *
 * Returns `undefined` when `AUDIT_LEDGER_S3_BUCKET` is not set (the caller
 * should check for bucket presence before calling this function).
 *
 * @param env - Environment variable map.  Defaults to `process.env`.
 */
export function createS3AnchorClientFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AwsSdkS3AnchorClient {
  return new AwsSdkS3AnchorClient({
    region: env['AWS_REGION'],
    endpoint: env['AUDIT_LEDGER_S3_ENDPOINT'],
    forcePathStyle:
      env['AUDIT_LEDGER_S3_FORCE_PATH_STYLE'] === 'true' ||
      env['AUDIT_LEDGER_S3_FORCE_PATH_STYLE'] === '1',
    accessKeyId: env['AWS_ACCESS_KEY_ID'],
    secretAccessKey: env['AWS_SECRET_ACCESS_KEY'],
    sessionToken: env['AWS_SESSION_TOKEN'],
  });
}

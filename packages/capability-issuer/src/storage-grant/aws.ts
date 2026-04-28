/**
 * AWS S3 storage-grant minter.
 *
 * Two issuance paths per
 * `docs/sprint-3-4-gaps/07-storage-grants.md` § 3 / AWS-specific:
 *
 *  - **Single-object capability** → one presigned URL per permitted
 *    method (`GetObject` / `PutObject` / `DeleteObject`).
 *  - **Wildcard / prefix capability** → STS `AssumeRole` with a
 *    scope-down policy restricting `s3:*` actions to the prefix.
 *
 * SDKs are loaded via dynamic `import()` so an Azure- or GCP-only
 * deployment can omit them. Tests inject a `clientFactory` to bypass
 * the dynamic import entirely.
 */

import { CapabilityError, ErrorCode, StorageGrant } from '@euno/common';
import { ParsedStorageUri } from './types';
import {
  StorageGrantMinter,
  StorageGrantMintInput,
  STORAGE_ACTION_MAP,
} from './types';
import { parseStorageUri } from './parse-uri';

/** Subset of the `@aws-sdk/client-s3` surface we depend on. */
export interface S3ClientLike {
  /** Region the client is configured for. */
  region?: string;
}

/** Subset of the `@aws-sdk/client-sts` surface we depend on. */
export interface StsClientLike {
  send(cmd: { input: Record<string, unknown> }): Promise<{
    Credentials?: {
      AccessKeyId?: string;
      SecretAccessKey?: string;
      SessionToken?: string;
      Expiration?: Date;
    };
  }>;
}

/** Function that produces a single presigned URL for a single command. */
export type S3Presigner = (input: {
  bucket: string;
  key: string;
  method: 'GET' | 'PUT' | 'DELETE';
  expiresIn: number;
}) => Promise<string>;

export interface AwsStorageGrantMinterOptions {
  /** AWS region used for both S3 and STS. Required for prefix grants. */
  region?: string;
  /** ARN of the role assumed for prefix grants. Required for wildcards. */
  assumeRoleArn?: string;
  /** Override the S3 client (mainly for tests). */
  s3ClientFactory?: () => Promise<S3ClientLike> | S3ClientLike;
  /** Override the STS client (mainly for tests). */
  stsClientFactory?: () => Promise<StsClientLike> | StsClientLike;
  /** Override the presigner (mainly for tests). */
  presigner?: S3Presigner;
}

export class AwsStorageGrantMinter implements StorageGrantMinter {
  public readonly provider = 's3' as const;
  private readonly opts: AwsStorageGrantMinterOptions;

  constructor(opts: AwsStorageGrantMinterOptions = {}) {
    this.opts = opts;
  }

  async mint(input: StorageGrantMintInput): Promise<StorageGrant> {
    const parsed = parseStorageUri(input.resource);
    if (!parsed || parsed.cloud !== 's3') {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `AWS storage-grant minter cannot handle resource: ${input.resource}`,
        400,
      );
    }
    const methods = mapActionsToS3Methods(input.actions);
    if (methods.length === 0 && !parsed.isWildcard) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `No S3 methods map to actions: ${input.actions.join(',')}`,
        400,
      );
    }

    const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();

    if (parsed.isWildcard) {
      return this.mintSession(parsed, input, expiresAt);
    }
    return this.mintPresigned(parsed, input, methods);
  }

  private async mintPresigned(
    parsed: ParsedStorageUri,
    input: StorageGrantMintInput,
    methods: ('GET' | 'PUT' | 'DELETE')[],
  ): Promise<StorageGrant> {
    const presigner = this.opts.presigner ?? (await this.loadPresigner());
    const presigned: { method: 'GET' | 'PUT' | 'DELETE'; url: string }[] = [];
    for (const method of methods) {
      const url = await presigner({
        bucket: parsed.bucket,
        key: parsed.keyOrPrefix,
        method,
        expiresIn: input.ttlSeconds,
      });
      presigned.push({ method, url });
    }
    return {
      provider: 's3',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: new Date(Date.now() + input.ttlSeconds * 1000).toISOString(),
      s3Presigned: presigned,
    };
  }

  private async mintSession(
    parsed: ParsedStorageUri,
    input: StorageGrantMintInput,
    expiresAt: string,
  ): Promise<StorageGrant> {
    if (!this.opts.assumeRoleArn) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'AWS storage-grant minter requires `assumeRoleArn` for wildcard / prefix capabilities',
        500,
      );
    }
    if (!this.opts.region) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'AWS storage-grant minter requires `region` for wildcard / prefix capabilities',
        500,
      );
    }
    const sts = this.opts.stsClientFactory
      ? await this.opts.stsClientFactory()
      : await this.loadStsClient();

    // Scope-down policy: limit to the bucket's prefix; deny everything else.
    const prefix = parsed.keyOrPrefix;
    const resourceArn = prefix
      ? `arn:aws:s3:::${parsed.bucket}/${prefix}/*`
      : `arn:aws:s3:::${parsed.bucket}/*`;
    const bucketArn = `arn:aws:s3:::${parsed.bucket}`;
    const policyDoc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'EunoScopedAccess',
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
          Resource: resourceArn,
        },
        {
          Sid: 'EunoListBucket',
          Effect: 'Allow',
          Action: 's3:ListBucket',
          Resource: bucketArn,
          ...(prefix ? { Condition: { StringLike: { 's3:prefix': [`${prefix}/*`] } } } : {}),
        },
      ],
    });

    const cmdInput: Record<string, unknown> = {
      RoleArn: this.opts.assumeRoleArn,
      RoleSessionName: `euno-${input.agentId}-${Date.now()}`,
      DurationSeconds: input.ttlSeconds,
      Policy: policyDoc,
    };
    const result = await sts.send({ input: cmdInput });
    const creds = result.Credentials;
    if (!creds || !creds.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'STS AssumeRole returned no credentials',
        502,
      );
    }
    return {
      provider: 's3',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: creds.Expiration ? creds.Expiration.toISOString() : expiresAt,
      s3Session: {
        accessKeyId: creds.AccessKeyId,
        secretAccessKey: creds.SecretAccessKey,
        sessionToken: creds.SessionToken,
        region: this.opts.region,
        bucket: parsed.bucket,
        ...(prefix ? { prefix } : {}),
      },
    };
  }

  private async loadPresigner(): Promise<S3Presigner> {
    const s3sdk: any = await dynamicImport('@aws-sdk/client-s3');
    const presignSdk: any = await dynamicImport('@aws-sdk/s3-request-presigner');
    const client = this.opts.s3ClientFactory
      ? await this.opts.s3ClientFactory()
      : new s3sdk.S3Client(this.opts.region ? { region: this.opts.region } : {});
    const cmds: Record<'GET' | 'PUT' | 'DELETE', any> = {
      GET: s3sdk.GetObjectCommand,
      PUT: s3sdk.PutObjectCommand,
      DELETE: s3sdk.DeleteObjectCommand,
    };
    return async ({ bucket, key, method, expiresIn }) => {
      const Cmd = cmds[method];
      const cmd = new Cmd({ Bucket: bucket, Key: key });
      return await presignSdk.getSignedUrl(client, cmd, { expiresIn });
    };
  }

  private async loadStsClient(): Promise<StsClientLike> {
    const sdk: any = await dynamicImport('@aws-sdk/client-sts');
    const client = new sdk.STSClient(this.opts.region ? { region: this.opts.region } : {});
    // Wrap so callers don't need the AssumeRoleCommand constructor.
    return {
      send: async ({ input }) => {
        const cmd = new sdk.AssumeRoleCommand(input);
        return await client.send(cmd);
      },
    };
  }
}

function mapActionsToS3Methods(actions: string[]): ('GET' | 'PUT' | 'DELETE')[] {
  const map = STORAGE_ACTION_MAP['s3'];
  const methods: ('GET' | 'PUT' | 'DELETE')[] = [];
  for (const a of actions) {
    const op = map[a];
    if (op === 'GetObject' && !methods.includes('GET')) methods.push('GET');
    if (op === 'PutObject' && !methods.includes('PUT')) methods.push('PUT');
    if (op === 'DeleteObject' && !methods.includes('DELETE')) methods.push('DELETE');
    // ListBucket is collection-level — only meaningful for prefix grants;
    // single-object presigned URLs cannot express it.
  }
  return methods;
}

async function dynamicImport(name: string): Promise<any> {
  try {
    return await import(name);
  } catch {
    throw new CapabilityError(
      ErrorCode.INTERNAL_ERROR,
      `Required SDK '${name}' is not installed; install it or disable storage grants for this provider`,
      500,
    );
  }
}

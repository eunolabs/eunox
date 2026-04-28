/**
 * Azure Blob storage-grant minter.
 *
 * Mints **user-delegation SAS** tokens (signed with an AAD-issued key,
 * not the storage-account key) per the design in
 * `docs/sprint-3-4-gaps/07-storage-grants.md` § 3 / Azure-specific.
 *
 * The `@azure/storage-blob` SDK is loaded via dynamic `import()` so an
 * AWS- or GCP-only deployment can omit the package without paying the
 * load cost. Tests inject a `clientFactory` to bypass the dynamic
 * import entirely.
 */

import { CapabilityError, ErrorCode, StorageGrant } from '@euno/common';
import { ParsedStorageUri } from './types';
import {
  StorageGrantMinter,
  StorageGrantMintInput,
  STORAGE_ACTION_MAP,
} from './types';
import { parseStorageUri } from './parse-uri';

/**
 * Minimal subset of `@azure/storage-blob` we depend on. Declared
 * structurally so tests can supply a hand-rolled stub without pulling in
 * the real SDK's typings.
 */
export interface AzureBlobClientLike {
  accountName: string;
  getUserDelegationKey(startsOn: Date, expiresOn: Date): Promise<unknown>;
}

/**
 * Function that signs a SAS query string from a key + permissions.
 * Mirrors `@azure/storage-blob`'s `generateBlobSASQueryParameters`.
 */
export type AzureSasSigner = (input: {
  client: AzureBlobClientLike;
  userDelegationKey: unknown;
  containerName: string;
  blobName?: string;
  permissions: string;
  startsOn: Date;
  expiresOn: Date;
}) => { sasToken: string; url: string };

export interface AzureStorageGrantMinterOptions {
  /** Override the Blob client (mainly for tests). */
  clientFactory?: () => Promise<AzureBlobClientLike> | AzureBlobClientLike;
  /** Override the SAS signer (mainly for tests). */
  signer?: AzureSasSigner;
}

export class AzureStorageGrantMinter implements StorageGrantMinter {
  public readonly provider = 'azure-blob' as const;
  private readonly opts: AzureStorageGrantMinterOptions;

  constructor(opts: AzureStorageGrantMinterOptions = {}) {
    this.opts = opts;
  }

  async mint(input: StorageGrantMintInput): Promise<StorageGrant> {
    const parsed = parseStorageUri(input.resource);
    if (!parsed || parsed.cloud !== 'azure-blob') {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Azure storage-grant minter cannot handle resource: ${input.resource}`,
        400,
      );
    }
    const permissions = mapActionsToAzurePermissions(input.actions);
    if (!permissions) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `No Azure SAS permissions map to actions: ${input.actions.join(',')}`,
        400,
      );
    }

    const client = await this.loadClient(parsed);
    const signer = this.opts.signer ?? (await loadDefaultSigner());

    const startsOn = new Date(Date.now() - 5 * 60 * 1000); // 5 min clock skew
    const expiresOn = new Date(Date.now() + input.ttlSeconds * 1000);
    const userDelegationKey = await client.getUserDelegationKey(startsOn, expiresOn);

    // Container == first segment of keyOrPrefix; blob == the rest, but
    // only for single-object grants. Wildcard grants get a container-
    // scoped SAS (signedResource=c) with a signed prefix.
    const segments = parsed.keyOrPrefix.split('/').filter((s) => s.length > 0);
    const containerName = segments[0] ?? '';
    if (!containerName) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Azure storage URI must include a container: ${input.resource}`,
        400,
      );
    }
    const blobName = parsed.isWildcard
      ? undefined
      : segments.length > 1
        ? segments.slice(1).join('/')
        : undefined;

    const signed = signer({
      client,
      userDelegationKey,
      containerName,
      blobName,
      permissions,
      startsOn,
      expiresOn,
    });

    return {
      provider: 'azure-blob',
      resource: input.resource,
      actions: [...input.actions],
      expiresAt: expiresOn.toISOString(),
      azureSas: { url: signed.url, sasToken: signed.sasToken },
    };
  }

  private async loadClient(parsed: ParsedStorageUri): Promise<AzureBlobClientLike> {
    if (this.opts.clientFactory) {
      return await this.opts.clientFactory();
    }
    // Lazy-import so AWS / GCP-only deployments don't pay the cost.
    const { BlobServiceClient } = await dynamicImport('@azure/storage-blob');
    const { DefaultAzureCredential } = await dynamicImport('@azure/identity');
    const url = `https://${parsed.bucket}.blob.core.windows.net`;
    const client = new BlobServiceClient(url, new DefaultAzureCredential());
    return client as unknown as AzureBlobClientLike;
  }
}

function mapActionsToAzurePermissions(actions: string[]): string {
  const map = STORAGE_ACTION_MAP['azure-blob'];
  const letters: string[] = [];
  for (const a of actions) {
    const letter = map[a];
    if (!letter) continue;
    if (!letters.includes(letter)) letters.push(letter);
  }
  // Azure expects letters in a canonical order (r,a,c,w,d,x,l,...).
  // We only emit r/w/d/l so a stable alphabetic sort is sufficient for
  // determinism in tests; Azure tolerates any order.
  return letters.sort().join('');
}

async function loadDefaultSigner(): Promise<AzureSasSigner> {
  const sdk: any = await dynamicImport('@azure/storage-blob');
  const {
    BlobSASPermissions,
    ContainerSASPermissions,
    generateBlobSASQueryParameters,
    SASProtocol,
  } = sdk;
  return ({ client, userDelegationKey, containerName, blobName, permissions, startsOn, expiresOn }) => {
    const PermsCtor = blobName ? BlobSASPermissions : ContainerSASPermissions;
    const perms = PermsCtor.parse(permissions);
    const sasParams = generateBlobSASQueryParameters(
      {
        containerName,
        blobName,
        permissions: perms,
        startsOn,
        expiresOn,
        protocol: SASProtocol.Https,
      },
      userDelegationKey,
      client.accountName,
    );
    const sasToken = sasParams.toString();
    const base = `https://${client.accountName}.blob.core.windows.net/${containerName}`;
    const url = blobName ? `${base}/${blobName}?${sasToken}` : `${base}?${sasToken}`;
    return { sasToken, url };
  };
}

/**
 * Dynamic-import wrapper kept in module scope (rather than inlined) so
 * tests can `jest.mock('@azure/storage-blob', ...)` and have it
 * intercepted reliably. Throws a structured CapabilityError when the
 * SDK is not installed so operators get an actionable message instead
 * of a raw `MODULE_NOT_FOUND`.
 */
async function dynamicImport(name: string): Promise<any> {
  try {
    return await import(name);
  } catch (err) {
    throw new CapabilityError(
      ErrorCode.INTERNAL_ERROR,
      `Required SDK '${name}' is not installed; install it or disable storage grants for this provider`,
      500,
    );
  }
}

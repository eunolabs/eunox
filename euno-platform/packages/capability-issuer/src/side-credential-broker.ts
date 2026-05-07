/**
 * Side-Credential Broker — thin facade over storage-grant and DB-token
 * credential minting.
 *
 * # Why this exists
 *
 * The original issuer monolith ran all three responsibilities —
 * capability-JWT minting, storage-grant STS, and DB-IAM credential
 * minting — in the same call stack, sharing:
 *
 *   - **Fate**: an exception in the DB-token path blocked capability
 *     issuance even though the JWT had already been signed.
 *   - **Rate limits**: a single limiter bucket covered all three;
 *     exhaustion from DB-token abuse starved capability issuance.
 *   - **KMS handle**: the signing key was ambient in every code path,
 *     including the side-credential paths that never need it.
 *
 * This module introduces `SideCredentialBroker` as the single seam
 * between the capability issuer and credential minting.  Two
 * implementations ship:
 *
 *   - `InProcessSideCredentialBroker` — delegates to the existing
 *     `StorageGrantService` / `DbTokenService` in-process.  Zero
 *     additional overhead; preserves the existing behavior as the
 *     default for existing deployments.
 *
 *   - `HttpSideCredentialBroker` — calls dedicated remote microservices
 *     (`storage-grant-service`, `db-token-service`) over HTTP, using
 *     the signed capability JWT as the Bearer proof of authorisation.
 *     The remote services verify the JWT with the issuer's public JWKS
 *     only — they carry **no KMS credentials**, and a full process
 *     crash in the DB-token service cannot affect the capability-issuer
 *     process at all.
 *
 * # Failure modes
 *
 * Both implementations surface failure through the `failureMode`
 * option on `CapabilityIssuerService`:
 *
 *   - `'fail-fast'` (default, back-compat): any broker error propagates
 *     and the response is a 500/502.  Matches the previous monolith
 *     behaviour.
 *   - `'best-effort'`: broker errors are logged and metered but the
 *     capability JWT is still returned without side credentials.  Opt
 *     in when the agent runtime is prepared to fall back gracefully
 *     (e.g. call the dedicated microservice endpoint directly).
 *
 * # KMS isolation
 *
 * The `CapabilityIssuerService.issueCapability` flow signs the JWT
 * **before** calling the broker, so the KMS `signDigest` operation
 * completes before any broker code runs.  In `'best-effort'` mode a
 * broker crash therefore never loses an already-signed token.
 */

import {
  CapabilityConstraint,
  CapabilityError,
  DbCredential,
  ErrorCode,
  Logger,
  RoleCapabilityPolicy,
  StorageGrant,
} from '@euno/common';
import { DbTokenService } from './db-token';
import { StorageGrantService } from './storage-grant';

// ---------------------------------------------------------------------------
// Typed broker errors
// ---------------------------------------------------------------------------

/**
 * Error thrown by `HttpSideCredentialBroker` when a remote service call
 * fails.  Carries an explicit `brokerKind` property so the issuer's
 * best-effort handler can classify the failure without string-matching
 * on error messages.
 */
export class BrokerCallError extends CapabilityError {
  /** Which side-credential kind failed. */
  readonly brokerKind: 'storage-grant' | 'db-token';

  constructor(
    brokerKind: 'storage-grant' | 'db-token',
    code: ErrorCode,
    message: string,
    statusCode: number,
  ) {
    super(code, message, statusCode);
    this.brokerKind = brokerKind;
    this.name = 'BrokerCallError';
    // Restore prototype chain (required when extending Error in TS).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Context forwarded by the issuer to the broker on every credential mint. */
export interface SideCredentialMintContext {
  /** Signing subject (agent ID). */
  agentId: string;
  /** Authenticated user who authorised this capability. */
  authorizedBy: string;
  /** Remaining TTL of the capability token (seconds). */
  capabilityTtlSeconds: number;
  /**
   * Roles of the authenticated user. Required by in-process DB-token
   * minting to resolve the IAM-mapped database principal via
   * `policy.dbUsernamesByRole`.  Not forwarded over HTTP (the remote
   * db-token service derives the username from the JWT's
   * `authorizedBy.roles` claim and its own policy file).
   */
  userRoles: string[];
  /**
   * Role → capability policy. Required by in-process DB-token minting.
   * Ignored by `HttpSideCredentialBroker`.
   */
  policy: RoleCapabilityPolicy;
}

/** Contract for all side-credential broker implementations. */
export interface SideCredentialBroker {
  /**
   * True when this broker is capable of minting storage grants.
   * The issuer uses this to decide whether to apply the dedicated
   * storage-grant rate limiter before calling `mint`.
   */
  isStorageEnabled(): boolean;

  /**
   * True when this broker is capable of minting DB tokens.
   * The issuer uses this to decide whether to apply the dedicated
   * db-token rate limiter before calling `mint`.
   */
  isDbEnabled(): boolean;

  /**
   * Mint side credentials for the given capability set.
   *
   * @param signedToken - The signed capability JWT.  In-process
   *   implementations may ignore this; HTTP implementations use it as
   *   the Bearer proof when calling remote services.
   * @param capabilities - The capability constraints granted by the JWT.
   * @param context - Caller-supplied context (agent, user, TTL, roles,
   *   policy).
   */
  mint(
    signedToken: string,
    capabilities: CapabilityConstraint[],
    context: SideCredentialMintContext,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }>;
}

// ---------------------------------------------------------------------------
// InProcessSideCredentialBroker
// ---------------------------------------------------------------------------

export interface InProcessSideCredentialBrokerOptions {
  storageGrantService?: StorageGrantService;
  dbTokenService?: DbTokenService;
}

/**
 * In-process broker that delegates to the existing `StorageGrantService`
 * and `DbTokenService` implementations.  No additional latency over the
 * original monolith; intended as the default for single-process
 * deployments that have not yet extracted the side-credential services
 * into separate pods.
 *
 * The signed token parameter is accepted but unused — verification is
 * implicit because both services run in the same trust boundary as the
 * issuer.
 */
export class InProcessSideCredentialBroker implements SideCredentialBroker {
  private readonly storageGrantService?: StorageGrantService;
  private readonly dbTokenService?: DbTokenService;

  constructor(opts: InProcessSideCredentialBrokerOptions = {}) {
    this.storageGrantService = opts.storageGrantService;
    this.dbTokenService = opts.dbTokenService;
  }

  isStorageEnabled(): boolean {
    return this.storageGrantService?.isEnabled() ?? false;
  }

  isDbEnabled(): boolean {
    return this.dbTokenService?.isEnabled() ?? false;
  }

  async mint(
    _signedToken: string,
    capabilities: CapabilityConstraint[],
    context: SideCredentialMintContext,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }> {
    const storageGrants = this.storageGrantService?.isEnabled()
      ? await this.storageGrantService.mintForCapabilities(capabilities, {
          agentId: context.agentId,
          authorizedBy: context.authorizedBy,
          capabilityTtlSeconds: context.capabilityTtlSeconds,
        })
      : undefined;

    const dbCredentials = this.dbTokenService?.isEnabled()
      ? await this.dbTokenService.mintForCapabilities(capabilities, {
          agentId: context.agentId,
          authorizedBy: context.authorizedBy,
          capabilityTtlSeconds: context.capabilityTtlSeconds,
          userRoles: context.userRoles,
          policy: context.policy,
        })
      : undefined;

    return { storageGrants, dbCredentials };
  }
}

// ---------------------------------------------------------------------------
// HttpSideCredentialBroker
// ---------------------------------------------------------------------------

export interface HttpSideCredentialBrokerOptions {
  /**
   * Base URL of the `storage-grant-service`, e.g.
   * `http://storage-grant-service:8080`.  When unset, storage-grant
   * minting is skipped (equivalent to the service being disabled).
   */
  storageGrantServiceUrl?: string;

  /**
   * Base URL of the `db-token-service`, e.g.
   * `http://db-token-service:8080`.  When unset, DB-token minting is
   * skipped.
   */
  dbTokenServiceUrl?: string;

  /**
   * Per-request HTTP timeout in milliseconds.  Defaults to 10 000 ms.
   * A hung side-credential service cannot block capability issuance
   * indefinitely — in `best-effort` mode the issuer returns the JWT
   * and omits the side credentials when the timeout fires.
   */
  timeoutMs?: number;

  /** Optional logger for request / error traces. */
  logger?: Logger;
}

/**
 * HTTP-based broker that delegates credential minting to dedicated
 * remote microservices.
 *
 * The signed capability JWT is forwarded as the `Authorization: Bearer`
 * header.  The remote services verify it against the issuer's public
 * JWKS (no KMS) and mint the relevant credentials — fully isolated from
 * the issuer's process, rate limiters, and IAM credentials.
 *
 * Both service calls run in parallel when both are configured.
 */
export class HttpSideCredentialBroker implements SideCredentialBroker {
  private readonly storageGrantServiceUrl?: string;
  private readonly dbTokenServiceUrl?: string;
  private readonly timeoutMs: number;
  private readonly logger?: Logger;

  constructor(opts: HttpSideCredentialBrokerOptions = {}) {
    this.storageGrantServiceUrl = opts.storageGrantServiceUrl?.replace(/\/$/, '');
    this.dbTokenServiceUrl = opts.dbTokenServiceUrl?.replace(/\/$/, '');
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.logger = opts.logger;
  }

  isStorageEnabled(): boolean {
    return !!this.storageGrantServiceUrl;
  }

  isDbEnabled(): boolean {
    return !!this.dbTokenServiceUrl;
  }

  async mint(
    signedToken: string,
    capabilities: CapabilityConstraint[],
    context: SideCredentialMintContext,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }> {
    // Check which resource types are present to avoid unnecessary HTTP calls.
    const hasStorage = capabilities.some(
      (c) => typeof c.resource === 'string' && c.resource.startsWith('storage://'),
    );
    const hasDb = capabilities.some(
      (c) => typeof c.resource === 'string' && c.resource.startsWith('db://'),
    );

    // Annotate each call with its kind so that errors can be classified
    // reliably without string-matching on error messages.
    const [storageResult, dbResult] = await Promise.all([
      hasStorage && this.storageGrantServiceUrl
        ? this.callStorageGrantService(signedToken, context.agentId)
        : Promise.resolve(undefined),
      hasDb && this.dbTokenServiceUrl
        ? this.callDbTokenService(signedToken, context.agentId)
        : Promise.resolve(undefined),
    ]);

    return {
      storageGrants: storageResult ?? undefined,
      dbCredentials: dbResult ?? undefined,
    };
  }

  private async callStorageGrantService(
    signedToken: string,
    agentId: string,
  ): Promise<StorageGrant[]> {
    const url = `${this.storageGrantServiceUrl!}/api/v1/storage-grants`;
    try {
      const body = await this.postJson<{ grants: StorageGrant[] }>(url, signedToken, { agentId });
      return body.grants;
    } catch (err) {
      // Wrap as a typed BrokerCallError so the issuer's best-effort handler
      // can identify the kind reliably via instanceof + .brokerKind property,
      // without mutating the original error object or inspecting messages.
      if (err instanceof BrokerCallError) throw err; // already typed
      if (err instanceof CapabilityError) {
        throw new BrokerCallError('storage-grant', err.code, err.message, err.statusCode);
      }
      throw new BrokerCallError(
        'storage-grant',
        ErrorCode.INTERNAL_ERROR,
        err instanceof Error ? err.message : String(err),
        502,
      );
    }
  }

  private async callDbTokenService(
    signedToken: string,
    agentId: string,
  ): Promise<DbCredential[]> {
    const url = `${this.dbTokenServiceUrl!}/api/v1/db-tokens`;
    try {
      const body = await this.postJson<{ credentials: DbCredential[] }>(url, signedToken, { agentId });
      return body.credentials;
    } catch (err) {
      if (err instanceof BrokerCallError) throw err;
      if (err instanceof CapabilityError) {
        throw new BrokerCallError('db-token', err.code, err.message, err.statusCode);
      }
      throw new BrokerCallError(
        'db-token',
        ErrorCode.INTERNAL_ERROR,
        err instanceof Error ? err.message : String(err),
        502,
      );
    }
  }

  private async postJson<T>(
    url: string,
    bearerToken: string,
    body: Record<string, unknown>,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${bearerToken}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger?.warn?.('side-credential HTTP call failed', { url, error: msg });
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Side-credential service unreachable (${url}): ${msg}`,
        502,
      );
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let errorCode: string | undefined;
      let errorMessage: string | undefined;
      try {
        const errBody = await response.json() as { error?: { code?: string; message?: string } };
        errorCode = errBody.error?.code;
        errorMessage = errBody.error?.message;
      } catch {
        // ignore parse failure — use HTTP status only
      }
      throw new CapabilityError(
        (errorCode as ErrorCode | undefined) ?? ErrorCode.INTERNAL_ERROR,
        errorMessage ?? `Side-credential service returned HTTP ${response.status}`,
        response.status >= 400 && response.status < 500 ? response.status : 502,
      );
    }

    return response.json() as Promise<T>;
  }
}

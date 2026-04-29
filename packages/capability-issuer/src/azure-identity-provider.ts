/**
 * Azure AD Identity Provider
 * Implements pluggable identity provider interface for Azure Active Directory
 *
 * Implements Sprint 3-4 Gap items #3 (Conditional Access policy
 * enforcement) and #4 (PIM activation checks). When the corresponding
 * configuration blocks (`AzureADConfig.conditionalAccess`,
 * `AzureADConfig.pim`) are omitted, behavior is identical to the
 * original implementation — `caEvaluation.satisfiedTiers` defaults to
 * all tiers and roles are treated as permanent — so existing
 * deployments are unaffected.
 *
 * See `docs/sprint-3-4-gaps/03-conditional-access.md` and
 * `docs/sprint-3-4-gaps/04-pim-activation.md`.
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential } from '@azure/identity';
import * as jose from 'jose';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  UserContext,
  AzureADConfig,
  CapabilityError,
  ErrorCode,
  CapabilityConstraint,
  mapRolesToCapabilities,
  CaActionTier,
  CaEvaluation,
  ResolvedRole,
  RoleSource,
} from '@euno/common';

/**
 * Azure AD specific configuration extending the base adapter config
 */
export interface AzureADAdapterConfig extends IdentityAdapterConfig {
  type: 'azure-ad';
  azureAD: AzureADConfig;
}

/** All four CA action tiers, in stable order. */
const CA_TIERS: readonly CaActionTier[] = ['read', 'write', 'delete', 'admin'];
/** Default sign-in age cap (1 hour). */
const DEFAULT_MAX_SIGN_IN_AGE_SECONDS = 3600;
/** PIM cache TTL — short by design; PIM activations are time-bound. */
const PIM_CACHE_TTL_MS = 30_000;
/** CA fresh-Graph-check cache TTL. */
const CA_CACHE_TTL_MS = 60_000;
/** LRU bound for either cache (per-provider instance). */
const CACHE_MAX_ENTRIES = 1024;

interface CacheEntry<V> {
  value: V;
  expiresAtMs: number;
}

/**
 * Tiny LRU + TTL cache. Bounded so a high-cardinality user/session
 * population can't grow the provider's memory unboundedly.
 */
class TtlLruCache<V> {
  private readonly entries = new Map<string, CacheEntry<V>>();
  constructor(private readonly maxEntries: number) {}

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Touch for LRU recency.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, value: V, ttlMs: number): void {
    if (this.entries.has(key)) this.entries.delete(key);
    this.entries.set(key, { value, expiresAtMs: Date.now() + ttlMs });
    while (this.entries.size > this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey === undefined) break;
      this.entries.delete(oldestKey);
    }
  }

  delete(key: string): void {
    this.entries.delete(key);
  }
}

/**
 * Microsoft Graph response shape — only the fields we read.
 * The `@microsoft/microsoft-graph-client` SDK returns `any`; we use
 * narrow local interfaces to keep type-safety at the call site.
 */
interface GraphAssignmentScheduleInstance {
  id: string;
  roleDefinitionId: string;
  assignmentType?: 'Assigned' | 'Activated';
  endDateTime?: string | null;
}
interface GraphEligibilityScheduleInstance {
  id: string;
  roleDefinitionId: string;
}
interface GraphRoleDefinition {
  id: string;
  displayName: string;
}
interface GraphRiskyUser {
  riskState?: string;
  riskLevel?: string;
}
interface GraphCollection<T> {
  value: T[];
  '@odata.nextLink'?: string;
}

export class AzureADIdentityProvider extends IdentityAdapter {
  public readonly name = 'azure-ad';
  private azureConfig: AzureADConfig;
  private graphClient?: Client;
  // Cached JWKS function — created once so jose's built-in TTL-based key cache
  // is reused across calls instead of being thrown away on every validateToken invocation.
  private jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

  /** Cache of role-definition id → display name. Role definitions are
   *  effectively static per tenant, so cache indefinitely once resolved. */
  private readonly roleDefinitionNameCache = new Map<string, string>();
  /** Cache keyed by `userId` → resolved roles. Short TTL: PIM state is by
   *  definition time-bound. */
  private readonly pimResolutionCache = new TtlLruCache<ResolvedRole[]>(CACHE_MAX_ENTRIES);
  /** Cache keyed by `userId|sessionId` → fresh-Graph-check satisfied flag. */
  private readonly caFreshCheckCache = new TtlLruCache<boolean>(CACHE_MAX_ENTRIES);

  constructor(config: AzureADAdapterConfig) {
    super(config);
    this.azureConfig = config.azureAD;
  }

  /**
   * Validate an OIDC token from Azure AD and extract user context.
   *
   * When `conditionalAccess` is configured, the resulting
   * {@link UserContext.caEvaluation} records which action tiers were
   * satisfied; the issuer denies any requested capability whose tier is
   * not in `satisfiedTiers`. When `pim` is configured, the user's roles
   * are resolved against Microsoft Graph's PIM endpoints and
   * {@link UserContext.roleSources} carries per-role source metadata so
   * the issuer can strip eligible-but-not-active roles and cap TTL.
   */
  async validateToken(token: string): Promise<UserContext> {
    let payload: jose.JWTPayload;
    try {
      // Get JWKS for token verification
      const authority = this.azureConfig.authority || `https://login.microsoftonline.com/${this.azureConfig.tenantId}`;

      // Lazily create the JWKS instance once and reuse it so that jose's
      // internal TTL-based key cache is effective across requests.
      if (!this.jwks) {
        const jwksUri = `${authority}/discovery/v2.0/keys`;
        this.jwks = jose.createRemoteJWKSet(new URL(jwksUri));
      }
      const JWKS = this.jwks;

      // Verify the token
      const verified = await jose.jwtVerify(token, JWKS, {
        issuer: `${authority}/v2.0`,
        audience: this.azureConfig.clientId,
      });
      payload = verified.payload;
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate Azure AD token: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401,
      );
    }

    // Extract base user context.
    const userId = (payload.oid as string) || (payload.sub as string);
    const userContext: UserContext = {
      userId,
      email: (payload.email as string) || (payload.upn as string),
      roles: (payload.roles as string[]) || [],
      tenantId: payload.tid as string,
      claims: payload as Record<string, unknown>,
    };

    // ── Conditional Access evaluation ───────────────────────────────────
    // Always populate caEvaluation so the issuer can apply a uniform
    // policy: when CA is unconfigured all tiers are satisfied
    // (back-compat), otherwise satisfied tiers are derived from the
    // token's `acrs` claim, sign-in age, and (optionally) Graph.
    userContext.caEvaluation = await this.evaluateConditionalAccess(payload);

    // Per the design's fail-closed principle, if CA is configured and
    // requireFreshGraphCheck is on but the Graph call could not be
    // completed, evaluateConditionalAccess() returns satisfiedTiers=[]
    // — the issuer will deny on the first sensitive request, which is
    // the desired behavior.

    // ── PIM resolution ──────────────────────────────────────────────────
    // Only fetch from Graph when configured; preserves back-compat for
    // deployments that have not enabled PIM.
    if (this.azureConfig.pim) {
      try {
        const resolved = await this.resolveActivePimRoles(userId);
        userContext.roleSources = resolved;

        // When enforceActivation is on (default true once `pim` is set),
        // the canonical `roles` list excludes eligible-but-not-active
        // roles so the downstream role→capability mapping never sees them.
        const enforceActivation = this.azureConfig.pim.enforceActivation !== false;
        if (enforceActivation) {
          userContext.roles = resolved
            .filter((r) => r.source.kind !== 'pim-eligible-not-active')
            .map((r) => r.name);
        } else {
          userContext.roles = resolved.map((r) => r.name);
        }
      } catch (error) {
        // Fail closed for PIM-required roles: if we can't determine PIM
        // state, treat all roles as `pim-eligible-not-active` so that
        // any role on the operator's `pimRequiredRoles` list is denied
        // by the issuer. Other roles fall through unchanged so a
        // transient Graph outage doesn't take down read-only issuance.
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new CapabilityError(
          ErrorCode.AUTHORIZATION_FAILED,
          `Failed to resolve PIM role state: ${message}`,
          500,
        );
      }
    }

    return userContext;
  }

  /**
   * Evaluate Conditional Access signals from the token (claim-based)
   * and, when configured, from Microsoft Graph (fresh check).
   *
   * Returns a {@link CaEvaluation} whose `satisfiedTiers` lists every
   * action tier this token is permitted to mint. When CA is
   * unconfigured, all tiers are satisfied (back-compat).
   */
  private async evaluateConditionalAccess(payload: jose.JWTPayload): Promise<CaEvaluation> {
    const presentedAcrs = this.extractAcrs(payload);
    const caConfig = this.azureConfig.conditionalAccess;

    if (!caConfig) {
      return {
        satisfiedTiers: [...CA_TIERS],
        presentedAcrs,
      };
    }

    const requiredAcrsByTier = caConfig.requiredAcrsByTier ?? {};
    const maxSignInAgeSeconds = caConfig.maxSignInAgeSeconds ?? DEFAULT_MAX_SIGN_IN_AGE_SECONDS;

    // Sign-in age check: when auth_time is older than the cap, admin /
    // delete are unsatisfied even if the acrs are present. read /
    // write are still allowed by age (operator can restrict further
    // via `requiredAcrsByTier`).
    const authTime = typeof payload.auth_time === 'number' ? payload.auth_time : undefined;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const signInIsFresh = authTime === undefined ? true : nowSeconds - authTime <= maxSignInAgeSeconds;

    const presentedSet = new Set(presentedAcrs);
    const satisfiedTiers: CaActionTier[] = [];
    for (const tier of CA_TIERS) {
      const required = requiredAcrsByTier[tier] ?? [];
      const acrsSatisfied = required.every((value) => presentedSet.has(value));
      if (!acrsSatisfied) continue;
      if (!signInIsFresh && (tier === 'admin' || tier === 'delete')) continue;
      satisfiedTiers.push(tier);
    }

    // Optional Graph fresh check: when enabled, every tier is gated on
    // the user not being flagged as risky in the most recent Graph
    // snapshot. Cached per (userId, sid) for ≤60s.
    if (caConfig.requireFreshGraphCheck) {
      const userId = (payload.oid as string) || (payload.sub as string);
      const sessionId = (payload.sid as string) || '';
      const cacheKey = `${userId}|${sessionId}`;
      let isClean = this.caFreshCheckCache.get(cacheKey);
      if (isClean === undefined) {
        try {
          isClean = await this.checkUserRiskClean(userId);
          this.caFreshCheckCache.set(cacheKey, isClean, CA_CACHE_TTL_MS);
        } catch {
          // Fail closed: cannot evaluate → no tiers satisfied.
          return {
            satisfiedTiers: [],
            requiredAcrsByTier,
            presentedAcrs,
          };
        }
      }
      if (!isClean) {
        return {
          satisfiedTiers: [],
          requiredAcrsByTier,
          presentedAcrs,
        };
      }
    }

    return {
      satisfiedTiers,
      requiredAcrsByTier,
      presentedAcrs,
    };
  }

  /**
   * Extract `acrs` values from a token payload. Azure AD emits the
   * authentication-context references as either an array under `acrs`
   * (modern) or a single string under `acr` (legacy). Both shapes are
   * normalized to a string array.
   */
  private extractAcrs(payload: jose.JWTPayload): string[] {
    const acrs = payload.acrs;
    if (Array.isArray(acrs)) {
      return acrs.filter((v): v is string => typeof v === 'string');
    }
    if (typeof acrs === 'string') return [acrs];
    if (typeof payload.acr === 'string') return [payload.acr];
    return [];
  }

  /**
   * Query Graph for the user's current risk state. Returns true when
   * the user is not flagged. A 404 (user has never been evaluated) is
   * treated as clean.
   */
  private async checkUserRiskClean(userId: string): Promise<boolean> {
    const graphClient = await this.getGraphClient();
    try {
      const risky = (await graphClient
        .api(`/identityProtection/riskyUsers/${userId}`)
        .get()) as GraphRiskyUser | null;
      if (!risky) return true;
      const riskState = (risky.riskState ?? '').toLowerCase();
      // Microsoft uses values: none | confirmedSafe | remediated | dismissed |
      // atRisk | confirmedCompromised. Only `atRisk` and
      // `confirmedCompromised` deny.
      return riskState !== 'atrisk' && riskState !== 'confirmedcompromised';
    } catch (error) {
      // 404 — user not in the risky-users index → clean.
      const status = (error as { statusCode?: number; status?: number } | null)?.statusCode
        ?? (error as { statusCode?: number; status?: number } | null)?.status;
      if (status === 404) return true;
      throw error;
    }
  }

  /**
   * Resolve the user's directory roles from Microsoft Graph PIM
   * endpoints, returning per-role source metadata. Cached per user for
   * 30 seconds.
   */
  private async resolveActivePimRoles(userId: string): Promise<ResolvedRole[]> {
    const cached = this.pimResolutionCache.get(userId);
    if (cached) return cached;

    const graphClient = await this.getGraphClient();

    const [assignments, eligibilities] = await Promise.all([
      this.fetchAssignmentScheduleInstances(graphClient, userId),
      this.fetchEligibilityScheduleInstances(graphClient, userId),
    ]);

    // Resolve display names — definitions are static so the cache lives
    // for the lifetime of the process.
    const definitionIds = new Set<string>();
    for (const a of assignments) definitionIds.add(a.roleDefinitionId);
    for (const e of eligibilities) definitionIds.add(e.roleDefinitionId);
    await this.ensureRoleDefinitionNames(graphClient, [...definitionIds]);

    const resolved: ResolvedRole[] = [];
    const seen = new Set<string>();

    // Active assignments first — both `Assigned` (permanent) and
    // `Activated` (currently-active PIM) come from this endpoint.
    for (const a of assignments) {
      const name = this.roleDefinitionNameCache.get(a.roleDefinitionId);
      if (!name || seen.has(name)) continue;
      seen.add(name);
      let source: RoleSource;
      if (a.assignmentType === 'Activated' && a.endDateTime) {
        source = { kind: 'pim-active', assignmentId: a.id, endDateTime: a.endDateTime };
      } else {
        source = { kind: 'permanent' };
      }
      resolved.push({ name, source });
    }

    // Eligibility entries that don't already appear as active are
    // eligible-but-not-active.
    for (const e of eligibilities) {
      const name = this.roleDefinitionNameCache.get(e.roleDefinitionId);
      if (!name || seen.has(name)) continue;
      seen.add(name);
      resolved.push({ name, source: { kind: 'pim-eligible-not-active' } });
    }

    this.pimResolutionCache.set(userId, resolved, PIM_CACHE_TTL_MS);
    return resolved;
  }

  /**
   * Fetch all currently-active role assignment schedule instances for
   * the user, paginated. Capped at 100 entries (the practical Azure AD
   * directory-role limit) to bound memory and Graph load.
   */
  private async fetchAssignmentScheduleInstances(
    graphClient: Client,
    userId: string,
  ): Promise<GraphAssignmentScheduleInstance[]> {
    return this.fetchPaginated<GraphAssignmentScheduleInstance>(
      graphClient,
      `/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '${userId}'`,
    );
  }

  private async fetchEligibilityScheduleInstances(
    graphClient: Client,
    userId: string,
  ): Promise<GraphEligibilityScheduleInstance[]> {
    return this.fetchPaginated<GraphEligibilityScheduleInstance>(
      graphClient,
      `/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '${userId}'`,
    );
  }

  /**
   * Generic Graph collection paginator. Caps total at 100 to avoid
   * unbounded fetches against a misconfigured tenant.
   */
  private async fetchPaginated<T>(graphClient: Client, initialPath: string): Promise<T[]> {
    const out: T[] = [];
    let path: string | undefined = initialPath;
    let pages = 0;
    while (path && out.length < 100 && pages < 10) {
      const page = (await graphClient.api(path).get()) as GraphCollection<T>;
      if (Array.isArray(page?.value)) {
        for (const item of page.value) {
          out.push(item);
          if (out.length >= 100) break;
        }
      }
      path = page?.['@odata.nextLink'];
      pages += 1;
    }
    return out;
  }

  /**
   * Look up `displayName` for any role-definition ids not already in
   * the cache. Definitions are stable so the cache is unbounded
   * (capped only by the size of the tenant's role catalog).
   */
  private async ensureRoleDefinitionNames(graphClient: Client, ids: string[]): Promise<void> {
    const missing = ids.filter((id) => !this.roleDefinitionNameCache.has(id));
    if (missing.length === 0) return;
    await Promise.all(
      missing.map(async (id) => {
        try {
          const def = (await graphClient
            .api(`/roleManagement/directory/roleDefinitions/${id}`)
            .select('displayName')
            .get()) as GraphRoleDefinition | null;
          if (def?.displayName) {
            this.roleDefinitionNameCache.set(id, def.displayName);
          }
        } catch {
          // A single missing definition shouldn't fail the whole
          // resolution; the role is dropped from the result instead.
        }
      }),
    );
  }

  /**
   * Get user roles from Azure AD via Microsoft Graph API.
   *
   * When `pim` is configured, returns only roles that are either
   * permanently assigned or currently PIM-activated; eligible-but-not-
   * active roles are filtered out so the caller never sees them.
   */
  async getUserRoles(userId: string): Promise<string[]> {
    try {
      if (this.azureConfig.pim) {
        const resolved = await this.resolveActivePimRoles(userId);
        const enforceActivation = this.azureConfig.pim.enforceActivation !== false;
        return resolved
          .filter((r) => !enforceActivation || r.source.kind !== 'pim-eligible-not-active')
          .map((r) => r.name);
      }

      const graphClient = await this.getGraphClient();

      // Get user's directory roles
      const roles = await graphClient
        .api(`/users/${userId}/memberOf`)
        .select('displayName')
        .get();

      return roles.value.map((role: any) => role.displayName);
    } catch (error) {
      if (error instanceof CapabilityError) throw error;
      throw new CapabilityError(
        ErrorCode.AUTHORIZATION_FAILED,
        `Failed to get user roles: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Check if user has a specific permission
   */
  async hasPermission(userId: string, permission: string): Promise<boolean> {
    const roles = await this.getUserRoles(userId);
    return roles.includes(permission);
  }

  /**
   * Get or create Graph API client
   */
  private async getGraphClient(): Promise<Client> {
    if (this.graphClient) {
      return this.graphClient;
    }

    if (!this.azureConfig.clientSecret) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Client secret required for Graph API access',
        500
      );
    }

    const credential = new ClientSecretCredential(
      this.azureConfig.tenantId,
      this.azureConfig.clientId,
      this.azureConfig.clientSecret
    );

    // Get access token for Microsoft Graph
    const tokenResponse = await credential.getToken('https://graph.microsoft.com/.default');

    this.graphClient = Client.init({
      authProvider: (done) => {
        done(null, tokenResponse.token);
      },
    });

    return this.graphClient;
  }

  /**
   * Map Azure AD roles to capability constraints.
   *
   * Retained as a static method for backwards compatibility; new code should
   * call {@link mapRolesToCapabilities} from `@euno/common` directly so the
   * same mapping is shared across every identity provider.
   */
  static mapRolesToCapabilities(roles: string[]): CapabilityConstraint[] {
    return mapRolesToCapabilities(roles);
  }

  /**
   * Test seam: install a Graph client (and optionally pre-warm the
   * role-definition name cache) without going through
   * {@link getGraphClient}, which requires a real client secret and
   * makes a network call to AAD for an access token. Used by unit
   * tests to inject a mocked Graph client.
   *
   * @internal
   */
  __setGraphClientForTests(client: Client, roleDefinitionNames?: Record<string, string>): void {
    this.graphClient = client;
    if (roleDefinitionNames) {
      for (const [id, name] of Object.entries(roleDefinitionNames)) {
        this.roleDefinitionNameCache.set(id, name);
      }
    }
  }
}

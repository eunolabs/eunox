/**
 * Unit tests for AzureADIdentityProvider — focused on the Sprint 3-4
 * gap items #3 (Conditional Access policy enforcement) and #4 (PIM
 * activation checks).
 *
 * The base token validation path (signature, issuer, audience, claim
 * extraction) is already covered indirectly by the e2e tests via the
 * issuer service; here we focus on the new CA + PIM logic.
 *
 * `jose.createRemoteJWKSet` is mocked so the provider verifies tokens
 * against a locally-generated RSA key pair without making real network
 * calls to Azure AD's keys endpoint. The Microsoft Graph client is
 * injected through the `__setGraphClientForTests` test seam.
 */

import * as jose from 'jose';
import { AzureADIdentityProvider } from '../src/azure-identity-provider';
import type { AzureADConfig } from '@euno/common';

const createRemoteJWKSetSpy = jest.spyOn(jose, 'createRemoteJWKSet');

const TENANT_ID = '11111111-1111-1111-1111-111111111111';
const CLIENT_ID = 'app-client-id';
const USER_OID = 'user-oid-123';

describe('AzureADIdentityProvider', () => {
  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;

  beforeAll(async () => {
    const keys = await jose.generateKeyPair('RS256');
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
  });

  beforeEach(() => {
    createRemoteJWKSetSpy.mockReset();
    createRemoteJWKSetSpy.mockReturnValue((async () => publicKey) as any);
  });

  afterAll(() => {
    createRemoteJWKSetSpy.mockRestore();
  });

  function makeProvider(extra: Partial<AzureADConfig> = {}) {
    return new AzureADIdentityProvider({
      type: 'azure-ad',
      name: 'azure',
      azureAD: {
        tenantId: TENANT_ID,
        clientId: CLIENT_ID,
        ...extra,
      },
    });
  }

  async function signAzureToken(payload: Record<string, unknown>) {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(`https://login.microsoftonline.com/${TENANT_ID}/v2.0`)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  // ── Base extraction ───────────────────────────────────────────────
  it('extracts userId, email, roles, and tenantId from a verified token', async () => {
    const provider = makeProvider();
    const token = await signAzureToken({
      oid: USER_OID,
      email: 'alice@example.com',
      roles: ['Reader'],
      tid: TENANT_ID,
    });

    const ctx = await provider.validateToken(token);
    expect(ctx.userId).toBe(USER_OID);
    expect(ctx.email).toBe('alice@example.com');
    expect(ctx.roles).toEqual(['Reader']);
    expect(ctx.tenantId).toBe(TENANT_ID);
  });

  // ── Conditional Access ────────────────────────────────────────────
  describe('Conditional Access', () => {
    it('marks all tiers satisfied when no CA config is supplied (back-compat)', async () => {
      const provider = makeProvider();
      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });

      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation).toBeDefined();
      expect(ctx.caEvaluation!.satisfiedTiers.sort()).toEqual(['admin', 'delete', 'read', 'write']);
      expect(ctx.caEvaluation!.presentedAcrs).toEqual([]);
    });

    it('excludes write/delete/admin when required acrs are missing', async () => {
      const provider = makeProvider({
        conditionalAccess: {
          requiredAcrsByTier: {
            write: ['urn:euno:mfa'],
            delete: ['urn:euno:mfa'],
            admin: ['urn:euno:mfa'],
          },
        },
      });
      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });

      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers).toEqual(['read']);
    });

    it('includes the tier when the required acrs is present in the token', async () => {
      const provider = makeProvider({
        conditionalAccess: {
          requiredAcrsByTier: {
            write: ['urn:euno:mfa'],
            admin: ['urn:euno:mfa'],
          },
        },
      });
      const token = await signAzureToken({
        oid: USER_OID,
        tid: TENANT_ID,
        acrs: ['urn:euno:mfa'],
      });

      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers.sort()).toEqual(['admin', 'delete', 'read', 'write']);
      expect(ctx.caEvaluation!.presentedAcrs).toEqual(['urn:euno:mfa']);
    });

    it('treats a single-string `acr` claim the same as a one-element `acrs` array', async () => {
      const provider = makeProvider({
        conditionalAccess: {
          requiredAcrsByTier: { write: ['urn:euno:mfa'] },
        },
      });
      const token = await signAzureToken({
        oid: USER_OID,
        tid: TENANT_ID,
        acr: 'urn:euno:mfa',
      });

      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers).toContain('write');
    });

    it('rejects admin/delete tiers when sign-in is older than maxSignInAgeSeconds', async () => {
      const provider = makeProvider({
        conditionalAccess: {
          maxSignInAgeSeconds: 60,
        },
      });
      const ancientAuthTime = Math.floor(Date.now() / 1000) - 3600;
      const token = await signAzureToken({
        oid: USER_OID,
        tid: TENANT_ID,
        auth_time: ancientAuthTime,
      });

      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers).toEqual(expect.arrayContaining(['read', 'write']));
      expect(ctx.caEvaluation!.satisfiedTiers).not.toContain('admin');
      expect(ctx.caEvaluation!.satisfiedTiers).not.toContain('delete');
    });

    it('returns no satisfied tiers when requireFreshGraphCheck is on and Graph reports atRisk', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        conditionalAccess: { requireFreshGraphCheck: true },
      });
      const fakeGraph: any = {
        api: () => ({
          select: () => ({ get: async () => ({ value: [] }) }),
          get: async () => ({ riskState: 'atRisk' }),
        }),
      };
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers).toEqual([]);
    });

    it('keeps satisfied tiers when Graph reports the user as not risky', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        conditionalAccess: { requireFreshGraphCheck: true },
      });
      const fakeGraph: any = {
        api: () => ({
          select: () => ({ get: async () => ({ value: [] }) }),
          get: async () => ({ riskState: 'none' }),
        }),
      };
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers.sort()).toEqual(['admin', 'delete', 'read', 'write']);
    });

    it('fails closed (no satisfied tiers) when Graph fresh-check throws', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        conditionalAccess: { requireFreshGraphCheck: true },
      });
      const fakeGraph: any = {
        api: () => ({
          get: async () => {
            throw Object.assign(new Error('boom'), { statusCode: 500 });
          },
        }),
      };
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers).toEqual([]);
    });

    it('treats Graph 404 (user never evaluated) as clean', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        conditionalAccess: { requireFreshGraphCheck: true },
      });
      const fakeGraph: any = {
        api: () => ({
          get: async () => {
            throw Object.assign(new Error('not found'), { statusCode: 404 });
          },
        }),
      };
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);
      expect(ctx.caEvaluation!.satisfiedTiers.sort()).toEqual(['admin', 'delete', 'read', 'write']);
    });
  });

  // ── PIM resolution ────────────────────────────────────────────────
  describe('PIM activation', () => {
    /**
     * Build a fake Graph client whose `.api(path)` dispatches based on
     * the URL prefix to canned responses.
     */
    function buildFakeGraph(routes: Record<string, any>) {
      const handler = (path: string) => {
        for (const prefix of Object.keys(routes)) {
          if (path.startsWith(prefix)) return routes[prefix];
        }
        throw new Error(`Unexpected Graph path: ${path}`);
      };
      return {
        api(path: string) {
          const value = handler(path);
          return {
            select: () => ({ get: async () => value }),
            get: async () => value,
          };
        },
      } as any;
    }

    it('strips pim-eligible-not-active roles before populating ctx.roles when enforceActivation is true', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: { enforceActivation: true },
      });
      const fakeGraph = buildFakeGraph({
        '/roleManagement/directory/roleAssignmentScheduleInstances': {
          value: [
            { id: 'a1', roleDefinitionId: 'def-reader', assignmentType: 'Assigned' },
          ],
        },
        '/roleManagement/directory/roleEligibilityScheduleInstances': {
          value: [
            { id: 'e1', roleDefinitionId: 'def-globaladmin' },
          ],
        },
        '/roleManagement/directory/roleDefinitions/': null, // overridden by cache
      });
      provider.__setGraphClientForTests(fakeGraph, {
        'def-reader': 'Reader',
        'def-globaladmin': 'Global Administrator',
      });

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);

      expect(ctx.roles).toEqual(['Reader']);
      expect(ctx.roleSources).toEqual([
        { name: 'Reader', source: { kind: 'permanent' } },
        { name: 'Global Administrator', source: { kind: 'pim-eligible-not-active' } },
      ]);
    });

    it('records pim-active source with endDateTime for activated assignments', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: {},
      });
      const endDateTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      const fakeGraph = buildFakeGraph({
        '/roleManagement/directory/roleAssignmentScheduleInstances': {
          value: [
            {
              id: 'assign-1',
              roleDefinitionId: 'def-globaladmin',
              assignmentType: 'Activated',
              endDateTime,
            },
          ],
        },
        '/roleManagement/directory/roleEligibilityScheduleInstances': { value: [] },
      });
      provider.__setGraphClientForTests(fakeGraph, {
        'def-globaladmin': 'Global Administrator',
      });

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);

      expect(ctx.roles).toEqual(['Global Administrator']);
      expect(ctx.roleSources).toEqual([
        {
          name: 'Global Administrator',
          source: { kind: 'pim-active', assignmentId: 'assign-1', endDateTime },
        },
      ]);
    });

    it('keeps eligible roles in ctx.roles when enforceActivation is explicitly false', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: { enforceActivation: false },
      });
      const fakeGraph = buildFakeGraph({
        '/roleManagement/directory/roleAssignmentScheduleInstances': { value: [] },
        '/roleManagement/directory/roleEligibilityScheduleInstances': {
          value: [{ id: 'e1', roleDefinitionId: 'def-globaladmin' }],
        },
      });
      provider.__setGraphClientForTests(fakeGraph, {
        'def-globaladmin': 'Global Administrator',
      });

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);

      expect(ctx.roles).toEqual(['Global Administrator']);
    });

    it('throws AUTHORIZATION_FAILED when Graph PIM resolution fails', async () => {
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: {},
      });
      const fakeGraph: any = {
        api: () => ({
          select: () => ({ get: async () => { throw new Error('graph down'); } }),
          get: async () => { throw new Error('graph down'); },
        }),
      };
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      await expect(provider.validateToken(token)).rejects.toMatchObject({
        statusCode: 500,
        code: 'AUTHORIZATION_FAILED',
      });
    });

    it('does not call Graph PIM endpoints when pim config is absent', async () => {
      const provider = makeProvider();
      // No graph client installed — if PIM resolution were attempted
      // getGraphClient() would throw (missing clientSecret).
      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);
      expect(ctx.roleSources).toBeUndefined();
    });

    it('merges directory roles obtained via group membership as permanent', async () => {
      // The memberOf endpoint surfaces directoryRole entries the user
      // holds transitively through group membership. These do NOT
      // appear in the PIM schedule endpoints, so without merging they
      // would be silently dropped when `pim` is enabled.
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: {},
      });
      const fakeGraph = buildFakeGraph({
        '/roleManagement/directory/roleAssignmentScheduleInstances': { value: [] },
        '/roleManagement/directory/roleEligibilityScheduleInstances': { value: [] },
        [`/users/${USER_OID}/memberOf`]: {
          value: [
            { '@odata.type': '#microsoft.graph.directoryRole', displayName: 'Directory Readers' },
            // group membership — must be filtered out
            { '@odata.type': '#microsoft.graph.group', displayName: 'Marketing Team' },
          ],
        },
      });
      provider.__setGraphClientForTests(fakeGraph);

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);

      expect(ctx.roles).toEqual(['Directory Readers']);
      expect(ctx.roleSources).toEqual([
        { name: 'Directory Readers', source: { kind: 'permanent' } },
      ]);
    });

    it('prefers schedule-instance metadata over memberOf for the same role', async () => {
      // If a user holds the same role both directly (PIM-Activated)
      // and via group membership, the schedule-instance entry must
      // win because it carries the activation metadata required for
      // TTL capping.
      const endDateTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      const provider = makeProvider({
        clientSecret: 'unused-in-test',
        pim: {},
      });
      const fakeGraph = buildFakeGraph({
        '/roleManagement/directory/roleAssignmentScheduleInstances': {
          value: [
            {
              id: 'a-active',
              roleDefinitionId: 'def-globaladmin',
              assignmentType: 'Activated',
              endDateTime,
            },
          ],
        },
        '/roleManagement/directory/roleEligibilityScheduleInstances': { value: [] },
        [`/users/${USER_OID}/memberOf`]: {
          value: [
            { '@odata.type': '#microsoft.graph.directoryRole', displayName: 'Global Administrator' },
          ],
        },
      });
      provider.__setGraphClientForTests(fakeGraph, {
        'def-globaladmin': 'Global Administrator',
      });

      const token = await signAzureToken({ oid: USER_OID, tid: TENANT_ID });
      const ctx = await provider.validateToken(token);

      expect(ctx.roleSources).toEqual([
        {
          name: 'Global Administrator',
          source: { kind: 'pim-active', assignmentId: 'a-active', endDateTime },
        },
      ]);
    });
  });
});

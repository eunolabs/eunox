/**
 * Tests for Enforcement Engine
 */

import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  DefaultKillSwitchManager,
  AuditEvidence,
  SignedAuditEvidence,
  EvidenceSigner,
  GENESIS_HASH,
  InMemoryCallCounterStore,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  canonicalSha256,
  CallCounterBackedGatewayQuotaEngine,
  GatewayQuotaEngine,
} from '@euno/common';
import * as jose from 'jose';

/**
 * Builds a stateful signEvidence stub that matches the production
 * `AuditEvidenceSigner` chain contract:
 *   - `seq` is 1-based and increments on every record
 *   - `previousHash` is `GENESIS_HASH` for the first record and the
 *     `canonicalSha256` of the prior signed record for every subsequent one
 *
 * This means jest mocks behave like a real signer chain, so any future
 * code that starts validating chain metadata will catch regressions
 * here instead of being silently masked by impossible mock values
 * (e.g. `seq: 0`).
 */
function makeChainedSignEvidence(
  overrides: Partial<Pick<SignedAuditEvidence, 'signature' | 'keyId' | 'algorithm'>> = {}
): jest.Mock<Promise<SignedAuditEvidence>, [AuditEvidence]> {
  let seq = 0;
  let previousHash: string = GENESIS_HASH;
  const signature = overrides.signature ?? 'sig';
  const keyId = overrides.keyId ?? 'kid';
  const algorithm = overrides.algorithm ?? 'RS256';
  return jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(async (ev) => {
    seq += 1;
    const signed: SignedAuditEvidence = {
      ...ev,
      signature,
      keyId,
      algorithm,
      previousHash,
      seq,
    };
    previousHash = canonicalSha256(signed);
    return signed;
  });
}

describe('EnforcementEngine', () => {
  let engine: EnforcementEngine;
  let verifier: JWTTokenVerifier;
  let privateKey: jose.KeyLike;
  let publicKey: string;
  const logger = createLogger('test');

  beforeAll(async () => {
    const { publicKey: pubKey, privateKey: privKey } = await jose.generateKeyPair('RS256');
    privateKey = privKey;
    publicKey = await jose.exportSPKI(pubKey);

    verifier = new JWTTokenVerifier(publicKey, { requireKid: false });
    engine = new EnforcementEngine({
      dpop: { required: false },
      verifier,
      logger,
    });
  });

  async function createTestToken(
    capabilities: CapabilityConstraint[],
    extra?: Partial<CapabilityTokenPayload>
  ): Promise<string> {
    const payload: CapabilityTokenPayload = {
      iss: 'did:web:test.com',
      sub: 'test-agent',
      aud: 'tool-gateway',
      iat: getCurrentTimestamp(),
      exp: getExpirationTimestamp(900),
      jti: `test-${Date.now()}`,
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities,
      ...extra,
    };

    return await new jose.SignJWT(payload as any)
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
  }

  describe('validateAction', () => {
    it('should allow action when capability matches', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read', 'write'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(true);
      expect(result.matchedCapability).toBeDefined();
      expect(result.matchedCapability?.resource).toBe('api://service/endpoint');
    });

    it('should deny action when capability does not match', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Insufficient permissions');
    });

    it('should deny action for wrong resource', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://other/endpoint',
      });

      expect(result.allowed).toBe(false);
    });

    it('should handle wildcard resources', async () => {
      const token = await createTestToken([
        { resource: 'api://service/*', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/anything',
      });

      expect(result.allowed).toBe(true);
    });

    it('should reject tokens with wrong audience', async () => {
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'test-agent',
        aud: 'wrong-audience',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti: 'test-token',
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [{ resource: 'api://test', actions: ['read'] }],
      };

      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://test',
        })
      ).rejects.toThrow('audience');
    });

    it('should handle multiple capability constraints', async () => {
      const token = await createTestToken([
        { resource: 'api://service1/endpoint', actions: ['read'] },
        { resource: 'api://service2/endpoint', actions: ['write'] },
      ]);

      const result1 = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service1/endpoint',
      });
      expect(result1.allowed).toBe(true);

      const result2 = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service2/endpoint',
      });
      expect(result2.allowed).toBe(true);

      const result3 = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://service1/endpoint',
      });
      expect(result3.allowed).toBe(false);
    });
  });

  // Argument-level enforcement: capabilities can declare an
  // `argumentSchema` that the gateway validates on every call. Without
  // this, an agent with `read on api://crm/customers` could pass any
  // body to that endpoint — exactly the gap this PR closes.
  describe('argument-level enforcement', () => {
    it('rejects calls whose args do not conform to the capability schema', async () => {
      const token = await createTestToken([
        {
          resource: 'api://crm/customers',
          actions: ['read'],
          argumentSchema: {
            type: 'object',
            properties: {
              customerId: { type: 'string', pattern: '[a-zA-Z0-9-]+', maxLength: 64 },
            },
            required: ['customerId'],
          },
        },
      ]);

      // Agent attempts to smuggle an extra `body` field that is not part
      // of the capability's declared shape.
      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: {
          args: { customerId: 'abc-123', body: { hidden: true } },
        },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/disallowed property "body"/);
    });

    it('allows calls whose args conform to the capability schema', async () => {
      const token = await createTestToken([
        {
          resource: 'api://crm/customers',
          actions: ['read'],
          argumentSchema: {
            type: 'object',
            properties: {
              customerId: { type: 'string', pattern: '[a-zA-Z0-9-]+' },
            },
            required: ['customerId'],
          },
        },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: { args: { customerId: 'abc-123' } },
      });

      expect(result.allowed).toBe(true);
    });

    it('also validates args supplied via context.body (proxy path)', async () => {
      const token = await createTestToken([
        {
          resource: 'api://crm/customers',
          actions: ['write'],
          argumentSchema: {
            type: 'object',
            properties: {
              email: { type: 'string', pattern: '[^@]+@[^@]+' },
            },
            required: ['email'],
            additionalProperties: false,
          },
        },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'write',
        resource: 'api://crm/customers',
        context: {
          method: 'POST',
          path: '/crm/customers',
          body: { email: 'attacker', role: 'admin' },
        },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/args/);
    });

    it('imposes no constraint when the matched capability has no argumentSchema', async () => {
      const token = await createTestToken([
        { resource: 'api://crm/customers', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: { args: { anything: 'goes' } },
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe('kill-switch enforcement', () => {
    let killEngine: EnforcementEngine;
    let killSwitchManager: DefaultKillSwitchManager;

    beforeEach(() => {
      killSwitchManager = new DefaultKillSwitchManager(logger);
      killEngine = new EnforcementEngine({ dpop: { required: false }, verifier, logger, killSwitchManager });
    });

    it('should block all requests when global kill switch is active', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.activateGlobalKill();

      await expect(
        killEngine.validateAction({ token, action: 'read', resource: 'api://service/endpoint' })
      ).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('terminated') });
    });

    it('should block requests for a killed session', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('session-abc');

      await expect(
        killEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          context: { sessionId: 'session-abc' },
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('should block requests for a killed agent', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { sub: 'agent-xyz' }
      );

      killSwitchManager.killAgent('agent-xyz');

      await expect(
        killEngine.validateAction({ token, action: 'read', resource: 'api://service/endpoint' })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('should not block requests when kill switch targets a different session', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('other-session');

      const result = await killEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 'session-abc' },
      });

      expect(result.allowed).toBe(true);
    });

    it('should not block requests when sessionId is not a string', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      killSwitchManager.killSession('undefined');

      // numeric sessionId must not be coerced – guard should treat it as absent
      const result = await killEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 42 as unknown as string },
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe('cryptographic evidence generation', () => {
    it('should invoke evidenceSigner for an allowed action', async () => {
      const signEvidence = makeChainedSignEvidence();
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const mockSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const auditEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: true,
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const result = await auditEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 'sess-1' },
      });

      expect(result.allowed).toBe(true);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'allow', sessionId: 'sess-1' })
      );
    });

    it('should invoke evidenceSigner for a denied action', async () => {
      const signEvidence = makeChainedSignEvidence();
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: true,
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const result = await auditEngine.validateAction({
        token,
        action: 'write',   // not allowed
        resource: 'api://service/endpoint',
        context: { sessionId: 'sess-2' },
      });

      expect(result.allowed).toBe(false);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny', sessionId: 'sess-2' })
      );
    });

    it('should not invoke evidenceSigner when audit is disabled', async () => {
      const signEvidence = makeChainedSignEvidence();
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        evidenceSigner: mockSigner,
        enableCryptographicAudit: false,
      });

      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      await auditEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(signEvidence).not.toHaveBeenCalled();
    });

    // I-8: per-decision evidence signing. The single boolean
    // `enableCryptographicAudit` cannot express asymmetric policies
    // (e.g. "sign every deny but skip allow"); `signedDecisions`
    // replaces it for callers that want fine-grained control.
    describe('per-decision signing (I-8)', () => {
      function makeMockSigner() {
        const signEvidence = makeChainedSignEvidence();
        const mockSigner: EvidenceSigner = {
          signEvidence,
          verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
        };
        return { signEvidence, mockSigner };
      }

      it('signs only deny when signedDecisions=["deny"]', async () => {
        const { signEvidence, mockSigner } = makeMockSigner();

        const auditEngine = new EnforcementEngine({
          dpop: { required: false },
          verifier,
          logger,
          evidenceSigner: mockSigner,
          signedDecisions: ['deny'],
          policyVersion: '1.0.0',
        });

        const token = await createTestToken(
          [{ resource: 'api://service/endpoint', actions: ['read'] }],
          { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
        );

        // allow path — should NOT sign
        const allowResult = await auditEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          context: { sessionId: 'sess-allow' },
        });
        expect(allowResult.allowed).toBe(true);
        expect(signEvidence).not.toHaveBeenCalled();

        // deny path — SHOULD sign
        const denyResult = await auditEngine.validateAction({
          token,
          action: 'write',
          resource: 'api://service/endpoint',
          context: { sessionId: 'sess-deny' },
        });
        expect(denyResult.allowed).toBe(false);
        expect(signEvidence).toHaveBeenCalledTimes(1);
        expect(signEvidence).toHaveBeenCalledWith(
          expect.objectContaining({ decision: 'deny', sessionId: 'sess-deny' })
        );
      });

      it('signs only allow when signedDecisions=["allow"]', async () => {
        const { signEvidence, mockSigner } = makeMockSigner();

        const auditEngine = new EnforcementEngine({
          dpop: { required: false },
          verifier,
          logger,
          evidenceSigner: mockSigner,
          signedDecisions: ['allow'],
          policyVersion: '1.0.0',
        });

        const token = await createTestToken(
          [{ resource: 'api://service/endpoint', actions: ['read'] }],
          { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
        );

        await auditEngine.validateAction({
          token,
          action: 'write',
          resource: 'api://service/endpoint',
          context: { sessionId: 'sess-deny' },
        });
        // deny path — must NOT sign in allow-only mode
        expect(signEvidence).not.toHaveBeenCalled();

        await auditEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          context: { sessionId: 'sess-allow' },
        });
        expect(signEvidence).toHaveBeenCalledTimes(1);
        expect(signEvidence).toHaveBeenCalledWith(
          expect.objectContaining({ decision: 'allow', sessionId: 'sess-allow' })
        );
      });

      it('signs nothing when signedDecisions=[] regardless of legacy boolean', async () => {
        const { signEvidence, mockSigner } = makeMockSigner();

        const auditEngine = new EnforcementEngine({
          dpop: { required: false },
          verifier,
          logger,
          evidenceSigner: mockSigner,
          signedDecisions: [],
          enableCryptographicAudit: true, // overridden by signedDecisions=[]
          policyVersion: '1.0.0',
        });

        const token = await createTestToken(
          [{ resource: 'api://service/endpoint', actions: ['read'] }],
          { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
        );

        await auditEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        });
        await auditEngine.validateAction({
          token,
          action: 'write',
          resource: 'api://service/endpoint',
        });

        expect(signEvidence).not.toHaveBeenCalled();
      });

      it('legacy enableCryptographicAudit=true still signs both decisions when signedDecisions is omitted', async () => {
        const { signEvidence, mockSigner } = makeMockSigner();

        const auditEngine = new EnforcementEngine({
          dpop: { required: false },
          verifier,
          logger,
          evidenceSigner: mockSigner,
          enableCryptographicAudit: true,
          policyVersion: '1.0.0',
        });

        const token = await createTestToken(
          [{ resource: 'api://service/endpoint', actions: ['read'] }],
          { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
        );

        await auditEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        });
        await auditEngine.validateAction({
          token,
          action: 'write',
          resource: 'api://service/endpoint',
        });

        expect(signEvidence).toHaveBeenCalledTimes(2);
      });
    });
  });

  // R-9 (addresses I-21): when an `auditPipeline` is wired into the
  // engine, the request critical path must enqueue evidence and return
  // immediately rather than awaiting `signEvidence` directly. These
  // tests pin that contract.
  describe('async audit pipeline (R-9)', () => {
    it('enqueues to the pipeline instead of awaiting signEvidence on the request path', async () => {
      // A signer that takes 100ms — if the engine awaited it on the
      // critical path, validateAction would inherit that latency.
      const chainedSign = makeChainedSignEvidence();
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => {
          await new Promise((r) => setTimeout(r, 100));
          return chainedSign(ev);
        }
      );
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const slowSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const { AuditPipeline } = await import('@euno/common');
      const pipeline = new AuditPipeline({ signer: slowSigner, workers: 1 });
      pipeline.start();

      const auditEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        auditPipeline: pipeline,
        signedDecisions: ['allow'],
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const start = Date.now();
      const result = await auditEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sessionId: 'sess-1' },
      });
      const elapsed = Date.now() - start;

      expect(result.allowed).toBe(true);
      // Critical-path budget: well under the 100ms signer delay.
      expect(elapsed).toBeLessThan(50);

      // Drain so the worker has a chance to call the signer before we
      // assert on the spy.
      await pipeline.drain(1000);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'allow', sessionId: 'sess-1' })
      );
      expect(pipeline.signedCount()).toBe(1);
      expect(pipeline.droppedCount()).toBe(0);
    });

    it('routes denial evidence through the pipeline as well', async () => {
      const signEvidence = makeChainedSignEvidence();
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const fastSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const { AuditPipeline } = await import('@euno/common');
      const pipeline = new AuditPipeline({ signer: fastSigner, workers: 1 });
      pipeline.start();

      const auditEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        auditPipeline: pipeline,
        signedDecisions: ['deny'],
        policyVersion: '1.0.0',
      });

      const token = await createTestToken(
        [{ resource: 'api://service/other', actions: ['read'] }],
        { authorizedBy: { userId: 'user-1', roles: ['reader'] } }
      );

      const result = await auditEngine.validateAction({
        token,
        action: 'write',
        resource: 'api://service/other',
        context: { sessionId: 'sess-1' },
      });

      expect(result.allowed).toBe(false);
      await pipeline.drain(1000);
      expect(signEvidence).toHaveBeenCalledTimes(1);
      expect(signEvidence).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny' })
      );
    });
  });

  // I-7: strict argument-schema mode. By default, capabilities without
  // an `argumentSchema` impose no argument-level constraint. Strict mode
  // flips that to deny-by-default for schema-less capabilities so an
  // operator can fail closed once every capability has been migrated.
  describe('strict argument-schema mode (I-7)', () => {
    let strictEngine: EnforcementEngine;

    beforeAll(() => {
      strictEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        argumentSchemaRequired: true,
      });
    });

    it('denies a matched capability that has no argumentSchema', async () => {
      const token = await createTestToken([
        { resource: 'api://crm/customers', actions: ['read'] },
      ]);

      const result = await strictEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: { args: { anything: 'goes' } },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/argument schema required/i);
    });

    it('allows a matched capability whose argumentSchema accepts the input', async () => {
      const token = await createTestToken([
        {
          resource: 'api://crm/customers',
          actions: ['read'],
          argumentSchema: {
            type: 'object',
            properties: {
              id: { type: 'string' },
            },
            required: ['id'],
          },
        },
      ]);

      const result = await strictEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: { args: { id: 'cust-1' } },
      });

      expect(result.allowed).toBe(true);
    });

    it('default (non-strict) engine still allows schema-less capabilities', async () => {
      const token = await createTestToken([
        { resource: 'api://crm/customers', actions: ['read'] },
      ]);

      const result = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://crm/customers',
        context: { args: { anything: 'goes' } },
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe('typed-condition enforcement', () => {
    // Spin up a dedicated engine wired with an in-memory counter store so
    // `maxCalls` can be exercised end-to-end. All other handlers are
    // stateless and run on the shared `engine`.
    let conditionEngine: EnforcementEngine;
    let counterStore: InMemoryCallCounterStore;

    beforeAll(() => {
      counterStore = new InMemoryCallCounterStore();
      conditionEngine = new EnforcementEngine({
        dpop: { required: false },
        verifier,
        logger,
        callCounterStore: counterStore,
      });
    });

    beforeEach(() => counterStore.reset());

    it('allows a request whose conditions all evaluate to allow', async () => {
      const token = await createTestToken([
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          conditions: [
            { type: 'timeWindow', notAfter: '2099-01-01T00:00:00Z' },
            { type: 'allowedOperations', operations: ['SELECT'] },
          ],
        },
      ]);

      const result = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { operation: 'select' },
      });

      expect(result.allowed).toBe(true);
    });

    it('denies when a timeWindow has expired', async () => {
      const token = await createTestToken([
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          conditions: [{ type: 'timeWindow', notAfter: '2000-01-01T00:00:00Z' }],
        },
      ]);

      const result = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Condition not satisfied');
      expect(result.reason).toMatch(/timeWindow/);
    });

    it('denies when the request sourceIp is outside the ipRange CIDR', async () => {
      const token = await createTestToken([
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          conditions: [{ type: 'ipRange', cidrs: ['10.0.0.0/8'] }],
        },
      ]);

      const denied = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sourceIp: '192.168.1.1' },
      });
      expect(denied.allowed).toBe(false);

      const allowed = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        context: { sourceIp: '10.5.6.7' },
      });
      expect(allowed.allowed).toBe(true);
    });

    it('denies when the requested operation is not in allowedOperations', async () => {
      const token = await createTestToken([
        {
          resource: 'db://crm/customers',
          actions: ['execute'],
          conditions: [{ type: 'allowedOperations', operations: ['SELECT'] }],
        },
      ]);

      const result = await conditionEngine.validateAction({
        token,
        action: 'execute',
        resource: 'db://crm/customers',
        context: { operation: 'DROP' },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/operation/);
    });

    it('denies when the requested table is not in allowedTables', async () => {
      const token = await createTestToken([
        {
          resource: 'db://crm/customers',
          actions: ['read'],
          conditions: [{ type: 'allowedTables', tables: ['customers'] }],
        },
      ]);

      const denied = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'db://crm/customers',
        context: { tables: [{ table: 'salaries' }] },
      });
      expect(denied.allowed).toBe(false);

      const allowed = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'db://crm/customers',
        context: { tables: [{ table: 'customers' }] },
      });
      expect(allowed.allowed).toBe(true);
    });

    it('denies when the file extension is not allowed', async () => {
      const token = await createTestToken([
        {
          resource: 'file://reports',
          actions: ['read'],
          conditions: [{ type: 'allowedExtensions', extensions: ['.pdf'] }],
        },
      ]);

      const denied = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'file://reports',
        context: { filePath: 'malware.exe' },
      });
      expect(denied.allowed).toBe(false);

      const allowed = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'file://reports',
        context: { filePath: 'q4.pdf' },
      });
      expect(allowed.allowed).toBe(true);
    });

    it('denies when a recipient domain is outside the allowed list', async () => {
      const token = await createTestToken([
        {
          resource: 'mail://outbound',
          actions: ['write'],
          conditions: [{ type: 'recipientDomain', domains: ['example.com'] }],
        },
      ]);

      const result = await conditionEngine.validateAction({
        token,
        action: 'write',
        resource: 'mail://outbound',
        context: { recipients: ['ok@example.com', 'leak@evil.com'] },
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/recipient/);
    });

    it('enforces maxCalls across requests sharing the same capability id', async () => {
      const token = await createTestToken([
        {
          resource: 'api://rate-limited/endpoint',
          actions: ['read'],
          conditions: [{ type: 'maxCalls', count: 2, windowSeconds: 60 }],
        },
      ]);

      const req = {
        token,
        action: 'read',
        resource: 'api://rate-limited/endpoint',
      };
      expect((await conditionEngine.validateAction(req)).allowed).toBe(true);
      expect((await conditionEngine.validateAction(req)).allowed).toBe(true);
      const third = await conditionEngine.validateAction(req);
      expect(third.allowed).toBe(false);
      expect(third.reason).toMatch(/maxCalls/);
    });

    it('denies maxCalls when the engine has no counter store wired (deny-by-default)', async () => {
      const noStoreEngine = new EnforcementEngine({ dpop: { required: false }, verifier, logger });
      const token = await createTestToken([
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          conditions: [{ type: 'maxCalls', count: 5, windowSeconds: 60 }],
        },
      ]);

      const result = await noStoreEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/maxCalls/);
    });

    it('denies on an unknown condition type carried in a token (forward-compat)', async () => {
      // A future issuer might mint a condition this gateway has never
      // heard of. Deny-by-default is the only safe behavior — the
      // gateway must NOT silently allow.
      const token = await createTestToken([
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          conditions: [
            { type: 'futureCondition' as 'timeWindow', notAfter: '2099-01-01T00:00:00Z' } as any,
          ],
        },
      ]);

      const result = await conditionEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/futureCondition/);
    });
  });

  // F-5 (I-16): the bootstrap wires a decision recorder that feeds the
  // Prometheus `euno_gateway_decisions_total` counter. These tests pin the
  // recorder contract — invoked exactly once per call with the right label,
  // including for thrown CapabilityErrors, and recorder exceptions must not
  // destabilise validateAction.
  describe('decision recorder (F-5)', () => {
    let recorderEngine: EnforcementEngine;
    let recorded: Array<'allow' | 'deny'>;

    beforeEach(() => {
      recorderEngine = new EnforcementEngine({ dpop: { required: false }, verifier, logger });
      recorded = [];
      recorderEngine.setDecisionRecorder((decision) => {
        recorded.push(decision);
      });
    });

    it('invokes the recorder with "allow" for a permitted action', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      await recorderEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(recorded).toEqual(['allow']);
    });

    it('invokes the recorder with "deny" when the action is not permitted', async () => {
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      await recorderEngine.validateAction({
        token,
        action: 'write',
        resource: 'api://service/endpoint',
      });

      expect(recorded).toEqual(['deny']);
    });

    it('records "deny" when validateAction throws (e.g. invalid audience)', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { aud: 'wrong-audience' },
      );

      await expect(
        recorderEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        }),
      ).rejects.toThrow();

      expect(recorded).toEqual(['deny']);
    });

    it('does not destabilise validateAction when the recorder throws', async () => {
      const noisyEngine = new EnforcementEngine({ dpop: { required: false }, verifier, logger });
      noisyEngine.setDecisionRecorder(() => {
        throw new Error('metrics sink exploded');
      });
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      const result = await noisyEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(result.allowed).toBe(true);
    });

    it('detaches the recorder when set to undefined', async () => {
      recorderEngine.setDecisionRecorder(undefined);
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);

      await recorderEngine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });

      expect(recorded).toEqual([]);
    });

    it('invokes the recorder exactly once per call (including on throw)', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { aud: 'wrong-audience' },
      );

      await expect(
        recorderEngine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        }),
      ).rejects.toThrow();

      expect(recorded).toHaveLength(1);
    });
  });

  describe('DPoP enforcement (F-2)', () => {
    let dpopPrivateKey: jose.KeyLike;
    let dpopPublicJwk: jose.JWK;
    let dpopJkt: string;

    beforeAll(async () => {
      const kp = await jose.generateKeyPair('ES256', { extractable: true });
      dpopPrivateKey = kp.privateKey as jose.KeyLike;
      dpopPublicJwk = await jose.exportJWK(kp.publicKey);
      // Reuse the runtime's jose to compute the thumbprint so the test
      // does not depend on @euno/common internals beyond what the
      // engine itself uses.
      dpopJkt = await jose.calculateJwkThumbprint(dpopPublicJwk, 'sha256');
    });

    async function createDpopProof(method: string, url: string, opts?: { iat?: number; jti?: string }) {
      const builder = new jose.SignJWT({
        htm: method.toUpperCase(),
        htu: url,
        jti: opts?.jti ?? `proof-${Math.random().toString(36).slice(2)}`,
      }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: dpopPublicJwk });
      builder.setIssuedAt(opts?.iat);
      return builder.sign(dpopPrivateKey);
    }

    it('rejects a sender-constrained token with no DPoP proof', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { cnf: { jkt: dpopJkt } },
      );
      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        }),
      ).rejects.toThrow(/DPoP proof required/);
    });

    it('accepts a sender-constrained token with a valid DPoP proof', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { cnf: { jkt: dpopJkt } },
      );
      const proof = await createDpopProof('GET', 'https://gw.example.com/proxy/api');
      const res = await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        dpop: {
          proof,
          httpMethod: 'GET',
          httpUrl: 'https://gw.example.com/proxy/api',
        },
      });
      expect(res.allowed).toBe(true);
    });

    it('rejects a replayed DPoP proof', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { cnf: { jkt: dpopJkt } },
      );
      const proof = await createDpopProof('GET', 'https://gw.example.com/proxy/api', {
        jti: 'fixed-jti',
      });
      await engine.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
        dpop: { proof, httpMethod: 'GET', httpUrl: 'https://gw.example.com/proxy/api' },
      });
      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          dpop: { proof, httpMethod: 'GET', httpUrl: 'https://gw.example.com/proxy/api' },
        }),
      ).rejects.toThrow(/already been used/);
    });

    it('rejects a proof for the wrong URL', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { cnf: { jkt: dpopJkt } },
      );
      const proof = await createDpopProof('GET', 'https://gw.example.com/other');
      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          dpop: { proof, httpMethod: 'GET', httpUrl: 'https://gw.example.com/proxy/api' },
        }),
      ).rejects.toThrow(/htu mismatch/);
    });

    it('rejects a proof signed by a different key', async () => {
      const token = await createTestToken(
        [{ resource: 'api://service/endpoint', actions: ['read'] }],
        { cnf: { jkt: dpopJkt } },
      );
      const otherKp = await jose.generateKeyPair('ES256', { extractable: true });
      const otherJwk = await jose.exportJWK(otherKp.publicKey);
      const proof = await new jose.SignJWT({
        htm: 'GET',
        htu: 'https://gw.example.com/proxy/api',
        jti: 'wrong-key',
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: otherJwk })
        .setIssuedAt()
        .sign(otherKp.privateKey as jose.KeyLike);
      await expect(
        engine.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
          dpop: { proof, httpMethod: 'GET', httpUrl: 'https://gw.example.com/proxy/api' },
        }),
      ).rejects.toThrow(/does not match/);
    });

    it('with dpop.required=true, rejects a plain token without cnf.jkt', async () => {
      const strict = new EnforcementEngine({
        verifier,
        logger,
        dpop: { required: true, allowInProcessReplayStore: true },
      });
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);
      await expect(
        strict.validateAction({
          token,
          action: 'read',
          resource: 'api://service/endpoint',
        }),
      ).rejects.toThrow(/requires DPoP/);
    });

    it('with dpop.required=false (explicit), still accepts plain bearer tokens', async () => {
      const permissive = new EnforcementEngine({
        verifier,
        logger,
        dpop: { required: false },
      });
      const token = await createTestToken([
        { resource: 'api://service/endpoint', actions: ['read'] },
      ]);
      const res = await permissive.validateAction({
        token,
        action: 'read',
        resource: 'api://service/endpoint',
      });
      expect(res.allowed).toBe(true);
    });

    // Security regression guard: the constructor MUST refuse to install
    // an in-process replay store when DPoP is required, otherwise a
    // captured proof is replayable at sibling pods (the bug this PR
    // closes). These tests pin both the throw and the explicit opt-in.
    describe('replay-store fail-closed (constructor)', () => {
      it('throws when dpop.required=true and no replayStore is supplied', () => {
        expect(
          () =>
            new EnforcementEngine({
              verifier,
              logger,
              dpop: { required: true },
            }),
        ).toThrow(/no dpop\.replayStore was supplied/);
      });

      it('throws even when other dpop fields are set but replayStore is omitted', () => {
        expect(
          () =>
            new EnforcementEngine({
              verifier,
              logger,
              dpop: {
                required: true,
                clockSkewSeconds: 30,
                maxAgeSeconds: 120,
              },
            }),
        ).toThrow(/no dpop\.replayStore was supplied/);
      });

      it('constructs successfully with allowInProcessReplayStore=true (single-replica opt-in)', () => {
        expect(
          () =>
            new EnforcementEngine({
              verifier,
              logger,
              dpop: { required: true, allowInProcessReplayStore: true },
            }),
        ).not.toThrow();
      });

      it('constructs successfully when a shared replayStore is supplied', async () => {
        const { InMemoryDpopReplayStore } = await import('@euno/common');
        expect(
          () =>
            new EnforcementEngine({
              verifier,
              logger,
              dpop: { required: true, replayStore: new InMemoryDpopReplayStore() },
            }),
        ).not.toThrow();
      });

      it('does not throw when dpop.required is false (in-process default is acceptable)', () => {
        expect(
          () =>
            new EnforcementEngine({
              verifier,
              logger,
              dpop: { required: false },
            }),
        ).not.toThrow();
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Gateway quota enforcement (F-1b)
  // ---------------------------------------------------------------------------

  describe('Gateway quota enforcement (F-1b)', () => {
    let quotaPrivKey: jose.KeyLike;
    let quotaPubKey: string;

    beforeAll(async () => {
      const { publicKey: pub, privateKey: priv } = await jose.generateKeyPair('RS256');
      quotaPrivKey = priv;
      quotaPubKey = await jose.exportSPKI(pub);
    });

    async function makeQuotaToken(
      capabilities: CapabilityConstraint[],
      jtiSuffix = 'quota-jti',
    ): Promise<{ token: string; jti: string }> {
      const jti = `${jtiSuffix}-${Date.now()}`;
      const payload: CapabilityTokenPayload = {
        iss: 'did:web:test.com',
        sub: 'quota-agent',
        aud: 'tool-gateway',
        iat: getCurrentTimestamp(),
        exp: getExpirationTimestamp(900),
        jti,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities,
      };
      const token = await new jose.SignJWT(payload as any)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(quotaPrivKey);
      return { token, jti };
    }

    function makeQuotaEngine(max: number): EnforcementEngine {
      const store = new InMemoryCallCounterStore();
      const quotaEng = new CallCounterBackedGatewayQuotaEngine(
        store,
        { max, windowSeconds: 60, failOpen: false },
        logger,
      );
      return new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(quotaPubKey, { requireKid: false }),
        logger,
        gatewayQuota: quotaEng,
      });
    }

    it('allows requests under the quota', async () => {
      const eng = makeQuotaEngine(3);
      const { token } = await makeQuotaToken([{ resource: 'api://svc/ep', actions: ['read'] }]);
      const r1 = await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' });
      const r2 = await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' });
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });

    it('denies with RATE_LIMIT_EXCEEDED once the quota is exhausted', async () => {
      const eng = makeQuotaEngine(2);
      const { token } = await makeQuotaToken([{ resource: 'api://svc/ep', actions: ['read'] }]);
      await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' }); // 1
      await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' }); // 2 = max
      // 3rd call exceeds the quota
      await expect(
        eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' }),
      ).rejects.toMatchObject({
        code: 'RATE_LIMIT_EXCEEDED',
        statusCode: 429,
      });
    });

    it('quotas are independent per (jti, action, resource)', async () => {
      const eng = makeQuotaEngine(1);
      const { token: t1 } = await makeQuotaToken([{ resource: 'api://a', actions: ['read'] }], 'jti-a');
      const { token: t2 } = await makeQuotaToken([{ resource: 'api://a', actions: ['read'] }], 'jti-b');
      // Exhaust quota for token t1
      await eng.validateAction({ token: t1, action: 'read', resource: 'api://a' });
      await expect(
        eng.validateAction({ token: t1, action: 'read', resource: 'api://a' }),
      ).rejects.toMatchObject({ code: 'RATE_LIMIT_EXCEEDED' });
      // Token t2 has an independent budget
      const r = await eng.validateAction({ token: t2, action: 'read', resource: 'api://a' });
      expect(r.allowed).toBe(true);
    });

    it('includes Retry-After in the denial error', async () => {
      const eng = makeQuotaEngine(1);
      const { token } = await makeQuotaToken([{ resource: 'api://svc/ep', actions: ['read'] }]);
      await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' }); // exhaust
      try {
        await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' });
        throw new Error('expected rejection');
      } catch (err: any) {
        expect(err.responseHeaders?.['Retry-After']).toBeDefined();
        expect(Number(err.responseHeaders?.['Retry-After'])).toBeGreaterThan(0);
      }
    });

    it('passes payload.sub as agentSub for shard-local fast path', async () => {
      const capturedKeys: Array<{ agentSub: string }> = [];
      const spyEngine: GatewayQuotaEngine = {
        windowSeconds: 60,
        checkAndCount: async (key) => {
          capturedKeys.push({ agentSub: key.agentSub });
          return { allowed: true, limit: 100, remaining: 99, windowSeconds: 60, retryAfterSeconds: 0 };
        },
      };
      const eng = new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(quotaPubKey, { requireKid: false }),
        logger,
        gatewayQuota: spyEngine,
      });
      const { token } = await makeQuotaToken([{ resource: 'api://svc/ep', actions: ['read'] }]);
      await eng.validateAction({ token, action: 'read', resource: 'api://svc/ep' });
      expect(capturedKeys[0]?.agentSub).toBe('quota-agent');
    });

    it('omitting gatewayQuota preserves pre-F-1b behaviour (no quota)', async () => {
      // Engine without a quota engine set
      const noQuota = new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(quotaPubKey, { requireKid: false }),
        logger,
      });
      const { token } = await makeQuotaToken([{ resource: 'api://svc/ep', actions: ['read'] }]);
      // Can call indefinitely with no quota
      for (let i = 0; i < 10; i++) {
        const r = await noQuota.validateAction({ token, action: 'read', resource: 'api://svc/ep' });
        expect(r.allowed).toBe(true);
      }
    });
  });

  // ── Usage meter / CI-2 ──────────────────────────────────────────────────────

  describe('onMeterError callback (CI-2)', () => {
    let meterKey: jose.KeyLike;
    let meterPubKey: string;

    beforeAll(async () => {
      const kp = await jose.generateKeyPair('RS256');
      meterKey = kp.privateKey;
      meterPubKey = await jose.exportSPKI(kp.publicKey);
    });

    const makeMeterToken = async (tenantId: string): Promise<string> => {
      const now = Math.floor(Date.now() / 1000);
      return new jose.SignJWT({
        iss: 'did:web:test.com',
        sub: 'agent-1',
        aud: 'tool-gateway',
        iat: now,
        exp: now + 3600,
        jti: `meter-test-${Date.now()}`,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [{ resource: 'res://tool', actions: ['call'] }],
        authorizedBy: { userId: 'user-1', roles: ['user'], tenantId },
      })
        .setProtectedHeader({ alg: 'RS256' })
        .sign(meterKey);
    };

    it('invokes onMeterError when usageMeter.recordEnforcement throws', async () => {
      const onMeterError = jest.fn();

      // Build a meter whose recordEnforcement always throws.
      const throwingMeter = {
        recordEnforcement: () => { throw new Error('Billing system unavailable'); },
        recordKillSwitchInvocation: jest.fn(),
        getUsage: jest.fn(),
        getAllUsage: jest.fn(),
        resetPeriod: jest.fn(),
      };

      const eng = new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(meterPubKey, { requireKid: false }),
        logger,
        usageMeter: throwingMeter,
        onMeterError,
      });

      const token = await makeMeterToken('acme');
      // The validate call must still complete and return a result, despite the
      // meter error. The enforcement outcome must NOT be affected.
      const result = await eng.validateAction({ token, action: 'call', resource: 'res://tool' });
      expect(result.allowed).toBe(true);

      // The onMeterError callback should have been called exactly once.
      expect(onMeterError).toHaveBeenCalledTimes(1);
    });

    it('does not call onMeterError when usageMeter.recordEnforcement succeeds', async () => {
      const onMeterError = jest.fn();

      const silentMeter = {
        recordEnforcement: jest.fn(),
        recordKillSwitchInvocation: jest.fn(),
        getUsage: jest.fn(),
        getAllUsage: jest.fn(),
        resetPeriod: jest.fn(),
      };

      const eng = new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(meterPubKey, { requireKid: false }),
        logger,
        usageMeter: silentMeter,
        onMeterError,
      });

      const token = await makeMeterToken('acme');
      await eng.validateAction({ token, action: 'call', resource: 'res://tool' });
      expect(onMeterError).not.toHaveBeenCalled();
    });

    it('does not invoke onMeterError when no usageMeter is configured', async () => {
      const onMeterError = jest.fn();

      const eng = new EnforcementEngine({
        dpop: { required: false },
        verifier: new JWTTokenVerifier(meterPubKey, { requireKid: false }),
        logger,
        onMeterError,
      });

      const token = await makeMeterToken('acme');
      await eng.validateAction({ token, action: 'call', resource: 'res://tool' });
      // No meter — no error
      expect(onMeterError).not.toHaveBeenCalled();
    });
  });
});

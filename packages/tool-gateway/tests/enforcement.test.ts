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
  InMemoryCallCounterStore,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
} from '@euno/common';
import * as jose from 'jose';

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

    verifier = new JWTTokenVerifier(publicKey);
    engine = new EnforcementEngine({
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
      killEngine = new EnforcementEngine({ verifier, logger, killSwitchManager });
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
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const mockSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const auditEngine = new EnforcementEngine({
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
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
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
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const mockSigner: EvidenceSigner = {
        signEvidence,
        verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
      };

      const auditEngine = new EnforcementEngine({
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
        const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
          async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
        );
        const mockSigner: EvidenceSigner = {
          signEvidence,
          verifyEvidence: jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false),
        };
        return { signEvidence, mockSigner };
      }

      it('signs only deny when signedDecisions=["deny"]', async () => {
        const { signEvidence, mockSigner } = makeMockSigner();

        const auditEngine = new EnforcementEngine({
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
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => {
          await new Promise((r) => setTimeout(r, 100));
          return { ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' };
        }
      );
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const slowSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const { AuditPipeline } = await import('@euno/common');
      const pipeline = new AuditPipeline({ signer: slowSigner, workers: 1 });
      pipeline.start();

      const auditEngine = new EnforcementEngine({
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
      const signEvidence = jest.fn<Promise<SignedAuditEvidence>, [AuditEvidence]>(
        async (ev) => ({ ...ev, signature: 'sig', keyId: 'kid', algorithm: 'RS256' })
      );
      const verifyEvidence = jest.fn<Promise<boolean>, [SignedAuditEvidence]>(async () => false);
      const fastSigner: EvidenceSigner = { signEvidence, verifyEvidence };

      const { AuditPipeline } = await import('@euno/common');
      const pipeline = new AuditPipeline({ signer: fastSigner, workers: 1 });
      pipeline.start();

      const auditEngine = new EnforcementEngine({
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
      const noStoreEngine = new EnforcementEngine({ verifier, logger });
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
      recorderEngine = new EnforcementEngine({ verifier, logger });
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
      const noisyEngine = new EnforcementEngine({ verifier, logger });
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
});

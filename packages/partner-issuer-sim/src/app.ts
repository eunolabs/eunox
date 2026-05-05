/**
 * Partner Issuer Simulator — Express app.
 *
 * This service is the "partner organization" half of the cross-org trust
 * harness described in `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`.
 *
 * It deliberately mirrors only the surface of `@euno/capability-issuer`
 * needed to round-trip a verifiable credential through our gateway:
 *
 * - `GET  /healthz`               — liveness probe.
 * - `GET  /.well-known/did.json`  — serves the partner DID document so a
 *                                   third-party (our gateway) can resolve
 *                                   the partner's signing key.
 * - `POST /issue`                 — mints an EdDSA-signed JWT with the
 *                                   same payload shape as our production
 *                                   issuer, scoped to a partner agent.
 * - `POST /validate`              — accepts a JWT and reports whether the
 *                                   partner sim trusts the issuer DID and
 *                                   whether the requested action is in the
 *                                   token's capability set. Used by the
 *                                   "outbound" half of the harness to
 *                                   prove the partner accepts our VCs.
 *
 * It is **not a product**: identity is pre-shared via configuration, no
 * persistent storage is used beyond the optional key file, and only the
 * routes above exist.
 */

import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import * as jose from 'jose';
import * as crypto from 'crypto';
import {
  CapabilityConstraint,
  CapabilityTokenPayload,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  matchesResource,
} from '@euno/common';
import {
  resolveDID,
  findVerificationMethod,
  extractPublicKeyPem,
  determineSigningAlgorithm,
} from '@euno/capability-issuer/adapters';
import { PartnerKeyMaterial } from './keys';

export interface PartnerAppConfig {
  /** Partner DID (e.g. `did:web:partner-sim.local%3A4001`). */
  issuerDid: string;
  /** Audience claim minted into issued tokens. */
  audience: string;
  /** Token TTL in seconds. */
  defaultTtlSeconds: number;
  /** Pre-shared signing key material. */
  key: PartnerKeyMaterial;
  /**
   * DIDs the partner is willing to accept VCs *from* on its `/validate`
   * endpoint. The harness sets this to our issuer's DID so we can prove
   * outbound trust. Empty by default.
   */
  trustedIssuerDids?: string[];
  /**
   * Pre-parsed HTTP allow-list for did:web resolution on the `/validate`
   * endpoint.  The sim passes this to `resolveDID()` so that CI harnesses
   * without TLS can resolve "our" (the gateway's) DID document over plain
   * HTTP.  In production or docker-compose deployments this is left unset
   * and HTTPS-only resolution applies.  Build via
   * `parseDidWebHttpAllowList(cfg.DID_WEB_ALLOW_HTTP_FOR_HOSTS)`.
   */
  httpAllowList?: Set<string>;
}

interface IssueRequestBody {
  partnerAgentId?: string;
  capabilities?: CapabilityConstraint[];
  ttl?: number;
  /** Audience override; defaults to {@link PartnerAppConfig.audience}. */
  audience?: string;
}

interface ValidateRequestBody {
  token?: string;
  action?: string;
  resource?: string;
}

/**
 * Build the partner-issuer-sim Express app. Returned as a stand-alone
 * `express.Application` so integration tests can mount it on an ephemeral
 * port without a network round-trip.
 *
 * Rate limiting: the `/validate` route performs cryptographic work
 * (DID resolution + JWT signature verification) and would otherwise be a
 * trivial DoS amplifier. We use `express-rate-limit` (already used in
 * `tool-gateway`) at 60 requests / minute / IP — generous for tests and
 * the docker-compose harness, harsh enough to stop a runaway loop.
 */
export function createPartnerApp(config: PartnerAppConfig): express.Express {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  const privateKeyPromise = jose.importPKCS8(config.key.privateKeyPem, 'EdDSA');

  const validateRateLimiter = rateLimit({
    windowMs: 60_000,
    limit: 60,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { allowed: false, reason: 'rate limit exceeded' },
  });

  // --- Health -------------------------------------------------------------

  app.get('/healthz', (_req: Request, res: Response) => {
    res.json({ status: 'ok', issuer: config.issuerDid });
  });

  // --- DID document -------------------------------------------------------

  app.get('/.well-known/did.json', (_req: Request, res: Response) => {
    const vmId = `${config.issuerDid}#key-1`;
    const didDoc = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
      id: config.issuerDid,
      verificationMethod: [
        {
          id: vmId,
          type: 'JsonWebKey2020',
          controller: config.issuerDid,
          publicKeyJwk: config.key.publicKeyJwk,
        },
      ],
      authentication: [vmId],
      assertionMethod: [vmId],
    };
    res.type('application/did+json').json(didDoc);
  });

  // --- Issue --------------------------------------------------------------

  app.post('/issue', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = (req.body || {}) as IssueRequestBody;
      if (!body.partnerAgentId || typeof body.partnerAgentId !== 'string') {
        return res.status(400).json({ error: 'partnerAgentId is required' });
      }
      if (!Array.isArray(body.capabilities) || body.capabilities.length === 0) {
        return res.status(400).json({ error: 'capabilities must be a non-empty array' });
      }

      const ttl = typeof body.ttl === 'number' && body.ttl > 0 ? body.ttl : config.defaultTtlSeconds;
      const now = Math.floor(Date.now() / 1000);
      const audience = body.audience ?? config.audience;
      const tokenId = crypto.randomUUID();

      const payload: CapabilityTokenPayload = {
        iss: config.issuerDid,
        sub: body.partnerAgentId,
        aud: audience,
        iat: now,
        exp: now + ttl,
        jti: tokenId,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: body.capabilities,
      };

      const privateKey = await privateKeyPromise;
      const token = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${config.issuerDid}#key-1` })
        .sign(privateKey);

      return res.json({
        token,
        expiresAt: payload.exp,
        tokenId,
        capabilities: payload.capabilities,
      });
    } catch (err) {
      return next(err);
    }
  });

  // --- Validate (outbound trust check) -----------------------------------

  app.post('/validate', validateRateLimiter, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = (req.body || {}) as ValidateRequestBody;
      if (!body.token || typeof body.token !== 'string') {
        return res.status(400).json({ allowed: false, reason: 'token is required' });
      }
      if (!body.action || !body.resource) {
        return res.status(400).json({ allowed: false, reason: 'action and resource are required' });
      }

      let header: jose.ProtectedHeaderParameters;
      let issuer: string;
      try {
        header = jose.decodeProtectedHeader(body.token);
        const decoded = jose.decodeJwt(body.token);
        issuer = String(decoded.iss ?? '');
      } catch {
        return res.status(401).json({ allowed: false, reason: 'malformed token' });
      }

      const trusted = config.trustedIssuerDids ?? [];
      if (!trusted.includes(issuer)) {
        return res.status(403).json({ allowed: false, reason: `issuer ${issuer || '(none)'} is not trusted by partner` });
      }

      // Resolve the issuer DID to fetch its verification key.
      let publicKeyPem: string;
      let alg: string;
      try {
        const didDoc = await resolveDID(issuer, { httpAllowList: config.httpAllowList });
        const kid = typeof header.kid === 'string' ? header.kid : undefined;
        const vm = findVerificationMethod(didDoc, kid);
        if (!vm) {
          return res.status(401).json({ allowed: false, reason: 'no verification method found' });
        }
        publicKeyPem = await extractPublicKeyPem(vm);
        alg = (typeof header.alg === 'string' && header.alg) || determineSigningAlgorithm(vm);
      } catch (err) {
        return res.status(401).json({
          allowed: false,
          reason: `DID resolution failed: ${err instanceof Error ? err.message : 'unknown'}`,
        });
      }

      let payload: CapabilityTokenPayload;
      try {
        const keyLike = await jose.importSPKI(publicKeyPem, alg);
        const result = await jose.jwtVerify(body.token, keyLike, { algorithms: [alg] });
        payload = result.payload as unknown as CapabilityTokenPayload;
      } catch (err) {
        return res.status(401).json({
          allowed: false,
          reason: `signature verification failed: ${err instanceof Error ? err.message : 'unknown'}`,
        });
      }

      const requestedAction = body.action!;
      const requestedResource = body.resource!;
      const cap = (payload.capabilities || []).find(
        (c) => matchesResource(requestedResource, c.resource) && c.actions.some((a) => a === requestedAction)
      );
      if (!cap) {
        return res.status(403).json({ allowed: false, reason: 'no capability matches the requested action/resource' });
      }

      return res.json({ allowed: true, issuer, subject: payload.sub, matchedCapability: cap });
    } catch (err) {
      return next(err);
    }
  });

  // --- Error handler ------------------------------------------------------

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: err.message || 'internal error' });
  });

  return app;
}
